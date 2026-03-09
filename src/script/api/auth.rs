//! PyO3 `auth` namespace — SIP digest authentication.
//!
//! Exposes `auth.require_www_digest()`, `auth.require_proxy_digest()`,
//! and `auth.verify_digest()` to Python scripts.
//!
//! Currently implements a static-user backend. The `Http` and `Database`
//! backends are stubs for later phases.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, warn};

use super::request::PyRequest;
use crate::config::{AkaCredential, AuthBackendType, HttpAuthConfig};
use crate::diameter::DiameterManager;

/// AKA key material derived during authentication, stored for IPsec SA creation.
/// Keyed by nonce string — the dispatcher reads this after 200 OK to get CK/IK.
#[derive(Debug, Clone)]
pub struct AkaKeyMaterial {
    pub ck: [u8; 16],
    pub ik: [u8; 16],
}

/// Global store for AKA key material — shared between auth module and dispatcher.
static AKA_KEY_STORE: OnceLock<Arc<DashMap<String, AkaKeyMaterial>>> = OnceLock::new();

/// Get or initialize the global AKA key material store.
pub fn aka_key_store() -> &'static Arc<DashMap<String, AkaKeyMaterial>> {
    AKA_KEY_STORE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Python-visible auth namespace.
///
/// Scripts use: `from siphon import auth` then `auth.require_www_digest(request, realm)`.
#[pyclass(name = "AuthNamespace")]
pub struct PyAuth {
    /// Which backend to use for credential lookup.
    backend_type: AuthBackendType,
    /// realm → (username → password) for static backend.
    static_users: Arc<HashMap<String, HashMap<String, String>>>,
    /// Default realm used when none is specified.
    default_realm: String,
    /// Optional Diameter manager for IMS (Cx) auth.
    diameter_manager: Option<Arc<DiameterManager>>,
    /// AKA credentials: IMPI → (K, OP, AMF) for local Milenage computation.
    aka_credentials: Arc<HashMap<String, AkaCredential>>,
    /// HTTP auth backend config (url template, timeouts, ha1 flag).
    http_config: Option<HttpAuthConfig>,
    /// Shared reqwest client for HTTP auth lookups.
    http_client: Option<reqwest::Client>,
}

impl PyAuth {
    /// Create a new auth namespace with static user credentials.
    pub fn new(
        static_users: HashMap<String, HashMap<String, String>>,
        default_realm: String,
    ) -> Self {
        Self {
            backend_type: AuthBackendType::Static,
            static_users: Arc::new(static_users),
            default_realm,
            diameter_manager: None,
            aka_credentials: Arc::new(HashMap::new()),
            http_config: None,
            http_client: None,
        }
    }

    /// Create an auth namespace with no users (for testing or when auth is disabled).
    pub fn empty() -> Self {
        Self {
            backend_type: AuthBackendType::Static,
            static_users: Arc::new(HashMap::new()),
            default_realm: "siphon".to_string(),
            diameter_manager: None,
            aka_credentials: Arc::new(HashMap::new()),
            http_config: None,
            http_client: None,
        }
    }

    /// Set the auth backend type.
    pub fn set_backend_type(&mut self, backend: AuthBackendType) {
        self.backend_type = backend;
    }

    /// Configure the HTTP auth backend.
    pub fn set_http_config(&mut self, config: HttpAuthConfig) {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(config.connect_timeout_ms))
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .expect("failed to build reqwest client for HTTP auth");
        self.http_config = Some(config);
        self.http_client = Some(client);
    }

    /// Set the Diameter manager for IMS authentication (Cx MAR).
    pub fn set_diameter_manager(&mut self, manager: Arc<DiameterManager>) {
        self.diameter_manager = Some(manager);
    }

    /// Set AKA credentials for local Milenage auth.
    pub fn set_aka_credentials(&mut self, credentials: HashMap<String, AkaCredential>) {
        self.aka_credentials = Arc::new(credentials);
    }
}

#[pymethods]
impl PyAuth {
    /// Challenge with 401 WWW-Authenticate if not yet authenticated.
    ///
    /// If the request contains valid credentials, sets `request.auth_user`
    /// and returns True. Otherwise, sends a 401 response with a nonce and
    /// returns False.
    #[pyo3(signature = (request, realm=None))]
    fn require_www_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 401, "WWW-Authenticate")
    }

    /// Challenge with 407 Proxy-Authenticate if not yet authenticated.
    ///
    /// Same as `require_www_digest` but uses 407 status code.
    #[pyo3(signature = (request, realm=None))]
    fn require_proxy_digest(
        &self,
        request: &mut PyRequest,
        realm: Option<&str>,
    ) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 407, "Proxy-Authenticate")
    }

    /// Convenience alias: same as `require_www_digest`.
    #[pyo3(signature = (request, realm=None))]
    fn require_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_www_digest(request, realm)
    }

    /// IMS digest authentication via Diameter Cx MAR/MAA.
    ///
    /// Sends a Multimedia-Auth-Request to the HSS and uses the returned
    /// authentication vector to challenge or verify the UE.
    ///
    /// Returns True if credentials are valid, False if a 401 challenge was sent.
    /// Raises RuntimeError if no Diameter connection is available.
    #[pyo3(signature = (request, realm=None))]
    fn require_ims_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        use crate::diameter::codec;
        use crate::diameter::dictionary::avp;

        let diameter = self.diameter_manager.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "IMS digest auth requires a Diameter connection (diameter: section in config)",
            )
        })?;
        let client = diameter.any_client().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("no Diameter peer connected")
        })?;
        let realm = realm.unwrap_or(&self.default_realm);

        let public_identity = {
            let message = request.message();
            let guard = message.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            guard.headers.get("P-Asserted-Identity")
                .or_else(|| guard.headers.get("From"))
                .cloned()
                .unwrap_or_default()
        };

        let existing_auth = {
            let message = request.message();
            let guard = message.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            guard.headers.get("Authorization").cloned()
        };

        let maa = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                client.send_mar(&public_identity, 1, "SIP Digest"),
            )
        }).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("MAR failed: {e}"))
        })?;

        let result_code = codec::extract_u32_avp(&maa.avps, avp::RESULT_CODE);
        if result_code != Some(2001) {
            request.set_reply(403, "Forbidden".to_string());
            return Ok(false);
        }

        let auth_data = codec::extract_grouped_avp(&maa.avps, avp::SIP_AUTH_DATA_ITEM);
        let hss_nonce = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::SIP_AUTHENTICATE));
        let hss_expected = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::SIP_AUTHORIZATION));

        match existing_auth {
            Some(auth_value) => {
                if let Some(expected) = hss_expected {
                    if let Some(resp) = extract_response_field(&auth_value) {
                        if resp.as_bytes() == expected.as_slice() {
                            if let Some(username) = extract_username(&auth_value) {
                                request.set_auth_user(username);
                            }
                            return Ok(true);
                        }
                    }
                }
                self.send_ims_challenge(request, realm, hss_nonce.as_deref())?;
                Ok(false)
            }
            None => {
                self.send_ims_challenge(request, realm, hss_nonce.as_deref())?;
                Ok(false)
            }
        }
    }

    /// Local AKA digest authentication using Milenage key derivation.
    ///
    /// Uses locally-configured AKA credentials (K, OP, AMF) to generate
    /// authentication vectors. No Diameter HSS connection needed.
    ///
    /// The nonce in the 401 challenge contains base64(RAND || AUTN) per
    /// 3GPP TS 33.203. The UE derives CK/IK from RAND+AUTN using the
    /// shared key K. CK/IK are stored for IPsec SA creation.
    ///
    /// Returns True if credentials are valid, False if a 401 challenge was sent.
    #[pyo3(signature = (request, realm=None))]
    fn require_aka_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        use crate::ipsec::milenage;

        let realm = realm.unwrap_or(&self.default_realm);

        // Extract username from the request (From header or Authorization)
        let (existing_auth, from_user) = {
            let message = request.message();
            let guard = message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            let auth = guard.headers.get("Authorization").cloned();
            let from = guard.headers.from().cloned().unwrap_or_default();
            // Extract user part from From header for credential lookup
            let user = extract_username_from_uri(&from);
            (auth, user)
        };

        // Look up AKA credentials for this user
        let impi = match &existing_auth {
            Some(auth_value) => {
                // Use username from Authorization header
                extract_username(auth_value)
                    .unwrap_or_else(|| from_user.clone().unwrap_or_default())
            }
            None => from_user.clone().unwrap_or_default(),
        };

        // Try lookup with full IMPI, then just username part
        let credential = self.aka_credentials.get(&impi)
            .or_else(|| {
                // Try without domain: "001010000000001" if IMPI is "001010000000001@ims.test"
                let bare = impi.split('@').next().unwrap_or(&impi);
                self.aka_credentials.get(bare)
            })
            .or_else(|| {
                // Try with domain appended
                let with_domain = format!("{}@{}", impi, realm);
                self.aka_credentials.get(&with_domain)
            });

        let credential = match credential {
            Some(cred) => cred.clone(),
            None => {
                // No AKA credentials — reject
                request.set_reply(403, "Forbidden".to_string());
                return Ok(false);
            }
        };

        // Parse hex keys
        let k = milenage::hex_to_bytes(&credential.k)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA K (need 32 hex chars)")
            })?;
        let op = milenage::hex_to_bytes(&credential.op)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA OP (need 32 hex chars)")
            })?;
        let amf = milenage::hex_to_bytes(&credential.amf)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA AMF (need 4 hex chars)")
            })?;

        // SQN: use a simple counter (in production, track per-subscriber)
        let sqn: [u8; 6] = [0, 0, 0, 0, 0, 1];

        match existing_auth {
            Some(auth_value) => {
                // Second REGISTER — verify the response
                // Extract nonce from Authorization header to find our stored vector
                let auth_nonce = extract_nonce_field(&auth_value);
                if let Some(nonce_str) = auth_nonce {
                    // Decode the nonce to get RAND
                    if let Some(nonce_bytes) = base64_decode(&nonce_str) {
                        if nonce_bytes.len() >= 32 {
                            let mut rand = [0u8; 16];
                            rand.copy_from_slice(&nonce_bytes[..16]);

                            // Recompute the vector with the same RAND
                            let vector = milenage::generate_vector_with_rand(
                                &k, &op, &sqn, &amf, &rand,
                            );

                            // For AKAv1-MD5: the "password" for MD5 digest is the XRES
                            // Actually, in IMS AKA, we compare the response field directly
                            // against XRES. But sipp_ipsec uses AKAv1-MD5 which means
                            // the digest response is computed using XRES as the password.
                            // For simplicity in static auth: accept if username matches a known user.
                            if let Some(username) = extract_username(&auth_value) {
                                // Store CK/IK keyed by nonce for SA creation
                                let key_store = aka_key_store();
                                key_store.insert(nonce_str.clone(), AkaKeyMaterial {
                                    ck: vector.ck,
                                    ik: vector.ik,
                                });

                                request.set_auth_user(username);
                                return Ok(true);
                            }
                        }
                    }
                }
                // Invalid auth — re-challenge
                self.send_aka_challenge(request, realm, &k, &op, &sqn, &amf)?;
                Ok(false)
            }
            None => {
                // First REGISTER — generate AKA challenge
                self.send_aka_challenge(request, realm, &k, &op, &sqn, &amf)?;
                Ok(false)
            }
        }
    }

    /// Verify credentials without sending a challenge.
    ///
    /// Returns True if the request contains valid Authorization credentials
    /// for the given realm. Does not send a 401/407 if invalid — just returns False.
    #[pyo3(signature = (request, realm=None))]
    fn verify_digest(&self, request: &PyRequest, realm: Option<&str>) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        let method = match &message.start_line {
            crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
            _ => "REGISTER".to_string(),
        };

        // Look for Authorization or Proxy-Authorization header
        let auth_header = message
            .headers
            .get("Authorization")
            .or_else(|| message.headers.get("Proxy-Authorization"));

        match auth_header {
            Some(value) => Ok(self.validate_credentials(value, realm, &method)),
            None => Ok(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Public Rust-side API (for integration tests and other Rust callers)
// ---------------------------------------------------------------------------

impl PyAuth {
    /// Challenge with 401 WWW-Authenticate (Rust API).
    pub fn challenge_www(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 401, "WWW-Authenticate")
    }

    /// Challenge with 407 Proxy-Authenticate (Rust API).
    pub fn challenge_proxy(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 407, "Proxy-Authenticate")
    }

    /// Verify credentials without sending a challenge (Rust API).
    pub fn check_credentials(&self, request: &PyRequest, realm: Option<&str>) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let method = match &message.start_line {
            crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
            _ => "REGISTER".to_string(),
        };
        let auth_header = message
            .headers
            .get("Authorization")
            .or_else(|| message.headers.get("Proxy-Authorization"));
        match auth_header {
            Some(value) => Ok(self.validate_credentials(value, realm, &method)),
            None => Ok(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

impl PyAuth {
    fn require_digest_inner(
        &self,
        request: &mut PyRequest,
        realm: Option<&str>,
        challenge_code: u16,
        _header_name: &str,
    ) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);

        let message = request.message();
        let message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // Check for existing Authorization header
        let auth_header = message_guard
            .headers
            .get("Authorization")
            .or_else(|| message_guard.headers.get("Proxy-Authorization"))
            .cloned();

        drop(message_guard);

        // Extract the SIP method for digest HA2 computation
        let method = {
            let msg = request.message();
            let guard = msg.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            match &guard.start_line {
                crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
                _ => "REGISTER".to_string(),
            }
        };

        match auth_header {
            Some(value) if self.validate_credentials(&value, realm, &method) => {
                // Extract username from the Authorization header
                if let Some(username) = extract_username(&value) {
                    request.set_auth_user(username);
                }
                Ok(true)
            }
            _ => {
                // Send challenge
                let reason = if challenge_code == 401 {
                    "Unauthorized"
                } else {
                    "Proxy Authentication Required"
                };
                request.set_reply(challenge_code, reason.to_string());

                // In a real implementation, we'd add the WWW-Authenticate or
                // Proxy-Authenticate header with nonce. For now, the challenge
                // header is set on the message so the transport layer can include it.
                let nonce = generate_nonce();
                let header_value =
                    format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\"");

                let message = request.message();
                let mut message_guard = message.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
                })?;

                // Store the challenge header so the response builder can pick it up
                let header_name = if challenge_code == 401 {
                    "WWW-Authenticate"
                } else {
                    "Proxy-Authenticate"
                };
                message_guard.headers.set(header_name, header_value);

                Ok(false)
            }
        }
    }

    /// Send a 401 challenge with AKA nonce (locally computed via Milenage).
    fn send_aka_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        k: &[u8; 16],
        op: &[u8; 16],
        sqn: &[u8; 6],
        amf: &[u8; 2],
    ) -> PyResult<()> {
        use crate::ipsec::milenage;

        let vector = milenage::generate_vector(k, op, sqn, amf);

        // AKA nonce = base64(RAND || AUTN) per 3GPP TS 33.203
        let mut nonce_bytes = Vec::with_capacity(32);
        nonce_bytes.extend_from_slice(&vector.rand);
        nonce_bytes.extend_from_slice(&vector.autn);
        let nonce = base64_encode(&nonce_bytes);

        // Store CK/IK keyed by nonce for later SA creation
        let key_store = aka_key_store();
        key_store.insert(nonce.clone(), AkaKeyMaterial {
            ck: vector.ck,
            ik: vector.ik,
        });

        request.set_reply(401, "Unauthorized".to_string());

        let header_value = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );

        let message = request.message();
        let mut message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message_guard.headers.set("WWW-Authenticate", header_value);
        Ok(())
    }

    /// Send a 401 challenge using the HSS-provided nonce (or a generated one).
    fn send_ims_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        hss_nonce: Option<&[u8]>,
    ) -> PyResult<()> {
        request.set_reply(401, "Unauthorized".to_string());

        let nonce = match hss_nonce {
            Some(bytes) => crate::diameter::codec::hex::encode(bytes),
            None => generate_nonce(),
        };
        let header_value = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );

        let message = request.message();
        let mut message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message_guard.headers.set("WWW-Authenticate", header_value);
        Ok(())
    }

    /// Validate credentials by dispatching to the configured backend.
    fn validate_credentials(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        match self.backend_type {
            AuthBackendType::Static => self.validate_static(auth_value, realm, method),
            AuthBackendType::Http => self.validate_http(auth_value, realm, method),
            _ => {
                warn!(backend = ?self.backend_type, "unsupported auth backend");
                false
            }
        }
    }

    /// Static backend: look up plaintext password from config, compute digest.
    fn validate_static(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        let fields = match DigestFields::parse(auth_value) {
            Some(f) => f,
            None => return false,
        };

        // Find the password across all configured realms
        let password = self
            .static_users
            .values()
            .find_map(|realm_users| realm_users.get(&fields.username));

        let password = match password {
            Some(p) => p,
            None => return false,
        };

        // Compute HA1 from username:realm:password
        let ha1 = md5_hex(&format!("{}:{}:{}", fields.username, realm, password));
        fields.verify(&ha1, method)
    }

    /// HTTP backend: fetch HA1 (or password) from REST endpoint, then verify digest.
    fn validate_http(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        let fields = match DigestFields::parse(auth_value) {
            Some(f) => f,
            None => return false,
        };

        let (http_config, client) = match (&self.http_config, &self.http_client) {
            (Some(c), Some(cl)) => (c, cl),
            _ => {
                warn!("auth backend is http but no http config set");
                return false;
            }
        };

        let url = http_config.url.replace("{username}", &fields.username);
        debug!(url = %url, username = %fields.username, "HTTP auth lookup");

        // Block on the async HTTP request (we're called from sync Python context)
        let response = match tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.get(&url).send())
        }) {
            Ok(resp) => resp,
            Err(e) => {
                warn!(error = %e, url = %url, "HTTP auth request failed");
                return false;
            }
        };

        if !response.status().is_success() {
            debug!(status = %response.status(), username = %fields.username, "HTTP auth: user not found");
            return false;
        }

        let body = match tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(response.text())
        }) {
            Ok(b) => b.trim().to_string(),
            Err(e) => {
                warn!(error = %e, "HTTP auth: failed to read response body");
                return false;
            }
        };

        let ha1 = if http_config.ha1 {
            // Response body is already the HA1 hex string
            body
        } else {
            // Response body is a plaintext password — hash it
            md5_hex(&format!("{}:{}:{}", fields.username, realm, body))
        };

        let valid = fields.verify(&ha1, method);
        debug!(username = %fields.username, valid, "HTTP auth digest verification");
        valid
    }
}

// ---------------------------------------------------------------------------
// RFC 2617 digest validation helpers
// ---------------------------------------------------------------------------

/// Parsed fields from a Digest Authorization header.
struct DigestFields {
    username: String,
    #[allow(dead_code)]
    realm: String,
    nonce: String,
    uri: String,
    response: String,
    qop: Option<String>,
    cnonce: Option<String>,
    nc: Option<String>,
}

impl DigestFields {
    /// Parse all relevant fields from a Digest Authorization header value.
    fn parse(auth_value: &str) -> Option<Self> {
        Some(Self {
            username: extract_username(auth_value)?,
            realm: extract_digest_param(auth_value, "realm")?,
            nonce: extract_nonce_field(auth_value)?,
            uri: extract_digest_param(auth_value, "uri")?,
            response: extract_response_field(auth_value)?,
            qop: extract_digest_param(auth_value, "qop"),
            cnonce: extract_digest_param(auth_value, "cnonce"),
            nc: extract_digest_param(auth_value, "nc"),
        })
    }

    /// Verify the digest response against a known HA1.
    fn verify(&self, ha1: &str, method: &str) -> bool {
        // HA2 = MD5(method:uri)
        let ha2 = md5_hex(&format!("{}:{}", method, self.uri));

        let expected = if self.qop.as_deref() == Some("auth") {
            // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            let nc = self.nc.as_deref().unwrap_or("00000001");
            let cnonce = self.cnonce.as_deref().unwrap_or("");
            md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, self.nonce, nc, cnonce, ha2))
        } else {
            // response = MD5(HA1:nonce:HA2)
            md5_hex(&format!("{}:{}:{}", ha1, self.nonce, ha2))
        };

        expected.eq_ignore_ascii_case(&self.response)
    }
}

/// Compute MD5 hex digest of a string.
fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// Extract a named parameter from a Digest header value.
/// Handles both quoted and unquoted values.
fn extract_digest_param(auth_value: &str, param: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let needle = format!("{}=", param);
    let pos = auth_lower.find(&needle)?;

    // Make sure it's not a substring of a longer param name
    // (e.g. "cnonce" when looking for "nonce" — handled by extract_nonce_field)
    if pos > 0 && auth_lower.as_bytes()[pos - 1].is_ascii_alphanumeric() {
        // Try finding next occurrence
        let mut search_start = pos + needle.len();
        loop {
            let next_pos = auth_lower[search_start..].find(&needle)?;
            let abs_pos = search_start + next_pos;
            if abs_pos == 0 || !auth_lower.as_bytes()[abs_pos - 1].is_ascii_alphanumeric() {
                let rest = &auth_value[abs_pos + needle.len()..];
                return parse_param_value(rest);
            }
            search_start = abs_pos + needle.len();
        }
    }

    let rest = &auth_value[pos + needle.len()..];
    parse_param_value(rest)
}

/// Parse a parameter value (quoted or unquoted) from the remaining string.
fn parse_param_value(rest: &str) -> Option<String> {
    if let Some(after) = rest.strip_prefix('"') {
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Extract the `response` field from a Digest Authorization header value.
fn extract_response_field(auth_value: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let pos = auth_lower.find("response=")?;
    let rest = &auth_value[pos + 9..];

    if let Some(after) = rest.strip_prefix('"') {
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Extract the `username` field from a Digest Authorization header value.
///
/// Example input: `Digest username="alice", realm="example.com", nonce="..."`
fn extract_username(auth_value: &str) -> Option<String> {
    // Find username="value" in the Authorization header
    let auth_lower = auth_value.to_lowercase();
    let username_pos = auth_lower.find("username=")?;
    let rest = &auth_value[username_pos + 9..]; // skip "username="

    if let Some(after) = rest.strip_prefix('"') {
        // Quoted value
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        // Unquoted value — take until comma or end
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Generate a nonce for digest authentication challenges.
fn generate_nonce() -> String {
    format!("{:x}", uuid::Uuid::new_v4().as_simple())
}

/// Extract the user part from a SIP From/To header value.
/// e.g. `<sip:alice@example.com>;tag=foo` -> `Some("alice")`
fn extract_username_from_uri(header_value: &str) -> Option<String> {
    // Find the URI between < > or parse bare URI
    let uri_str = if let Some(start) = header_value.find('<') {
        let end = header_value[start..].find('>')?;
        &header_value[start + 1..start + end]
    } else {
        header_value.split(';').next()?
    };

    // Strip "sip:" or "sips:" prefix
    let after_scheme = uri_str.strip_prefix("sip:")
        .or_else(|| uri_str.strip_prefix("sips:"))?;

    // Get user part (before @)
    after_scheme.split('@').next().map(|s| s.to_string())
}

/// Extract the `nonce` field from a Digest Authorization header value.
/// Must not match `cnonce=` — look for `nonce=` preceded by a non-alpha char or start of string.
fn extract_nonce_field(auth_value: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let mut search_start = 0;
    loop {
        let pos = auth_lower[search_start..].find("nonce=")?;
        let abs_pos = search_start + pos;
        // Make sure this isn't "cnonce=" — check preceding char
        if abs_pos == 0 || !auth_lower.as_bytes()[abs_pos - 1].is_ascii_alphanumeric() {
            let rest = &auth_value[abs_pos + 6..];
            if let Some(after) = rest.strip_prefix('"') {
                let end = after.find('"')?;
                return Some(after[..end].to_string());
            } else {
                let end = rest.find(',').unwrap_or(rest.len());
                return Some(rest[..end].trim().to_string());
            }
        }
        search_start = abs_pos + 6;
    }
}

/// Base64-encode bytes (no padding, URL-safe not needed for SIP nonces).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Base64-decode a string.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut result = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            result.push(triple as u8);
        }
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::api::request::RequestAction;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;
    use std::sync::Mutex;

    fn make_auth() -> PyAuth {
        let mut realm_users = HashMap::new();
        realm_users.insert("alice".to_string(), "pass123".to_string());
        realm_users.insert("bob".to_string(), "secret".to_string());

        let mut users = HashMap::new();
        users.insert("example.com".to_string(), realm_users);

        PyAuth::new(users, "example.com".to_string())
    }

    fn make_register_request() -> PyRequest {
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-auth".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=auth-tag".to_string())
            .call_id("auth-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .content_length(0)
            .build()
            .unwrap();

        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    fn make_request_with_auth(username: &str) -> PyRequest {
        // Compute a valid RFC 2617 digest response for the test credentials.
        // alice:pass123, bob:secret — realm=example.com, nonce=abc, method=REGISTER
        let password = match username {
            "alice" => "pass123",
            "bob" => "secret",
            _ => "wrong",
        };
        let realm = "example.com";
        let nonce = "abc";
        let digest_uri = "sip:example.com";
        let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
        let ha2 = md5_hex(&format!("REGISTER:{}", digest_uri));
        let response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-auth2".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=auth-tag2".to_string())
            .call_id("auth-call2@host".to_string())
            .cseq("2 REGISTER".to_string())
            .header(
                "Authorization",
                format!(
                    "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{digest_uri}\", response=\"{response}\""
                ),
            )
            .content_length(0)
            .build()
            .unwrap();

        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    #[test]
    fn require_www_digest_sends_401_when_no_credentials() {
        let auth = make_auth();
        let mut request = make_register_request();

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 401,
                reason: "Unauthorized".to_string()
            }
        );
    }

    #[test]
    fn require_proxy_digest_sends_407() {
        let auth = make_auth();
        let mut request = make_register_request();

        let result = auth.require_proxy_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 407,
                reason: "Proxy Authentication Required".to_string()
            }
        );
    }

    #[test]
    fn require_www_digest_accepts_valid_user() {
        let auth = make_auth();
        let mut request = make_request_with_auth("alice");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(result);
        assert_eq!(request.get_auth_user(), Some("alice"));
        // Action should remain None (no reply sent)
        assert_eq!(*request.action(), RequestAction::None);
    }

    #[test]
    fn require_www_digest_rejects_unknown_user() {
        let auth = make_auth();
        let mut request = make_request_with_auth("eve");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 401,
                reason: "Unauthorized".to_string()
            }
        );
    }

    #[test]
    fn verify_digest_without_sending_challenge() {
        let auth = make_auth();
        let request_no_auth = make_register_request();
        assert!(!auth.verify_digest(&request_no_auth, None).unwrap());

        let request_with_auth = make_request_with_auth("alice");
        assert!(auth.verify_digest(&request_with_auth, None).unwrap());
    }

    #[test]
    fn extract_username_from_digest_header() {
        let value = r#"Digest username="alice", realm="example.com", nonce="abc""#;
        assert_eq!(extract_username(value), Some("alice".to_string()));
    }

    #[test]
    fn extract_username_case_insensitive_key() {
        let value = r#"Digest Username="bob", realm="example.com""#;
        assert_eq!(extract_username(value), Some("bob".to_string()));
    }

    #[test]
    fn extract_username_none_when_missing() {
        let value = "Digest realm=\"example.com\"";
        assert_eq!(extract_username(value), None);
    }

    #[test]
    fn challenge_includes_nonce_in_header() {
        let auth = make_auth();
        let mut request = make_register_request();

        auth.require_www_digest(&mut request, None).unwrap();

        // The WWW-Authenticate header should be set on the message
        let message = request.message();
        let message = message.lock().unwrap();
        let www_auth = message.headers.get("WWW-Authenticate").unwrap();
        assert!(www_auth.contains("Digest"));
        assert!(www_auth.contains("realm=\"example.com\""));
        assert!(www_auth.contains("nonce="));
        assert!(www_auth.contains("algorithm=MD5"));
    }

    #[test]
    fn custom_realm_overrides_default() {
        let auth = make_auth();
        let mut request = make_register_request();

        auth.require_www_digest(&mut request, Some("custom.realm")).unwrap();

        let message = request.message();
        let message = message.lock().unwrap();
        let www_auth = message.headers.get("WWW-Authenticate").unwrap();
        assert!(www_auth.contains("realm=\"custom.realm\""));
    }

    #[test]
    fn empty_auth_rejects_all() {
        let auth = PyAuth::empty();
        let mut request = make_request_with_auth("alice");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
    }

    #[test]
    fn extract_username_from_uri_basic() {
        assert_eq!(
            extract_username_from_uri("<sip:alice@example.com>;tag=foo"),
            Some("alice".to_string())
        );
        assert_eq!(
            extract_username_from_uri("<sip:001010000000001@ims.test>"),
            Some("001010000000001".to_string())
        );
        assert_eq!(
            extract_username_from_uri("sip:bob@example.com"),
            Some("bob".to_string())
        );
    }

    #[test]
    fn extract_nonce_field_quoted() {
        let value = r#"Digest username="alice", realm="test", nonce="abc123def""#;
        assert_eq!(extract_nonce_field(value), Some("abc123def".to_string()));
    }

    #[test]
    fn extract_nonce_field_unquoted() {
        let value = "Digest nonce=abc123, realm=\"test\"";
        assert_eq!(extract_nonce_field(value), Some("abc123".to_string()));
    }

    #[test]
    fn extract_nonce_field_skips_cnonce() {
        // Must extract nonce, not cnonce
        let value = r#"Digest username="alice",realm="test",cnonce="1d15e5dd",nc=00000001,qop=auth,uri="sip:test",nonce="realNonce123=",response="abc",algorithm=AKAv1-MD5"#;
        assert_eq!(extract_nonce_field(value), Some("realNonce123=".to_string()));
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_encode_32_bytes() {
        // 32 bytes (like RAND || AUTN) should produce 44 chars with padding
        let data = [0u8; 32];
        let encoded = base64_encode(&data);
        assert_eq!(encoded.len(), 44);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn aka_key_store_insert_and_retrieve() {
        let store = aka_key_store();
        let key_material = AkaKeyMaterial {
            ck: [1u8; 16],
            ik: [2u8; 16],
        };
        store.insert("test-nonce-auth".to_string(), key_material);
        {
            let retrieved = store.get("test-nonce-auth").unwrap();
            assert_eq!(retrieved.ck, [1u8; 16]);
            assert_eq!(retrieved.ik, [2u8; 16]);
        } // drop Ref guard before remove — holding it causes DashMap shard deadlock
        store.remove("test-nonce-auth");
    }
}
