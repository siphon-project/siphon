//! IPsec SA management for P-CSCF (3GPP TS 33.203).
//!
//! Manages IPsec Security Associations (SAs) and Security Policies (SPs)
//! for IMS UE registration. Uses Linux xfrm via the `ip` command.

pub mod milenage;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Encryption algorithm
// ---------------------------------------------------------------------------

/// Encryption algorithm for IPsec SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// NULL encryption (integrity-only).
    Null,
    /// AES-CBC with 128-bit key.
    AesCbc128,
    /// DES-EDE3-CBC (3DES).
    DesEde3Cbc,
}

impl EncryptionAlgorithm {
    /// Return the `ip xfrm` algorithm name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            Self::Null => "ecb(cipher_null)",
            Self::AesCbc128 => "aes",
            Self::DesEde3Cbc => "des3_ede",
        }
    }

    /// Key length in bytes.
    pub fn key_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::AesCbc128 => 16,
            Self::DesEde3Cbc => 24,
        }
    }
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(formatter, "NULL"),
            Self::AesCbc128 => write!(formatter, "AES-CBC-128"),
            Self::DesEde3Cbc => write!(formatter, "DES-EDE3-CBC"),
        }
    }
}

// ---------------------------------------------------------------------------
// Integrity algorithm
// ---------------------------------------------------------------------------

/// Integrity algorithm for IPsec SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    /// HMAC-MD5-96.
    HmacMd5,
    /// HMAC-SHA-1-96.
    HmacSha1,
}

impl IntegrityAlgorithm {
    /// Return the `ip xfrm` algorithm name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            Self::HmacMd5 => "hmac(md5)",
            Self::HmacSha1 => "hmac(sha1)",
        }
    }

    /// Key length in bytes.
    pub fn key_length(&self) -> usize {
        match self {
            Self::HmacMd5 => 16,
            Self::HmacSha1 => 20,
        }
    }
}

impl std::fmt::Display for IntegrityAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacMd5 => write!(formatter, "HMAC-MD5-96"),
            Self::HmacSha1 => write!(formatter, "HMAC-SHA-1-96"),
        }
    }
}

// ---------------------------------------------------------------------------
// Security Association pair
// ---------------------------------------------------------------------------

/// IPsec SAs for a UE registration (4 SAs per 3GPP TS 33.203 §7.1).
///
/// The four SAs cover two port pairs (client and server) in both directions:
/// 1. UE:port_uc → PCSCF:port_ps, SPI=spi_ps (UE sends requests to P-CSCF server)
/// 2. PCSCF:port_ps → UE:port_uc, SPI=spi_uc (P-CSCF replies from server port)
/// 3. PCSCF:port_pc → UE:port_us, SPI=spi_us (P-CSCF sends requests from client port)
/// 4. UE:port_us → PCSCF:port_pc, SPI=spi_pc (UE replies to P-CSCF client port)
#[derive(Debug, Clone)]
pub struct SecurityAssociationPair {
    /// UE IP address.
    pub ue_addr: IpAddr,
    /// P-CSCF IP address.
    pub pcscf_addr: IpAddr,
    /// UE client port (from Security-Client).
    pub ue_port_c: u16,
    /// UE server port (from Security-Client).
    pub ue_port_s: u16,
    /// P-CSCF protected client port.
    pub pcscf_port_c: u16,
    /// P-CSCF protected server port.
    pub pcscf_port_s: u16,
    /// UE client SPI (from Security-Client spi-c).
    pub spi_uc: u32,
    /// UE server SPI (from Security-Client spi-s).
    pub spi_us: u32,
    /// P-CSCF client SPI (allocated by P-CSCF, in Security-Server spi-c).
    pub spi_pc: u32,
    /// P-CSCF server SPI (allocated by P-CSCF, in Security-Server spi-s).
    pub spi_ps: u32,
    /// Encryption algorithm.
    pub ealg: EncryptionAlgorithm,
    /// Integrity algorithm.
    pub aalg: IntegrityAlgorithm,
    /// Encryption key (hex-encoded for ip xfrm).
    pub encryption_key: String,
    /// Integrity key (hex-encoded for ip xfrm).
    pub integrity_key: String,
}

// ---------------------------------------------------------------------------
// Security-Client header (3GPP TS 33.203)
// ---------------------------------------------------------------------------

/// Parsed Security-Client header (3GPP TS 33.203).
///
/// Example header value:
/// ```text
/// ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062
/// ```
#[derive(Debug, Clone)]
pub struct SecurityClient {
    /// Security mechanism, e.g. `"ipsec-3gpp"`.
    pub mechanism: String,
    /// Integrity algorithm, e.g. `"hmac-md5-96"` or `"hmac-sha-1-96"`.
    pub algorithm: String,
    /// Client SPI proposed by the UE.
    pub spi_c: u32,
    /// Server SPI proposed by the UE.
    pub spi_s: u32,
    /// Client port proposed by the UE.
    pub port_c: u16,
    /// Server port proposed by the UE.
    pub port_s: u16,
    /// Optional encryption algorithm, e.g. `"aes-cbc"`.
    pub ealg: Option<String>,
}

/// Parse a Security-Client header value.
///
/// Expects a semicolon-separated list of parameters following the mechanism name.
/// Returns `None` if the header is malformed or missing required parameters.
///
/// # Example
///
/// ```
/// use siphon::ipsec::parse_security_client;
///
/// let header = "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062";
/// let parsed = parse_security_client(header).unwrap();
/// assert_eq!(parsed.mechanism, "ipsec-3gpp");
/// assert_eq!(parsed.spi_c, 11111);
/// ```
pub fn parse_security_client(header: &str) -> Option<SecurityClient> {
    let parts: Vec<&str> = header.split(';').map(|part| part.trim()).collect();
    if parts.is_empty() {
        return None;
    }

    let mechanism = parts[0].to_string();
    let mut algorithm = None;
    let mut spi_c = None;
    let mut spi_s = None;
    let mut port_c = None;
    let mut port_s = None;
    let mut ealg = None;

    for part in &parts[1..] {
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "alg" => algorithm = Some(value.to_string()),
                "spi-c" => spi_c = value.parse().ok(),
                "spi-s" => spi_s = value.parse().ok(),
                "port-c" => port_c = value.parse().ok(),
                "port-s" => port_s = value.parse().ok(),
                "ealg" => ealg = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some(SecurityClient {
        mechanism,
        algorithm: algorithm?,
        spi_c: spi_c?,
        spi_s: spi_s?,
        port_c: port_c?,
        port_s: port_s?,
        ealg,
    })
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from IPsec SA management.
#[derive(Debug)]
pub enum IpsecError {
    /// `ip xfrm` command failed.
    Command(String),
    /// Invalid key material.
    InvalidKey(String),
}

impl std::fmt::Display for IpsecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(message) => write!(formatter, "IPsec command error: {}", message),
            Self::InvalidKey(message) => write!(formatter, "IPsec invalid key: {}", message),
        }
    }
}

impl std::error::Error for IpsecError {}

// ---------------------------------------------------------------------------
// IPsec Manager
// ---------------------------------------------------------------------------

/// Manages active IPsec SAs for UE registrations.
///
/// Each UE registration that negotiates IPsec (via Security-Client/Security-Server
/// headers) gets a pair of SAs: one inbound (UE -> P-CSCF) and one outbound
/// (P-CSCF -> UE). The manager tracks these pairs and creates/deletes the
/// corresponding Linux xfrm state and policies via `ip xfrm` commands.
pub struct IpsecManager {
    /// contact_key (e.g. "ue_ip:ue_port") -> SA pair.
    associations: DashMap<String, SecurityAssociationPair>,
    /// SPI counter for generating unique SPIs.
    next_spi: AtomicU32,
}

impl Default for IpsecManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpsecManager {
    /// Create a new IPsec manager with no active SAs.
    pub fn new() -> Self {
        Self {
            associations: DashMap::new(),
            // Start SPIs above well-known range.
            next_spi: AtomicU32::new(10000),
        }
    }

    /// Generate a unique SPI pair (inbound, outbound).
    pub fn allocate_spi_pair(&self) -> (u32, u32) {
        let spi1 = self.next_spi.fetch_add(2, Ordering::Relaxed);
        (spi1, spi1 + 1)
    }

    /// Contact key for looking up SAs.
    fn contact_key(ue_addr: &IpAddr, ue_port_c: u16) -> String {
        format!("{}:{}", ue_addr, ue_port_c)
    }

    /// Create IPsec SAs and SPs for a UE registration.
    ///
    /// Per 3GPP TS 33.203 §7.1, creates 4 SAs and 4 policies:
    /// 1. UE:port_uc → PCSCF:port_ps, SPI=spi_ps (inbound requests)
    /// 2. PCSCF:port_ps → UE:port_uc, SPI=spi_uc (outbound replies)
    /// 3. PCSCF:port_pc → UE:port_us, SPI=spi_us (outbound requests)
    /// 4. UE:port_us → PCSCF:port_pc, SPI=spi_pc (inbound replies)
    pub async fn create_sa_pair(
        &self,
        sa: SecurityAssociationPair,
    ) -> Result<(), IpsecError> {
        let key = Self::contact_key(&sa.ue_addr, sa.ue_port_c);

        // SA1: UE:port_uc → PCSCF:port_ps, SPI=spi_ps (inbound to P-CSCF server)
        Self::xfrm_sa_add(
            &sa.ue_addr, sa.ue_port_c,
            &sa.pcscf_addr, sa.pcscf_port_s,
            sa.spi_ps,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
        ).await?;

        // SA2: PCSCF:port_ps → UE:port_uc, SPI=spi_uc (outbound from P-CSCF server)
        Self::xfrm_sa_add(
            &sa.pcscf_addr, sa.pcscf_port_s,
            &sa.ue_addr, sa.ue_port_c,
            sa.spi_uc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
        ).await?;

        // SA3: PCSCF:port_pc → UE:port_us, SPI=spi_us (outbound from P-CSCF client)
        Self::xfrm_sa_add(
            &sa.pcscf_addr, sa.pcscf_port_c,
            &sa.ue_addr, sa.ue_port_s,
            sa.spi_us,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
        ).await?;

        // SA4: UE:port_us → PCSCF:port_pc, SPI=spi_pc (inbound to P-CSCF client)
        Self::xfrm_sa_add(
            &sa.ue_addr, sa.ue_port_s,
            &sa.pcscf_addr, sa.pcscf_port_c,
            sa.spi_pc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
        ).await?;

        // Policy 1 (in): UE:port_uc → PCSCF:port_ps
        Self::xfrm_policy_add(
            &sa.ue_addr, sa.ue_port_c,
            &sa.pcscf_addr, sa.pcscf_port_s,
            "in", sa.spi_ps,
        ).await?;

        // Policy 2 (out): PCSCF:port_ps → UE:port_uc
        Self::xfrm_policy_add(
            &sa.pcscf_addr, sa.pcscf_port_s,
            &sa.ue_addr, sa.ue_port_c,
            "out", sa.spi_uc,
        ).await?;

        // Policy 3 (out): PCSCF:port_pc → UE:port_us
        Self::xfrm_policy_add(
            &sa.pcscf_addr, sa.pcscf_port_c,
            &sa.ue_addr, sa.ue_port_s,
            "out", sa.spi_us,
        ).await?;

        // Policy 4 (in): UE:port_us → PCSCF:port_pc
        Self::xfrm_policy_add(
            &sa.ue_addr, sa.ue_port_s,
            &sa.pcscf_addr, sa.pcscf_port_c,
            "in", sa.spi_pc,
        ).await?;

        info!(
            ue = %sa.ue_addr,
            ue_port_c = sa.ue_port_c,
            spi_uc = sa.spi_uc,
            spi_us = sa.spi_us,
            spi_pc = sa.spi_pc,
            spi_ps = sa.spi_ps,
            "IPsec: SA pair created"
        );

        self.associations.insert(key, sa);
        Ok(())
    }

    /// Delete IPsec SAs and SPs for a UE.
    pub async fn delete_sa_pair(
        &self,
        ue_addr: &IpAddr,
        ue_port_c: u16,
    ) -> Result<(), IpsecError> {
        let key = Self::contact_key(ue_addr, ue_port_c);
        if let Some((_, sa)) = self.associations.remove(&key) {
            // Delete all 4 SAs.
            Self::xfrm_sa_del(&sa.ue_addr, &sa.pcscf_addr, sa.spi_ps).await?;
            Self::xfrm_sa_del(&sa.pcscf_addr, &sa.ue_addr, sa.spi_uc).await?;
            Self::xfrm_sa_del(&sa.pcscf_addr, &sa.ue_addr, sa.spi_us).await?;
            Self::xfrm_sa_del(&sa.ue_addr, &sa.pcscf_addr, sa.spi_pc).await?;

            // Delete policies (best-effort — ignore errors on cleanup).
            Self::xfrm_policy_del(
                &sa.ue_addr,
                sa.ue_port_c,
                &sa.pcscf_addr,
                sa.pcscf_port_s,
                "in",
            )
            .await
            .ok();
            Self::xfrm_policy_del(
                &sa.pcscf_addr,
                sa.pcscf_port_c,
                &sa.ue_addr,
                sa.ue_port_s,
                "out",
            )
            .await
            .ok();
            Self::xfrm_policy_del(
                &sa.ue_addr,
                sa.ue_port_s,
                &sa.pcscf_addr,
                sa.pcscf_port_c,
                "in",
            )
            .await
            .ok();
            Self::xfrm_policy_del(
                &sa.pcscf_addr,
                sa.pcscf_port_s,
                &sa.ue_addr,
                sa.ue_port_c,
                "out",
            )
            .await
            .ok();

            info!(ue = %ue_addr, ue_port_c, "IPsec: SA pair deleted");
        }
        Ok(())
    }

    /// Number of active SA pairs.
    pub fn active_count(&self) -> usize {
        self.associations.len()
    }

    /// Check if a UE has an active SA pair.
    pub fn has_sa(&self, ue_addr: &IpAddr, ue_port_c: u16) -> bool {
        self.associations
            .contains_key(&Self::contact_key(ue_addr, ue_port_c))
    }

    /// Get the SA pair for a UE (for inspection/logging).
    pub fn get_sa(
        &self,
        ue_addr: &IpAddr,
        ue_port_c: u16,
    ) -> Option<SecurityAssociationPair> {
        self.associations
            .get(&Self::contact_key(ue_addr, ue_port_c))
            .map(|entry| entry.value().clone())
    }

    // -----------------------------------------------------------------------
    // xfrm command helpers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn xfrm_sa_add(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        spi: u32,
        ealg: &EncryptionAlgorithm,
        aalg: &IntegrityAlgorithm,
        encryption_key: &str,
        integrity_key: &str,
    ) -> Result<(), IpsecError> {
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);
        let sel_src = format!("{}/32", source);
        let sel_dst = format!("{}/32", destination);
        let sel_sport = source_port.to_string();
        let sel_dport = destination_port.to_string();

        let mut args = vec![
            "xfrm", "state", "add",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
            "mode", "transport",
            "sel",
            "src", &sel_src,
            "dst", &sel_dst,
            "sport", &sel_sport,
            "dport", &sel_dport,
            "proto", "udp",
        ];

        let enc_key_hex = format!("0x{}", encryption_key);
        // HMAC-SHA1-96 requires 160-bit (20-byte) key; IK from Milenage is 128-bit (16 bytes).
        // Zero-pad to 20 bytes as per 3GPP TS 33.203 / sipp_ipsec convention.
        let int_key_hex = if *aalg == IntegrityAlgorithm::HmacSha1 && integrity_key.len() == 32 {
            format!("0x{}00000000", integrity_key)
        } else {
            format!("0x{}", integrity_key)
        };

        // ESP always requires an enc algorithm — use ecb(cipher_null) with empty key for null
        args.push("enc");
        args.push(ealg.xfrm_name());
        if *ealg != EncryptionAlgorithm::Null {
            args.push(&enc_key_hex);
        } else {
            args.push("");
        }
        args.push("auth");
        args.push(aalg.xfrm_name());
        args.push(&int_key_hex);

        Self::run_ip_command(&args).await
    }

    async fn xfrm_sa_del(
        source: &IpAddr,
        destination: &IpAddr,
        spi: u32,
    ) -> Result<(), IpsecError> {
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);

        let args = vec![
            "xfrm", "state", "delete",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
        ];
        Self::run_ip_command(&args).await
    }

    async fn xfrm_policy_add(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: &str,
        spi: u32,
    ) -> Result<(), IpsecError> {
        let source_cidr = format!("{}/32", source);
        let destination_cidr = format!("{}/32", destination);
        let source_port_str = source_port.to_string();
        let destination_port_str = destination_port.to_string();
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);

        let args = vec![
            "xfrm", "policy", "add",
            "src", &source_cidr,
            "dst", &destination_cidr,
            "sport", &source_port_str,
            "dport", &destination_port_str,
            "proto", "udp",
            "dir", direction,
            "tmpl",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
            "mode", "transport",
        ];
        Self::run_ip_command(&args).await
    }

    async fn xfrm_policy_del(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: &str,
    ) -> Result<(), IpsecError> {
        let source_cidr = format!("{}/32", source);
        let destination_cidr = format!("{}/32", destination);
        let source_port_str = source_port.to_string();
        let destination_port_str = destination_port.to_string();

        let args = vec![
            "xfrm", "policy", "delete",
            "src", &source_cidr,
            "dst", &destination_cidr,
            "sport", &source_port_str,
            "dport", &destination_port_str,
            "proto", "udp",
            "dir", direction,
        ];
        Self::run_ip_command(&args).await
    }

    async fn run_ip_command(args: &[&str]) -> Result<(), IpsecError> {
        debug!(cmd = %args.join(" "), "IPsec: running ip command");
        let output = tokio::process::Command::new("ip")
            .args(args)
            .output()
            .await
            .map_err(|error| {
                IpsecError::Command(format!("failed to run ip: {}", error))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(IpsecError::Command(format!(
                "ip {} failed (exit {}): {}",
                args.get(1).copied().unwrap_or(""),
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn encryption_algorithm_xfrm_names() {
        assert_eq!(EncryptionAlgorithm::Null.xfrm_name(), "ecb(cipher_null)");
        assert_eq!(EncryptionAlgorithm::AesCbc128.xfrm_name(), "aes");
        assert_eq!(EncryptionAlgorithm::DesEde3Cbc.xfrm_name(), "des3_ede");
    }

    #[test]
    fn encryption_algorithm_key_lengths() {
        assert_eq!(EncryptionAlgorithm::Null.key_length(), 0);
        assert_eq!(EncryptionAlgorithm::AesCbc128.key_length(), 16);
        assert_eq!(EncryptionAlgorithm::DesEde3Cbc.key_length(), 24);
    }

    #[test]
    fn integrity_algorithm_xfrm_names() {
        assert_eq!(IntegrityAlgorithm::HmacMd5.xfrm_name(), "hmac(md5)");
        assert_eq!(IntegrityAlgorithm::HmacSha1.xfrm_name(), "hmac(sha1)");
    }

    #[test]
    fn integrity_algorithm_key_lengths() {
        assert_eq!(IntegrityAlgorithm::HmacMd5.key_length(), 16);
        assert_eq!(IntegrityAlgorithm::HmacSha1.key_length(), 20);
    }

    #[test]
    fn allocate_spi_pair_unique() {
        let manager = IpsecManager::new();
        let (spi1_a, spi1_b) = manager.allocate_spi_pair();
        let (spi2_a, spi2_b) = manager.allocate_spi_pair();

        // Each pair is consecutive.
        assert_eq!(spi1_b, spi1_a + 1);
        assert_eq!(spi2_b, spi2_a + 1);

        // Pairs do not overlap.
        assert_ne!(spi1_a, spi2_a);
        assert_ne!(spi1_b, spi2_b);
        assert_eq!(spi2_a, spi1_a + 2);
    }

    #[test]
    fn allocate_spi_pair_starts_above_well_known_range() {
        let manager = IpsecManager::new();
        let (spi_a, _) = manager.allocate_spi_pair();
        assert!(spi_a >= 10000);
    }

    #[test]
    fn contact_key_format() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let key = IpsecManager::contact_key(&addr, 5060);
        assert_eq!(key, "10.0.0.1:5060");
    }

    #[test]
    fn contact_key_format_ipv6() {
        let addr: IpAddr = "::1".parse().unwrap();
        let key = IpsecManager::contact_key(&addr, 5060);
        assert_eq!(key, "::1:5060");
    }

    #[test]
    fn manager_new_empty() {
        let manager = IpsecManager::new();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn has_sa_false_initially() {
        let manager = IpsecManager::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(!manager.has_sa(&addr, 5060));
    }

    #[test]
    fn get_sa_none_initially() {
        let manager = IpsecManager::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(manager.get_sa(&addr, 5060).is_none());
    }

    #[test]
    fn parse_security_client_basic() {
        let header = concat!(
            "ipsec-3gpp; alg=hmac-sha-1-96; ",
            "spi-c=11111; spi-s=22222; ",
            "port-c=5060; port-s=5062"
        );
        let parsed = parse_security_client(header).unwrap();
        assert_eq!(parsed.mechanism, "ipsec-3gpp");
        assert_eq!(parsed.algorithm, "hmac-sha-1-96");
        assert_eq!(parsed.spi_c, 11111);
        assert_eq!(parsed.spi_s, 22222);
        assert_eq!(parsed.port_c, 5060);
        assert_eq!(parsed.port_s, 5062);
        assert!(parsed.ealg.is_none());
    }

    #[test]
    fn parse_security_client_with_ealg() {
        let header = concat!(
            "ipsec-3gpp; alg=hmac-md5-96; ealg=aes-cbc; ",
            "spi-c=33333; spi-s=44444; ",
            "port-c=6060; port-s=6062"
        );
        let parsed = parse_security_client(header).unwrap();
        assert_eq!(parsed.mechanism, "ipsec-3gpp");
        assert_eq!(parsed.algorithm, "hmac-md5-96");
        assert_eq!(parsed.spi_c, 33333);
        assert_eq!(parsed.spi_s, 44444);
        assert_eq!(parsed.port_c, 6060);
        assert_eq!(parsed.port_s, 6062);
        assert_eq!(parsed.ealg.as_deref(), Some("aes-cbc"));
    }

    #[test]
    fn parse_security_client_missing_required_field() {
        // Missing spi-s — should return None.
        let header = "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; port-c=5060; port-s=5062";
        assert!(parse_security_client(header).is_none());
    }

    #[test]
    fn parse_security_client_empty() {
        assert!(parse_security_client("").is_none());
    }

    #[test]
    fn parse_security_client_no_alg() {
        let header = "ipsec-3gpp; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062";
        assert!(parse_security_client(header).is_none());
    }

    #[test]
    fn encryption_algorithm_display() {
        assert_eq!(format!("{}", EncryptionAlgorithm::Null), "NULL");
        assert_eq!(format!("{}", EncryptionAlgorithm::AesCbc128), "AES-CBC-128");
        assert_eq!(
            format!("{}", EncryptionAlgorithm::DesEde3Cbc),
            "DES-EDE3-CBC"
        );
    }

    #[test]
    fn integrity_algorithm_display() {
        assert_eq!(format!("{}", IntegrityAlgorithm::HmacMd5), "HMAC-MD5-96");
        assert_eq!(
            format!("{}", IntegrityAlgorithm::HmacSha1),
            "HMAC-SHA-1-96"
        );
    }

    #[test]
    fn ipsec_error_display() {
        let command_error = IpsecError::Command("something broke".to_string());
        assert_eq!(
            format!("{}", command_error),
            "IPsec command error: something broke"
        );

        let key_error = IpsecError::InvalidKey("bad hex".to_string());
        assert_eq!(
            format!("{}", key_error),
            "IPsec invalid key: bad hex"
        );
    }

    #[test]
    fn security_association_pair_clone() {
        let sa = SecurityAssociationPair {
            ue_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            pcscf_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ue_port_c: 5060,
            ue_port_s: 5062,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 10000,
            spi_us: 10001,
            spi_pc: 10002,
            spi_ps: 10003,
            ealg: EncryptionAlgorithm::AesCbc128,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: "deadbeef".to_string(),
            integrity_key: "cafebabe".to_string(),
        };
        let cloned = sa.clone();
        assert_eq!(cloned.spi_uc, 10000);
        assert_eq!(cloned.spi_us, 10001);
        assert_eq!(cloned.spi_pc, 10002);
        assert_eq!(cloned.spi_ps, 10003);
        assert_eq!(cloned.ealg, EncryptionAlgorithm::AesCbc128);
        assert_eq!(cloned.aalg, IntegrityAlgorithm::HmacSha1);
    }
}
