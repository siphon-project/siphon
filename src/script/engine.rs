//! Script engine — compiles Python scripts once at startup, caches callable
//! references, and hot-reloads on file change via inotify.
//!
//! # Design
//!
//! The engine holds a `ScriptState` behind an `ArcSwap` so readers (the SIP
//! hot path) never block while a reload is in progress. On file change:
//!   1. Read the new source from disk
//!   2. Compile + execute in a fresh Python module (populates decorator registry)
//!   3. Atomically swap the `ScriptState` pointer
//!
//! Python is initialised once via `Python::initialize()`.
//! With free-threaded Python 3.14t there is no GIL — multiple Rust worker
//! threads can call into Python concurrently.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use tracing::{debug, error, info, warn};

use crate::config::{ReloadMode, ScriptConfig};
use crate::error::{Result, SiphonError};

// ---------------------------------------------------------------------------
// Handler kind — each decorator type maps to one variant
// ---------------------------------------------------------------------------

/// Identifies which SIP event a registered Python handler listens for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HandlerKind {
    /// `@proxy.on_request` — optional method filter (None = all methods).
    ProxyRequest(Option<String>),
    /// `@proxy.on_reply` — intercept responses.
    ProxyReply,
    /// `@proxy.on_failure` — all branches failed.
    ProxyFailure,
    /// `@proxy.on_register_reply` — REGISTER-specific reply handler.
    ProxyRegisterReply,
    /// `@b2bua.on_invite`
    B2buaInvite,
    /// `@b2bua.on_answer`
    B2buaAnswer,
    /// `@b2bua.on_failure`
    B2buaFailure,
    /// `@b2bua.on_bye`
    B2buaBye,
    /// `@b2bua.on_refer` — call transfer (RFC 3515).
    B2buaRefer,
    /// `@registrar.on_change` — registration state change callback.
    RegistrarOnChange,
}

// ---------------------------------------------------------------------------
// Handler entry
// ---------------------------------------------------------------------------

/// A single registered Python callback.
#[derive(Debug, Clone)]
pub struct HandlerEntry {
    pub kind: HandlerKind,
    /// The Python callable (function / coroutine function).
    pub callable: Py<PyAny>,
    /// `true` when `asyncio.iscoroutinefunction(callable)` returned `True`.
    pub is_async: bool,
}

// ---------------------------------------------------------------------------
// Script state — the atomically-swapped payload
// ---------------------------------------------------------------------------

/// Immutable snapshot of a compiled script's handler registrations.
/// Replaced atomically on hot-reload.
#[derive(Debug)]
pub struct ScriptState {
    /// Path the script was loaded from.
    pub source_path: PathBuf,
    /// All registered handlers, keyed by kind.
    pub handlers: Vec<HandlerEntry>,
}

impl ScriptState {
    /// Return all handlers that match the given kind.
    pub fn handlers_for(&self, kind: &HandlerKind) -> Vec<&HandlerEntry> {
        self.handlers.iter().filter(|h| &h.kind == kind).collect()
    }

    /// Return all `ProxyRequest` handlers whose method filter matches `method`.
    /// A handler with `None` filter matches everything.
    pub fn proxy_request_handlers(&self, method: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::ProxyRequest(None) => true,
                HandlerKind::ProxyRequest(Some(filter)) => {
                    filter.split('|').any(|m| m == method)
                }
                _ => false,
            })
            .collect()
    }

    /// Whether the script registered any B2BUA handlers.
    pub fn has_b2bua_handlers(&self) -> bool {
        self.handlers.iter().any(|h| matches!(
            h.kind,
            HandlerKind::B2buaInvite
                | HandlerKind::B2buaAnswer
                | HandlerKind::B2buaFailure
                | HandlerKind::B2buaBye
                | HandlerKind::B2buaRefer
        ))
    }
}

// ---------------------------------------------------------------------------
// Script engine
// ---------------------------------------------------------------------------

/// The script engine manages Python initialisation, script compilation,
/// hot-reload watching, and the handler registry.
pub struct ScriptEngine {
    /// Atomically-swappable current script state.
    state: Arc<ArcSwap<ScriptState>>,
    /// Script file path (from config).
    script_path: PathBuf,
    /// Reload mode (auto = inotify, sighup = manual).
    reload_mode: ReloadMode,
}

impl ScriptEngine {
    /// Create and initialise the engine.
    ///
    /// 1. Initialise the Python interpreter (idempotent).
    /// 2. Register the `siphon` built-in module so scripts can `from siphon import ...`.
    /// 3. Compile and execute the configured script.
    /// 4. Extract registered handlers from the decorator registry.
    pub fn new(config: &ScriptConfig) -> Result<Self> {
        let script_path = PathBuf::from(&config.path);

        // Ensure the script file exists before we initialise Python.
        if !script_path.exists() {
            return Err(SiphonError::Script(format!(
                "script not found: {}",
                script_path.display()
            )));
        }

        // Initialise the free-threaded Python interpreter (no-op if already done).
        Python::initialize();

        let state = Self::compile_script(&script_path)?;

        info!(
            path = %script_path.display(),
            handlers = state.handlers.len(),
            "script loaded"
        );

        let state = Arc::new(ArcSwap::from_pointee(state));

        Ok(Self {
            state,
            script_path,
            reload_mode: config.reload.clone(),
        })
    }

    /// Get a snapshot of the current script state.
    /// This is cheap — just an `Arc` clone.
    pub fn state(&self) -> arc_swap::Guard<Arc<ScriptState>> {
        self.state.load()
    }

    /// Reload the script from disk and atomically swap the state.
    /// Called by the file watcher or on SIGHUP.
    pub fn reload(&self) -> Result<()> {
        info!(path = %self.script_path.display(), "reloading script");

        match Self::compile_script(&self.script_path) {
            Ok(new_state) => {
                info!(
                    handlers = new_state.handlers.len(),
                    "script reloaded successfully"
                );
                self.state.store(Arc::new(new_state));
                Ok(())
            }
            Err(error) => {
                // Keep the old state on failure — never leave the engine without handlers.
                error!(%error, "script reload failed, keeping previous version");
                Err(error)
            }
        }
    }

    /// Whether auto-reload (inotify) is configured.
    pub fn auto_reload(&self) -> bool {
        self.reload_mode == ReloadMode::Auto
    }

    /// The path being watched.
    pub fn script_path(&self) -> &Path {
        &self.script_path
    }

    // -----------------------------------------------------------------------
    // Internal: compile + extract handlers
    // -----------------------------------------------------------------------

    /// Read, compile, and execute a Python script file. Returns the extracted
    /// handler registrations.
    fn compile_script(path: &Path) -> Result<ScriptState> {
        let source = std::fs::read_to_string(path).map_err(|error| {
            SiphonError::Script(format!("cannot read {}: {error}", path.display()))
        })?;

        Python::attach(|python| {
            Self::compile_source(python, path, &source)
        })
    }

    /// Compile source code and extract handlers. Runs inside `Python::attach`.
    fn compile_source(
        python: Python<'_>,
        path: &Path,
        source: &str,
    ) -> Result<ScriptState> {
        // Create (or get) the registry module first — siphon_package.py imports it.
        let registry_module = get_or_create_registry(python)?;

        // Ensure the siphon package is installed in sys.modules.
        super::api::install_siphon_module(python)?;

        // Clear the handler registry before executing the script.
        let clear_fn = registry_module
            .getattr("clear")
            .map_err(|error| SiphonError::Script(format!("registry.clear: {error}")))?;
        clear_fn
            .call0()
            .map_err(|error| SiphonError::Script(format!("registry.clear(): {error}")))?;

        // Compile the script into a code object (bytecode).
        let source_cstr = CString::new(source)
            .map_err(|error| SiphonError::Script(format!("source contains null byte: {error}")))?;
        let file_name = CString::new(path.to_str().unwrap_or("<script>"))
            .unwrap_or_else(|_| CString::new("<script>").unwrap());
        let module_name = CString::new("siphon_user_script").unwrap();
        let _code = PyModule::from_code(
            python,
            &source_cstr,
            &file_name,
            &module_name,
        )
        .map_err(|error| {
            SiphonError::Script(format!(
                "compilation failed for {}: {error}",
                path.display()
            ))
        })?;

        // The script has now executed — decorators have registered themselves
        // into the registry module.
        let handlers = extract_handlers(python, &registry_module)?;

        debug!(
            path = %path.display(),
            handler_count = handlers.len(),
            "script compiled and handlers extracted"
        );

        Ok(ScriptState {
            source_path: path.to_owned(),
            handlers,
        })
    }
}

// ---------------------------------------------------------------------------
// File watcher task
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that watches the script file for changes
/// and triggers hot-reload. Returns immediately.
pub fn spawn_file_watcher(engine: Arc<ScriptEngine>) {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    if !engine.auto_reload() {
        info!("script auto-reload disabled (mode: sighup)");
        return;
    }

    let path = engine.script_path().to_owned();

    // `notify` v8 uses std channels for sync, we bridge to tokio via spawn_blocking.
    tokio::task::spawn_blocking(move || {
        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "failed to create file watcher");
                return;
            }
        };

        // Watch the parent directory so we catch renames/recreates
        // (editors like vim write to a temp file then rename).
        let watch_dir = path.parent().unwrap_or(Path::new("."));
        if let Err(error) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            error!(%error, path = %watch_dir.display(), "failed to watch directory");
            return;
        }

        info!(path = %path.display(), "file watcher started");

        let file_name = path.file_name();

        for event in receiver {
            match event {
                Ok(Event {
                    kind: EventKind::Modify(_) | EventKind::Create(_),
                    paths,
                    ..
                }) => {
                    // Only reload if the event is about our specific file.
                    let is_our_file = paths.iter().any(|p| p.file_name() == file_name);
                    if !is_our_file {
                        continue;
                    }

                    // Small debounce — editors sometimes generate multiple events.
                    std::thread::sleep(std::time::Duration::from_millis(50));

                    if let Err(error) = engine.reload() {
                        warn!(%error, "hot-reload failed");
                    }
                }
                Ok(_) => {} // Ignore other event kinds
                Err(error) => {
                    warn!(%error, "file watcher error");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Registry — Python-side handler storage
// ---------------------------------------------------------------------------

/// The registry is a small Python module (`_siphon_registry`) that decorators
/// write into. After script execution we read it from Rust.
///
/// This approach decouples the decorator implementation (pure Python, lives in
/// `src/script/api/`) from the extraction (Rust, here).
fn get_or_create_registry(python: Python<'_>) -> Result<Bound<'_, PyAny>> {
    // Ensure the registry module exists (idempotent).
    super::api::ensure_registry(python)?;

    // Return it from sys.modules.
    let registry = python
        .import("_siphon_registry")
        .map_err(|error| SiphonError::Script(format!("import _siphon_registry: {error}")))?;

    Ok(registry.into_any())
}

/// Read the handlers list from the Python registry and convert to Rust types.
fn extract_handlers(
    _python: Python<'_>,
    registry: &Bound<'_, PyAny>,
) -> Result<Vec<HandlerEntry>> {
    let entries = registry
        .getattr("entries")
        .map_err(|error| SiphonError::Script(format!("registry.entries: {error}")))?
        .call0()
        .map_err(|error| SiphonError::Script(format!("registry.entries(): {error}")))?;

    let mut handlers = Vec::new();

    for item in entries
        .try_iter()
        .map_err(|error| SiphonError::Script(format!("iterate entries: {error}")))?
    {
        let item: Bound<'_, PyAny> =
            item.map_err(|error| SiphonError::Script(format!("entry item: {error}")))?;

        let kind_str: String = item
            .get_item(0)
            .map_err(|error| SiphonError::Script(format!("entry[0]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[0] str: {error}")))?;

        let filter: Option<String> = item
            .get_item(1)
            .ok()
            .and_then(|v: Bound<'_, PyAny>| {
                if v.is_none() { None } else { v.extract().ok() }
            });

        let callable: Py<PyAny> = item
            .get_item(2)
            .map_err(|error| SiphonError::Script(format!("entry[2]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[2] callable: {error}")))?;

        let is_async: bool = item
            .get_item(3)
            .map_err(|error| SiphonError::Script(format!("entry[3]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[3] bool: {error}")))?;

        let kind = match kind_str.as_str() {
            "proxy.on_request" => HandlerKind::ProxyRequest(filter),
            "proxy.on_reply" => HandlerKind::ProxyReply,
            "proxy.on_failure" => HandlerKind::ProxyFailure,
            "proxy.on_register_reply" => HandlerKind::ProxyRegisterReply,
            "b2bua.on_invite" => HandlerKind::B2buaInvite,
            "b2bua.on_answer" => HandlerKind::B2buaAnswer,
            "b2bua.on_failure" => HandlerKind::B2buaFailure,
            "b2bua.on_bye" => HandlerKind::B2buaBye,
            "b2bua.on_refer" => HandlerKind::B2buaRefer,
            "registrar.on_change" => HandlerKind::RegistrarOnChange,
            other => {
                warn!(kind = other, "unknown handler kind, skipping");
                continue;
            }
        };

        handlers.push(HandlerEntry {
            kind,
            callable,
            is_async,
        });
    }

    Ok(handlers)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: write Python source to a temp file and compile it.
    fn compile_temp_script(source: &str) -> Result<ScriptState> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(source.as_bytes()).unwrap();
        file.flush().unwrap();

        Python::initialize();
        ScriptEngine::compile_script(file.path())
    }

    #[test]
    fn empty_script_yields_no_handlers() {
        let state = compile_temp_script("# empty script\npass\n").unwrap();
        assert!(state.handlers.is_empty());
    }

    #[test]
    fn proxy_on_request_decorator_registers_handler() {
        let source = r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyRequest(None));
        assert!(!state.handlers[0].is_async);
    }

    #[test]
    fn proxy_on_request_with_method_filter() {
        let source = r#"
from siphon import proxy

@proxy.on_request("REGISTER")
def handle_register(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(
            state.handlers[0].kind,
            HandlerKind::ProxyRequest(Some("REGISTER".to_owned()))
        );
    }

    #[test]
    fn proxy_on_request_pipe_separated_filter() {
        let source = r#"
from siphon import proxy

@proxy.on_request("INVITE|SUBSCRIBE")
def handle_invite_subscribe(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        let handlers = state.proxy_request_handlers("INVITE");
        assert_eq!(handlers.len(), 1);
        let handlers = state.proxy_request_handlers("SUBSCRIBE");
        assert_eq!(handlers.len(), 1);
        let handlers = state.proxy_request_handlers("REGISTER");
        assert!(handlers.is_empty());
    }

    #[test]
    fn b2bua_decorators_register_correctly() {
        let source = r#"
from siphon import b2bua

@b2bua.on_invite
def new_call(call):
    pass

@b2bua.on_answer
def answered(call):
    pass

@b2bua.on_bye
def ended(call, initiator):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 3);
        assert!(state.handlers_for(&HandlerKind::B2buaInvite).len() == 1);
        assert!(state.handlers_for(&HandlerKind::B2buaAnswer).len() == 1);
        assert!(state.handlers_for(&HandlerKind::B2buaBye).len() == 1);
    }

    #[test]
    fn registrar_on_change_decorator_registers_handler() {
        let source = r#"
from siphon import registrar

@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers_for(&HandlerKind::RegistrarOnChange).len() == 1);
    }

    #[test]
    fn async_handler_detected() {
        let source = r#"
from siphon import proxy

@proxy.on_request
async def route(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers[0].is_async);
    }

    #[test]
    fn syntax_error_returns_script_error() {
        let result = compile_temp_script("def broken(\n");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, SiphonError::Script(_)));
    }

    #[test]
    fn missing_file_returns_error() {
        let config = ScriptConfig {
            path: "/nonexistent/script.py".to_owned(),
            reload: ReloadMode::Auto,
        };
        let result = ScriptEngine::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn reload_swaps_state_atomically() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#
        )
        .unwrap();
        file.flush().unwrap();

        let config = ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: ReloadMode::Auto,
        };
        let engine = ScriptEngine::new(&config).unwrap();
        assert_eq!(engine.state().handlers.len(), 1);

        // Overwrite with a script that has 2 handlers
        let mut file_handle = std::fs::File::create(file.path()).unwrap();
        write!(
            file_handle,
            r#"
from siphon import proxy

@proxy.on_request("REGISTER")
def handle_register(request):
    pass

@proxy.on_request("INVITE")
def handle_invite(request):
    pass
"#
        )
        .unwrap();
        file_handle.flush().unwrap();

        engine.reload().unwrap();
        assert_eq!(engine.state().handlers.len(), 2);
    }

    #[test]
    fn failed_reload_keeps_previous_state() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#
        )
        .unwrap();
        file.flush().unwrap();

        let config = ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: ReloadMode::Auto,
        };
        let engine = ScriptEngine::new(&config).unwrap();
        assert_eq!(engine.state().handlers.len(), 1);

        // Overwrite with broken syntax
        std::fs::write(file.path(), "def broken(\n").unwrap();

        let result = engine.reload();
        assert!(result.is_err());
        // Old state is preserved
        assert_eq!(engine.state().handlers.len(), 1);
    }

    #[test]
    fn proxy_on_reply_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_reply
def handle_reply(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyReply);
    }

    #[test]
    fn proxy_on_failure_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_failure
def failure_route(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyFailure);
    }

    #[test]
    fn proxy_on_register_reply_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_register_reply
async def handle_register_reply(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyRegisterReply);
        assert!(state.handlers[0].is_async);
    }

    #[test]
    fn b2bua_session_timer_python_api() {
        use crate::script::api::call::PyCall;
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::uri::SipUri;
        use std::sync::{Arc, Mutex};

        // Compile a script that sets a per-call session timer override
        let source = r#"
from siphon import b2bua, log

@b2bua.on_invite
def new_call(call):
    log.info(f"Setting session timer for call {call.id}")
    call.session_timer(expires=3600, min_se=120, refresher="uas")
    call.dial("sip:bob@10.0.0.2:5060")
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::B2buaInvite);

        // Build a real SIP INVITE
        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-py".to_string())
            .from("<sip:alice@atlanta.com>;tag=py-test".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("session-timer-py@test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let message_arc = Arc::new(Mutex::new(invite));
        let py_call = PyCall::new(
            "st-test-001".to_string(),
            Arc::clone(&message_arc),
            "10.0.0.1".to_string(),
        );

        // Invoke the handler and verify the override was set
        Python::attach(|python| {
            let call_obj = Py::new(python, py_call).expect("failed to create PyCall");
            let callable = state.handlers[0].callable.bind(python);
            callable.call1((call_obj.bind(python),)).expect("handler invocation failed");

            // Check that session_timer() set the override
            let borrowed = call_obj.borrow(python);
            let override_config = borrowed.session_timer_override()
                .expect("session_timer_override should be set after handler runs");
            assert_eq!(override_config.session_expires, 3600);
            assert_eq!(override_config.min_se, 120);
            assert_eq!(override_config.refresher, "uas");

            // Also check that dial() set the action
            let action = borrowed.action();
            assert_eq!(
                action,
                &crate::script::api::call::CallAction::Dial {
                    target: "sip:bob@10.0.0.2:5060".to_string(),
                    timeout: 30,
                }
            );
        });
    }

    #[test]
    fn b2bua_session_timer_default_values() {
        use crate::script::api::call::PyCall;
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::uri::SipUri;
        use std::sync::{Arc, Mutex};

        // Script calls session_timer() with no arguments — should get defaults
        let source = r#"
from siphon import b2bua

@b2bua.on_invite
def new_call(call):
    call.session_timer()
    call.dial("sip:bob@10.0.0.2:5060")
"#;
        let state = compile_temp_script(source).unwrap();

        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-def".to_string())
            .from("<sip:alice@atlanta.com>;tag=def-test".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("session-timer-defaults@test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let message_arc = Arc::new(Mutex::new(invite));
        let py_call = PyCall::new(
            "st-test-002".to_string(),
            message_arc,
            "10.0.0.1".to_string(),
        );

        Python::attach(|python| {
            let call_obj = Py::new(python, py_call).expect("failed to create PyCall");
            let callable = state.handlers[0].callable.bind(python);
            callable.call1((call_obj.bind(python),)).expect("handler invocation failed");

            let borrowed = call_obj.borrow(python);
            let override_config = borrowed.session_timer_override()
                .expect("session_timer_override should be set");
            // Defaults from #[pyo3(signature = (expires=1800, min_se=90, refresher="b2bua"))]
            assert_eq!(override_config.session_expires, 1800);
            assert_eq!(override_config.min_se, 90);
            assert_eq!(override_config.refresher, "b2bua");
        });
    }

    #[test]
    fn multiple_handler_types_in_one_script() {
        let source = r#"
from siphon import proxy, b2bua

@proxy.on_request
def route(request):
    pass

@proxy.on_reply
def reply_route(request, reply):
    pass

@proxy.on_failure
def failure_route(request, reply):
    pass

@proxy.on_register_reply
def register_reply_route(request, reply):
    pass

@b2bua.on_invite
def new_call(call):
    pass

@b2bua.on_failure
def failed(call, code, reason):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 6);
    }
}
