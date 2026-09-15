//! D32-A fixed, sandboxed Cargo-check production façade.
//!
//! The façade deliberately contains no model-controlled process fields.  It
//! reuses the D29-H7 prepared-image, final-fence, Job and bounded-I/O
//! supervisor; the only new surface is the static zero-argument Cargo profile
//! and its AppContainer security-capabilities attribute.

#![allow(dead_code)]

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::d29h7::{
    H7ExecutableCatalog, H7PendingConfirmationBridge, H7PendingProcessAction, H7ProcessBroker,
    H7ProcessRequest, H7SandboxProfile, VitaGitStatusAuthorityAdapter,
    VITA_WORKSPACE_CARGO_CHECK_CAPABILITY_ID, VITA_WORKSPACE_CARGO_CHECK_PROFILE_ID,
    VITA_WORKSPACE_CARGO_CHECK_TOOL_NAME,
};
use crate::{TrustedWorkspaceRoot, VitaExecutionContext, VitaGitStatusAuthority};

pub(crate) const D32_CARGO_PROGRAM_ID: &str = "cargo-check-v1";
pub(crate) const D32_CARGO_PROFILE_ID: &str = VITA_WORKSPACE_CARGO_CHECK_PROFILE_ID;
pub(crate) const D32_CARGO_TOOL_NAME: &str = VITA_WORKSPACE_CARGO_CHECK_TOOL_NAME;
pub(crate) const D32_CARGO_CAPABILITY_ID: &str = VITA_WORKSPACE_CARGO_CHECK_CAPABILITY_ID;
pub(crate) use crate::d29h7::D32_CARGO_NO_GIT_METADATA_FENCE;

type CargoConfirmationReceiver = tokio::sync::mpsc::Receiver<H7PendingProcessAction>;

struct CargoInner {
    broker: Arc<H7ProcessBroker>,
    catalog: Arc<H7ExecutableCatalog>,
    context: VitaExecutionContext,
    workspace_root: TrustedWorkspaceRoot,
    sandbox: Arc<H7SandboxProfile>,
}

/// Production D32 Cargo profile.  If a trusted toolchain or AppContainer
/// cannot be established, the model-visible tool remains fail-closed and the
/// caller can report the exact prerequisite blocker without weakening the
/// process boundary.
pub struct VitaCargoCheckProduction {
    inner: Option<Arc<CargoInner>>,
    confirmation: Arc<H7PendingConfirmationBridge>,
    receiver: Mutex<Option<CargoConfirmationReceiver>>,
    unavailable_reason: Option<String>,
}

impl VitaCargoCheckProduction {
    pub fn new(
        context: VitaExecutionContext,
        workspace_root: TrustedWorkspaceRoot,
        cargo_path: PathBuf,
        authority: Arc<dyn VitaGitStatusAuthority>,
    ) -> Self {
        let (confirmation, receiver) =
            H7PendingConfirmationBridge::new_with_timeout(std::time::Duration::from_secs(30));
        let attempted = (|| {
            let catalog = Arc::new(H7ExecutableCatalog::cargo_check(
                cargo_path,
                workspace_root.requested_path().to_path_buf(),
            )?);
            let sandbox = H7SandboxProfile::new()?;
            let authority = Arc::new(VitaGitStatusAuthorityAdapter::new(authority));
            let broker = H7ProcessBroker::new(
                context.clone(),
                Arc::clone(&catalog),
                authority,
                Arc::clone(&confirmation),
            );
            Ok::<_, String>(Arc::new(CargoInner {
                broker,
                catalog,
                context,
                workspace_root,
                sandbox,
            }))
        })();
        let (inner, unavailable_reason) = match attempted {
            Ok(inner) => (Some(inner), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            inner,
            confirmation,
            receiver: Mutex::new(Some(receiver)),
            unavailable_reason,
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        self.inner.is_some()
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub fn contributor(&self) -> VitaCargoCheckToolContributor {
        VitaCargoCheckToolContributor {
            inner: self.inner.clone(),
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn take_confirmation_receiver(&self) -> Option<CargoConfirmationReceiver> {
        self.receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    pub fn cancel(&self) {
        if let Some(inner) = &self.inner {
            inner.broker.cancel();
        }
        self.confirmation.cancel_pending();
    }

    pub fn begin_turn(&self) {
        if let Some(inner) = &self.inner {
            inner.broker.begin_turn();
        }
    }

    pub fn cancel_turn(&self) {
        if let Some(inner) = &self.inner {
            inner.broker.cancel_turn();
        }
        self.confirmation.cancel_pending();
    }
}

pub struct VitaCargoCheckToolContributor {
    inner: Option<Arc<CargoInner>>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaCargoCheckToolContributor {
    pub(crate) fn available(&self) -> bool {
        self.inner.is_some()
    }
}

impl ToolContributor for VitaCargoCheckToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        if !self.available() {
            // A missing toolchain, scratch root, or AppContainer profile is a
            // production prerequisite failure.  Do not advertise a tool that
            // cannot ever reach the fixed sandbox; the Host descriptor stays
            // fail-closed and the sidecar can report the blocker explicitly.
            return Vec::new();
        }
        vec![Arc::new(VitaCargoCheckTool {
            inner: self.inner.clone(),
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoCheckArguments {}

fn cargo_check_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": false
    })
}

fn bounded_tool_id(value: &str) -> Option<String> {
    (!value.is_empty() && value.chars().count() <= 256 && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn denied_value() -> Value {
    json!({
        "status": "denied",
        "exit_code": null,
        "timed_out": false,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": false,
        "stderr_truncated": false
    })
}

struct VitaCargoCheckTool {
    inner: Option<Arc<CargoInner>>,
    tool_call_count: Arc<AtomicUsize>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaCargoCheckTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(D32_CARGO_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: D32_CARGO_TOOL_NAME.to_string(),
            description: "Run the fixed Host-owned sandboxed cargo check profile.".to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&cargo_check_schema_contract())
                .expect("D32 cargo schema is static and valid"),
            output_schema: None,
        })
    }

    fn supports_parallel_tool_calls(&self) -> bool {
        false
    }

    fn handle<'a>(&'a self, call: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        'call: 'a,
    {
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        let inner = self.inner.clone();
        Box::pin(async move {
            let value = match (
                inner,
                call.tool_name.name == D32_CARGO_TOOL_NAME && call.tool_name.is_default_namespace(),
                bounded_tool_id(&call.call_id),
                bounded_tool_id(&call.turn_id),
                call.function_arguments()
                    .ok()
                    .and_then(|raw| serde_json::from_str::<CargoCheckArguments>(raw).ok()),
            ) {
                (Some(inner), true, Some(call_id), Some(turn_id), Some(_)) => {
                    let request = H7ProcessRequest::synthetic_fixed(
                        &call_id,
                        &turn_id,
                        D32_CARGO_PROGRAM_ID,
                        &["check", "--locked"],
                    );
                    match inner.catalog.prepare_fixed_workspace_action(
                        inner.context.clone(),
                        request,
                        D32_CARGO_CAPABILITY_ID,
                        D32_CARGO_PROFILE_ID,
                        inner.workspace_root.clone(),
                        Arc::clone(&inner.sandbox),
                    ) {
                        Ok(action) => inner.broker.execute(action).await.cargo_value(),
                        Err(_) => denied_value(),
                    }
                }
                _ => denied_value(),
            };
            Ok(Box::new(JsonToolOutput::with_success(value, Some(false))) as Box<dyn ToolOutput>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_model_schema_is_exactly_zero_argument() {
        assert_eq!(
            cargo_check_schema_contract(),
            json!({
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            })
        );
        assert!(serde_json::from_str::<CargoCheckArguments>(r#"{}"#).is_ok());
        assert!(serde_json::from_str::<CargoCheckArguments>(r#"{"args": []}"#).is_err());
    }

    #[test]
    fn cargo_profile_identity_is_static() {
        assert_eq!(D32_CARGO_PROGRAM_ID, "cargo-check-v1");
        assert_eq!(D32_CARGO_PROFILE_ID, "d32.workspace.cargo_check.v1");
        assert_eq!(D32_CARGO_TOOL_NAME, "vita_workspace_cargo_check");
        assert_eq!(
            D32_CARGO_CAPABILITY_ID,
            "vita.process.workspace.cargo_check"
        );
        assert_eq!(D32_CARGO_NO_GIT_METADATA_FENCE, "d32-no-git-fence-v1");
    }
}
