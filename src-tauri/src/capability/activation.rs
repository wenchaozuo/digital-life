//! D30-A user-controlled capability activation control plane.
//!
//! This module is a *control surface* for D28, not a second permission system.
//! It owns no authorization state of its own: every read goes through the
//! durable `life_capability_authorization` row and every write goes through
//! `CapabilityAuthorizationRepository`, the same boundary that
//! `evaluate_capability_authorization` reads on each invocation.
//!
//! The boundary rules enforced here are:
//!
//! * the trusted production catalog always comes from
//!   `CapabilityRegistry::production()`; descriptor metadata is never accepted
//!   from the frontend;
//! * the current life always comes from Host storage; the frontend may only
//!   echo the snapshot Life ID as a stale-intent fence, never select a target;
//! * the event identity is minted by the Host from a cryptographic source and
//!   can never be supplied by the caller;
//! * the caller must be the `settings` window, in addition to the Tauri ACL;
//! * a missing row is provisioned only as `disabled`/`revision 1`, and an
//!   existing row is never overwritten;
//! * enabling never lowers the descriptor's risk, approval floor, or scope
//!   requirement, and never authorizes a single action.
//!
//! No model, persona, emotion, relationship, goal, plan, action-intent,
//! autonomy, or vision value participates in any function below.

use serde::Serialize;
use tauri::{State, WebviewWindow};

use super::authorization::{
    CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError,
    CapabilityAuthorizationErrorCode, CapabilityAuthorizationRepository,
    CapabilityAuthorizationUpdateOutcome, LifeCapabilityAuthorization,
    LifeCapabilityAuthorizationCreateRequest, LifeCapabilityAuthorizationEvent,
    LifeCapabilityAuthorizationUpdateRequest,
};
use super::descriptor::{
    ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, RiskClass,
    ScopeRequirement,
};
use crate::storage::{LifeIdentityRecord, StorageService};

/// The only window label permitted to read or transition the user
/// authorization root. The label is assigned by the Tauri capability
/// configuration and cannot be spoofed by frontend code.
pub(crate) const SETTINGS_WINDOW_LABEL: &str = "settings";

/// Bounded audit history returned to the Settings surface.
pub(crate) const MAX_RECENT_AUTHORIZATION_EVENTS: usize = 20;

/// Hard bound on catalog entries exposed in one snapshot.
pub(crate) const MAX_CATALOG_ENTRIES: usize = 16;

/// Host-owned prefix for minted authorization event identities.
const HOST_EVENT_ID_PREFIX: &str = "d30a-user-root";

// ── Wire DTOs ─────────────────────────────────────────────────────────

/// Display-safe descriptor metadata. Every field is derived from the trusted
/// registry on the Host; none of it is accepted from the frontend.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityDescriptorView {
    pub(crate) capability_id: String,
    pub(crate) display_name: String,
    pub(crate) risk_class: String,
    pub(crate) approval_floor: String,
    pub(crate) scope_requirement: String,
    pub(crate) read_only: bool,
}

/// One immutable D28 audit transition, projected for display.
///
/// The internal `event_id` is deliberately not exposed: the UI never needs it,
/// and it is not a user-facing concept.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityAuthorizationEventView {
    pub(crate) old_enabled: bool,
    pub(crate) new_enabled: bool,
    pub(crate) old_revision: i64,
    pub(crate) new_revision: i64,
    pub(crate) changed_at: String,
    pub(crate) actor_kind: String,
    pub(crate) provenance_kind: String,
}

/// One trusted production capability plus its durable current root state.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityAuthorizationEntryView {
    #[serde(flatten)]
    pub(crate) descriptor: CapabilityDescriptorView,
    pub(crate) enabled: bool,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) recent_authorization_events: Vec<CapabilityAuthorizationEventView>,
}

/// The complete Settings capability view for the current life.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityAuthorizationSnapshot {
    pub(crate) life_id: String,
    pub(crate) capabilities: Vec<CapabilityAuthorizationEntryView>,
}

/// The result of one applied or replayed user-root transition.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityAuthorizationUpdateResult {
    pub(crate) capability_id: String,
    pub(crate) enabled: bool,
    pub(crate) revision: i64,
    pub(crate) previous_enabled: bool,
    pub(crate) previous_revision: i64,
    /// `applied` for a new immutable transition, `replayed` for an exact
    /// idempotent replay of an already-committed event identity.
    pub(crate) transition: String,
    pub(crate) events: Vec<CapabilityAuthorizationEventView>,
}

/// Stable, machine-readable failure codes for the Settings control plane.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapabilityActivationCommandError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl CapabilityActivationCommandError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// The caller is not the Settings window.
    fn settings_window_required() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_SETTINGS_WINDOW_REQUIRED",
            "Capability authorization may only be changed from the Settings window.",
        )
    }

    /// No current Life exists, so there is nothing to authorize against.
    fn life_not_available() -> Self {
        Self::new(
            "LIFE_NOT_AVAILABLE",
            "No current Life is available. Complete Life setup before managing capabilities.",
        )
    }

    /// The Settings card belongs to a Life that is no longer current.
    fn life_changed() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_LIFE_CHANGED",
            "The current Life changed. Review permissions again before applying this change.",
        )
    }

    /// The requested capability is not in the trusted production catalog.
    fn unknown_capability() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_UNKNOWN_CAPABILITY",
            "The requested capability is not in the trusted production catalog.",
        )
    }

    /// Another action changed the durable row first.
    fn revision_conflict() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_REVISION_CONFLICT",
            "The capability authorization changed since it was loaded. Refresh and try again.",
        )
    }

    /// The requested state equals the current state; D28 refuses a no-op.
    fn no_transition() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_NO_TRANSITION",
            "The capability is already in the requested state.",
        )
    }

    /// The durable row was expected but could not be found.
    fn not_provisioned() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_NOT_PROVISIONED",
            "The capability authorization row is not available for the current Life.",
        )
    }

    /// The request was structurally invalid.
    fn invalid_request() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_INVALID_REQUEST",
            "The capability authorization request was invalid.",
        )
    }

    /// The durable authorization store could not be read or written.
    fn storage_unavailable() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_STORAGE_UNAVAILABLE",
            "The capability authorization store is unavailable.",
        )
    }

    /// The trusted catalog cannot be represented by the bounded Settings view.
    fn catalog_too_large() -> Self {
        Self::new(
            "CAPABILITY_ACTIVATION_CATALOG_TOO_LARGE",
            "The trusted capability catalog is too large to manage safely.",
        )
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────

/// Defense in depth on top of the Tauri ACL: the label is assigned by the
/// Tauri capability configuration and cannot be spoofed by frontend code.
pub(crate) fn require_settings_label(label: &str) -> Result<(), CapabilityActivationCommandError> {
    if label == SETTINGS_WINDOW_LABEL {
        Ok(())
    } else {
        Err(CapabilityActivationCommandError::settings_window_required())
    }
}

fn require_settings_window(window: &WebviewWindow) -> Result<(), CapabilityActivationCommandError> {
    require_settings_label(window.label())
}

fn risk_class_str(value: RiskClass) -> &'static str {
    match value {
        RiskClass::Low => "LOW",
        RiskClass::Medium => "MEDIUM",
        RiskClass::High => "HIGH",
        RiskClass::Critical => "CRITICAL",
    }
}

fn approval_floor_str(value: ApprovalFloor) -> &'static str {
    match value {
        ApprovalFloor::RootEnabled => "ROOT_ENABLED",
        ApprovalFloor::ExplicitPerAction => "EXPLICIT_PER_ACTION",
        ApprovalFloor::Forbidden => "FORBIDDEN",
    }
}

fn scope_requirement_str(value: ScopeRequirement) -> &'static str {
    match value {
        ScopeRequirement::None => "NONE",
        ScopeRequirement::WorkspaceRequired => "WORKSPACE_REQUIRED",
        ScopeRequirement::NetworkDestinationRequired => "NETWORK_DESTINATION_REQUIRED",
        ScopeRequirement::ExternalResourceRequired => "EXTERNAL_RESOURCE_REQUIRED",
    }
}

fn descriptor_view(descriptor: &CapabilityDescriptor) -> CapabilityDescriptorView {
    CapabilityDescriptorView {
        capability_id: descriptor.capability_id().as_str().to_string(),
        display_name: descriptor.display_name().to_string(),
        risk_class: risk_class_str(descriptor.risk_class()).to_string(),
        approval_floor: approval_floor_str(descriptor.approval_floor()).to_string(),
        scope_requirement: scope_requirement_str(descriptor.scope_requirement()).to_string(),
        read_only: descriptor.is_read_only(),
    }
}

fn event_view(event: &LifeCapabilityAuthorizationEvent) -> CapabilityAuthorizationEventView {
    CapabilityAuthorizationEventView {
        old_enabled: event.old_enabled(),
        new_enabled: event.new_enabled(),
        old_revision: event.old_revision(),
        new_revision: event.new_revision(),
        changed_at: event.changed_at().to_string(),
        actor_kind: event.actor_kind().to_string(),
        provenance_kind: event.provenance_kind().to_string(),
    }
}

/// Host-owned, collision-resistant event identity.
///
/// The value is derived from a 128-bit cryptographic draw; it is neither a
/// timestamp nor a counter, and it is never accepted from the frontend.
fn mint_host_event_id() -> Result<String, CapabilityActivationCommandError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| CapabilityActivationCommandError::storage_unavailable())?;
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{HOST_EVENT_ID_PREFIX}-{suffix}"))
}

/// Captures the current Life from Host storage exactly once at the command
/// boundary. The frontend never supplies the authorization target.
fn current_life(
    storage: &StorageService,
) -> Result<LifeIdentityRecord, CapabilityActivationCommandError> {
    match storage.get_current_life() {
        Ok(Some(life)) => Ok(life),
        Ok(None) => Err(CapabilityActivationCommandError::life_not_available()),
        Err(_) => Err(CapabilityActivationCommandError::storage_unavailable()),
    }
}

/// The observed Life is only an optimistic stale-intent fence. Once it
/// matches, the Host-owned Life record is the immutable target for the rest of
/// this transition; no deeper operation re-reads current Life.
fn current_life_for_observed_intent(
    storage: &StorageService,
    observed_life_id: &str,
) -> Result<LifeIdentityRecord, CapabilityActivationCommandError> {
    let life = current_life(storage)?;
    if life.id != observed_life_id {
        return Err(CapabilityActivationCommandError::life_changed());
    }
    Ok(life)
}

/// Resolves a capability id only if the trusted production catalog contains
/// it. Structurally invalid ids are indistinguishable from unknown ids.
fn trusted_capability(
    registry: &CapabilityRegistry,
    capability_id: &str,
) -> Result<CapabilityId, CapabilityActivationCommandError> {
    let capability_id = CapabilityId::try_from(capability_id)
        .map_err(|_| CapabilityActivationCommandError::unknown_capability())?;
    if registry.descriptor(&capability_id).is_none() {
        return Err(CapabilityActivationCommandError::unknown_capability());
    }
    Ok(capability_id)
}

/// Validates the complete trusted catalog before any provisioning or
/// transition side effect. A bounded control surface must never silently hide
/// entries after the first sixteen.
fn validated_catalog<'a>(
    registry: &'a CapabilityRegistry,
) -> Result<Vec<&'a CapabilityDescriptor>, CapabilityActivationCommandError> {
    let catalog = registry.entries().collect::<Vec<_>>();
    if catalog.len() > MAX_CATALOG_ENTRIES {
        return Err(CapabilityActivationCommandError::catalog_too_large());
    }
    Ok(catalog)
}

/// Idempotently ensures a disabled `revision 1` row exists for every trusted
/// production capability of the current Life.
///
/// This function may only ever create a missing row in the `disabled` state.
/// It never enables, never infers consent, never reuses prior consent, and
/// never overwrites an existing row. A created row that is not exactly
/// `disabled`/`revision 1` is treated as a storage failure.
fn ensure_disabled_rows(
    storage: &StorageService,
    catalog: &[&CapabilityDescriptor],
    life_id: &str,
) -> Result<(), CapabilityActivationCommandError> {
    for &descriptor in catalog {
        let capability_id = descriptor.capability_id().clone();
        let existing = storage.find_capability_authorization(life_id, &capability_id);
        match existing {
            // Existing rows are never modified by provisioning.
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(_) => return Err(CapabilityActivationCommandError::storage_unavailable()),
        }
        let outcome = storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: life_id.to_string(),
                capability_id,
            })
            .map_err(|_| CapabilityActivationCommandError::storage_unavailable())?;
        let created: LifeCapabilityAuthorization = match outcome {
            CapabilityAuthorizationCreateOutcome::Applied(row) => row,
            CapabilityAuthorizationCreateOutcome::Replayed(row) => row,
        };
        if created.enabled || created.revision != 1 {
            // Provisioning must only ever produce a disabled revision 1 row.
            return Err(CapabilityActivationCommandError::storage_unavailable());
        }
    }
    Ok(())
}

fn map_update_error(error: CapabilityAuthorizationError) -> CapabilityActivationCommandError {
    match error.code {
        CapabilityAuthorizationErrorCode::RevisionConflict => {
            CapabilityActivationCommandError::revision_conflict()
        }
        CapabilityAuthorizationErrorCode::InvalidTransition => {
            CapabilityActivationCommandError::no_transition()
        }
        CapabilityAuthorizationErrorCode::AuthorizationNotFound => {
            CapabilityActivationCommandError::not_provisioned()
        }
        CapabilityAuthorizationErrorCode::LifeNotFound => {
            CapabilityActivationCommandError::life_not_available()
        }
        CapabilityAuthorizationErrorCode::InvalidArgument => {
            CapabilityActivationCommandError::invalid_request()
        }
        CapabilityAuthorizationErrorCode::AuthorizationConflict
        | CapabilityAuthorizationErrorCode::EventConflict
        | CapabilityAuthorizationErrorCode::DatabaseUnavailable => {
            CapabilityActivationCommandError::storage_unavailable()
        }
    }
}

// ── Control-plane operations (testable without a webview) ─────────────

fn build_snapshot(
    storage: &StorageService,
    registry: &CapabilityRegistry,
) -> Result<CapabilityAuthorizationSnapshot, CapabilityActivationCommandError> {
    let life = current_life(storage)?;
    let catalog = validated_catalog(registry)?;
    build_snapshot_for_life(storage, &catalog, &life)
}

fn build_snapshot_for_life(
    storage: &StorageService,
    catalog: &[&CapabilityDescriptor],
    life: &LifeIdentityRecord,
) -> Result<CapabilityAuthorizationSnapshot, CapabilityActivationCommandError> {
    let life_id = &life.id;
    ensure_disabled_rows(storage, catalog, life_id)?;

    let mut capabilities = Vec::new();
    for &descriptor in catalog {
        let capability_id = descriptor.capability_id().clone();
        let row = storage
            .find_capability_authorization(life_id, &capability_id)
            .map_err(|_| CapabilityActivationCommandError::storage_unavailable())?
            .ok_or_else(CapabilityActivationCommandError::not_provisioned)?;
        if row.life_id.as_str() != life_id || row.capability_id != capability_id {
            return Err(CapabilityActivationCommandError::storage_unavailable());
        }
        let events = storage
            .list_capability_authorization_events(
                life_id,
                &capability_id,
                MAX_RECENT_AUTHORIZATION_EVENTS,
            )
            .map_err(|_| CapabilityActivationCommandError::storage_unavailable())?;
        capabilities.push(CapabilityAuthorizationEntryView {
            descriptor: descriptor_view(descriptor),
            enabled: row.enabled,
            revision: row.revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
            recent_authorization_events: events.iter().map(event_view).collect(),
        });
    }

    Ok(CapabilityAuthorizationSnapshot {
        life_id: life_id.clone(),
        capabilities,
    })
}

fn apply_transition(
    storage: &StorageService,
    registry: &CapabilityRegistry,
    capability_id: &str,
    enabled: bool,
    expected_revision: i64,
    observed_life_id: &str,
) -> Result<CapabilityAuthorizationUpdateResult, CapabilityActivationCommandError> {
    // The equality check is deliberately before catalog validation,
    // provisioning, event-id minting, and every D28 mutation. The observed
    // Life never selects the target; it only rejects stale Settings intent.
    let life = current_life_for_observed_intent(storage, observed_life_id)?;
    let catalog = validated_catalog(registry)?;
    apply_transition_for_life(
        storage,
        registry,
        &catalog,
        &life,
        capability_id,
        enabled,
        expected_revision,
    )
}

/// Narrow composition seam for Host integration tests.  Production callers
/// must use the Settings-window command below; keeping this helper behind
/// `cfg(test)` lets Vita tests exercise the exact D30 transition path without
/// widening the runtime authorization API.
#[cfg(test)]
pub(crate) fn apply_transition_for_test(
    storage: &StorageService,
    registry: &CapabilityRegistry,
    capability_id: &str,
    enabled: bool,
    expected_revision: i64,
    observed_life_id: &str,
) -> Result<CapabilityAuthorizationUpdateResult, CapabilityActivationCommandError> {
    apply_transition(
        storage,
        registry,
        capability_id,
        enabled,
        expected_revision,
        observed_life_id,
    )
}

fn apply_transition_for_life(
    storage: &StorageService,
    registry: &CapabilityRegistry,
    catalog: &[&CapabilityDescriptor],
    life: &LifeIdentityRecord,
    capability_id: &str,
    enabled: bool,
    expected_revision: i64,
) -> Result<CapabilityAuthorizationUpdateResult, CapabilityActivationCommandError> {
    let life_id = &life.id;
    let capability_id = trusted_capability(registry, capability_id)?;
    // Provision first so a freshly installed catalog still has a durable row to
    // compare-and-swap against. This never enables anything.
    ensure_disabled_rows(storage, catalog, life_id)?;

    let request = LifeCapabilityAuthorizationUpdateRequest::from_host_user_authorization_root(
        mint_host_event_id()?,
        life_id.clone(),
        capability_id.clone(),
        enabled,
        expected_revision,
    )
    .map_err(|_| CapabilityActivationCommandError::invalid_request())?;

    let (event, current, transition) = match storage.update_capability_authorization(request) {
        Ok(CapabilityAuthorizationUpdateOutcome::Applied {
            event,
            authorization,
        }) => (event, authorization, "applied"),
        Ok(CapabilityAuthorizationUpdateOutcome::Replayed { event, current }) => {
            (event, current, "replayed")
        }
        Err(error) => return Err(map_update_error(error)),
    };

    let events = storage
        .list_capability_authorization_events(
            life_id,
            &capability_id,
            MAX_RECENT_AUTHORIZATION_EVENTS,
        )
        .map_err(|_| CapabilityActivationCommandError::storage_unavailable())?;

    Ok(CapabilityAuthorizationUpdateResult {
        capability_id: capability_id.as_str().to_string(),
        enabled: current.enabled,
        revision: current.revision,
        previous_enabled: event.old_enabled(),
        previous_revision: event.old_revision(),
        transition: transition.to_string(),
        events: events.iter().map(event_view).collect(),
    })
}

// ── Tauri commands ────────────────────────────────────────────────────

/// Settings-only snapshot of the trusted production catalog and the durable
/// D28 authorization state for the current Life.
#[tauri::command]
pub(crate) fn get_capability_authorization_snapshot(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    registry: State<'_, CapabilityRegistry>,
) -> Result<CapabilityAuthorizationSnapshot, CapabilityActivationCommandError> {
    require_settings_window(&window)?;
    build_snapshot(&storage, &registry)
}

/// Settings-only explicit user-root transition.
///
/// The frontend supplies only the capability id, the desired state, and the
/// revision it last observed, plus the Host-derived Life ID it observed in the
/// snapshot. The Life ID is only a stale-intent fence: event identity,
/// authorization target, provenance, scope, risk, approval floor, and the
/// resulting revision are all decided by the Host and D28.
#[tauri::command]
pub(crate) fn set_capability_authorization_enabled(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    registry: State<'_, CapabilityRegistry>,
    capability_id: String,
    enabled: bool,
    expected_revision: i64,
    observed_life_id: String,
) -> Result<CapabilityAuthorizationUpdateResult, CapabilityActivationCommandError> {
    require_settings_window(&window)?;
    apply_transition(
        &storage,
        &registry,
        &capability_id,
        enabled,
        expected_revision,
        &observed_life_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::authorization::{
        evaluate_capability_authorization, CapabilityAuthorizationDecisionCode,
        CapabilityAuthorizationDecisionKind, RequestedCapabilityScope,
    };
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};

    const PRODUCTION_CAPABILITY_ID: &str = "vita.process.workspace.git_status";
    const LIFE_ID: &str = "d30a-life";
    const SECOND_LIFE_ID: &str = "d30a-life-b";

    struct Fixture {
        _root: tempfile::TempDir,
        storage: StorageService,
        registry: CapabilityRegistry,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("d30a fixture root");
            let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .expect("d30a fixture storage");
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d30a-persona".to_string(),
                    name: "D30-A persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("d30a fixture persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: LIFE_ID.to_string(),
                    name: "D30-A life".to_string(),
                    created_at: "2026-09-12T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d30a-body".to_string(),
                    persona_id: "d30a-persona".to_string(),
                    persona_version: 1,
                })
                .expect("d30a fixture life");
            Self {
                _root: root,
                storage,
                registry: CapabilityRegistry::production().expect("production registry"),
            }
        }

        fn capability_id(&self) -> CapabilityId {
            CapabilityId::try_from(PRODUCTION_CAPABILITY_ID).expect("production capability id")
        }

        fn life_record(id: &str, name: &str) -> LifeIdentityRecord {
            LifeIdentityRecord {
                id: id.to_string(),
                name: name.to_string(),
                created_at: "2026-09-12T00:00:00.000Z".to_string(),
                version: 1,
                body_id: "d30a-body".to_string(),
                persona_id: "d30a-persona".to_string(),
                persona_version: 1,
            }
        }

        fn decision(&self) -> (CapabilityAuthorizationDecisionKind, Option<i64>) {
            let decision = evaluate_capability_authorization(
                &self.storage,
                &self.registry,
                LIFE_ID,
                &self.capability_id(),
                RequestedCapabilityScope::Workspace,
            )
            .expect("d30a evaluation");
            (decision.outcome(), decision.authorization_revision())
        }

        fn row(&self) -> LifeCapabilityAuthorization {
            self.row_for(LIFE_ID).expect("d30a row present")
        }

        fn row_for(&self, life_id: &str) -> Option<LifeCapabilityAuthorization> {
            self.storage
                .find_capability_authorization(life_id, &self.capability_id())
                .expect("d30a row read")
        }

        fn event_count(&self) -> usize {
            self.event_count_for(LIFE_ID)
        }

        fn event_count_for(&self, life_id: &str) -> usize {
            self.storage
                .list_capability_authorization_events(
                    life_id,
                    &self.capability_id(),
                    MAX_RECENT_AUTHORIZATION_EVENTS,
                )
                .expect("d30a audit history")
                .len()
        }

        /// The durable root table has `PRIMARY KEY (life_id, capability_id)`,
        /// so existence of the keyed row is exactly "one durable row".
        fn row_exists(&self) -> bool {
            self.row_for(LIFE_ID).is_some()
        }
    }

    #[test]
    fn snapshot_provisions_only_a_disabled_revision_one_row() {
        let fixture = Fixture::new();
        assert!(!fixture.row_exists());

        let snapshot = build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        assert_eq!(snapshot.life_id, LIFE_ID);
        assert_eq!(snapshot.capabilities.len(), 1);

        let entry = &snapshot.capabilities[0];
        assert_eq!(entry.descriptor.capability_id, PRODUCTION_CAPABILITY_ID);
        assert!(!entry.enabled, "provisioning must never enable");
        assert_eq!(entry.revision, 1, "provisioning must create revision 1");
        assert!(entry.recent_authorization_events.is_empty());
        assert!(fixture.row_exists());
        assert_eq!(fixture.event_count(), 0);

        // Idempotent: a second snapshot neither duplicates nor re-enables.
        let again = build_snapshot(&fixture.storage, &fixture.registry).expect("second snapshot");
        assert!(!again.capabilities[0].enabled);
        assert_eq!(again.capabilities[0].revision, 1);
        assert!(fixture.row_exists());
        assert_eq!(fixture.event_count(), 0);
    }

    #[test]
    fn snapshot_exposes_trusted_descriptor_metadata_not_frontend_values() {
        let fixture = Fixture::new();
        let snapshot = build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        let descriptor = &snapshot.capabilities[0].descriptor;
        assert_eq!(descriptor.risk_class, "CRITICAL");
        assert_eq!(descriptor.approval_floor, "EXPLICIT_PER_ACTION");
        assert_eq!(descriptor.scope_requirement, "WORKSPACE_REQUIRED");
        assert!(descriptor.read_only);
        assert_eq!(
            descriptor.display_name,
            "Governed read-only workspace Git status"
        );
    }

    #[test]
    fn observed_life_fence_denies_stale_a_intent_before_provisioning_b() {
        let fixture = Fixture::new();

        // The Settings card was rendered for Life A at revision 1.
        let snapshot_a = build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot A");
        assert_eq!(snapshot_a.life_id, LIFE_ID);
        assert_eq!(snapshot_a.capabilities[0].revision, 1);

        // Switch the Host-owned current Life to B. Both lives would otherwise
        // naturally have revision 1, so the revision alone cannot fence this
        // stale intent.
        fixture
            .storage
            .save_life(Fixture::life_record(SECOND_LIFE_ID, "D30-A life B"))
            .expect("switch current Life to B");

        let error = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            LIFE_ID,
        )
        .expect_err("a stale Life A intent must be denied");
        assert_eq!(error.code, "CAPABILITY_ACTIVATION_LIFE_CHANGED");

        // The mismatch check happens before provisioning, event-id minting, or
        // D28 mutation: B remains absent and A remains untouched.
        assert!(fixture.row_for(SECOND_LIFE_ID).is_none());
        assert_eq!(fixture.event_count_for(SECOND_LIFE_ID), 0);
        let row_a = fixture.row_for(LIFE_ID).expect("Life A row");
        assert!(!row_a.enabled);
        assert_eq!(row_a.revision, 1);
        assert_eq!(fixture.event_count_for(LIFE_ID), 0);

        // A fresh B snapshot creates only B's disabled rev1 row; the fresh B
        // intent then enables B through the Host-derived current target.
        let snapshot_b = build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot B");
        assert_eq!(snapshot_b.life_id, SECOND_LIFE_ID);
        assert_eq!(snapshot_b.capabilities[0].revision, 1);
        let enabled_b = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            SECOND_LIFE_ID,
        )
        .expect("fresh Life B intent");
        assert_eq!(enabled_b.revision, 2);
        assert!(enabled_b.enabled);
        assert_eq!(fixture.event_count_for(SECOND_LIFE_ID), 1);
    }

    #[test]
    fn oversized_trusted_catalog_fails_closed_without_partial_provisioning() {
        let fixture = Fixture::new();
        let descriptors = (0..17)
            .map(|index| {
                CapabilityDescriptor::synthetic(
                    CapabilityId::try_from(format!("synthetic.capability.{index:02}")).unwrap(),
                    format!("Synthetic capability {index}"),
                    RiskClass::Low,
                    ApprovalFloor::RootEnabled,
                    ScopeRequirement::None,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let registry = CapabilityRegistry::synthetic(descriptors).expect("synthetic registry");

        let error = build_snapshot(&fixture.storage, &registry)
            .expect_err("catalog overflow must fail closed");
        assert_eq!(error.code, "CAPABILITY_ACTIVATION_CATALOG_TOO_LARGE");
        for descriptor in registry.entries() {
            assert!(fixture
                .storage
                .find_capability_authorization(LIFE_ID, descriptor.capability_id())
                .expect("overflow row read")
                .is_none());
            assert!(fixture
                .storage
                .list_capability_authorization_events(
                    LIFE_ID,
                    descriptor.capability_id(),
                    MAX_RECENT_AUTHORIZATION_EVENTS,
                )
                .expect("overflow event read")
                .is_empty());
        }

        let first_id = registry
            .entries()
            .next()
            .expect("synthetic descriptor")
            .capability_id()
            .as_str();
        let error = apply_transition(&fixture.storage, &registry, first_id, true, 1, LIFE_ID)
            .expect_err("transition must reject an oversized catalog");
        assert_eq!(error.code, "CAPABILITY_ACTIVATION_CATALOG_TOO_LARGE");
        for descriptor in registry.entries() {
            assert!(fixture
                .storage
                .find_capability_authorization(LIFE_ID, descriptor.capability_id())
                .expect("transition overflow row read")
                .is_none());
        }
    }

    #[test]
    fn enable_then_disable_mints_exactly_two_immutable_user_events() {
        let fixture = Fixture::new();
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");

        // disabled rev1 -> enabled rev2
        let enabled = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            LIFE_ID,
        )
        .expect("enable");
        assert_eq!(enabled.transition, "applied");
        assert!(enabled.enabled);
        assert_eq!(enabled.previous_enabled, false);
        assert_eq!(enabled.previous_revision, 1);
        assert_eq!(enabled.revision, 2);
        assert_eq!(fixture.event_count(), 1);

        // enabled rev2 -> disabled rev3
        let disabled = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            false,
            2,
            LIFE_ID,
        )
        .expect("disable");
        assert_eq!(disabled.transition, "applied");
        assert!(!disabled.enabled);
        assert_eq!(disabled.previous_enabled, true);
        assert_eq!(disabled.previous_revision, 2);
        assert_eq!(disabled.revision, 3);
        assert_eq!(fixture.event_count(), 2);
        assert!(fixture.row_exists(), "one durable row only");

        // Audit content and provenance are fixed by the Host.
        assert_eq!(disabled.events.len(), 2);
        // Deterministic ordering: newest revision first.
        assert_eq!(disabled.events[0].new_revision, 3);
        assert_eq!(disabled.events[0].old_revision, 2);
        assert_eq!(disabled.events[0].old_enabled, true);
        assert_eq!(disabled.events[0].new_enabled, false);
        assert_eq!(disabled.events[1].new_revision, 2);
        assert_eq!(disabled.events[1].old_revision, 1);
        assert_eq!(disabled.events[1].old_enabled, false);
        assert_eq!(disabled.events[1].new_enabled, true);
        for event in &disabled.events {
            assert_eq!(event.actor_kind, "user_explicit");
            assert_eq!(event.provenance_kind, "user_authorization_root");
            assert!(!event.changed_at.is_empty());
        }
    }

    #[test]
    fn stale_expected_revision_is_a_conflict_and_mutates_nothing() {
        let fixture = Fixture::new();
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            LIFE_ID,
        )
        .expect("enable");

        let error = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            false,
            1, // stale: the row is already at revision 2
            LIFE_ID,
        )
        .expect_err("stale revision must conflict");
        assert_eq!(
            error.code, "CAPABILITY_ACTIVATION_REVISION_CONFLICT",
            "a stale revision must never be converted into success"
        );

        // Nothing changed.
        let row = fixture.row();
        assert!(row.enabled);
        assert_eq!(row.revision, 2);
        assert_eq!(fixture.event_count(), 1);
    }

    #[test]
    fn duplicate_desired_state_creates_no_second_event() {
        let fixture = Fixture::new();
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            LIFE_ID,
        )
        .expect("enable");
        assert_eq!(fixture.event_count(), 1);

        let error = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true, // already enabled
            2,
            LIFE_ID,
        )
        .expect_err("a no-op transition must not be fabricated");
        assert_eq!(error.code, "CAPABILITY_ACTIVATION_NO_TRANSITION");
        assert_eq!(fixture.event_count(), 1, "no duplicate immutable event");
        assert_eq!(fixture.row().revision, 2);
    }

    #[test]
    fn unknown_or_structurally_invalid_capability_is_denied() {
        let fixture = Fixture::new();
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        for candidate in [
            "vita.process.workspace.run",
            "vita.shell",
            "not.a.real.capability",
            "",
            "UPPERCASE",
            "with space",
            "with/slash",
        ] {
            let error = apply_transition(
                &fixture.storage,
                &fixture.registry,
                candidate,
                true,
                1,
                LIFE_ID,
            )
            .expect_err("unknown capability must be denied");
            assert_eq!(
                error.code, "CAPABILITY_ACTIVATION_UNKNOWN_CAPABILITY",
                "capability {candidate:?} must be denied"
            );
        }
        assert_eq!(fixture.event_count(), 0);
    }

    #[test]
    fn only_the_settings_window_label_is_admitted() {
        assert!(require_settings_label("settings").is_ok());
        for denied in ["main", "chat", "", "settings2", "Settings"] {
            let error =
                require_settings_label(denied).expect_err("non-settings label must be denied");
            assert_eq!(
                error.code, "CAPABILITY_ACTIVATION_SETTINGS_WINDOW_REQUIRED",
                "label {denied:?} must be denied"
            );
        }
    }

    #[test]
    fn missing_current_life_is_a_fail_closed_life_not_available() {
        let root = tempfile::tempdir().expect("d30a empty root");
        let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
            .expect("d30a empty storage");
        let registry = CapabilityRegistry::production().expect("production registry");

        let error = build_snapshot(&storage, &registry).expect_err("no life must fail closed");
        assert_eq!(error.code, "LIFE_NOT_AVAILABLE");

        let error = apply_transition(
            &storage,
            &registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            "missing-life",
        )
        .expect_err("no life must fail closed");
        assert_eq!(error.code, "LIFE_NOT_AVAILABLE");
    }

    #[test]
    fn host_event_identity_is_unique_bounded_and_host_owned() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let event_id = mint_host_event_id().expect("minted event id");
            assert!(event_id.starts_with(HOST_EVENT_ID_PREFIX));
            assert!(event_id.len() <= 128);
            assert!(
                event_id
                    .chars()
                    .all(|character| !character.is_whitespace() && !character.is_control()),
                "event identity must satisfy the D28 identity contract"
            );
            assert!(seen.insert(event_id), "event identities must not collide");
        }
    }

    #[test]
    fn authority_revocation_uses_one_durable_row_and_the_real_evaluator() {
        let fixture = Fixture::new();
        let authority_view = fixture
            .storage
            .open_authority_view()
            .expect("separate Host authority view");

        // 1. initial state: disabled revision 1 (provisioned, never enabled)
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        assert!(!fixture.row().enabled);
        assert_eq!(fixture.row().revision, 1);
        let (outcome, revision) = fixture.decision();
        assert_eq!(outcome, CapabilityAuthorizationDecisionKind::RootDisabled);
        assert_eq!(revision, Some(1));

        // 2. user enable: enabled revision 2
        let enabled = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            true,
            1,
            LIFE_ID,
        )
        .expect("user enable");
        assert_eq!(enabled.revision, 2);

        // 3. the D29 authorization/grant path is valid against this row: the
        // real evaluator now reaches the descriptor scope floor and yields the
        // revision the Host would bind into confirmation and grant evidence.
        let (outcome, revision) = fixture.decision();
        assert_eq!(
            outcome,
            CapabilityAuthorizationDecisionKind::ScopeRequired,
            "an enabled root must reach the descriptor's workspace scope floor"
        );
        assert_eq!(
            revision,
            Some(2),
            "confirmation/grant evidence is bound to the enabled revision"
        );

        let authority_enabled = evaluate_capability_authorization(
            &authority_view,
            &fixture.registry,
            LIFE_ID,
            &fixture.capability_id(),
            RequestedCapabilityScope::Workspace,
        )
        .expect("authority view sees rev2");
        assert_eq!(
            authority_enabled.outcome(),
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        assert_eq!(authority_enabled.authorization_revision(), Some(2));

        // 4. the same durable row is disabled by the user: revision 3
        let disabled = apply_transition(
            &fixture.storage,
            &fixture.registry,
            PRODUCTION_CAPABILITY_ID,
            false,
            2,
            LIFE_ID,
        )
        .expect("user disable");
        assert_eq!(disabled.revision, 3);
        assert!(!disabled.enabled);

        // 5. execution-time revalidation re-reads the same row and denies.
        let (outcome, revision) = fixture.decision();
        assert_eq!(
            outcome,
            CapabilityAuthorizationDecisionKind::RootDisabled,
            "the final revalidation must deny after revocation"
        );
        assert_eq!(revision, Some(3));

        let authority_disabled = evaluate_capability_authorization(
            &authority_view,
            &fixture.registry,
            LIFE_ID,
            &fixture.capability_id(),
            RequestedCapabilityScope::Workspace,
        )
        .expect("authority view sees rev3");
        assert_eq!(
            authority_disabled.outcome(),
            CapabilityAuthorizationDecisionKind::RootDisabled
        );
        assert_eq!(authority_disabled.authorization_revision(), Some(3));

        // The denial is the same decision code the D29 Host maps to a refusal
        // before any native operation is attempted.
        let decision = evaluate_capability_authorization(
            &fixture.storage,
            &fixture.registry,
            LIFE_ID,
            &fixture.capability_id(),
            RequestedCapabilityScope::Workspace,
        )
        .expect("post-revocation evaluation");
        assert_eq!(
            decision.decision_code(),
            CapabilityAuthorizationDecisionCode::RootDisabled
        );

        // 6. exactly one durable row, two immutable events, deterministic order.
        assert!(fixture.row_exists());
        assert_eq!(fixture.event_count(), 2);
        let events = fixture
            .storage
            .list_capability_authorization_events(
                LIFE_ID,
                &fixture.capability_id(),
                MAX_RECENT_AUTHORIZATION_EVENTS,
            )
            .expect("audit history");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].new_revision(), 3);
        assert_eq!(events[1].new_revision(), 2);
        assert_eq!(events[0].new_enabled(), false);
        assert_eq!(events[1].new_enabled(), true);
    }

    #[test]
    fn audit_history_is_bounded_by_the_requested_window() {
        let fixture = Fixture::new();
        build_snapshot(&fixture.storage, &fixture.registry).expect("snapshot");
        for step in 0..8 {
            let enabled = step % 2 == 0;
            let expected_revision = step + 1;
            apply_transition(
                &fixture.storage,
                &fixture.registry,
                PRODUCTION_CAPABILITY_ID,
                enabled,
                expected_revision,
                LIFE_ID,
            )
            .expect("alternating transition");
        }
        assert_eq!(fixture.event_count(), 8);

        let bounded = fixture
            .storage
            .list_capability_authorization_events(LIFE_ID, &fixture.capability_id(), 3)
            .expect("bounded audit history");
        assert_eq!(bounded.len(), 3);
        assert_eq!(bounded[0].new_revision(), 9);
        assert_eq!(bounded[2].new_revision(), 7);

        // The control plane never asks for more than its own window; an
        // oversized limit is clamped by the storage layer rather than becoming
        // an unbounded scan. Only 8 events exist, so the clamped page returns
        // all of them and none are lost.
        let clamped = fixture
            .storage
            .list_capability_authorization_events(LIFE_ID, &fixture.capability_id(), usize::MAX)
            .expect("clamped audit history");
        assert_eq!(clamped.len(), 8);
    }

    // ── D30-A command surface, schema, and side-effect-class contracts ──

    const SETTINGS_ACL: &str = include_str!("../../permissions/settings-commands.toml");
    const MAIN_ACL: &str = include_str!("../../permissions/main-commands.toml");
    const CHAT_ACL: &str = include_str!("../../permissions/chat-commands.toml");
    const HOST_APP_MANIFEST: &str = include_str!("../../build.rs");
    const HOST_INVOKE_HANDLER: &str = include_str!("../lib.rs");

    /// Extracts every quoted command token from a permission file's allow list.
    fn acl_commands(source: &str) -> Vec<String> {
        let allow = source.find("commands.allow").expect("commands.allow list");
        let open = source[allow..].find('[').expect("allow list open") + allow;
        let close = source[open..].find(']').expect("allow list close") + open;
        source[open + 1..close]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn d30a_command_surface_is_settings_only_across_all_five_surfaces() {
        let settings = acl_commands(SETTINGS_ACL);
        let main = acl_commands(MAIN_ACL);
        let chat = acl_commands(CHAT_ACL);

        // The new D30-A control-plane commands: declared, registered, and
        // reachable from Settings only.
        for command in [
            "get_capability_authorization_snapshot",
            "set_capability_authorization_enabled",
        ] {
            assert!(
                settings.iter().any(|entry| entry == command),
                "Settings must grant {command}"
            );
            assert!(
                HOST_APP_MANIFEST.contains(&format!("\"{command}\"")),
                "the Tauri AppManifest must declare {command}"
            );
            assert!(
                HOST_INVOKE_HANDLER.contains(&format!("activation::{command}")),
                "the invoke_handler must register {command}"
            );
            assert!(
                !main.iter().any(|entry| entry == command),
                "the main window must not grant {command}"
            );
            assert!(
                !chat.iter().any(|entry| entry == command),
                "the chat window must not grant {command}"
            );
        }

        // The D29 Vita lifecycle commands remain Settings-only after the D30-A
        // main-window ACL cleanup.
        for command in [
            "start_vita_sidecar",
            "get_vita_sidecar_status",
            "start_vita_turn",
            "cancel_vita_turn",
            "confirm_vita_sidecar",
            "deny_vita_sidecar",
            "stop_vita_sidecar",
        ] {
            assert!(
                settings.iter().any(|entry| entry == command),
                "Settings must still grant {command}"
            );
            assert!(
                !main.iter().any(|entry| entry == command),
                "the main window must not grant {command}"
            );
            assert!(
                !chat.iter().any(|entry| entry == command),
                "the chat window must not grant {command}"
            );
        }

        // No Vita or capability-authority command may be reachable outside
        // Settings on any window surface.
        for (surface_name, surface) in [("main", &main), ("chat", &chat)] {
            for command in surface {
                for prefix in [
                    "start_vita",
                    "stop_vita",
                    "cancel_vita",
                    "confirm_vita",
                    "deny_vita",
                    "get_vita",
                    "get_capability_authorization",
                    "set_capability_authorization",
                ] {
                    assert!(
                        !command.starts_with(prefix),
                        "{surface_name} must not reach authority command {command}"
                    );
                }
            }
        }
    }

    #[test]
    fn d30a_adds_no_schema_and_no_new_side_effect_class() {
        // The control plane contains no SQL of its own: every read and write
        // goes through the Schema-30 D28 repository. Only the production
        // portion is scanned; the forbidden-token list itself lives in this
        // test module below the split point.
        let source = include_str!("activation.rs");
        let production_source = source
            .split_once("mod tests")
            .expect("the production/test module boundary must remain explicit")
            .0;
        for forbidden in [
            "CREATE TABLE",
            "ALTER TABLE",
            "CREATE TRIGGER",
            "DROP TABLE",
            "DELETE FROM",
            "INSERT INTO",
            "rusqlite",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "the D30-A control plane must contain no schema or SQL surface: {forbidden}"
            );
        }

        // The production catalog is unchanged: exactly one read-only
        // capability, so D30-A changes authorization reachability only.
        let registry = CapabilityRegistry::production().expect("production registry");
        let entries: Vec<&CapabilityDescriptor> = registry.entries().collect();
        assert_eq!(
            entries.len(),
            1,
            "D30-A must not widen the production tool surface"
        );
        assert!(entries[0].is_read_only());
        assert_eq!(
            entries[0].capability_id().as_str(),
            "vita.process.workspace.git_status"
        );
        assert_eq!(
            entries[0].approval_floor(),
            ApprovalFloor::ExplicitPerAction
        );
        assert_eq!(
            entries[0].scope_requirement(),
            ScopeRequirement::WorkspaceRequired
        );
        for forbidden in [
            "vita.process.run",
            "vita.process.workspace.run",
            "vita.shell",
            "vita.git",
            "vita.write",
            "vita.network",
        ] {
            let id = CapabilityId::try_from(forbidden).expect("negative capability id");
            assert!(
                registry.descriptor(&id).is_none(),
                "{forbidden} must not become production-reachable"
            );
        }
    }

    #[test]
    fn schema_thirty_and_absent_migration_031_explicit_guards_are_intact() {
        let migration = include_str!("../storage/migration.rs");
        // These two assertions are the explicit Schema-30 / Migration-031
        // guards; they are executed by the D28 migration test suite.
        assert!(migration.contains("Migration 030 must be the current migration"));
        assert!(migration.contains("Migration 031 must not exist"));
    }
}
