mod candidate_memory_internal;
use std::sync::Arc;
// D11-B1 is the emotion authority foundation; the emotion domain has no
// production caller until the D11-B2+ policy/conversation stages, so the
// frozen surface is allowed as dead code outside test builds. D12-B1 is the
// same foundation stage for the relationship domain.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod capability;

#[cfg(feature = "d29-h1-host-fixture")]
pub fn run_d29h1_authority_fixture() -> Result<(), String> {
    capability::d29h1_host_fixture::run_from_stdio()
}

#[cfg(feature = "d29-h3-host-fixture")]
pub fn run_d29h3_authority_fixture() -> Result<(), String> {
    capability::d29h3_host_fixture::run_from_stdio()
}

#[cfg(feature = "d29-h4-host-fixture")]
pub fn run_d29h4_authority_fixture() -> Result<(), String> {
    capability::d29h4_host_fixture::run_from_stdio()
}
pub mod conversation;
pub mod embedding;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod emotion;
// D29-A: the Codex App Server process/protocol foundation is intentionally
// private and has no production caller until a later governed execution
// stage.  Keeping it outside capability/autonomy preserves the D28 firewall.
#[cfg_attr(not(test), allow(dead_code))]
mod execution_enclave;
pub(crate) mod experience;
// D14-B1 is the goal / plan / action-intent authority foundation; the domain
// has no production caller until the D14-B2+ lifecycle stages, so the frozen
// surface is allowed as dead code outside test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod life_intent;
// D15-B1 is the explicit autonomy-policy / proactive-intent authority
// foundation; its crate-internal surface has no production caller yet.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod autonomy;
// D16-B1 remains the independent foreground-focus consent authority. D23-B2
// exposes only the separate screen-perception consent/session authority to
// Settings; neither domain performs operating-system capture here.
pub mod memory;
pub mod model;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod perception;
pub mod prompt;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod relationship;
pub mod secrets;
mod storage;
pub mod vector_store;

use tauri::{Manager, WebviewWindowBuilder, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .register_uri_scheme_protocol(
            storage::body_package::BODY_ASSET_PROTOCOL_SCHEME,
            |context, request| {
                let storage = context.app_handle().state::<storage::StorageService>();
                storage::body_package::serve_body_asset_request_for_webview(
                    &storage,
                    context.webview_label(),
                    request,
                )
            },
        )
        .register_uri_scheme_protocol(
            storage::live2d_core::CORE_ASSET_PROTOCOL_SCHEME,
            |context, request| {
                let storage = context.app_handle().state::<storage::StorageService>();
                storage::live2d_core::serve_core_request_for_webview(
                    &storage,
                    context.webview_label(),
                    request,
                )
            },
        )
        .setup(|app| {
            let storage = storage::StorageService::initialize(app.handle())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(storage);
            let capability_registry = capability::CapabilityRegistry::production()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            app.manage(capability_registry);
            app.manage(secrets::WindowsCredentialSecretStore::new());
            app.manage(perception::screen_policy::ScreenPerceptionSessionGate::new());
            app.manage(perception::screen_capture::target::ScreenCaptureTargetBroker::new());
            app.manage(perception::screen_capture::operation::ScreenCaptureOperationGate::new());
            // D27: one process-local cross-source Chat perception offer
            // gate.  OCR and Cloud Vision keep separate source authorities,
            // but neither may occupy the unified Chat slot concurrently.
            let chat_offer_gate = Arc::new(perception::perception_chat_offer_gate::PerceptionChatOfferGate::new());
            app.manage(Arc::clone(&chat_offer_gate));
            // D24-A/B1: the single App-managed process-local screen-context
            // handoff broker.  Main observation and explicit handoff commands
            // consume it; Chat integration remains a later stage.
            app.manage(perception::screen_context::ScreenContextHandoffBroker::new());
            // D24-C1: the single App-managed Chat screen-attachment marker
            // bridging a validated Pending Grant to an opaque Chat-facing
            // attachment ID.  Presentation-only; the handoff broker above
            // remains the actual grant authority.
            app.manage(perception::screen_chat_attachment::ScreenContextChatAttachmentBroker::new_with_offer_gate(
                Arc::clone(&chat_offer_gate),
            ));
            // D27: bounded semantic result and the separate Vision → Chat
            // handoff are process-local single-slot authorities.  Neither
            // stores image bytes or survives process restart.
            app.manage(perception::screen_vision_semantic_result::ScreenVisionSemanticResultBroker::new());
            app.manage(perception::screen_vision_context_handoff::ScreenVisionContextHandoffBroker::new_with_offer_gate(
                chat_offer_gate,
            ));
            // D25-C2: the single process-local screen-vision outbound
            // candidate authority.  It owns at most one C1 projection and is
            // deliberately not exposed through a Tauri command or ACL.
            app.manage(
                perception::screen_vision_outbound_candidate::ScreenVisionOutboundCandidateBroker::new(),
            );
            // D25-D2: the single process-local one-shot outbound grant broker.
            // It is internal state only; no command or ACL is added here.
            app.manage(
                perception::screen_vision_outbound_grant::ScreenVisionOutboundGrantBroker::new(),
            );
            // D26-B: Main-owned explicit Vision delivery state.  Both brokers
            // are process-local single-slot authorities and are not exposed
            // to Settings or Chat.
            app.manage(perception::screen_vision_delivery::ScreenVisionReviewBroker::new());
            app.manage(
                perception::screen_vision_delivery::ScreenVisionDeliveryOperationGate::new(),
            );
            app.manage(storage::LlmCandidateExtractionCoordinator::default());
            app.manage(model::runtime::ModelRuntimeCoordinator::default());
            app.manage(conversation::ConversationCognitionCoordinator::default());
            app.manage(vector_store::LanceDbVectorStoreRegistry::default());
            app.manage(
                memory::vector_sync_stage_runtime::FencedVectorSyncCompositionGate::default(),
            );
            app.manage(
                memory::vector_index_runtime::MemoryVectorIndexRuntimeCoordinator::default(),
            );
            app.manage(memory::vector_sync_worker::MemoryVectorSyncWorkerCoordinator::default());
            app.manage(memory::candidate_service::CandidateConfirmationCoordinator::default());
            create_configured_windows(app)?;
            configure_window_lifecycle(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            conversation::service::chat_with_governed_context,
            conversation::history::create_conversation,
            conversation::history::list_conversations,
            conversation::history::get_conversation_messages,
            conversation::history::rename_conversation,
            conversation::history::delete_conversation,
            model::profile::create_model_profile,
            model::profile::list_model_profiles,
            model::profile::get_model_profile,
            model::profile::update_model_profile,
            model::profile::delete_model_profile,
            model::profile::set_active_model_profile,
            model::profile::get_active_model_profile,
            model::runtime::test_model_profile_connection,
            memory::create_memory_candidate,
            memory::list_memories,
            memory::get_memory,
            memory::update_memory_candidate,
            memory::delete_memory,
            memory::candidate_confirmation_commands::prepare_candidate_confirmation,
            memory::candidate_confirmation_commands::confirm_candidate_memory,
            memory::candidate_confirmation_commands::cancel_candidate_confirmation_approval,
            memory::extraction_commands::extract_candidate_memories,
            memory::management::list_managed_memories,
            memory::management::get_managed_memory,
            memory::management::list_memory_revisions,
            memory::management::update_confirmed_memory,
            memory::management::set_memory_sensitive,
            memory::management::delete_memory_permanently,
            memory::vector_index_runtime::get_memory_vector_index_status,
            memory::vector_index_runtime::get_memory_vector_index_job,
            memory::vector_index_runtime::cancel_memory_vector_index_job,
            memory::vector_sync_worker::get_memory_vector_sync_settings,
            memory::vector_sync_worker::set_memory_vector_sync_enabled,
            memory::vector_sync_worker::get_memory_vector_sync_status,
            memory::vector_sync_stage_runtime::start_fenced_vector_sync_drain,
            memory::vector_sync_stage_runtime::run_late_delete_resolution_once,
            memory::vector_sync_stage_runtime::start_vector_generation_rebuild,
            memory::vector_sync_stage_runtime::get_vector_generation_rebuild_job,
            memory::vector_sync_stage_runtime::cancel_vector_generation_rebuild,
            memory::vector_sync_worker::pause_memory_vector_sync,
            memory::vector_sync_worker::retry_memory_vector_sync_failures,
            secrets::save_api_credential,
            secrets::has_api_credential,
            secrets::delete_api_credential,
            open_settings_window,
            open_chat_window,
            close_settings_window,
            storage::initialize_storage,
            storage::get_storage_location,
            storage::validate_storage_location,
            storage::migrate_storage_location,
            storage::save_life_identity,
            storage::get_current_life_identity,
            storage::get_life_identity,
            storage::update_life_identity_base_info,
            storage::save_persona_template,
            storage::get_persona_template,
            storage::body_package::install_live2d_body_package,
            storage::body_package::list_body_packages,
            storage::body_package::get_body_package,
            storage::body_package::delete_body_package,
            storage::body_package::get_body_package_registry_snapshot,
            storage::body_package::set_current_life_body,
            storage::live2d_core::import_cubism_core,
            storage::live2d_core::get_cubism_core_snapshot,
            perception::screen_settings::get_screen_perception_policy,
            perception::screen_settings::create_screen_perception_policy,
            perception::screen_settings::update_screen_perception_policy,
            perception::screen_settings::get_screen_perception_session_status,
            perception::screen_settings::arm_screen_perception_session,
            perception::screen_settings::disarm_screen_perception_session,
            perception::screen_vision_outbound_settings::get_screen_vision_outbound_policy,
            perception::screen_vision_outbound_settings::create_screen_vision_outbound_policy,
            perception::screen_vision_outbound_settings::update_screen_vision_outbound_policy,
            perception::screen_capture::pick_screen_capture_target,
            perception::screen_capture::get_screen_capture_target_status,
            perception::screen_capture::clear_screen_capture_target,
            perception::screen_capture::capture_screen_smoke,
            perception::screen_observation::observe_screen_now,
            perception::screen_observation::prepare_main_screen_context_for_chat,
            perception::screen_observation::get_main_screen_perception_status,
            perception::screen_observation::offer_main_screen_context_to_chat,
            perception::screen_observation::revoke_main_pending_screen_context_grant,
            perception::screen_observation::revoke_main_screen_context_attachment,
            perception::screen_chat_attachment::get_pending_screen_context_attachment,
            perception::screen_chat_attachment::dismiss_pending_screen_context_attachment,
            perception::screen_vision_delivery::prepare_main_screen_vision_review,
            perception::screen_vision_delivery::get_main_screen_vision_status,
            perception::screen_vision_delivery::execute_main_screen_vision_review,
            perception::screen_vision_delivery::abandon_main_screen_vision_delivery,
            perception::screen_vision_delivery::offer_screen_vision_result_to_chat,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn create_configured_windows(app: &mut tauri::App) -> Result<(), std::io::Error> {
    let windows = app.config().app.windows.clone();
    for config in windows.iter().filter(|window| !window.create) {
        WebviewWindowBuilder::from_config(app.handle(), config)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .build()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }
    Ok(())
}

#[tauri::command]
fn open_settings_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    show_secondary_window(&app, "settings")
}

#[tauri::command]
fn open_chat_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    show_secondary_window(&app, "chat")
}

fn show_secondary_window(app: &tauri::AppHandle, label: &str) -> Result<(), storage::StorageError> {
    let window = app.get_webview_window(label).ok_or_else(|| {
        storage::StorageError::new(
            "SECONDARY_WINDOW_NOT_CONFIGURED",
            "The requested secondary window is not configured.",
            false,
        )
    })?;
    window
        .unminimize()
        .and_then(|_| window.set_always_on_top(true))
        .and_then(|_| window.show())
        .and_then(|_| window.set_focus())
        .map_err(|error| {
            storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
        })
}

#[tauri::command]
fn close_settings_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    hide_secondary_window(&app, "settings")
}

fn hide_secondary_window(app: &tauri::AppHandle, label: &str) -> Result<(), storage::StorageError> {
    let window = app.get_webview_window(label).ok_or_else(|| {
        storage::StorageError::new(
            "SECONDARY_WINDOW_NOT_CONFIGURED",
            "The requested secondary window is not configured.",
            false,
        )
    })?;
    window
        .set_always_on_top(false)
        .and_then(|_| window.hide())
        .map_err(|error| {
            storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
        })
}

fn configure_window_lifecycle(app: &mut tauri::App) -> Result<(), std::io::Error> {
    for label in ["chat", "settings"] {
        let window = app.get_webview_window(label).ok_or_else(|| {
            std::io::Error::other(format!("Configured window '{label}' is missing."))
        })?;
        let window_to_hide = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window_to_hide.set_always_on_top(false);
                let _ = window_to_hide.hide();
            }
        });
    }

    let main_window = app
        .get_webview_window("main")
        .ok_or_else(|| std::io::Error::other("Configured main window is missing."))?;
    let app_handle = app.handle().clone();
    main_window.on_window_event(move |event| {
        if matches!(event, WindowEvent::CloseRequested { .. }) {
            app_handle.exit(0);
        }
    });

    Ok(())
}
