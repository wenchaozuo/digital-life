mod candidate_memory_internal;
// D11-B1 is the emotion authority foundation; the emotion domain has no
// production caller until the D11-B2+ policy/conversation stages, so the
// frozen surface is allowed as dead code outside test builds. D12-B1 is the
// same foundation stage for the relationship domain.
pub mod conversation;
pub mod embedding;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod emotion;
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
pub mod memory;
pub mod model;
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
        .setup(|app| {
            let storage = storage::StorageService::initialize(app.handle())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(storage);
            app.manage(secrets::WindowsCredentialSecretStore::new());
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
