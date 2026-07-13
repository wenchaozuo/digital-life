pub mod embedding;
pub mod memory;
pub mod model;
mod storage;

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
            create_configured_windows(app)?;
            configure_window_lifecycle(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            model::chat_with_model,
            memory::create_memory_candidate,
            memory::list_memories,
            memory::get_memory,
            memory::update_memory_candidate,
            memory::confirm_memory,
            memory::delete_memory,
            memory::retrieval::retrieve_memories,
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
