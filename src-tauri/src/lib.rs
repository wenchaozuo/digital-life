pub mod model;
mod storage;

use tauri::Manager;
use tauri::{WebviewUrl, WebviewWindowBuilder};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let storage = storage::StorageService::initialize(app.handle())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(storage);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            model::chat_with_model,
            open_settings_window,
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

#[tauri::command]
fn open_settings_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    if let Some(window) = app.get_webview_window("settings") {
        window.unminimize().map_err(|error| {
            storage::StorageError::new("SETTINGS_WINDOW_ERROR", error.to_string(), true)
        })?;
        window.show().map_err(|error| {
            storage::StorageError::new("SETTINGS_WINDOW_ERROR", error.to_string(), true)
        })?;
        window.set_focus().map_err(|error| {
            storage::StorageError::new("SETTINGS_WINDOW_ERROR", error.to_string(), true)
        })?;
        return Ok(());
    }

    let uses_dev_server = app.config().build.dev_url.is_some();
    let page = if uses_dev_server {
        "index.html"
    } else {
        "settings.html"
    };
    let builder = WebviewWindowBuilder::new(&app, "settings", WebviewUrl::App(page.into()))
        .title("Digital Life Settings")
        .inner_size(680.0, 650.0)
        .min_inner_size(560.0, 520.0)
        .resizable(true)
        .decorations(true)
        .transparent(false);
    let builder = if uses_dev_server {
        builder.initialization_script("window.__DIGITAL_LIFE_WINDOW_KIND__ = 'settings';")
    } else {
        builder
    };

    builder.build().map(|_| ()).map_err(|error| {
        storage::StorageError::new("SETTINGS_WINDOW_ERROR", error.to_string(), true)
    })
}

#[tauri::command]
fn close_settings_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    if let Some(window) = app.get_webview_window("settings") {
        window.close().map_err(|error| {
            storage::StorageError::new("SETTINGS_WINDOW_ERROR", error.to_string(), true)
        })?;
    }

    Ok(())
}
