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

struct SecondaryWindowDefinition {
    label: &'static str,
    title: &'static str,
    width: f64,
    height: f64,
    min_width: f64,
    min_height: f64,
    production_page: &'static str,
    dev_window_kind: &'static str,
}

#[tauri::command]
fn open_settings_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    open_secondary_window(
        &app,
        SecondaryWindowDefinition {
            label: "settings",
            title: "Digital Life Settings",
            width: 680.0,
            height: 650.0,
            min_width: 560.0,
            min_height: 520.0,
            production_page: "settings.html",
            dev_window_kind: "settings",
        },
    )
}

#[tauri::command]
fn open_chat_window(app: tauri::AppHandle) -> Result<(), storage::StorageError> {
    open_secondary_window(
        &app,
        SecondaryWindowDefinition {
            label: "chat",
            title: "Digital Life Chat",
            width: 680.0,
            height: 720.0,
            min_width: 560.0,
            min_height: 520.0,
            production_page: "chat.html",
            dev_window_kind: "chat",
        },
    )
}

fn open_secondary_window(
    app: &tauri::AppHandle,
    definition: SecondaryWindowDefinition,
) -> Result<(), storage::StorageError> {
    if let Some(window) = app.get_webview_window(definition.label) {
        window.unminimize().map_err(|error| {
            storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
        })?;
        window.show().map_err(|error| {
            storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
        })?;
        window.set_focus().map_err(|error| {
            storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
        })?;
        return Ok(());
    }

    let uses_dev_server = app.config().build.dev_url.is_some();
    let page = if uses_dev_server {
        "index.html"
    } else {
        definition.production_page
    };
    let builder = WebviewWindowBuilder::new(app, definition.label, WebviewUrl::App(page.into()))
        .title(definition.title)
        .inner_size(definition.width, definition.height)
        .min_inner_size(definition.min_width, definition.min_height)
        .resizable(true)
        .decorations(true)
        .transparent(false);
    let builder = if uses_dev_server {
        builder.initialization_script(format!(
            "window.__DIGITAL_LIFE_WINDOW_KIND__ = '{}';",
            definition.dev_window_kind
        ))
    } else {
        builder
    };

    builder.build().map(|_| ()).map_err(|error| {
        storage::StorageError::new("SECONDARY_WINDOW_ERROR", error.to_string(), true)
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
