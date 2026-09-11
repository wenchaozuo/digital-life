use std::{env, path::PathBuf};

fn main() {
    let sidecar = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../vita-agent/target/release/vita-agent.exe");
    if !sidecar.is_file() {
        if env::var("PROFILE").as_deref() == Ok("release") {
            panic!(
                "Vita sidecar release image is missing at {}; run `npm run build:vita-sidecar` first",
                sidecar.display()
            );
        }
        // `cargo check` and debug library tests must remain runnable before a
        // release bundle is staged.  The release build above is still a hard
        // gate, and the packaged resource mapping remains explicit in the
        // Tauri config.
        if env::var_os("TAURI_CONFIG").is_none() {
            env::set_var("TAURI_CONFIG", r#"{"bundle":{"resources":[]}}"#);
        }
    }
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "chat_with_governed_context",
            "create_conversation",
            "list_conversations",
            "get_conversation_messages",
            "rename_conversation",
            "delete_conversation",
            "create_model_profile",
            "list_model_profiles",
            "get_model_profile",
            "update_model_profile",
            "delete_model_profile",
            "set_active_model_profile",
            "get_active_model_profile",
            "test_model_profile_connection",
            "create_memory_candidate",
            "list_memories",
            "get_memory",
            "update_memory_candidate",
            "delete_memory",
            "prepare_candidate_confirmation",
            "confirm_candidate_memory",
            "cancel_candidate_confirmation_approval",
            "list_managed_memories",
            "get_managed_memory",
            "list_memory_revisions",
            "update_confirmed_memory",
            "set_memory_sensitive",
            "delete_memory_permanently",
            "get_memory_vector_index_status",
            "start_memory_vector_index_rebuild",
            "get_memory_vector_index_job",
            "cancel_memory_vector_index_job",
            "get_memory_vector_sync_settings",
            "set_memory_vector_sync_enabled",
            "get_memory_vector_sync_status",
            "start_memory_vector_sync",
            "pause_memory_vector_sync",
            "retry_memory_vector_sync_failures",
            "save_api_credential",
            "has_api_credential",
            "delete_api_credential",
            "open_settings_window",
            "open_chat_window",
            "close_settings_window",
            "start_vita_sidecar",
            "get_vita_sidecar_status",
            "start_vita_turn",
            "cancel_vita_turn",
            "confirm_vita_sidecar",
            "deny_vita_sidecar",
            "cancel_vita_sidecar",
            "stop_vita_sidecar",
            "get_capability_authorization_snapshot",
            "set_capability_authorization_enabled",
            "initialize_storage",
            "get_storage_location",
            "validate_storage_location",
            "migrate_storage_location",
            "save_life_identity",
            "get_current_life_identity",
            "get_life_identity",
            "update_life_identity_base_info",
            "save_persona_template",
            "get_persona_template",
        ]),
    ))
    .expect("failed to build Tauri application manifest")
}
