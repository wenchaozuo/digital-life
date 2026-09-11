#![cfg(all(windows, feature = "d29-h9-test-helper"))]

//! D29-H9-R1's positive process boundary canary.
//!
//! The child is the actual `vita-agent` binary built with the narrowly scoped
//! test helper feature.  The child still composes the pinned Codex runtime,
//! the authenticated local Responses gateway, the production H7-C
//! contributor, and the normal Host authority message protocol.  Only the
//! downstream Chat transport is replaced by the deterministic two-response
//! test seam; production transport construction remains untouched.

use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use protocol::{
    ConfirmationDecision, GrantIssued, GrantRevalidated, HostMessage, InitializeSession,
    ProcessGrant, ProviderBinding, ProviderConfiguration, SensitiveCredential, StartTurn,
    VitaMessage, CODEX_UPSTREAM_COMMIT, PROTOCOL_VERSION, RUNTIME_ID,
};
use vita_agent_protocol as protocol;

const LIFE_ID: &str = "h9-canary-life";
const TASK_ID: &str = "h9-canary-task";
const SESSION_ID: &str = "h9-canary-session";
const MODEL: &str = "h9-canary-model";

fn provider() -> ProviderConfiguration {
    ProviderConfiguration {
        profile_id: "h9-canary-profile".to_string(),
        purpose: "chat".to_string(),
        provider_kind: "openai_compatible".to_string(),
        base_url: "http://127.0.0.1:9/v1".to_string(),
        model: MODEL.to_string(),
        credential_ref: "h9-canary-credential".to_string(),
        credential_destination: "http://127.0.0.1:9/v1".to_string(),
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

fn send<T: serde::Serialize>(writer: &mut BufWriter<impl std::io::Write>, message: &T) {
    protocol::write_frame(writer, message).expect("canary Host frame");
}

fn send_sensitive<T: serde::Serialize>(writer: &mut BufWriter<impl std::io::Write>, message: &T) {
    protocol::write_sensitive_frame(writer, message).expect("canary sensitive Host frame");
}

fn receive(reader: &mut BufReader<impl std::io::Read>) -> VitaMessage {
    let body = protocol::read_frame(reader)
        .expect("canary Vita frame")
        .expect("canary sidecar did not close its frame stream");
    protocol::decode_frame(&body).expect("canary Vita message")
}

fn git_fixture() -> (tempfile::TempDir, PathBuf) {
    let workspace = tempfile::tempdir().expect("canary Git workspace");
    std::fs::write(workspace.path().join("canary.txt"), "h9\n").expect("canary file");
    let git_path = [
        PathBuf::from(r"E:\Program Files\Git\mingw64\bin\git.exe"),
        PathBuf::from(r"C:\Program Files\Git\mingw64\bin\git.exe"),
        PathBuf::from(r"E:\Program Files\Git\bin\git.exe"),
        PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("absolute Git executable");
    let initialized = Command::new(&git_path)
        .args(["init", "--quiet"])
        .current_dir(workspace.path())
        .status()
        .expect("initialize canary Git repository");
    assert!(initialized.success(), "canary Git repository initialized");
    (workspace, git_path)
}

fn grant(binding: protocol::ProcessBinding, used: bool) -> ProcessGrant {
    let now = unix_millis();
    ProcessGrant {
        session_id: SESSION_ID.to_string(),
        grant_id: "h9-canary-grant".to_string(),
        confirmation_id: "h9-canary-confirmation".to_string(),
        binding,
        authorization_revision: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(30_000),
        single_use: true,
        used,
    }
}

#[test]
fn process_isolated_codex_h8_h7c_second_provider_closure() {
    let (workspace, git_path) = git_fixture();
    let app_data = tempfile::tempdir().expect("canary app data");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_vita-agent"));
    assert!(executable.is_file(), "feature-enabled Vita binary exists");

    let mut child = Command::new(&executable)
        .arg("--serve-ipc-test-canary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn process-isolated Vita sidecar");
    assert!(child.id() != 0, "canary has a distinct sidecar process");
    let stdin = child.stdin.take().expect("canary stdin");
    let stdout = child.stdout.take().expect("canary stdout");
    let mut writer = BufWriter::new(stdin);
    let mut reader = BufReader::new(stdout);

    let handshake = receive(&mut reader);
    let VitaMessage::Handshake(handshake) = handshake else {
        panic!("canary first frame was not Handshake");
    };
    assert_eq!(handshake.protocol_version, PROTOCOL_VERSION);
    assert_eq!(handshake.runtime, RUNTIME_ID);
    assert_eq!(handshake.codex_commit, CODEX_UPSTREAM_COMMIT);

    let configuration = provider();
    send(
        &mut writer,
        &HostMessage::Initialize(InitializeSession {
            request_id: "h9-canary-initialize".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            session_id: SESSION_ID.to_string(),
            life_id: LIFE_ID.to_string(),
            task_id: TASK_ID.to_string(),
            app_data_root: app_data.path().to_string_lossy().into_owned(),
            workspace_path: workspace.path().to_string_lossy().into_owned(),
            git_path: git_path.to_string_lossy().into_owned(),
            provider: Some(configuration.clone()),
        }),
    );
    assert!(matches!(receive(&mut reader), VitaMessage::Ready(_)));

    let turn_id = "h9-canary-turn";
    let binding = ProviderBinding::derive(SESSION_ID, turn_id, &configuration)
        .expect("canary provider binding");
    send(
        &mut writer,
        &HostMessage::StartTurn(StartTurn {
            request_id: "h9-canary-start".to_string(),
            session_id: SESSION_ID.to_string(),
            turn_id: turn_id.to_string(),
            prompt: "Inspect the governed workspace status.".to_string(),
            binding,
        }),
    );

    let mut confirmation_seen = false;
    let mut scope_seen = false;
    let mut grant_seen = false;
    let mut revalidation_seen = false;
    let mut credential_requests = 0_u32;
    let final_text = loop {
        match receive(&mut reader) {
            VitaMessage::TurnState(_) => {}
            VitaMessage::ConfirmationRequired(request) => {
                confirmation_seen = true;
                assert_eq!(request.capability_id, "vita.process.workspace.git_status");
                assert_eq!(request.host_turn_id, turn_id);
                send(
                    &mut writer,
                    &HostMessage::ConfirmationReply(protocol::ConfirmationReply {
                        request_id: request.request_id,
                        session_id: SESSION_ID.to_string(),
                        decision: ConfirmationDecision::Confirm,
                        authorization_revision: Some(1),
                    }),
                );
            }
            VitaMessage::AuthorityEvaluate(request) => {
                scope_seen = true;
                assert_eq!(request.host_turn_id, turn_id);
                send(
                    &mut writer,
                    &HostMessage::AuthorityScopeReply(protocol::AuthorityScopeReply {
                        request_id: request.request_id,
                        session_id: SESSION_ID.to_string(),
                        allowed: true,
                        authorization_revision: Some(1),
                        error_code: None,
                    }),
                );
            }
            VitaMessage::IssueGrant(request) => {
                grant_seen = true;
                assert_eq!(request.host_turn_id, turn_id);
                send(
                    &mut writer,
                    &HostMessage::GrantIssued(GrantIssued {
                        request_id: request.request_id,
                        session_id: SESSION_ID.to_string(),
                        allowed: true,
                        grant: Some(grant(request.binding, false)),
                        error_code: None,
                    }),
                );
            }
            VitaMessage::RevalidateGrant(request) => {
                revalidation_seen = true;
                assert_eq!(request.host_turn_id, turn_id);
                send(
                    &mut writer,
                    &HostMessage::GrantRevalidated(GrantRevalidated {
                        request_id: request.request_id,
                        session_id: SESSION_ID.to_string(),
                        allowed: true,
                        grant: Some(grant(request.binding, true)),
                        error_code: None,
                    }),
                );
            }
            VitaMessage::CredentialRequired(request) => {
                credential_requests += 1;
                assert_eq!(request.session_id, SESSION_ID);
                assert_eq!(request.turn_id, turn_id);
                assert_eq!(request.binding.credential_ref, "h9-canary-credential");
                send_sensitive(
                    &mut writer,
                    &HostMessage::SensitiveCredentialReply(protocol::SensitiveCredentialReply {
                        request_id: request.request_id,
                        session_id: SESSION_ID.to_string(),
                        turn_id: request.turn_id,
                        binding_hash: request.binding.binding_hash,
                        credential_ref: request.binding.credential_ref,
                        credential: Some(
                            SensitiveCredential::new("h9-canary-fake-credential".to_string())
                                .expect("canary fake credential"),
                        ),
                        error_code: None,
                    }),
                );
            }
            VitaMessage::TurnCompleted(message) => {
                break message.assistant_text;
            }
            VitaMessage::TurnFailed(message) => {
                panic!(
                    "process canary failed: {} {}",
                    message.error_code, message.message
                );
            }
            other => panic!("unexpected process-canary frame: {other:?}"),
        }
    };

    assert!(confirmation_seen, "real H8 confirmation RPC was observed");
    assert!(scope_seen, "real H8 workspace authority RPC was observed");
    assert!(grant_seen, "Host ProcessGrant was issued");
    assert!(
        revalidation_seen,
        "final ProcessGrant revalidation was observed"
    );
    assert_eq!(
        credential_requests, 2,
        "each provider request resolved a credential"
    );
    assert_eq!(
        final_text.as_str(),
        "D29-H9 process-isolated closure complete (provider_requests=2)"
    );
    assert!(!final_text.contains("h9-canary-fake-credential"));

    send(
        &mut writer,
        &HostMessage::Shutdown(protocol::Shutdown {
            request_id: "h9-canary-shutdown".to_string(),
            session_id: SESSION_ID.to_string(),
        }),
    );
    assert!(matches!(
        receive(&mut reader),
        VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id, .. }) if session_id == SESSION_ID
    ));
    drop(writer);
    let status = child.wait().expect("sidecar exit");
    assert!(status.success(), "sidecar exited successfully");
}
