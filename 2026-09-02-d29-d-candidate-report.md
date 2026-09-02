# D29-D Candidate Report

Status: **D29-D-V1 VERIFICATION CANDIDATE ONLY — NOT FROZEN**

## Revision and scope

- Branch: `deepseek/d29-d-anonymous-ephemeral-thread-001`
- Exact base / certified D29-C head: `43da2917ed4d474d1de47f4881002ff70fc727b0`
- Candidate implementation SHA: `e6c4dda8b0ea09da1663a56af3a4cc3c5fd2e534`
- Candidate implementation parent: `e97521406ae91b0371b3c0bf4e3d4811a6dce4b3`
- Publication: local commit only; no GitHub push and no model-assignment/review dispatch was performed
- Exact parent: `c6e98f7c7b77198afc4ddfa3ded1071d00492253`
- Base comparison at the implementation candidate: ahead `4`, behind `0`; linear history; no merge, rebase, pull, or cleanup was performed
- Pinned upstream: `openai/codex` `rust-v0.152.0` at `316795b3cf2a45e90d121d9f46499d4658b2645c`
- Protocol schema: `d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669`

Changed candidate files:

- `src-tauri/src/execution_enclave/anonymous_runtime.rs`
- `src-tauri/src/execution_enclave/mod.rs`
- `src-tauri/src/execution_enclave/runtime_provisioning.rs`

No D28 authority, schema, Tauri command, frontend route, or fake App Server file was changed. Existing inherited untracked reports, documents, and `.workbuddy` content were preserved.

## AUTH SOURCE MATRIX

| Source | Reachable under D29-D? | Why / why not | Guard |
|---|---|---|---|
| `$CODEX_HOME/auth.json` | No | Child `CODEX_HOME` is the private provisioned home, never the user home; private preflight rejects `auth.json`. | Complete replacement environment and private-home preflight |
| `OPENAI_API_KEY`, `CODEX_API_KEY`, `CODEX_ACCESS_TOKEN` | No | The child receives exactly `CODEX_HOME` plus two D29 identity markers; production preflight does not inspect the parent environment. | No environment inheritance; exact child-environment report |
| Refresh/revoke/client-id auth override variables | No | These are not copied into the child. | Complete replacement environment and host audit |
| CLI persisted auth / ChatGPT login | No | The pinned auth source supports file, keyring, Auto, and ephemeral stores; private `CODEX_HOME` alone does not isolate the OS-global keyring. | Fixed `--config cli_auth_credentials_store="file"`; no private auth file; no caller config |
| OS keyring / Codex Auth keyring | No | File-only CLI auth prevents Auto/Keyring selection in the official child. | Compile-time fixed launch override; negative fence test |
| MCP OAuth credential store | No | No project/user MCP config is reachable and Auto/Keyring selection is overridden. | Fixed `--config mcp_oauth_credentials_store="file"`; private preflight |
| `CODEX_EXEC_SERVER_URL` / external exec configuration | No | Not present in the child; no caller-selected config is accepted. | Complete replacement environment; isolated cwd; fixed read-only config |
| workload / external auth provider | No | No auth environment or process configuration is passed to the child. | Exact child environment construction |
| user/project/profile/managed config | No | Private home is isolated, cwd is a dedicated temporary root, and the trusted launch has no caller-supplied config JSON. | Private preflight plus fixed `sandbox_mode="read-only"` |
| plugins, apps, skills, MCP server definitions | No | User `CODEX_HOME` and project `.codex` are outside the child's private home/cwd; no turn or tool loop is started. | Private home/cwd isolation and no `turn/start` |
| OTLP / telemetry exporter environment | No | The complete child environment contains no exporter/proxy/diagnostic variables. | Exact three-entry child environment audit; no real network test |
| model cache refresh / provider selection | No remote model operation | Pinned source audit records the no-auth `should_refresh_models=false` condition; D29-D stops before any model turn and does not use network to prove it. | No auth, no `turn/start`, source-level invariant |
| remote-control state | No | No private persisted remote-control state or remote-control client request is supplied. | Empty private runtime plus complete environment replacement |

## Anonymous runtime profile and preflight

`AnonymousCodexRuntimeProfile` is a fail-closed runtime precondition, not a capability or permission authority. Before the trusted spawn it:

- verifies the private home path again under the trusted runtime root;
- reads only that Digital Life-private `CODEX_HOME`; it does not inspect `CODEX_HOME`, `HOME`, `USERPROFILE`, `PATH`, or user config in the production preflight;
- rejects unreadable roots, unreadable directory entries, non-directory roots, and reparse/symlink entries;
- rejects credential/config names including `auth.json`, `.credentials.json`, `config.toml`, `*.config.toml`, `environments.toml`, `managed_config.toml`, `requirements.toml`, `session_index.jsonl`, `secrets`, and `AGENTS.md`;
- rejects unclassifiable direct private-home entries;
- leaves the parent environment unconsulted; the exact child environment is audited separately; and
- returns `AnonymousRuntimeViolation` before the Windows `CreateProcessW` boundary.

The production `CODEX_HOME` value is derived only from `TrustedCodexRuntimeLayout.private_codex_home`, which is shaped as the fixed `codex-home` child of the verified, hash-pinned runtime root. `HOME`, `USERPROFILE`, and the parent `CODEX_HOME` are not used to derive an execution path. The only user-home environment lookup is inside the ignored test-only global canary and the existing test-only forbidden-location check.

The child environment is a complete replacement, not an overlay. The official smoke re-report must contain only:

1. `CODEX_HOME=<private provisioned home>`
2. `CODEX_D29_CLIENT_CONTRACT_VERSION=<pinned contract>`
3. `CODEX_D29_UPSTREAM_COMMIT=<pinned commit>`

## Exact private-home artifact policy

Recognized non-authority runtime artifacts are:

- `installation_id`
- `state_5.sqlite`, `logs_2.sqlite`, `goals_1.sqlite`, `memories_1.sqlite`, `queue_1.sqlite`
- their `-wal` / `-shm` SQLite sidecars
- `thread_history_1.sqlite` and its sidecars as a recognized official runtime name, but it is explicitly rejected by the official smoke if it exists after the ephemeral run
- `models_cache.json`
- `.sandbox_migration` (the pinned upstream one-shot sandbox-policy migration marker)
- `log/`, `skills/`, `.tmp/`, and `tmp/`
- empty `sessions/` and `archived_sessions/` directories

Any entry under `sessions/` or `archived_sessions/` is rejected by preflight. The official pinned rollout source uses `archived_sessions` with an underscore; the previous space-separated spelling is not accepted. Unknown direct entries fail closed.

The smoke uses a complete before/after snapshot of both private `CODEX_HOME` and the isolated cwd. The real pinned smoke passed after classifying the two observed official runtime outputs (`.sandbox_migration` and `skills/`); it still rejects added or changed `sessions/`, `archived_sessions/`, `session_index.jsonl`, `thread_history_1.sqlite*`, and rollout JSONL/Zstandard artifacts. No durable private-home or isolated-cwd artifact was observed.

Delta status is kept separate: (A) Digital Life-private `CODEX_HOME`: official smoke passed with no durable artifact; (B) isolated workspace: official smoke passed with no durable artifact; (C) user `~/.codex`: no valid isolated canary before/after pair was collected, and no Digital-Life-attributed mutation was found in the read-only source/process audit.

## Thread/start and side-effect audit

The typed D29-B request remains exactly `{"cwd": <isolated root>, "ephemeral": true}`. No arbitrary caller fields were added.

The official smoke records the only successful client writes and requires this exact sequence:

```text
initialize -> initialized -> thread/start
```

It fails if `turn/start` appears. Therefore no provider response, model inference, agent loop, shell, patch, or tool execution is entered. The returned thread id remains nonempty and bounded, the `thread/started` id must equal it exactly, and the existing wrong-thread/RPC-id/server-request-deny/queue invariants remain untouched.

The initialize result is also typed to retain `codexHome`; the official smoke compares it with the provisioned private home after Windows verbatim-prefix normalization.

## Official asset and real smoke

- Asset: `codex-app-server-x86_64-pc-windows-msvc.exe`
- Asset id: `538792479`
- Size: `227369264`
- SHA-256: `cb8e6cd9996b0647ccecd37d324438c8625738deca754faa74d98e4d7398a98c`
- Smoke: **PASS** — `official_pinned_app_server_ephemeral_thread_smoke`
- Fixture verification: exact size and SHA-256 passed; fixture was kept outside the repository in the system temporary directory

The ignored test `official_pinned_app_server_ephemeral_thread_smoke` performed independent size/hash verification, private provisioning, preflight, trusted spawn, initialize, `thread/start`, exact binding, child-environment audit, before/after snapshots, and clean shutdown. It passed with the exact pinned executable.

The separate ignored `official_smoke_preserves_user_codex_global_canary` gate fingerprints only the three requested user-global files before and after the official smoke. It requires the operator to close unrelated Codex processes and set `DIGITAL_LIFE_D29_D_CANARY_PROCESSES_CLOSED=1`; it never stops processes or changes the files. Result in this environment: **NOT RUN / BLOCKED** because the current Codex Desktop/host/runner processes are active. The test was not forced by setting the marker falsely.

ProcMon incident audit: **NOT PERFORMED**. A safe path-filtered capture could not be established; an unfiltered launch was rejected by the execution safety boundary. No process-level attribution is claimed.

## Schema and production reachability

- Schema 30 remains current.
- `Migration030` remains final.
- No `Migration031` exists.
- `PromptCompiler` remains `rust-v5`.
- `mod execution_enclave;` remains the only reachability; no production caller, Tauri command, Chat route, autonomy route, frontend button, or Agent daemon was added.

## Local Codex configuration investigation

This investigation was read-only. No command or patch in this task deleted, restored, moved, or overwrote anything under `C:\Users\zuo\.codex`; auth contents were not read.

At the latest read-only sample during this task, the following files were still present:

- `C:\Users\zuo\.codex\config.toml` — 3003 bytes; latest observed write metadata changed during the verification window
- `C:\Users\zuo\.codex\auth.json` — 4224 bytes; observed metadata unchanged from `2026-09-01 22:53:19` local time
- `C:\Users\zuo\.codex\.codex-global-state.json` — present; latest observed size and write metadata changed during the verification window
- `C:\Users\zuo\.codex\.codex-global-state.json.bak` — present; latest observed size and write metadata changed during the verification window

The changing `config.toml` and global-state timestamps continued to coincide with active `codex`, `codex-code-mode-host`, `codex-command-runner-0.152.0`, and sandbox-helper processes. Project-source searches found no operation targeting the user Codex home. The most supported explanation is a normal Codex desktop/config or global-state writer, or another concurrently running Codex process, rewriting/recreating state while the task was active. A prior child that did not replace `CODEX_HOME` could also have reached the default user home; this is why D29-D now uses a complete child environment and a private home.

The exact historical deleter cannot be proven from the available evidence: current files exist, Windows object-access auditing was not enabled for a file-specific attribution, and shell history was inaccessible. A future exact attribution would require a scoped Windows Process Monitor/Object Access audit around the Codex home. No such monitor was started by this task.

Historical root cause: **UNRESOLVED**. No process-level causal attribution is claimed.

The public Codex configuration documentation confirms that `CODEX_HOME` defaults to `~/.codex` and controls config, auth, logs, sessions, skills, and other Codex state: <https://learn.chatgpt.com/docs/config-file/environment-variables>.

## Verification status

- `git diff --check`: passed; only the existing Git LF/CRLF working-copy normalization warning appeared during staging.
- `cargo test --lib execution_enclave`: passed; `96` passed, `0` failed, `3` ignored, `0` measured, `2247` filtered out; the lib-test build emitted `8` existing dead-code warnings.
- `cargo check --lib`: passed; the lib check emitted `1` existing dead-code warning.
- `cargo fmt --all -- --check`: passed.
- Official smoke: passed with the exact pinned asset and fixture.
- User-global canary: not run because current Codex writers could not be closed safely; ProcMon fallback not completed.

Final declaration: **D29-D-V1 VERIFICATION CANDIDATE ONLY — NOT FROZEN**
