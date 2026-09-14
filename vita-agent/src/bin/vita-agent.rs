use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::exit;

use vita_agent::VITA_AGENT_RUNTIME_ID;

fn main() {
    let mut args = std::env::args_os();
    let _executable = args.next();
    let probe = args.next();
    let remaining = args.collect::<Vec<_>>();
    let no_extra_arguments = remaining.is_empty();

    if probe.as_deref() == Some(OsStr::new("--probe")) && no_extra_arguments {
        println!(
            r#"{{"runtime":"{}","mode":"probe","model_execution":"forbidden","provider_policy":"not_configured"}}"#,
            VITA_AGENT_RUNTIME_ID
        );
        return;
    }

    #[cfg(all(windows, feature = "d29-h9-test-helper"))]
    if probe.as_deref() == Some(OsStr::new("--seed-recovery-fixture")) {
        let mut args = remaining.into_iter();
        let Some(app_data_root) = args.next() else {
            eprintln!(
                "usage: vita-agent --seed-recovery-fixture <app-data> <workspace> <life> <task>"
            );
            exit(2);
        };
        let Some(workspace_root) = args.next() else {
            eprintln!(
                "usage: vita-agent --seed-recovery-fixture <app-data> <workspace> <life> <task>"
            );
            exit(2);
        };
        let Some(life_id) = args.next() else {
            eprintln!(
                "usage: vita-agent --seed-recovery-fixture <app-data> <workspace> <life> <task>"
            );
            exit(2);
        };
        let Some(task_id) = args.next() else {
            eprintln!(
                "usage: vita-agent --seed-recovery-fixture <app-data> <workspace> <life> <task>"
            );
            exit(2);
        };
        if args.next().is_some() {
            eprintln!(
                "usage: vita-agent --seed-recovery-fixture <app-data> <workspace> <life> <task>"
            );
            exit(2);
        }
        let life_id = life_id.to_string_lossy();
        let task_id = task_id.to_string_lossy();
        match vita_agent::seed_recovery_fixture(
            PathBuf::from(app_data_root),
            PathBuf::from(workspace_root),
            &life_id,
            &task_id,
        ) {
            Ok(transaction_id) => {
                println!("{transaction_id}");
                return;
            }
            Err(error) => {
                eprintln!("Vita recovery fixture seeding failed: {error}");
                exit(1);
            }
        }
    }

    if probe.as_deref() == Some(OsStr::new("--serve-ipc")) && no_extra_arguments {
        #[cfg(windows)]
        {
            if let Err(error) = vita_agent::run_sidecar_ipc() {
                eprintln!("Vita sidecar terminated: {error}");
                exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("Vita sidecar is supported only on Windows");
            exit(2);
        }
    }

    #[cfg(all(windows, feature = "d29-h9-test-helper"))]
    if probe.as_deref() == Some(OsStr::new("--serve-ipc-test-canary")) && no_extra_arguments {
        if let Err(error) = vita_agent::run_sidecar_ipc_test_canary() {
            eprintln!("Vita H9 test canary sidecar terminated: {error}");
            exit(1);
        }
        return;
    }

    eprintln!("usage: vita-agent --probe | --serve-ipc");
    exit(2);
}
