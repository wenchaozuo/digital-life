use std::ffi::OsStr;
use std::process::exit;

use vita_agent::VITA_AGENT_RUNTIME_ID;

fn main() {
    let mut args = std::env::args_os();
    let _executable = args.next();
    let probe = args.next();
    let no_extra_arguments = args.next().is_none();

    if probe.as_deref() == Some(OsStr::new("--probe")) && no_extra_arguments {
        println!(
            r#"{{"runtime":"{}","mode":"probe","model_execution":"forbidden","provider_policy":"not_configured"}}"#,
            VITA_AGENT_RUNTIME_ID
        );
        return;
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
