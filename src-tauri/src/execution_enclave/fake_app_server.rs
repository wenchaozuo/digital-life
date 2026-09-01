use std::{
    env,
    fs,
    io::{self, BufRead, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn main() {
    let mut arguments = env::args();
    let _program = arguments.next();
    let mode = arguments.next().unwrap_or_else(|| "success".to_owned());
    let extra_argument = arguments.next();

    if mode == "descendant-retains-pipes-child" {
        thread::sleep(Duration::from_secs(10));
        return;
    }

    if mode == "crash" {
        std::process::exit(19);
    }

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout());
    for line_result in stdin.lock().lines() {
        let Ok(line) = line_result else {
            return;
        };

        if line.contains("\"method\":\"initialize\"") {
            if mode == "timeout" {
                thread::sleep(Duration::from_secs(5));
                return;
            }
            if mode == "malformed" {
                let _ = writeln!(stdout, "{{malformed");
                let _ = stdout.flush();
                return;
            }
            if mode == "burst" {
                for _ in 0..4096 {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        r#"{"jsonrpc":"2.0","method":"unknown/notification","params":{}}"#
                    );
                }
                let _ = stdout.flush();
                thread::sleep(Duration::from_millis(100));
            }
            if mode == "unknown-notification" {
                let _ = writeln!(
                    stdout,
                    "{}",
                    r#"{"jsonrpc":"2.0","method":"unknown/notification","params":{}}"#
                );
            }
            if mode == "oversized" {
                let oversized = format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":{{"codexHome":"C:/isolated","platformFamily":"windows","platformOs":"windows","userAgent":"{}"}}}}"#,
                    "x".repeat(70_000)
                );
                let _ = writeln!(stdout, "{oversized}");
                let _ = stdout.flush();
                return;
            }
            if mode == "server-request" || mode == "unknown-server-request" {
                let request_method = if mode == "unknown-server-request" {
                    "unknown/serverRequest"
                } else {
                    "item/commandExecution/requestApproval"
                };
                let _ = writeln!(
                    stdout,
                    r#"{{"jsonrpc":"2.0","id":99,"method":"{}","params":{{}}}}"#,
                    request_method
                );
            }
            if mode == "env-probe" {
                let report = [
                    "PATH",
                    "HOME",
                    "USERPROFILE",
                    "CODEX_HOME",
                    "D29_SECRET_LOOKING",
                    "D29_TOKEN_LOOKING",
                    "CODEX_D29_UPSTREAM_COMMIT",
                    "CODEX_D29_CLIENT_CONTRACT_VERSION",
                ]
                .iter()
                .map(|key| format!("{key}={}", env::var_os(key).is_some()))
                .collect::<Vec<_>>()
                .join("\n");
                let _ = fs::write("d29-env-report.txt", report);
            }
            if mode == "stderr-burst" {
                let _ = writeln!(io::stderr(), "{}", "x".repeat(100_000));
            }
            if mode == "write-probe" {
                if let Some(file_name) = extra_argument.as_deref() {
                    let _ = fs::write(file_name, b"child-working-directory");
                }
            }

            let _ = writeln!(
                stdout,
                "{}",
                r#"{"jsonrpc":"2.0","id":1,"result":{"codexHome":"C:/isolated","platformFamily":"windows","platformOs":"windows","userAgent":"codex-d29-fake"}}"#
            );
            let _ = stdout.flush();
            if mode == "crash-after-init" {
                std::process::exit(23);
            }
        } else if line.contains("\"method\":\"initialized\"") {
            if mode == "close-after-init" {
                return;
            }
            if mode == "descendant-retains-pipes" {
                let descendant = Command::new(env::current_exe().expect("fake executable path"))
                    .arg("descendant-retains-pipes-child")
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn pipe-retaining descendant");
                let _ = fs::write(
                    "d29-descendant-pid.txt",
                    descendant.id().to_string().as_bytes(),
                );
                return;
            }
            if mode == "server-request-after-init" {
                let _ = writeln!(
                    stdout,
                    "{}",
                    r#"{"jsonrpc":"2.0","id":99,"method":"item/commandExecution/requestApproval","params":{}}"#
                );
                let _ = stdout.flush();
            }
        } else if (mode == "server-request"
            || mode == "unknown-server-request"
            || mode == "server-request-after-init")
            && line.contains("\"id\":99")
            && line.contains("\"error\"")
        {
            let _ = fs::write("d29-server-request-denied.txt", b"denied");
        }
    }

    if mode == "drop-observe" {
        let _ = fs::write("d29-drop-observed.txt", b"stdin-closed");
    }
}
