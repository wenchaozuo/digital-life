use std::{
    env, fs,
    io::{self, BufRead, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

const D29_B_BACKLOG_NOTIFICATION_COUNT: usize = 33;
const D29_B_PROVISIONAL_ITEM_COUNT: usize = 32;

fn main() {
    let mut arguments = env::args();
    let _program = arguments.next();
    let mode = arguments.next().unwrap_or_else(|| "success".to_owned());
    let extra_argument = arguments.next();
    let mut initialize_number = 0_u32;
    let mut thread_start_number = 0_u32;
    let mut turn_number = 0_u32;

    if mode == "d29-b-admission-probe" {
        let _ = fs::write("d29-admission-first-user-code.txt", b"first-user-code");
    }

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
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                let _ = fs::write("d29-initialize-request.txt", &line);
            }
            if mode == "timeout" || mode == "d29-b-initialize-delayed" {
                initialize_number += 1;
                let _ = fs::write(
                    "d29-initialize-count.txt",
                    initialize_number.to_string().as_bytes(),
                );
            }
            if mode == "timeout" {
                thread::sleep(Duration::from_secs(5));
                return;
            }
            if mode == "d29-b-initialize-delayed" {
                thread::sleep(Duration::from_millis(200));
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
                        r#"{"method":"unknown/notification","params":{}}"#
                    );
                }
                let _ = stdout.flush();
                thread::sleep(Duration::from_millis(100));
            }
            if mode == "unknown-notification" {
                let _ = writeln!(
                    stdout,
                    "{}",
                    r#"{"method":"unknown/notification","params":{}}"#
                );
            }
            if mode == "oversized" {
                let oversized = format!(
                    r#"{{"id":1,"result":{{"codexHome":"C:/isolated","platformFamily":"windows","platformOs":"windows","userAgent":"{}"}}}}"#,
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
                    r#"{{"id":99,"method":"{}","params":{{}}}}"#,
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
                r#"{"id":1,"result":{"codexHome":"C:/isolated","platformFamily":"windows","platformOs":"windows","userAgent":"codex-d29-fake"}}"#
            );
            let _ = stdout.flush();
            if mode == "crash-after-init" {
                std::process::exit(23);
            }
        } else if line.contains("\"method\":\"initialized\"") {
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                let _ = fs::write("d29-initialized-notification.txt", &line);
            }
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
                    r#"{"id":99,"method":"item/commandExecution/requestApproval","params":{}}"#
                );
                let _ = stdout.flush();
            }
        } else if line.contains("\"method\":\"thread/start\"") {
            let request_id = request_id(&line);
            let cwd = request_string(&line, "cwd").unwrap_or_else(|| {
                env::current_dir()
                    .expect("fake app server working directory")
                    .to_string_lossy()
                    .into_owned()
            });
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                let _ = fs::write("d29-thread-start-request.txt", &line);
            }
            if mode == "d29-b-thread-start-delayed" {
                thread_start_number += 1;
                let _ = fs::write(
                    "d29-thread-start-count.txt",
                    thread_start_number.to_string().as_bytes(),
                );
                thread::sleep(Duration::from_millis(200));
            }
            if mode == "d29-b-wrong-thread-rpc-id" {
                write_line(
                    &mut stdout,
                    format_thread_response(request_id + 100, &cwd, false),
                );
            }
            if mode == "d29-b-malformed-thread-response" {
                write_line(
                    &mut stdout,
                    format!(
                        r#"{{"id":{request_id},"result":{{"thread":{{"id":"thread-d29-ephemeral-1","ephemeral":false,"cwd":"{}"}}}}}}"#,
                        json_escape(&cwd)
                    ),
                );
            } else {
                write_line(&mut stdout, format_thread_response(request_id, &cwd, true));
            }
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                write_line(&mut stdout, format_thread_started_notification(&cwd));
            }
            let _ = stdout.flush();
        } else if line.contains("\"method\":\"turn/start\"") {
            turn_number += 1;
            let request_id = request_id(&line);
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                let _ = fs::write("d29-turn-start-request.txt", &line);
            }
            if mode == "d29-b-turn-start-timeout" {
                let _ = fs::write(
                    "d29-turn-start-count.txt",
                    turn_number.to_string().as_bytes(),
                );
                // The fake accepts and creates the remote turn before
                // delaying its response, matching the upstream ambiguity that
                // this regression must fence off.
                thread::sleep(Duration::from_millis(200));
            }
            let provisional_error_mode = matches!(
                mode.as_str(),
                "d29-b-turn-start-error-after-provisional"
                    | "d29-b-turn-start-error-after-fast-provisional-terminal"
            );
            if mode == "d29-b-turn-start-error-no-provisional" || provisional_error_mode {
                let _ = fs::write(
                    "d29-turn-start-error-count.txt",
                    turn_number.to_string().as_bytes(),
                );
            }
            let turn_id = if mode == "d29-b-stale-old-turn-event" && turn_number > 1 {
                "turn-d29-2"
            } else {
                match turn_number {
                    1 => "turn-d29-1",
                    _ => "turn-d29-2",
                }
            };
            let provisional_mode = matches!(
                mode.as_str(),
                "d29-b-turn-started-before-response"
                    | "d29-b-pre-response-fast-terminal"
                    | "d29-b-turn-completed-before-response"
                    | "d29-b-pre-response-wrong-turn"
                    | "d29-b-pre-response-wrong-thread"
                    | "d29-b-pre-response-provisional-overflow"
                    | "d29-b-turn-start-error-after-provisional"
                    | "d29-b-turn-start-error-after-fast-provisional-terminal"
            );
            if provisional_mode {
                match mode.as_str() {
                    "d29-b-turn-started-before-response" => write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    ),
                    "d29-b-pre-response-fast-terminal" => {
                        write_line(
                            &mut stdout,
                            format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                        );
                        write_line(
                            &mut stdout,
                            format_item_notification(
                                "item/started",
                                "thread-d29-ephemeral-1",
                                turn_id,
                            ),
                        );
                        write_line(
                            &mut stdout,
                            format_item_notification(
                                "item/completed",
                                "thread-d29-ephemeral-1",
                                turn_id,
                            ),
                        );
                        write_line(
                            &mut stdout,
                            format_turn_completed_notification(
                                "thread-d29-ephemeral-1",
                                turn_id,
                                "completed",
                            ),
                        );
                    }
                    "d29-b-turn-completed-before-response" => {
                        write_line(
                            &mut stdout,
                            format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                        );
                        write_line(
                            &mut stdout,
                            format_turn_completed_notification(
                                "thread-d29-ephemeral-1",
                                turn_id,
                                "completed",
                            ),
                        );
                    }
                    "d29-b-pre-response-wrong-turn" => write_line(
                        &mut stdout,
                        format_turn_started_notification(
                            "thread-d29-ephemeral-1",
                            "turn-d29-wrong",
                        ),
                    ),
                    "d29-b-pre-response-wrong-thread" => write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-wrong", turn_id),
                    ),
                    "d29-b-pre-response-provisional-overflow" => {
                        write_line(
                            &mut stdout,
                            format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                        );
                        for _ in 0..D29_B_PROVISIONAL_ITEM_COUNT {
                            write_line(
                                &mut stdout,
                                format_item_notification(
                                    "item/started",
                                    "thread-d29-ephemeral-1",
                                    turn_id,
                                ),
                            );
                            let _ = stdout.flush();
                            thread::sleep(Duration::from_millis(5));
                        }
                    }
                    "d29-b-turn-start-error-after-provisional" => write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    ),
                    "d29-b-turn-start-error-after-fast-provisional-terminal" => {
                        write_line(
                            &mut stdout,
                            format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                        );
                        write_line(
                            &mut stdout,
                            format_turn_completed_notification(
                                "thread-d29-ephemeral-1",
                                turn_id,
                                "completed",
                            ),
                        );
                    }
                    _ => {}
                }
                let _ = stdout.flush();
                if mode == "d29-b-pre-response-provisional-overflow" {
                    thread::sleep(Duration::from_secs(5));
                }
            }
            if provisional_error_mode || mode == "d29-b-turn-start-error-no-provisional" {
                write_line(&mut stdout, format_turn_start_error_response(request_id));
            } else {
                write_line(&mut stdout, format_turn_start_response(request_id, turn_id));
            }

            if !provisional_mode && mode == "d29-b-crash-during-turn" {
                let _ = stdout.flush();
                thread::sleep(Duration::from_millis(100));
                std::process::exit(29);
            }

            if !provisional_mode {
                if mode == "d29-b-out-of-order" {
                    write_line(
                        &mut stdout,
                        format_turn_completed_notification(
                            "thread-d29-ephemeral-1",
                            turn_id,
                            "completed",
                        ),
                    );
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                } else if mode == "d29-b-wrong-binding" {
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-wrong", "turn-d29-wrong"),
                    );
                } else if mode == "d29-b-malformed-lifecycle" {
                    write_line(
                    &mut stdout,
                    r#"{"method":"turn/started","params":{"threadId":"thread-d29-ephemeral-1"}}"#.to_owned(),
                );
                } else if mode == "d29-b-interrupt" || mode == "d29-b-interrupt-backlog-saturation"
                {
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                } else if mode == "d29-b-server-request" {
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                    write_line(
                        &mut stdout,
                        r#"{"id":99,"method":"item/commandExecution/requestApproval","params":{}}"#
                            .to_owned(),
                    );
                } else if mode == "d29-b-unknown-notification" {
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                    write_line(
                    &mut stdout,
                    r#"{"method":"unknown/notification","params":{"presentationOnly":"ignored"}}"#.to_owned(),
                );
                    write_line(
                        &mut stdout,
                        format_turn_completed_notification(
                            "thread-d29-ephemeral-1",
                            turn_id,
                            "completed",
                        ),
                    );
                } else if mode == "d29-b-stale-old-turn-event" && turn_number > 1 {
                    write_line(
                        &mut stdout,
                        format_turn_completed_notification(
                            "thread-d29-ephemeral-1",
                            "turn-d29-1",
                            "completed",
                        ),
                    );
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                    write_line(
                        &mut stdout,
                        format_turn_completed_notification(
                            "thread-d29-ephemeral-1",
                            turn_id,
                            "completed",
                        ),
                    );
                } else {
                    write_line(
                        &mut stdout,
                        format_turn_started_notification("thread-d29-ephemeral-1", turn_id),
                    );
                    write_line(
                        &mut stdout,
                        format_item_notification("item/started", "thread-d29-ephemeral-1", turn_id),
                    );
                    write_line(
                        &mut stdout,
                        format_item_notification(
                            "item/completed",
                            "thread-d29-ephemeral-1",
                            turn_id,
                        ),
                    );
                    write_line(
                        &mut stdout,
                        format_turn_completed_notification(
                            "thread-d29-ephemeral-1",
                            turn_id,
                            "completed",
                        ),
                    );
                    if mode == "d29-b-duplicate-terminal" {
                        write_line(
                            &mut stdout,
                            format_turn_completed_notification(
                                "thread-d29-ephemeral-1",
                                turn_id,
                                "completed",
                            ),
                        );
                    }
                }
            }
            let _ = stdout.flush();
        } else if line.contains("\"method\":\"turn/interrupt\"") {
            let request_id = request_id(&line);
            if mode == "d29-b" || mode.starts_with("d29-b-") {
                let _ = fs::write("d29-turn-interrupt-request.txt", &line);
            }
            if mode == "d29-b-interrupt-backlog-saturation" {
                for _ in 0..D29_B_BACKLOG_NOTIFICATION_COUNT {
                    write_line(
                        &mut stdout,
                        format_item_notification(
                            "item/started",
                            "thread-d29-ephemeral-1",
                            "turn-d29-1",
                        ),
                    );
                    let _ = stdout.flush();
                    // Pace the producer so the client's bounded reader queue
                    // does not mask the pending-projection queue regression.
                    thread::sleep(Duration::from_millis(5));
                }
                thread::sleep(Duration::from_secs(5));
                write_line(
                    &mut stdout,
                    format!(r#"{{"id":{request_id},"result":{{}}}}"#),
                );
            } else {
                write_line(
                    &mut stdout,
                    format!(r#"{{"id":{request_id},"result":{{}}}}"#),
                );
            }
            if mode == "d29-b-interrupt" {
                write_line(
                    &mut stdout,
                    format_turn_completed_notification(
                        "thread-d29-ephemeral-1",
                        "turn-d29-1",
                        "interrupted",
                    ),
                );
            }
            let _ = stdout.flush();
        } else if (mode == "server-request"
            || mode == "unknown-server-request"
            || mode == "server-request-after-init"
            || mode == "d29-b-server-request")
            && line.contains("\"id\":99")
            && line.contains("\"error\"")
        {
            let _ = fs::write("d29-server-request-denied.txt", b"denied");
            let _ = fs::write("d29-server-request-denial.txt", &line);
            if mode == "d29-b-server-request" {
                write_line(
                    &mut stdout,
                    format_turn_completed_notification(
                        "thread-d29-ephemeral-1",
                        if turn_number == 1 {
                            "turn-d29-1"
                        } else {
                            "turn-d29-2"
                        },
                        "completed",
                    ),
                );
                let _ = stdout.flush();
            }
        }
    }

    if mode == "drop-observe" {
        let _ = fs::write("d29-drop-observed.txt", b"stdin-closed");
    }
}

fn request_id(line: &str) -> i64 {
    let marker = "\"id\":";
    let Some(start) = line.find(marker).map(|index| index + marker.len()) else {
        return -1;
    };
    let digits = line[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    digits.parse().unwrap_or(-1)
}

fn request_string(line: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = line.find(&marker).map(|index| index + marker.len())?;
    let mut value = String::new();
    let mut escaped = false;
    for character in line[start..].chars() {
        if escaped {
            value.push(match character {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(value);
        } else {
            value.push(character);
        }
    }
    None
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn write_line(stdout: &mut io::BufWriter<io::Stdout>, line: String) {
    let _ = writeln!(stdout, "{line}");
}

fn thread_object(cwd: &str, ephemeral: bool) -> String {
    format!(
        r#"{{"id":"thread-d29-ephemeral-1","cliVersion":"d29-fake","createdAt":0,"cwd":"{}","ephemeral":{},"modelProvider":"d29-fake","preview":"","projectId":null,"sessionId":"session-d29-1","source":"appServer","status":{{"type":"idle"}},"turns":[],"updatedAt":0}}"#,
        json_escape(cwd),
        ephemeral
    )
}

fn format_thread_response(request_id: i64, cwd: &str, ephemeral: bool) -> String {
    format!(
        r#"{{"id":{},"result":{{"approvalPolicy":"never","approvalsReviewer":"user","cwd":"{}","model":"d29-fake-model","modelProvider":"d29-fake","sandbox":{{"type":"readOnly"}},"thread":{}}}}}"#,
        request_id,
        json_escape(cwd),
        thread_object(cwd, ephemeral)
    )
}

fn format_thread_started_notification(cwd: &str) -> String {
    format!(
        r#"{{"method":"thread/started","params":{{"thread":{}}}}}"#,
        thread_object(cwd, true)
    )
}

fn turn_object(turn_id: &str, status: &str) -> String {
    format!(
        r#"{{"id":"{}","items":[],"status":"{}"}}"#,
        json_escape(turn_id),
        status
    )
}

fn format_turn_start_response(request_id: i64, turn_id: &str) -> String {
    format!(
        r#"{{"id":{},"result":{{"turn":{}}}}}"#,
        request_id,
        turn_object(turn_id, "inProgress")
    )
}

fn format_turn_start_error_response(request_id: i64) -> String {
    format!(
        r#"{{"id":{},"error":{{"code":-32000,"message":"turn rejected"}}}}"#,
        request_id
    )
}

fn format_turn_started_notification(thread_id: &str, turn_id: &str) -> String {
    format!(
        r#"{{"method":"turn/started","params":{{"threadId":"{}","turn":{}}}}}"#,
        json_escape(thread_id),
        turn_object(turn_id, "inProgress")
    )
}

fn format_item_notification(method: &str, thread_id: &str, turn_id: &str) -> String {
    format!(
        r#"{{"method":"{}","params":{{"{}AtMs":0,"item":{{"type":"userMessage","id":"item-d29-1","content":[{{"type":"text","text":"fixture"}}]}},"threadId":"{}","turnId":"{}"}}}}"#,
        method,
        if method == "item/started" {
            "started"
        } else {
            "completed"
        },
        json_escape(thread_id),
        json_escape(turn_id)
    )
}

fn format_turn_completed_notification(thread_id: &str, turn_id: &str, status: &str) -> String {
    format!(
        r#"{{"method":"turn/completed","params":{{"threadId":"{}","turn":{}}}}}"#,
        json_escape(thread_id),
        turn_object(turn_id, status)
    )
}
