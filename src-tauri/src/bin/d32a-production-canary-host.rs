#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "positive".to_string());
    match digital_life_lib::run_d32_a_host_integration(&mode) {
        Ok(mut report) => {
            if let serde_json::Value::Object(fields) = &mut report {
                let ok = matches!(
                    fields.get("status").and_then(serde_json::Value::as_str),
                    Some("EXECUTED" | "DENIED")
                );
                fields.insert("ok".to_string(), serde_json::Value::Bool(ok));
            }
            println!("{}", report);
        }
        Err(error) => emit_failure(&error),
    }
}

#[cfg(not(all(windows, feature = "d32-a-host-canary")))]
fn main() {
    emit_failure("D32_A_NOT_EXECUTABLE: production Host canary is Windows-only");
}

fn emit_failure(error: &str) -> ! {
    let not_executable = error.starts_with("D32_A_NOT_EXECUTABLE:");
    let code = if not_executable {
        "D32_A_NOT_EXECUTABLE"
    } else {
        "D32_A_HOST_FAILURE"
    };
    let kind = if not_executable {
        "not_executable"
    } else {
        "host_failure"
    };
    let status = if not_executable {
        "NOT_EXECUTABLE"
    } else {
        "FAILURE"
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "ok": false,
            "code": code,
            "kind": kind,
            "status": status,
            "message": error,
        })
    );
    std::process::exit(if not_executable { 78 } else { 1 });
}
