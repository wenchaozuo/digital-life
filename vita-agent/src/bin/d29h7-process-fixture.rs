//! The only executable image allowed by the D29-H7-A test catalog.
//!
//! This binary intentionally has no generic command mode and never interprets
//! arguments as shell text. It reports only bounded, test-owned observations.

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("d29h7-process-fixture: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn run() -> Result<(), String> {
    use std::io::{self, Write};
    use std::process::Command;
    use std::time::Duration;

    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| "fixture mode is required".to_string())?;
    let rest = args.collect::<Vec<_>>();
    match mode.as_str() {
        "echo-argv" => {
            let output = serde_json::json!({"mode": mode, "args": rest});
            println!(
                "{}",
                serde_json::to_string(&output).map_err(|_| "argv output failed".to_string())?
            );
        }
        "report-env" => {
            let mut environment = std::env::vars().collect::<Vec<_>>();
            environment.sort();
            let output = serde_json::json!({"mode": mode, "environment": environment});
            println!(
                "{}",
                serde_json::to_string(&output)
                    .map_err(|_| "environment output failed".to_string())?
            );
        }
        "report-cwd" => {
            let cwd = std::env::current_dir().map_err(|_| "cwd unavailable".to_string())?;
            println!(
                "{}",
                serde_json::json!({"mode": mode, "cwd": cwd.to_string_lossy()})
            );
        }
        "sleep" => {
            let milliseconds = rest
                .first()
                .ok_or_else(|| "sleep duration is required".to_string())?
                .parse::<u64>()
                .map_err(|_| "sleep duration is invalid".to_string())?;
            std::thread::sleep(Duration::from_millis(milliseconds.min(10_000)));
            println!(
                "{}",
                serde_json::json!({"mode": mode, "slept": milliseconds})
            );
        }
        "flood-stdout" => {
            let bytes = vec![b'O'; 128 * 1024];
            io::stdout()
                .write_all(&bytes)
                .map_err(|_| "stdout flood failed".to_string())?;
            io::stdout()
                .flush()
                .map_err(|_| "stdout flush failed".to_string())?;
            std::thread::sleep(Duration::from_millis(1_000));
        }
        "flood-stderr" => {
            let bytes = vec![b'E'; 128 * 1024];
            io::stderr()
                .write_all(&bytes)
                .map_err(|_| "stderr flood failed".to_string())?;
            io::stderr()
                .flush()
                .map_err(|_| "stderr flush failed".to_string())?;
            std::thread::sleep(Duration::from_millis(1_000));
        }
        "fast-exit-both" => {
            io::stdout()
                .write_all(b"D29-H7 stdout exact tail\n")
                .map_err(|_| "stdout fast-exit write failed".to_string())?;
            io::stderr()
                .write_all(b"D29-H7 stderr exact tail\n")
                .map_err(|_| "stderr fast-exit write failed".to_string())?;
            io::stdout()
                .flush()
                .map_err(|_| "stdout fast-exit flush failed".to_string())?;
            io::stderr()
                .flush()
                .map_err(|_| "stderr fast-exit flush failed".to_string())?;
        }
        "large-fast-exit-both" => {
            let stdout = (0..(24 * 1024))
                .map(|index| b'A' + (index % 26) as u8)
                .collect::<Vec<_>>();
            let stderr = (0..(24 * 1024))
                .map(|index| b'a' + (index % 26) as u8)
                .collect::<Vec<_>>();
            io::stdout()
                .write_all(&stdout)
                .map_err(|_| "stdout large fast-exit write failed".to_string())?;
            io::stderr()
                .write_all(&stderr)
                .map_err(|_| "stderr large fast-exit write failed".to_string())?;
            io::stdout()
                .flush()
                .map_err(|_| "stdout large fast-exit flush failed".to_string())?;
            io::stderr()
                .flush()
                .map_err(|_| "stderr large fast-exit flush failed".to_string())?;
        }
        "attempt-child" => {
            let child = std::env::current_exe()
                .map_err(|_| "fixture executable path unavailable".to_string())?;
            let result = Command::new(child).args(["sleep", "2000"]).spawn();
            let child_spawned = result.is_ok();
            if let Ok(mut child) = result {
                let _ = child.kill();
                let _ = child.wait();
            }
            println!(
                "{}",
                serde_json::json!({"mode": mode, "child_spawned": child_spawned})
            );
        }
        "probe-handle" => {
            use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileType, FILE_TYPE_CHAR, FILE_TYPE_UNKNOWN,
            };
            let raw = rest
                .first()
                .ok_or_else(|| "probe handle is required".to_string())?
                .parse::<usize>()
                .map_err(|_| "probe handle is invalid".to_string())?;
            let handle = raw as HANDLE;
            let file_type = unsafe { GetFileType(handle) };
            let error = unsafe { GetLastError() };
            let valid = !handle.is_null()
                && file_type != FILE_TYPE_UNKNOWN
                && (file_type != FILE_TYPE_CHAR || error == 0);
            println!("{}", serde_json::json!({"mode": mode, "valid": valid}));
        }
        _ => return Err("unsupported fixture mode".to_string()),
    }
    Ok(())
}
