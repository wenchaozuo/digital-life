//! D32-A adversarial sandbox fixture.
//!
//! This executable is test-only.  It receives attack targets from the
//! deterministic canary harness, actively attempts every forbidden operation,
//! and emits one bounded JSON observation.  It is never part of the model
//! visible production catalog.

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("d32a-sandbox-fixture: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn run() -> Result<(), String> {
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessHandleCount, CREATE_BREAKAWAY_FROM_JOB,
    };

    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments
        .next()
        .ok_or_else(|| "fixture mode is required".to_string())?;
    if mode == "d32-grandchild" {
        std::thread::sleep(Duration::from_secs(30));
        return Ok(());
    }
    if mode != "d32-sandbox-canary" {
        return Err("unsupported fixture mode".to_string());
    }
    let allowed = absolute_path(arguments.next(), "allowed sandbox path")?;
    let scratch = absolute_path(arguments.next(), "sandbox scratch root")?;
    let outside = absolute_path(arguments.next(), "outside sibling path")?;
    let user_profile = absolute_path(arguments.next(), "user profile fixture")?;
    let authority = absolute_path(arguments.next(), "Host authority fixture")?;
    let recovery = absolute_path(arguments.next(), "recovery fixture")?;
    let network_target = arguments
        .next()
        .ok_or_else(|| "network target is required".to_string())?
        .to_string_lossy()
        .parse::<SocketAddr>()
        .map_err(|_| "network target is invalid".to_string())?;

    let allowed_read = bounded_read(&allowed).is_ok();
    fs::create_dir_all(&scratch).map_err(|_| "sandbox scratch root unavailable".to_string())?;
    let scratch_file = scratch.join("d32a-canary-output.txt");
    let scratch_write = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&scratch_file)
        .and_then(|mut file| file.write_all(b"d32a-sandbox-fixture\n"))
        .is_ok();

    let outside_read_denied = bounded_read(&outside).is_err();
    let outside_write_denied = denied_create(&outside);
    let profile_read_denied = bounded_read(&user_profile).is_err();
    let authority_read_denied = bounded_read(&authority).is_err();
    let recovery_read_denied = bounded_read(&recovery).is_err();

    let tcp_denied =
        TcpStream::connect_timeout(&network_target, Duration::from_millis(250)).is_err();
    let udp_denied = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.send_to(b"d32a", network_target))
        .is_err();

    let executable =
        std::env::current_exe().map_err(|_| "fixture executable unavailable".to_string())?;
    let grandchild = Command::new(&executable)
        .arg("d32-grandchild")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let grandchild_spawned = grandchild.is_ok();

    let breakaway = Command::new(&executable)
        .arg("d32-grandchild")
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let breakaway_denied = breakaway.is_err();

    let mut handle_count = 0_u32;
    let handle_count_ok =
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handle_count) } != 0;
    let forbidden_handle_probe_denied = std::env::var("D32_FIXTURE_FORBIDDEN_HANDLE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|raw| {
            let handle = raw as HANDLE;
            let file_type = unsafe { windows_sys::Win32::Storage::FileSystem::GetFileType(handle) };
            let error = unsafe { GetLastError() };
            handle.is_null()
                || file_type == windows_sys::Win32::Storage::FileSystem::FILE_TYPE_UNKNOWN
                    && error != 0
        })
        .unwrap_or(true);

    println!(
        "{}",
        json!({
            "allowed_read": allowed_read,
            "scratch_write": scratch_write,
            "outside_read_denied": outside_read_denied,
            "outside_write_denied": outside_write_denied,
            "user_profile_read_denied": profile_read_denied,
            "host_authority_read_denied": authority_read_denied,
            "recovery_read_denied": recovery_read_denied,
            "tcp_denied": tcp_denied,
            "udp_denied": udp_denied,
            "grandchild_spawned": grandchild_spawned,
            "breakaway_denied": breakaway_denied,
            "handle_count_observed": handle_count_ok,
            "handle_count": handle_count,
            "forbidden_handle_probe_denied": forbidden_handle_probe_denied,
        })
    );
    Ok(())
}

#[cfg(windows)]
fn absolute_path(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let path = value
        .map(std::path::PathBuf::from)
        .ok_or_else(|| format!("{label} is required"))?;
    if !path.is_absolute() {
        return Err(format!("{label} was not absolute"));
    }
    Ok(path)
}

#[cfg(windows)]
fn bounded_read(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|_| "read denied".to_string())?;
    let mut bytes = Vec::new();
    file.take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| "read denied".to_string())?;
    Ok(bytes)
}

#[cfg(windows)]
fn denied_create(path: &std::path::Path) -> bool {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .is_err()
}
