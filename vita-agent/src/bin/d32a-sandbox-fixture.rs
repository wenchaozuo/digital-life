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
    use std::io::{ErrorKind, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
    };
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
    let forbidden_handle = arguments
        .next()
        .ok_or_else(|| "known inheritable sentinel handle is required".to_string())?
        .to_string_lossy()
        .parse::<usize>()
        .map_err(|_| "known inheritable sentinel handle was invalid".to_string())?;

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
    let outside_write_target = outside.join("d32a-outside-write-sentinel.txt");
    let outside_write_denied = denied_create(&outside_write_target);
    let profile_read_denied = bounded_read(&user_profile).is_err();
    let authority_read_denied = bounded_read(&authority).is_err();
    let recovery_read_denied = bounded_read(&recovery).is_err();

    // The harness owns a live listener at network_target.  Connection refused
    // is reported separately and is never folded into the sandbox-denied
    // result; otherwise a dead fixture could create a false security PASS.
    let tcp_probe = TcpStream::connect_timeout(&network_target, Duration::from_millis(250));
    let tcp_refused = tcp_probe
        .as_ref()
        .err()
        .is_some_and(|error| error.kind() == ErrorKind::ConnectionRefused);
    let tcp_denied = tcp_probe.is_err() && !tcp_refused;
    let udp_denied = match UdpSocket::bind("0.0.0.0:0") {
        Err(_) => true,
        Ok(socket) => {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
            let sent = socket.send_to(b"d32a", network_target).is_ok();
            let mut response = [0_u8; 16];
            let echoed = sent
                && socket
                    .recv_from(&mut response)
                    .is_ok_and(|(length, _)| &response[..length] == b"d32a-ack");
            !echoed
        }
    };
    let tcp_listener_denied = TcpListener::bind("127.0.0.1:0").is_err();
    let udp_listener_denied = UdpSocket::bind("127.0.0.1:0").is_err();

    let executable =
        std::env::current_exe().map_err(|_| "fixture executable unavailable".to_string())?;
    let mut grandchild = Command::new(&executable)
        .arg("d32-grandchild")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let grandchild_spawned = grandchild.is_ok();
    // Do not terminate this process from inside the fixture.  The production
    // Job/cancellation supervisor owns the tree and must prove that an outer
    // cancellation closes both the fixture and this grandchild.
    let grandchild_alive_after_probe = match grandchild.as_mut() {
        Ok(child) => child.try_wait().ok().flatten().is_none(),
        Err(_) => false,
    };

    let mut breakaway = Command::new(&executable)
        .arg("d32-grandchild")
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let breakaway_denied = match breakaway.as_mut() {
        Ok(child) => {
            let _ = child.kill();
            let _ = child.wait();
            false
        }
        Err(_) => true,
    };

    let mut handle_count = 0_u32;
    let handle_count_ok =
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handle_count) } != 0;
    let forbidden_handle_probe_denied = {
        let handle = forbidden_handle as HANDLE;
        let mut duplicated = std::ptr::null_mut();
        let duplicated_ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } != 0;
        if duplicated_ok && !duplicated.is_null() {
            unsafe { CloseHandle(duplicated) };
        }
        !duplicated_ok
    };
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
            "tcp_refused": tcp_refused,
            "udp_denied": udp_denied,
            "tcp_listener_denied": tcp_listener_denied,
            "udp_listener_denied": udp_listener_denied,
            "grandchild_spawned": grandchild_spawned,
            "grandchild_alive_after_probe": grandchild_alive_after_probe,
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
