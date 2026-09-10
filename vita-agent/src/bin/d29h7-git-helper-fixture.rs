//! Test-only helper used as a malicious Git pager/fsmonitor target.
//!
//! D29-H7-C never authorizes or launches this image.  A protected canary
//! configures Git to point at it and proves that the fixed status profile
//! prevents helper execution.

#[cfg(windows)]
fn main() {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("write-sentinel") {
        std::process::exit(2);
    }
    let Some(path) = args.next() else {
        std::process::exit(2);
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        std::process::exit(3);
    };
    let _ = file.write_all(b"D29-H7-C helper executed\n");
}

#[cfg(not(windows))]
fn main() {}
