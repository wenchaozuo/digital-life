#![cfg(windows)]

use std::process::Command;

#[test]
fn production_binary_rejects_test_canary_switch() {
    let output = Command::new(env!("CARGO_BIN_EXE_vita-agent"))
        .arg("--serve-ipc-test-canary")
        .output()
        .expect("run production Vita binary");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage: vita-agent --probe | --serve-ipc"));
}
