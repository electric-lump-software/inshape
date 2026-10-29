use std::process::Command;

#[test]
fn version_prints_name_and_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_inshape"))
        .arg("--version")
        .output()
        .expect("run inshape");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8"),
        format!("inshape {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_prints_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_inshape"))
        .arg("--help")
        .output()
        .expect("run inshape");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf8");
    assert!(text.contains("inshape [--optional] --allowlist FILE -- CMD [ARGS...]"));
}

#[test]
fn bad_arguments_exit_64() {
    let output = Command::new(env!("CARGO_BIN_EXE_inshape"))
        .arg("--bogus")
        .output()
        .expect("run inshape");
    assert_eq!(output.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("inshape: "));
}
