use std::{fs, process::Command};

#[test]
fn binary_loads_config_and_reports_startup_validation_error() {
    let config_path = std::env::temp_dir().join(format!(
        "edr-user-disabled-ebpf-{}-{}.toml",
        std::process::id(),
        unique_suffix()
    ));
    let config = include_str!("../../../config.example.toml")
        .replace("[ebpf]\nenabled = true", "[ebpf]\nenabled = false");
    fs::write(&config_path, config).expect("test config should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_edr-user"))
        .env("EDR_CONFIG", &config_path)
        .output()
        .expect("edr-user binary should run");

    fs::remove_file(&config_path).expect("test config should be removable");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("eBPF is disabled by config"),
        "stderr should explain startup validation failure, got: {stderr}"
    );
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after UNIX epoch")
        .as_nanos()
}
