use provision_certs::{ProvisionError, SensorTlsOutcome, provision_sensor_tls};
use std::path::Path;

/// The self-signed cert is its own trust root, so the mTLS builder accepting (crt, crt, key)
/// proves rustls found the key matching the certificate.
fn pair_matches(dir: &Path, sensor: &str) -> bool {
    let crt = std::fs::read(dir.join(format!("{sensor}.crt"))).unwrap();
    let key = std::fs::read(dir.join(format!("{sensor}.key"))).unwrap();
    collector_wire::tls::server_config(&crt, &crt, &key).is_ok()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn sensor_tls_mints_a_matching_pair_with_key_0600_and_cert_0644() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Minted
    );
    let crt = std::fs::read_to_string(dir.path().join("http.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("http.key")).unwrap();
    assert!(crt.contains("CERTIFICATE"));
    assert!(key.contains("PRIVATE KEY"));
    #[cfg(unix)]
    {
        assert_eq!(mode(&dir.path().join("http.key")), 0o600);
        assert_eq!(mode(&dir.path().join("http.crt")), 0o644);
    }
    assert!(pair_matches(dir.path(), "http"));
}

#[test]
fn sensor_tls_is_idempotent_and_leaves_existing_bytes_alone() {
    let dir = tempfile::tempdir().unwrap();
    provision_sensor_tls(dir.path(), "http").unwrap();
    let crt = std::fs::read(dir.path().join("http.crt")).unwrap();
    let key = std::fs::read(dir.path().join("http.key")).unwrap();
    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Kept
    );
    assert_eq!(std::fs::read(dir.path().join("http.crt")).unwrap(), crt);
    assert_eq!(std::fs::read(dir.path().join("http.key")).unwrap(), key);
}

#[test]
fn sensor_tls_keeps_an_operator_supplied_pair() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("http.crt"), b"operator cert").unwrap();
    std::fs::write(dir.path().join("http.key"), b"operator key").unwrap();
    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Kept
    );
    assert_eq!(
        std::fs::read(dir.path().join("http.crt")).unwrap(),
        b"operator cert"
    );
    assert_eq!(
        std::fs::read(dir.path().join("http.key")).unwrap(),
        b"operator key"
    );
}

#[cfg(unix)]
#[test]
fn sensor_tls_keeps_a_symlinked_operator_cert() {
    use std::os::unix::fs::symlink;

    let real = tempfile::tempdir().unwrap();
    std::fs::write(real.path().join("real.crt"), b"operator cert").unwrap();
    std::fs::write(real.path().join("real.key"), b"operator key").unwrap();
    let dir = tempfile::tempdir().unwrap();
    symlink(real.path().join("real.crt"), dir.path().join("http.crt")).unwrap();
    symlink(real.path().join("real.key"), dir.path().join("http.key")).unwrap();

    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Kept
    );
    for name in ["http.crt", "http.key"] {
        assert!(
            std::fs::symlink_metadata(dir.path().join(name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[test]
fn sensor_tls_remints_both_halves_when_only_one_exists() {
    let dir = tempfile::tempdir().unwrap();
    provision_sensor_tls(dir.path(), "http").unwrap();
    let old_key = std::fs::read(dir.path().join("http.key")).unwrap();
    std::fs::remove_file(dir.path().join("http.crt")).unwrap();

    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Minted
    );
    assert!(dir.path().join("http.crt").exists());
    assert_ne!(std::fs::read(dir.path().join("http.key")).unwrap(), old_key);
    assert!(pair_matches(dir.path(), "http"));
}

#[test]
fn sensor_tls_gives_each_sensor_its_own_key() {
    let dir = tempfile::tempdir().unwrap();
    provision_sensor_tls(dir.path(), "http").unwrap();
    provision_sensor_tls(dir.path(), "mqtt").unwrap();
    assert_ne!(
        std::fs::read(dir.path().join("http.key")).unwrap(),
        std::fs::read(dir.path().join("mqtt.key")).unwrap()
    );
}

#[test]
fn unsafe_sensor_name_is_rejected_before_writing_anything() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["../x", "", "a/b"] {
        let err = provision_sensor_tls(dir.path(), name).unwrap_err();
        assert!(
            matches!(err, ProvisionError::InvalidSensorName(_)),
            "{name:?}"
        );
    }
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn sensor_tls_replaces_a_dangling_symlink_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("nonexistent");
    let dir = tempfile::tempdir().unwrap();
    symlink(&target, dir.path().join("http.key")).unwrap();

    assert_eq!(
        provision_sensor_tls(dir.path(), "http").unwrap(),
        SensorTlsOutcome::Minted
    );
    assert!(!target.exists());
    assert!(
        std::fs::symlink_metadata(dir.path().join("http.key"))
            .unwrap()
            .file_type()
            .is_file()
    );
}

fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_provision-certs"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_sensor_tls_reports_minted_then_kept_and_never_prints_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display().to_string();
    for verb in ["minted", "kept"] {
        let out = cli(&["--sensor-tls", &d, "http", "mqtt"]);
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout.clone()).unwrap();
        let expected: String = ["http.crt", "http.key", "mqtt.crt", "mqtt.key"]
            .iter()
            .map(|f| format!("{verb} {d}/{f}\n"))
            .collect();
        assert_eq!(stdout, expected);
        let all = [out.stdout, out.stderr].concat();
        assert!(!String::from_utf8_lossy(&all).contains("PRIVATE KEY"));
    }
}

#[test]
fn cli_sensor_tls_refuses_a_missing_output_dir_and_does_not_create_it() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("tls");
    let out = cli(&["--sensor-tls", &missing.display().to_string(), "http"]);
    assert!(!out.status.success());
    assert!(!missing.exists());
}

#[test]
fn cli_sensor_tls_with_no_sensors_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        !cli(&["--sensor-tls", &dir.path().display().to_string()])
            .status
            .success()
    );
}

#[test]
fn cli_legacy_three_arg_form_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let out = cli(&[
        &dir.path().display().to_string(),
        "gateway.local",
        "collector-01",
    ]);
    assert!(out.status.success());
    assert!(dir.path().join("ca.crt").exists());
    assert!(dir.path().join("gateway.key").exists());
}

#[test]
fn provisioned_pair_builds_valid_tls_configs() {
    let dir = tempfile::tempdir().unwrap();
    provision_certs::provision(dir.path(), "gateway.local", "collector-01").unwrap();
    let ca = std::fs::read(dir.path().join("ca.crt")).unwrap();
    let gc = std::fs::read(dir.path().join("gateway.crt")).unwrap();
    let gk = std::fs::read(dir.path().join("gateway.key")).unwrap();
    let cc = std::fs::read(dir.path().join("collector-01.crt")).unwrap();
    let ck = std::fs::read(dir.path().join("collector-01.key")).unwrap();
    assert!(collector_wire::tls::server_config(&ca, &gc, &gk).is_ok());
    assert!(collector_wire::tls::client_config(&ca, &cc, &ck).is_ok());
}

#[cfg(unix)]
#[test]
fn key_files_are_written_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    provision_certs::provision(dir.path(), "gateway.local", "collector-02").unwrap();
    for key_file in ["gateway.key", "collector-02.key"] {
        let mode = std::fs::metadata(dir.path().join(key_file))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{key_file} must be mode 0600, got {mode:o}");
    }
}

#[test]
fn unsafe_collector_id_is_rejected_before_writing_anything() {
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("certs");
    std::fs::create_dir(&out).unwrap();

    let err = provision_certs::provision(&out, "gateway.local", "../escaped").unwrap_err();
    assert!(matches!(
        err,
        provision_certs::ProvisionError::InvalidCollectorId(_)
    ));
    assert!(std::fs::read_dir(&out).unwrap().next().is_none());
    assert!(!parent.path().join("escaped.crt").exists());
    assert!(!parent.path().join("escaped.key").exists());
}

#[cfg(unix)]
#[test]
fn existing_symlink_is_replaced_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"do not overwrite").unwrap();
    symlink(&victim, dir.path().join("gateway.key")).unwrap();

    provision_certs::provision(dir.path(), "gateway.local", "collector-03").unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"do not overwrite");
    assert!(
        !std::fs::symlink_metadata(dir.path().join("gateway.key"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
