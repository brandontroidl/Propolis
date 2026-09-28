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
