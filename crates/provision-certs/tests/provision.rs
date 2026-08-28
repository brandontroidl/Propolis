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
