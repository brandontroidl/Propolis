//! The producer-to-consumer boundary: `deploy/fleet-listeners.sh` writes the inventory,
//! `fleet::parse_listeners` reads it.
//!
//! Two component tests, each against its own hand-written fixture, would not cover this: the
//! generator could emit a field order or a separator the parser rejects and both would stay green.
//! These run the real script against a real directory of sensor env files and feed its real output
//! to the real parser, so the wire format is asserted once, in both directions, from one artifact.

use std::path::PathBuf;

use fleet::inventory::{Listener, Proto, parse_listeners};

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/fleet-listeners.sh")
}

/// Runs the generator over `env_dir` and returns the `PROPOLIS_FLEET_LISTENERS` value it wrote,
/// or `None` when it asserted no inventory at all.
fn generate(env_dir: &std::path::Path) -> Option<String> {
    let out = env_dir.join("fleet-listeners.env");
    let status = std::process::Command::new("bash")
        .arg(script_path())
        .arg(env_dir)
        .arg(&out)
        .output()
        .expect("failed to run deploy/fleet-listeners.sh");
    assert!(
        status.status.success(),
        "fleet-listeners.sh exited non-zero; stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let written = std::fs::read_to_string(&out).expect("generator wrote no file");
    written
        .lines()
        .find_map(|l| l.strip_prefix("PROPOLIS_FLEET_LISTENERS="))
        .map(str::to_string)
}

fn write(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn listener(sensor: &str, protocol: Proto, port: u16) -> Listener {
    Listener {
        collector_id: "local".into(),
        sensor: sensor.into(),
        protocol,
        port,
    }
}

#[test]
fn the_generated_inventory_parses_and_names_each_sensor_as_it_reports_itself() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "ssh.env", "PROPOLIS_SSH_BIND=0.0.0.0:22\n");
    write(
        dir.path(),
        "telnet.env",
        "# PROPOLIS_TELNET_BIND=0.0.0.0:2323\nPROPOLIS_TELNET_BIND=\"0.0.0.0:23\"\n",
    );
    // sensor-cred is one process with five independent binds, and it reports each protocol under
    // its own name. An inventory keyed on the `cred-*` log labels would join to nothing in the
    // ledger, which is the single most likely way to get this wrong.
    write(
        dir.path(),
        "cred.env",
        "PROPOLIS_CRED_VNC_BIND=0.0.0.0:5900\nPROPOLIS_CRED_PG_BIND=0.0.0.0:5432\n",
    );
    // The daemon's own console bind lives in propolis.env and is not a sensor listener.
    write(
        dir.path(),
        "propolis.env",
        "PROPOLIS_CONSOLE_BIND=127.0.0.1:8080\nDATABASE_URL=postgres://x\n",
    );

    let value = generate(dir.path()).expect("a listener inventory was expected");
    let mut parsed = parse_listeners(&value).expect("the generated value must parse");
    parsed.sort();

    let mut expected = vec![
        listener("ssh", Proto::Tcp, 22),
        listener("telnet", Proto::Tcp, 23),
        listener("vnc", Proto::Tcp, 5900),
        listener("postgresql", Proto::Tcp, 5432),
    ];
    expected.sort();
    assert_eq!(parsed, expected);
}

#[test]
fn an_mqtt_bind_yields_one_tcp_listener_named_mqtt() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "mqtt.env",
        "PROPOLIS_MQTT_BIND=203.0.113.7:1883\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("mqtt", Proto::Tcp, 1883)]);
}

#[test]
fn an_mqtt_tls_bind_yields_one_tcp_listener_named_mqtt() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "mqtt.env",
        "PROPOLIS_MQTT_TLS_BIND=203.0.113.7:8883\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("mqtt", Proto::Tcp, 8883)]);
}

#[test]
fn a_cert_and_key_without_an_mqtt_tls_bind_derive_no_listener() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "mqtt.env",
        "PROPOLIS_MQTT_TLS_CERT=/etc/propolis/tls/mqtt.crt\nPROPOLIS_MQTT_TLS_KEY=/etc/propolis/tls/mqtt.key\n",
    );

    assert_eq!(generate(dir.path()), None);
}

#[test]
fn an_smtp_submission_bind_yields_one_tcp_listener_named_smtp() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "smtp.env",
        "PROPOLIS_SMTP_SUBMISSION_BIND=203.0.113.7:587\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("smtp", Proto::Tcp, 587)]);
}

#[test]
fn an_smtp_tls_bind_yields_one_tcp_listener_named_smtp() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "smtp.env",
        "PROPOLIS_SMTP_TLS_BIND=203.0.113.7:465\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("smtp", Proto::Tcp, 465)]);
}

#[test]
fn a_cert_and_key_without_an_smtp_tls_bind_derive_no_listener() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "smtp.env",
        "PROPOLIS_SMTP_TLS_CERT=/etc/propolis/tls/smtp.crt\nPROPOLIS_SMTP_TLS_KEY=/etc/propolis/tls/smtp.key\n",
    );

    assert_eq!(generate(dir.path()), None);
}

#[test]
fn an_http_tls_bind_yields_one_tcp_listener_named_http() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "http.env",
        "PROPOLIS_HTTP_TLS_BIND=203.0.113.7:443\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("http", Proto::Tcp, 443)]);
}

#[test]
fn a_cert_and_key_without_an_http_tls_bind_derive_no_listener() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "http.env",
        "PROPOLIS_HTTP_TLS_CERT=/etc/propolis/tls/http.crt\nPROPOLIS_HTTP_TLS_KEY=/etc/propolis/tls/http.key\n",
    );

    assert_eq!(generate(dir.path()), None);
}

#[test]
fn a_redis_tls_bind_yields_one_tcp_listener_named_redis() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "redis.env",
        "PROPOLIS_REDIS_TLS_BIND=203.0.113.7:6380\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("redis", Proto::Tcp, 6380)]);
}

#[test]
fn a_cert_and_key_without_a_redis_tls_bind_derive_no_listener() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "redis.env",
        "PROPOLIS_REDIS_TLS_CERT=/etc/propolis/tls/redis.crt\nPROPOLIS_REDIS_TLS_KEY=/etc/propolis/tls/redis.key\n",
    );

    assert_eq!(generate(dir.path()), None);
}

#[test]
fn a_catchall_bind_list_yields_both_transports_for_every_port() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "catchall.env",
        "PROPOLIS_CATCHALL_BIND_ADDRS=0.0.0.0:1024, 0.0.0.0:8081\n",
    );

    let value = generate(dir.path()).unwrap();
    let mut parsed = parse_listeners(&value).unwrap();
    parsed.sort();

    let mut expected = vec![
        listener("catchall", Proto::Tcp, 1024),
        listener("catchall", Proto::Udp, 1024),
        listener("catchall", Proto::Tcp, 8081),
        listener("catchall", Proto::Udp, 8081),
    ];
    expected.sort();
    assert_eq!(parsed, expected);
}

#[test]
fn a_tftp_bind_yields_one_udp_listener_named_tftp() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "tftp.env",
        "PROPOLIS_TFTP_BIND=203.0.113.7:69\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();

    assert_eq!(parsed, vec![listener("tftp", Proto::Udp, 69)]);
}

/// The catch-all sensor still reads the deprecated bare spelling of its own bind variable. A box
/// using it must not silently produce an inventory with no catch-all in it.
#[test]
fn the_deprecated_bare_catchall_variable_is_still_derived() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "catchall.env",
        "CATCHALL_BIND_ADDRS=0.0.0.0:1024\n",
    );

    let value = generate(dir.path()).unwrap();
    let parsed = parse_listeners(&value).unwrap();
    assert_eq!(parsed.len(), 2, "one port, both transports: {parsed:?}");
    assert!(parsed.iter().all(|l| l.sensor == "catchall"));
}

/// A fresh install runs before the operator has populated any sensor env file. The generator must
/// assert nothing rather than write an empty value, because an empty value is the shape a lost
/// configuration takes and the two must not look alike.
#[test]
fn an_env_dir_with_no_sensor_binds_asserts_no_inventory_at_all() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "propolis.env", "DATABASE_URL=postgres://x\n");

    assert_eq!(generate(dir.path()), None);
}
