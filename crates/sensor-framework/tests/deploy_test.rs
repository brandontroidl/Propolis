//! Asserts the deployment artifacts in `deploy/` (not this crate's own source) carry the
//! hardening directives `internal/design/02-sensor-framework.md`'s "Isolation and deployment"
//! requires, and that the log rotation policy is size-based with a survivable rotation mode.
//! Lives in `sensor-framework` (the crate every sensor binary depends on) rather than in either
//! sensor's own crate, because the directive set - and the failure mode it guards - is shared
//! across every sensor `deploy/` ships, not specific to one.
//!
//! Per the design doc: "The unit hardening is asserted by test, not by documentation. A
//! directive that exists only in prose is one careless edit away from silently disappearing,
//! and nothing about a passing test suite or a running sensor would reveal it." These tests are
//! that mechanical check: a directive dropped from a unit file fails the build, the same way the
//! never-exec guarantee is asserted rather than merely documented.
//!
//! One corrected spelling, verified rather than copied from the spec: both
//! `internal/design/02-sensor-framework.md` ("Containment") and this task's own plan/brief write
//! the containment directive as `MemoryDenyWriteExecution`. The real systemd directive has no
//! trailing "-ion" - `MemoryDenyWriteExecute` - confirmed on the build host by two independent
//! checks: `systemd-analyze verify` rejects the "-ion" spelling as an unknown key (silently
//! installing no seccomp rule at all), and the string `MemoryDenyWriteExecute` (with the format
//! strings systemd logs when the rule fails to install) is present in the installed
//! `libsystemd-shared` library, while `MemoryDenyWriteExecution` appears nowhere in it. Asserting
//! the spec's literal (wrong) spelling here would make this test pass while the shipped unit
//! silently carried no W^X protection at all - exactly the "check that disagrees with what it
//! measures" failure this test suite exists to prevent. `deploy/sensor-catchall.service` and
//! `deploy/sensor-ssh.service` both carry a comment recording this correction at its point of use.

#[test]
fn catchall_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-catchall.service"
    ))
    .unwrap();
    assert_unit_hardened(&unit, "sensor-catchall");
}

#[test]
fn ssh_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-ssh.service"
    ))
    .unwrap();
    assert_unit_hardened(&unit, "sensor-ssh");
}

/// The three layers `internal/design/02-sensor-framework.md`'s "Isolation and deployment"
/// requires of every sensor unit: least authority, resource caps, and containment. Shared by
/// both units below so the two can never drift into checking different bars.
fn assert_unit_hardened(unit: &str, name: &str) {
    // Least authority.
    assert!(
        unit.contains("NoNewPrivileges=yes"),
        "{name}: missing NoNewPrivileges"
    );
    assert!(
        unit.contains("ProtectSystem=strict"),
        "{name}: missing ProtectSystem=strict"
    );
    assert!(
        unit.contains("ProtectHome=yes"),
        "{name}: missing ProtectHome"
    );
    assert!(
        unit.contains("PrivateTmp=yes"),
        "{name}: missing PrivateTmp"
    );
    assert!(
        unit.contains("RestrictAddressFamilies=AF_INET AF_INET6"),
        "{name}: missing RestrictAddressFamilies"
    );

    // Must run as a non-root dedicated user - a sensor is internet-facing, so this is the floor
    // the rest of the sandboxing sits on.
    assert!(unit.contains("User="), "{name}: missing User directive");
    let user_line = unit
        .lines()
        .find(|l| l.starts_with("User="))
        .expect("already asserted present above");
    assert_ne!(user_line, "User=root", "{name}: must not run as root");

    // Resource caps: bound the aggregate a flood can consume (the framework's per-connection
    // bounds in bounds.rs govern one attacker; these govern all of them together).
    assert!(unit.contains("MemoryMax="), "{name}: missing MemoryMax");
    assert!(unit.contains("TasksMax="), "{name}: missing TasksMax");
    assert!(unit.contains("LimitNOFILE="), "{name}: missing LimitNOFILE");
    assert!(unit.contains("CPUQuota="), "{name}: missing CPUQuota");

    // Containment: pays off when a memory-safety defect exists despite Rust (unsafe code, a
    // dependency, or a logic error reachable pre-authentication) by downgrading memory
    // corruption from remote code execution to a crash.
    assert!(
        unit.contains("SystemCallFilter="),
        "{name}: missing SystemCallFilter"
    );
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "{name}: missing MemoryDenyWriteExecute (note the corrected spelling - see this file's \
         module doc; the spec's own \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );
}

/// SSH binds port 22 (privileged), so it needs `CAP_NET_BIND_SERVICE` granted by the service
/// manager rather than running as root - design doc: "carries only CAP_NET_BIND_SERVICE when it
/// must bind a privileged port - granted by the service manager, never by root."
#[test]
fn ssh_unit_has_cap_net_bind() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-ssh.service"
    ))
    .unwrap();
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// The catch-all's operator-configured port set also spans below 1024 (design doc: "a wide
/// default on the order of the old ~50 ports"), so it carries the identical capability grant.
#[test]
fn catchall_unit_has_cap_net_bind() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-catchall.service"
    ))
    .unwrap();
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// Rotation must be triggered by size, not a calendar cadence: an unbounded append driven by
/// internet-facing traffic is a disk-fill denial of service, and a flood of probes costs an
/// attacker nothing while each one writes a line - see design doc's "Transport". `copytruncate`
/// is required (over a plain rename) because it needs no cooperation from the sensor process and
/// disturbs no file ownership/permissions, unlike rename-and-recreate.
#[test]
fn logrotate_config_exists_and_is_size_based() {
    let config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/logrotate-sensors.conf"
    ))
    .unwrap();
    assert!(config.contains("size "), "rotation must be size-based");
    assert!(
        config.contains("rotate "),
        "must specify retained generations"
    );
    assert!(
        config.contains("copytruncate") || config.contains("postrotate"),
        "must use copytruncate or a reopen-on-signal mechanism"
    );
}

/// `intake` (sub-project 3) is a database-holding consumer, not an internet-facing listener like
/// the two sensors above: no port bind, so no `CAP_NET_BIND_SERVICE` - but it must still clear
/// the same least-authority/resource-cap/containment floor
/// `internal/design/03-event-intake-aggregation.md`'s "Isolation and deployment" requires.
/// Checked directly (not via `assert_unit_hardened`) since its required directive set differs
/// from the sensors' (no `RestrictAddressFamilies`/capability assertions here).
#[test]
fn intake_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/intake.service"
    ))
    .unwrap();
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    // Intake does not bind ports, so no CAP_NET_BIND_SERVICE needed.
    // But it does need network access to PostgreSQL.
    assert!(unit.contains("User="));
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root");
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("SystemCallFilter="));
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "missing MemoryDenyWriteExecute (note the corrected spelling - see this file's module \
         doc; \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );
}

/// The rotation policy must cover both sensors' logs, at the exact paths their systemd units
/// grant write access to (`ReadWritePaths`) - a policy that rotates the wrong path silently
/// protects nothing.
#[test]
fn logrotate_config_covers_both_sensor_logs() {
    let config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/logrotate-sensors.conf"
    ))
    .unwrap();
    assert!(
        config.contains("/var/log/propolis/catchall/events.jsonl"),
        "must rotate the catch-all sensor's log"
    );
    assert!(
        config.contains("/var/log/propolis/ssh/events.jsonl"),
        "must rotate the SSH honeypot's log"
    );
}
