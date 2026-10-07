//! Asserts the deployment artifacts in `deploy/` (not this crate's own source) carry the
//! hardening directives `internal/design/02-sensor-framework.md`'s "Isolation and deployment"
//! requires, and that the log rotation policy is size-based with a survivable rotation mode.
//! Lives in `sensor-framework` (the crate every sensor binary depends on) rather than in either
//! sensor's own crate, because the directive set - and the failure mode it guards - is shared
//! across every sensor `deploy/` ships, not specific to one. Also covers `intake.service`
//! (sub-project 3), `review.service` (sub-project 4), `feed.service` (sub-project 5),
//! `console.service` (sub-project 6), and `propolis.service` plus `install.sh` (sub-project 7):
//! none of these depends on this crate, but their hardening (and, for `install.sh`, its control
//! flow) is asserted here too rather than splitting `deploy/`'s test coverage across crates.
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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

/// The TFTP sensor is one of the two units that answer over UDP. It must clear the same bar as
/// every other sensor, bind port 69 without root, and stay off by default: the unit carries no
/// compiled-in bind, so an installed-but-unconfigured unit has nothing to listen on.
#[test]
fn tftp_unit_has_hardening_directives_and_cap_net_bind() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-tftp.service"
    ))
    .unwrap();
    assert_unit_hardened(&unit, "sensor-tftp");
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
    assert!(
        unit.contains("EnvironmentFile=/etc/propolis/tftp.env"),
        "the unit must read its bind from the operator's tftp.env, with no inline default"
    );
    assert!(
        !unit
            .lines()
            .any(|l| l.contains("PROPOLIS_TFTP_BIND") && !l.trim_start().starts_with('#')),
        "the unit must not hardcode a bind address"
    );
}

/// The DNS sensor answers over UDP and TCP on 53 and optionally DNS over TLS on 853, all
/// privileged ports, so it keeps `CAP_NET_BIND_SERVICE`. It stays off by default (no inline bind)
/// and captures no bodies, so its only writable path is its own log directory.
#[test]
fn dns_unit_has_hardening_directives_and_cap_net_bind() {
    let unit = deploy_file("sensor-dns.service");
    assert_unit_hardened(&unit, "sensor-dns");
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
    assert!(
        unit.contains("EnvironmentFile=/etc/propolis/dns.env"),
        "the unit must read its bind from the operator's dns.env, with no inline default"
    );
    assert!(
        !unit
            .lines()
            .any(|l| l.contains("PROPOLIS_DNS_BIND") && !l.trim_start().starts_with('#')),
        "the unit must not hardcode a bind address"
    );
    assert!(
        unit.contains("ReadWritePaths=/var/log/propolis/dns\n"),
        "the only writable path is the sensor's own log directory"
    );
}

/// The DNS sensor reads its DoT cert and key from the root-owned TLS directory, read-only, and
/// keeps the capability its privileged ports need.
#[test]
fn dns_unit_reads_tls_dir_read_only_and_keeps_cap_net_bind() {
    let unit = deploy_file("sensor-dns.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// The MQTT sensor listens on 1883, an unprivileged port, so unlike the other sensor units it must
/// carry no `CAP_NET_BIND_SERVICE` grant (least privilege), and stay off by default: the unit
/// carries no compiled-in bind, so an installed-but-unconfigured unit has nothing to listen on.
/// It spools binary PUBLISH payloads, so its only writable paths are its own log directory and
/// that spool directory.
#[test]
fn mqtt_unit_has_hardening_directives_and_no_cap_net_bind() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/sensor-mqtt.service"
    ))
    .unwrap();
    assert_unit_hardened(&unit, "sensor-mqtt");
    assert!(
        !unit.contains("CAP_NET_BIND_SERVICE")
            || unit
                .lines()
                .filter(|l| l.contains("CAP_NET_BIND_SERVICE"))
                .all(|l| l.trim_start().starts_with('#')),
        "port 1883 is unprivileged: the unit must not grant CAP_NET_BIND_SERVICE"
    );
    assert!(
        unit.contains("CapabilityBoundingSet=\n"),
        "the capability bounding set must be explicitly emptied"
    );
    assert!(
        unit.contains("ReadWritePaths=/var/log/propolis/mqtt /var/spool/propolis/mqtt\n"),
        "the only writable paths are the sensor's own log and binary-payload spool directories"
    );
    assert!(
        unit.contains("EnvironmentFile=/etc/propolis/mqtt.env"),
        "the unit must read its bind from the operator's mqtt.env, with no inline default"
    );
    assert!(
        !unit
            .lines()
            .any(|l| l.contains("PROPOLIS_MQTT_BIND") && !l.trim_start().starts_with('#')),
        "the unit must not hardcode a bind address"
    );
}

/// The MQTT sensor's deploy ports (1883 plain, 8883 TLS) are both unprivileged, so its unit grants
/// no capability, and it reads its cert and key from the root-owned TLS directory, which
/// `ProtectSystem=strict` leaves readable but which the unit must not be able to write.
#[test]
fn mqtt_unit_reads_tls_dir_read_only_and_grants_no_capability() {
    let unit = deploy_file("sensor-mqtt.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("CapabilityBoundingSet=\n"));
    assert!(
        unit.lines()
            .filter(|l| l.contains("CAP_NET_BIND_SERVICE"))
            .all(|l| l.trim_start().starts_with('#')),
        "ports 1883 and 8883 are unprivileged: the unit must not grant CAP_NET_BIND_SERVICE"
    );
}

/// The Redis sensor's deploy ports (6379 plain, 6380 TLS) are both unprivileged, so its unit grants
/// no capability, and it reads its cert and key from the root-owned TLS directory, which
/// `ProtectSystem=strict` leaves readable but which the unit must not be able to write.
#[test]
fn redis_unit_reads_tls_dir_read_only_and_grants_no_capability() {
    let unit = deploy_file("sensor-redis.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("CapabilityBoundingSet=\n"));
    assert!(
        unit.lines()
            .filter(|l| l.contains("CAP_NET_BIND_SERVICE"))
            .all(|l| l.trim_start().starts_with('#')),
        "ports 6379 and 6380 are unprivileged: the unit must not grant CAP_NET_BIND_SERVICE"
    );
}

/// The HTTP sensor's deploy ports (80 plain, 443 TLS) are both privileged, so its unit keeps
/// `CAP_NET_BIND_SERVICE`, and it reads its cert and key from the root-owned TLS directory, which
/// `ProtectSystem=strict` leaves readable but which the unit must not be able to write.
#[test]
fn http_unit_reads_tls_dir_read_only_and_keeps_cap_net_bind() {
    let unit = deploy_file("sensor-http.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// The SMTP sensor's deploy ports (25 plain, 587 submission, 465 SMTPS) include privileged ones,
/// so its unit keeps `CAP_NET_BIND_SERVICE`, and it reads its cert and key from the root-owned TLS
/// directory, which `ProtectSystem=strict` leaves readable but which the unit must not be able to
/// write.
#[test]
fn smtp_unit_reads_tls_dir_read_only_and_keeps_cap_net_bind() {
    let unit = deploy_file("sensor-smtp.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// The FTP sensor's deploy ports (21 plain, 990 implicit FTPS) are privileged, so its unit keeps
/// `CAP_NET_BIND_SERVICE`, and it reads its cert and key from the root-owned TLS directory, which
/// `ProtectSystem=strict` leaves readable but which the unit must not be able to write.
#[test]
fn ftp_unit_reads_tls_dir_read_only_and_keeps_cap_net_bind() {
    let unit = deploy_file("sensor-ftp.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

/// The cred sensor's deploy ports (5432, 3306, 1433, 27017, 5900) are all unprivileged and its TLS
/// runs on those same ports, so its unit grants no capability, and it reads its cert and key from
/// the root-owned TLS directory, which `ProtectSystem=strict` leaves readable but which the unit
/// must not be able to write.
#[test]
fn cred_unit_reads_tls_dir_read_only_and_grants_no_capability() {
    let unit = deploy_file("sensor-cred.service");
    assert!(unit.lines().any(|l| l == TLS_READ_ONLY_LINE));
    assert!(unit.contains("CapabilityBoundingSet=\n"));
    assert!(
        unit.lines()
            .filter(|l| l.contains("CAP_NET_BIND_SERVICE"))
            .all(|l| l.trim_start().starts_with('#')),
        "every cred port is unprivileged: the unit must not grant CAP_NET_BIND_SERVICE"
    );
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

/// `review` (sub-project 4) is architecturally the same shape as `intake`: a PostgreSQL client
/// with no inbound listener and no sensor log access. Unlike `intake`, it also makes outbound
/// HTTPS calls to vendor abuse-reporting APIs
/// (`internal/design/04-review-gatekeeper-reporting.md`'s "Vendor adapters"), so - unlike
/// `intake_unit_has_hardening_directives` above, which does not assert `RestrictAddressFamilies`
/// at all - this test asserts it explicitly, matching the task brief's stated requirement.
#[test]
fn review_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/review.service"
    ))
    .unwrap();
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(
        unit.contains("RestrictAddressFamilies=AF_INET AF_INET6"),
        "review needs outbound HTTPS to vendor APIs plus a PostgreSQL connection"
    );
    // review binds no port at all, so no CAP_NET_BIND_SERVICE needed.
    assert!(unit.contains("User="));
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root");
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("TasksMax="));
    assert!(unit.contains("CPUQuota="));
    assert!(unit.contains("LimitNOFILE="));
    assert!(unit.contains("SystemCallFilter="));
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "missing MemoryDenyWriteExecute (note the corrected spelling - see this file's module \
         doc; \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );
}

/// `feed` (sub-project 5) is architecturally close to `intake`/`review` - a PostgreSQL client with
/// no inbound listener - but unlike either of them, its whole purpose is to WRITE the published
/// feed to disk (`crates/feed/src/publisher.rs`'s atomic write-then-rename), so it is the only one
/// of the three that must also carry a `ReadWritePaths` grant. That grant must stay scoped to this
/// service's own dedicated directory rather than widening to the shared `/var/lib/propolis` root
/// intake also writes under (see `deploy/feed.service`'s own header comment for the full
/// reasoning) - checked explicitly below, not just "some ReadWritePaths exists", so a silent
/// broadening to the shared parent would fail this test.
#[test]
fn feed_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/feed.service"
    ))
    .unwrap();
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(
        unit.contains("RestrictAddressFamilies="),
        "feed needs a PostgreSQL connection"
    );
    // feed binds no port at all, so no CAP_NET_BIND_SERVICE needed.
    assert!(unit.contains("User="));
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root");
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("TasksMax="));
    assert!(unit.contains("CPUQuota="));
    assert!(unit.contains("LimitNOFILE="));
    assert!(unit.contains("SystemCallFilter="));
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "missing MemoryDenyWriteExecute (note the corrected spelling - see this file's module \
         doc; \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );
    assert!(
        unit.contains("ReadWritePaths=/var/lib/propolis/feed"),
        "feed publishes files and needs a write grant scoped to its own dedicated directory, \
         never blanket filesystem access"
    );
    assert!(
        !unit.contains("ReadWritePaths=/var/lib/propolis\n")
            && !unit.contains("ReadWritePaths=/var/lib/propolis "),
        "the write grant must not widen to the shared /var/lib/propolis root that other \
         services (e.g. intake's cursor directory) also live under"
    );
}

/// `console` (sub-project 6) is the only unit in this deploy set that is BOTH a network listener
/// (like the two sensor units) and a PostgreSQL client (like intake/review/feed) - see that file's
/// own header comment for the full architectural reasoning. Checked directly rather than via
/// `assert_unit_hardened` (which assumes a sensor's `RestrictAddressFamilies=AF_INET AF_INET6`
/// wording, which console shares, but also a `CapabilityBoundingSet` grant, which console
/// deliberately omits - its bound port, 8080, is unprivileged).
#[test]
fn console_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/console.service"
    ))
    .unwrap();
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(
        unit.contains("RestrictAddressFamilies=AF_INET AF_INET6"),
        "console needs both a loopback HTTP listener and a PostgreSQL connection"
    );
    assert!(unit.contains("User="), "missing User directive");
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root", "must not run as root");
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("TasksMax="));
    assert!(unit.contains("CPUQuota="));
    assert!(unit.contains("LimitNOFILE="));
    assert!(unit.contains("SystemCallFilter="));
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "missing MemoryDenyWriteExecute (note the corrected spelling - see this file's module \
         doc; \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );
    // Binds an unprivileged port (8080, > 1024) - unlike sensor-ssh's port 22, this never needs
    // CAP_NET_BIND_SERVICE, so (unlike the two sensor units) it carries no AmbientCapabilities
    // grant, and CapabilityBoundingSet is explicitly emptied rather than left at its broad
    // default.
    assert!(!unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet="));
    // Read-only access to feed's own publish directory (for routes::feed / routes::metrics to
    // read manifest.json) - never widened to a write grant, and never widened past feed's own
    // dedicated directory.
    assert!(
        unit.contains("ReadOnlyPaths=/var/lib/propolis/feed"),
        "console reads feed's manifest.json for the feed status page and /metrics, read-only"
    );
    assert!(
        !unit.contains("ReadWritePaths="),
        "console writes nothing to the local filesystem at all (in-memory sessions only)"
    );
}

/// `propolis` (sub-project 7) is the unified daemon superseding `intake`/`review`/`feed`/`console`
/// for production - see `deploy/propolis.service`'s own header comment for the full architectural
/// reasoning. Checked directly (like `console_unit_has_hardening_directives`, not via
/// `assert_unit_hardened`) because its required directive set matches none of the existing shapes
/// exactly: it is simultaneously a network listener (the console subsystem), a sensor-log reader
/// (the intake subsystem, like `intake.service`), a vendor-API HTTPS client (the review subsystem,
/// like `review.service`), and a local file publisher (the feed subsystem, like `feed.service`).
#[test]
fn propolis_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/propolis.service"
    ))
    .unwrap();

    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    // Needs all three families at once - see deploy/propolis.service's own header for why this is
    // the one unit in the deploy set that does (AF_UNIX for a same-host PostgreSQL socket, plus
    // AF_INET/AF_INET6 for outbound vendor HTTPS and the console's inbound listener).
    assert!(
        unit.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"),
        "propolis needs AF_UNIX (local PostgreSQL) in addition to AF_INET/AF_INET6 (vendor HTTPS \
         and the console listener)"
    );

    assert!(unit.contains("User="), "missing User directive");
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root", "must not run as root");

    // Binds only an unprivileged port (console, default 8080) - no capability grant needed, same
    // as console.service.
    assert!(
        !unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"),
        "propolis binds no privileged port"
    );
    assert!(unit.contains("CapabilityBoundingSet="));

    // Resource caps - presence only (not exact values): these are operational tuning knobs, not a
    // security boundary, so pinning exact numbers here would block a legitimate re-tune.
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("TasksMax="));
    assert!(unit.contains("CPUQuota="));
    assert!(unit.contains("LimitNOFILE="));

    assert!(unit.contains("SystemCallFilter="));
    assert!(
        unit.contains("MemoryDenyWriteExecute=yes"),
        "missing MemoryDenyWriteExecute (note the corrected spelling - see this file's module \
         doc; \"MemoryDenyWriteExecution\" is not a real systemd directive)"
    );

    // Read-only across every sensor's log tree (the intake subsystem tails all of them) - matches
    // intake.service's identical grant, checked as an exact line so a future edit cannot silently
    // narrow or widen it to a different path.
    assert!(
        unit.lines().any(|l| l == "ReadOnlyPaths=/var/log/propolis"),
        "propolis's intake subsystem must read every sensor's log directory"
    );
    // Writable across the whole /var/lib/propolis tree - deliberately wider than intake's own
    // /var/lib/propolis/cursors and feed's own /var/lib/propolis/feed (see deploy/propolis.service's
    // header for why the union is correct once cursors and feed output are written by the same
    // process rather than two separate ones).
    assert!(
        unit.lines()
            .any(|l| l == "ReadWritePaths=/var/lib/propolis"),
        "propolis's intake and feed subsystems both need this shared writable root"
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
    assert!(
        config.contains("/var/log/propolis/tftp/events.jsonl"),
        "must rotate the TFTP honeypot's log"
    );
    assert!(
        config.contains("/var/log/propolis/mqtt/events.jsonl"),
        "must rotate the MQTT honeypot's log"
    );
    assert!(
        config.contains("/var/log/propolis/dns/events.jsonl"),
        "must rotate the DNS honeypot's log"
    );
}

/// `deploy/install.sh` is a real (if small) bash program - control flow, idempotent helpers, a
/// `--dry-run` mode - not declarative config like the unit files above, so a text-content check
/// would not catch a broken script. This test exercises it for real, needing no root and mutating
/// nothing: a syntax check, matching `bash -n`'s own definition of "parses".
#[test]
fn install_script_is_valid_bash() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/install.sh");
    let status = std::process::Command::new("bash")
        .arg("-n")
        .arg(script)
        .status()
        .expect("failed to invoke `bash -n` on deploy/install.sh");
    assert!(
        status.success(),
        "deploy/install.sh has a bash syntax error"
    );
}

/// Runs `install.sh --dry-run` for real (no root, no mutation - every mutating command in the
/// script is routed through its own `run()` wrapper, which only ever prints under `--dry-run`) and
/// asserts the reported actions match `internal/design/07-runtime-coordination-deployment.md`'s
/// "Install script" step list: the three users, every directory sub-project 7 and the two sensor
/// units need, the three production binaries and unit files, the logrotate config, and the final
/// `daemon-reload` - plus, as a regression guard on `deploy/install.sh`'s own "What gets retired"
/// scoping, that none of the four now-superseded per-subsystem units get installed alongside it.
#[test]
fn install_script_dry_run_reports_expected_actions() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/install.sh");
    let output = std::process::Command::new(script)
        .arg("--dry-run")
        .output()
        .expect("failed to run deploy/install.sh --dry-run");
    assert!(
        output.status.success(),
        "install.sh --dry-run exited non-zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    for user in ["propolis", "propolis-catchall", "propolis-ssh"] {
        assert!(stdout.contains(user), "dry-run output missing user {user}");
    }
    for dir in [
        "/etc/propolis",
        "/var/log/propolis/catchall",
        "/var/log/propolis/ssh",
        "/var/lib/propolis/cursors",
        "/var/lib/propolis/feed",
        "/var/lib/propolis/spool",
        "/var/spool/propolis/catchall",
        "/var/spool/propolis/ssh",
    ] {
        assert!(
            stdout.contains(dir),
            "dry-run output missing directory {dir}"
        );
    }
    for bin in ["propolis", "sensor-catchall", "sensor-ssh"] {
        assert!(stdout.contains(bin), "dry-run output missing binary {bin}");
    }
    for unit in [
        "propolis.service",
        "sensor-catchall.service",
        "sensor-ssh.service",
    ] {
        assert!(stdout.contains(unit), "dry-run output missing unit {unit}");
    }
    for retired in [
        "intake.service",
        "review.service",
        "feed.service",
        "console.service",
    ] {
        assert!(
            !stdout.contains(retired),
            "install.sh must not install the retired {retired} - it is superseded by \
             propolis.service in production"
        );
    }
    assert!(
        stdout.contains("logrotate"),
        "dry-run output missing logrotate step"
    );
    assert!(
        stdout.contains("daemon-reload"),
        "dry-run output missing final daemon-reload step"
    );
}

/// `/var/lib/propolis` must be created root-owned, not propolis-owned. POSIX write permission on a
/// directory lets its owner unlink/rename ANY child regardless of the child's own owner, so a
/// propolis-owned parent lets a compromised `propolis` daemon swap the sibling
/// `/var/lib/propolis/ssh` host-key directory (owned by propolis-ssh) for a symlink that
/// sensor-ssh.service's `ProtectSystem=strict` bind-mount setup would then follow into an
/// attacker-chosen path. propolis writes only into its own children (cursors/, feed/, spool/),
/// never the shared root, so root ownership of the parent costs it nothing.
#[test]
fn install_script_var_lib_root_is_root_owned() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/install.sh");
    let output = std::process::Command::new(script)
        .arg("--dry-run")
        .output()
        .expect("failed to run deploy/install.sh --dry-run");
    assert!(
        output.status.success(),
        "install.sh --dry-run exited non-zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("-o root -g root /var/lib/propolis\n"),
        "the shared /var/lib/propolis root must be created root:root so a compromised propolis \
         cannot rename the sibling propolis-ssh host-key directory; dry-run output:\n{stdout}"
    );
}

/// The six `CaptureHandoff` body-capturing sensors (ssh/ftp/adb/telnet/tftp/mqtt) each default their
/// outbox manifest directory to `<default spool_dir>/outbox` (see e.g. `sensor-ssh/src/main.rs`'s
/// `resolve_outbox_dir`). That default must always land inside a path the unit's own
/// `ReadWritePaths` already grants, or the manifest write silently fails under
/// `ProtectSystem=strict` and the outbox never persists in production - exactly the SP-B-1b
/// regression this test exists to catch, whose default was the shared `/var/lib/propolis/outbox`,
/// granted by none of these units. This is the production-sandbox machine check: a tempdir-based
/// unit test of the resolver function alone cannot see this failure mode.
#[test]
fn body_capturer_default_outbox_is_inside_read_write_paths() {
    for (unit_file, default_spool_dir) in [
        ("sensor-ssh.service", "/var/spool/propolis/ssh"),
        ("sensor-ftp.service", "/var/spool/propolis/ftp"),
        ("sensor-adb.service", "/var/spool/propolis/adb"),
        ("sensor-telnet.service", "/var/spool/propolis/telnet"),
        ("sensor-tftp.service", "/var/spool/propolis/tftp"),
        ("sensor-mqtt.service", "/var/spool/propolis/mqtt"),
    ] {
        let unit = std::fs::read_to_string(format!(
            "{}/../../deploy/{unit_file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|e| panic!("failed to read deploy/{unit_file}: {e}"));
        let default_outbox_dir = PathBuf::from(default_spool_dir).join("outbox");
        assert!(
            unit_grants_ancestor_of(&unit, &default_outbox_dir),
            "{unit_file}: no ReadWritePaths entry is an ancestor of the default outbox dir {}; \
             the manifest write would silently fail under ProtectSystem=strict",
            default_outbox_dir.display()
        );
    }
}

/// True if one of `unit`'s `ReadWritePaths=` entries is an ancestor of (or equal to) `path`.
fn unit_grants_ancestor_of(unit: &str, path: &Path) -> bool {
    unit.lines()
        .filter(|l| l.starts_with("ReadWritePaths="))
        .flat_map(|l| l.trim_start_matches("ReadWritePaths=").split_whitespace())
        .any(|granted| path.starts_with(granted))
}

/// SP-B-1e regression: `upgrade.sh` never provisioned directories - it assumed `install.sh` had
/// already run once - so a spool/state directory a change added only ever existed after a fresh
/// install. `sensor-telnet.service`'s own `/var/spool/propolis/telnet` `ReadWritePaths` grant
/// shipped this way and was never created on a live upgrade, crash-looping the unit under
/// `ProtectSystem=strict` (its `ReadWritePaths` bind-mount target did not exist). Provisioning is
/// now one shared, idempotent routine (`deploy/provision.sh`) both `install.sh` and `upgrade.sh`
/// run - this test is the machine check that forecloses the underlying class: it cross-checks
/// every sensor unit's spool/state `ReadWritePaths` entries against the directories
/// `provision.sh` actually creates, so a unit granting a path nothing provisions fails the build
/// rather than only failing in production on the next upgrade.
#[test]
fn every_unit_readwrite_dir_is_provisioned() {
    let provisioned = provisioned_dirs();

    let deploy_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy"));
    let mut checked_any = false;
    for entry in std::fs::read_dir(&deploy_dir).expect("failed to read deploy/") {
        let entry = entry.expect("failed to read a deploy/ directory entry");
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy().into_owned();
        if !file_name.starts_with("sensor-") || !file_name.ends_with(".service") {
            continue;
        }
        checked_any = true;

        let unit = std::fs::read_to_string(entry.path())
            .unwrap_or_else(|e| panic!("failed to read deploy/{file_name}: {e}"));
        for dir in spool_state_read_write_dirs(&unit) {
            assert!(
                provisioned.contains(&dir),
                "deploy/{file_name} grants ReadWritePaths={dir}, but deploy/provision.sh does \
                 not provision that directory - a live upgrade would leave it missing and the \
                 unit would crash-loop under ProtectSystem=strict (the SP-B-1e telnet outage)"
            );
        }
    }
    assert!(
        checked_any,
        "no deploy/sensor-*.service units found - the glob in this test is broken"
    );
}

/// The `/var/spool/propolis/*` and `/var/lib/propolis/*` entries in `unit`'s `ReadWritePaths=`
/// lines - the spool/state directories a sensor must be able to write, and the exact class of
/// directory the telnet outage was missing. `/var/log/propolis/*` log directories are provisioned
/// by the same routine but excluded here; they are not what this regression test targets.
fn spool_state_read_write_dirs(unit: &str) -> Vec<String> {
    unit.lines()
        .filter(|l| l.starts_with("ReadWritePaths="))
        .flat_map(|l| l.trim_start_matches("ReadWritePaths=").split_whitespace())
        .filter(|p| p.starts_with("/var/spool/propolis/") || p.starts_with("/var/lib/propolis/"))
        .map(str::to_string)
        .collect()
}

/// The set of directories `deploy/provision.sh` creates, parsed from its `ensure_dir <path> ...`
/// call sites. Deliberately does not match `provision.sh`'s own `ensure_dir() {` function
/// definition: split on whitespace, that line's first token is `ensure_dir()` (attached
/// parenthesis), not the bare `ensure_dir` this parser requires as the first token of a real call.
fn provisioned_dirs() -> HashSet<String> {
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/provision.sh"
    ))
    .expect("failed to read deploy/provision.sh");

    script
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            if tokens.next()? != "ensure_dir" {
                return None;
            }
            tokens.next().map(str::to_string)
        })
        .collect()
}

/// The deploy stamp is what lets the console tell a stale BINARY from a stale CHECKOUT: each
/// binary records the commit it was built from, this file records what the deploy installed, and
/// the pane compares them. A deploy that skipped it would leave the panel reading "not recorded"
/// forever, which looks like a missing feature rather than a missing step.
#[test]
fn deploy_stamp_script_is_valid_bash_and_both_deploy_scripts_run_it() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/deploy-stamp.sh");
    let status = std::process::Command::new("bash")
        .arg("-n")
        .arg(script)
        .status()
        .expect("failed to invoke `bash -n` on deploy/deploy-stamp.sh");
    assert!(
        status.success(),
        "deploy/deploy-stamp.sh has a bash syntax error"
    );

    let install = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/install.sh"
    ))
    .expect("failed to read deploy/install.sh");
    let upgrade = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/upgrade.sh"
    ))
    .expect("failed to read deploy/upgrade.sh");
    for (name, text) in [("install.sh", &install), ("upgrade.sh", &upgrade)] {
        assert!(
            text.contains("deploy-stamp.sh"),
            "deploy/{name} does not run deploy/deploy-stamp.sh, so a box deployed through it \
             could never tell a stale binary from a stale checkout"
        );
        // Ordering alone does not stop a failed install from being stamped as a success: without
        // `set -e` the install step's failure would be reported and the script would walk on to
        // the stamp anyway, recording this checkout as deployed. Neither script can be executed
        // from a test (they write /usr/local/bin and restart units), so this is the static half of
        // that evidence; the stamp's own behavior is exercised for real against fixtures below.
        assert!(
            text.lines().any(|l| l.trim_start().starts_with("set -e")),
            "deploy/{name} must abort on a failed step, or a failed install would still reach the \
             deploy stamp and be recorded as a finished deployment"
        );
    }

    // After the build AND after every binary is actually installed, so a failed build or a
    // partial install-loop failure leaves the previous stamp in place rather than claiming a
    // commit that produced no binaries, or claiming success for an install that did not finish -
    // a checkout SHA alone does not prove which binary is actually on disk, which is exactly what
    // stamping before the install used to get wrong. Before the first restart, so the console
    // reads the new stamp as soon as it comes back up. Matches on the real invocation
    // (`"$SCRIPT_DIR/deploy-stamp.sh"`), not a bare substring match, so a comment that merely
    // mentions the script's name elsewhere in the file cannot be mistaken for where it actually
    // runs.
    let lines: Vec<&str> = upgrade.lines().collect();
    let build_at = lines
        .iter()
        .position(|l| l.contains("cargo build --release"))
        .expect("upgrade.sh no longer builds - this parser is broken");
    assert!(
        lines[build_at].contains("--workspace") && lines[build_at].contains("--locked"),
        "upgrade.sh must build the complete locked workspace so production cannot resolve a \
         dependency graph different from the one reviewed and tested by CI"
    );
    let install_binaries_at = lines
        .iter()
        .position(|l| l.contains("install -m 0755") && l.contains("$BUILD_DIR"))
        .expect("upgrade.sh no longer installs binaries from $BUILD_DIR - this parser is broken");
    let stamp_at = lines
        .iter()
        .position(|l| l.contains("\"$SCRIPT_DIR/deploy-stamp.sh\""))
        .expect("upgrade.sh never invokes deploy-stamp.sh");
    let first_restart_at = lines
        .iter()
        .position(|l| l.trim_start().starts_with("systemctl restart"))
        .expect("upgrade.sh never restarts a unit - this parser is broken");
    assert!(
        build_at < stamp_at && install_binaries_at < stamp_at && stamp_at < first_restart_at,
        "upgrade.sh must stamp after the build (line {}) and after installing binaries (line {}) \
         and before the first restart (line {}), but stamps at line {}",
        build_at + 1,
        install_binaries_at + 1,
        first_restart_at + 1,
        stamp_at + 1
    );
}

// ---- deploy/deploy-stamp.sh, executed for real against fixtures ----
//
// `installed` is the field that separates "the deploy recorded a commit" from "that commit is the
// file actually on disk", so reading the script's text proves nothing about it. Every test below
// runs the real script against a disposable git repository and a directory of stand-in
// executables under `tempfile::tempdir()` - never this project's own repository, and never
// /usr/local/bin.

const DEPLOY_STAMP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/deploy-stamp.sh");

/// A disposable git repository with one commit, returning its full HEAD sha.
fn fixture_repo(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "test"]);
    git(&["commit", "-q", "--allow-empty", "-m", "fixture"]);
    git(&["rev-parse", "HEAD"])
}

fn write_executable(path: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// An executable stand-in for an installed binary, answering `--version` the way
/// `crates/console/src/main.rs` and `crates/propolis/src/main.rs` do and exiting non-zero for
/// anything else - so a producer that stopped passing `--version` records nothing rather than
/// quietly keeping its result. The line is written to a sibling data file and `cat`-ed, so no test
/// input is ever interpolated into shell text.
fn write_fake_installed_binary(bin_dir: &Path, name: &str, version_line: &str) {
    std::fs::create_dir_all(bin_dir).unwrap();
    std::fs::write(
        bin_dir.join(format!("{name}.version")),
        format!("{version_line}\n"),
    )
    .unwrap();
    write_executable(
        &bin_dir.join(name),
        "#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 64\ncat \"$0.version\"\n",
    );
}

fn run_deploy_stamp(repo: &Path, out_file: &Path, bin_dir: &Path) -> std::process::Output {
    std::process::Command::new(DEPLOY_STAMP)
        .arg(repo)
        .arg(out_file)
        .arg(bin_dir)
        .output()
        .expect("failed to run deploy/deploy-stamp.sh")
}

fn stamp_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("deploy-stamp.sh wrote no stamp file");
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "deploy-stamp.sh wrote something that is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn installed_sha(stamp: &serde_json::Value, binary: &str) -> String {
    stamp["installed"][binary]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Both deployment shapes exist on this project - the unified `propolis` daemon serves the console
/// on a single box, and `console.service` runs a separate `/usr/local/bin/console` where the
/// operator splits them - so the stamp has to answer for each binary on its own. The two fixtures
/// report DIFFERENT revisions on purpose: a producer that read one binary and wrote its answer
/// under both names would pass a fixture where they agreed.
#[test]
fn deploy_stamp_records_each_installed_binary_under_its_own_name() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let head = fixture_repo(&repo);
    let bin_dir = tmp.path().join("bin");
    write_fake_installed_binary(
        &bin_dir,
        "propolis",
        &format!(
            "propolis 0.3.0 ({}, built 2026-09-09T00:00:00Z)",
            &head[..12]
        ),
    );
    write_fake_installed_binary(
        &bin_dir,
        "console",
        "console 0.3.0 (0123456789ab, built 2026-09-09T00:00:00Z)",
    );

    let out_file = tmp.path().join("deploy-stamp.json");
    let output = run_deploy_stamp(&repo, &out_file, &bin_dir);
    assert!(
        output.status.success(),
        "deploy-stamp.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stamp = stamp_json(&out_file);
    assert_eq!(stamp["head_sha"].as_str(), Some(head.as_str()));
    assert_eq!(
        installed_sha(&stamp, "propolis"),
        head[..12],
        "the propolis entry must carry what the propolis binary itself reported: {stamp}"
    );
    assert_eq!(
        installed_sha(&stamp, "console"),
        "0123456789ab",
        "the console entry must carry what the console binary reported, not the other one's \
         revision: {stamp}"
    );
}

/// A collector-only box has no console binary, and `install.sh --dry-run` installs nothing at all.
/// Neither is an error, and neither may be filled in from the checkout or from the other binary:
/// the entry stays empty and the console renders it as not recorded.
#[test]
fn deploy_stamp_leaves_a_binary_that_is_not_installed_unrecorded() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let head = fixture_repo(&repo);
    let bin_dir = tmp.path().join("bin");
    write_fake_installed_binary(
        &bin_dir,
        "propolis",
        &format!(
            "propolis 0.3.0 ({}, built 2026-09-09T00:00:00Z)",
            &head[..12]
        ),
    );

    let out_file = tmp.path().join("deploy-stamp.json");
    let output = run_deploy_stamp(&repo, &out_file, &bin_dir);
    assert!(
        output.status.success(),
        "a missing binary must not abort the deploy over a monitoring detail: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stamp = stamp_json(&out_file);
    assert_eq!(installed_sha(&stamp, "propolis"), head[..12]);
    assert_eq!(
        installed_sha(&stamp, "console"),
        "",
        "a binary that is not installed must leave its entry empty, never inherit the checkout's \
         revision: {stamp}"
    );
}

/// Anything that is not a version line in the expected shape, from the expected program, must
/// record nothing. A wrong or malformed value here would be worse than an absent one: the console
/// compares it against the deploy and would report a difference that means nothing. The good line
/// is checked in the same test so a producer that simply recorded nothing at all could not pass.
#[test]
fn deploy_stamp_refuses_a_version_line_it_cannot_trust() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let head = fixture_repo(&repo);
    let bin_dir = tmp.path().join("bin");
    let out_file = tmp.path().join("deploy-stamp.json");
    let good = format!(
        "propolis 0.3.0 ({}, built 2026-09-09T00:00:00Z)",
        &head[..12]
    );

    for line in [
        // Not a revision at all.
        "propolis 0.3.0 (not-a-git-sha, built 2026-09-09T00:00:00Z)",
        // The shape is gone: nothing to read a revision out of.
        "propolis 0.3.0 built 2026-09-09T00:00:00Z",
        "",
        // Some other program installed at that path. Its idea of a revision is not this one's.
        "somethingelse 0.3.0 (0123456789ab, built 2026-09-09T00:00:00Z)",
    ] {
        write_fake_installed_binary(&bin_dir, "propolis", line);
        let output = run_deploy_stamp(&repo, &out_file, &bin_dir);
        assert!(output.status.success(), "line {line:?} aborted the deploy");
        assert_eq!(
            installed_sha(&stamp_json(&out_file), "propolis"),
            "",
            "a version line of {line:?} must record nothing"
        );
    }

    write_fake_installed_binary(&bin_dir, "propolis", &good);
    run_deploy_stamp(&repo, &out_file, &bin_dir);
    assert_eq!(
        installed_sha(&stamp_json(&out_file), "propolis"),
        head[..12],
        "and a well-formed line must still be recorded, or this check would pass by rejecting \
         everything"
    );
}

/// The case this field exists to catch is an install that did NOT replace the binary - and the
/// binary left behind is by definition an older one, from before `--version` existed, which treats
/// the flag as no argument at all and starts the service. Asking it for its version must not hang
/// the deploy waiting for a daemon to exit.
#[test]
fn deploy_stamp_does_not_hang_when_the_installed_binary_ignores_the_version_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fixture_repo(&repo);
    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(&bin_dir.join("propolis"), "#!/bin/sh\nsleep 300\n");

    let out_file = tmp.path().join("deploy-stamp.json");
    let started = std::time::Instant::now();
    let output = run_deploy_stamp(&repo, &out_file, &bin_dir);
    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "deploy-stamp.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "deploy-stamp.sh took {elapsed:?}, so a binary that does not answer --version can stall a \
         deploy indefinitely"
    );
    assert_eq!(
        installed_sha(&stamp_json(&out_file), "propolis"),
        "",
        "a binary that never answered must leave its entry empty"
    );
}

/// The mismatch is loud where an operator is already looking. Waiting for someone to open the
/// fleet pane is not a notification, and the stamp still records what the binary actually said:
/// the point is to report the box as it is, not to suppress the disagreement.
#[test]
fn deploy_stamp_warns_when_the_installed_binary_is_not_the_commit_that_was_built() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fixture_repo(&repo);
    let bin_dir = tmp.path().join("bin");
    write_fake_installed_binary(
        &bin_dir,
        "propolis",
        "propolis 0.3.0 (0123456789ab, built 2026-09-09T00:00:00Z)",
    );

    let out_file = tmp.path().join("deploy-stamp.json");
    let output = run_deploy_stamp(&repo, &out_file, &bin_dir);
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning") && stderr.contains("propolis"),
        "an installed binary that is not this checkout's commit must be reported at deploy time, \
         naming the binary: {stderr}"
    );
    assert_eq!(
        installed_sha(&stamp_json(&out_file), "propolis"),
        "0123456789ab",
        "and the stamp records what is actually on disk, not what the deploy wanted to be there"
    );
}

/// Same standard as `install_script_is_valid_bash`: `upgrade.sh` has no `--dry-run`, so a syntax
/// check is the one real execution it gets without root.
#[test]
fn upgrade_script_is_valid_bash() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/upgrade.sh");
    let status = std::process::Command::new("bash")
        .arg("-n")
        .arg(script)
        .status()
        .expect("failed to invoke `bash -n` on deploy/upgrade.sh");
    assert!(
        status.success(),
        "deploy/upgrade.sh has a bash syntax error"
    );
}

/// `upgrade.sh` only ever reinstalled binaries and restarted units, so a unit-file change (a
/// hardening directive, a new `ReadWritePaths` grant, a changed `ExecStart`) merged to main was
/// never installed on a live box by an upgrade - and without a `daemon-reload` systemd kept
/// running the unit definition from the last fresh install. The logrotate policy had the same
/// gap. This cross-checks the two scripts against each other: every unit `install.sh` installs
/// must also be installed by `upgrade.sh`, the logrotate config must be reinstalled, and the
/// `daemon-reload` must come before the first restart so the restarts pick up the new files.
#[test]
fn upgrade_script_reinstalls_every_installed_unit_and_reloads_before_restarting() {
    let install = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/install.sh"
    ))
    .expect("failed to read deploy/install.sh");
    let upgrade = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/upgrade.sh"
    ))
    .expect("failed to read deploy/upgrade.sh");

    let installed_units = unit_install_loop_members(&install);
    assert!(
        !installed_units.is_empty(),
        "no `for unit in ... .service` loop found in install.sh - this parser is broken"
    );
    let upgraded_units = unit_install_loop_members(&upgrade);
    for unit in &installed_units {
        assert!(
            upgraded_units.contains(unit),
            "install.sh installs {unit} but upgrade.sh does not reinstall it - a change to that \
             unit file never reaches a box that is only ever upgraded"
        );
    }
    assert!(
        upgrade
            .lines()
            .any(|l| l.contains("install -m 0644") && l.contains("/etc/systemd/system/")),
        "upgrade.sh must install unit files into /etc/systemd/system/"
    );
    assert!(
        upgrade
            .lines()
            .any(|l| l.contains("logrotate-sensors.conf") && l.contains("/etc/logrotate.d/")),
        "upgrade.sh must reinstall deploy/logrotate-sensors.conf into /etc/logrotate.d/"
    );

    let reload_at = upgrade
        .lines()
        .position(|l| l.trim_start().starts_with("systemctl daemon-reload"))
        .expect("upgrade.sh never runs `systemctl daemon-reload`");
    let first_restart_at = upgrade
        .lines()
        .position(|l| l.trim_start().starts_with("systemctl restart"))
        .expect("upgrade.sh never restarts a unit - the parser is broken");
    assert!(
        reload_at < first_restart_at,
        "upgrade.sh runs daemon-reload (line {}) after its first restart (line {}); the restart \
         would start the OLD unit definition",
        reload_at + 1,
        first_restart_at + 1
    );
}

/// The fleet listener inventory is DERIVED at deploy time precisely so it cannot drift from the
/// sensor env files it describes. That guarantee is only as good as both entry points running the
/// generator: a box that is only ever upgraded would otherwise keep the inventory of whichever
/// install last ran, and the pane would confidently describe listeners that no longer exist.
/// `upgrade.sh` must also run it BEFORE the first restart, since the units read the file at start.
#[test]
fn both_deploy_scripts_derive_the_fleet_listener_inventory() {
    let install = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/install.sh"
    ))
    .expect("failed to read deploy/install.sh");
    let upgrade = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/upgrade.sh"
    ))
    .expect("failed to read deploy/upgrade.sh");

    for (name, script) in [("install.sh", &install), ("upgrade.sh", &upgrade)] {
        assert!(
            script.contains("fleet-listeners.sh"),
            "deploy/{name} does not run deploy/fleet-listeners.sh, so PROPOLIS_FLEET_LISTENERS \
             would go stale on any box deployed through it"
        );
    }

    let derive_at = upgrade
        .lines()
        .position(|l| {
            l.trim_start()
                .starts_with("\"$SCRIPT_DIR/fleet-listeners.sh\"")
        })
        .expect("upgrade.sh never invokes fleet-listeners.sh as a command");
    let first_restart_at = upgrade
        .lines()
        .position(|l| l.trim_start().starts_with("systemctl restart"))
        .expect("upgrade.sh never restarts a unit - the parser is broken");
    assert!(
        derive_at < first_restart_at,
        "upgrade.sh derives the inventory (line {}) after its first restart (line {}); the \
         restarted unit would load the previous deploy's inventory",
        derive_at + 1,
        first_restart_at + 1
    );
}

/// Both units must load the generated inventory, and must load it BEFORE their operator-owned env
/// file: systemd lets a later `EnvironmentFile` override an earlier one, so the reverse order would
/// silently discard an operator's deliberate `PROPOLIS_FLEET_LISTENERS` override.
#[test]
fn units_load_the_generated_fleet_inventory_before_their_operator_env_file() {
    for (unit, operator_env) in [
        ("propolis.service", "/etc/propolis/propolis.env"),
        ("console.service", "/etc/propolis/console.env"),
    ] {
        let path = format!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/{}"),
            unit
        );
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let generated_at = text
            .lines()
            .position(|l| l.trim() == "EnvironmentFile=-/etc/propolis/fleet-listeners.env")
            .unwrap_or_else(|| {
                panic!("{unit} does not load the generated /etc/propolis/fleet-listeners.env")
            });
        let operator_at = text
            .lines()
            .position(|l| l.trim() == format!("EnvironmentFile={operator_env}"))
            .unwrap_or_else(|| panic!("{unit} no longer loads {operator_env}"));
        assert!(
            generated_at < operator_at,
            "{unit} loads the generated inventory (line {}) after {operator_env} (line {}), so an \
             operator override in that file would be discarded",
            generated_at + 1,
            operator_at + 1
        );
    }
}

/// The `.service` names listed by every `for unit in ...` loop in a deploy script. Both scripts
/// keep their unit lists as literal loop members, so this is the authoritative population, not a
/// hand-copied list that could drift from the scripts it guards.
fn unit_install_loop_members(script: &str) -> HashSet<String> {
    script
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("for unit in "))
        .flat_map(|l| {
            l.trim_start_matches("for unit in ")
                .split_whitespace()
                .map(|t| t.trim_end_matches(';'))
                .filter(|t| t.ends_with(".service"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// "The sensors make no outbound connections" rested on one crate's test: `sensor-ssh` asserts
/// its own manifest names no HTTP client. Every other sensor was covered only by prose. This
/// walks every `crates/sensor-*/Cargo.toml` in the workspace, so a sensor added later, or an
/// HTTP client added to an existing one, fails the build rather than quietly breaking the claim
/// the docs make about all of them. The `review` crate legitimately uses reqwest for vendor
/// reporting; it is not a sensor and is not walked.
#[test]
fn no_sensor_crate_depends_on_an_http_client() {
    const BANNED: [&str; 7] = [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
    ];
    let crates_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let mut checked = Vec::new();
    for entry in std::fs::read_dir(&crates_dir).expect("failed to read crates/") {
        let entry = entry.expect("failed to read a crates/ entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("sensor-") {
            continue;
        }
        let manifest = entry.path().join("Cargo.toml");
        let content = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", manifest.display()));
        for line in content.lines() {
            let key = line.split(['=', ' ', '.']).next().unwrap_or("").trim();
            assert!(
                !BANNED.contains(&key),
                "{name}/Cargo.toml names the HTTP client crate `{key}`; sensors must not be \
                 able to make outbound requests"
            );
        }
        checked.push(name);
    }
    assert!(
        checked.len() >= 9,
        "expected every sensor crate to be walked, found only {checked:?}"
    );
}

/// Sensors with a TLS listener (telnet is deliberately out of scope).
const TLS_SENSORS: [&str; 7] = ["http", "mqtt", "redis", "smtp", "ftp", "cred", "dns"];

/// The TLS directory grant every TLS-capable sensor unit carries. The leading `-` makes a missing
/// directory non-fatal: without it systemd refuses to start the unit (226/NAMESPACE) on a box where
/// `/etc/propolis/tls` was never provisioned, even when the sensor uses no TLS. TLS itself stays
/// fail-closed in-process, because the loader refuses a configured pair it cannot read.
const TLS_READ_ONLY_LINE: &str = "ReadOnlyPaths=-/etc/propolis/tls";

/// The sensors `deploy/provision-tls.sh` mints a pair for, parsed from its `TLS_SENSORS=(...)`.
fn provision_tls_sensors() -> Vec<String> {
    deploy_file("provision-tls.sh")
        .lines()
        .find_map(|l| l.strip_prefix("TLS_SENSORS=("))
        .and_then(|rest| rest.strip_suffix(')'))
        .expect("provision-tls.sh has no TLS_SENSORS=(...) line at column 0")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Coverage gate for the per-unit TLS assertions above: those check only the units somebody
/// listed. Both sides are derived from the files at test time, so a unit that gained (or kept) the
/// TLS grant without a minted pair, or a minted sensor whose unit cannot read its pair, fails here.
/// Any `ReadOnlyPaths` line naming the TLS directory counts, so a unit that reverts to the
/// undashed form is caught as well.
#[test]
fn tls_dir_grant_units_match_provision_tls_sensors_exactly() {
    let deploy_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy"));
    let mut granted = std::collections::BTreeSet::new();
    let mut units_seen = 0usize;
    for entry in std::fs::read_dir(&deploy_dir).expect("failed to read deploy/") {
        let name = entry
            .expect("failed to read a deploy/ entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        let Some(sensor) = name
            .strip_prefix("sensor-")
            .and_then(|n| n.strip_suffix(".service"))
        else {
            continue;
        };
        units_seen += 1;
        let unit = deploy_file(&name);
        let tls_lines: Vec<&str> = unit
            .lines()
            .filter(|l| l.starts_with("ReadOnlyPaths=") && l.contains("/etc/propolis/tls"))
            .collect();
        if tls_lines.is_empty() {
            continue;
        }
        assert_eq!(
            tls_lines,
            [TLS_READ_ONLY_LINE],
            "deploy/{name} must grant the TLS directory exactly as `{TLS_READ_ONLY_LINE}`"
        );
        granted.insert(sensor.to_string());
    }
    assert!(
        units_seen >= 9,
        "only {units_seen} deploy/sensor-*.service units found: the walk is broken"
    );
    let minted: std::collections::BTreeSet<String> = provision_tls_sensors().into_iter().collect();
    assert_eq!(
        granted, minted,
        "units granting {TLS_READ_ONLY_LINE} must be exactly the sensors provision-tls.sh mints for"
    );
}

fn deploy_file(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../deploy/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("failed to read deploy/{name}: {e}"))
}

/// The key directory is root-owned and traverse-only: sensor uids need x to open their own key by
/// name, nobody needs to list it. 0750 would lock every sensor out.
#[test]
fn tls_dir_is_provisioned_root_owned_and_traverse_only() {
    assert!(provisioned_dirs().contains("/etc/propolis/tls"));
    let line = deploy_file("provision.sh")
        .lines()
        .find(|l| {
            l.split_whitespace().take(2).collect::<Vec<_>>() == ["ensure_dir", "/etc/propolis/tls"]
        })
        .expect("provision.sh has no ensure_dir line for /etc/propolis/tls")
        .to_string();
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>(),
        ["ensure_dir", "/etc/propolis/tls", "0711", "root", "root"]
    );
}

/// provision-tls.sh must be valid bash, and every sensor it mints for must be a user that
/// provision.sh creates (the chown would fail otherwise).
#[test]
fn provision_tls_script_is_valid_bash_and_mints_for_provisioned_users() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/provision-tls.sh");
    let status = std::process::Command::new("bash")
        .arg("-n")
        .arg(script)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "deploy/provision-tls.sh has a bash syntax error"
    );

    let minted = provision_tls_sensors();
    assert_eq!(minted, TLS_SENSORS);

    let provision = deploy_file("provision.sh");
    for sensor in minted {
        let user = format!("ensure_user propolis-{sensor}");
        assert!(
            provision.lines().any(|l| l.trim_end() == user),
            "provision.sh does not create propolis-{sensor}"
        );
    }
}

/// Ordering contract: install mints after the binaries are installed; upgrade mints after the
/// build, after provision.sh created the directory, and before the first restart.
#[test]
fn both_deploy_scripts_mint_tls_certs_at_the_right_point() {
    let install = deploy_file("install.sh");
    let upgrade = deploy_file("upgrade.sh");
    let at = |s: &str, pred: &dyn Fn(&str) -> bool| {
        s.lines()
            .position(|l| pred(l.trim_start()))
            .expect("expected line not found")
    };

    let bins_at = at(&install, &|l| l.starts_with("for bin in "));
    let mint_at = at(&install, &|l| l == "run_provision_tls");
    assert!(
        bins_at < mint_at,
        "install.sh must mint after installing binaries"
    );
    assert!(install.contains("PROVISION_CERTS_BIN=\"$BUILD_DIR/provision-certs\""));

    let build_at = at(&upgrade, &|l| l.contains("cargo build --release"));
    let prov_at = at(&upgrade, &|l| l == "\"$SCRIPT_DIR/provision.sh\"");
    let tls_at = at(&upgrade, &|l| {
        l.starts_with("PROVISION_CERTS_BIN=") && l.contains("provision-tls.sh")
    });
    let restart_at = at(&upgrade, &|l| l.starts_with("systemctl restart"));
    assert!(build_at < prov_at && prov_at < tls_at && tls_at < restart_at);
    assert!(upgrade.contains("PROVISION_CERTS_BIN=\"$BUILD_DIR/provision-certs\""));
}

/// Real dry-run of install.sh: the tls dir at 0711, one --sensor-tls call over all seven sensors,
/// and per-sensor ownership + modes (key 0600 owned by the sensor's own user).
#[test]
fn install_dry_run_mints_and_locks_down_a_pair_per_tls_sensor() {
    let out = std::process::Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/install.sh"
    ))
    .arg("--dry-run")
    .output()
    .expect("failed to run install.sh --dry-run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("install -d -m 0711 -o root -g root /etc/propolis/tls\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("--sensor-tls /etc/propolis/tls http mqtt redis smtp ftp cred dns\n"),
        "{stdout}"
    );
    for s in TLS_SENSORS {
        for needle in [
            // One path per chown/chmod: the loop skips a symlinked path rather than following it,
            // so it cannot batch the pair into a single chown.
            format!("chown propolis-{s}:propolis-{s} /etc/propolis/tls/{s}.key\n"),
            format!("chmod 0600 /etc/propolis/tls/{s}.key\n"),
            format!("chown propolis-{s}:propolis-{s} /etc/propolis/tls/{s}.crt\n"),
            format!("chmod 0644 /etc/propolis/tls/{s}.crt\n"),
        ] {
            assert!(stdout.contains(&needle), "missing `{needle}` in:\n{stdout}");
        }
    }
}

/// A private key must never be committed: the repo rule is generate-at-deploy, ephemeral in tests.
/// The needles are assembled at runtime so this file does not match itself, and no other file
/// under crates/ or deploy/ may spell a PEM private-key header (tests assert on "PRIVATE KEY"
/// without the BEGIN prefix instead).
#[test]
fn no_private_key_pem_is_committed_under_crates_or_deploy() {
    let needles: Vec<String> = ["", "RSA ", "EC ", "ENCRYPTED ", "OPENSSH "]
        .iter()
        .map(|p| format!("BEGIN {p}PRIVATE KEY"))
        .collect();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut stack = vec![root.join("crates"), root.join("deploy")];
    let mut scanned = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                scanned += 1;
                for n in &needles {
                    assert!(
                        !text.contains(n.as_str()),
                        "{} contains a PEM private key header",
                        path.display()
                    );
                }
            }
        }
    }
    assert!(
        scanned > 100,
        "the walk is broken: only {scanned} text files scanned"
    );
}

/// The groups `provision.sh` adds `user` to with `usermod -aG <groups> <user>`.
fn supplementary_groups(provision: &str, user: &str) -> HashSet<String> {
    provision
        .lines()
        .filter_map(|l| {
            let tokens: Vec<&str> = l.split_whitespace().collect();
            match tokens.as_slice() {
                ["run", "usermod", "-aG", groups, who] if *who == user => Some(groups.to_string()),
                _ => None,
            }
        })
        .flat_map(|groups| groups.split(',').map(str::to_string).collect::<Vec<_>>())
        .collect()
}

/// The live watcher's account must be able to read every sensor's event log and nothing else:
/// its groups are exactly the owning groups of the log directories `provision.sh` creates (read
/// through the 0750/0640 group bits, never write), and `systemd-journal` stays an opt-in the
/// operator adds by hand. It must also be reachable by SSH: a real shell for the forced command,
/// a home for authorized_keys, and a password field sshd does not treat as locked.
#[test]
fn watch_user_reads_every_sensor_log_and_nothing_more_by_default() {
    let provision = deploy_file("provision.sh");
    let log_groups: HashSet<String> = provision
        .lines()
        .filter_map(|l| {
            let tokens: Vec<&str> = l.split_whitespace().collect();
            match tokens.as_slice() {
                ["ensure_dir", path, mode, _owner, group]
                    if path.starts_with("/var/log/propolis/") =>
                {
                    assert_eq!(*mode, "0750", "{path} must stay owner-write, group-read");
                    Some(group.to_string())
                }
                _ => None,
            }
        })
        .collect();
    assert!(log_groups.len() >= 12, "parsed only {log_groups:?}");
    assert_eq!(
        supplementary_groups(&provision, "propolis-watch"),
        log_groups
    );
    assert_eq!(
        supplementary_groups(&provision, "propolis-watch"),
        supplementary_groups(&provision, "propolis"),
        "the watcher reads exactly the logs the daemon reads"
    );
    let watch_groups = supplementary_groups(&provision, "propolis-watch");
    assert!(
        !watch_groups.contains("systemd-journal") && !watch_groups.contains("adm"),
        "journal access is an opt-in step, not provisioned"
    );
    assert!(provision.lines().any(|l| l.trim()
        == "run useradd --system --no-create-home --home-dir /var/lib/propolis-watch --shell /bin/sh --user-group propolis-watch"));
    assert!(
        provision
            .lines()
            .any(|l| l.trim() == "run usermod -p '*' propolis-watch")
    );
    // Root-owned all the way to the key file, so the account cannot change which keys log in.
    for expected in [
        [
            "ensure_dir",
            "/var/lib/propolis-watch",
            "0750",
            "root",
            "propolis-watch",
        ],
        [
            "ensure_dir",
            "/var/lib/propolis-watch/.ssh",
            "0755",
            "root",
            "root",
        ],
    ] {
        assert!(
            provision
                .lines()
                .any(|l| l.split_whitespace().collect::<Vec<_>>() == expected),
            "provision.sh must run {expected:?}"
        );
    }
}

#[test]
fn both_deploy_scripts_install_the_watcher_binary() {
    for script in ["install.sh", "upgrade.sh"] {
        assert!(
            install_bin_list(script).contains("propolis-watch"),
            "{script} does not install propolis-watch"
        );
    }
}

/// The names in `INSTALL_BINS=(...)` of a deploy script: the one list its install loop and its
/// post-install check both walk.
fn install_bin_list(script: &str) -> std::collections::BTreeSet<String> {
    let text = deploy_file(script);
    let list = text
        .lines()
        .find_map(|l| l.strip_prefix("INSTALL_BINS=("))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("{script} has no single-line INSTALL_BINS=(...) at column 0"));
    list.split_whitespace().map(str::to_string).collect()
}

/// Every binary target in the workspace, derived from the crates themselves: a crate with a
/// `src/main.rs` builds the `[[bin]]` names its manifest declares, or the package name when it
/// declares none.
fn workspace_binaries() -> std::collections::BTreeSet<String> {
    let crates_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let mut bins = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&crates_dir).expect("failed to read crates/") {
        let dir = entry.expect("failed to read a crates/ entry").path();
        if !dir.join("Cargo.toml").is_file() {
            continue;
        }
        assert!(
            !dir.join("src/bin").exists(),
            "{} has src/bin/, which this derivation does not read; extend it before adding one",
            dir.display()
        );
        if !dir.join("src/main.rs").is_file() {
            continue;
        }
        let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        let quoted_name = |l: &str| {
            l.trim()
                .strip_prefix("name")
                .and_then(|r| r.trim_start().strip_prefix('='))
                .map(|r| r.trim().trim_matches('"').to_string())
        };
        let mut section = "";
        let mut declared = Vec::new();
        let mut package = None;
        for line in manifest.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = if t == "[[bin]]" {
                    "bin"
                } else if t == "[package]" {
                    "package"
                } else {
                    ""
                };
            } else if section == "bin" {
                declared.extend(quoted_name(t));
            } else if section == "package" {
                package = package.or_else(|| quoted_name(t));
            }
        }
        if declared.is_empty() {
            declared
                .push(package.unwrap_or_else(|| panic!("{} has no package name", dir.display())));
        }
        bins.extend(declared);
    }
    assert!(bins.len() >= 15, "the workspace walk is broken: {bins:?}");
    bins
}

/// Workspace binaries that are deliberately not installed to /usr/local/bin. A binary added to the
/// workspace belongs in neither place by default: it fails the test below until someone either
/// adds it to the install lists or lists it here with the reason.
const NOT_INSTALLED_BINS: [&str; 5] = [
    // Superseded by the unified `propolis` daemon in production; kept for development only
    // (install.sh's header, "What gets retired").
    "intake",
    "review",
    "feed",
    "console",
    // A deploy tool run from the build directory by provision-tls.sh (PROVISION_CERTS_BIN), not a
    // service.
    "provision-certs",
];

/// A release that adds a binary to the workspace but not to the install lists leaves that binary
/// built and never installed (the `propolis-watch` outage: upgrade.sh built it and installed from
/// a list that did not name it). Both sides are derived from the files at test time. The install
/// lists differ in exactly the gateway and shipper, which only upgrade.sh installs (a fresh single
/// box has no unit for them; the split-deployment roles install them through upgrade.sh).
#[test]
fn install_lists_cover_exactly_the_workspace_binaries_meant_to_be_installed() {
    let expected: std::collections::BTreeSet<String> = workspace_binaries()
        .into_iter()
        .filter(|b| !NOT_INSTALLED_BINS.contains(&b.as_str()))
        .collect();
    for excluded in NOT_INSTALLED_BINS {
        assert!(
            workspace_binaries().contains(excluded),
            "NOT_INSTALLED_BINS names {excluded}, which is no longer a workspace binary"
        );
    }

    let upgrade = install_bin_list("upgrade.sh");
    assert_eq!(
        upgrade, expected,
        "upgrade.sh's INSTALL_BINS must be exactly the workspace binaries meant to be installed"
    );

    let install = install_bin_list("install.sh");
    let upgrade_only: std::collections::BTreeSet<String> =
        upgrade.difference(&install).cloned().collect();
    assert_eq!(
        upgrade_only,
        ["gateway", "shipper"].map(String::from).into(),
        "install.sh and upgrade.sh must differ only by the split-deployment gateway and shipper"
    );
    assert!(
        install.is_subset(&upgrade),
        "install.sh installs a binary upgrade.sh does not"
    );
}

/// The lines of `upgrade.sh` between its pull-and-reexec markers.
fn pull_and_reexec_block() -> String {
    let text = deploy_file("upgrade.sh");
    let mut inside = false;
    let mut block = String::new();
    for line in text.lines() {
        match line {
            "# END pull-and-reexec" => inside = false,
            _ if inside => {
                block.push_str(line);
                block.push('\n');
            }
            "# BEGIN pull-and-reexec" => inside = true,
            _ => {}
        }
    }
    assert!(!block.is_empty(), "upgrade.sh has no pull-and-reexec block");
    block
}

/// The re-exec has to happen before anything that depends on the script's own content: the build,
/// the binary list, the provisioning and the restarts. After the pull and before all of them.
#[test]
fn upgrade_script_reexecs_after_the_pull_and_before_any_build_or_install() {
    let upgrade = deploy_file("upgrade.sh");
    let lines: Vec<&str> = upgrade.lines().collect();
    let at = |needle: &str| {
        lines
            .iter()
            .position(|l| l.trim_start().starts_with(needle))
            .unwrap_or_else(|| panic!("upgrade.sh has no line starting with `{needle}`"))
    };
    let pull = at("sudo -u \"$(stat -c '%U' \"$REPO_DIR\")\" git pull");
    let reexec = at("exec \"$SCRIPT_DIR/upgrade.sh\" \"$@\"");
    let build = at("sudo -u \"$(stat -c '%U' \"$REPO_DIR\")\" cargo build");
    let first_install = at("install -m 0755");
    let provision = at("\"$SCRIPT_DIR/provision.sh\"");
    let first_restart = at("systemctl restart");
    assert!(
        pull < reexec
            && reexec < build
            && build < first_install
            && first_install < provision
            && provision < first_restart,
        "the re-exec (line {}) must follow the pull (line {}) and precede the build (line {}), \
         the installs (line {}), provisioning (line {}) and the restarts (line {})",
        reexec + 1,
        pull + 1,
        build + 1,
        first_install + 1,
        provision + 1,
        first_restart + 1
    );
    let block = pull_and_reexec_block();
    assert!(block.contains("PROPOLIS_UPGRADE_REEXEC"));
    assert!(
        block.contains("sha256sum"),
        "the re-exec must be conditional on the file changing"
    );
}

struct ReexecRun {
    output: std::process::Output,
    pulls: usize,
}

/// Runs a copy of the real pull-and-reexec block as `deploy/upgrade.sh` of a throwaway tree, with
/// a stub `sudo` standing in for `sudo -u <owner> git pull`. The stub counts pulls and, when
/// `pull_rewrites_script`, rewrites the running script the way a pull of a release that changes
/// upgrade.sh does. The script ends in a `CONTINUED` line so the output shows how many times
/// execution got past the block.
fn run_pull_and_reexec(pull_rewrites_script: bool, env: &[(&str, &str)]) -> ReexecRun {
    let tmp = tempfile::tempdir().unwrap();
    let deploy = tmp.path().join("deploy");
    let stubs = tmp.path().join("stubs");
    std::fs::create_dir_all(&deploy).unwrap();
    std::fs::create_dir_all(&stubs).unwrap();
    let pull_log = tmp.path().join("pulls.log");
    let script = deploy.join("upgrade.sh");
    write_executable(
        &script,
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\n\
             SCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\n\
             REPO_DIR=\"$(cd \"$SCRIPT_DIR/..\" && pwd)\"\n\
             echo ENTERED\n\
             {}\
             echo \"CONTINUED pulled_at=$PULLED_AT args=$* guard=${{PROPOLIS_UPGRADE_REEXEC:-none}}\"\n",
            pull_and_reexec_block()
        ),
    );
    // `sudo -u <owner> git pull`: record it, and optionally change the script like a real pull.
    write_executable(
        &stubs.join("sudo"),
        "#!/bin/sh\n[ \"$1\" = \"-u\" ] && [ \"$3\" = \"git\" ] && [ \"$4\" = \"pull\" ] || exit 64\n\
         echo pull >> \"$PULL_LOG\"\n\
         [ \"$(wc -l < \"$PULL_LOG\")\" -le 3 ] || exit 70\n\
         [ -z \"$PULL_REWRITES_SCRIPT\" ] || printf '# changed by pull\\n' >> \"$UPGRADE_SCRIPT\"\n",
    );
    let path = format!("{}:{}", stubs.display(), std::env::var("PATH").unwrap());
    let mut cmd = std::process::Command::new(&script);
    cmd.args(["--flag", "value"])
        .env("PATH", path)
        .env("PULL_LOG", &pull_log)
        .env("UPGRADE_SCRIPT", &script)
        .env_remove("PROPOLIS_UPGRADE_REEXEC")
        .env_remove("PROPOLIS_UPGRADE_PULLED_AT");
    if pull_rewrites_script {
        cmd.env("PULL_REWRITES_SCRIPT", "1");
    } else {
        cmd.env_remove("PULL_REWRITES_SCRIPT");
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("failed to run the fixture upgrade.sh");
    let pulls = std::fs::read_to_string(&pull_log)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    ReexecRun { output, pulls }
}

/// How many times the script started: a re-exec starts it a second time, where merely setting the
/// guard variable and carrying on does not.
fn script_starts(run: &ReexecRun) -> usize {
    String::from_utf8_lossy(&run.output.stdout)
        .lines()
        .filter(|l| *l == "ENTERED")
        .count()
}

fn continued_lines(run: &ReexecRun) -> Vec<String> {
    String::from_utf8_lossy(&run.output.stdout)
        .lines()
        .filter(|l| l.starts_with("CONTINUED"))
        .map(str::to_string)
        .collect()
}

/// The defect: a pull that replaces upgrade.sh must not leave the rest of the upgrade running from
/// the old copy. The stub rewrites the script on EVERY pull, so a re-executed run that pulled again
/// would loop; the guard has to hold it to exactly one pull, one pass through the rest of the
/// script, the original arguments, and the first run's pull timestamp.
#[test]
fn upgrade_reexecs_once_when_the_pull_changes_the_script_and_does_not_pull_again() {
    let run = run_pull_and_reexec(true, &[]);
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    assert_eq!(run.pulls, 1, "the re-executed run must not pull again");
    assert_eq!(
        script_starts(&run),
        2,
        "the changed script must be exec'd anew"
    );
    let continued = continued_lines(&run);
    assert_eq!(
        continued.len(),
        1,
        "stdout: {}",
        String::from_utf8_lossy(&run.output.stdout)
    );
    assert!(
        continued[0].ends_with("args=--flag value guard=1"),
        "the surviving run must be the re-executed one, with the original arguments: {continued:?}"
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(stdout.contains("re-executing the new version"), "{stdout}");
    let pulled_at = continued[0]
        .strip_prefix("CONTINUED pulled_at=")
        .and_then(|r| r.split_once(' '))
        .map(|(t, _)| t)
        .unwrap();
    assert!(
        pulled_at.len() == 20 && pulled_at.ends_with('Z') && pulled_at.as_bytes()[10] == b'T',
        "the stamp's PULLED_AT must be the pull's UTC timestamp, got {pulled_at:?}"
    );
}

#[test]
fn upgrade_does_not_reexec_when_the_pull_leaves_the_script_unchanged() {
    let run = run_pull_and_reexec(false, &[]);
    assert!(run.output.status.success());
    assert_eq!(run.pulls, 1);
    let continued = continued_lines(&run);
    assert_eq!(continued.len(), 1);
    assert!(continued[0].ends_with("guard=none"), "{continued:?}");
    assert_eq!(script_starts(&run), 1);
    assert!(
        !String::from_utf8_lossy(&run.output.stdout).contains("re-executing"),
        "an unchanged script must not be re-executed"
    );
}

/// The guard alone skips the pull, takes PULLED_AT from the environment, and fails closed when the
/// timestamp is missing rather than stamping an empty or invented one.
#[test]
fn upgrade_guard_skips_the_pull_and_requires_the_carried_timestamp() {
    let run = run_pull_and_reexec(
        true,
        &[
            ("PROPOLIS_UPGRADE_REEXEC", "1"),
            ("PROPOLIS_UPGRADE_PULLED_AT", "2026-01-02T03:04:05Z"),
        ],
    );
    assert!(run.output.status.success());
    assert_eq!(run.pulls, 0, "the guard must skip the pull");
    assert_eq!(
        continued_lines(&run),
        ["CONTINUED pulled_at=2026-01-02T03:04:05Z args=--flag value guard=1"]
    );

    let run = run_pull_and_reexec(true, &[("PROPOLIS_UPGRADE_REEXEC", "1")]);
    assert!(
        !run.output.status.success(),
        "a guarded run with no carried timestamp must abort"
    );
    assert_eq!(run.pulls, 0);
    assert!(continued_lines(&run).is_empty());
}

/// Both loops run under `set -e` with an explicit check, so a listed binary the build did not
/// produce stops the upgrade before the stamp and the restarts, and a binary absent from
/// /usr/local/bin afterwards is caught before any service is restarted onto it.
#[test]
fn upgrade_script_fails_on_a_missing_binary_before_the_restarts() {
    let upgrade = deploy_file("upgrade.sh");
    let lines: Vec<&str> = upgrade.lines().map(str::trim_start).collect();
    let src_check = lines
        .iter()
        .position(|l| l.starts_with("if [ ! -x \"$BUILD_DIR/$bin\" ]"))
        .expect("upgrade.sh does not check each built binary exists before installing it");
    let dst_check = lines
        .iter()
        .position(|l| l.starts_with("if [ ! -x \"/usr/local/bin/$bin\" ]"))
        .expect("upgrade.sh has no post-install check of /usr/local/bin");
    let stamp = lines
        .iter()
        .position(|l| l.contains("\"$SCRIPT_DIR/deploy-stamp.sh\""))
        .unwrap();
    let first_restart = lines
        .iter()
        .position(|l| l.starts_with("systemctl restart"))
        .unwrap();
    assert!(src_check < dst_check && dst_check < stamp && stamp < first_restart);
    for check in [src_check, dst_check] {
        assert!(
            lines[check..check + 4].contains(&"exit 1"),
            "the check at line {} must exit non-zero",
            check + 1
        );
    }
}

/// The example key line is the whole security boundary of the remote read path, so its options
/// are pinned: `restrict` first, a forced command that runs only the watcher, and no option that
/// would hand back a pty or a forward. It must carry a placeholder, never a real key.
#[test]
fn watch_authorized_keys_example_forces_the_watcher_under_restrict() {
    let example = deploy_file("watch-authorized-keys.example");
    let lines: Vec<&str> = example
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one example key line");
    let line = lines[0];
    let (options, rest) = line
        .split_once(" ssh-ed25519 ")
        .expect("an ssh-ed25519 key line");
    assert_eq!(
        options, "restrict,command=\"/usr/local/bin/propolis-watch\"",
        "the key's only options are restrict and the bare forced command; the log list comes \
         from /etc/propolis/watch.env, never a hand-kept copy here"
    );
    assert!(
        rest.starts_with("AAAA... "),
        "the example must not carry a real key"
    );
}

/// Runs deploy/watch-env.sh against `source` content, writing into a fresh directory, and returns
/// the directory and the script's output.
fn run_watch_env(source: Option<&str>, dry_run: bool) -> (tempfile::TempDir, std::process::Output) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("propolis.env");
    if let Some(content) = source {
        std::fs::write(&src, content).unwrap();
    }
    let out = std::process::Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/watch-env.sh"
    ))
    .arg(&src)
    .arg(dir.path().join("watch.env"))
    .env("DRY_RUN", if dry_run { "1" } else { "0" })
    .output()
    .expect("run deploy/watch-env.sh");
    assert!(
        out.status.success(),
        "watch-env.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, out)
}

/// The watcher's account may read watch.env, so nothing from propolis.env but the one key may
/// ever reach it: the database URL and the console password sit in the same source file.
#[test]
fn watch_env_copies_only_the_sensor_logs_line_from_propolis_env() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = "DATABASE_URL=postgres://propolis:EXAMPLE-SECRET@localhost/propolis\n\
                   PROPOLIS_CONSOLE_PASSWORD=EXAMPLE-SECRET\n\
                   # PROPOLIS_SENSOR_LOGS=commented:/var/log/x.jsonl\n\
                   PROPOLIS_SENSOR_LOGS=old:/var/log/old.jsonl\n\
                   PROPOLIS_SENSOR_LOGS_EXTRA=EXAMPLE-SECRET\n\
                   PROPOLIS_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl\n\
                   PROPOLIS_VENDOR_ABUSEIPDB_KEY=EXAMPLE-SECRET\n";
    let (dir, _) = run_watch_env(Some(fixture), false);
    let written = std::fs::read_to_string(dir.path().join("watch.env")).unwrap();
    assert_eq!(
        written,
        "PROPOLIS_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl\n"
    );
    assert!(!written.contains("EXAMPLE-SECRET"));
    let mode = std::fs::metadata(dir.path().join("watch.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["propolis.env", "watch.env"],
        "no temporary file left behind"
    );
}

#[test]
fn watch_env_writes_nothing_without_the_key_without_a_source_or_in_dry_run() {
    let (dir, _) = run_watch_env(
        Some("DATABASE_URL=postgres://u:EXAMPLE-SECRET@h/db\n"),
        false,
    );
    assert!(!dir.path().join("watch.env").exists());
    let (dir, _) = run_watch_env(None, false);
    assert!(!dir.path().join("watch.env").exists());
    let (dir, out) = run_watch_env(Some("PROPOLIS_SENSOR_LOGS=a:/x\n"), true);
    assert!(!dir.path().join("watch.env").exists());
    assert!(String::from_utf8_lossy(&out.stdout).contains("[dry-run]"));
}

/// Derived on every provision, which upgrade.sh runs, and only once the account it hands the file
/// to exists.
#[test]
fn provision_derives_watch_env_after_creating_the_account() {
    let provision = deploy_file("provision.sh");
    let lines: Vec<&str> = provision.lines().collect();
    let derive = lines
        .iter()
        .position(|l| l.contains("/watch-env.sh\""))
        .expect("provision.sh never runs watch-env.sh");
    let account = lines
        .iter()
        .position(|l| l.contains("usermod -aG") && l.trim_end().ends_with(" propolis-watch"))
        .expect("provision.sh never sets the watch account's groups");
    assert!(account < derive);
    assert!(
        lines[derive].contains("DRY_RUN=\"$DRY_RUN\""),
        "dry runs must stay dry"
    );
    assert!(deploy_file("upgrade.sh").contains("/provision.sh\""));
}
