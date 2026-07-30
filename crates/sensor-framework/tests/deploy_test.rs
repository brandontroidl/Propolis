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
