//! Exercises `deploy/config-check.sh` against fixture env directories with `systemctl`, `ss`, `ufw`,
//! `nft`, `firewall-cmd` and `psql` replaced by stubs on PATH, the way `deploy_test.rs` runs the
//! other deploy scripts without root.
//!
//! Every fixture is chosen so a wrong implementation answers differently from the right one: a
//! port held on a different address than the sensor's, a label that differs from the sensor's
//! reported name, a rule that sits in a forward chain rather than the input chain, a password with
//! a character that needs decoding. The all-green fixture is the control: each failure test
//! changes exactly one thing from it.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute, because the tests replace PATH and a bare name would be resolved against it.
const BASH: &str = "/usr/bin/bash";
const NOW: u64 = 1_800_000_000;
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/config-check.sh");
const FLEET_SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/fleet-listeners.sh"
);
const UPGRADE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/upgrade.sh");

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.out)
            .unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}): {}", self.out))
    }

    /// The status word (last column) of the table row whose first column is `label`.
    fn row_status(&self, label: &str) -> String {
        self.out
            .lines()
            .find(|l| l.split_whitespace().next() == Some(label))
            .unwrap_or_else(|| panic!("no row {label} in:\n{}", self.out))
            .split_whitespace()
            .last()
            .unwrap()
            .to_string()
    }

    fn has(&self, needle: &str) -> bool {
        self.out.contains(needle)
    }
}

fn listener<'a>(v: &'a serde_json::Value, sensor: &str, proto: &str) -> &'a serde_json::Value {
    v["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["sensor"] == sensor && l["protocol"] == proto)
        .unwrap_or_else(|| panic!("no listener {sensor}/{proto} in {v}"))
}

fn check<'a>(v: &'a serde_json::Value, sensor: &str, proto: &str, col: &str) -> &'a str {
    listener(v, sensor, proto)["checks"][col]["state"]
        .as_str()
        .unwrap()
}

fn finding_messages(v: &serde_json::Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} | {}",
                f["message"].as_str().unwrap(),
                f["fix"].as_str().unwrap()
            )
        })
        .collect()
}

fn install_bins() -> Vec<String> {
    let text = std::fs::read_to_string(UPGRADE).unwrap();
    text.lines()
        .find_map(|l| l.strip_prefix("INSTALL_BINS=("))
        .and_then(|r| r.strip_suffix(')'))
        .expect("upgrade.sh has no single-line INSTALL_BINS")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

struct Fx {
    root: tempfile::TempDir,
    head: String,
}

const UFW_ALL: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n1883/tcp                   ALLOW IN    Anywhere\n5432/tcp                   ALLOW IN    Anywhere\n69/udp                     ALLOW IN    Anywhere\n53                         ALLOW IN    Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";

impl Fx {
    fn p(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.p(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.p(rel)).unwrap()
    }

    fn exec(&self, rel: &str, body: &str) {
        self.write(rel, &format!("#!/bin/sh\n{body}"));
        std::fs::set_permissions(self.p(rel), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn touch(&self, rel: &str, epoch: u64) {
        let st = Command::new("touch")
            .arg("-d")
            .arg(format!("@{epoch}"))
            .arg(self.p(rel))
            .status()
            .unwrap();
        assert!(st.success());
    }

    fn unit(&self, name: &str, enabled: &str, active: &str) {
        self.write(&format!("state/enabled/{name}"), enabled);
        self.write(&format!("state/active/{name}"), active);
    }

    fn ss(&self, tcp: &[(&str, &str)], udp: &[(&str, &str)]) {
        let render = |state: &str, rows: &[(&str, &str)]| {
            rows.iter()
                .map(|(addr, owner)| {
                    if owner.is_empty() {
                        format!("{state} 0 128 {addr} 0.0.0.0:*\n")
                    } else {
                        format!(
                            "{state} 0 128 {addr} 0.0.0.0:* users:((\"{owner}\",pid=11,fd=3))\n"
                        )
                    }
                })
                .collect::<String>()
        };
        self.write("state/ss_tcp", &render("LISTEN", tcp));
        self.write("state/ss_udp", &render("UNCONN", udp));
    }

    fn log(&self, rel: &str, bytes: usize, mtime: u64) {
        self.write(rel, &"x".repeat(bytes));
        self.touch(rel, mtime);
    }

    /// Builds the all-green fixture: ssh/22, mqtt/1883, cred postgresql/5432, tftp/69 udp and dns
    /// 53 udp+tcp beside a systemd-resolved stub on 127.0.0.53, everything running as root.
    fn new() -> Fx {
        let root = tempfile::tempdir().unwrap();
        let fx = Fx {
            root,
            head: String::new(),
        };
        let logs = fx.p("logs").display().to_string();

        fx.write(
            "etc/ssh.env",
            &format!(
                "PROPOLIS_SSH_BIND=0.0.0.0:22\nPROPOLIS_SSH_LOG_PATH={logs}/ssh/events.jsonl\n"
            ),
        );
        fx.write(
            "etc/mqtt.env",
            &format!(
                "PROPOLIS_MQTT_BIND=0.0.0.0:1883\nPROPOLIS_MQTT_LOG_PATH={logs}/mqtt/events.jsonl\n"
            ),
        );
        fx.write(
            "etc/cred.env",
            &format!("PROPOLIS_CRED_PG_BIND=0.0.0.0:5432\nPROPOLIS_CRED_LOG_DIR={logs}/cred\n"),
        );
        fx.write(
            "etc/tftp.env",
            &format!(
                "PROPOLIS_TFTP_BIND=0.0.0.0:69\nPROPOLIS_TFTP_LOG_PATH={logs}/tftp/events.jsonl\n"
            ),
        );
        fx.write(
            "etc/dns.env",
            &format!(
                "PROPOLIS_DNS_BIND=203.0.113.7:53\nPROPOLIS_DNS_LOG_PATH={logs}/dns/events.jsonl\n"
            ),
        );
        let sensor_logs = format!(
            "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
        );
        fx.write(
            "etc/propolis.env",
            &format!("DATABASE_URL=postgres://propolis:s3cret%21pw@db.example.invalid:5433/propolis?sslmode=require\n{sensor_logs}\n"),
        );
        fx.write("etc/watch.env", &format!("{sensor_logs}\n"));
        for (dir, file) in [
            ("ssh", "events"),
            ("mqtt", "events"),
            ("dns", "events"),
            ("tftp", "events"),
            ("cred", "postgresql"),
        ] {
            fx.log(&format!("logs/{dir}/{file}.jsonl"), 200, NOW - 120);
        }

        for u in [
            "sensor-ssh",
            "sensor-mqtt",
            "sensor-cred",
            "sensor-tftp",
            "sensor-dns",
        ] {
            fx.unit(&format!("{u}.service"), "enabled", "active");
        }
        fx.unit("propolis-logrotate.timer", "enabled", "active");

        fx.ss(
            &[
                ("0.0.0.0:22", "sensor-ssh"),
                ("0.0.0.0:1883", "sensor-mqtt"),
                ("0.0.0.0:5432", "sensor-cred"),
                ("203.0.113.7:53", "sensor-dns"),
                ("127.0.0.53:53", "systemd-resolve"),
            ],
            &[
                ("0.0.0.0:69", "sensor-tftp"),
                ("203.0.113.7:53", "sensor-dns"),
                ("127.0.0.53:53", "systemd-resolve"),
            ],
        );
        fx.write("state/ufw", UFW_ALL);
        fx.write(
            "state/psql_out",
            "ssh|60\nmqtt|90\ntftp|100\ndns|30\npostgresql|200\n",
        );

        fx.write("state/logrotate.state", "x");
        fx.touch("state/logrotate.state", NOW - 600);
        fx.write(
            "etc-logrotate/propolis-sensors",
            "/var/log/propolis/ssh/events.jsonl\n{\n    size 100M\n    rotate 5\n}\n",
        );
        fx.exec("sbin/propolis-logrotate-guard", "exit 0\n");

        std::fs::create_dir_all(fx.p("bin")).unwrap();
        for b in install_bins() {
            fx.exec(&format!("bin/{b}"), "exit 0\n");
        }
        std::fs::create_dir_all(fx.p("build")).unwrap();

        // A real repository, so the deploy stamp can be compared with the checkout's HEAD.
        std::fs::create_dir_all(fx.p("repo")).unwrap();
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
        ] {
            let st = Command::new("git")
                .current_dir(fx.p("repo"))
                .args(&args)
                .status()
                .unwrap();
            assert!(st.success());
        }
        let head = String::from_utf8(
            Command::new("git")
                .current_dir(fx.p("repo"))
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let mut fx = fx;
        fx.head = head.clone();
        fx.write(
            "state/deploy-stamp.json",
            &format!("{{\"head_sha\": \"{head}\", \"origin_main_sha\": \"\", \"branch\": \"main\", \"pulled_at\": \"2027-01-01T00:00:00Z\", \"built_at\": \"2027-01-01T00:00:00Z\", \"installed\": {{\"propolis\": \"{}\", \"console\": \"\"}}}}\n",
                &head[..12]),
        );

        fx.write(
            "home-watch/.ssh/authorized_keys",
            "restrict ssh-ed25519 AAAAEXAMPLE watcher\n",
        );

        fx.install_stubs();
        fx.link_tools();
        fx
    }

    fn link_tools(&self) {
        std::fs::create_dir_all(self.p("tools")).unwrap();
        for t in [
            "grep", "sed", "stat", "cat", "cmp", "head", "tail", "mktemp", "date", "id", "dirname",
            "git", "timeout", "rm", "env", "sort", "cut",
        ] {
            let real = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| Path::new(d).join(t))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("no {t} on this host"));
            std::os::unix::fs::symlink(real, self.p(&format!("tools/{t}"))).unwrap();
        }
    }

    fn install_stubs(&self) {
        self.exec(
            "stubs/systemctl",
            r#"d="$STUB_STATE"
case "$1" in
  is-enabled) f="$d/enabled/$2"; if [ -f "$f" ]; then cat "$f"; [ "$(cat "$f")" = enabled ]; exit $?; fi; echo not-found; exit 4 ;;
  is-active) f="$d/active/$2"; if [ -f "$f" ]; then cat "$f"; [ "$(cat "$f")" = active ]; exit $?; fi; echo inactive; exit 3 ;;
  is-failed) f="$d/failed/$2"; if [ -f "$f" ]; then cat "$f"; exit 0; fi; echo active; exit 1 ;;
esac
exit 1
"#,
        );
        self.exec(
            "stubs/ss",
            r#"d="$STUB_STATE"
[ -f "$d/ss_fail" ] && exit 1
case "$*" in *-lunp*) cat "$d/ss_udp" ;; *-ltnp*) cat "$d/ss_tcp" ;; *) exit 2 ;; esac
"#,
        );
        self.exec(
            "stubs/ufw",
            r#"if [ -f "$STUB_STATE/ufw" ]; then cat "$STUB_STATE/ufw"; exit 0; fi
echo "ERROR: You need to be root to run this script" >&2; exit 1
"#,
        );
        self.exec(
            "stubs/psql",
            r#"d="$STUB_STATE"
{ echo "ARGV: $*"; env | grep '^PG' | sort; } > "$d/psql.log"
[ -f "$d/psql_rc" ] && exit "$(cat "$d/psql_rc")"
cat "$d/psql_out"
"#,
        );
    }

    fn remove_stub(&self, name: &str) {
        std::fs::remove_file(self.p(&format!("stubs/{name}"))).unwrap();
    }

    fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        let mut cmd = Command::new(BASH);
        cmd.arg(SCRIPT)
            .args(args)
            .arg("--env-dir")
            .arg(self.p("etc"));
        cmd.env_clear()
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.p("stubs").display(),
                    self.p("tools").display()
                ),
            )
            .env("STUB_STATE", self.p("state"))
            .env("PROPOLIS_CC_NOW", NOW.to_string())
            .env("PROPOLIS_CC_EUID", "0")
            .env("PROPOLIS_CC_BIN_DIR", self.p("bin"))
            .env("PROPOLIS_CC_BUILD_DIR", self.p("build"))
            .env("PROPOLIS_CC_REPO_DIR", self.p("repo"))
            .env("PROPOLIS_CC_STAMP", self.p("state/deploy-stamp.json"))
            .env(
                "PROPOLIS_CC_LOGROTATE_STATE",
                self.p("state/logrotate.state"),
            )
            .env(
                "PROPOLIS_CC_LOGROTATE_POLICY",
                self.p("etc-logrotate/propolis-sensors"),
            )
            .env(
                "PROPOLIS_CC_LOGROTATE_GUARD",
                self.p("sbin/propolis-logrotate-guard"),
            )
            .env("PROPOLIS_CC_WATCH_HOME", self.p("home-watch"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run deploy/config-check.sh");
        // A debugging aid: CC_SHOW_OUTPUT=1 cargo test ... -- --nocapture --test-threads=1
        if std::env::var_os("CC_SHOW_OUTPUT").is_some() {
            eprintln!(
                "---- {args:?} exit {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout)
            );
        }
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, &[])
    }

    fn json(&self) -> serde_json::Value {
        self.run(&["--json"]).json()
    }

    /// Replaces the one line of propolis.env that starts with `prefix`.
    fn set_env_line(&self, file: &str, prefix: &str, replacement: Option<&str>) {
        let text = self.read(file);
        let mut lines: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with(prefix))
            .map(str::to_string)
            .collect();
        if let Some(r) = replacement {
            lines.push(r.to_string());
        }
        self.write(file, &(lines.join("\n") + "\n"));
    }

    fn logs(&self) -> String {
        self.p("logs").display().to_string()
    }
}

fn is_root() -> bool {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---- the control ---------------------------------------------------------------------------

#[test]
fn an_all_green_host_reports_every_listener_ok_and_exits_zero() {
    let fx = Fx::new();
    let r = fx.run(&[]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.out, r.err);
    for label in [
        "ssh/tcp",
        "mqtt/tcp",
        "postgresql/tcp",
        "tftp/udp",
        "dns/udp",
        "dns/tcp",
    ] {
        assert_eq!(r.row_status(label), "ok", "{label}:\n{}", r.out);
    }
    assert!(
        r.has("SUMMARY: 0 failure(s), 0 warning(s), 0 unknown check(s): ok"),
        "{}",
        r.out
    );
    assert!(!r.has("FINDINGS"), "{}", r.out);
    assert!(!r.has("LIMITED CHECKS"), "{}", r.out);
    let v = fx.json();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["listeners"].as_array().unwrap().len(), 6);
    assert_eq!(v["firewall"]["kind"], "ufw");
    for l in v["listeners"].as_array().unwrap() {
        for col in ["unit", "listen", "firewall", "log", "intake", "events"] {
            assert_eq!(
                l["checks"][col]["state"], "ok",
                "{} {col}: {l}",
                l["sensor"]
            );
        }
    }
}

#[test]
fn it_writes_nothing_outside_its_own_temp_directory() {
    let fx = Fx::new();
    let snapshot = |fx: &Fx| -> BTreeMap<PathBuf, (u64, u64)> {
        let mut m = BTreeMap::new();
        let mut stack = vec![fx.p("")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    stack.push(p);
                } else if !p.starts_with(fx.p("state/psql.log")) {
                    m.insert(
                        p,
                        (
                            md.len(),
                            md.modified()
                                .unwrap()
                                .elapsed()
                                .map(|d| d.as_secs())
                                .unwrap_or(0)
                                / 3600,
                        ),
                    );
                }
            }
        }
        m
    };
    let before = snapshot(&fx);
    let _ = fx.run(&[]);
    let _ = fx.run(&["--json"]);
    assert_eq!(
        before,
        snapshot(&fx),
        "the check changed files in the fixture"
    );
}

// ---- PROPOLIS_SENSOR_LOGS ------------------------------------------------------------------

#[test]
fn a_log_missing_from_the_list_is_named_with_the_exact_entry_to_add() {
    let fx = Fx::new();
    let logs = fx.logs();
    let line = format!(
        "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
    );
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", Some(&line));
    let r = fx.run(&[]);
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.row_status("mqtt/tcp"), "FAIL");
    for ok in ["ssh/tcp", "dns/udp", "tftp/udp", "postgresql/tcp"] {
        assert_eq!(
            r.row_status(ok),
            "ok",
            "{ok} must be unaffected:\n{}",
            r.out
        );
    }
    let v = fx.json();
    assert_eq!(check(&v, "mqtt", "tcp", "intake"), "fail");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains(&format!(
            "append ,mqtt:{logs}/mqtt/events.jsonl to PROPOLIS_SENSOR_LOGS"
        )),
        "{msgs}"
    );
}

#[test]
fn a_typo_in_a_log_path_is_reported_against_the_label_and_the_path_the_sensor_writes() {
    let fx = Fx::new();
    let logs = fx.logs();
    let text = fx.read("etc/propolis.env").replace(
        &format!("mqtt:{logs}/mqtt/events.jsonl"),
        &format!("mqtt:{logs}/mqtt/event.jsonl"),
    );
    fx.write("etc/propolis.env", &text);
    let v = fx.json();
    assert_eq!(check(&v, "mqtt", "tcp", "intake"), "fail");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains(&format!(
            "names 'mqtt:{logs}/mqtt/event.jsonl' but mqtt writes {logs}/mqtt/events.jsonl"
        )),
        "{msgs}"
    );
    assert!(
        msgs.contains(&format!("set the entry to mqtt:{logs}/mqtt/events.jsonl")),
        "{msgs}"
    );
    // The typo'd path is also an entry that matches no sensor.
    assert!(
        msgs.contains("matches no configured sensor's log path"),
        "{msgs}"
    );
    assert_eq!(fx.run(&[]).code, 2);
}

#[test]
fn a_wrong_separator_is_a_malformed_entry_the_daemon_would_refuse_with_a_suggested_fix() {
    let fx = Fx::new();
    let logs = fx.logs();
    let text = fx.read("etc/propolis.env").replace(
        &format!("ssh:{logs}/ssh/events.jsonl"),
        &format!("ssh;{logs}/ssh/events.jsonl"),
    );
    fx.write("etc/propolis.env", &text);
    let v = fx.json();
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains(&format!(
            "entry 'ssh;{logs}/ssh/events.jsonl' is malformed (no ':' separator"
        )),
        "{msgs}"
    );
    assert!(
        msgs.contains(&format!("change it to ssh:{logs}/ssh/events.jsonl")),
        "{msgs}"
    );
    assert!(msgs.contains("the daemon refuses to start"), "{msgs}");
    assert_eq!(fx.run(&[]).code, 2);
}

#[test]
fn a_label_with_no_path_and_a_path_with_no_label_are_both_malformed_and_each_is_suggested_a_repair()
{
    let fx = Fx::new();
    let logs = fx.logs();
    let text = fx.read("etc/propolis.env").replace(
        &format!("ssh:{logs}/ssh/events.jsonl"),
        &format!("ssh:, :{logs}/mqtt/events.jsonl"),
    );
    fx.write("etc/propolis.env", &text);
    let v = fx.json();
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("entry 'ssh:' is malformed (label with no path"),
        "{msgs}"
    );
    assert!(
        msgs.contains(&format!(
            "entry ':{logs}/mqtt/events.jsonl' is malformed (empty label"
        )),
        "{msgs}"
    );
    assert!(
        msgs.contains(&format!("change it to ssh:{logs}/ssh/events.jsonl")),
        "{msgs}"
    );
    assert!(
        msgs.contains(&format!("change it to mqtt:{logs}/mqtt/events.jsonl")),
        "{msgs}"
    );
}

#[test]
fn the_daemons_splitting_rules_are_followed_first_colon_trim_and_blank_entries() {
    let fx = Fx::new();
    let logs = fx.logs();
    // A path that itself holds a colon is legal, blank entries and padding are ignored, and none of
    // that may raise a malformed-entry finding.
    fx.log("logs/odd:name/events.jsonl", 10, NOW - 10);
    let text = fx.read("etc/propolis.env").replace(
        &format!("ssh:{logs}/ssh/events.jsonl"),
        &format!(" ssh:{logs}/ssh/events.jsonl , ,, extra:{logs}/odd:name/events.jsonl ,"),
    );
    fx.write("etc/propolis.env", &text);
    let v = fx.json();
    let msgs = finding_messages(&v).join("\n");
    assert!(!msgs.contains("malformed"), "{msgs}");
    assert_eq!(check(&v, "ssh", "tcp", "intake"), "ok");
}

#[test]
fn a_duplicate_label_is_a_failure_and_a_duplicate_path_is_a_warning() {
    let fx = Fx::new();
    let logs = fx.logs();
    fx.set_env_line(
        "etc/propolis.env",
        "PROPOLIS_SENSOR_LOGS=",
        Some(&format!(
            "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,mqtt:{logs}/dns/events.jsonl,dns2:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl,dns:{logs}/dns/events.jsonl"
        )),
    );
    let v = fx.json();
    let by_level: Vec<(String, String)> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["level"].as_str().unwrap().into(),
                f["message"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        by_level
            .iter()
            .any(|(l, m)| l == "fail" && m.contains("label 'mqtt' appears twice")),
        "{by_level:?}"
    );
    assert!(
        by_level.iter().any(|(l, m)| l == "warn"
            && m.contains(&format!("path {logs}/dns/events.jsonl is listed twice"))),
        "{by_level:?}"
    );
}

#[test]
fn a_misspelled_variable_name_or_a_space_before_the_equals_is_found() {
    let fx = Fx::new();
    let logs = fx.logs();
    let value = format!("ssh:{logs}/ssh/events.jsonl");
    for (bad, expect_unset) in [
        ("PROPOLIS_SENSOR_LOG", true),
        ("PROPOLIS_SENSORS_LOGS", true),
        ("SENSOR_LOGS", true),
        ("PROPOLIS_SENSOR_LOGS ", true),
    ] {
        let fx2 = Fx::new();
        fx2.set_env_line(
            "etc/propolis.env",
            "PROPOLIS_SENSOR_LOGS=",
            Some(&format!("{bad}={value}")),
        );
        let v = fx2.json();
        let msgs = finding_messages(&v).join("\n");
        assert!(
            msgs.contains(&format!(
                "sets '{bad}', which is not a variable anything reads"
            )),
            "{bad}: {msgs}"
        );
        assert!(
            msgs.contains("PROPOLIS_SENSOR_LOGS is not set") == expect_unset,
            "{bad}: {msgs}"
        );
        assert_eq!(fx2.run(&[]).code, 2, "{bad}");
    }
    // The control: the exact name raises no such finding.
    assert!(
        !finding_messages(&fx.json())
            .join("\n")
            .contains("not a variable anything reads")
    );
}

#[test]
fn an_entry_naming_a_directory_that_does_not_exist_is_a_failure() {
    let fx = Fx::new();
    let logs = fx.logs();
    let text = fx.read("etc/propolis.env") + "";
    let text = text.replace(
        "PROPOLIS_SENSOR_LOGS=",
        &format!("PROPOLIS_SENSOR_LOGS=typo:{logs}/nosuchdir/events.jsonl,"),
    );
    fx.write("etc/propolis.env", &text);
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("names a directory that does not exist"),
        "{msgs}"
    );
}

// ---- unit, listening, firewall -------------------------------------------------------------

#[test]
fn nothing_listening_is_reported_apart_from_a_port_held_by_someone_else() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:5432", "sensor-cred"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    assert_eq!(r.row_status("mqtt/tcp"), "FAIL");
    let v = fx.json();
    assert_eq!(check(&v, "mqtt", "tcp", "listen"), "fail");
    let text = listener(&v, "mqtt", "tcp")["checks"]["listen"]["text"]
        .as_str()
        .unwrap();
    assert_eq!(text, "nothing listening");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("nothing is listening on tcp/1883 although sensor-mqtt is active"),
        "{msgs}"
    );
    assert!(!msgs.contains("held by another process"), "{msgs}");
}

#[test]
fn a_port_held_by_another_process_that_the_firewall_exposes_is_the_dangerous_row() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "postgres"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    assert_eq!(r.row_status("postgresql/tcp"), "FAIL");
    assert_eq!(r.row_status("ssh/tcp"), "ok");
    let v = fx.json();
    assert_eq!(check(&v, "postgresql", "tcp", "listen"), "fail");
    assert_eq!(check(&v, "postgresql", "tcp", "firewall"), "fail");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("5432 is held by another process (postgres), not sensor-cred"),
        "{msgs}"
    );
    assert!(msgs.contains("DANGEROUS: tcp/5432 is open in the ufw firewall and bound by a process that is not sensor-cred (postgres)"), "{msgs}");
    assert!(
        msgs.contains("close it: sudo ufw delete allow 5432/tcp"),
        "{msgs}"
    );
    assert!(
        v["findings"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("DANGEROUS"),
        "the exposed service is read first: {msgs}"
    );
}

#[test]
fn the_same_foreign_holder_behind_a_closed_firewall_is_a_failure_but_not_dangerous() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "postgres"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    fx.write(
        "state/ufw",
        &UFW_ALL.replace("5432/tcp                   ALLOW IN    Anywhere\n", ""),
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("held by another process (postgres)"),
        "{msgs}"
    );
    assert!(!msgs.contains("DANGEROUS"), "{msgs}");
}

#[test]
fn a_foreign_holder_with_no_firewall_detected_warns_it_is_reachable() {
    let fx = Fx::new();
    fx.remove_stub("ufw");
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "postgres"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    let v = fx.json();
    assert_eq!(v["firewall"]["kind"], "none");
    assert!(
        v["firewall"]["note"]
            .as_str()
            .unwrap()
            .contains("no firewall tool found")
    );
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("no host firewall was detected and tcp/5432 is held by a non-sensor process"),
        "{msgs}"
    );
    assert!(!msgs.contains("DANGEROUS"), "{msgs}");
}

#[test]
fn a_local_resolver_on_another_address_is_not_a_conflict_with_the_sensor() {
    let fx = Fx::new();
    // Only the resolver's loopback stub is bound; the sensor's 203.0.113.7:53 is not. Matching on
    // the port alone would call this "held by another process".
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "sensor-cred"),
            ("127.0.0.53:53", "systemd-resolve"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("127.0.0.53:53", "systemd-resolve"),
        ],
    );
    let v = fx.json();
    for proto in ["udp", "tcp"] {
        assert_eq!(
            listener(&v, "dns", proto)["checks"]["listen"]["text"],
            "nothing listening",
            "{proto}"
        );
    }
    assert!(
        !finding_messages(&v)
            .join("\n")
            .contains("held by another process")
    );
}

#[test]
fn a_wildcard_resolver_does_conflict_with_a_specific_sensor_bind() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "sensor-cred"),
            ("0.0.0.0:53", "dnsmasq"),
        ],
        &[("0.0.0.0:69", "sensor-tftp"), ("0.0.0.0:53", "dnsmasq")],
    );
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("udp/53 is held by another process (dnsmasq)"),
        "{msgs}"
    );
}

#[test]
fn the_longest_sensor_name_is_shown_whole_by_ss_and_matches_exactly() {
    // comm is cut to 15 characters, and sensor-catchall is exactly 15.
    let fx = Fx::new();
    fx.write("etc/catchall.env", &format!("PROPOLIS_CATCHALL_BIND_ADDRS=0.0.0.0:1024\nPROPOLIS_CATCHALL_LOG_PATH={}/catchall/events.jsonl\n", fx.logs()));
    fx.unit("sensor-catchall.service", "enabled", "active");
    fx.log("logs/catchall/events.jsonl", 10, NOW - 5);
    let logs = fx.logs();
    let text = fx.read("etc/propolis.env").replace(
        "PROPOLIS_SENSOR_LOGS=",
        &format!("PROPOLIS_SENSOR_LOGS=catchall:{logs}/catchall/events.jsonl,"),
    );
    fx.write("etc/propolis.env", &text);
    fx.write(
        "state/ufw",
        &format!("{UFW_ALL}1024                       ALLOW IN    Anywhere\n"),
    );
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "sensor-cred"),
            ("203.0.113.7:53", "sensor-dns"),
            ("0.0.0.0:1024", "sensor-catchall"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
            ("0.0.0.0:1024", "sensor-catchall"),
        ],
    );
    let v = fx.json();
    assert_eq!(check(&v, "catchall", "tcp", "listen"), "ok");
    assert_eq!(check(&v, "catchall", "udp", "listen"), "ok");
}

#[test]
fn unit_states_are_told_apart_with_their_own_fix_lines() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("state/enabled/sensor-mqtt.service")).unwrap();
    std::fs::remove_file(fx.p("state/active/sensor-mqtt.service")).unwrap();
    fx.unit("sensor-ssh.service", "disabled", "inactive");
    fx.unit("sensor-tftp.service", "enabled", "failed");
    fx.unit("sensor-dns.service", "disabled", "active");
    let v = fx.json();
    assert_eq!(
        listener(&v, "mqtt", "tcp")["checks"]["unit"]["text"],
        "not installed"
    );
    assert_eq!(
        listener(&v, "ssh", "tcp")["checks"]["unit"]["text"],
        "not enabled (inactive)"
    );
    assert_eq!(
        listener(&v, "tftp", "udp")["checks"]["unit"]["text"],
        "failed"
    );
    assert_eq!(
        listener(&v, "dns", "udp")["checks"]["unit"]["text"],
        "active, not enabled"
    );
    assert_eq!(check(&v, "dns", "udp", "unit"), "warn");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("sensor-mqtt.service is not installed but mqtt/tcp is configured"),
        "{msgs}"
    );
    assert!(
        msgs.contains("sudo systemctl enable --now sensor-ssh.service"),
        "{msgs}"
    );
    assert!(
        msgs.contains(
            "sensor-tftp.service is enabled but failed | sudo journalctl -u sensor-tftp.service"
        ),
        "{msgs}"
    );
    assert!(
        msgs.contains("sudo systemctl enable sensor-dns.service"),
        "{msgs}"
    );
    // A dead unit with a free port is one finding (the unit), not also "nothing listening".
    assert!(!msgs.contains("nothing is listening on tcp/22"), "{msgs}");
}

#[test]
fn the_firewall_warns_when_it_blocks_a_port_the_sensor_serves() {
    let fx = Fx::new();
    fx.write(
        "state/ufw",
        &UFW_ALL
            .replace("22/tcp                     ALLOW IN    Anywhere\n", "")
            .replace("22/tcp (v6)                ALLOW IN    Anywhere (v6)\n", ""),
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 1, "{}", r.out);
    let v = fx.json();
    assert_eq!(check(&v, "ssh", "tcp", "firewall"), "warn");
    let msgs = finding_messages(&v).join("\n");
    assert!(msgs.contains("tcp/22 is served by sensor-ssh but the ufw firewall does not allow it, so nothing reaches this sensor | sudo ufw allow 22/tcp"), "{msgs}");
}

#[test]
fn a_udp_rule_does_not_open_the_same_tcp_port() {
    let fx = Fx::new();
    // 69/udp is allowed; a tcp/69 sensor would not be. 53 with no protocol covers both.
    let v = fx.json();
    assert_eq!(
        listener(&v, "tftp", "udp")["checks"]["firewall"]["text"],
        "open"
    );
    assert_eq!(
        listener(&v, "dns", "tcp")["checks"]["firewall"]["text"],
        "open"
    );
    fx.write("state/ufw", &UFW_ALL.replace("69/udp  ", "69/tcp  "));
    let v = fx.json();
    assert_eq!(check(&v, "tftp", "udp", "firewall"), "warn");
}

#[test]
fn ufw_out_rules_and_inactive_ufw_do_not_count_as_open() {
    let fx = Fx::new();
    fx.write(
        "state/ufw",
        &UFW_ALL
            .replace(
                "22/tcp                     ALLOW IN    Anywhere\n",
                "22/tcp                     ALLOW OUT   Anywhere\n",
            )
            .replace("22/tcp (v6)                ALLOW IN    Anywhere (v6)\n", ""),
    );
    assert_eq!(check(&fx.json(), "ssh", "tcp", "firewall"), "warn");
    fx.write("state/ufw", "Status: inactive\n");
    let v = fx.json();
    assert_eq!(v["firewall"]["kind"], "none");
    assert_eq!(
        listener(&v, "ssh", "tcp")["checks"]["firewall"]["text"],
        "none detected"
    );
}

#[test]
fn nftables_input_chain_rules_are_read_and_forward_chain_rules_are_not() {
    let fx = Fx::new();
    fx.remove_stub("ufw");
    let ruleset = |input_ports: &str, forward_ports: &str| {
        format!(
            "table inet filter {{\n\tchain input {{\n\t\ttype filter hook input priority filter; policy drop;\n\t\tiif \"lo\" accept\n\t\ttcp dport {{ {input_ports} }} accept\n\t\tudp dport 69 accept\n\t\tudp dport 53 accept\n\t\ttcp dport 53 accept\n\t}}\n\tchain forward {{\n\t\ttype filter hook forward priority filter; policy drop;\n\t\ttcp dport {{ {forward_ports} }} accept\n\t}}\n}}\n"
        )
    };
    fx.exec("stubs/nft", "[ -f \"$STUB_STATE/nft\" ] && cat \"$STUB_STATE/nft\" && exit 0\necho 'Operation not permitted' >&2; exit 1\n");
    fx.write("state/nft", &ruleset("22, 1883, 5432", "9999"));
    let v = fx.json();
    assert_eq!(v["firewall"]["kind"], "nftables");
    assert_eq!(fx.run(&[]).code, 0, "{}", fx.run(&[]).out);
    // 22 only in the forward chain: not open to the host.
    fx.write("state/nft", &ruleset("1883, 5432", "22"));
    assert_eq!(check(&fx.json(), "ssh", "tcp", "firewall"), "warn");
    // A range.
    fx.write("state/nft", &ruleset("20-30, 1883, 5432", "9999"));
    assert_eq!(check(&fx.json(), "ssh", "tcp", "firewall"), "ok");
}

#[test]
fn firewalld_ports_and_services_are_read_from_the_active_zones() {
    let fx = Fx::new();
    fx.remove_stub("ufw");
    fx.exec(
        "stubs/firewall-cmd",
        r#"d="$STUB_STATE"
case "$*" in
  "--state") echo running ;;
  "--get-active-zones") printf 'public\n  interfaces: eth0\n' ;;
  "--zone=public --list-all") printf 'public (active)\n  target: default\n  ports: 1883/tcp 5432/tcp 69/udp\n  services: ssh dns\n  rich rules:\n' ;;
  "--permanent --service=ssh --get-ports") echo 22/tcp ;;
  "--permanent --service=dns --get-ports") echo "53/tcp 53/udp" ;;
  *) exit 1 ;;
esac
"#,
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert_eq!(fx.json()["firewall"]["kind"], "firewalld");
    // Dropping the ssh service closes port 22 in the zone.
    fx.exec(
        "stubs/firewall-cmd",
        r#"case "$*" in
  "--state") echo running ;;
  "--get-active-zones") printf 'public\n  interfaces: eth0\n' ;;
  "--zone=public --list-all") printf 'public (active)\n  ports: 1883/tcp 5432/tcp 69/udp\n  services: dns\n' ;;
  "--permanent --service=dns --get-ports") echo "53/tcp 53/udp" ;;
  *) exit 1 ;;
esac
"#,
    );
    let v = fx.json();
    assert_eq!(check(&v, "ssh", "tcp", "firewall"), "warn");
    assert!(
        finding_messages(&v).join("\n").contains(
            "sudo firewall-cmd --permanent --add-port=22/tcp && sudo firewall-cmd --reload"
        )
    );
}

// ---- logs ----------------------------------------------------------------------------------

#[test]
fn log_size_is_judged_against_the_logrotate_size_with_the_alerts_thresholds() {
    let fx = Fx::new();
    fx.write(
        "etc-logrotate/propolis-sensors",
        "/x\n{\n    size 1k\n    rotate 5\n}\n",
    );
    let ssh = "logs/ssh/events.jsonl";
    fx.log(ssh, 1500, NOW - 60);
    assert_eq!(
        check(&fx.json(), "ssh", "tcp", "log"),
        "ok",
        "1.5x the size is within one hourly rotation interval"
    );
    fx.log(ssh, 2500, NOW - 60);
    assert_eq!(check(&fx.json(), "ssh", "tcp", "log"), "warn");
    assert_eq!(fx.run(&[]).code, 1);
    fx.log(ssh, 3500, NOW - 60);
    let v = fx.json();
    assert_eq!(check(&v, "ssh", "tcp", "log"), "fail");
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("more than 3x the rotation size (1K)")
    );
    assert_eq!(fx.run(&[]).code, 2);
}

#[test]
fn the_rotation_size_falls_back_to_the_default_and_says_so() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("etc-logrotate/propolis-sensors")).unwrap();
    let v = fx.json();
    let g = v["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == "logrotate")
        .unwrap();
    assert_eq!(g["state"], "fail");
    assert!(
        g["text"]
            .as_str()
            .unwrap()
            .contains("assumed 104857600 (policy not readable)")
    );
}

#[test]
fn a_quiet_log_on_a_running_sensor_is_a_warning_and_a_missing_one_is_too() {
    let fx = Fx::new();
    fx.touch("logs/ssh/events.jsonl", NOW - 3 * 86400);
    let v = fx.json();
    assert_eq!(check(&v, "ssh", "tcp", "log"), "warn");
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("has not been written for 3d although sensor-ssh is bound and running")
    );
    let fx = Fx::new();
    std::fs::remove_file(fx.p("logs/mqtt/events.jsonl")).unwrap();
    let v = fx.json();
    assert_eq!(
        listener(&v, "mqtt", "tcp")["checks"]["log"]["text"],
        "missing"
    );
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("does not exist although sensor-mqtt is running and bound")
    );
}

#[test]
fn the_cred_log_is_the_per_protocol_file_and_the_label_differs_from_the_reported_name() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("logs/cred/postgresql.jsonl")).unwrap();
    // The file named after the intake label is NOT the sensor's log.
    fx.log("logs/cred/cred-pg.jsonl", 10, NOW - 5);
    let v = fx.json();
    assert_eq!(
        listener(&v, "postgresql", "tcp")["checks"]["log"]["text"],
        "missing"
    );
    assert_eq!(check(&v, "postgresql", "tcp", "intake"), "ok");
}

#[test]
fn the_catchall_relative_default_log_is_flagged() {
    let fx = Fx::new();
    fx.write(
        "etc/catchall.env",
        "PROPOLIS_CATCHALL_BIND_ADDRS=0.0.0.0:1024\n",
    );
    fx.unit("sensor-catchall.service", "enabled", "active");
    let v = fx.json();
    assert_eq!(
        listener(&v, "catchall", "tcp")["checks"]["log"]["text"],
        "relative default"
    );
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("add PROPOLIS_CATCHALL_LOG_PATH=/var/log/propolis/catchall/events.jsonl")
    );
}

// ---- host-wide -----------------------------------------------------------------------------

#[test]
fn a_dead_logrotate_timer_and_a_stale_state_file_are_failures_with_their_fixes() {
    let fx = Fx::new();
    fx.unit("propolis-logrotate.timer", "enabled", "inactive");
    let v = fx.json();
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("propolis-logrotate.timer is inactive"),
        "{msgs}"
    );
    assert!(
        msgs.contains("sudo systemctl enable --now propolis-logrotate.timer"),
        "{msgs}"
    );
    assert_eq!(fx.run(&[]).code, 2);

    let fx = Fx::new();
    fx.touch("state/logrotate.state", NOW - 2 * 3600);
    assert_eq!(
        fx.run(&[]).code,
        0,
        "two hours is inside the three-hour alert window"
    );
    fx.touch("state/logrotate.state", NOW - 4 * 3600);
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    assert!(
        finding_messages(&fx.json())
            .join("\n")
            .contains("logrotate has not run for 4h")
    );
}

#[test]
fn a_failed_rotation_service_and_a_missing_guard_are_reported() {
    let fx = Fx::new();
    fx.write("state/failed/propolis-logrotate.service", "failed");
    let v = fx.json();
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("propolis-logrotate.service last exited non-zero")
    );
    assert_eq!(fx.run(&[]).code, 1);
    std::fs::remove_file(fx.p("sbin/propolis-logrotate-guard")).unwrap();
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(msgs.contains("propolis-logrotate-guard is not installed or not executable: every rotation fails closed"), "{msgs}");
}

#[test]
fn a_missing_binary_fails_and_role_specific_binaries_are_exempt_without_their_unit() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("bin/gateway")).unwrap();
    std::fs::remove_file(fx.p("bin/shipper")).unwrap();
    assert_eq!(
        fx.run(&[]).code,
        0,
        "no gateway or shipper unit installed: not expected here"
    );
    fx.unit("shipper.service", "enabled", "active");
    let v = fx.json();
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("binaries missing from"),
        "shipper is enabled but missing"
    );
    let fx = Fx::new();
    std::fs::remove_file(fx.p("bin/sensor-mqtt")).unwrap();
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("binaries missing from") && msgs.contains("sensor-mqtt"),
        "{msgs}"
    );
    assert_eq!(fx.run(&[]).code, 2);
}

#[test]
fn an_installed_binary_that_differs_from_the_build_warns() {
    let fx = Fx::new();
    fx.write("build/sensor-ssh", "new build");
    fx.write("build/sensor-mqtt", &fx.read("bin/sensor-mqtt"));
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("installed binaries differ from the build") && msgs.contains("sensor-ssh"),
        "{msgs}"
    );
    assert!(
        !msgs.contains("sensor-mqtt (built"),
        "an identical build is not a difference: {msgs}"
    );
    assert_eq!(fx.run(&[]).code, 1);
}

#[test]
fn the_deploy_stamp_must_match_the_installed_binary_and_the_checkout() {
    let fx = Fx::new();
    let head = fx.head.clone();
    let stamp = fx.read("state/deploy-stamp.json").replace(
        &format!("\"propolis\": \"{}\"", &head[..12]),
        "\"propolis\": \"deadbeef0000\"",
    );
    fx.write("state/deploy-stamp.json", &stamp);
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    assert!(
        finding_messages(&fx.json())
            .join("\n")
            .contains("the installed propolis binary reports deadbeef0000"),
        "{}",
        r.out
    );

    let fx = Fx::new();
    let st = Command::new("git")
        .current_dir(fx.p("repo"))
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "y",
        ])
        .status()
        .unwrap();
    assert!(st.success());
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("the checkout is at") && msgs.contains("but the last deploy was"),
        "{msgs}"
    );
    assert_eq!(fx.run(&[]).code, 1);

    let fx = Fx::new();
    std::fs::remove_file(fx.p("state/deploy-stamp.json")).unwrap();
    assert!(
        finding_messages(&fx.json())
            .join("\n")
            .contains("deploy-stamp.json not found")
    );
}

#[test]
fn the_watcher_is_checked_only_where_installed_and_drift_from_propolis_env_fails() {
    let fx = Fx::new();
    fx.write("etc/watch.env", "PROPOLIS_SENSOR_LOGS=ssh:/old/path\n");
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("differs from PROPOLIS_SENSOR_LOGS in propolis.env"),
        "{msgs}"
    );
    assert!(msgs.contains("watch-env.sh"), "{msgs}");
    assert_eq!(fx.run(&[]).code, 2);

    let fx = Fx::new();
    std::fs::remove_file(fx.p("home-watch/.ssh/authorized_keys")).unwrap();
    let r = fx.run(&[]);
    assert_eq!(r.code, 1);
    assert!(
        finding_messages(&fx.json())
            .join("\n")
            .contains("does not exist: nobody can start the watcher"),
        "{}",
        r.out
    );

    let fx = Fx::new();
    std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
    assert!(
        finding_messages(&fx.json())
            .join("\n")
            .contains("watch.env does not exist")
    );

    let fx = Fx::new();
    std::fs::remove_file(fx.p("bin/propolis-watch")).unwrap();
    std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
    // No binary, but the system account may still exist on this host: only assert it is not an error
    // by the file alone when the account is absent.
    let v = fx.json();
    let w = v["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == "watcher")
        .unwrap();
    assert!(w["state"] == "skip" || w["state"] == "fail", "{w}");
}

#[test]
fn an_enabled_sensor_unit_with_no_bind_is_a_failure_that_names_the_cause() {
    let fx = Fx::new();
    fx.unit("sensor-redis.service", "enabled", "active");
    fx.write("etc/redis.env", "PROPOLIS_REDIS_BNID=0.0.0.0:6379\n");
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(
        msgs.contains("sensor-redis.service is enabled or running but no bind variable is set"),
        "{msgs}"
    );
    // A disabled, inactive unit with no bind is simply not in use.
    let fx = Fx::new();
    fx.unit("sensor-redis.service", "disabled", "inactive");
    assert_eq!(fx.run(&[]).code, 0);
}

#[test]
fn a_bind_with_no_usable_port_is_a_failure_not_a_dropped_row() {
    let fx = Fx::new();
    fx.write("etc/telnet.env", "PROPOLIS_TELNET_BIND=0.0.0.0:99999\n");
    let v = fx.json();
    let t = listener(&v, "telnet", "tcp");
    assert!(t["port"].is_null());
    assert_eq!(t["status"], "fail");
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("PROPOLIS_TELNET_BIND=0.0.0.0:99999 has no usable port")
    );
}

// ---- events --------------------------------------------------------------------------------

#[test]
fn events_are_keyed_by_the_sensors_reported_name_and_age_is_judged() {
    let fx = Fx::new();
    // 'cred-pg' is the intake label, not the name the sensor reports; only 'postgresql' counts.
    fx.write(
        "state/psql_out",
        "ssh|60\nmqtt|90\ntftp|100\ndns|30\ncred-pg|5\n",
    );
    let v = fx.json();
    assert_eq!(check(&v, "postgresql", "tcp", "events"), "warn");
    assert_eq!(
        listener(&v, "postgresql", "tcp")["checks"]["events"]["text"],
        "none in 7d"
    );
    fx.write(
        "state/psql_out",
        "ssh|60\nmqtt|90000\ntftp|100\ndns|30\npostgresql|200\n",
    );
    let v = fx.json();
    assert_eq!(
        listener(&v, "mqtt", "tcp")["checks"]["events"]["text"],
        "25h ago"
    );
    assert_eq!(check(&v, "mqtt", "tcp", "events"), "warn");
    assert_eq!(
        listener(&v, "ssh", "tcp")["checks"]["events"]["text"],
        "60s ago"
    );
}

#[test]
fn the_database_password_never_reaches_a_command_line_or_the_report() {
    let fx = Fx::new();
    let r = fx.run(&[]);
    let log = fx.read("state/psql.log");
    let argv = log.lines().find(|l| l.starts_with("ARGV:")).unwrap();
    assert!(
        !argv.contains("s3cret") && !argv.contains("postgres://"),
        "{argv}"
    );
    assert!(argv.contains("SELECT sensor"), "{argv}");
    for expect in [
        "PGPASSWORD=s3cret!pw",
        "PGHOST=db.example.invalid",
        "PGPORT=5433",
        "PGUSER=propolis",
        "PGDATABASE=propolis",
        "PGSSLMODE=require",
    ] {
        assert!(
            log.lines().any(|l| l == expect),
            "{expect} missing from:\n{log}"
        );
    }
    let opts = log.lines().find(|l| l.starts_with("PGOPTIONS=")).unwrap();
    assert!(
        opts.contains("default_transaction_read_only=on") && opts.contains("statement_timeout="),
        "{opts}"
    );
    assert!(!r.out.contains("s3cret") && !r.err.contains("s3cret"));
    assert!(!fx.run(&["--json"]).out.contains("s3cret"));
}

#[test]
fn the_ledger_query_is_skipped_cleanly_without_access_or_when_it_fails() {
    // No DATABASE_URL.
    let fx = Fx::new();
    fx.set_env_line("etc/propolis.env", "DATABASE_URL=", None);
    let r = fx.run(&[]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.has("events: skipped (no DATABASE_URL in"), "{}", r.out);
    assert!(
        !r.has("LIMITED CHECKS"),
        "an unconfigured database is not a limit: {}",
        r.out
    );
    assert_eq!(check(&fx.json(), "ssh", "tcp", "events"), "skip");
    // --no-events.
    let fx = Fx::new();
    let r = fx.run(&["--no-events"]);
    assert_eq!(r.code, 0);
    assert!(r.has("events: skipped (disabled by --no-events)"));
    assert!(
        !fx.p("state/psql.log").exists(),
        "psql must not run under --no-events"
    );
    // The query fails (unreachable database, or the timeout).
    let fx = Fx::new();
    fx.write("state/psql_rc", "2");
    let r = fx.run(&[]);
    assert_eq!(
        r.code, 0,
        "an optional check that could not run does not change the verdict: {}",
        r.out
    );
    assert!(
        r.has("ledger query skipped: the database could not be queried"),
        "{}",
        r.out
    );
    assert!(
        r.has("events: skipped (ledger query failed or timed out)"),
        "{}",
        r.out
    );
}

// ---- no root, tools missing ----------------------------------------------------------------

#[test]
fn without_root_a_socket_whose_owner_is_hidden_is_unknown_never_a_pass_or_a_failure() {
    let fx = Fx::new();
    // ss run as a non-root user lists the sockets but not other users' processes.
    fx.ss(
        &[
            ("0.0.0.0:22", ""),
            ("0.0.0.0:1883", ""),
            ("0.0.0.0:5432", ""),
            ("203.0.113.7:53", ""),
            ("127.0.0.53:53", ""),
        ],
        &[
            ("0.0.0.0:69", ""),
            ("203.0.113.7:53", ""),
            ("127.0.0.53:53", ""),
        ],
    );
    let r = fx.run_with(&[], &[("PROPOLIS_CC_EUID", "1000")]);
    let rj = fx.run_with(&["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    assert_eq!(
        r.code, 1,
        "unknown is a warning, not a pass and not a failure:\n{}",
        r.out
    );
    assert!(r.has("bound, owner unknown"), "{}", r.out);
    assert!(r.out.contains("not root:"), "{}", r.out);
    assert!(r.out.contains("socket owners hidden"), "{}", r.out);
    assert!(!r.has("FAIL"), "{}", r.out);
    let v = rj.json();
    assert_eq!(v["root"], false);
    for l in v["listeners"].as_array().unwrap() {
        assert_eq!(l["checks"]["listen"]["state"], "unknown", "{l}");
        assert_eq!(l["checks"]["listen"]["text"], "bound, owner unknown", "{l}");
        assert_ne!(l["status"], "ok", "{l}");
    }
}

#[test]
fn without_root_a_bound_port_on_a_stopped_sensor_is_still_proved_foreign() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", ""),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    fx.unit("sensor-cred.service", "enabled", "inactive");
    let r = fx.run_with(&["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    let v = r.json();
    assert_eq!(check(&v, "postgresql", "tcp", "listen"), "fail");
    let msgs = finding_messages(&v).join("\n");
    assert!(
        msgs.contains("is bound by a process that is not sensor-cred (sensor-cred is not running)"),
        "{msgs}"
    );
    assert!(msgs.contains("DANGEROUS"), "firewall-open too: {msgs}");
    assert_eq!(r.code, 2);
}

#[test]
fn unreadable_env_files_are_a_limit_not_an_empty_inventory() {
    if is_root() {
        return; // chmod 000 does not stop root
    }
    let fx = Fx::new();
    std::fs::set_permissions(fx.p("etc/cred.env"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = fx.run_with(&[], &[("PROPOLIS_CC_EUID", "1000")]);
    assert!(
        r.has("env files not readable as this user (1 of 7)"),
        "{}",
        r.out
    );
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        !r.has("FAIL"),
        "an unreadable file must not be read as a missing bind: {}",
        r.out
    );
    let v = fx
        .run_with(&["--json"], &[("PROPOLIS_CC_EUID", "1000")])
        .json();
    assert!(
        v["listeners"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["sensor"] != "postgresql")
    );
    let envg = v["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == "env-files")
        .unwrap();
    assert_eq!(envg["state"], "unknown");
    std::fs::set_permissions(
        fx.p("etc/propolis.env"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let r = fx.run_with(&["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    let v = r.json();
    // PROPOLIS_SENSOR_LOGS unreadable: every intake cell is unknown rather than "absent".
    assert_eq!(check(&v, "ssh", "tcp", "intake"), "unknown");
    assert!(v["limited"].as_array().unwrap().iter().any(|l| {
        l.as_str()
            .unwrap()
            .contains("propolis.env / shipper.env not readable")
    }));
    std::fs::set_permissions(fx.p("etc/cred.env"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(
        fx.p("etc/propolis.env"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

#[test]
fn missing_tools_make_their_checks_unknown_and_never_crash_the_report() {
    let fx = Fx::new();
    for stub in ["systemctl", "ss", "ufw", "psql"] {
        fx.remove_stub(stub);
    }
    let r = fx.run(&[]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(r.err.is_empty(), "no stderr noise: {}", r.err);
    assert!(r.has("SUMMARY:") && r.has("LIMITED CHECKS"), "{}", r.out);
    assert!(r.has("systemctl not found"), "{}", r.out);
    assert!(r.has("ss unavailable or failed"), "{}", r.out);
    assert!(
        r.has("ledger query skipped: psql not installed"),
        "{}",
        r.out
    );
    let v = fx.json();
    for l in v["listeners"].as_array().unwrap() {
        assert_eq!(l["checks"]["unit"]["state"], "unknown");
        assert_eq!(l["checks"]["listen"]["state"], "unknown");
        assert_eq!(l["checks"]["firewall"]["text"], "none detected");
        assert_eq!(l["checks"]["log"]["state"], "ok", "files need no tool: {l}");
    }
    assert!(!r.has("FAIL"), "{}", r.out);
}

#[test]
fn an_ss_that_fails_is_unknown_not_nothing_listening() {
    let fx = Fx::new();
    fx.write("state/ss_fail", "1");
    let v = fx.json();
    assert_eq!(check(&v, "ssh", "tcp", "listen"), "unknown");
    assert!(
        !finding_messages(&v)
            .join("\n")
            .contains("nothing is listening")
    );
}

#[test]
fn an_unreadable_firewall_is_unknown_but_a_readable_active_one_wins() {
    let fx = Fx::new();
    fx.remove_stub("ufw");
    fx.exec(
        "stubs/ufw",
        "echo 'ERROR: You need to be root to run this script' >&2; exit 1\n",
    );
    let v = fx.json();
    assert_eq!(v["firewall"]["kind"], "unknown");
    assert_eq!(check(&v, "ssh", "tcp", "firewall"), "unknown");
    assert!(v["limited"].as_array().unwrap().iter().any(|l| {
        l.as_str()
            .unwrap()
            .contains("firewall rules unreadable: ufw is installed")
    }));
}

// ---- output contracts ----------------------------------------------------------------------

#[test]
fn json_is_valid_for_hostile_values_and_carries_the_documented_fields() {
    let fx = Fx::new();
    let logs = fx.logs();
    // A quote, a backslash, a control character and non-ASCII in an env-supplied label.
    let hostile = "bad\"label\\x\u{1b}[31m\u{e9}";
    let text = fx.read("etc/propolis.env").replace(
        "PROPOLIS_SENSOR_LOGS=",
        &format!("PROPOLIS_SENSOR_LOGS={hostile}:{logs}/zzz/events.jsonl,"),
    );
    fx.write("etc/propolis.env", &text);
    let r = fx.run(&["--json"]);
    let v = r.json();
    for key in [
        "schema",
        "generated_at_epoch",
        "env_dir",
        "root",
        "status",
        "exit_code",
        "counts",
        "firewall",
        "limited",
        "listeners",
        "global",
        "findings",
    ] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    assert_eq!(v["schema"], 1);
    assert_eq!(v["generated_at_epoch"], NOW);
    assert!(
        !r.out.contains('\u{1b}'),
        "no escape byte may reach the output"
    );
    let table = fx.run(&[]);
    assert!(!table.out.contains('\u{1b}'));
    // And the same value, in text, is printed as plain ASCII.
    assert!(table.out.is_ascii(), "{}", table.out);
}

#[test]
fn exit_codes_are_zero_one_two_and_report_only_never_fails() {
    let fx = Fx::new();
    assert_eq!(fx.run(&[]).code, 0);
    fx.touch("logs/ssh/events.jsonl", NOW - 3 * 86400);
    assert_eq!(fx.run(&[]).code, 1);
    let v = fx.json();
    assert_eq!(v["status"], "warn");
    assert_eq!(v["exit_code"], 1);
    fx.unit("propolis-logrotate.timer", "enabled", "inactive");
    assert_eq!(fx.run(&[]).code, 2);
    assert_eq!(fx.json()["status"], "fail");
    let r = fx.run(&["--report-only"]);
    assert_eq!(r.code, 0, "--report-only must not fail the caller");
    assert!(r.has("SUMMARY: 1 failure(s)"), "{}", r.out);
    let r = fx.run(&["--report-only", "--json"]);
    assert_eq!(r.code, 0);
    assert_eq!(
        r.json()["exit_code"],
        2,
        "the document still records the real verdict"
    );
}

#[test]
fn bad_usage_is_its_own_exit_status_and_help_succeeds() {
    let fx = Fx::new();
    let st = |args: &[&str]| {
        Command::new(BASH)
            .arg(SCRIPT)
            .args(args)
            .env(
                "PATH",
                format!("{}:{}", fx.p("stubs").display(), fx.p("tools").display()),
            )
            .output()
            .unwrap()
    };
    let o = st(&["--frobnicate"]);
    assert_eq!(o.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown argument: --frobnicate"));
    assert_eq!(st(&["--env-dir"]).status.code(), Some(64));
    assert_eq!(st(&["--help"]).status.code(), Some(0));
}

// ---- one derivation, and the upgrade wiring ------------------------------------------------

#[test]
fn the_check_and_the_fleet_inventory_derive_the_same_listeners() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.env"),
        "PROPOLIS_SSH_BIND=0.0.0.0:22\nPROPOLIS_TELNET_BIND=\"0.0.0.0:23\"\nPROPOLIS_REDIS_BIND=0.0.0.0:6379\nPROPOLIS_REDIS_TLS_BIND=0.0.0.0:6380\nPROPOLIS_SMTP_BIND=0.0.0.0:25\nPROPOLIS_SMTP_SUBMISSION_BIND=0.0.0.0:587\nPROPOLIS_SMTP_TLS_BIND=0.0.0.0:465\nPROPOLIS_MQTT_BIND=0.0.0.0:1883\nPROPOLIS_CRED_VNC_BIND=0.0.0.0:5900\nPROPOLIS_CRED_MYSQL_BIND=0.0.0.0:3306\nPROPOLIS_CRED_MSSQL_BIND=0.0.0.0:1433\nPROPOLIS_CRED_PG_BIND=0.0.0.0:5432\nPROPOLIS_CRED_MONGO_BIND=0.0.0.0:27017\nPROPOLIS_TFTP_BIND=0.0.0.0:69\nPROPOLIS_DNS_BIND=203.0.113.7:53\nPROPOLIS_DNS_TLS_BIND=203.0.113.7:853\nPROPOLIS_ADB_BIND=0.0.0.0:5555\nPROPOLIS_HTTP_BIND=0.0.0.0:80\nPROPOLIS_HTTP_TLS_BIND=0.0.0.0:443\nPROPOLIS_FTP_BIND=0.0.0.0:21\nPROPOLIS_FTP_TLS_BIND=0.0.0.0:990\nCATCHALL_BIND_ADDRS=0.0.0.0:1024, [::]:8081 ,\n",
    )
    .unwrap();
    let out = dir.path().join("fleet.env");
    let st = Command::new("bash")
        .arg(FLEET_SCRIPT)
        .arg(dir.path())
        .arg(&out)
        .output()
        .unwrap();
    assert!(st.status.success());
    let fleet: std::collections::BTreeSet<String> = std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("PROPOLIS_FLEET_LISTENERS="))
        .unwrap()
        .split(',')
        .map(|e| e.strip_prefix("local/").unwrap().to_string())
        .collect();

    let fx = Fx::new();
    let o = Command::new(BASH)
        .arg(SCRIPT)
        .args(["--json", "--no-events", "--env-dir"])
        .arg(dir.path())
        .env(
            "PATH",
            format!("{}:{}", fx.p("stubs").display(), fx.p("tools").display()),
        )
        .env("STUB_STATE", fx.p("state"))
        .env("PROPOLIS_CC_EUID", "0")
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let check_set: std::collections::BTreeSet<String> = v["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            format!(
                "{}/{}/{}",
                l["sensor"].as_str().unwrap(),
                l["protocol"].as_str().unwrap(),
                l["port"]
            )
        })
        .collect();
    assert_eq!(check_set, fleet);
    assert_eq!(fleet.len(), 26, "{fleet:?}");
}

#[test]
fn both_scripts_use_the_shared_derivation_and_neither_keeps_a_private_table() {
    for script in ["fleet-listeners.sh", "config-check.sh"] {
        let text = std::fs::read_to_string(format!(
            "{}/../../deploy/{script}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert!(
            text.contains("listeners-lib.sh"),
            "{script} does not source the shared derivation"
        );
        assert!(
            !text.contains("PROPOLIS_SSH_BIND:ssh"),
            "{script} carries its own copy of the bind table"
        );
    }
}

#[test]
fn upgrade_runs_the_check_last_in_report_only_mode_and_its_failure_cannot_fail_the_upgrade() {
    let text = std::fs::read_to_string(UPGRADE).unwrap();
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let last = *code.last().unwrap();
    assert!(
        last.contains("config-check.sh") && last.contains("--report-only") && last.contains("||"),
        "the last command of upgrade.sh must run the check in report-only mode and tolerate its failure: {last}"
    );
    let status_at = code
        .iter()
        .position(|l| l.contains("systemctl --no-pager status propolis.service"))
        .unwrap();
    let check_at = code
        .iter()
        .position(|l| l.contains("config-check.sh"))
        .unwrap();
    assert!(
        check_at > status_at,
        "the check must follow the restarts and the status line"
    );
    assert_eq!(
        code.iter()
            .filter(|l| l.contains("config-check.sh"))
            .count(),
        1
    );
}
