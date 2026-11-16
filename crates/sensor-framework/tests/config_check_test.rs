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
/// The read-check binding of the fixture's target: the first 16 hex of
/// sha256("https://ntfy.example.invalid\npropolis-ops\n").
const FX_BINDING: &str = "d26d66e235545f4b";
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/config-check.sh");
const FLEET_SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/fleet-listeners.sh"
);
const UPGRADE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/upgrade.sh");
const ALERT_LIB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-lib.sh");
const LISTENERS_LIB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/listeners-lib.sh");

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

/// The account the test runs as, standing in for propolis-watch: it owns every fixture file.
fn current_user() -> String {
    let out = std::process::Command::new("id")
        .arg("-un")
        .output()
        .expect("run id -un");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

struct Fx {
    root: tempfile::TempDir,
    head: String,
    /// The account config-check treats as propolis-watch; the tests' own user unless a test
    /// names another.
    watch_account: std::cell::RefCell<String>,
}

const UFW_ALL: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n1883/tcp                   ALLOW IN    Anywhere\n5432/tcp                   ALLOW IN    Anywhere\n69/udp                     ALLOW IN    Anywhere\n53                         ALLOW IN    Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";

impl Fx {
    fn p(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    /// An env file is written 0600, the mode the operator gives every one in production, so the
    /// control stays green and a test that wants a looser mode sets it on purpose.
    fn write(&self, rel: &str, body: &str) {
        let path = self.p(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        if rel.starts_with("etc/") && rel.ends_with(".env") {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
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
            watch_account: std::cell::RefCell::new(current_user()),
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
            &format!("DATABASE_URL=postgres://propolis:s3cret%21pw@db.example.invalid:5433/propolis?sslmode=require\n{sensor_logs}\nPROPOLIS_OPS_ENABLED=true\nPROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\nPROPOLIS_OPS_HEARTBEAT_URL=https://hc.example.invalid/check\n"),
        );
        // A good encrypted backup an hour ago, the timer running, and the failure hook installed.
        let an_hour_ago = String::from_utf8(
            Command::new("date")
                .args([
                    "-u",
                    "-d",
                    &format!("@{}", NOW - 3600),
                    "+%Y-%m-%dT%H:%M:%SZ",
                ])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        fx.write(
            "state/backup-status/last-success",
            &format!(
                "{{\"completed_at\":\"{}\",\"reason\":\"scheduled\",\"set\":\"x-scheduled\",\"encrypted\":true,\"dump_bytes\":1,\"archive_bytes\":1}}\n",
                an_hour_ago.trim()
            ),
        );
        fx.unit("propolis-backup.timer", "enabled", "active");
        fx.exec("sbin/propolis-alert", "exit 0\n");
        // The witness installed, both its timers enabled, its /run directory made by tmpfiles.
        fx.exec("sbin/propolis-witness", "exit 0\n");
        fx.unit("propolis-witness@light.timer", "enabled", "active");
        fx.unit("propolis-witness@hourly.timer", "enabled", "active");
        std::fs::create_dir_all(fx.p("alert-root/run/propolis-witness")).unwrap();
        // The stored anonymous-read check of the fixture's target, a refusal made ten minutes
        // ago, as the witness leaves it.
        fx.readcheck("refused");
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

    /// The stored anonymous-read check of the fixture's target (https://ntfy.example.invalid,
    /// propolis-ops), one line for the shell and the daemon, with this definite class, decided
    /// and attempted ten minutes before NOW.
    fn readcheck(&self, class: &str) {
        let s = format!("{}/0000aaaa/1", NOW - 600);
        self.write(
            "alert-root/var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\t{class}\t{s}\t{class}\t-\t403\t403\tboth\t403\n"
            ),
        );
    }

    fn link_tools(&self) {
        std::fs::create_dir_all(self.p("tools")).unwrap();
        for t in [
            "grep",
            "sed",
            "stat",
            "du",
            "cat",
            "cmp",
            "head",
            "tail",
            "mktemp",
            "date",
            "id",
            "dirname",
            "git",
            "timeout",
            "rm",
            "env",
            "sort",
            "cut",
            "sha256sum",
            "readlink",
            "tr",
            // What the alert library's functions run: pa_read_as starts a child bash under
            // timeout, and the others are what its remaining functions call.
            "bash",
            "od",
            "awk",
            "find",
            "flock",
            "wc",
            "ls",
            "setpriv",
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
# pa_role asks `is-enabled --quiet UNIT` and reads only the status; quiet_fails makes those
# queries fail as a systemctl that cannot answer them would.
if [ "$1" = is-enabled ] && [ "${2:-}" = --quiet ]; then
  [ ! -f "$d/quiet_fails" ] || exit 1
  set -- is-enabled "$3"
  exec >/dev/null
fi
case "$1" in
  is-enabled) f="$d/enabled/$2"; if [ -f "$f" ]; then cat "$f"; [ "$(cat "$f")" = enabled ]; exit $?; fi; echo not-found; exit 4 ;;
  is-active) f="$d/active/$2"; if [ -f "$f" ]; then cat "$f"; [ "$(cat "$f")" = active ]; exit $?; fi; echo inactive; exit 3 ;;
  is-failed) f="$d/failed/$2"; if [ -f "$f" ]; then cat "$f"; exit 0; fi; echo active; exit 1 ;;
  show) [ -f "$d/backup_env" ] && cat "$d/backup_env"; exit 0 ;;
esac
exit 1
"#,
        );
        self.exec(
            "stubs/df",
            r#"d="$STUB_STATE"
printf 'Size Avail\n%s %s\n' "$(cat "$d/df_size" 2>/dev/null || echo 1099511627776)" "$(cat "$d/df_avail" 2>/dev/null || echo 1099511627776)"
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
            "stubs/timedatectl",
            r#"if [ -f "$STUB_STATE/ntp_unsynced" ]; then echo no; else echo yes; fi
"#,
        );
        self.exec(
            "stubs/psql",
            r#"d="$STUB_STATE"
# The ledger-role query has its own answer and log, so the events query's are what they were.
case "$*" in
    *relowner*)
        { echo "ARGV: $*"; env | grep '^PG' | sort; } > "$d/psql_role.log"
        [ -f "$d/psql_role_rc" ] && exit "$(cat "$d/psql_role_rc")"
        [ -f "$d/psql_role_out" ] && cat "$d/psql_role_out"
        exit 0
        ;;
esac
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
        self.run_under(&[], args, env)
    }

    /// The same run with the script started through `wrapper` (a privilege drop), so a check that
    /// depends on what the account can read is exercised even when the tests run as root.
    fn run_under(&self, wrapper: &[&str], args: &[&str], env: &[(&str, &str)]) -> Run {
        self.run_script_under(Path::new(SCRIPT), wrapper, args, env)
    }

    /// The same run of another copy of the script (an installed one).
    fn run_script(&self, script: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
        self.run_script_under(script, &[], args, env)
    }

    fn run_script_under(
        &self,
        script: &Path,
        wrapper: &[&str],
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Run {
        let mut cmd = match wrapper.split_first() {
            Some((first, rest)) => {
                let mut c = Command::new(first);
                c.args(rest).arg(BASH);
                c
            }
            None => Command::new(BASH),
        };
        cmd.arg(script)
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
            .env("PROPOLIS_CC_CURSOR_DIR", self.p("state/cursors"))
            .env(
                "PROPOLIS_CC_ROTATE_DROPIN_DIR",
                self.p("etc-logrotate/dropin"),
            )
            .env("PROPOLIS_CC_WATCH_HOME", self.p("home-watch"))
            .env("PROPOLIS_CC_WATCH_ACCOUNT", &*self.watch_account.borrow())
            .env("PROPOLIS_CC_BACKUP_STATUS", self.p("state/backup-status"))
            .env("PROPOLIS_CC_BACKUP_DIR", self.p("state/backups"))
            .env("PROPOLIS_CC_ALERT_HOOK", self.p("sbin/propolis-alert"))
            .env("PROPOLIS_CC_WITNESS", self.p("sbin/propolis-witness"))
            // Absent until a test creates it, so a run never looks at this host's own spool.
            .env("PROPOLIS_CC_GATEWAY_SPOOL_DIR", self.p("spool/gateway"))
            // The checkout's library, whichever copy of the script runs, and a root of its own.
            .env("PROPOLIS_CC_ALERT_LIB", ALERT_LIB)
            .env("PROPOLIS_CC_ALERT_ROOT", self.p("alert-root"))
            // The tests run as root here and as an ordinary user in CI, and neither has the
            // accounts the library would read as (propolis, the checkout's owner): read as self.
            .env("PA_TEST_READ_AS_SELF", "1");
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

    /// The gateway spool directory every run looks in (PROPOLIS_CC_GATEWAY_SPOOL_DIR).
    fn spool_dir(&self) -> String {
        self.p("spool/gateway").display().to_string()
    }

    /// One collector's spool file as the gateway writes it, `<spool>/<id>/events.jsonl`; returns
    /// its path.
    fn spool(&self, id: &str, bytes: usize, mtime: u64) -> String {
        let rel = format!("spool/gateway/{id}/events.jsonl");
        self.log(&rel, bytes, mtime);
        self.p(&rel).display().to_string()
    }

    /// Appends `entries` (already `label:path,...`) to PROPOLIS_SENSOR_LOGS in propolis.env.
    fn add_intake_entries(&self, entries: &str) {
        let text: Vec<String> = self
            .read("etc/propolis.env")
            .lines()
            .map(|l| {
                if l.starts_with("PROPOLIS_SENSOR_LOGS=") {
                    format!("{l},{entries}")
                } else {
                    l.to_string()
                }
            })
            .collect();
        self.write("etc/propolis.env", &(text.join("\n") + "\n"));
    }
}

/// The findings whose id starts with `spool-`, the gateway spool checks.
fn spool_findings(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"].as_str().unwrap().starts_with("spool-"))
        .cloned()
        .collect()
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
    // A gateway spool too, one collector listed and one not, so its check is held to the same rule.
    let listed = fx.spool("collector-01", 200, NOW - 60);
    fx.spool("collector-02", 200, NOW - 60);
    fx.add_intake_entries(&format!("collector-01:{listed}"));
    let snapshot = |fx: &Fx| -> BTreeMap<PathBuf, (u64, u64)> {
        let mut m = BTreeMap::new();
        let mut stack = vec![fx.p("")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    stack.push(p);
                } else if !p.starts_with(fx.p("state/psql.log"))
                    && !p.starts_with(fx.p("state/psql_role.log"))
                {
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
    // Split on the FIRST colon: the label is `extra` and the path keeps its own colon.
    assert!(
        msgs.contains(&format!(
            "entry 'extra:{logs}/odd:name/events.jsonl' matches no configured sensor's log path"
        )),
        "{msgs}"
    );
}

#[test]
fn ufw_default_allow_incoming_opens_every_port_and_a_loopback_bind_needs_no_rule() {
    let fx = Fx::new();
    fx.write(
        "state/ufw",
        "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n",
    );
    let v = fx.json();
    assert_eq!(
        listener(&v, "ssh", "tcp")["checks"]["firewall"]["text"],
        "open"
    );

    let fx = Fx::new();
    fx.write(
        "etc/ssh.env",
        &format!(
            "PROPOLIS_SSH_BIND=127.0.0.1:22\nPROPOLIS_SSH_LOG_PATH={}/ssh/events.jsonl\n",
            fx.logs()
        ),
    );
    fx.write(
        "state/ufw",
        &UFW_ALL
            .replace("22/tcp                     ALLOW IN    Anywhere\n", "")
            .replace("22/tcp (v6)                ALLOW IN    Anywhere (v6)\n", ""),
    );
    fx.ss(
        &[
            ("127.0.0.1:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("0.0.0.0:5432", "sensor-cred"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert_eq!(
        listener(&fx.json(), "ssh", "tcp")["checks"]["firewall"]["text"],
        "loopback"
    );
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
    assert!(msgs.contains("| sudo ufw delete allow 5432/tcp"), "{msgs}");
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

// The production box's case: the host's own PostgreSQL on 127.0.0.1 and [::1] blocks sensor-cred's
// 0.0.0.0:5432 bind, while the firewall allows 5432. Exposure is a property of where the other
// process listens, so this is a collection failure, never DANGEROUS and never "reachable".
#[test]
fn a_loopback_only_holder_blocks_the_sensor_but_is_not_reported_as_exposed() {
    let tcp = [
        ("0.0.0.0:22", "sensor-ssh"),
        ("0.0.0.0:1883", "sensor-mqtt"),
        ("127.0.0.1:5432", "postgres"),
        ("[::1]:5432", "postgres"),
        ("203.0.113.7:53", "sensor-dns"),
    ];
    let udp = [
        ("0.0.0.0:69", "sensor-tftp"),
        ("203.0.113.7:53", "sensor-dns"),
    ];

    let fx = Fx::new();
    fx.ss(&tcp, &udp);
    let r = fx.run(&[]);
    assert_eq!(r.code, 2);
    let v = fx.json();
    assert_eq!(check(&v, "postgresql", "tcp", "listen"), "fail");
    assert_ne!(check(&v, "postgresql", "tcp", "firewall"), "fail");
    let msgs = finding_messages(&v).join("\n");
    assert!(!msgs.contains("DANGEROUS"), "{msgs}");
    assert!(
        msgs.contains("tcp/5432 is held on loopback only by another process (postgres), so it is not reachable from the network"),
        "{msgs}"
    );
    assert!(
        msgs.contains("set PROPOLIS_CRED_PG_BIND=<this host's address>:5432"),
        "{msgs}"
    );
    assert!(!msgs.contains("move it off tcp/5432"), "{msgs}");

    let fx = Fx::new();
    fx.remove_stub("ufw");
    fx.ss(&tcp, &udp);
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(msgs.contains("held on loopback only"), "{msgs}");
    assert!(!msgs.contains("reachable from anywhere"), "{msgs}");
}

// One non-loopback socket is enough: a holder on loopback AND a network address is exposed.
#[test]
fn a_holder_on_loopback_and_a_network_address_is_still_exposed() {
    let fx = Fx::new();
    fx.ss(
        &[
            ("0.0.0.0:22", "sensor-ssh"),
            ("0.0.0.0:1883", "sensor-mqtt"),
            ("127.0.0.1:5432", "postgres"),
            ("198.51.100.20:5432", "postgres"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
        &[
            ("0.0.0.0:69", "sensor-tftp"),
            ("203.0.113.7:53", "sensor-dns"),
        ],
    );
    let msgs = finding_messages(&fx.json()).join("\n");
    assert!(msgs.contains("DANGEROUS: tcp/5432"), "{msgs}");
    assert!(!msgs.contains("held on loopback only"), "{msgs}");
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
            "sensor-tftp.service is enabled but failed: read its log, fix what it reports, then run: sudo systemctl restart sensor-tftp.service | sudo journalctl -u sensor-tftp.service"
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

/// A watch.env that exists and is readable to the check (root reads everything) but not to the
/// watcher's own account is the 2026-10-14 incident: the file was 0600 root:root, the watcher
/// exited, and every check passed.
#[test]
fn a_watch_env_the_watcher_account_cannot_read_is_a_failure() {
    let fx = Fx::new();
    let ids = |fx: &Fx, account: &str| -> Vec<String> {
        *fx.watch_account.borrow_mut() = account.to_string();
        fx.json()["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_str().unwrap().to_string())
            .collect()
    };
    // Owned by the watcher's account, owner-readable: fine (the fixture default).
    assert!(!ids(&fx, &current_user()).contains(&"watch-env-owner".to_string()));
    // Owned and grouped by someone else, no other-read bit: the watcher cannot read it.
    std::fs::set_permissions(
        fx.p("etc/watch.env"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(ids(&fx, "no-such-watch-account").contains(&"watch-env-owner".to_string()));
    // Group read does not help an account that is not the group.
    let r = fx.run(&[]);
    assert_eq!(r.code, 2, "{}", r.out);
}

/// The correctly provisioned shape is root:propolis-watch 0640: the watcher reads it through the
/// GROUP bit. Without the group branch config-check fails every good box. The kernel then applies
/// only the group class, so 0604 (other can read, the group cannot) is still unreadable.
#[test]
fn a_watch_env_is_readable_through_the_group_bit_and_only_the_group_bit() {
    let fx = Fx::new();
    let me = current_user();
    let out = std::process::Command::new("id")
        .arg("-Gn")
        .output()
        .unwrap();
    let groups = String::from_utf8(out.stdout).unwrap();
    let Some(group) = groups.split_whitespace().find(|g| *g != me) else {
        eprintln!("skipped: {me} has no group named differently from the user");
        return;
    };
    let status = std::process::Command::new("chgrp")
        .arg(group)
        .arg(fx.p("etc/watch.env"))
        .status()
        .unwrap();
    assert!(status.success(), "chgrp {group}");
    *fx.watch_account.borrow_mut() = group.to_string();
    let flagged = |fx: &Fx, mode: u32| -> bool {
        std::fs::set_permissions(fx.p("etc/watch.env"), std::fs::Permissions::from_mode(mode))
            .unwrap();
        fx.json()["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "watch-env-owner")
    };
    assert!(
        !flagged(&fx, 0o640),
        "group-readable watch.env wrongly failed"
    );
    assert!(flagged(&fx, 0o600), "owner-only watch.env must fail");
    assert!(flagged(&fx, 0o604), "the group class has no bits at 0604");
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

// ---- fix lines -----------------------------------------------------------------------------
//
// The report's `fix:` lines are copy-pasted by an operator who is not root and has no
// DATABASE_URL in their shell. Two went wrong live (a grep of root-only env files with no sudo, and
// a psql line followed by prose that bash parsed as an `if`), so the contract is enforced here for
// every finding the script can raise, by EXECUTING each `fix` line in bash against stub commands
// that record who ran them. A parse check alone would pass `sudo`-less commands.

/// The privileged commands a run fix may only invoke through sudo.
const ROOT_COMMANDS: [&str; 8] = [
    "systemctl",
    "journalctl",
    "ss",
    "ufw",
    "firewall-cmd",
    "nft",
    "install",
    "chmod",
];

/// Every finding id in the script: the part of each `finding LEVEL "scope" "KEY"` key before its
/// first colon. One id per call site, so a new finding is a new id.
fn script_finding_ids() -> Vec<String> {
    let text = std::fs::read_to_string(SCRIPT).unwrap();
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("finding fail \"") || l.starts_with("finding warn \""))
        .map(|l| {
            let key = l.split('"').nth(3).unwrap_or_else(|| panic!("{l}"));
            key.split(':').next().unwrap().to_string()
        })
        .collect()
}

impl Fx {
    /// Stub commands for executing a fix line: `sudo` runs a stub of that name with UNDER_SUDO=1
    /// (or a root script by absolute path, which it only records), every other command records
    /// whether it ran under sudo. Nothing else is on PATH, so an unlisted command is "not found".
    fn install_fix_stubs(&self) {
        let find = |t: &str| -> String {
            ["/usr/bin", "/bin"]
                .iter()
                .map(|d| format!("{d}/{t}"))
                .find(|p| Path::new(p).exists())
                .unwrap_or_else(|| panic!("no {t} on this host"))
        };
        // One write per record: the stages of a pipeline (journalctl | grep) append concurrently,
        // and piecewise printf calls interleave into blank or spliced lines.
        let record = |name: &str| {
            format!(
                "line=\"{name} sudo=${{UNDER_SUDO:-0}}\"\nfor a in \"$@\"; do line=\"$line [$a]\"; done\nprintf '%s\\n' \"$line\" >> \"$FIXLOG\"\n"
            )
        };
        for name in [
            "systemctl",
            "ss",
            "ufw",
            "firewall-cmd",
            "nft",
            "psql",
            "timedatectl",
            "chmod",
            "propolis-migrate",
        ] {
            self.exec(&format!("fixstubs/{name}"), &record(name));
        }
        // A log line that a `| grep -i bind` filter keeps, so the pipeline's exit status is 0.
        self.exec(
            "fixstubs/journalctl",
            &format!("{}echo 'failed to bind 0.0.0.0'\n", record("journalctl")),
        );
        // install checks its source exists: a fix that names a missing file fails here, loudly.
        self.exec(
            "fixstubs/install",
            &format!(
                "{}n=$#; i=0; for a in \"$@\"; do i=$((i+1)); [ $i -eq $((n-1)) ] && src=$a; done\n[ -f \"$src\" ] || {{ echo \"install: cannot stat $src\" >&2; exit 1; }}\n",
                record("install")
            ),
        );
        // grep really runs, so a fix that reads DATABASE_URL out of the env file gets the real URL.
        self.exec(
            "fixstubs/grep",
            &format!("{}exec {} \"$@\"\n", record("grep"), find("grep")),
        );
        self.exec(
            "fixstubs/sudo",
            r#"line=sudo
for a in "$@"; do line="$line [$a]"; done
printf '%s\n' "$line" >> "$FIXLOG"
while [ $# -gt 0 ]; do case "$1" in -u) shift 2 ;; -*) shift ;; *) break ;; esac; done
cmd="$1"; shift
if [ -x "$FIXSTUBS/$cmd" ]; then UNDER_SUDO=1 exec "$FIXSTUBS/$cmd" "$@"; fi
case "$cmd" in /*) if [ -x "$cmd" ]; then line="root-script sudo=1 [$cmd]"; for a in "$@"; do line="$line [$a]"; done; printf '%s\n' "$line" >> "$FIXLOG"; exit 0; fi ;; esac
echo "sudo: $cmd: command not found" >&2
exit 127
"#,
        );
        for t in ["tail", "cut", "tr", "head"] {
            std::os::unix::fs::symlink(find(t), self.p(&format!("fixstubs/{t}"))).unwrap();
        }
    }

    /// Runs `fix` as an operator would paste it (bash -c, a directory that is not the repo, no
    /// DATABASE_URL, no sudo-free access to anything); returns (exit, stderr, recorded commands).
    fn run_fix(&self, fix: &str) -> (i32, String, Vec<String>) {
        let log = self.p("fixlog");
        let _ = std::fs::remove_file(&log);
        std::fs::create_dir_all(self.p("cwd")).unwrap();
        let out = Command::new(BASH)
            .arg("-c")
            .arg(fix)
            .current_dir(self.p("cwd"))
            .env_clear()
            .env("PATH", self.p("fixstubs"))
            .env("FIXSTUBS", self.p("fixstubs"))
            .env("FIXLOG", &log)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let recorded = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            recorded,
        )
    }
}

/// Asserts the contract for one finding's fix and returns nothing; `what` names it for failures.
fn assert_fix_contract(fx: &Fx, what: &str, id: &str, kind: &str, fix: &str) {
    if fix.is_empty() {
        assert_eq!(kind, "", "{what}: a finding with no fix has no fix_kind");
        return;
    }
    assert!(
        kind == "run" || kind == "manual",
        "{what}: fix_kind must be run or manual, got {kind:?}"
    );
    // A secret must never ride on a command line, and a pasted line must not reach for the
    // database directly: the script's own --newest-event mode does that through PG* variables.
    for forbidden in [
        "DATABASE_URL",
        "psql",
        "postgres://",
        "postgresql://",
        "PGPASSWORD",
    ] {
        assert!(
            !fix.contains(forbidden),
            "{what}: a fix line must not contain {forbidden}: {fix}"
        );
    }
    if kind == "manual" {
        return;
    }
    let parse = Command::new(BASH).args(["-n", "-c", fix]).output().unwrap();
    assert!(
        parse.status.success(),
        "{what}: a run fix must parse as shell: {fix}\n{}",
        String::from_utf8_lossy(&parse.stderr)
    );
    let (code, err, recorded) = fx.run_fix(fix);
    assert!(
        err.is_empty(),
        "{what}: running the fix wrote to stderr (prose, a missing command, a bad path): {fix}\n{err}"
    );
    assert_eq!(code, 0, "{what}: the fix exited {code}: {fix}");
    assert!(
        !recorded.is_empty(),
        "{what}: the fix ran no command: {fix}"
    );
    for line in recorded
        .iter()
        .filter(|l| !l.starts_with("sudo ") && !l.starts_with("root-script "))
    {
        let name = line.split_whitespace().next().unwrap();
        let under_sudo = line.contains(" sudo=1");
        assert!(
            under_sudo || !ROOT_COMMANDS.contains(&name),
            "{what}: {name} needs root but ran without sudo: {fix}\n{line}"
        );
        assert!(
            under_sudo || !line.contains(".env"),
            "{what}: an env file is root-only and was read without sudo: {fix}\n{line}"
        );
    }
    if id == "events-none" {
        let script = recorded
            .iter()
            .find(|l| l.starts_with("root-script "))
            .unwrap_or_else(|| {
                panic!("{what}: the ledger query is not a root run of the script: {fix}")
            });
        assert!(
            script.contains("config-check.sh] ") && script.contains("[--newest-event] ["),
            "{what}: {script}"
        );
    }
}

fn use_nft(fx: &Fx, input_ports: &str, forward_ports: &str) {
    fx.remove_stub("ufw");
    fx.exec("stubs/nft", "[ -f \"$STUB_STATE/nft\" ] && cat \"$STUB_STATE/nft\" && exit 0\necho 'Operation not permitted' >&2; exit 1\n");
    fx.write(
        "state/nft",
        &format!(
            "table inet filter {{\n\tchain input {{\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport {{ {input_ports} }} accept\n\t\tudp dport 69 accept\n\t\tudp dport 53 accept\n\t\ttcp dport 53 accept\n\t}}\n\tchain forward {{\n\t\ttype filter hook forward priority filter; policy drop;\n\t\ttcp dport {{ {forward_ports} }} accept\n\t}}\n}}\n"
        ),
    );
}

fn use_firewalld_without_ssh(fx: &Fx) {
    fx.remove_stub("ufw");
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
}

/// A host PostgreSQL on 0.0.0.0:5432 where sensor-cred should be.
fn foreign_holder_on_5432(fx: &Fx) {
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
}

fn set_stamp_installed_empty(fx: &Fx) {
    let head = fx.head.clone();
    let stamp = fx.read("state/deploy-stamp.json").replace(
        &format!("\"propolis\": \"{}\"", &head[..12]),
        "\"propolis\": \"\"",
    );
    fx.write("state/deploy-stamp.json", &stamp);
}

type Scenario = (&'static str, fn(&Fx));

/// One fixture per way the host can be wrong; together they raise every finding id.
fn fix_scenarios() -> Vec<Scenario> {
    vec![
        ("the daemon's database role owns the ledger", |fx| {
            fx.write("state/psql_role_out", "propolis|t||t|t\n");
        }),
        (
            "the daemon's database role holds extra ledger privileges",
            |fx| {
                fx.write("state/psql_role_out", "propolis|f|UPDATE DELETE|f|f\n");
            },
        ),
        (
            "the daemon's database role owns the database but not the ledger",
            |fx| {
                fx.write("state/psql_role_out", "propolis|f||t|t\n");
            },
        ),
        ("the witness is not installed", |fx| {
            std::fs::remove_file(fx.p("sbin/propolis-witness")).unwrap();
        }),
        ("the ntfy URL has no scheme", |fx| {
            let env = fx.read("etc/propolis.env").replace(
                "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid",
                "PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid",
            );
            fx.write("etc/propolis.env", &env);
        }),
        (
            "the stored check found the alert topic readable by anyone",
            |fx| {
                fx.readcheck("readable");
            },
        ),
        ("the witness's hourly timer is not enabled", |fx| {
            fx.unit("propolis-witness@hourly.timer", "disabled", "inactive");
        }),
        ("env files all empty", |fx| {
            for name in ["ssh", "mqtt", "cred", "tftp", "dns", "propolis"] {
                // Comments only, as a copied example file leaves them.
                fx.write(&format!("etc/{name}.env"), "# BIND is set here\n");
            }
        }),
        ("watch.env the watcher account cannot read", |fx| {
            *fx.watch_account.borrow_mut() = "no-such-watch-account".to_string();
            std::fs::set_permissions(
                fx.p("etc/watch.env"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }),
        ("bad bind", |fx| {
            fx.write("etc/telnet.env", "PROPOLIS_TELNET_BIND=0.0.0.0:99999\n");
        }),
        ("unit states", |fx| {
            fx.write("repo/deploy/sensor-mqtt.service", "[Unit]\n");
            std::fs::remove_file(fx.p("state/enabled/sensor-mqtt.service")).unwrap();
            std::fs::remove_file(fx.p("state/active/sensor-mqtt.service")).unwrap();
            fx.unit("sensor-ssh.service", "disabled", "inactive");
            fx.unit("sensor-tftp.service", "enabled", "failed");
            fx.unit("sensor-dns.service", "disabled", "active");
            fx.unit("sensor-cred.service", "masked", "inactive");
        }),
        ("foreign holder behind an open ufw", foreign_holder_on_5432),
        ("foreign holder behind an open nftables", |fx| {
            use_nft(fx, "22, 1883, 5432", "9999");
            foreign_holder_on_5432(fx);
        }),
        ("foreign holder, no firewall", |fx| {
            fx.remove_stub("ufw");
            foreign_holder_on_5432(fx);
        }),
        ("loopback holder", |fx| {
            fx.ss(
                &[
                    ("0.0.0.0:22", "sensor-ssh"),
                    ("0.0.0.0:1883", "sensor-mqtt"),
                    ("127.0.0.1:5432", "postgres"),
                    ("203.0.113.7:53", "sensor-dns"),
                ],
                &[
                    ("0.0.0.0:69", "sensor-tftp"),
                    ("203.0.113.7:53", "sensor-dns"),
                ],
            );
        }),
        ("holder of unknown name, unit stopped", |fx| {
            fx.unit("sensor-cred.service", "enabled", "inactive");
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
        }),
        ("nothing listening", |fx| {
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
        }),
        ("ufw closes the port", |fx| {
            fx.write(
                "state/ufw",
                &UFW_ALL
                    .replace("22/tcp                     ALLOW IN    Anywhere\n", "")
                    .replace("22/tcp (v6)                ALLOW IN    Anywhere (v6)\n", ""),
            );
        }),
        ("firewalld closes the port", |fx| {
            use_firewalld_without_ssh(fx)
        }),
        ("nftables closes the port", |fx| {
            use_nft(fx, "1883, 5432", "22");
        }),
        ("catchall without a log path", |fx| {
            fx.write(
                "etc/catchall.env",
                "PROPOLIS_CATCHALL_BIND_ADDRS=0.0.0.0:1024\n",
            );
            fx.unit("sensor-catchall.service", "enabled", "active");
        }),
        ("log sizes, quiet and missing", |fx| {
            fx.write(
                "etc-logrotate/propolis-sensors",
                "/x\n{\n    size 1k\n    rotate 5\n}\n",
            );
            fx.log("logs/ssh/events.jsonl", 3500, NOW - 60);
            fx.log("logs/mqtt/events.jsonl", 2500, NOW - 60);
            fx.touch("logs/tftp/events.jsonl", NOW - 3 * 86400);
            std::fs::remove_file(fx.p("logs/dns/events.jsonl")).unwrap();
        }),
        ("intake path typo", |fx| {
            let logs = fx.logs();
            let text = fx.read("etc/propolis.env").replace(
                &format!("mqtt:{logs}/mqtt/events.jsonl"),
                &format!("mqtt:{logs}/mqtt/event.jsonl"),
            );
            fx.write("etc/propolis.env", &text);
        }),
        ("intake entry absent", |fx| {
            let logs = fx.logs();
            let line = format!(
                "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
            );
            fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", Some(&line));
        }),
        ("intake wrong separator", |fx| {
            let logs = fx.logs();
            let text = fx.read("etc/propolis.env").replace(
                &format!("ssh:{logs}/ssh/events.jsonl"),
                &format!("ssh;{logs}/ssh/events.jsonl"),
            );
            fx.write("etc/propolis.env", &text);
        }),
        ("intake duplicates", |fx| {
            let logs = fx.logs();
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_SENSOR_LOGS=",
                Some(&format!(
                    "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,mqtt:{logs}/dns/events.jsonl,dns2:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl,dns:{logs}/dns/events.jsonl"
                )),
            );
        }),
        ("intake relative path and missing directory", |fx| {
            let logs = fx.logs();
            let text = fx.read("etc/propolis.env").replace(
                "PROPOLIS_SENSOR_LOGS=",
                &format!(
                    "PROPOLIS_SENSOR_LOGS=rel:relative/p.jsonl,typo:{logs}/nosuchdir/events.jsonl,"
                ),
            );
            fx.write("etc/propolis.env", &text);
        }),
        ("intake variable misspelled", |fx| {
            let logs = fx.logs();
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_SENSOR_LOGS=",
                Some(&format!("PROPOLIS_SENSOR_LOG=ssh:{logs}/ssh/events.jsonl")),
            );
        }),
        ("ledger has no or old events", |fx| {
            fx.write(
                "state/psql_out",
                "ssh|60\nmqtt|90000\ntftp|100\ndns|30\ncred-pg|5\n",
            );
        }),
        ("rotation dead", |fx| {
            fx.unit("propolis-logrotate.timer", "enabled", "inactive");
            fx.write("state/failed/propolis-logrotate.service", "failed");
            std::fs::remove_file(fx.p("sbin/propolis-logrotate-guard")).unwrap();
            std::fs::remove_file(fx.p("etc-logrotate/propolis-sensors")).unwrap();
            std::fs::remove_file(fx.p("state/logrotate.state")).unwrap();
        }),
        ("rotation stale and timer not enabled", |fx| {
            fx.unit("propolis-logrotate.timer", "disabled", "active");
            fx.touch("state/logrotate.state", NOW - 4 * 3600);
        }),
        ("binaries missing and different", |fx| {
            std::fs::remove_file(fx.p("bin/sensor-mqtt")).unwrap();
            fx.write("build/sensor-ssh", "new build");
        }),
        ("stamp behind the checkout and binary mismatch", |fx| {
            let head = fx.head.clone();
            let stamp = fx.read("state/deploy-stamp.json").replace(
                &format!("\"propolis\": \"{}\"", &head[..12]),
                "\"propolis\": \"deadbeef0000\"",
            );
            fx.write("state/deploy-stamp.json", &stamp);
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
        }),
        ("no deploy stamp", |fx| {
            std::fs::remove_file(fx.p("state/deploy-stamp.json")).unwrap();
        }),
        ("stamp without head", |fx| {
            fx.write("state/deploy-stamp.json", "{}\n");
        }),
        ("stamp without installed version", |fx| {
            set_stamp_installed_empty(fx);
        }),
        ("watcher env missing, key empty", |fx| {
            std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
            fx.write("home-watch/.ssh/authorized_keys", "");
        }),
        ("watcher env without a list, key missing", |fx| {
            fx.write("etc/watch.env", "UNRELATED=1\n");
            std::fs::remove_file(fx.p("home-watch/.ssh/authorized_keys")).unwrap();
        }),
        ("watcher env drifted", |fx| {
            fx.write("etc/watch.env", "PROPOLIS_SENSOR_LOGS=ssh:/old/path\n");
        }),
        ("enabled unit with no bind", |fx| {
            fx.unit("sensor-redis.service", "enabled", "active");
            fx.write("etc/redis.env", "PROPOLIS_REDIS_BNID=0.0.0.0:6379\n");
        }),
        ("cursor missing for a log with content", |fx| {
            fx.write("state/cursors/unrelated.json", "{}");
        }),
        ("a collector spool the daemon does not list", |fx| {
            fx.spool("collector-09", 300, NOW - 7200);
        }),
        (
            "spool entries under a sensor's name and under a name that is not the collector id",
            |fx| {
                let a = fx.spool("collector-01", 300, NOW - 60);
                let b = fx.spool("collector-02", 300, NOW - 60);
                fx.add_intake_entries(&format!("telnet:{a},edge-box:{b}"));
            },
        ),
        ("a spool entry under a daemon subsystem's name", |fx| {
            let a = fx.spool("collector-01", 300, NOW - 60);
            fx.add_intake_entries(&format!("console:{a}"));
        }),
        ("cursor directory the rotation unit cannot see", |fx| {
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_CURSOR_DIR=",
                Some("PROPOLIS_CURSOR_DIR=/srv/propolis-cursors"),
            );
        }),
        ("env files readable or writable by other accounts", |fx| {
            std::fs::set_permissions(
                fx.p("etc/propolis.env"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            std::fs::set_permissions(
                fx.p("etc/watch.env"),
                std::fs::Permissions::from_mode(0o660),
            )
            .unwrap();
        }),
        ("no env files", |fx| {
            std::fs::remove_dir_all(fx.p("etc")).unwrap();
            std::fs::create_dir_all(fx.p("etc")).unwrap();
            // No units either, so nothing is "enabled with no bind" in an empty directory.
            for d in ["state/enabled", "state/active"] {
                std::fs::remove_dir_all(fx.p(d)).unwrap();
            }
        }),
        (
            "backups failing, timer not enabled, recipients without age",
            |fx| {
                std::fs::remove_file(fx.p("state/backup-status/last-success")).unwrap();
                fx.write(
                "state/backup-status/last-failure",
                "{\"failed_at\":\"x\",\"reason\":\"scheduled\",\"step\":\"dumping the database\",\"exit_code\":1}\n",
            );
                fx.unit("propolis-backup.timer", "disabled", "active");
                fx.write("etc/backup-recipients.txt", "age1example\n");
            },
        ),
        ("a stale plaintext backup", |fx| {
            fx.write(
                "state/backup-status/last-success",
                &format!(
                    "{{\"completed_at\":\"{}\",\"reason\":\"scheduled\",\"set\":\"x\",\"encrypted\":false}}\n",
                    iso(NOW - 3 * 86_400)
                ),
            );
        }),
        ("retention too large for the backup volume", |fx| {
            seed_backup_volume(fx, 7);
        }),
        ("no backup has run yet", |fx| {
            std::fs::remove_file(fx.p("state/backup-status/last-success")).unwrap();
        }),
        (
            "no alerting configured, no failure hook, clock unsynced",
            |fx| {
                for prefix in [
                    "PROPOLIS_OPS_ENABLED=",
                    "PROPOLIS_OPS_NTFY_URL=",
                    "PROPOLIS_OPS_NTFY_TOPIC=",
                    "PROPOLIS_OPS_HEARTBEAT_URL=",
                ] {
                    fx.set_env_line("etc/propolis.env", prefix, None);
                }
                std::fs::remove_file(fx.p("sbin/propolis-alert")).unwrap();
                fx.write("state/ntp_unsynced", "");
            },
        ),
        ("alerting on with an ntfy URL and no topic", |fx| {
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_OPS_NTFY_TOPIC=",
                Some("PROPOLIS_OPS_NTFY_TOPIC="),
            );
        }),
        (
            "an indented ntfy URL line, which systemd reads and the failure hook does not",
            |fx| {
                fx.set_env_line(
                    "etc/propolis.env",
                    "PROPOLIS_OPS_NTFY_URL=",
                    Some("  PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid"),
                );
            },
        ),
    ]
}

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// The live incident's volume: 17 GiB holding 7 767 448 361 bytes of everything but backup sets
/// (a 6.6 GiB database among them), whose last good set was 1 148 903 751 bytes.
const INCIDENT_SIZE: u64 = 18_253_611_008;
const INCIDENT_OTHER: u64 = 7_767_448_361;
const INCIDENT_SET: u64 = 1_148_903_751;

fn backups_dir(fx: &Fx) -> std::path::PathBuf {
    let dir = fx.p("state/backups");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What `du -s -B1` reports for `dir`, which is what the script subtracts from the volume's used space.
fn du_bytes(dir: &std::path::Path) -> u64 {
    let out = Command::new("du")
        .args(["-s", "-B1", "--"])
        .arg(dir)
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// A backup volume of `size` bytes holding `other` bytes besides the backup directory, whose last
/// good set was `set` bytes taken from `source` bytes, with `keep` scheduled sets kept.
fn seed_volume(fx: &Fx, size: u64, other: u64, set: u64, source: u64, keep: &str) {
    let used = other + du_bytes(&backups_dir(fx));
    fx.write("state/df_size", &size.to_string());
    fx.write("state/df_avail", &(size - used).to_string());
    fx.write(
        "state/backup-status/last-success",
        &format!(
            "{{\"completed_at\":\"{}\",\"reason\":\"scheduled\",\"set\":\"x-scheduled\",\"encrypted\":true,\"dump_bytes\":{},\"archive_bytes\":{},\"source_bytes\":{}}}\n",
            iso(NOW - 3600),
            set - 1024,
            1024,
            source
        ),
    );
    fx.write(
        "state/backup_env",
        &format!("PROPOLIS_BACKUP_KEEP={keep}\n"),
    );
}

fn seed_incident(fx: &Fx, keep: &str) {
    seed_volume(
        fx,
        INCIDENT_SIZE,
        INCIDENT_OTHER,
        INCIDENT_SET,
        7_086_696_038 + 4096,
        keep,
    );
}

fn seed_backup_volume(fx: &Fx, keep: u32) {
    seed_incident(fx, &keep.to_string());
}

fn finding_ids(fx: &Fx) -> Vec<String> {
    fx.json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect()
}

fn headroom_warned(fx: &Fx) -> bool {
    finding_ids(fx).contains(&"backup-headroom".to_string())
}

fn headroom_finding(v: &serde_json::Value) -> &serde_json::Value {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "backup-headroom")
        .expect("a backup-headroom finding")
}

/// The incident's numbers, through the real script and a stub `df`: on that 17 GiB volume the
/// default retention and KEEP 5 and 4 cannot fit (KEEP 4 is short by 524 MB, which is what
/// backup.sh refuses by every night), while KEEP 3 and below can.
#[test]
fn retention_that_backup_sh_would_refuse_is_warned_with_the_numbers() {
    let fx = Fx::new();
    for keep in ["7", "5", "4"] {
        seed_incident(&fx, keep);
        assert!(headroom_warned(&fx), "KEEP {keep} refuses every night");
    }
    for keep in ["3", "2", "1"] {
        seed_incident(&fx, keep);
        assert!(!headroom_warned(&fx), "KEEP {keep} fits");
    }

    seed_incident(&fx, "4");
    let v = fx.json();
    let f = headroom_finding(&v);
    assert_eq!(f["level"], "warn");
    assert_eq!(f["fix_kind"], "manual");
    let msg = f["message"].as_str().unwrap();
    for needle in [
        "4 scheduled backups",
        "6 sets of about 1.1G",
        "7.2G of other data",
        "the next set needs 1.3G",
        "the larger of the 15% low-disk threshold",
        "short by 499.7M",
        "17G volume",
    ] {
        assert!(msg.contains(needle), "{needle} missing: {msg}");
    }
    assert!(f["fix"].as_str().unwrap().contains("PROPOLIS_BACKUP_KEEP"));

    // The monitor's own threshold is the line: 70% of the volume is kept free, so even KEEP 1 fails.
    seed_incident(&fx, "1");
    fx.set_env_line(
        "etc/propolis.env",
        "PROPOLIS_OPS_CAPACITY_FREE_PCT=",
        Some("PROPOLIS_OPS_CAPACITY_FREE_PCT=70"),
    );
    assert!(headroom_warned(&fx));
}

/// Exactly what backup.sh needs passes and one byte less does not: the line is `total <= size`, with
/// the threshold's share rounded up (15% of 10 000 000 050 is 1 500 000 007.5).
#[test]
fn the_headroom_line_is_the_volume_size_to_the_byte_with_the_share_rounded_up() {
    let fx = Fx::new();
    let size: u64 = 10_000_000_050;
    let keep_free: u64 = 1_500_000_008;
    let set: u64 = 100_000_000;
    // KEEP 3: 2 scheduled + 3 pre-upgrade sets, and the next set a fifth over.
    let exact_other = size - 5 * set - (set + set / 5) - keep_free;
    seed_volume(&fx, size, exact_other, set, 1000, "3");
    assert!(!headroom_warned(&fx), "needing exactly the volume fits");
    seed_volume(&fx, size, exact_other + 1, set, 1000, "3");
    assert!(headroom_warned(&fx), "one byte over does not");
}

/// A small volume is held to logrotate's 512 MiB reserve, not to the threshold's smaller share: 15%
/// of 2 GiB is 307 MiB.
#[test]
fn the_logrotate_reserve_binds_the_headroom_on_a_small_volume() {
    let fx = Fx::new();
    // other 1500 MiB + 4 sets of 40 MiB + a next set of 48 MiB is 1708 MiB: with 307 MiB kept free
    // that is 2015 MiB of 2048, with the 512 MiB reserve it is 2220.
    seed_volume(&fx, 2 * GIB, 1500 * MIB, 40 * MIB, 1000, "1");
    assert!(headroom_warned(&fx));
    seed_volume(&fx, 2 * GIB, 1000 * MIB, 40 * MIB, 1000, "1");
    assert!(!headroom_warned(&fx));
}

/// A dedicated backup volume holds neither the database nor the logs, so the same retention that
/// cannot fit beside them on /var fits on it.
#[test]
fn a_dedicated_backup_volume_is_not_charged_for_the_database() {
    let fx = Fx::new();
    seed_volume(&fx, 20 * GIB, 0, GIB + 70 * MIB, 6 * GIB, "7");
    assert!(!headroom_warned(&fx));
    // The same sets beside the incident's other data on a 20 GiB volume do not fit.
    seed_volume(&fx, 20 * GIB, 8 * GIB, GIB + 70 * MIB, 6 * GIB, "7");
    assert!(headroom_warned(&fx));
}

/// Not root, the real backup directory (0750 root) cannot be measured, so what else the volume
/// holds is unknown. That is a limited check, never a pass: on the incident's volume KEEP 4 is
/// refused by backup.sh every night, and the fallback that used to charge only the source size
/// stayed silent about it.
#[test]
fn an_unmeasurable_backup_directory_is_a_limited_check_not_a_pass() {
    if is_root() {
        return;
    }
    let fx = Fx::new();
    seed_incident(&fx, "4");
    let dir = backups_dir(&fx);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let v = fx
        .run_with(
            &["--json"],
            &[("PROPOLIS_CC_BACKUP_DIR", dir.to_str().unwrap())],
        )
        .json();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        v["limited"].as_array().unwrap().iter().any(|l| {
            let l = l.as_str().unwrap();
            l.contains("backup") && l.contains("headroom was not checked")
        }),
        "an unreadable backup directory must be listed under LIMITED CHECKS: {}",
        v["limited"]
    );
    assert!(
        !v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "backup-headroom"),
        "no verdict either way when nothing was measured"
    );

    // The same directory, readable, is measured and KEEP 4 warns.
    let v = fx.json();
    assert!(headroom_warned(&fx), "{}", v["findings"]);
    assert!(
        !v["limited"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("headroom was not checked")),
        "{}",
        v["limited"]
    );
}

/// The backup directory's own usage is subtracted from the volume's used space, so a set is not
/// counted twice (once as "other data", once as a set). Real, non-sparse bytes in the directory make
/// du report them, and the line is still the volume size to the byte: without the subtraction the
/// exactly-fitting case is warned.
#[test]
fn the_backup_directorys_own_usage_is_not_charged_as_other_data() {
    let fx = Fx::new();
    let set_dir = backups_dir(&fx).join("20200101T000000Z-scheduled");
    std::fs::create_dir_all(&set_dir).unwrap();
    // Pseudo-random so no filesystem compresses or deduplicates it away.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let data: Vec<u8> = (0..16 * MIB)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(set_dir.join("propolis.dump.age"), data).unwrap();
    assert!(
        du_bytes(&backups_dir(&fx)) >= 16 * MIB,
        "the bytes are real"
    );

    let size: u64 = 10_000_000_050;
    let keep_free: u64 = 1_500_000_008;
    let set: u64 = 100_000_000;
    let exact_other = size - 5 * set - (set + set / 5) - keep_free;
    seed_volume(&fx, size, exact_other, set, 1000, "3");
    assert!(!headroom_warned(&fx), "needing exactly the volume fits");
    seed_volume(&fx, size, exact_other + 1, set, 1000, "3");
    assert!(headroom_warned(&fx), "one byte over does not");
}

/// With KEEP 1 backup.sh still holds the one set it must keep while the new one is written, the same
/// count as KEEP 2: the night is (max(KEEP-1, 1) + 3) sets, not (KEEP-1) + 3. Each KEEP's line is
/// exact to the byte.
#[test]
fn keep_one_is_sized_with_the_set_backup_sh_must_keep() {
    let size: u64 = 10_000_000_050;
    let keep_free: u64 = 1_500_000_008;
    let set: u64 = 100_000_000;
    for (keep, sets) in [("1", 4), ("2", 4), ("3", 5)] {
        let fx = Fx::new();
        let exact_other = size - sets * set - (set + set / 5) - keep_free;
        seed_volume(&fx, size, exact_other, set, 1000, keep);
        assert!(!headroom_warned(&fx), "KEEP {keep}: exactly fitting passes");
        seed_volume(&fx, size, exact_other + 1, set, 1000, keep);
        assert!(headroom_warned(&fx), "KEEP {keep}: one byte over warns");
    }
}

/// Sizes in the finding read to one decimal in MiB and GiB, rounded half up, and a size that rounds
/// up to 1024.0M is written as 1G rather than "1024M".
#[test]
fn sizes_in_the_finding_round_and_never_read_1024m() {
    // 4 sets of this size are named in "sets of about X"; the 100 MiB volume cannot hold the 512 MiB
    // reserve, so the finding is raised whatever the size.
    let about = |set: u64| -> String {
        let fx = Fx::new();
        seed_volume(&fx, 100 * MIB, 0, set, 1000, "1");
        let v = fx.json();
        let msg = headroom_finding(&v)["message"]
            .as_str()
            .unwrap()
            .to_string();
        let rest = msg.split("sets of about ").nth(1).expect("sets of about");
        rest.split(' ').next().unwrap().to_string()
    };
    // Just under and just at the half-tenth: 5.04999 MiB reads 5M, 5.05000095 MiB reads 5.1M.
    assert_eq!(about(5 * MIB + 52_428), "5M");
    assert_eq!(about(5 * MIB + 52_429), "5.1M");
    // The last byte count that reads in MiB, and the first that reads as a GiB.
    assert_eq!(about(1_073_689_395), "1023.9M");
    assert_eq!(about(1_073_689_396), "1G");
    assert_eq!(about(1_073_741_823), "1G");
    assert_eq!(about(1_073_741_824), "1G");
}

/// The backup row itself goes to warn (not left ok) and says why, unless a worse state already holds it.
#[test]
fn a_retention_that_cannot_fit_raises_the_backup_row_to_warn() {
    let fx = Fx::new();
    let row = |v: &serde_json::Value| {
        v["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == "backup")
            .unwrap()
            .clone()
    };
    seed_incident(&fx, "3");
    let g = row(&fx.json());
    assert_eq!(g["state"], "ok", "{g}");
    seed_incident(&fx, "7");
    let g = row(&fx.json());
    assert_eq!(g["state"], "warn", "{g}");
    assert!(
        g["text"]
            .as_str()
            .unwrap()
            .contains("retention too large for the volume"),
        "{g}"
    );
}

/// The unit's own PROPOLIS_BACKUP_DIR is the directory measured when the test hook is not set.
#[test]
fn the_units_backup_directory_is_the_one_measured() {
    let fx = Fx::new();
    seed_incident(&fx, "7");
    let unit_dir = fx.p("state/unit-sets");
    std::fs::create_dir_all(&unit_dir).unwrap();
    fx.write(
        "state/backup_env",
        &format!(
            "PROPOLIS_BACKUP_KEEP=7 PROPOLIS_BACKUP_DIR={}\n",
            unit_dir.display()
        ),
    );
    let v = fx
        .run_with(&["--json"], &[("PROPOLIS_CC_BACKUP_DIR", "")])
        .json();
    let msg = headroom_finding(&v)["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        msg.contains(&format!("{}'s 17G volume", unit_dir.display())),
        "{msg}"
    );
}

/// PROPOLIS_BACKUP_KEEP outside 1..=365 is one backup.sh refuses to run with, so there is no
/// retention to size; the ends of the range are in it.
#[test]
fn the_keep_range_matches_backup_sh() {
    let fx = Fx::new();
    // 10 GiB holding 7.2 GiB: even KEEP 1 (1 + 3 sets) cannot fit with the next set and the 15%.
    for (keep, warns) in [
        ("1", true),
        ("365", true),
        ("007", true),
        ("", true),
        ("0", false),
        ("366", false),
        ("1000", false),
        ("x", false),
    ] {
        seed_volume(&fx, 10 * GIB, INCIDENT_OTHER, INCIDENT_SET, 1000, keep);
        assert_eq!(headroom_warned(&fx), warns, "KEEP {keep:?}");
    }
}

/// The threshold is read as the daemon reads it (whitespace around the key, the '=' and the value,
/// a leading '+', leading zeros; the last assignment wins; a value the daemon refuses leaves 15),
/// and backup.sh reads it the same way: backup_script_test.rs runs this same table.
#[test]
fn the_threshold_is_parsed_as_the_daemon_parses_it() {
    for (line, pct) in LOW_DISK_TABLE {
        let fx = Fx::new();
        seed_incident(&fx, "7");
        fx.set_env_line("etc/propolis.env", "PROPOLIS_OPS_CAPACITY_FREE_PCT=", None);
        let env = fx.read("etc/propolis.env");
        fx.write("etc/propolis.env", &format!("{env}{line}\n"));
        let v = fx.json();
        let msg = headroom_finding(&v)["message"]
            .as_str()
            .unwrap()
            .to_string();
        let want = format!("the larger of the {pct}% low-disk threshold");
        assert!(msg.contains(&want), "{line:?} should read as {pct}: {msg}");
    }
}

/// Lines of propolis.env and the percentage each means. Every one is at least the default 15, so the
/// 14%-free volume in backup_script_test.rs refuses under all of them and names the figure it used.
/// One table (fixtures/low_disk_table.in) for both scripts' tests.
const LOW_DISK_TABLE: &[(&str, u32)] = include!("fixtures/low_disk_table.in");

/// config-check.sh and backup.sh each carry the daemon's default and the guard's reserve; they must
/// carry the same ones.
#[test]
fn the_headroom_constants_match_backup_sh() {
    let read = |rel: &str| {
        std::fs::read_to_string(format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    };
    let check = read("deploy/config-check.sh");
    let backup = read("deploy/backup.sh");
    for line in [
        "DEFAULT_LOW_DISK_PCT=15\n",
        "LOGROTATE_RESERVE_BYTES=536870912\n",
    ] {
        assert!(check.contains(line), "config-check.sh lacks {line:?}");
        assert!(backup.contains(line), "backup.sh lacks {line:?}");
    }
}

/// The staleness limit is the one the daemon alerts on, PROPOLIS_OPS_BACKUP_MAX_AGE_SECS when it
/// is set, and a run from before DATABASE_URL existed reads as never-ran, not as a failure.
#[test]
fn backup_staleness_follows_the_configured_limit_and_not_configured_is_not_a_failure() {
    let fx = Fx::new();
    fx.write(
        "state/backup-status/last-success",
        &format!(
            "{{\"completed_at\":\"{}\",\"reason\":\"scheduled\",\"set\":\"x\",\"encrypted\":true}}\n",
            iso(NOW - 2 * 86_400)
        ),
    );
    let ids = |fx: &Fx| -> Vec<String> {
        fx.json()["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(ids(&fx).contains(&"backup-stale".to_string()));
    fx.set_env_line(
        "etc/propolis.env",
        "PROPOLIS_OPS_BACKUP_MAX_AGE_SECS=",
        Some("PROPOLIS_OPS_BACKUP_MAX_AGE_SECS=259200"),
    );
    assert!(!ids(&fx).contains(&"backup-stale".to_string()));

    std::fs::remove_file(fx.p("state/backup-status/last-success")).unwrap();
    fx.write(
        "state/backup-status/last-failure",
        "{\"failed_at\":\"x\",\"reason\":\"scheduled\",\"step\":\"not configured: no DATABASE_URL in /etc/propolis/propolis.env\",\"exit_code\":0}\n",
    );
    let found = ids(&fx);
    assert!(found.contains(&"backup-never".to_string()), "{found:?}");
    assert!(!found.contains(&"backup-failing".to_string()), "{found:?}");
}

/// `epoch` as the backup script writes its timestamps.
fn iso(epoch: u64) -> String {
    let out = Command::new("date")
        .args(["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn every_finding_has_a_fix_that_is_a_command_run_as_pasted_or_a_labelled_manual_step() {
    let ids = script_finding_ids();
    let expected: std::collections::BTreeSet<String> = ids.iter().cloned().collect();
    assert_eq!(
        ids.len(),
        expected.len(),
        "each finding call site needs its own id (the key prefix before ':'): {ids:?}"
    );
    assert!(
        expected.len() >= 45,
        "the id enumeration found too few call sites ({}): is the finding(...) layout changed?",
        expected.len()
    );

    let mut seen = std::collections::BTreeSet::new();
    let mut runs = 0;
    let mut manuals = 0;
    for (name, build) in fix_scenarios() {
        let fx = Fx::new();
        fx.install_fix_stubs();
        build(&fx);
        let v = fx.json();
        for f in v["findings"].as_array().unwrap() {
            let id = f["id"].as_str().unwrap();
            let kind = f["fix_kind"].as_str().unwrap();
            let fix = f["fix"].as_str().unwrap();
            assert!(
                expected.contains(id),
                "{name}: the script raised id {id:?} that the source enumeration does not list"
            );
            let what = format!("scenario '{name}', finding {id}");
            assert_fix_contract(&fx, &what, id, kind, fix);
            match kind {
                "run" => runs += 1,
                "manual" => manuals += 1,
                _ => {}
            }
            seen.insert(id.to_string());
        }
    }
    let missing: Vec<&String> = expected.difference(&seen).collect();
    assert!(
        missing.is_empty(),
        "findings no scenario exercises (add a fixture that raises each, so its fix is checked): {missing:?}"
    );
    assert!(runs > 40 && manuals > 8, "runs {runs}, manuals {manuals}");
}

/// The witness records config-check's findings by deploy/witness.sh's WITNESS_CC_TABLE, and an id
/// with no row there is never recorded: so every id this script emits has exactly one row, every
/// row names an id the script emits, and every page row has a tier, a stage, a way to find its
/// instance and the phrase a push will carry.
#[test]
fn every_finding_id_has_a_witness_eligibility_row() {
    let witness = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/witness.sh"
    ))
    .unwrap();
    let start = witness
        .find("WITNESS_CC_TABLE='\n")
        .expect("deploy/witness.sh has WITNESS_CC_TABLE")
        + "WITNESS_CC_TABLE='\n".len();
    let end = start + witness[start..].find("\n'\n").unwrap();
    let mut rows = std::collections::BTreeMap::new();
    for line in witness[start..end].lines() {
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(f.len(), 7, "{line}");
        assert!(
            rows.insert(f[0].to_string(), f).is_none(),
            "{line}: a second row"
        );
    }
    let ids: std::collections::BTreeSet<String> = script_finding_ids().into_iter().collect();
    for id in &ids {
        assert!(rows.contains_key(id), "{id} has no row in WITNESS_CC_TABLE");
    }
    for (id, f) in &rows {
        assert!(
            ids.contains(id),
            "row {id} names no id deploy/config-check.sh emits"
        );
        match f[1] {
            "page" => {
                assert!(["PAGE", "ACT"].contains(&f[2]), "{id}: {}", f[2]);
                assert!(
                    ["unit", "scope", "logpath", "fold", "-"].contains(&f[5]),
                    "{id}: {}",
                    f[5]
                );
                assert!(f[6] != "-" && !f[6].is_empty(), "{id} has no phrase");
                assert_eq!(f[6].contains("<inst>"), f[5] != "-", "{id}: {}", f[6]);
            }
            "daily" => assert_eq!(f[2], "NOTICE", "{id}"),
            "never" => assert_eq!(f[2], "-", "{id}"),
            other => panic!("{id}: eligibility {other}"),
        }
        assert!(
            !f[3].is_empty() && !f[4].is_empty(),
            "{id}: a stage and a row"
        );
    }
    let pages = rows.values().filter(|f| f[1] == "page").count();
    assert_eq!(pages, 16, "the sixteen page rows");
}

/// A host with Propolis units enabled and no witness, or with one of its two timers not enabled,
/// gets a warning on the witness row with the fix for each; a collector, which has no upgrade
/// script to run, gets the written steps. A missing /run directory is named on the row.
#[test]
fn witness_missing_and_witness_timer_are_warnings_on_the_witness_row() {
    let witness_row = |v: &serde_json::Value| {
        v["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == "witness")
            .cloned()
            .unwrap()
    };
    let finding = |v: &serde_json::Value, id: &str| {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .cloned()
    };
    let fx = Fx::new();
    let v = fx.json();
    assert_eq!(witness_row(&v)["state"], "ok", "{}", witness_row(&v));
    assert!(finding(&v, "witness-missing").is_none() && finding(&v, "witness-timer").is_none());

    let fx = Fx::new();
    std::fs::remove_file(fx.p("sbin/propolis-witness")).unwrap();
    let v = fx.json();
    let f = finding(&v, "witness-missing").unwrap();
    assert_eq!(
        (f["level"].as_str(), f["fix_kind"].as_str()),
        (Some("warn"), Some("run"))
    );
    assert!(f["fix"].as_str().unwrap().ends_with("upgrade.sh"), "{f}");
    assert_eq!(witness_row(&v)["state"], "warn");
    fx.write("etc/shipper.env", "PROPOLIS_SHIPPER_SENSOR_LOGS=\n");
    let f = finding(&fx.json(), "witness-missing").unwrap();
    assert_eq!(f["fix_kind"], "manual", "{f}");
    assert!(
        f["fix"].as_str().unwrap().contains("split-deployment.md"),
        "{f}"
    );

    let fx = Fx::new();
    fx.unit("propolis-witness@light.timer", "disabled", "inactive");
    let v = fx.json();
    let f = finding(&v, "witness-timer").unwrap();
    assert_eq!(f["level"], "warn");
    assert_eq!(
        f["fix"],
        "sudo systemctl enable --now propolis-witness@light.timer propolis-witness@hourly.timer"
    );
    assert!(
        f["message"]
            .as_str()
            .unwrap()
            .contains("propolis-witness@light.timer disabled"),
        "{f}"
    );

    let fx = Fx::new();
    std::fs::remove_dir(fx.p("alert-root/run/propolis-witness")).unwrap();
    let v = fx.json();
    assert_eq!(witness_row(&v)["state"], "warn");
    assert!(
        witness_row(&v)["text"]
            .as_str()
            .unwrap()
            .contains("is missing (the tmpfiles entry"),
        "{}",
        witness_row(&v)
    );
}

#[test]
fn the_newest_event_mode_reaches_the_ledger_through_the_environment_never_an_argument() {
    // The fix line for a silent sensor runs this mode. The password-bearing URL must reach psql
    // only as PG* variables, whether the env file quotes the value or not.
    let url = "postgres://u:p%40ss@db.example.invalid:5432/propolis?sslmode=require&options=-c%20x";
    for quoted in [format!("\"{url}\""), format!("'{url}'"), url.to_string()] {
        let fx = Fx::new();
        fx.set_env_line(
            "etc/propolis.env",
            "DATABASE_URL=",
            Some(&format!("DATABASE_URL={quoted}")),
        );
        fx.write("state/psql_out", "2027-01-01 00:00:00+00\n");
        let r = fx.run(&["--newest-event", "postgresql"]);
        assert_eq!(r.code, 0, "{quoted}: {}{}", r.out, r.err);
        assert!(
            r.has("sensor postgresql: newest event 2027-01-01 00:00:00+00"),
            "{}",
            r.out
        );
        let log = fx.read("state/psql.log");
        let argv = log.lines().find(|l| l.starts_with("ARGV:")).unwrap();
        assert!(
            argv.contains("SELECT max(observed_at) FROM event WHERE sensor = 'postgresql'"),
            "{argv}"
        );
        for secret in ["p%40ss", "p@ss", "postgres://", "db.example.invalid"] {
            assert!(
                !argv.contains(secret),
                "{secret} reached psql's argv: {argv}"
            );
        }
        assert!(log.lines().any(|l| l == "PGPASSWORD=p@ss"), "{log}");
        assert!(
            log.lines().any(|l| l == "PGHOST=db.example.invalid"),
            "{log}"
        );
        assert!(
            log.lines()
                .any(|l| l.starts_with("PGOPTIONS=")
                    && l.contains("default_transaction_read_only=on")),
            "{log}"
        );
        assert!(!r.out.contains("p%40ss") && !r.err.contains("p%40ss"));
    }
    // A name that is not a plain sensor name is refused before any query (it is interpolated).
    let fx = Fx::new();
    let r = fx.run(&["--newest-event", "x'; DROP TABLE event; --"]);
    assert_eq!(r.code, 64, "{}", r.err);
    assert!(!fx.p("state/psql.log").exists());
    // Without a readable URL it fails loudly instead of printing an empty answer.
    let fx = Fx::new();
    fx.set_env_line("etc/propolis.env", "DATABASE_URL=", None);
    let r = fx.run(&["--newest-event", "ssh"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no DATABASE_URL"), "{}", r.err);
}

#[test]
fn the_report_prints_fix_for_commands_and_do_for_manual_steps_and_json_carries_the_kind() {
    let fx = Fx::new();
    // A disabled unit (a command) and a missing intake entry (an instruction) in one report.
    fx.unit("sensor-ssh.service", "disabled", "inactive");
    let logs = fx.logs();
    let line = format!(
        "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
    );
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", Some(&line));
    let r = fx.run(&[]);
    assert!(
        r.has("        fix: sudo systemctl enable --now sensor-ssh.service\n"),
        "{}",
        r.out
    );
    assert!(
        r.has("        do:  append ,mqtt:"),
        "an instruction is not printed as a fix:\n{}",
        r.out
    );
    assert!(
        !r.out
            .lines()
            .any(|l| l.trim_start().starts_with("fix: append")),
        "{}",
        r.out
    );
    let kinds: Vec<(String, String)> = fx.json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_str().unwrap().to_string(),
                f["fix_kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        kinds.contains(&("unit-disabled".into(), "run".into()))
            && kinds.contains(&("intake-absent".into(), "manual".into())),
        "{kinds:?}"
    );
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
    // The line that runs the check names the script and --report-only. Other lines may name the
    // script (the one that installs the copy under /usr/local/lib/propolis), never both.
    let runs_check = |l: &&str| l.contains("config-check.sh") && l.contains("--report-only");
    let last = *code.last().unwrap();
    assert!(
        runs_check(&last) && last.contains("||"),
        "the last command of upgrade.sh must run the check in report-only mode and tolerate its failure: {last}"
    );
    let status_at = code
        .iter()
        .position(|l| l.contains("systemctl --no-pager status propolis.service"))
        .unwrap();
    let check_at = code.iter().position(runs_check).unwrap();
    assert!(
        check_at > status_at,
        "the check must follow the restarts and the status line"
    );
    assert_eq!(code.iter().filter(|l| runs_check(l)).count(), 1);
    // A run without --report-only would stop the upgrade under set -e once the binaries are in.
    assert_eq!(
        early_check_runs(&text),
        Vec::<String>::new(),
        "only the last line of upgrade.sh may run the check"
    );
    let doctored = text.replacen(
        "systemctl daemon-reload\n",
        "\"$SCRIPT_DIR/config-check.sh\" --no-events\nsystemctl daemon-reload\n",
        1,
    );
    assert_ne!(doctored, text);
    assert_eq!(
        early_check_runs(&doctored),
        ["\"$SCRIPT_DIR/config-check.sh\" --no-events"]
    );
}

/// The code lines of `text` before its last one that name config-check.sh and do not install it.
fn early_check_runs(text: &str) -> Vec<String> {
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    code[..code.len() - 1]
        .iter()
        .filter(|l| l.contains("config-check.sh") && !l.starts_with("install "))
        .map(|l| l.to_string())
        .collect()
}

fn global_state(v: &serde_json::Value, id: &str) -> String {
    v["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == id)
        .map(|g| g["state"].as_str().unwrap().to_string())
        .unwrap_or_else(|| "absent".into())
}

/// Each intake log with content needs a cursor the rotation guard can find, named by the SHA-256 of
/// the log's resolved path (the same rule the daemon and the guard use).
#[test]
fn each_intake_log_with_content_needs_a_cursor_file_and_a_visible_cursor_directory() {
    use sha2::{Digest, Sha256};
    let fx = Fx::new();
    let before = fx.json();
    assert_eq!(
        global_state(&before, "cursors"),
        "skip",
        "no cursor dir yet"
    );

    // The directory exists but holds no cursor for the logs: every one is named.
    fx.write("state/cursors/unrelated.json", "{}");
    let v = fx.json();
    assert_eq!(global_state(&v, "cursors"), "warn");
    let msgs = v["findings"].to_string();
    for log in ["ssh", "mqtt", "dns", "tftp"] {
        assert!(
            msgs.contains(&format!(
                "no cursor file for {}",
                fx.p(&format!("logs/{log}/events.jsonl")).display()
            )),
            "{log}: {msgs}"
        );
    }

    // Cursors in place for all five: green.
    for rel in [
        "logs/ssh/events.jsonl",
        "logs/mqtt/events.jsonl",
        "logs/dns/events.jsonl",
        "logs/tftp/events.jsonl",
        "logs/cred/postgresql.jsonl",
    ] {
        let resolved = std::fs::canonicalize(fx.p(rel)).unwrap();
        let hash: String = Sha256::digest(resolved.to_str().unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fx.write(&format!("state/cursors/{hash}.json"), "{}");
    }
    let green = fx.json();
    assert_eq!(
        global_state(&green, "cursors"),
        "ok",
        "{}",
        green["findings"]
    );

    // A cursor directory moved off the default is invisible to the rotation unit until a drop-in
    // names it.
    fx.set_env_line(
        "etc/propolis.env",
        "PROPOLIS_CURSOR_DIR=",
        Some("PROPOLIS_CURSOR_DIR=/srv/propolis-cursors"),
    );
    assert!(
        fx.json()["findings"]
            .to_string()
            .contains("does not read that file")
    );
    fx.write(
        "etc-logrotate/dropin/cursor-dir.conf",
        "[Service]\nEnvironment=PROPOLIS_CURSOR_DIR=/srv/propolis-cursors\n",
    );
    assert!(
        !fx.json()["findings"]
            .to_string()
            .contains("does not read that file")
    );
}

/// On a collector the sensor logs are read by the shipper, which keeps its cursors in its own
/// directory (crates/shipper/src/config.rs DEFAULT_CURSOR_DIR, or PROPOLIS_SHIPPER_CURSOR_DIR) and
/// saves a log's first one when a ship cycle starts reading the log (crates/shipper/src/client.rs
/// ship_cycle), which needs a connection to the gateway and no other log's batch in flight, not
/// an accepted batch. The finding must send the operator to that unit and that directory, not to
/// an intake this host does not run, and must give the reasons that hold.
#[test]
fn a_missing_cursor_on_a_collector_names_the_shipper_its_unit_and_its_cursor_directory() {
    use sha2::{Digest, Sha256};
    let fx = Fx::new();
    let logs = fx.logs();
    let list = format!(
        "PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
    );
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", None);
    let shipper_dir = fx.p("state/shipper-cursors");
    fx.write(
        "etc/shipper.env",
        &format!(
            "{list}\nPROPOLIS_SHIPPER_CURSOR_DIR={}\n",
            shipper_dir.display()
        ),
    );
    fx.write("state/shipper-cursors/unrelated.json", "{}");
    // A leftover intake cursor directory holding a cursor for every log must not count: on a
    // collector only the shipper's cursors say how far a log was read.
    let intake_dir = fx.p("state/intake-cursors");
    fx.set_env_line(
        "etc/propolis.env",
        "PROPOLIS_CURSOR_DIR=",
        Some(&format!("PROPOLIS_CURSOR_DIR={}", intake_dir.display())),
    );
    for rel in [
        "logs/ssh/events.jsonl",
        "logs/mqtt/events.jsonl",
        "logs/dns/events.jsonl",
        "logs/tftp/events.jsonl",
        "logs/cred/postgresql.jsonl",
    ] {
        let resolved = std::fs::canonicalize(fx.p(rel)).unwrap();
        let hash: String = Sha256::digest(resolved.to_str().unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fx.write(&format!("state/intake-cursors/{hash}.json"), "{}");
    }
    // No test override, so the directory is the one the script itself derives.
    let v = fx
        .run_with(&["--json"], &[("PROPOLIS_CC_CURSOR_DIR", "")])
        .json();
    assert_eq!(global_state(&v, "cursors"), "warn", "{}", v["global"]);
    let missing: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == "cursor-missing")
        .collect();
    assert_eq!(missing.len(), 5, "{}", v["findings"]);
    let ssh = missing
        .iter()
        .find(|f| {
            f["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{logs}/ssh/events.jsonl"))
        })
        .unwrap_or_else(|| panic!("no finding for the ssh log: {missing:?}"));
    let msg = ssh["message"].as_str().unwrap();
    let fix = ssh["fix"].as_str().unwrap();
    assert!(
        msg.contains(&format!("in {}", shipper_dir.display())),
        "the shipper's cursor directory: {msg}"
    );
    assert!(msg.contains("the shipper"), "{msg}");
    assert!(msg.contains("shipper.service"), "{msg}");
    assert!(
        msg.contains("when a ship cycle starts reading the log")
            && msg.contains("cannot reach the gateway")
            && msg.contains("another log's batch is in flight"),
        "{msg}"
    );
    // The cursor is saved before any batch is sent, so neither an accepted batch nor a log the
    // shipper cannot read decides whether it exists.
    assert!(!msg.contains("accepts a batch"), "{msg}");
    assert!(!msg.contains("cannot read the log"), "{msg}");
    assert!(!msg.contains("intake"), "no intake on a collector: {msg}");
    assert!(
        fix.contains("journalctl -u shipper.service"),
        "the shipper's journal: {fix}"
    );
    // The shipper's errors carry the log's label as sensor=, which is how its journal is read.
    assert!(fix.contains("sensor=ssh"), "{fix}");
    assert!(!fix.contains("propolis.service"), "{fix}");
    assert_eq!(ssh["fix_kind"], "manual");
}

/// The daemon and the failure hook both push only with PROPOLIS_OPS_NTFY_URL and
/// PROPOLIS_OPS_NTFY_TOPIC set (crates/propolis/src/ops_alert/config.rs parse_ops_alert,
/// deploy/alert.sh). Every combination of the monitor switch and the two values is told as it is.
#[test]
fn alerting_is_reported_truthfully_for_every_combination_of_the_switch_the_url_and_the_topic() {
    struct Row {
        enabled: bool,
        url: bool,
        topic: bool,
        state: &'static str,
        ids: &'static [&'static str],
        pushes: bool,
        missing: Option<&'static str>,
        // A topic line written as it stands in the file, in place of the plain one.
        topic_line: Option<&'static str>,
        // Text the alerting row must contain, for rows where the two readers disagree.
        row_has: Option<&'static str>,
        // Text the push finding's message must, and must not, contain.
        says: &'static [&'static str],
        never_says: &'static [&'static str],
    }
    let rows = [
        Row {
            enabled: true,
            url: true,
            topic: true,
            state: "ok",
            ids: &[],
            pushes: true,
            missing: None,
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: true,
            url: true,
            topic: false,
            state: "fail",
            ids: &["ops-push-half"],
            pushes: false,
            missing: Some("PROPOLIS_OPS_NTFY_TOPIC"),
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: true,
            url: false,
            topic: true,
            state: "fail",
            ids: &["ops-push-half"],
            pushes: false,
            missing: Some("PROPOLIS_OPS_NTFY_URL"),
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: true,
            url: false,
            topic: false,
            state: "warn",
            ids: &["ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: false,
            url: true,
            topic: true,
            state: "warn",
            ids: &["ops-monitor-off"],
            pushes: true,
            missing: None,
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: false,
            url: true,
            topic: false,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: Some("PROPOLIS_OPS_NTFY_TOPIC"),
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: false,
            url: false,
            topic: true,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: Some("PROPOLIS_OPS_NTFY_URL"),
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        Row {
            enabled: false,
            url: false,
            topic: false,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: None,
            row_has: None,
            says: &[],
            never_says: &[],
        },
        // Unquoted spaces only: systemd trims them, so the daemon sees no topic and refuses to
        // start, however set the line looks.
        Row {
            enabled: true,
            url: true,
            topic: false,
            state: "fail",
            ids: &["ops-push-half"],
            pushes: false,
            missing: Some("PROPOLIS_OPS_NTFY_TOPIC"),
            topic_line: Some("PROPOLIS_OPS_NTFY_TOPIC=   "),
            row_has: None,
            says: &[],
            never_says: &[],
        },
        // An indented line: the unit gets the topic, but deploy/alert.sh reads only lines that
        // start with the name, so the failure hook has no push target.
        Row {
            enabled: false,
            url: true,
            topic: true,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: Some("  PROPOLIS_OPS_NTFY_TOPIC=propolis-ops"),
            row_has: Some("journal only"),
            says: &[],
            never_says: &[],
        },
        // The same with the monitor on: the daemon pushes its own alerts, the hook does not.
        Row {
            enabled: true,
            url: true,
            topic: true,
            state: "warn",
            ids: &["ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: Some("  PROPOLIS_OPS_NTFY_TOPIC=propolis-ops"),
            row_has: Some("ntfy for the daemon only, failure hook journal only"),
            says: &["pushes its own alerts"],
            never_says: &[],
        },
        // A quoted space: systemd keeps it and deploy/alert.sh strips only the quotes, so both
        // readers see a topic and both push. Nothing is indented and nothing is missing.
        Row {
            enabled: true,
            url: true,
            topic: true,
            state: "ok",
            ids: &[],
            pushes: true,
            missing: None,
            topic_line: Some("PROPOLIS_OPS_NTFY_TOPIC=' '"),
            row_has: None,
            says: &[],
            never_says: &[],
        },
        // An unindented line the hook reads as empty: systemd removes the pair of double quotes
        // and keeps the single quote, deploy/alert.sh removes one quote of each kind from each end
        // and is left with nothing. The check must not blame indentation that is not there.
        Row {
            enabled: false,
            url: true,
            topic: true,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: Some("PROPOLIS_OPS_NTFY_TOPIC=\"'\""),
            row_has: Some("journal only"),
            says: &[
                "PROPOLIS_OPS_NTFY_TOPIC",
                "failure hook",
                "does not see",
                "journal",
            ],
            never_says: &["indented"],
        },
        // A value the hook sees and the daemon does not: systemd trims the unquoted spaces to
        // nothing, deploy/alert.sh keeps them and posts. The hook is not journal-only.
        Row {
            enabled: false,
            url: true,
            topic: false,
            state: "warn",
            ids: &["ops-monitor-off", "ops-no-push"],
            pushes: false,
            missing: None,
            topic_line: Some("PROPOLIS_OPS_NTFY_TOPIC=   "),
            row_has: Some("ntfy for the failure hook only"),
            says: &[
                "PROPOLIS_OPS_NTFY_TOPIC",
                "failure hook",
                "posts",
                "refuse to start",
            ],
            never_says: &["journal", "indented"],
        },
    ];
    for row in rows {
        let what = format!(
            "enabled={} url={} topic={} topic_line={:?}",
            row.enabled, row.url, row.topic, row.topic_line
        );
        let fx = Fx::new();
        fx.set_env_line(
            "etc/propolis.env",
            "PROPOLIS_OPS_ENABLED=",
            Some(&format!("PROPOLIS_OPS_ENABLED={}", row.enabled)),
        );
        if !row.url {
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_OPS_NTFY_URL=",
                Some("PROPOLIS_OPS_NTFY_URL="),
            );
        }
        if !row.topic {
            fx.set_env_line(
                "etc/propolis.env",
                "PROPOLIS_OPS_NTFY_TOPIC=",
                Some("PROPOLIS_OPS_NTFY_TOPIC="),
            );
        }
        if let Some(line) = row.topic_line {
            fx.set_env_line("etc/propolis.env", "PROPOLIS_OPS_NTFY_TOPIC=", Some(line));
        }
        let v = fx.json();
        assert_eq!(
            global_state(&v, "alerting"),
            row.state,
            "{what}: {}",
            v["global"]
        );
        let ops: Vec<&serde_json::Value> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["scope"] == "alerting")
            .collect();
        let ids: Vec<&str> = ops.iter().map(|f| f["id"].as_str().unwrap()).collect();
        assert_eq!(ids, row.ids, "{what}: {}", v["findings"]);
        let text = global_text(&v, "alerting");
        assert_eq!(
            text.split(", ").any(|p| p == "ntfy"),
            row.pushes,
            "{what}: the alerting row says ntfy only when both values are set: {text}"
        );
        if let Some(part) = row.row_has {
            assert!(text.contains(part), "{what}: {text}");
        } else if !row.pushes {
            assert!(!text.contains("ntfy"), "{what}: {text}");
        }
        let push_finding = ops
            .iter()
            .find(|f| f["id"] == "ops-push-half" || f["id"] == "ops-no-push");
        assert!(
            push_finding.is_some() || (row.says.is_empty() && row.never_says.is_empty()),
            "{what}: no push finding to check: {}",
            v["findings"]
        );
        if let Some(f) = push_finding {
            let msg = f["message"].as_str().unwrap();
            let fix = f["fix"].as_str().unwrap();
            for s in row.says {
                assert!(msg.contains(s), "{what}: says {s:?}: {msg}");
            }
            for s in row.never_says {
                assert!(!msg.contains(s), "{what}: never says {s:?}: {msg}");
            }
            let indented = row.topic_line.is_some_and(|l| l.starts_with(' '));
            // Indentation is named only where the file really has it.
            assert!(
                indented || !(msg.contains("indented") || fix.contains("whitespace before")),
                "{what}: {msg} / {fix}"
            );
            if indented {
                // The target is set; only where it is written keeps the hook from it.
                assert!(
                    msg.contains("PROPOLIS_OPS_NTFY_TOPIC")
                        && msg.contains("indented")
                        && msg.contains("failure hook")
                        && msg.contains("journal"),
                    "{what}: {msg}"
                );
                assert!(
                    fix.contains("remove the whitespace before PROPOLIS_OPS_NTFY_TOPIC="),
                    "{what}: {fix}"
                );
            } else {
                assert!(
                    fix.contains("read access is restricted to you")
                        && fix.contains("anyone who knows the topic name can read the alerts"),
                    "{what}: {fix}"
                );
            }
            if row.enabled
                && let Some(var) = row.missing
            {
                // The other way out: empty the one that is set, for journal-only alerts.
                let set = if var == "PROPOLIS_OPS_NTFY_TOPIC" {
                    "PROPOLIS_OPS_NTFY_URL"
                } else {
                    "PROPOLIS_OPS_NTFY_TOPIC"
                };
                assert!(fix.contains(&format!("empty {set}")), "{what}: {fix}");
            }
            if let Some(var) = row.missing {
                assert!(
                    msg.contains(&format!("{var} is empty")),
                    "{what}: the message names the missing variable: {msg}"
                );
                assert!(fix.contains(&format!("set {var}")), "{what}: {fix}");
            }
            if row.enabled && row.missing.is_some() {
                assert_eq!(f["level"], "fail", "{what}");
                assert!(
                    msg.contains("the daemon will not start with this file"),
                    "{what}: {msg}"
                );
            }
            if !row.enabled && row.missing.is_some() {
                assert!(
                    msg.contains("failure hook") && msg.contains("journal"),
                    "{what}: {msg}"
                );
            }
        }
    }
}

// ---- gateway spool -------------------------------------------------------------------------

#[test]
fn a_host_without_a_gateway_spool_gets_no_spool_finding_and_no_spool_row() {
    let fx = Fx::new();
    // A gateway.env alone (a control plane being set up) is not a spool either.
    fx.write("etc/gateway.env", "PROPOLIS_GATEWAY_BIND=0.0.0.0:9443\n");
    let r = fx.run(&["--json"]);
    let v = r.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "absent",
        "{}",
        v["global"]
    );
    assert_eq!(r.code, 0, "{}", r.out);
    let table = fx.run(&[]);
    assert!(!table.has("gateway-spool"), "{}", table.out);
    assert!(!table.has("spool"), "no noise about a spool: {}", table.out);
}

#[test]
fn a_collector_spool_missing_from_the_daemons_list_is_a_failure_that_names_the_collector() {
    let fx = Fx::new();
    let path = fx.spool("collector-07", 4096, NOW - 3 * 86_400);
    let r = fx.run(&["--json"]);
    assert_eq!(r.code, 2, "{}", r.out);
    let v = r.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f["id"], "spool-unlisted");
    assert_eq!(f["level"], "fail");
    assert_eq!(f["fix_kind"], "manual");
    let msg = f["message"].as_str().unwrap();
    for needle in [
        "collector-07",
        "accepting and acknowledging",
        "not ingesting",
        path.as_str(),
        "4K",
        "3d",
    ] {
        assert!(msg.contains(needle), "{needle:?} not in: {msg}");
    }
    let fix = f["fix"].as_str().unwrap();
    assert!(
        fix.contains(&format!(",collector-07:{path} ")),
        "the exact entry, labelled with the collector id: {fix}"
    );
    assert!(
        fix.contains("sudo systemctl restart propolis.service"),
        "{fix}"
    );
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
    let table = fx.run(&[]);
    assert!(
        table.has("        do:  append ,collector-07:"),
        "{}",
        table.out
    );
}

#[test]
fn a_spool_listed_under_its_collector_id_gets_neither_spool_finding() {
    let fx = Fx::new();
    let a = fx.spool("collector-01", 200, NOW - 60);
    fx.spool("collector-02", 200, NOW - 60);
    // The second is listed by a path that is the same file written differently.
    let b = format!("{}//collector-02/./events.jsonl", fx.spool_dir());
    fx.add_intake_entries(&format!("collector-01:{a},collector-02:{b}"));
    let v = fx.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
}

#[test]
fn the_spool_directory_is_read_from_gateway_env_as_the_unit_reads_it() {
    let fx = Fx::new();
    let other = fx.p("srv/gateway-spool");
    fx.write(
        "etc/gateway.env",
        &format!(
            "PROPOLIS_GATEWAY_BIND=0.0.0.0:9443\nPROPOLIS_GATEWAY_SPOOL_DIR={}\n",
            other.display()
        ),
    );
    fx.log("srv/gateway-spool/collector-05/events.jsonl", 10, NOW - 60);
    // The unit's default holds a collector too; gateway.env moved the spool away from it.
    fx.spool("collector-99", 10, NOW - 60);
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let msg = found[0]["message"].as_str().unwrap();
    assert!(msg.contains("collector-05"), "{msg}");
    assert!(!v["findings"].to_string().contains("collector-99"));
}

#[test]
fn a_spool_entry_under_a_sensors_name_fails_and_under_another_name_warns() {
    let fx = Fx::new();
    let a = fx.spool("collector-01", 200, NOW - 60);
    let b = fx.spool("collector-02", 200, NOW - 60);
    let c = fx.spool("collector-03", 200, NOW - 60);
    fx.add_intake_entries(&format!("telnet:{a},edge-box:{b},cred-mongo:{c}"));
    let v = fx.json();
    let found = spool_findings(&v);
    let by =
        |id: &str| -> Vec<&serde_json::Value> { found.iter().filter(|f| f["id"] == id).collect() };
    let bound = by("spool-label-sensor");
    assert_eq!(bound.len(), 2, "{found:?}");
    for f in &bound {
        assert_eq!(f["level"], "fail");
        assert_eq!(f["fix_kind"], "manual");
        let msg = f["message"].as_str().unwrap();
        assert!(msg.contains("refused"), "{msg}");
    }
    let telnet = bound
        .iter()
        .find(|f| f["message"].as_str().unwrap().contains("'telnet'"))
        .expect("the telnet-labelled entry");
    assert!(
        telnet["message"].as_str().unwrap().contains("collector-01"),
        "{telnet}"
    );
    assert!(
        telnet["fix"]
            .as_str()
            .unwrap()
            .contains(&format!("collector-01:{a}")),
        "{telnet}"
    );
    let cred = bound
        .iter()
        .find(|f| f["message"].as_str().unwrap().contains("'cred-mongo'"))
        .expect("a cred-* label binds as well");
    assert!(
        cred["message"].as_str().unwrap().contains("mongodb"),
        "names the sensor it binds to: {cred}"
    );
    let other = by("spool-label-other");
    assert_eq!(other.len(), 1, "{found:?}");
    assert_eq!(other[0]["level"], "warn");
    let msg = other[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("'edge-box'") && msg.contains("collector-02"),
        "{msg}"
    );
    assert!(
        msg.contains("ingested") && msg.contains("alerts"),
        "says what the wrong name does and does not do: {msg}"
    );
    assert!(
        msg.contains("/metrics as collector=\"edge-box\""),
        "the capture counters carry the label too: {msg}"
    );
    assert!(by("spool-unlisted").is_empty(), "every spool is listed");
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
}

#[test]
fn an_unreadable_gateway_spool_is_a_limited_check_never_a_pass() {
    let fx = Fx::new();
    fx.spool("collector-07", 200, NOW - 60);
    let spool = fx.p("spool/gateway");
    // Root reads through any mode, so as root the run drops to nobody instead; the fixture's
    // own directories are opened for traversal and the spool stays root's at 0700.
    let wrapper: Vec<&str> = if is_root() {
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o700)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o000)).unwrap();
        vec![]
    };
    let r = fx.run_under(&wrapper, &["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let v = r.json();
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "unknown",
        "{}",
        v["global"]
    );
    assert!(
        v["limited"].as_array().unwrap().iter().any(|l| {
            let l = l.as_str().unwrap();
            l.contains("gateway spool") && l.contains("not checked")
        }),
        "{}",
        v["limited"]
    );
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_ne!(r.code, 0);
}

#[test]
fn hostile_collector_directory_names_are_cleaned_capped_and_never_executed() {
    let fx = Fx::new();
    let subst = "$(touch $STUB_STATE.pwned)";
    let backtick = "`touch $STUB_STATE.pwned2`; x";
    let escape = "esc\u{1b}[31mred";
    let long = "a".repeat(200);
    for name in [subst, backtick, escape, long.as_str()] {
        fx.spool(name, 10, NOW - 60);
    }
    let r = fx.run(&["--json"]);
    let v = r.json();
    let table = fx.run(&[]);
    assert!(!fx.p("state.pwned").exists() && !fx.p("state.pwned2").exists());
    assert!(r.out.is_ascii() && table.out.is_ascii(), "{}", table.out);
    assert!(!r.out.contains('\u{1b}') && !table.out.contains('\u{1b}'));

    let found = spool_findings(&v);
    let unlisted: Vec<&serde_json::Value> = found
        .iter()
        .filter(|f| f["id"] == "spool-unlisted")
        .collect();
    // A name with a control character is one the gateway never creates: it is not a collector.
    assert_eq!(unlisted.len(), 3, "{found:?}");
    assert!(!v["findings"].to_string().contains("[31mred"), "{found:?}");
    assert!(
        v["global"].to_string().contains("ignored"),
        "the odd entry is counted, not trusted: {}",
        v["global"]
    );
    for f in &unlisted {
        let fix = f["fix"].as_str().unwrap();
        assert_eq!(f["fix_kind"], "manual");
        assert!(
            !fix.contains("touch") && !fix.contains(&long),
            "no directory name that is not a plain id reaches a step: {fix}"
        );
        assert_fix_contract(&fx, "hostile spool name", "spool-unlisted", "manual", fix);
    }
    let msgs = v["findings"].to_string();
    assert!(
        msgs.contains("$(touch $STUB_STATE.pwned)"),
        "named, cleaned: {msgs}"
    );
    assert!(!msgs.contains(&long), "a long name is capped: {msgs}");
    assert!(msgs.contains(&format!("{}...", "a".repeat(64))), "{msgs}");
    assert!(
        !v["global"].to_string().contains(&long),
        "the row prints the cut name too: {}",
        v["global"]
    );
}

/// The row text of the global check `id`.
fn global_text(v: &serde_json::Value, id: &str) -> String {
    v["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == id)
        .map(|g| g["text"].as_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}

/// Writes intake's cursor for the log at `path` the way `log-tailer` names it (the SHA-256 of the
/// resolved path) into the fixture's cursor directory, at `offset` and with the file's own inode
/// unless `inode` is given.
fn spool_cursor(fx: &Fx, path: &str, offset: u64, inode: Option<u64>) {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let resolved = std::fs::canonicalize(path).unwrap();
    let hash: String = Sha256::digest(resolved.to_str().unwrap().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ino = inode.unwrap_or_else(|| std::fs::metadata(path).unwrap().ino());
    let fp = vec!["0"; 32].join(",");
    fx.write(
        &format!("state/cursors/{hash}.json"),
        &format!("{{\"inode\":{ino},\"offset\":{offset},\"fingerprint\":[{fp}]}}"),
    );
}

#[test]
fn a_spool_read_to_its_end_and_no_longer_listed_is_named_in_the_row_and_raises_no_finding() {
    let fx = Fx::new();
    // A collector rebuilt under a new id: the old id's spool stays, read in full.
    let old = fx.spool("collector-01", 500, NOW - 86_400);
    let new = fx.spool("collector-02", 200, NOW - 60);
    fx.add_intake_entries(&format!("collector-02:{new}"));
    spool_cursor(&fx, &old, 500, None);
    let v = fx.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
    let text = global_text(&v, "gateway-spool");
    assert!(
        text.contains("1 read to the end and no longer listed: collector-01"),
        "{text}"
    );
}

#[test]
fn an_unlisted_spool_with_bytes_past_its_cursor_fails_and_says_how_much_was_written_since() {
    let fx = Fx::new();
    let old = fx.spool("collector-01", 4096, NOW - 60);
    spool_cursor(&fx, &old, 1024, None);
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["id"], "spool-unlisted");
    let msg = found[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("3K written to it since are not ingested"),
        "{msg}"
    );
    assert!(!msg.contains("never read"), "{msg}");
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
}

#[test]
fn an_unlisted_spool_with_no_cursor_fails_and_says_it_was_not_read_or_the_cursors_are_elsewhere() {
    let fx = Fx::new();
    fx.spool("collector-01", 300, NOW - 60);
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let msg = found[0]["message"].as_str().unwrap();
    // The check looks in one directory; a daemon that keeps its cursors in another has read the
    // file, so the message must not say flatly that it never did.
    assert!(
        msg.contains("Intake has no cursor for this file in")
            && msg.contains("it has not read it, or keeps its cursors elsewhere"),
        "{msg}"
    );
    assert!(!msg.contains("never read"), "{msg}");
}

/// A spool read to its end is taken for a retired collector's only once it has gone unwritten
/// for ten minutes. A collector whose entry was removed by mistake looks the same until its next
/// batch arrives, and a capturing sensor writes at least a stats line every minute.
#[test]
fn a_spool_read_to_its_end_but_written_minutes_ago_fails_because_its_collector_may_be_shipping() {
    for (age, retired) in [(60, false), (599, false), (600, true), (86_400, true)] {
        let fx = Fx::new();
        let old = fx.spool("collector-01", 500, NOW - age);
        spool_cursor(&fx, &old, 500, None);
        let v = fx.json();
        let found = spool_findings(&v);
        let text = global_text(&v, "gateway-spool");
        if retired {
            assert!(found.is_empty(), "written {age} s ago: {found:?}");
            assert_eq!(global_state(&v, "gateway-spool"), "ok", "{age}");
            assert!(
                text.contains("1 read to the end and no longer listed: collector-01 (last written"),
                "written {age} s ago: {text}"
            );
        } else {
            assert_eq!(found.len(), 1, "written {age} s ago: {found:?}");
            assert_eq!(found[0]["id"], "spool-unlisted");
            let msg = found[0]["message"].as_str().unwrap();
            assert!(
                msg.contains("read the file to its end")
                    && msg.contains("the collector may still be shipping")
                    && msg.contains("clears once the file has gone unwritten"),
                "written {age} s ago: {msg}"
            );
            assert_eq!(global_state(&v, "gateway-spool"), "fail", "{age}");
            assert!(!text.contains("no longer listed"), "{text}");
        }
    }
}

#[test]
fn an_unlisted_spool_whose_cursor_is_for_another_inode_fails_and_says_what_could_not_be_told() {
    let fx = Fx::new();
    let old = fx.spool("collector-01", 300, NOW - 60);
    // At the file's size, but for a file that has since been replaced.
    spool_cursor(&fx, &old, 300, Some(1));
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let msg = found[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("could not be determined") && msg.contains("is for inode 1"),
        "{msg}"
    );
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
}

#[test]
fn a_collector_whose_id_is_a_sensors_name_listed_under_that_id_fails_and_needs_a_new_id() {
    let fx = Fx::new();
    let p = fx.spool("mysql", 200, NOW - 60);
    fx.add_intake_entries(&format!("mysql:{p}"));
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f["id"], "spool-label-sensor");
    assert_eq!(f["level"], "fail");
    let msg = f["message"].as_str().unwrap();
    assert!(msg.contains("'mysql'") && msg.contains("refused"), "{msg}");
    let fix = f["fix"].as_str().unwrap();
    assert!(fix.contains("new id"), "{fix}");
    assert!(!fix.contains("change the entry to"), "{fix}");
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
    assert!(
        global_text(&v, "gateway-spool").contains("1 listed under an id that is a sensor's"),
        "{}",
        v["global"]
    );
}

#[test]
fn a_daemon_subsystem_name_is_never_suggested_and_is_flagged_when_used_as_a_label() {
    let fx = Fx::new();
    fx.spool("console", 200, NOW - 60);
    let own = fx.spool("campaigns", 200, NOW - 60);
    let other = fx.spool("collector-03", 200, NOW - 60);
    fx.add_intake_entries(&format!("campaigns:{own},review:{other}"));
    let v = fx.json();
    let found = spool_findings(&v);
    let by =
        |id: &str| -> Vec<&serde_json::Value> { found.iter().filter(|f| f["id"] == id).collect() };

    let unlisted = by("spool-unlisted");
    assert_eq!(unlisted.len(), 1, "{found:?}");
    let fix = unlisted[0]["fix"].as_str().unwrap();
    assert!(!fix.contains(",console:"), "{fix}");
    assert!(fix.contains("new id"), "{fix}");
    assert!(
        unlisted[0]["message"]
            .as_str()
            .unwrap()
            .contains("one the daemon gives one of its own subsystems"),
        "{}",
        unlisted[0]
    );

    let subsys = by("spool-label-subsystem");
    assert_eq!(subsys.len(), 2, "{found:?}");
    for f in &subsys {
        assert_eq!(f["level"], "warn");
        assert!(
            f["message"].as_str().unwrap().contains("sensor-down"),
            "{f}"
        );
    }
    let campaigns = subsys
        .iter()
        .find(|f| f["message"].as_str().unwrap().contains("'campaigns'"))
        .expect("the entry listed under its own id");
    assert!(
        campaigns["fix"].as_str().unwrap().contains("new id"),
        "{campaigns}"
    );
    let review = subsys
        .iter()
        .find(|f| f["message"].as_str().unwrap().contains("'review'"))
        .expect("the entry under a subsystem's name");
    assert!(
        review["fix"]
            .as_str()
            .unwrap()
            .contains(&format!("change the entry to collector-03:{other}")),
        "{review}"
    );
    assert!(by("spool-label-other").is_empty(), "{found:?}");
}

#[test]
fn the_spool_directory_in_gateway_env_is_trimmed_and_unquoted_as_systemd_reads_it() {
    let fx = Fx::new();
    let other = fx.p("srv/gateway-spool");
    fx.write(
        "etc/gateway.env",
        &format!(
            "PROPOLIS_GATEWAY_BIND=0.0.0.0:9443\nPROPOLIS_GATEWAY_SPOOL_DIR= \"{}\" \n",
            other.display()
        ),
    );
    fx.log("srv/gateway-spool/collector-05/events.jsonl", 10, NOW - 60);
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["id"], "spool-unlisted");
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains(&format!("{}/collector-05/events.jsonl", other.display())),
        "{}",
        found[0]
    );
}

#[test]
fn a_spool_directory_gateway_env_names_that_does_not_exist_is_unknown_and_named() {
    let fx = Fx::new();
    let missing = fx.p("srv/no-such-spool");
    fx.write(
        "etc/gateway.env",
        &format!("PROPOLIS_GATEWAY_SPOOL_DIR={}\n", missing.display()),
    );
    // The default location holds a spool, but the gateway does not write there.
    fx.spool("collector-99", 10, NOW - 60);
    let v = fx.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "unknown",
        "{}",
        v["global"]
    );
    assert!(
        global_text(&v, "gateway-spool").contains(&missing.display().to_string()),
        "{}",
        v["global"]
    );
}

#[test]
fn a_listed_spool_path_with_a_trailing_slash_does_not_count_and_the_entry_is_named() {
    let fx = Fx::new();
    let p = fx.spool("collector-01", 200, NOW - 60);
    fx.add_intake_entries(&format!("collector-01:{p}/"));
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f["id"], "spool-unlisted");
    let msg = f["message"].as_str().unwrap();
    assert!(
        msg.contains(&format!("'collector-01:{p}/' ends in '/'")),
        "{msg}"
    );
    let fix = f["fix"].as_str().unwrap();
    assert!(fix.contains("remove the trailing '/'"), "{fix}");
    assert_eq!(global_state(&v, "gateway-spool"), "fail");
}

#[test]
fn an_unreadable_gateway_env_is_a_limited_check_whether_or_not_a_spool_exists() {
    for with_spool in [false, true] {
        let fx = Fx::new();
        if with_spool {
            fx.spool("collector-07", 200, NOW - 60);
        }
        fx.write("etc/gateway.env", "PROPOLIS_GATEWAY_BIND=0.0.0.0:9443\n");
        let genv = fx.p("etc/gateway.env");
        let wrapper: Vec<&str> = if is_root() {
            std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&genv, std::fs::Permissions::from_mode(0o600)).unwrap();
            vec![
                "/usr/bin/setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
            ]
        } else {
            std::fs::set_permissions(&genv, std::fs::Permissions::from_mode(0o000)).unwrap();
            vec![]
        };
        let r = fx.run_under(&wrapper, &["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
        std::fs::set_permissions(&genv, std::fs::Permissions::from_mode(0o600)).unwrap();
        let v = r.json();
        assert_eq!(
            global_state(&v, "gateway-spool"),
            "unknown",
            "spool {with_spool}: {}",
            v["global"]
        );
        assert!(
            v["limited"].as_array().unwrap().iter().any(|l| {
                let l = l.as_str().unwrap();
                l.starts_with("gateway spool not checked") && l.contains("gateway.env")
            }),
            "spool {with_spool}: {}",
            v["limited"]
        );
        assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    }
}

#[test]
fn an_unreadable_propolis_env_alone_is_the_limit_the_spool_check_names() {
    let fx = Fx::new();
    fx.spool("collector-07", 200, NOW - 60);
    let penv = fx.p("etc/propolis.env");
    let wrapper: Vec<&str> = if is_root() {
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o600)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o000)).unwrap();
        vec![]
    };
    let r = fx.run_under(&wrapper, &["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o600)).unwrap();
    let v = r.json();
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "unknown",
        "{}",
        v["global"]
    );
    let spool_limits: Vec<&str> = v["limited"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .filter(|l| l.starts_with("gateway spool"))
        .collect();
    assert_eq!(spool_limits.len(), 1, "{spool_limits:?}");
    assert!(
        spool_limits[0].contains(&format!("{} is not readable", penv.display())),
        "{spool_limits:?}"
    );
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
}

#[test]
fn an_unreadable_collector_directory_is_a_limited_check_and_no_unlisted_finding() {
    let fx = Fx::new();
    fx.spool("collector-07", 200, NOW - 60);
    let dir = fx.p("spool/gateway/collector-07");
    let penv = fx.p("etc/propolis.env");
    let wrapper: Vec<&str> = if is_root() {
        // As nobody, propolis.env has to be readable for the spool check to get this far.
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        vec![]
    };
    let r = fx.run_under(&wrapper, &["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o600)).unwrap();
    let v = r.json();
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "unknown",
        "{}",
        v["global"]
    );
    assert!(
        v["limited"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("collector directories under")),
        "{}",
        v["limited"]
    );
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
}

#[test]
fn a_symlink_and_a_backslash_name_in_the_spool_are_ignored_and_counted() {
    let fx = Fx::new();
    let p = fx.spool("collector-01", 10, NOW - 60);
    fx.add_intake_entries(&format!("collector-01:{p}"));
    std::os::unix::fs::symlink(
        fx.p("spool/gateway/collector-01"),
        fx.p("spool/gateway/link"),
    )
    .unwrap();
    fx.spool("b\\x", 10, NOW - 60);
    let v = fx.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert!(
        global_text(&v, "gateway-spool")
            .contains("2 entries that are not collector directories ignored"),
        "{}",
        v["global"]
    );
}

#[test]
fn a_spool_listed_by_its_real_path_through_a_symlinked_spool_directory_is_listed() {
    let fx = Fx::new();
    let p = fx.spool("collector-01", 10, NOW - 60);
    fx.add_intake_entries(&format!("collector-01:{p}"));
    let link = fx.p("spool-link");
    std::os::unix::fs::symlink(fx.p("spool/gateway"), &link).unwrap();
    let v = fx
        .run_with(
            &["--json"],
            &[("PROPOLIS_CC_GATEWAY_SPOOL_DIR", link.to_str().unwrap())],
        )
        .json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
    // The intake-list check resolves the spool directory the same way, so the real path is a
    // collector's spool there too and not an entry no sensor writes.
    let named: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["scope"] == "intake-list" && f["message"].as_str().unwrap().contains(&p))
        .collect();
    assert!(named.is_empty(), "{named:?}");
}

#[test]
fn an_empty_collector_directory_is_counted_and_raises_no_finding() {
    let fx = Fx::new();
    std::fs::create_dir_all(fx.p("spool/gateway/collector-08")).unwrap();
    let v = fx.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
    assert!(
        global_text(&v, "gateway-spool").starts_with("1 collectors in"),
        "{}",
        v["global"]
    );
}

#[test]
fn past_twenty_unlisted_spools_the_rest_are_counted_in_the_row_only() {
    let fx = Fx::new();
    for i in 0..25 {
        fx.spool(&format!("collector-{i:02}"), 10, NOW - 60);
    }
    let v = fx.json();
    let unlisted = spool_findings(&v)
        .iter()
        .filter(|f| f["id"] == "spool-unlisted")
        .count();
    assert_eq!(unlisted, 20);
    assert!(
        global_text(&v, "gateway-spool").ends_with("and 20 more"),
        "{}",
        v["global"]
    );
}

#[test]
fn an_unlisted_spool_under_a_sensors_name_gets_the_new_id_step_and_no_entry() {
    let fx = Fx::new();
    fx.spool("ssh", 10, NOW - 60);
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let fix = found[0]["fix"].as_str().unwrap();
    assert!(!fix.contains(",ssh:"), "{fix}");
    assert!(fix.contains("new id"), "{fix}");
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains("its name is a sensor's name"),
        "{}",
        found[0]
    );
}

#[test]
fn a_collector_whose_intake_list_is_in_shipper_env_still_has_its_spools_checked() {
    let fx = Fx::new();
    let p = fx.spool("collector-01", 10, NOW - 60);
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", None);
    fx.write(
        "etc/shipper.env",
        &format!("PROPOLIS_SHIPPER_SENSOR_LOGS=collector-01:{p}\n"),
    );
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["id"], "spool-unlisted");
}

/// A host running sensors and a gateway lists each collector's spool beside its own sensor logs.
/// Those entries are judged by the gateway-spool row; the older check that knows only local
/// sensors must not call them orphans, nor call a collector that has not delivered yet a typo.
/// The row names such a collector instead, since a listed id with no spool may be misspelled.
#[test]
fn a_listed_collector_spool_on_a_sensor_host_is_no_orphan_while_a_real_orphan_still_is() {
    let fx = Fx::new();
    let logs = fx.logs();
    let a = fx.spool("collector-01", 200, NOW - 60);
    // Listed ahead of its first batch: the spool directory exists, its own does not yet.
    let b = format!("{}/collector-02/events.jsonl", fx.spool_dir());
    fx.log("logs/retired/events.jsonl", 10, NOW - 60);
    let orphan = format!("{logs}/retired/events.jsonl");
    fx.add_intake_entries(&format!(
        "collector-01:{a},collector-02:{b},retired:{orphan}"
    ));
    let v = fx.json();
    let intake: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["scope"] == "intake-list")
        .collect();
    for f in &intake {
        let msg = f["message"].as_str().unwrap();
        assert!(
            !msg.contains(&a) && !msg.contains(&b),
            "a listed collector spool is not an intake-list finding: {msg}"
        );
    }
    assert_eq!(intake.len(), 1, "{intake:?}");
    assert_eq!(intake[0]["id"], "intake-orphan");
    assert!(
        intake[0]["message"].as_str().unwrap().contains(&format!(
            "'retired:{orphan}' matches no configured sensor's log path"
        )),
        "{}",
        intake[0]
    );
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
    // Named in the row, so a misspelled id does not go unseen, but no finding: a collector
    // listed ahead of its first batch is the documented way to add one.
    let text = global_text(&v, "gateway-spool");
    assert!(
        text.contains("listed but nothing delivered yet: collector-02"),
        "{text}"
    );
    assert!(!text.contains("collector-01"), "{text}");
}

/// Undelivered listed ids in the gateway-spool row are cleaned like every other name and cut
/// to a few, so a long or hostile list cannot flood or garble the row.
#[test]
fn listed_collectors_that_have_delivered_nothing_are_named_cleaned_and_capped_in_the_spool_row() {
    let fx = Fx::new();
    let dir = fx.spool_dir();
    let a = fx.spool("collector-01", 200, NOW - 60);
    let long = "l".repeat(70);
    let ids = ["c-a", long.as_str(), "esc\u{1b}[31m", "c-d", "c-e"];
    let entries: Vec<String> = ids
        .iter()
        .map(|id| format!("{id}:{dir}/{id}/events.jsonl"))
        .collect();
    fx.add_intake_entries(&format!("collector-01:{a},{}", entries.join(",")));
    let r = fx.run(&["--json"]);
    assert!(!r.out.contains('\u{1b}'), "{}", r.out);
    let v = r.json();
    assert!(spool_findings(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
    let text = global_text(&v, "gateway-spool");
    // Cut at 64 characters like every spool name, the most a certificate CommonName holds.
    let cut = format!("{}...", "l".repeat(64));
    assert!(
        text.contains(&format!(
            "listed but nothing delivered yet: c-a, {cut}, esc?[31m and 2 more"
        )),
        "{text}"
    );
}

/// The findings of any scope whose message contains `needle`.
fn findings_naming<'a>(v: &'a serde_json::Value, needle: &str) -> Vec<&'a serde_json::Value> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["message"].as_str().unwrap().contains(needle))
        .collect()
}

/// With no spool directory and no gateway.env naming one, the gateway-spool row is absent, so an
/// entry that only looks like a spool path must still be judged by the intake-list check.
#[test]
fn an_entry_under_the_spool_path_on_a_host_with_no_spool_is_still_an_intake_list_finding() {
    let fx = Fx::new();
    assert!(!fx.p("spool/gateway").exists());
    let entry = format!("{}/c1/events.jsonl", fx.spool_dir());
    fx.add_intake_entries(&format!("c1:{entry}"));
    let v = fx.json();
    let named = findings_naming(&v, &entry);
    assert_eq!(named.len(), 1, "{named:?}");
    assert_eq!(named[0]["scope"], "intake-list", "{}", named[0]);
    let id = named[0]["id"].as_str().unwrap();
    assert!(id == "intake-orphan" || id == "intake-nodir", "{id}");
    assert_eq!(
        global_state(&v, "gateway-spool"),
        "absent",
        "{}",
        v["global"]
    );
}

/// A spool entry written with a trailing '/' lists nothing; the spool-unlisted finding already
/// says so and how to fix it, so the intake-list check must not report it a second time.
#[test]
fn a_trailing_slash_spool_entry_on_a_sensor_host_is_reported_as_spool_unlisted_only() {
    let fx = Fx::new();
    let a = fx.spool("collector-01", 200, NOW - 60);
    let entry = format!("{a}/");
    fx.add_intake_entries(&format!("collector-01:{entry}"));
    let v = fx.json();
    let named = findings_naming(&v, &format!("collector-01:{entry}"));
    assert_eq!(named.len(), 1, "{named:?}");
    assert_eq!(named[0]["id"], "spool-unlisted", "{}", named[0]);
    assert!(
        named[0]["message"]
            .as_str()
            .unwrap()
            .contains("ends in '/'"),
        "{}",
        named[0]
    );
}

/// gateway.env moves the spool, and the intake-list check finds it there with the same reading
/// the unit gets: surrounding whitespace trimmed and one pair of quotes removed.
#[test]
fn a_spool_entry_under_the_directory_gateway_env_names_is_no_intake_list_finding() {
    let fx = Fx::new();
    let other = fx.p("srv/gateway-spool");
    fx.write(
        "etc/gateway.env",
        &format!(
            "PROPOLIS_GATEWAY_BIND=0.0.0.0:9443\nPROPOLIS_GATEWAY_SPOOL_DIR=\"{}\" \n",
            other.display()
        ),
    );
    fx.log("srv/gateway-spool/collector-05/events.jsonl", 10, NOW - 60);
    let entry = format!("{}/collector-05/events.jsonl", other.display());
    fx.add_intake_entries(&format!("collector-05:{entry}"));
    let v = fx.json();
    let named = findings_naming(&v, &entry);
    assert!(
        named.iter().all(|f| f["scope"] != "intake-list"),
        "{named:?}"
    );
    assert_eq!(global_state(&v, "gateway-spool"), "ok", "{}", v["global"]);
}

/// On a collector the list in shipper.env is the shipper's, which no gateway spool feeds: an entry
/// under the spool path there is no collector's spool and stays an orphan.
#[test]
fn an_entry_under_the_spool_path_in_a_collectors_list_is_still_an_orphan() {
    let fx = Fx::new();
    let logs = fx.logs();
    let p = fx.spool("collector-01", 10, NOW - 60);
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", None);
    fx.write(
        "etc/shipper.env",
        &format!(
            "PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl,collector-01:{p}\n"
        ),
    );
    let v = fx.json();
    let orphan: Vec<&serde_json::Value> = findings_naming(&v, &format!("collector-01:{p}"))
        .into_iter()
        .filter(|f| f["id"] == "intake-orphan")
        .collect();
    assert_eq!(orphan.len(), 1, "{}", v["findings"]);
}

#[test]
fn a_spool_directory_under_a_sensors_name_listed_under_another_label_is_not_told_to_take_that_name()
{
    let fx = Fx::new();
    let p = fx.spool("ssh", 10, NOW - 60);
    fx.add_intake_entries(&format!("x:{p}"));
    let v = fx.json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["id"], "spool-label-other");
    let fix = found[0]["fix"].as_str().unwrap();
    assert!(!fix.contains("change the entry to"), "{fix}");
    assert!(fix.contains("new id"), "{fix}");
}

/// Which labels bind a log to one sensor is the origin policy's decision
/// (`sensor_wire::origin::bound_sensor`); the spool check's copy must name the same set.
#[test]
fn the_labels_the_spool_check_treats_as_sensor_names_are_the_origin_policys() {
    let origin = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sensor-wire/src/origin.rs"
    ))
    .unwrap();
    let table = &origin[..origin.find("#[cfg(test)]").unwrap()];
    let mut want = std::collections::BTreeSet::new();
    for l in table.lines().map(str::trim) {
        if let Some(rest) = l.strip_prefix("sensor: \"") {
            want.insert(rest.split('"').next().unwrap().to_string());
        }
        if let Some(rest) = l.strip_prefix("(\"cred-") {
            want.insert(format!("cred-{}", rest.split('"').next().unwrap()));
        }
    }
    assert!(want.len() >= 21, "the scan of origin.rs broke: {want:?}");
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let have: std::collections::BTreeSet<String> = script
        .lines()
        .find_map(|l| l.strip_prefix("SPOOL_BOUND_LABELS=\""))
        .expect("config-check.sh has no SPOOL_BOUND_LABELS line")
        .trim_end_matches('"')
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert_eq!(have, want);

    // And each cred-* label binds to the sensor CRED_LABELS pairs it with, which the finding names.
    let cred: Vec<(String, String)> = table
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("(\"cred-"))
        .map(|rest| {
            let parts: Vec<&str> = rest.split('"').collect();
            (format!("cred-{}", parts[0]), parts[2].to_string())
        })
        .collect();
    assert_eq!(cred.len(), 5, "the scan of CRED_LABELS broke: {cred:?}");
    let fx = Fx::new();
    let entries: Vec<String> = cred
        .iter()
        .enumerate()
        .map(|(i, (label, _))| {
            let p = fx.spool(&format!("collector-{i:02}"), 10, NOW - 60);
            format!("{label}:{p}")
        })
        .collect();
    fx.add_intake_entries(&entries.join(","));
    let v = fx.json();
    let found = spool_findings(&v);
    for (label, sensor) in &cred {
        let f = found
            .iter()
            .find(|f| {
                f["id"] == "spool-label-sensor"
                    && f["message"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("'{label}'"))
            })
            .unwrap_or_else(|| panic!("no spool-label-sensor for {label}: {found:?}"));
        assert!(
            f["message"]
                .as_str()
                .unwrap()
                .contains(&format!("binds the log to {sensor} alone")),
            "{label}: {f}"
        );
    }
}

/// The daemon's subsystem names are `condition.rs`'s decision (`DAEMON_SUBSYSTEMS`); the spool
/// check's copy, which it never suggests and flags as a label, must name the same set.
#[test]
fn the_names_the_spool_check_treats_as_daemon_subsystems_are_the_daemons() {
    let condition = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../propolis/src/ops_alert/condition.rs"
    ))
    .unwrap();
    let start = condition
        .find("pub const DAEMON_SUBSYSTEMS")
        .expect("condition.rs has no DAEMON_SUBSYSTEMS");
    let body = &condition[start..];
    let body = &body[body.find("= &[").unwrap()..body.find("];").unwrap()];
    let want: std::collections::BTreeSet<String> = body
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    assert!(want.len() >= 9, "the scan of condition.rs broke: {want:?}");
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let have: std::collections::BTreeSet<String> = script
        .lines()
        .find_map(|l| l.strip_prefix("SPOOL_SUBSYSTEM_NAMES=\""))
        .expect("config-check.sh has no SPOOL_SUBSYSTEM_NAMES line")
        .trim_end_matches('"')
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert_eq!(have, want);
}

/// On a fresh box provisioning creates every service env file EMPTY. That must read as "nothing
/// is configured" (the same warning as no files at all), not as a control-plane-only host that
/// passed; one assignment in one file is enough to clear it.
#[test]
fn env_files_created_empty_by_provisioning_are_not_configuration() {
    let fx = Fx::new();
    let etc = fx.p("etc");
    for entry in std::fs::read_dir(&etc).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "env") {
            std::fs::remove_file(path).unwrap();
        }
    }
    let out = std::process::Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/env-files.sh"
    ))
    .arg(&etc)
    .env("DRY_RUN", "0")
    .output()
    .expect("run deploy/env-files.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fx.p("etc/propolis.env").exists());

    let findings = |v: &serde_json::Value| -> Vec<String> {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["id"] == "env-empty")
            .map(|f| f["level"].as_str().unwrap().to_string())
            .collect()
    };
    let v = fx.json();
    assert_eq!(global_state(&v, "env-files"), "warn", "{v}");
    assert_eq!(findings(&v), ["warn"], "{}", v["findings"]);

    // A comment and blank lines are still nothing; a real assignment is configuration.
    fx.write("etc/propolis.env", "# fill me in\n\n");
    assert_eq!(global_state(&fx.json(), "env-files"), "warn");
    fx.write("etc/propolis.env", "PROPOLIS_CONSOLE_BIND=127.0.0.1:8080\n");
    let v = fx.json();
    assert_eq!(global_state(&v, "env-files"), "ok", "{v}");
    assert!(findings(&v).is_empty(), "{}", v["findings"]);
}

/// An env file another account can read is a failure naming the chmod that closes it: 0600 for
/// a secret-bearing file, 0640 for the watcher's copy (its group reads it by design), 0644 for
/// the generated listener inventory. A mode stricter than the limit is not reported, so a file
/// with no access at all (which the unreadable-files test uses) raises nothing here.
#[test]
fn an_env_file_readable_by_other_accounts_is_a_failure_with_the_chmod_that_closes_it() {
    let fx = Fx::new();
    let mode_findings = |fx: &Fx| -> Vec<(String, String, String)> {
        fx.json()["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["id"] == "env-mode")
            .map(|f| {
                (
                    f["level"].as_str().unwrap().to_string(),
                    f["fix"].as_str().unwrap().to_string(),
                    f["fix_kind"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let chmod = |fx: &Fx, rel: &str, mode: u32| {
        std::fs::set_permissions(fx.p(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    };

    // The control writes every env file 0600, and the modes each file is allowed raise nothing.
    chmod(&fx, "etc/watch.env", 0o640);
    fx.write(
        "etc/fleet-listeners.env",
        "PROPOLIS_FLEET_LISTENERS=local/ssh/tcp/22\n",
    );
    chmod(&fx, "etc/fleet-listeners.env", 0o644);
    chmod(&fx, "etc/tftp.env", 0o400);
    assert!(mode_findings(&fx).is_empty(), "{}", fx.json()["findings"]);
    assert_eq!(global_state(&fx.json(), "env-files"), "ok");

    // A secret-bearing file readable by its group or by everyone fails, with the 0600 fix.
    chmod(&fx, "etc/propolis.env", 0o640);
    let propolis_env = fx.p("etc/propolis.env").display().to_string();
    assert_eq!(
        mode_findings(&fx),
        [(
            "fail".to_string(),
            format!("sudo chmod 0600 {propolis_env}"),
            "run".to_string()
        )]
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 2, "{}", r.out);
    assert!(
        r.has(&format!(
            "{propolis_env} is mode 0640, so accounts other than its owner can read or write it"
        )),
        "{}",
        r.out
    );
    assert_eq!(global_state(&fx.json(), "env-files"), "fail");

    // The text must name BOTH exceptions. It once said every env file but fleet-listeners.env
    // carries a secret, which led to a blanket `chmod 600` that locked the watcher's account out
    // of watch.env (live, 2026-10-14).
    let message = fx.json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "env-mode")
        .map(|f| f["message"].as_str().unwrap().to_string())
        .unwrap();
    assert!(
        message.contains("watch.env")
            && message.contains("0640")
            && message.contains("propolis-watch"),
        "{message}"
    );
    assert!(
        message.contains("fleet-listeners.env") && message.contains("0644"),
        "{message}"
    );
    assert!(
        !message.contains("every env file but"),
        "a blanket claim again: {message}"
    );

    // The watcher's copy may be group-readable, not world-readable, and each loose file is its
    // own finding.
    chmod(&fx, "etc/watch.env", 0o644);
    let watch_env = fx.p("etc/watch.env").display().to_string();
    let found = mode_findings(&fx);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.contains(&(
        "fail".to_string(),
        format!("sudo chmod 0640 {watch_env}"),
        "run".to_string()
    )));

    // Closing the modes clears every finding; stricter than required stays clear.
    chmod(&fx, "etc/propolis.env", 0o600);
    chmod(&fx, "etc/watch.env", 0o600);
    assert!(mode_findings(&fx).is_empty());
    assert_eq!(fx.run(&[]).code, 0);
}

// ---- the daemon's database role and the ledger -------------------------------------------------

fn ledger_findings(fx: &Fx) -> Vec<serde_json::Value> {
    fx.json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"].as_str().is_some_and(|id| id.starts_with("ledger-")))
        .cloned()
        .collect()
}

fn ledger_finding(fx: &Fx) -> Option<serde_json::Value> {
    ledger_findings(fx).into_iter().next()
}

/// The answer a role-split node gives (`role|controls|privileges|owns_database|can_create`):
/// nothing to report, and the verdict is what it was without the check.
#[test]
fn a_daemon_role_that_can_only_append_to_the_ledger_is_not_a_finding() {
    let fx = Fx::new();
    let before = fx.run(&[]).code;
    fx.write("state/psql_role_out", "propolis|f||f|f\n");
    assert_eq!(ledger_finding(&fx), None);
    assert_eq!(fx.run(&[]).code, before);
    assert!(
        fx.p("state/psql_role.log").exists(),
        "the role query was never asked"
    );
}

/// A revoke does not bind a table's owner. A daemon connected as the role that owns `event` is
/// told so, with the page that fixes it as a manual step: there is no command to paste. On a node
/// with one role that role owns the database too, and it is still this finding and no other.
#[test]
fn a_daemon_role_that_owns_the_ledger_is_a_warning_with_a_manual_step() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|t||t|t\n");
    let finding = ledger_finding(&fx).expect("an owning role is reported");
    assert_eq!(finding["id"], "ledger-owner");
    assert_eq!(finding["level"], "warn");
    let message = finding["message"].as_str().unwrap();
    assert!(message.contains("role propolis"), "{message}");
    assert!(message.contains("owns the event table"), "{message}");
    assert!(
        finding["fix"]
            .as_str()
            .unwrap()
            .contains("docs/operations/database-roles.md"),
        "{finding}"
    );
    assert_eq!(
        ledger_findings(&fx).len(),
        1,
        "a single-role node gets the finding it always got, once"
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .lines()
            .any(|l| l.trim_start().starts_with("do:") && l.contains("database-roles.md")),
        "the step is printed as do:, not as a command to paste:\n{}",
        r.out
    );
}

/// The roles are split but something granted the daemon's role more than it needs: the owner's
/// migration resets the grants, and that is a command.
#[test]
fn a_daemon_role_holding_extra_ledger_privileges_is_told_to_reset_its_grants() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|f|UPDATE TRIGGER|f|f\n");
    let finding = ledger_finding(&fx).expect("the extra privileges are reported");
    assert_eq!(finding["id"], "ledger-grants");
    assert_eq!(finding["level"], "warn");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("holds UPDATE TRIGGER on the event table"),
        "{finding}"
    );
    assert_eq!(finding["fix"], "sudo propolis-migrate");
}

/// What a database restored for the wrong owner leaves: the tables and every grant on them as
/// they should be, and the database itself owned by the role the daemon connects as. Nothing
/// about the event table shows it. It is a warning with a manual step, because handing a
/// database back takes a superuser.
#[test]
fn a_daemon_role_that_owns_the_database_but_not_the_ledger_is_a_warning_with_a_manual_step() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|f||t|t\n");
    let finding = ledger_finding(&fx).expect("a role that owns the database is reported");
    assert_eq!(finding["id"], "ledger-database");
    assert_eq!(finding["level"], "warn");
    let message = finding["message"].as_str().unwrap();
    assert!(
        message.contains("role propolis does not own the event table but owns the database"),
        "{message}"
    );
    assert_eq!(finding["fix_kind"], "manual");
    assert!(
        finding["fix"]
            .as_str()
            .unwrap()
            .contains("docs/operations/database-roles.md"),
        "{finding}"
    );
    assert_eq!(fx.run(&[]).code, 1);
}

/// A right to create in the schema the ledger is in, without owning the database: the same
/// finding, saying which of the two it is.
#[test]
fn a_daemon_role_that_may_create_in_the_ledgers_schema_is_the_same_warning() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|f||f|t\n");
    let finding = ledger_finding(&fx).expect("a role that may create in the schema is reported");
    assert_eq!(finding["id"], "ledger-database");
    let message = finding["message"].as_str().unwrap();
    assert!(
        message.contains("may create objects in the ledger's schema"),
        "{message}"
    );
    assert!(!message.contains("owns the database"), "{message}");
}

/// Stray table privileges and a database the role owns are two findings with two different
/// steps, and one does not hide the other.
#[test]
fn extra_ledger_privileges_and_an_owned_database_are_both_reported() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|f|DELETE|t|f\n");
    let mut ids: Vec<String> = ledger_findings(&fx)
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    assert_eq!(ids, ["ledger-database", "ledger-grants"]);
}

/// The check is optional like the events query it rides behind: where the database cannot be
/// asked, or answers with something that is not this query's row, nothing is claimed either way.
#[test]
fn the_ledger_role_check_claims_nothing_when_it_cannot_be_answered() {
    // No event table yet: the query returns no row.
    let fx = Fx::new();
    fx.write("state/psql_role_out", "");
    assert_eq!(ledger_finding(&fx), None);

    // The role query itself fails.
    let fx = Fx::new();
    fx.write("state/psql_role_rc", "2");
    fx.write("state/psql_role_out", "propolis|t||t|t\n");
    assert_eq!(ledger_finding(&fx), None);

    // A row of another shape is not this query's answer, whichever column is off: a privilege
    // list that is not one, the three columns an older script asked for, a column this script
    // does not know (which must not be read as part of the one before it), a boolean that is
    // neither, and one the server left empty. None is trusted, and none reaches the report.
    for row in [
        "propolis|t|$(touch /tmp/x); DROP|t|t",
        "propolis|t|",
        "propolis|f|UPDATE",
        "propolis|f||t|t|t",
        "propolis|f||t|f|owner",
        "propolis|f||yes|f",
        "propolis|f|||t",
        "propolis|f||t|",
        "propolis||UPDATE|f|f",
    ] {
        let fx = Fx::new();
        fx.write("state/psql_role_out", &format!("{row}\n"));
        assert_eq!(ledger_finding(&fx), None, "{row}");
    }

    // The events query could not run: the role query is not attempted.
    let fx = Fx::new();
    fx.write("state/psql_rc", "2");
    fx.write("state/psql_role_out", "propolis|t||t|t\n");
    assert_eq!(ledger_finding(&fx), None);
    assert!(!fx.p("state/psql_role.log").exists());

    // --no-events skips every ledger query.
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|t||t|t\n");
    let r = fx.run(&["--no-events"]);
    assert!(
        !r.has("ledger-owner") && !r.has("owns the event table"),
        "{}",
        r.out
    );
    assert!(!fx.p("state/psql_role.log").exists());
}

/// Like the events query: the URL's password goes to psql in PGPASSWORD, never on its command
/// line, and the session is read-only.
#[test]
fn the_ledger_role_query_is_read_only_and_keeps_the_password_off_the_command_line() {
    let fx = Fx::new();
    fx.write("state/psql_role_out", "propolis|f||f|f\n");
    fx.run(&[]);
    let log = fx.read("state/psql_role.log");
    let argv = log.lines().find(|l| l.starts_with("ARGV:")).unwrap();
    assert!(argv.contains("has_table_privilege"), "{argv}");
    assert!(
        argv.contains("datdba") && argv.contains("has_schema_privilege"),
        "the database's owner and the schema are not asked about: {argv}"
    );
    assert!(!argv.contains("postgres://"), "{argv}");
    let password = log
        .lines()
        .find_map(|l| l.strip_prefix("PGPASSWORD="))
        .expect("the password travels in the environment");
    assert!(!password.is_empty() && !argv.contains(password), "{log}");
    assert!(
        log.contains("default_transaction_read_only=on"),
        "the session is not read-only: {log}"
    );
}

/// A password-free node reaches PostgreSQL over its Unix socket. Both ways of writing that in
/// `DATABASE_URL` must reach psql as the socket directory: named by `host=`, or percent-encoded
/// in the host position, which psql was once handed undecoded and looked up as a host name.
#[test]
fn a_unix_socket_database_url_reaches_psql_as_the_socket_directory() {
    for url in [
        "postgres://propolis@localhost:5433/propolis?host=/run/postgresql",
        "postgres://propolis@%2Frun%2Fpostgresql:5433/propolis",
    ] {
        let fx = Fx::new();
        fx.set_env_line(
            "etc/propolis.env",
            "DATABASE_URL=",
            Some(&format!("DATABASE_URL={url}")),
        );
        fx.write("state/psql_out", "2027-01-01 00:00:00+00\n");
        let r = fx.run(&["--newest-event", "ssh"]);
        assert_eq!(r.code, 0, "{url}: {}{}", r.out, r.err);
        let log = fx.read("state/psql.log");
        for want in [
            "PGHOST=/run/postgresql",
            "PGPORT=5433",
            "PGUSER=propolis",
            "PGDATABASE=propolis",
        ] {
            assert!(log.lines().any(|l| l == want), "{url}: no {want} in {log}");
        }
        // No password in the URL means none is invented for psql.
        assert!(
            !log.lines()
                .any(|l| l.starts_with("PGPASSWORD=") && l != "PGPASSWORD="),
            "{log}"
        );
    }
}

// ---- the installed copy, the library, HEAD without git, TSV --------------------------------

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A copy of the script and its listener library in `fx/lib`, laid out as install.sh and
/// upgrade.sh lay out /usr/local/lib/propolis: `repo-dir` holds `repo_dir` (none when `None`),
/// and `install-bins` holds upgrade.sh's binary list plus `sensor-extra`, which upgrade.sh does not
/// name, so a finding about it proves which list was read. Returns the copy's path.
fn install_copy(fx: &Fx, repo_dir: Option<&str>) -> PathBuf {
    let lib = fx.p("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::copy(SCRIPT, lib.join("config-check.sh")).unwrap();
    std::fs::copy(LISTENERS_LIB, lib.join("listeners-lib.sh")).unwrap();
    if let Some(dir) = repo_dir {
        std::fs::write(lib.join("repo-dir"), dir).unwrap();
    }
    std::fs::write(
        lib.join("install-bins"),
        format!("INSTALL_BINS=({} sensor-extra)\n", install_bins().join(" ")),
    )
    .unwrap();
    lib.join("config-check.sh")
}

/// The installed copy's run: PROPOLIS_CC_REPO_DIR empty, so the checkout comes from `repo-dir`.
fn run_installed(fx: &Fx, script: &Path, args: &[&str]) -> Run {
    fx.run_script(script, args, &[("PROPOLIS_CC_REPO_DIR", "")])
}

#[test]
fn the_installed_copy_prints_checkout_paths_and_reads_its_own_bin_list() {
    let fx = Fx::new();
    fx.install_fix_stubs();
    let repo = fx.p("repo").display().to_string();
    // The checkout's scripts the fix lines name, so the run fixes can be executed. Its upgrade.sh
    // lists one binary only: were it read, sensor-extra would not be reported.
    for name in ["upgrade.sh", "watch-env.sh", "logrotate-guard.sh"] {
        fx.exec(
            &format!("repo/deploy/{name}"),
            "INSTALL_BINS=(propolis)\nexit 0\n",
        );
    }
    let script = install_copy(&fx, Some(&format!("{repo}\n")));
    std::fs::remove_file(fx.p("sbin/propolis-logrotate-guard")).unwrap();
    std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
    fx.write("state/psql_out", "ssh|60\nmqtt|90\ntftp|100\ndns|30\n");
    let r = run_installed(&fx, &script, &["--json"]);
    let v = r.json();
    let by_id = |id: &str| -> serde_json::Value {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .unwrap_or_else(|| panic!("no {id} in {}", v["findings"]))
            .clone()
    };
    let bins = by_id("bins-missing");
    assert!(
        bins["message"].as_str().unwrap().contains("sensor-extra"),
        "{bins}"
    );
    assert_eq!(bins["fix"], format!("sudo {repo}/deploy/upgrade.sh"));
    assert_eq!(bins["fix_kind"], "run");
    let guard = by_id("guard");
    assert!(
        guard["fix"].as_str().unwrap().starts_with(&format!(
            "sudo install -m 0755 {repo}/deploy/logrotate-guard.sh "
        )),
        "{guard}"
    );
    assert_eq!(
        by_id("watch-env-missing")["fix"],
        format!("sudo {repo}/deploy/watch-env.sh")
    );
    // The ledger query runs the installed copy itself, a valid root-owned command.
    assert!(
        by_id("events-none")["fix"]
            .as_str()
            .unwrap()
            .starts_with(&format!("sudo {} ", script.display())),
        "{}",
        by_id("events-none")
    );
    for f in v["findings"].as_array().unwrap() {
        let fix = f["fix"].as_str().unwrap();
        assert!(
            !fix.contains(&fx.p("lib/upgrade.sh").display().to_string())
                && !fix.contains(&fx.p("lib/watch-env.sh").display().to_string()),
            "a fix names the installed directory instead of the checkout: {f}"
        );
        assert_fix_contract(
            &fx,
            "installed copy",
            f["id"].as_str().unwrap(),
            f["fix_kind"].as_str().unwrap(),
            fix,
        );
    }
    // The checkout's HEAD is still compared, and nothing says the checkout is unknown.
    assert!(
        !v["limited"].to_string().contains("checkout"),
        "{}",
        v["limited"]
    );
    let tsv = run_installed(&fx, &script, &["--tsv"]);
    let s = tsv.out.lines().nth(1).unwrap();
    assert_eq!(s.split('\t').nth(8), Some("1"), "installed flag: {s}");
}

/// deploy/witness.sh#WITNESS_CC_TABLE as id to eligibility (`page`, `daily` or `never`).
fn witness_eligibility() -> BTreeMap<String, String> {
    let witness = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/witness.sh"
    ))
    .unwrap();
    let start = witness
        .find("WITNESS_CC_TABLE='\n")
        .expect("deploy/witness.sh has WITNESS_CC_TABLE")
        + "WITNESS_CC_TABLE='\n".len();
    let end = start + witness[start..].find("\n'\n").unwrap();
    witness[start..end]
        .lines()
        .filter_map(|l| {
            let mut f = l.split('|');
            Some((f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect()
}

/// The finding ids of a run's TSV, each once, in the order printed.
fn tsv_ids(tsv: &str) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for id in tsv
        .lines()
        .filter_map(|l| l.strip_prefix("F\t"))
        .filter_map(|l| l.split('\t').nth(1))
    {
        if !ids.iter().any(|i| i == id) {
            ids.push(id.to_string());
        }
    }
    ids
}

/// The ids among a run's findings that the witness records (daily or page in WITNESS_CC_TABLE).
fn recorded_ids(tsv: &str) -> Vec<String> {
    let elig = witness_eligibility();
    tsv_ids(tsv)
        .into_iter()
        .filter(|id| matches!(elig.get(id).map(String::as_str), Some("daily" | "page")))
        .collect()
}

/// What a healthy collector or gateway-only host reported every hour before config-check asked
/// the host's role: the daemon's alert monitor, its push target and heartbeat, the backup of the
/// daemon's database and the live watch of the daemon's intake list.
const DAEMON_HOST_IDS: [&str; 6] = [
    "ops-monitor-off",
    "ops-no-push",
    "ops-no-heartbeat",
    "backup-never",
    "watch-env-missing",
    "watch-key-missing",
];

/// The line of the human report that starts with `prefix`, if there is one.
fn report_line<'a>(r: &'a Run, prefix: &str) -> Option<&'a str> {
    r.out.lines().find(|l| l.starts_with(prefix))
}

/// A healthy collector as deploy/install.sh and a hand upgrade leave it: provisioning's empty
/// propolis.env beside the daemon's unit installed and disabled, the shipper's list in
/// shipper.env with a cursor for every log, the propolis-watch account with neither a watch.env
/// (watch-env.sh writes none without PROPOLIS_SENSOR_LOGS in propolis.env) nor a key, the nightly
/// backup recording `not configured`, and what the hand upgrade leaves behind: a checkout one
/// commit past the deploy stamp and a build of the daemon that differs from its installed binary,
/// beside a shipper build that was installed. Returns the installed copy of config-check.
fn healthy_collector(fx: &Fx) -> PathBuf {
    use sha2::{Digest, Sha256};
    let logs = fx.logs();
    fx.write("etc/propolis.env", "");
    fx.unit("propolis.service", "disabled", "inactive");
    // The shipper's cursors in the directory every run of this file reads them from
    // (PROPOLIS_CC_CURSOR_DIR), as the default directory is on a collector.
    fx.write(
        "etc/shipper.env",
        &format!(
            "PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,mqtt:{logs}/mqtt/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl\n"
        ),
    );
    for rel in [
        "logs/ssh/events.jsonl",
        "logs/mqtt/events.jsonl",
        "logs/dns/events.jsonl",
        "logs/tftp/events.jsonl",
        "logs/cred/postgresql.jsonl",
    ] {
        let resolved = std::fs::canonicalize(fx.p(rel)).unwrap();
        let hash: String = Sha256::digest(resolved.to_str().unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fx.write(&format!("state/cursors/{hash}.json"), "{}");
    }
    fx.unit("shipper.service", "enabled", "active");
    std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
    std::fs::remove_file(fx.p("home-watch/.ssh/authorized_keys")).unwrap();
    std::fs::remove_file(fx.p("state/backup-status/last-success")).unwrap();
    fx.write(
        "state/backup-status/last-failure",
        "{\"failed_at\":\"2027-01-15T03:00:00Z\",\"reason\":\"scheduled\",\"step\":\"not configured: no DATABASE_URL in /etc/propolis/propolis.env\",\"exit_code\":0}\n",
    );
    // The hand upgrade installs the sensors and the shipper from the build, and leaves the
    // daemon's binary and the deploy stamp as install.sh wrote them.
    fx.exec("build/shipper", "exit 0\n");
    fx.exec("build/propolis", "exit 1\n");
    // The checkout repo-dir names holds deploy/upgrade.sh, as a real one does.
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
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
            "pulled",
        ])
        .status()
        .unwrap();
    assert!(st.success());
    // install-bins as the collector block writes it: upgrade.sh's own line, every binary
    // install.sh put in place.
    let script = install_copy(fx, Some(&format!("{}\n", fx.p("repo").display())));
    std::fs::write(
        fx.p("lib/install-bins"),
        format!("INSTALL_BINS=({})\n", install_bins().join(" ")),
    )
    .unwrap();
    script
}

/// A healthy gateway-only host: the gateway enabled with its spool, the daemon's and the sensors'
/// units installed and disabled, no sensor configured, provisioning's empty propolis.env, the
/// propolis-watch account with no watch.env and no key, and the nightly backup recording `not
/// configured`.
fn healthy_gateway_only_host(fx: &Fx) {
    for name in ["ssh", "mqtt", "cred", "tftp", "dns"] {
        std::fs::remove_file(fx.p(&format!("etc/{name}.env"))).unwrap();
    }
    for u in [
        "sensor-ssh",
        "sensor-mqtt",
        "sensor-cred",
        "sensor-tftp",
        "sensor-dns",
    ] {
        fx.unit(&format!("{u}.service"), "disabled", "inactive");
    }
    fx.write("etc/propolis.env", "");
    fx.unit("propolis.service", "disabled", "inactive");
    fx.unit("gateway.service", "enabled", "active");
    std::fs::create_dir_all(fx.p("spool/gateway")).unwrap();
    fx.write(
        "etc/gateway.env",
        &format!("PROPOLIS_GATEWAY_SPOOL_DIR={}\n", fx.spool_dir()),
    );
    std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
    std::fs::remove_file(fx.p("home-watch/.ssh/authorized_keys")).unwrap();
    std::fs::remove_file(fx.p("state/backup-status/last-success")).unwrap();
    fx.write(
        "state/backup-status/last-failure",
        "{\"failed_at\":\"2027-01-15T03:00:00Z\",\"reason\":\"scheduled\",\"step\":\"not configured: no DATABASE_URL in /etc/propolis/propolis.env\",\"exit_code\":0}\n",
    );
}

/// Sets propolis-backup.timer as install.sh leaves it (enabled), as an operator who disabled it
/// leaves it, or as a host from before the timer existed has it (not installed).
fn set_backup_timer(fx: &Fx, state: Option<(&str, &str)>) {
    match state {
        Some((enabled, active)) => fx.unit("propolis-backup.timer", enabled, active),
        None => {
            for dir in ["enabled", "active"] {
                let _ = std::fs::remove_file(fx.p(&format!("state/{dir}/propolis-backup.timer")));
            }
        }
    }
}

const BACKUP_TIMER_STATES: [Option<(&str, &str)>; 3] = [
    Some(("enabled", "active")),
    Some(("disabled", "inactive")),
    None,
];

/// The witness runs the installed config-check every hour and records each daily or page finding
/// it prints. A collector does not run the daemon, so the daemon's alert monitor, the backup of
/// its database, the live watch of its intake list and the deploy stamp of its install are not
/// the collector's to report: a healthy collector records nothing, whether install.sh's backup
/// timer is still enabled, was disabled, or was never installed, and the human report names in
/// one line what it leaves to the control node.
#[test]
fn a_healthy_collectors_installed_config_check_prints_no_daily_or_page_finding() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    for timer in BACKUP_TIMER_STATES {
        set_backup_timer(&fx, timer);
        let r = run_installed(&fx, &script, &["--tsv"]);
        assert!(
            r.out.starts_with("#config-check tsv v1\n"),
            "{}\n{}",
            r.out,
            r.err
        );
        let recorded = recorded_ids(&r.out);
        assert!(
            recorded.is_empty(),
            "backup timer {timer:?}: a healthy collector records {recorded:?}\n{}",
            r.out
        );
        let text = run_installed(&fx, &script, &[]);
        assert_eq!(text.code, 0, "backup timer {timer:?}:\n{}", text.out);
        assert!(
            !text.has("\nFINDINGS"),
            "backup timer {timer:?}:\n{}",
            text.out
        );
        let line = report_line(&text, "role: collector;")
            .unwrap_or_else(|| panic!("no role line:\n{}", text.out));
        // The host that runs the daemon checks its own monitor, backup and watch; no host
        // compares this collector's binaries or stamp, so those are named apart, as not checked.
        let (daemon_host, not_here) = role_line_clauses(line);
        for part in ["alert monitor", "backup", "live watch"] {
            assert!(
                daemon_host.contains(part),
                "the role line's clause for the host that runs propolis.service names no \
                 {part}: {line}"
            );
        }
        for part in ["deploy stamp", "binaries"] {
            assert!(
                not_here.contains(part),
                "the role line names no {part} after `not checked here`: {line}"
            );
            assert!(
                !daemon_host.contains(part),
                "the role line says the host that runs propolis.service checks {part}: {line}"
            );
        }
    }
}

/// The role line's two clauses: what config-check checks on the host that runs propolis.service,
/// and what is not checked anywhere (empty when the line has no such clause).
fn role_line_clauses(line: &str) -> (&str, &str) {
    let daemon = "checked by config-check on the host that runs propolis.service:";
    let start = line
        .find(daemon)
        .unwrap_or_else(|| panic!("the role line has no `{daemon}` clause: {line}"));
    let rest = &line[start + daemon.len()..];
    match rest.find("not checked here") {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

/// A gateway-only host does not run the daemon either: it reports none of the daemon's checks,
/// with the backup timer in any state, and says what it leaves to the control node. Its deploy
/// stamp is still compared, since nothing shows that a gateway-only host is upgraded by hand.
#[test]
fn a_healthy_gateway_only_host_prints_no_daily_or_page_finding_and_names_what_the_control_node_checks()
 {
    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    for timer in BACKUP_TIMER_STATES {
        set_backup_timer(&fx, timer);
        let r = fx.run(&["--tsv"]);
        let recorded = recorded_ids(&r.out);
        assert!(
            recorded.is_empty(),
            "backup timer {timer:?}: a healthy gateway-only host records {recorded:?}\n{}",
            r.out
        );
        let ids = tsv_ids(&r.out);
        assert!(
            !ids.iter().any(|i| i == "backup-timer"),
            "backup timer {timer:?}: {ids:?}"
        );
        let text = fx.run(&[]);
        assert_eq!(text.code, 0, "backup timer {timer:?}:\n{}", text.out);
        let line = report_line(&text, "role: gateway only;")
            .unwrap_or_else(|| panic!("no role line:\n{}", text.out));
        let (daemon_host, _) = role_line_clauses(line);
        for part in ["alert monitor", "backup", "live watch"] {
            assert!(
                daemon_host.contains(part),
                "the role line names no {part}: {line}"
            );
        }
        assert!(!line.contains("deploy stamp"), "{line}");
        // A gateway-only host is upgraded with deploy/upgrade.sh, which installs every binary:
        // the line must not say nothing on the host refreshes the ones it does not compare.
        assert!(!line.contains("refresh"), "{line}");
        assert!(
            text.out.contains("deploy-stamp"),
            "the stamp row is still there:\n{}",
            text.out
        );
    }
}

/// A finding about the list of sensor logs names the file the list is in, and its fix restarts
/// whoever reads that file: on a collector the list is PROPOLIS_SHIPPER_SENSOR_LOGS in
/// shipper.env and the reader is the shipper, so the fix restarts shipper.service and never the
/// daemon, which a collector does not run. Where the daemon reads the list, the fix is as before.
#[test]
fn an_intake_finding_on_a_collector_restarts_the_shipper_and_never_the_daemon() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    let logs = fx.logs();
    // The ssh entry under a wrong path, and the mqtt log not listed at all.
    fx.write(
        "etc/shipper.env",
        &format!(
            "PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{logs}/ssh/other.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl\n"
        ),
    );
    let v = run_installed(&fx, &script, &["--json"]).json();
    for id in ["intake-wrongpath", "intake-absent"] {
        let f = json_finding(&v, id);
        assert!(
            f["fix"]
                .as_str()
                .unwrap()
                .contains("sudo systemctl restart shipper.service"),
            "{id}: {f}"
        );
    }
    // No finding about the list, whatever its fix, names the daemon's unit or the live watch's
    // script on a collector.
    for f in v["findings"].as_array().unwrap() {
        let id = f["id"].as_str().unwrap();
        if id.starts_with("intake-") {
            let fix = f["fix"].as_str().unwrap();
            assert!(!fix.contains("propolis.service"), "{id}: {f}");
            assert!(!fix.contains("watch-env.sh"), "{id}: {f}");
        }
    }

    // No list at all, and a misspelt name for it: both are the shipper's file to fix.
    fx.write("etc/shipper.env", "PROPOLIS_SHIPER_SENSOR_LOGS=x:/y\n");
    let v = run_installed(&fx, &script, &["--json"]).json();
    for id in ["intake-none", "intake-name"] {
        let f = json_finding(&v, id);
        let fix = f["fix"].as_str().unwrap();
        assert!(
            fix.contains("PROPOLIS_SHIPPER_SENSOR_LOGS")
                && fix.contains("shipper.env")
                && fix.contains("sudo systemctl restart shipper.service"),
            "{id}: {f}"
        );
        assert!(!fix.contains("propolis.service"), "{id}: {f}");
    }

    // On a host whose daemon reads the list, the same two findings restart the daemon.
    let fx = Fx::new();
    let logs = fx.logs();
    let env = fx.read("etc/propolis.env").replace(
        &format!("ssh:{logs}/ssh/events.jsonl"),
        &format!("ssh:{logs}/ssh/other.jsonl"),
    );
    fx.write("etc/propolis.env", &env);
    let v = fx.json();
    let f = json_finding(&v, "intake-wrongpath");
    assert!(
        f["fix"]
            .as_str()
            .unwrap()
            .contains("sudo systemctl restart propolis.service"),
        "{f}"
    );
}

/// What a collector or a gateway-only host runs itself is still checked there: its sensor units,
/// the log rotation install.sh enables, the clock, the witness, the env files' modes, the
/// failure hook every unit names in OnFailure= and the binaries its units run.
#[test]
fn a_collector_and_a_gateway_only_host_still_report_their_own_units_rotation_clock_witness_env_files_hook_and_binaries()
 {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.unit("sensor-ssh.service", "enabled", "inactive");
    fx.unit("propolis-logrotate.timer", "enabled", "inactive");
    fx.write("state/ntp_unsynced", "");
    fx.unit("propolis-witness@hourly.timer", "disabled", "inactive");
    std::fs::set_permissions(
        fx.p("etc/shipper.env"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::remove_file(fx.p("sbin/propolis-alert")).unwrap();
    fx.exec("build/shipper", "exit 2\n");
    // The shipper's list and cursors: one log the shipper has not saved a cursor for.
    let ssh = std::fs::canonicalize(fx.p("logs/ssh/events.jsonl")).unwrap();
    let ssh = ssh.to_str().unwrap().to_string();
    std::fs::remove_file(fx.p(&format!("state/cursors/{}.json", sha256_hex(&ssh)))).unwrap();
    let ids = tsv_ids(&run_installed(&fx, &script, &["--tsv"]).out);
    for id in [
        "unit-down",
        "timer",
        "clock-unsynced",
        "witness-timer",
        "env-mode",
        "ops-failure-hook",
        "bins-differ",
        "cursor-missing",
    ] {
        assert!(ids.iter().any(|i| i == id), "collector: no {id} in {ids:?}");
    }
    for id in DAEMON_HOST_IDS {
        assert!(!ids.iter().any(|i| i == id), "collector: {id} in {ids:?}");
    }
    let v = run_installed(&fx, &script, &["--json"]).json();
    assert!(
        v["findings"].as_array().unwrap().iter().any(|f| {
            f["id"] == "cursor-missing" && f["message"].as_str().unwrap().contains(&ssh)
        }),
        "collector: no cursor-missing for {ssh}: {}",
        v["findings"]
    );

    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    fx.unit("propolis-logrotate.timer", "enabled", "inactive");
    fx.write("state/ntp_unsynced", "");
    fx.unit("propolis-witness@hourly.timer", "disabled", "inactive");
    std::fs::set_permissions(
        fx.p("etc/gateway.env"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::remove_file(fx.p("sbin/propolis-alert")).unwrap();
    fx.exec("build/gateway", "exit 2\n");
    // The gateway's spool: a collector directory no intake entry lists.
    fx.spool("collector-unlisted", 200, NOW - 60);
    let v = fx.json();
    let ids: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        v["findings"].as_array().unwrap().iter().any(|f| {
            f["id"] == "spool-unlisted"
                && f["message"]
                    .as_str()
                    .unwrap()
                    .contains("collector-unlisted")
        }),
        "gateway: no spool-unlisted for collector-unlisted: {}",
        v["findings"]
    );
    for id in [
        "timer",
        "clock-unsynced",
        "witness-timer",
        "env-mode",
        "ops-failure-hook",
        "bins-differ",
        "spool-unlisted",
    ] {
        assert!(ids.iter().any(|i| i == id), "gateway: no {id} in {ids:?}");
    }
    for id in DAEMON_HOST_IDS {
        assert!(!ids.iter().any(|i| i == id), "gateway: {id} in {ids:?}");
    }
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains(": gateway (built but not installed"),
        "{}",
        v["findings"]
    );
}

/// A host whose daemon is enabled, or running though not enabled, is not a collector or a
/// gateway-only host, whatever env files it has: every check runs again, also when pa_role's own
/// systemctl query fails and it still answers collector from shipper.env alone.
#[test]
fn a_collector_or_gateway_only_host_whose_daemon_is_enabled_or_running_reports_every_check_again() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    for (case, enabled, active, quiet_fails) in [
        ("enabled", "enabled", "active", false),
        (
            "enabled, pa_role still answering collector",
            "enabled",
            "active",
            true,
        ),
        (
            "enabled, stopped, pa_role still answering collector",
            "enabled",
            "inactive",
            true,
        ),
        ("started by hand", "disabled", "active", false),
        // Failed is not stopped: a daemon that dies is still this host's.
        ("disabled and failed", "disabled", "failed", false),
    ] {
        fx.unit("propolis.service", enabled, active);
        if quiet_fails {
            fx.write("state/quiet_fails", "");
        } else {
            let _ = std::fs::remove_file(fx.p("state/quiet_fails"));
        }
        let ids = tsv_ids(&run_installed(&fx, &script, &["--tsv"]).out);
        for id in DAEMON_HOST_IDS
            .iter()
            .copied()
            .chain(["bins-differ", "stamp-behind"])
        {
            assert!(ids.iter().any(|i| i == id), "{case}: no {id} in {ids:?}");
        }
        let text = run_installed(&fx, &script, &[]);
        assert!(
            report_line(&text, "role:").is_none(),
            "{case}:\n{}",
            text.out
        );
    }

    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    fx.unit("propolis.service", "enabled", "active");
    let ids = tsv_ids(&fx.run(&["--tsv"]).out);
    for id in DAEMON_HOST_IDS {
        assert!(ids.iter().any(|i| i == id), "gateway: no {id} in {ids:?}");
    }
    assert!(report_line(&fx.run(&[]), "role:").is_none());
}

/// A role that cannot be read never hides a finding: with no systemctl to ask (pa_role then finds
/// no unit enabled and answers collector from shipper.env alone), with a library that has no
/// pa_role, whose pa_role fails or answers a word that is not a role, and with role unknown, every
/// check runs as on a host that runs the daemon.
#[test]
fn a_host_whose_role_cannot_be_read_reports_every_check() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    let expect = |case: &str, r: &Run| {
        let ids = tsv_ids(&r.out);
        for id in DAEMON_HOST_IDS {
            assert!(
                ids.iter().any(|i| i == id),
                "{case}: no {id} in {ids:?}\n{}\n{}",
                r.out,
                r.err
            );
        }
    };

    std::fs::rename(fx.p("stubs/systemctl"), fx.p("stubs-systemctl")).unwrap();
    expect("no systemctl", &run_installed(&fx, &script, &["--tsv"]));
    let text = run_installed(&fx, &script, &[]);
    assert!(report_line(&text, "role:").is_none(), "{}", text.out);
    std::fs::rename(fx.p("stubs-systemctl"), fx.p("stubs/systemctl")).unwrap();

    for (case, body) in [
        ("no pa_role", "unset -f pa_role\n"),
        (
            "pa_role fails after a word",
            "pa_role() { printf collector; return 1; }\n",
        ),
        (
            "pa_role answers no role",
            "pa_role() { printf 'collectors'; }\n",
        ),
    ] {
        let lib = fx.p("old-lib/alert-lib.sh");
        fx.write("old-lib/alert-lib.sh", &format!(". {ALERT_LIB}\n{body}"));
        let lib = lib.display().to_string();
        let env = [
            ("PROPOLIS_CC_REPO_DIR", ""),
            ("PROPOLIS_CC_ALERT_LIB", lib.as_str()),
        ];
        expect(case, &fx.run_script(&script, &["--tsv"], &env));
        let text = fx.run_script(&script, &[], &env);
        assert!(
            report_line(&text, "role:").is_none(),
            "{case}:\n{}",
            text.out
        );
    }

    std::fs::remove_file(fx.p("etc/shipper.env")).unwrap();
    expect("role unknown", &run_installed(&fx, &script, &["--tsv"]));
}

/// The witness and the walk parse --tsv. On a collector a check that was not run prints no F
/// line, no L line (one of no group the witness knows would keep every finding from resolving)
/// and no G row in a problem state: its row reads skip, and the S record counts nothing.
#[test]
fn a_collectors_tsv_holds_no_finding_limit_or_problem_row_for_a_check_it_left_out() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    set_backup_timer(&fx, Some(("disabled", "inactive")));
    let r = run_installed(&fx, &script, &["--tsv"]);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines[0], "#config-check tsv v1", "{}", r.out);
    let s: Vec<&str> = lines[1].split('\t').collect();
    assert_eq!(&s[..6], &["S", "ok", "0", "0", "0", "0"], "{}", r.out);
    assert_eq!(lines.last(), Some(&"E\t0"), "{}", r.out);
    for l in &lines {
        assert!(
            !l.starts_with("F\t") && !l.starts_with("L\t"),
            "{l}\n{}",
            r.out
        );
    }
    let row = |id: &str| -> String {
        lines
            .iter()
            .find_map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                (f[0] == "G" && f.get(1) == Some(&id)).then(|| f[2].to_string())
            })
            .unwrap_or_else(|| panic!("no G row {id}:\n{}", r.out))
    };
    for id in ["backup", "watcher", "deploy-stamp"] {
        assert_eq!(row(id), "skip", "{id}:\n{}", r.out);
    }
    assert_eq!(row("alerting"), "ok", "{}", r.out);
    for l in lines.iter().filter(|l| l.starts_with("G\t")) {
        let state = l.split('\t').nth(2).unwrap();
        assert!(state == "ok" || state == "skip", "{l}\n{}", r.out);
    }
}

/// A collector's hand upgrade installs the sensors and the shipper from the build and leaves the
/// daemon's binary, propolis-watch and the deploy stamp as install.sh wrote them. The binaries a
/// unit on the collector runs are still compared and still reported missing, with the collector's
/// own steps as the fix (deploy/upgrade.sh must not run there); the others and the stamp are the
/// control node's. With the daemon enabled the whole comparison comes back.
#[test]
fn a_collector_compares_only_the_binaries_its_units_run_and_leaves_the_deploy_stamp_to_the_control_node()
 {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.exec("build/shipper", "exit 2\n");
    fx.exec("build/propolis-watch", "exit 2\n");
    std::fs::remove_file(fx.p("bin/sensor-mqtt")).unwrap();
    std::fs::remove_file(fx.p("bin/propolis")).unwrap();
    let v = run_installed(&fx, &script, &["--json"]).json();
    let by_id = |v: &serde_json::Value, id: &str| -> serde_json::Value {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no {id} in {}", v["findings"]))
    };
    let differ = by_id(&v, "bins-differ");
    let msg = differ["message"].as_str().unwrap();
    assert!(msg.contains(": shipper (built"), "{msg}");
    assert!(!msg.contains("propolis-watch"), "{msg}");
    let missing = by_id(&v, "bins-missing");
    let msg = missing["message"].as_str().unwrap();
    assert!(msg.contains(": sensor-mqtt (the units"), "{msg}");
    for f in [&differ, &missing] {
        assert_eq!(f["fix_kind"], "manual", "{f}");
        let fix = f["fix"].as_str().unwrap();
        assert!(fix.contains("docs/operations/split-deployment.md"), "{f}");
        assert!(!fix.contains("upgrade.sh"), "{f}");
    }
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(!ids.iter().any(|i| i.starts_with("stamp-")), "{ids:?}");
    assert_eq!(global_state(&v, "deploy-stamp"), "skip", "{}", v["global"]);

    fx.unit("propolis.service", "enabled", "active");
    let v = run_installed(&fx, &script, &["--json"]).json();
    let msg = by_id(&v, "bins-differ")["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(msg.contains("propolis-watch"), "{msg}");
    let missing = by_id(&v, "bins-missing");
    assert!(
        missing["message"]
            .as_str()
            .unwrap()
            .contains(": propolis sensor-mqtt ("),
        "{missing}"
    );
    assert!(
        missing["fix"].as_str().unwrap().ends_with("upgrade.sh"),
        "{missing}"
    );
    by_id(&v, "stamp-behind");
}

/// deploy/backup.sh dumps whatever database DATABASE_URL in propolis.env names, on any host, so a
/// collector or a gateway-only host that has one still has its backup checked.
#[test]
fn a_collector_or_gateway_only_host_with_a_database_url_still_has_its_backup_checked() {
    let url = "DATABASE_URL=postgres://propolis@db.example.invalid/propolis\n";
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.write("etc/propolis.env", url);
    set_backup_timer(&fx, Some(("disabled", "inactive")));
    let ids = tsv_ids(&run_installed(&fx, &script, &["--tsv", "--no-events"]).out);
    for id in ["backup-never", "backup-timer"] {
        assert!(ids.iter().any(|i| i == id), "collector: no {id} in {ids:?}");
    }

    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    fx.write("etc/propolis.env", url);
    set_backup_timer(&fx, Some(("disabled", "inactive")));
    let ids = tsv_ids(&fx.run(&["--tsv", "--no-events"]).out);
    for id in ["backup-never", "backup-timer"] {
        assert!(ids.iter().any(|i| i == id), "gateway: no {id} in {ids:?}");
    }
}

/// The text of the HOST row `id` in a run's TSV.
fn tsv_row_text(tsv: &str, id: &str) -> String {
    tsv.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[0] == "G" && f.get(1) == Some(&id)).then(|| f.get(3).unwrap_or(&"").to_string())
        })
        .unwrap_or_else(|| panic!("no G row {id}:\n{tsv}"))
}

/// The finding `id` of a --json run.
fn json_finding(v: &serde_json::Value, id: &str) -> serde_json::Value {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("no {id} in {}", v["findings"]))
}

/// deploy/watch-env.sh writes watch.env from PROPOLIS_SENSOR_LOGS in propolis.env, and
/// deploy/backup.sh dumps the database DATABASE_URL there names, on whatever host they run. So a
/// host whose propolis.env names either is set up to run the daemon, and is checked in full even
/// when its daemon is stopped and pa_role reads gateway (a control node with the daemon disabled
/// or masked) or collector (a single box with a leftover shipper.env).
#[test]
fn a_host_whose_propolis_env_configures_the_daemon_is_checked_in_full_though_the_daemon_is_stopped()
{
    let setup = |fx: &Fx| {
        std::fs::remove_file(fx.p("etc/watch.env")).unwrap();
        std::fs::remove_file(fx.p("home-watch/.ssh/authorized_keys")).unwrap();
        fx.set_env_line("etc/propolis.env", "PROPOLIS_OPS_ENABLED=", None);
        fx.exec("build/propolis", "exit 2\n");
    };
    let expect = |case: &str, fx: &Fx| {
        let r = fx.run(&["--tsv"]);
        let ids = tsv_ids(&r.out);
        for id in [
            "watch-env-missing",
            "watch-key-missing",
            "ops-monitor-off",
            "bins-differ",
        ] {
            assert!(
                ids.iter().any(|i| i == id),
                "{case}: no {id} in {ids:?}\n{}",
                r.out
            );
        }
        let v = fx.json();
        assert!(
            json_finding(&v, "bins-differ")["message"]
                .as_str()
                .unwrap()
                .contains("propolis"),
            "{case}: {}",
            v["findings"]
        );
        let text = fx.run(&[]);
        assert!(
            report_line(&text, "role:").is_none(),
            "{case}:\n{}",
            text.out
        );
    };

    // A control node whose daemon is stopped: pa_role reads gateway.
    for daemon in ["disabled", "masked"] {
        let fx = Fx::new();
        setup(&fx);
        fx.unit("gateway.service", "enabled", "active");
        fx.unit("propolis.service", daemon, "inactive");
        expect(&format!("control node, daemon {daemon}"), &fx);
    }

    // A single box with a shipper.env left behind: pa_role reads collector.
    let fx = Fx::new();
    setup(&fx);
    fx.write(
        "etc/shipper.env",
        &format!(
            "PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{}/ssh/events.jsonl\n",
            fx.logs()
        ),
    );
    fx.unit("propolis.service", "disabled", "inactive");
    expect("single box with a leftover shipper.env", &fx);

    // Either setting alone is enough.
    let fx = Fx::new();
    setup(&fx);
    fx.unit("gateway.service", "enabled", "active");
    fx.unit("propolis.service", "disabled", "inactive");
    fx.set_env_line("etc/propolis.env", "DATABASE_URL=", None);
    expect("intake list only", &fx);
}

/// Where a collector has no propolis.env at all, nothing on it configures the daemon: the
/// daemon's checks are left out as with provisioning's empty file.
#[test]
fn a_collector_without_a_propolis_env_leaves_the_daemons_checks_out() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    std::fs::remove_file(fx.p("etc/propolis.env")).unwrap();
    let ids = tsv_ids(&run_installed(&fx, &script, &["--tsv"]).out);
    for id in DAEMON_HOST_IDS {
        assert!(!ids.iter().any(|i| i == id), "{id} in {ids:?}");
    }
    let text = run_installed(&fx, &script, &[]);
    assert!(
        report_line(&text, "role: collector;").is_some(),
        "{}",
        text.out
    );
}

/// deploy/alert.sh, the failure hook every unit on a collector names in OnFailure=, posts each
/// unit failure to the PROPOLIS_OPS_NTFY_* target in this host's own propolis.env, whatever the
/// role. So the alerting row says where the hook posts, or that it writes to the journal only,
/// and leaves to the control node only the daemon's monitor and heartbeat. A URL is shown without
/// any user name or password it carries.
#[test]
fn a_collectors_alerting_row_names_where_its_failure_hook_posts() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t\n",
    );
    let r = run_installed(&fx, &script, &["--tsv"]);
    let row = tsv_row_text(&r.out, "alerting");
    assert!(row.contains("http://ntfy.example.invalid"), "{row}");
    assert!(!row.contains("push target"), "{row}");
    assert!(!row.contains("journal only"), "{row}");
    assert!(
        row.contains("monitor and heartbeat are checked on the control node"),
        "{row}"
    );
    let ids = tsv_ids(&r.out);
    for id in DAEMON_HOST_IDS {
        assert!(!ids.iter().any(|i| i == id), "{id} in {ids:?}");
    }

    // Of the URL the report shows the scheme and the host only: a user name and password, a
    // path (a topic written into the URL) and a query (ntfy takes a token there) stay in the file.
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ops:s3cret@ntfy.example.invalid:8443/pathpart?auth=tok3n\nPROPOLIS_OPS_NTFY_TOPIC=t\n",
    );
    for mode in ["--tsv", "--json"] {
        let r = run_installed(&fx, &script, &[mode]);
        assert!(
            r.out.contains("https://ntfy.example.invalid:8443 "),
            "{mode}: {}",
            r.out
        );
        for part in ["s3cret", "ops:", "pathpart", "tok3n", "auth="] {
            assert!(!r.out.contains(part), "{mode}: {part} in {}", r.out);
        }
    }
    // A value that is not a plain URL of that form is not shown at all.
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid/pathpart\nPROPOLIS_OPS_NTFY_TOPIC=t\n",
    );
    let r = run_installed(&fx, &script, &["--tsv"]);
    let row = tsv_row_text(&r.out, "alerting");
    assert!(
        row.contains("it posts unit failures to the target"),
        "{row}"
    );
    assert!(!r.out.contains("pathpart"), "{}", r.out);

    fx.write("etc/propolis.env", "");
    let row = tsv_row_text(&run_installed(&fx, &script, &["--tsv"]).out, "alerting");
    assert!(row.contains("journal only"), "{row}");
    assert!(!row.contains("ntfy.example.invalid"), "{row}");
}

/// A collector has no upgrade script of its own, so a missing failure hook there names the
/// collector's written steps, and its message does not speak of a daemon the host does not run.
/// A gateway-only host is upgraded with deploy/upgrade.sh, which installs the hook.
#[test]
fn a_missing_failure_hook_names_the_collectors_steps_on_a_collector_and_the_upgrade_script_on_a_gateway_only_host()
 {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    std::fs::remove_file(fx.p("sbin/propolis-alert")).unwrap();
    let f = json_finding(
        &run_installed(&fx, &script, &["--json"]).json(),
        "ops-failure-hook",
    );
    assert_eq!(f["fix_kind"], "manual", "{f}");
    let fix = f["fix"].as_str().unwrap();
    assert!(fix.contains("docs/operations/split-deployment.md"), "{f}");
    assert!(!fix.contains("upgrade.sh"), "{f}");
    let message = f["message"].as_str().unwrap();
    assert!(!message.contains("(the daemon included)"), "{f}");
    // The witness on this host still records a unit it samples as failed, hook or no hook.
    assert!(!message.contains("not recorded"), "{f}");

    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
    std::fs::remove_file(fx.p("sbin/propolis-alert")).unwrap();
    let f = json_finding(&fx.json(), "ops-failure-hook");
    assert!(f["fix"].as_str().unwrap().ends_with("upgrade.sh"), "{f}");
    assert_ne!(f["fix_kind"], "manual", "{f}");
}

/// A gateway-only host is upgraded with deploy/upgrade.sh, so a binary of its own that differs
/// from the build names that script; only a collector's fix is its written steps.
#[test]
fn a_gateway_only_hosts_differing_binary_names_the_upgrade_script() {
    let fx = Fx::new();
    healthy_gateway_only_host(&fx);
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
    fx.exec("build/gateway", "exit 2\n");
    let f = json_finding(&fx.json(), "bins-differ");
    assert!(f["fix"].as_str().unwrap().ends_with("upgrade.sh"), "{f}");
    assert_ne!(f["fix_kind"], "manual", "{f}");
}

/// systemd reports a unit that cannot be started as masked, and a unit with no file as
/// not-found: on a collector either leaves the daemon's checks out, as disabled does.
#[test]
fn a_collector_whose_daemon_unit_is_masked_or_not_installed_leaves_the_daemons_checks_out() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    for case in ["masked", "not installed"] {
        if case == "masked" {
            fx.unit("propolis.service", "masked", "inactive");
        } else {
            for dir in ["enabled", "active"] {
                std::fs::remove_file(fx.p(&format!("state/{dir}/propolis.service"))).unwrap();
            }
        }
        let ids = tsv_ids(&run_installed(&fx, &script, &["--tsv"]).out);
        for id in DAEMON_HOST_IDS {
            assert!(!ids.iter().any(|i| i == id), "{case}: {id} in {ids:?}");
        }
        let text = run_installed(&fx, &script, &[]);
        assert!(
            report_line(&text, "role: collector;").is_some(),
            "{case}:\n{}",
            text.out
        );
    }
}

/// A propolis.env this run cannot read is not known to configure no daemon: the host is checked
/// in full, its backup included, and no role line claims a check was left out.
#[test]
fn a_collector_whose_propolis_env_cannot_be_read_is_checked_in_full() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    let penv = fx.p("etc/propolis.env");
    // Root reads through any mode, so as root the run drops to nobody, with the fixture's own
    // directories opened for traversal and propolis.env left root's at 0600.
    let wrapper: Vec<&str> = if is_root() {
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o000)).unwrap();
        vec![]
    };
    let env = [("PROPOLIS_CC_REPO_DIR", ""), ("PROPOLIS_CC_EUID", "1000")];
    let r = fx.run_script_under(&script, &wrapper, &["--tsv"], &env);
    let text = fx.run_script_under(&script, &wrapper, &[], &env);
    std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o600)).unwrap();
    let backup = r
        .out
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[0] == "G" && f.get(1) == Some(&"backup")).then(|| f[2].to_string())
        })
        .unwrap_or_else(|| panic!("no G row backup:\n{}\n{}", r.out, r.err));
    assert_ne!(backup, "skip", "{}", r.out);
    assert!(
        report_line(&text, "role:").is_none(),
        "{}\n{}",
        text.out,
        text.err
    );
}

#[test]
fn an_installed_copy_without_repo_dir_turns_checkout_fixes_manual() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("sbin/propolis-logrotate-guard")).unwrap();
    std::fs::remove_file(fx.p("state/deploy-stamp.json")).unwrap();
    for repo_dir in [
        None,
        Some("relative/path\n"),
        Some("/one\n/two\n"),
        Some(""),
    ] {
        let script = install_copy(&fx, repo_dir);
        let _ = std::fs::remove_file(fx.p("lib/repo-dir"));
        if let Some(text) = repo_dir {
            std::fs::write(fx.p("lib/repo-dir"), text).unwrap();
        }
        let v = run_installed(&fx, &script, &["--json"]).json();
        let limit = format!(
            "checkout unknown: {}/repo-dir missing or invalid; fix lines that need the checkout are manual",
            fx.p("lib").display()
        );
        assert!(
            v["limited"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l == limit.as_str()),
            "{repo_dir:?}: {}",
            v["limited"]
        );
        let find = |id: &str| -> serde_json::Value {
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .unwrap_or_else(|| panic!("{repo_dir:?}: no {id} in {}", v["findings"]))
                .clone()
        };
        let stamp = find("stamp-missing");
        assert_eq!(stamp["fix_kind"], "manual", "{stamp}");
        assert_eq!(
            stamp["fix"],
            "from the top of the Propolis checkout run: sudo ./deploy/upgrade.sh"
        );
        let guard = find("guard");
        assert_eq!(guard["fix_kind"], "manual", "{guard}");
        assert!(
            guard["fix"]
                .as_str()
                .unwrap()
                .starts_with("from the top of the Propolis checkout run: sudo install -m 0755 ./deploy/logrotate-guard.sh "),
            "{guard}"
        );
        for f in v["findings"].as_array().unwrap() {
            if f["fix_kind"] == "run" {
                let fix = f["fix"].as_str().unwrap();
                assert!(
                    !fix.contains("deploy/")
                        && !fix.contains(&fx.p("lib/upgrade.sh").display().to_string()),
                    "{repo_dir:?}: a run fix names a checkout path it does not know: {f}"
                );
            }
        }
    }

    // A repo-dir that is a symbolic link, even to a valid one-line file naming a real checkout, is
    // not the installer's.
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
    let script = install_copy(&fx, None);
    let _ = std::fs::remove_file(fx.p("lib/repo-dir"));
    fx.write(
        "elsewhere/repo-dir",
        &format!("{}\n", fx.p("repo").display()),
    );
    std::os::unix::fs::symlink(fx.p("elsewhere/repo-dir"), fx.p("lib/repo-dir")).unwrap();
    let v = run_installed(&fx, &script, &["--json"]).json();
    assert!(
        v["limited"].as_array().unwrap().iter().any(|l| l
            == format!(
                "checkout unknown: {}/repo-dir missing or invalid; fix lines that need the checkout are manual",
                fx.p("lib").display()
            )
            .as_str()),
        "a linked repo-dir: {}",
        v["limited"]
    );
    let guard = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "guard")
        .unwrap()
        .clone();
    assert_eq!(guard["fix_kind"], "manual", "a linked repo-dir: {guard}");
    std::fs::remove_file(fx.p("lib/repo-dir")).unwrap();

    // A repo-dir that names a path holding no checkout (moved, deleted, or hidden from the
    // sandbox): the same manual fixes and a limit naming the path, whether the stamp is absent or
    // has no head to compare, so nothing points at scripts that are not there.
    let gone = fx.p("gone-checkout").display().to_string();
    let script = install_copy(&fx, Some(&format!("{gone}\n")));
    let limit = format!(
        "checkout unknown: {}/repo-dir names {gone}, which holds no deploy/upgrade.sh (moved, deleted, or not visible from this sandbox); fix lines that need the checkout are manual",
        fx.p("lib").display()
    );
    for (stamp, stamp_id) in [
        (None, "stamp-missing"),
        (
            Some("{\"head_sha\": \"\", \"installed\": {\"propolis\": \"\"}}\n"),
            "stamp-nohead",
        ),
    ] {
        let _ = std::fs::remove_file(fx.p("state/deploy-stamp.json"));
        if let Some(text) = stamp {
            fx.write("state/deploy-stamp.json", text);
        }
        let v = run_installed(&fx, &script, &["--json"]).json();
        assert!(
            v["limited"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l == limit.as_str()),
            "{stamp_id}: {}",
            v["limited"]
        );
        let find = |id: &str| -> serde_json::Value {
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .unwrap_or_else(|| panic!("{stamp_id}: no {id} in {}", v["findings"]))
                .clone()
        };
        let stamp = find(stamp_id);
        assert_eq!(stamp["fix_kind"], "manual", "{stamp}");
        assert_eq!(
            stamp["fix"],
            "from the top of the Propolis checkout run: sudo ./deploy/upgrade.sh"
        );
        assert_eq!(find("guard")["fix_kind"], "manual");
        for f in v["findings"].as_array().unwrap() {
            assert!(
                !f["fix"].as_str().unwrap().contains(&gone),
                "{stamp_id}: a fix names the checkout that is not there: {f}"
            );
        }
    }

    // A stamp that agrees with the installed binary says nothing about the checkout. Without one
    // the build was not compared and the stamp was not held against HEAD, so neither row may read
    // ok, whether the checkout is gone or repo-dir is missing. Every listed binary is installed
    // here, and no build directory is given, as on a real host.
    fx.exec("bin/sensor-extra", "exit 0\n");
    fx.write(
        "state/deploy-stamp.json",
        "{\"head_sha\": \"abcdef0123456789\", \"installed\": {\"propolis\": \"abcdef0123456789\"}}\n",
    );
    let global_text = |v: &serde_json::Value, id: &str| -> String {
        v["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == id)
            .map(|g| g["text"].as_str().unwrap().to_string())
            .unwrap_or_default()
    };
    for repo_dir in [Some(format!("{gone}\n")), None] {
        let script = install_copy(&fx, repo_dir.as_deref());
        if repo_dir.is_none() {
            let _ = std::fs::remove_file(fx.p("lib/repo-dir"));
        }
        let v = fx
            .run_script(
                &script,
                &["--json"],
                &[("PROPOLIS_CC_REPO_DIR", ""), ("PROPOLIS_CC_BUILD_DIR", "")],
            )
            .json();
        assert_eq!(global_state(&v, "binaries"), "unknown", "{repo_dir:?}: {v}");
        assert!(
            global_text(&v, "binaries").ends_with(", build not compared (checkout unknown)"),
            "{repo_dir:?}: {}",
            global_text(&v, "binaries")
        );
        assert_eq!(
            global_state(&v, "deploy-stamp"),
            "unknown",
            "{repo_dir:?}: {v}"
        );
        assert!(
            global_text(&v, "deploy-stamp")
                .ends_with(", checkout unknown: stamp-behind not checked"),
            "{repo_dir:?}: {}",
            global_text(&v, "deploy-stamp")
        );
        assert!(
            v["counts"]["unknown"].as_i64().unwrap() >= 2,
            "{repo_dir:?}: the two rows count as unknown: {}",
            v["counts"]
        );
        assert!(
            !v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["id"] == "stamp-behind" || f["id"] == "bins-differ"),
            "{repo_dir:?}: a check that was not made is not a finding: {}",
            v["findings"]
        );
    }
}

/// The installed copy's build comparison: the build is read as the checkout's owner and compared
/// by digest, and a build file it could not read is a limit and an unknown row, never a difference.
#[test]
fn an_installed_copy_compares_the_build_by_digest_and_an_unread_build_is_unknown_not_a_difference()
{
    let fx = Fx::new();
    let repo = fx.p("repo").display().to_string();
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
    let script = install_copy(&fx, Some(&format!("{repo}\n")));
    // upgrade.sh's own list, with no sensor-extra, so only the build decides the binaries row.
    std::fs::write(
        fx.p("lib/install-bins"),
        format!("INSTALL_BINS=({})\n", install_bins().join(" ")),
    )
    .unwrap();
    let build = fx.p("build").display().to_string();
    fx.write("build/sensor-mqtt", &fx.read("bin/sensor-mqtt"));
    fx.write("build/sensor-ssh", "new build");
    std::os::unix::fs::symlink(fx.p("bin/sensor-dns"), fx.p("build/sensor-dns")).unwrap();
    let limit = format!(
        "the build of sensor-dns in {build} was not compared with the installed binary: not a regular file as {}",
        current_user()
    );
    let differ = |v: &serde_json::Value| -> Vec<String> {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["id"] == "bins-differ")
            .map(|f| f["message"].as_str().unwrap().to_string())
            .collect()
    };
    let v = run_installed(&fx, &script, &["--json"]).json();
    let found = differ(&v);
    assert_eq!(found.len(), 1, "{}", v["findings"]);
    assert!(
        found[0].contains("sensor-ssh")
            && !found[0].contains("sensor-mqtt")
            && !found[0].contains("sensor-dns"),
        "{}",
        found[0]
    );
    assert!(
        v["limited"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == limit.as_str()),
        "{}",
        v["limited"]
    );
    // A difference outranks a build that was not compared.
    assert_eq!(global_state(&v, "binaries"), "warn", "{}", v["global"]);

    // The link alone: nothing differs, and the row says the build was not compared.
    std::fs::remove_file(fx.p("build/sensor-ssh")).unwrap();
    std::fs::remove_file(fx.p("build/sensor-mqtt")).unwrap();
    let v = run_installed(&fx, &script, &["--json"]).json();
    assert!(differ(&v).is_empty(), "{}", v["findings"]);
    assert_eq!(global_state(&v, "binaries"), "unknown", "{}", v["global"]);
    assert!(
        global_text(&v, "binaries").ends_with(", build not compared for: sensor-dns"),
        "{}",
        global_text(&v, "binaries")
    );
    assert!(
        v["limited"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == limit.as_str()),
        "{}",
        v["limited"]
    );
    let r = run_installed(&fx, &script, &[]);
    assert_eq!(r.code, 1, "{}", r.out);
}

/// `id` answers for propolis (unless `propolis_known` is false) and for `owner` with numbers of
/// their own, and `setpriv` logs the uid it is asked to become and the file the child reads, then
/// runs the child as the caller. Together they show which account each read drops to, as root or
/// not.
fn stub_privilege_drop(fx: &Fx, propolis_known: bool, owner: &str) {
    let real_id = ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .expect("no id on this host");
    let propolis = if propolis_known {
        "  -u:propolis | -g:propolis) echo 4001; exit 0 ;;\n"
    } else {
        "  -u:propolis | -g:propolis) exit 1 ;;\n"
    };
    // The library asks `id -u -- USER`, so the account is the third argument.
    fx.exec(
        "stubs/id",
        &format!(
            "case \"$1:$3\" in\n{propolis}  \"-u:{owner}\" | \"-g:{owner}\") echo 4002; exit 0 ;;\nesac\nexec {real_id} \"$@\"\n"
        ),
    );
    fx.exec(
        "stubs/setpriv",
        r#"uid=""
for a in "$@"; do case "$a" in --reuid=*) uid="${a#--reuid=}" ;; esac; done
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
printf '%s %s\n' "$uid" "$5" >> "$STUB_STATE/setpriv.log"
exec "$@"
"#,
    );
}

/// The cursor file that holds intake's position in `path`.
fn cursor_path(fx: &Fx, path: &str) -> String {
    let resolved = std::fs::canonicalize(path).unwrap();
    fx.p(&format!(
        "state/cursors/{}.json",
        sha256_hex(resolved.to_str().unwrap())
    ))
    .display()
    .to_string()
}

/// As root, with no read-as-self shortcut: the daemon's cursor is read as propolis, and the
/// checkout's HEAD, its ref and its build output as the account that owns the checkout.
#[test]
fn the_cursor_is_read_as_propolis_and_the_checkout_and_its_build_as_their_owner() {
    let fx = Fx::new();
    // The checkout's owner must not be root, or a read as root would pass for a read as the
    // owner: as root, the fixture's checkout is handed to nobody's uid.
    if is_root() {
        std::os::unix::fs::chown(fx.p("repo"), Some(65534), Some(65534)).unwrap();
    }
    let owner = String::from_utf8(
        Command::new("stat")
            .args(["-c", "%U"])
            .arg(fx.p("repo"))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert_ne!(owner, "root");
    stub_privilege_drop(&fx, true, &owner);
    let drop = [("PA_TEST_READ_AS_SELF", ""), ("PA_TEST_UID", "0")];
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    spool_cursor(&fx, &spool, 300, None);
    let cursor = cursor_path(&fx, &spool);
    let repo = fx.p("repo").display().to_string();
    let head = fx.read("repo/.git/HEAD");
    let branch = head.trim().strip_prefix("ref: ").unwrap().to_string();
    let v = fx.run_with(&["--json"], &drop).json();
    let log = fx.read("state/setpriv.log");
    let lines: Vec<&str> = log.lines().collect();
    for want in [
        format!("4001 {cursor}"),
        format!("4002 {repo}/.git/HEAD"),
        format!("4002 {repo}/.git/{branch}"),
    ] {
        assert!(lines.contains(&want.as_str()), "no `{want}` in:\n{log}");
    }
    assert!(
        !v["limited"].to_string().contains("HEAD"),
        "{}",
        v["limited"]
    );

    // The installed copy reads the build as the checkout's owner too.
    fx.exec("repo/deploy/upgrade.sh", "exit 0\n");
    let script = install_copy(&fx, Some(&format!("{repo}\n")));
    fx.write("build/sensor-ssh", "new build");
    std::fs::remove_file(fx.p("state/setpriv.log")).unwrap();
    let v = fx
        .run_script(
            &script,
            &["--json"],
            &[drop[0], drop[1], ("PROPOLIS_CC_REPO_DIR", "")],
        )
        .json();
    let log = fx.read("state/setpriv.log");
    let want = format!("4002 {}", fx.p("build/sensor-ssh").display());
    assert!(log.lines().any(|l| l == want), "no `{want}` in:\n{log}");
    assert!(
        finding_messages(&v)
            .join("\n")
            .contains("installed binaries differ from the build"),
        "{}",
        v["findings"]
    );
}

/// A cursor that cannot be read is named with the account it was read as: propolis under root
/// (where the account may also be missing), the caller otherwise.
#[test]
fn a_cursor_that_cannot_be_read_names_the_account_it_was_read_as() {
    let unlisted_message = |v: &serde_json::Value| -> String {
        let found = spool_findings(v);
        assert_eq!(found.len(), 1, "{found:?}");
        found[0]["message"].as_str().unwrap().to_string()
    };

    // Root, and no propolis account to read as.
    let fx = Fx::new();
    stub_privilege_drop(&fx, false, &current_user());
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    spool_cursor(&fx, &spool, 300, None);
    let cursor = cursor_path(&fx, &spool);
    let v = fx
        .run_with(
            &["--json"],
            &[("PA_TEST_READ_AS_SELF", ""), ("PA_TEST_UID", "0")],
        )
        .json();
    let msg = unlisted_message(&v);
    assert!(
        msg.contains(&format!(
            "its cursor {cursor} is not readable as propolis (or the propolis account is missing)"
        )),
        "{msg}"
    );

    // A cursor this account cannot open (mode 0000; as root, the run drops to nobody).
    let fx = Fx::new();
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    spool_cursor(&fx, &spool, 300, None);
    let cursor = cursor_path(&fx, &spool);
    std::fs::set_permissions(&cursor, std::fs::Permissions::from_mode(0o000)).unwrap();
    let penv = fx.p("etc/propolis.env");
    let wrapper: Vec<&str> = if is_root() {
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o644)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        vec![]
    };
    let r = fx.run_under(&wrapper, &["--json"], &[("PROPOLIS_CC_EUID", "1000")]);
    std::fs::set_permissions(&cursor, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&penv, std::fs::Permissions::from_mode(0o600)).unwrap();
    let msg = unlisted_message(&r.json());
    assert!(
        msg.contains(&format!("its cursor {cursor} is not readable as this user")),
        "{msg}"
    );

    // A read that does not finish in time.
    let fx = Fx::new();
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    spool_cursor(&fx, &spool, 300, None);
    let cursor = cursor_path(&fx, &spool);
    fx.exec("stubs/timeout", "exit 124\n");
    let msg = unlisted_message(&fx.json());
    assert!(
        msg.contains(&format!("its cursor {cursor} could not be read in time")),
        "{msg}"
    );
}

/// Lays out `fx/heads/<name>/.git` by hand, with no git involved.
fn fake_checkout(fx: &Fx, name: &str, files: &[(&str, &str)]) -> String {
    for (rel, body) in files {
        fx.write(&format!("heads/{name}/.git/{rel}"), body);
    }
    fx.p(&format!("heads/{name}")).display().to_string()
}

#[test]
fn head_is_read_from_loose_packed_and_detached_refs_without_running_git() {
    let fx = Fx::new();
    // First on PATH: a git that leaves a mark if anything runs it.
    fx.exec("stubs/git", "touch \"$STUB_STATE/git_ran\"\nexit 1\n");
    let other = "0123456789abcdef0123456789abcdef01234567";
    let other256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let stale = "fedcba9876543210fedcba9876543210fedcba98";
    let head = fx.head.clone();
    let layouts = |at: &str| -> Vec<(&'static str, Vec<(&'static str, String)>)> {
        vec![
            (
                "loose",
                vec![
                    ("HEAD", "ref: refs/heads/main\n".to_string()),
                    ("refs/heads/main", format!("{at}\n")),
                ],
            ),
            (
                "packed",
                vec![
                    ("HEAD", "ref: refs/heads/main\n".to_string()),
                    (
                        "packed-refs",
                        format!(
                            "# pack-refs with: peeled fully-peeled sorted \n{other} refs/heads/mainline\n{at} refs/heads/main\n^{other}\n"
                        ),
                    ),
                ],
            ),
            ("detached", vec![("HEAD", format!("{at}\n"))]),
            // git writes a moved branch as a loose ref and leaves its old packed line behind: the
            // loose ref is the branch.
            (
                "both",
                vec![
                    ("HEAD", "ref: refs/heads/main\n".to_string()),
                    ("refs/heads/main", format!("{at}\n")),
                    ("packed-refs", format!("{stale} refs/heads/main\n")),
                ],
            ),
        ]
    };
    for (at, behind) in [(other, true), (other256, true), (head.as_str(), false)] {
        for (name, files) in layouts(at) {
            let name = format!("{name}-{}", &at[..4]);
            let files: Vec<(&str, &str)> = files.iter().map(|(p, b)| (*p, b.as_str())).collect();
            let _ = std::fs::remove_dir_all(fx.p(&format!("heads/{name}")));
            let dir = fake_checkout(&fx, &name, &files);
            let v = fx
                .run_with(&["--json"], &[("PROPOLIS_CC_REPO_DIR", &dir)])
                .json();
            let ids: Vec<&str> = v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["id"].as_str().unwrap())
                .collect();
            assert_eq!(ids.contains(&"stamp-behind"), behind, "{name}: {ids:?}");
            if behind {
                let msg = finding_messages(&v).join("\n");
                assert!(
                    msg.contains(&format!("the checkout is at {}", &at[..12])),
                    "{name}: {msg}"
                );
            }
            assert!(
                !finding_messages(&v).join("\n").contains(&stale[..12]),
                "{name}: the stale packed line was read before the loose ref"
            );
            assert!(
                !v["limited"].to_string().contains("HEAD"),
                "{name}: {}",
                v["limited"]
            );
        }
    }
    assert!(!fx.p("state/git_ran").exists(), "git was run");
}

#[test]
fn an_unreadable_or_worktree_head_is_a_limit_not_silence() {
    let fx = Fx::new();
    let other = "0123456789abcdef0123456789abcdef01234567";
    let worktree = fx.p("heads/worktree");
    std::fs::create_dir_all(&worktree).unwrap();
    std::fs::write(
        worktree.join(".git"),
        "gitdir: /elsewhere/.git/worktrees/x\n",
    )
    .unwrap();
    let escaping = fake_checkout(
        &fx,
        "escaping",
        &[
            ("HEAD", "ref: refs/heads/../../../etc/passwd\n"),
            ("refs/heads/main", &format!("{other}\n")),
        ],
    );
    let garbage = fake_checkout(&fx, "garbage", &[("HEAD", "not a head\n")]);
    let missing_ref = fake_checkout(&fx, "missing-ref", &[("HEAD", "ref: refs/heads/gone\n")]);
    let linked = fake_checkout(&fx, "linked", &[("real-head", &format!("{other}\n"))]);
    std::os::unix::fs::symlink(
        fx.p("heads/linked/.git/real-head"),
        fx.p("heads/linked/.git/HEAD"),
    )
    .unwrap();
    // A .git that is a link to a valid .git directory is not followed.
    fake_checkout(&fx, "real", &[("HEAD", &format!("{other}\n"))]);
    std::fs::create_dir_all(fx.p("heads/linked-git")).unwrap();
    std::os::unix::fs::symlink(fx.p("heads/real/.git"), fx.p("heads/linked-git/.git")).unwrap();
    let on_main = ("HEAD", "ref: refs/heads/main\n");
    // A loose ref that is there but unusable is the answer: a packed line for the same branch,
    // which would read as the checkout being behind, is not consulted.
    let packed_main = format!("{other} refs/heads/main\n");
    let packed = ("packed-refs", packed_main.as_str());
    let dangling = fake_checkout(&fx, "dangling-ref", &[on_main, packed]);
    std::fs::create_dir_all(fx.p("heads/dangling-ref/.git/refs/heads")).unwrap();
    std::os::unix::fs::symlink(
        fx.p("heads/dangling-ref/.git/nowhere"),
        fx.p("heads/dangling-ref/.git/refs/heads/main"),
    )
    .unwrap();
    let garbage_ref = fake_checkout(
        &fx,
        "garbage-ref",
        &[on_main, ("refs/heads/main", "not a commit\n"), packed],
    );
    let fifo_packed = fake_checkout(&fx, "fifo-packed", &[on_main]);
    let st = Command::new("mkfifo")
        .arg(fx.p("heads/fifo-packed/.git/packed-refs"))
        .status()
        .unwrap();
    assert!(st.success());
    // A packed-refs past 1 MiB, its one line for main naming another commit.
    let big = format!("{}\n{other} refs/heads/main\n", "#".repeat(1024 * 1024));
    let big_packed = fake_checkout(&fx, "big-packed", &[on_main, ("packed-refs", &big)]);
    let nowhere = fx.p("heads/nowhere").display().to_string();
    let linked_git = fx.p("heads/linked-git").display().to_string();
    let owner = current_user();
    let worktree = worktree.display().to_string();
    for (dir, why) in [
        (
            worktree.clone(),
            format!("{worktree}/.git is not a directory, as in a worktree or a submodule"),
        ),
        (
            escaping,
            ".git/HEAD holds neither a commit id nor a branch under refs/heads".to_string(),
        ),
        (
            garbage,
            ".git/HEAD holds neither a commit id nor a branch under refs/heads".to_string(),
        ),
        (
            missing_ref,
            "the branch refs/heads/gone is in neither .git/refs nor .git/packed-refs".to_string(),
        ),
        (linked, format!(".git/HEAD not a regular file as {owner}")),
        (
            linked_git.clone(),
            format!("{linked_git}/.git is a symbolic link"),
        ),
        (
            dangling,
            format!(".git/refs/heads/main not a regular file as {owner}"),
        ),
        (
            garbage_ref,
            ".git/refs/heads/main holds no commit id".to_string(),
        ),
        (
            fifo_packed,
            format!(".git/packed-refs not a regular file as {owner}"),
        ),
        (
            big_packed,
            format!(".git/packed-refs larger than expected as {owner}"),
        ),
        (
            nowhere.clone(),
            format!("checkout not visible from this sandbox: {nowhere}"),
        ),
    ] {
        let v = fx
            .run_with(&["--json"], &[("PROPOLIS_CC_REPO_DIR", &dir)])
            .json();
        let limited = v["limited"].to_string();
        assert!(
            limited.contains(&format!(
                "checkout HEAD not readable ({why}): stamp-behind not checked"
            )),
            "{dir}: {limited}"
        );
        assert!(
            !finding_messages(&v)
                .join("\n")
                .contains("the checkout is at"),
            "{dir}: {}",
            v["findings"]
        );
        // What could not be compared is unknown, never ok.
        assert_eq!(
            global_state(&v, "deploy-stamp"),
            "unknown",
            "{dir}: {}",
            v["global"]
        );
        assert!(
            global_text(&v, "deploy-stamp").ends_with(", checkout HEAD not read"),
            "{dir}: {}",
            global_text(&v, "deploy-stamp")
        );
    }
    let r = fx.run_with(&["--tsv"], &[("PROPOLIS_CC_REPO_DIR", &worktree)]);
    let s = &tsv_records(&r.out)[0];
    assert!(s[5].parse::<u32>().unwrap() >= 1, "{s:?}");
    assert_eq!(r.code, 1, "{}", r.out);
}

#[test]
fn a_cursor_fifo_or_link_in_the_spool_check_is_unknown_and_does_not_hang() {
    use std::os::unix::fs::MetadataExt;
    let cursor_of = |path: &str| -> PathBuf {
        let resolved = std::fs::canonicalize(path).unwrap();
        PathBuf::from(format!("{}.json", sha256_hex(resolved.to_str().unwrap())))
    };
    let unlisted_message = |fx: &Fx| -> String {
        let v = fx.json();
        let found = spool_findings(&v);
        assert_eq!(found.len(), 1, "{found:?}");
        found[0]["message"].as_str().unwrap().to_string()
    };

    // A FIFO where the cursor should be: opened, it would block the root run.
    let fx = Fx::new();
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    std::fs::create_dir_all(fx.p("state/cursors")).unwrap();
    let cur = fx.p("state/cursors").join(cursor_of(&spool));
    let st = Command::new("mkfifo").arg(&cur).status().unwrap();
    assert!(st.success());
    let msg = unlisted_message(&fx);
    assert!(
        msg.contains(&format!(
            "its cursor {} is not a regular file",
            cur.display()
        )),
        "{msg}"
    );

    // A link where the cursor should be, to a file that would read as a cursor.
    let fx = Fx::new();
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    let ino = std::fs::metadata(&spool).unwrap().ino();
    fx.write(
        "elsewhere/cursor.json",
        &format!("{{\"inode\":{ino},\"offset\":300}}"),
    );
    std::fs::create_dir_all(fx.p("state/cursors")).unwrap();
    let cur = fx.p("state/cursors").join(cursor_of(&spool));
    std::os::unix::fs::symlink(fx.p("elsewhere/cursor.json"), &cur).unwrap();
    let msg = unlisted_message(&fx);
    assert!(
        msg.contains(&format!(
            "its cursor {} is not a regular file",
            cur.display()
        )),
        "{msg}"
    );

    // A cursor larger than any cursor the daemon writes.
    let fx = Fx::new();
    let spool = fx.spool("collector-07", 300, NOW - 7200);
    let rel = format!("state/cursors/{}", cursor_of(&spool).display());
    fx.write(
        &rel,
        &format!("{{\"inode\":1,\"offset\":1}}{}", " ".repeat(5000)),
    );
    let msg = unlisted_message(&fx);
    assert!(msg.contains("is larger than a cursor"), "{msg}");

    // The spool file itself a symbolic link: its metadata is not followed.
    let fx = Fx::new();
    fx.log("elsewhere/events.jsonl", 300, NOW - 7200);
    std::fs::create_dir_all(fx.p("spool/gateway/collector-08")).unwrap();
    std::os::unix::fs::symlink(
        fx.p("elsewhere/events.jsonl"),
        fx.p("spool/gateway/collector-08/events.jsonl"),
    )
    .unwrap();
    let msg = unlisted_message(&fx);
    assert!(
        msg.contains(&format!(
            "{} is a symbolic link",
            fx.p("spool/gateway/collector-08/events.jsonl").display()
        )),
        "{msg}"
    );

    // The same link on a host whose stat names file types in the operator's language: systemd
    // passes LANG to a service, and coreutils translates %F unless LC_ALL=C reaches it.
    let real = |t: &str| -> String {
        ["/usr/bin", "/bin"]
            .iter()
            .map(|d| format!("{d}/{t}"))
            .find(|p| Path::new(p).exists())
            .unwrap_or_else(|| panic!("no {t} on this host"))
    };
    fx.exec(
        "stubs/stat",
        &format!(
            "case \"$*\" in\n  *%F*)\n    if [ \"${{LC_ALL:-}}\" != C ]; then\n        {stat} \"$@\" | {sed} 's/^symbolic link/symbolische Verkn\u{fc}pfung/'\n        exit 0\n    fi\n    ;;\nesac\nexec {stat} \"$@\"\n",
            stat = real("stat"),
            sed = real("sed")
        ),
    );
    let v = fx.run_with(&["--json"], &[("LANG", "de_DE.UTF-8")]).json();
    let found = spool_findings(&v);
    assert_eq!(found.len(), 1, "{found:?}");
    let msg = found[0]["message"].as_str().unwrap();
    assert!(
        msg.contains(&format!(
            "{} is a symbolic link",
            fx.p("spool/gateway/collector-08/events.jsonl").display()
        )),
        "{msg}"
    );
}

/// The fields each TSV record type carries, the type included.
fn tsv_fields(kind: &str) -> usize {
    match kind {
        "S" => 9,
        "R" => 10,
        "G" => 4,
        "F" => 7,
        "X" | "L" | "E" => 2,
        other => panic!("unknown TSV record type {other:?}"),
    }
}

/// Checks the TSV document's shape and returns its records, the header line left out.
fn tsv_records(out: &str) -> Vec<Vec<String>> {
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("#config-check tsv v1"), "{out}");
    let records: Vec<Vec<String>> = lines
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect();
    for r in &records {
        assert_eq!(r.len(), tsv_fields(&r[0]), "{r:?}");
        assert!(r.iter().all(|f| !f.is_empty()), "an empty field: {r:?}");
    }
    records
}

#[test]
fn tsv_has_one_record_per_line_and_an_end_count() {
    let fx = Fx::new();
    // A run fix, a manual fix and a limit in one report.
    fx.unit("sensor-ssh.service", "disabled", "inactive");
    let logs = fx.logs();
    let line = format!(
        "PROPOLIS_SENSOR_LOGS=ssh:{logs}/ssh/events.jsonl,dns:{logs}/dns/events.jsonl,tftp:{logs}/tftp/events.jsonl,cred-pg:{logs}/cred/postgresql.jsonl"
    );
    fx.set_env_line("etc/propolis.env", "PROPOLIS_SENSOR_LOGS=", Some(&line));
    fx.remove_stub("df");
    fx.write(
        "state/backup-status/last-success",
        &format!(
            "{{\"completed_at\":\"{}\",\"reason\":\"scheduled\",\"set\":\"x\",\"encrypted\":true,\"dump_bytes\":1,\"archive_bytes\":1,\"source_bytes\":1}}\n",
            iso(NOW - 3600)
        ),
    );
    let r = fx.run(&["--tsv"]);
    let v = fx.json();
    assert_eq!(r.code, v["exit_code"].as_i64().unwrap() as i32);
    let recs = tsv_records(&r.out);
    assert_eq!(recs[0][0], "S");
    assert_eq!(recs.last().unwrap()[0], "E");
    let s = &recs[0];
    assert_eq!(s[1], v["status"].as_str().unwrap());
    assert_eq!(s[2], v["exit_code"].to_string());
    assert_eq!(s[3], v["counts"]["fail"].to_string());
    assert_eq!(s[4], v["counts"]["warn"].to_string());
    assert_eq!(s[5], v["counts"]["unknown"].to_string());
    assert_eq!(s[6], "1");
    assert_eq!(s[7], NOW.to_string());
    assert_eq!(s[8], "0");
    // In order: S, the G rows, the R rows, each F with its X, the L lines, E.
    let order: String = recs.iter().map(|r| r[0].as_str()).collect();
    let shape = regex_like_order(&order);
    assert!(shape, "records out of order: {order}");
    let f: Vec<&Vec<String>> = recs.iter().filter(|r| r[0] == "F").collect();
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(f.len(), findings.len());
    assert_eq!(recs.last().unwrap()[1], f.len().to_string());
    for (rec, j) in f.iter().zip(findings) {
        assert_eq!(rec[1], j["level"].as_str().unwrap());
        assert_eq!(rec[2], j["id"].as_str().unwrap());
        assert_eq!(rec[4], j["scope"].as_str().unwrap());
        let kind = j["fix_kind"].as_str().unwrap();
        assert_eq!(rec[5], if kind.is_empty() { "-" } else { kind });
        assert_eq!(rec[6], j["message"].as_str().unwrap());
    }
    // The k12 is of the whole key, instance included.
    let disabled = f.iter().find(|r| r[2] == "unit-disabled").unwrap();
    assert_eq!(
        disabled[3],
        sha256_hex("unit-disabled:sensor-ssh")[..12].to_string()
    );
    let fixes: Vec<&Vec<String>> = recs.iter().filter(|r| r[0] == "X").collect();
    assert!(
        fixes
            .iter()
            .any(|x| x[1] == "sudo systemctl enable --now sensor-ssh.service"),
        "{fixes:?}"
    );
    let rows: Vec<&Vec<String>> = recs.iter().filter(|r| r[0] == "R").collect();
    assert_eq!(rows.len(), v["listeners"].as_array().unwrap().len());
    let ssh = rows.iter().find(|r| r[1] == "ssh/tcp").unwrap();
    assert_eq!(ssh[2], "sensor-ssh");
    assert_eq!(ssh[3], "fail");
    for state in &ssh[4..] {
        assert!(
            ["ok", "warn", "fail", "unknown", "skip"].contains(&state.as_str()),
            "{ssh:?}"
        );
    }
    let limits: Vec<&Vec<String>> = recs.iter().filter(|r| r[0] == "L").collect();
    assert_eq!(limits.len(), v["limited"].as_array().unwrap().len());
    assert!(!limits.is_empty(), "the fixture has no limit to show");
    // --report-only keeps exit 0 and the S line keeps the real code.
    let r = fx.run(&["--tsv", "--report-only"]);
    assert_eq!(r.code, 0);
    assert_eq!(tsv_records(&r.out)[0][2], v["exit_code"].to_string());
}

/// A danger finding is put first, and its k12 travels with it: every F line's k12 is the hash of
/// that finding's own full key.
#[test]
fn tsv_keeps_each_k12_with_its_finding_when_a_danger_finding_is_put_first() {
    let fx = Fx::new();
    fx.unit("sensor-ssh.service", "disabled", "inactive");
    // A host PostgreSQL holds 5432, which ufw allows: danger:tcp:5432.
    foreign_holder_on_5432(&fx);
    let r = fx.run(&["--tsv"]);
    let recs = tsv_records(&r.out);
    let f: Vec<&Vec<String>> = recs.iter().filter(|r| r[0] == "F").collect();
    assert_eq!(f[0][2], "danger", "{f:?}");
    let k12 = |key: &str| sha256_hex(key)[..12].to_string();
    for (id, key) in [
        ("danger", "danger:tcp:5432"),
        ("listen-foreign", "listen-foreign:tcp:5432"),
        ("unit-disabled", "unit-disabled:sensor-ssh"),
    ] {
        let rec = f
            .iter()
            .find(|r| r[2] == id)
            .unwrap_or_else(|| panic!("no {id} in {f:?}"));
        assert_eq!(rec[3], k12(key), "{id}: {rec:?}");
    }
    let mut seen: Vec<&str> = f.iter().map(|r| r[3].as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), f.len(), "two findings share a k12: {f:?}");
}

/// S, then G*, R*, (F X?)*, L*, E: the order the TSV promises, written without a regex crate.
fn regex_like_order(order: &str) -> bool {
    let mut rest = order.strip_prefix('S').unwrap_or("!");
    rest = rest.trim_start_matches('G');
    rest = rest.trim_start_matches('R');
    while let Some(r) = rest.strip_prefix('F') {
        rest = r.strip_prefix('X').unwrap_or(r);
    }
    rest = rest.trim_start_matches('L');
    rest == "E"
}

#[test]
fn tsv_is_safe_for_hostile_values() {
    let fx = Fx::new();
    let logs = fx.logs();
    let hostile = "bad\"label\\x\u{1b}[31m\u{e9}\ttab";
    let text = fx.read("etc/propolis.env").replace(
        "PROPOLIS_SENSOR_LOGS=",
        &format!("PROPOLIS_SENSOR_LOGS={hostile}:{logs}/zzz/events.jsonl,"),
    );
    fx.write("etc/propolis.env", &text);
    let r = fx.run(&["--tsv"]);
    assert!(r.out.is_ascii(), "{}", r.out);
    assert!(!r.out.contains('\u{1b}'));
    let recs = tsv_records(&r.out);
    assert!(
        recs.iter()
            .any(|r| r[0] == "F" && r[6].contains("bad\"label\\x?[31m??")),
        "{recs:?}"
    );
}

#[test]
fn tsv_and_json_together_is_bad_usage() {
    let fx = Fx::new();
    for args in [["--tsv", "--json"], ["--json", "--tsv"]] {
        let r = fx.run(&args);
        assert_eq!(r.code, 64, "{args:?}: {}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
}

#[test]
fn config_check_makes_no_network_call() {
    let text = std::fs::read_to_string(SCRIPT).unwrap();
    for word in ["curl", "wget", " nc ", "pa_send", "pa_readcheck_run"] {
        assert!(
            !text.contains(word),
            "deploy/config-check.sh contains {word:?}"
        );
    }
    let fx = Fx::new();
    assert!(!fx.p("tools/curl").exists() && !fx.p("stubs/curl").exists());
    assert_eq!(fx.run(&[]).code, 0);
}

#[test]
fn env_syntax_reports_only_the_disagreeing_forms_and_never_the_value() {
    let fx = Fx::new();
    fx.write(
        "etc/syntax.env",
        concat!(
            "# PROPOLIS_COMMENTED = secretvalue0\n",
            "  PROPOLIS_A=secretvalue1\n",
            "PROPOLIS_B = secretvalue2\n",
            "PROPOLIS_C=secretvalue3  \n",
            "PROPOLIS_D=secret\\value4\n",
            "PROPOLIS_F=\"a b secretvalue6\"\n",
            "PROPOLIS_G=secretvalue7\r\n",
            "OTHER_KEY = secretvalue8\n",
            "PROPOLIS_H = secretvalue9\n",
            "PROPOLIS_H=secretvalue10\n",
            "DATABASE_URL =secretvalue11\n",
            // A value ending in a backslash runs into the next line, and so does a comment that
            // ends in one (systemd before v254): Y and Z are not read on their own.
            "PROPOLIS_X=secretvalue12\\\n",
            "PROPOLIS_Y=secretvalue13\n",
            "# a comment that ends in a backslash \\\n",
            "PROPOLIS_Z=secretvalue14\n",
            // A CR in the middle of a line ends a line for systemd, so Q is a setting of its own.
            "PROPOLIS_P=secretvalue15\rPROPOLIS_Q=secretvalue16\n",
            // Last: systemd runs an open quote on into the lines after it.
            "PROPOLIS_E=\"secretvalue5\n",
        ),
    );
    let file = fx.p("etc/syntax.env").display().to_string();
    let v = fx.json();
    // The env-files row carries what its findings say.
    assert_eq!(global_state(&v, "env-files"), "warn", "{}", v["global"]);
    assert!(
        global_text(&v, "env-files")
            .ends_with("; 12 settings in a form systemd and the shell scripts read differently"),
        "{}",
        global_text(&v, "env-files")
    );
    let found: BTreeMap<String, String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == "env-systemd-only")
        .map(|f| {
            let msg = f["message"].as_str().unwrap().to_string();
            assert_eq!(f["level"], "warn", "{f}");
            assert_eq!(f["fix_kind"], "manual", "{f}");
            let key = msg
                .split(" sets ")
                .nth(1)
                .and_then(|r| r.split(' ').next())
                .unwrap_or_else(|| panic!("{msg}"))
                .to_string();
            (key, msg)
        })
        .collect();
    let keys: Vec<&str> = found.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "DATABASE_URL",
            "PROPOLIS_A",
            "PROPOLIS_B",
            "PROPOLIS_C",
            "PROPOLIS_D",
            "PROPOLIS_E",
            "PROPOLIS_G",
            "PROPOLIS_P",
            "PROPOLIS_Q",
            "PROPOLIS_X",
            "PROPOLIS_Y",
            "PROPOLIS_Z"
        ],
        "{found:#?}"
    );
    let joined = "a line systemd reads as part of the line before it";
    for (key, line, form) in [
        ("PROPOLIS_A", 2, "blanks before the name"),
        ("PROPOLIS_B", 3, "blanks around '='"),
        ("PROPOLIS_C", 4, "trailing blanks or a CR"),
        ("PROPOLIS_D", 5, "a backslash or an unmatched quote"),
        ("PROPOLIS_G", 7, "trailing blanks or a CR"),
        ("DATABASE_URL", 11, "blanks around '='"),
        ("PROPOLIS_X", 12, "a backslash or an unmatched quote"),
        ("PROPOLIS_Y", 13, joined),
        ("PROPOLIS_Z", 15, joined),
        ("PROPOLIS_P", 16, "trailing blanks or a CR"),
        ("PROPOLIS_Q", 16, "trailing blanks or a CR"),
        ("PROPOLIS_E", 17, "a backslash or an unmatched quote"),
    ] {
        let msg = &found[key];
        assert!(
            msg.starts_with(&format!("line {line} of {file} sets {key} in a form systemd reads one way and the shell scripts read another way or not at all (")),
            "{msg}"
        );
        assert!(msg.contains(form), "{key}: {msg}");
        assert!(msg.ends_with("; the value is not shown"), "{msg}");
    }
    // The fix names the key, except DATABASE_URL, which a fix line never names.
    let fix_of = |key: &str| -> String {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| {
                f["id"] == "env-systemd-only"
                    && f["message"]
                        .as_str()
                        .unwrap()
                        .contains(&format!(" sets {key} "))
            })
            .map(|f| f["fix"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(
        fix_of("PROPOLIS_A"),
        format!(
            "rewrite line 2 of {file} as PROPOLIS_A=value, with nothing before PROPOLIS_A, no blanks around '=', no trailing blanks, no backslash and no unmatched quote"
        )
    );
    assert_eq!(
        fix_of("DATABASE_URL"),
        format!(
            "rewrite line 11 of {file} as NAME=value, with nothing before the name, no blanks around '=', no trailing blanks, no backslash and no unmatched quote"
        )
    );
    assert_fix_contract(
        &fx,
        "env-systemd-only for DATABASE_URL",
        "env-systemd-only",
        "manual",
        &fix_of("DATABASE_URL"),
    );
    for args in [vec![], vec!["--json"], vec!["--tsv"]] {
        let r = fx.run(&args);
        assert!(!r.out.contains("secretvalue"), "{args:?}: {}", r.out);
    }

    // Without the file, the row is what check_env_files makes it.
    std::fs::remove_file(fx.p("etc/syntax.env")).unwrap();
    assert_eq!(global_state(&fx.json(), "env-files"), "ok");
}

#[test]
fn parse_intake_and_pa_sensor_logs_agree() {
    let fx = Fx::new();
    let logs = fx.logs();
    for value in [
        " a:L/x/1 , ,b:L/x/2,,",
        "a;L/x/1,b:L/x/2",
        ":L/x/3,c:",
        "e:L/x/5:with:colons",
        "\u{a0}d:L/x/4\u{2003}, f:L/x/6",
    ] {
        let value = value.replace('L', &logs);
        let lib = Command::new(BASH)
            .args([
                "-c",
                ". \"$1\"; pa_sensor_logs \"$2\"; for i in \"${!PA_LOG_LABEL[@]}\"; do printf 'good\\t%s:%s\\n' \"${PA_LOG_LABEL[$i]}\" \"${PA_LOG_PATH[$i]}\"; done; for i in \"${!PA_LOG_BAD[@]}\"; do printf 'bad\\t%s\\t%s\\n' \"${PA_LOG_BAD[$i]}\" \"${PA_LOG_BAD_WHY[$i]}\"; done",
                "_",
                ALERT_LIB,
                &value,
            ])
            .output()
            .unwrap();
        assert!(lib.status.success());
        let lib_out = String::from_utf8(lib.stdout).unwrap();
        fx.set_env_line(
            "etc/propolis.env",
            "PROPOLIS_SENSOR_LOGS=",
            Some(&format!("PROPOLIS_SENSOR_LOGS={value}")),
        );
        let v = fx.json();
        let msgs = finding_messages(&v).join("\n");
        let mut entries = 0;
        for line in lib_out.lines() {
            entries += 1;
            let parts: Vec<&str> = line.split('\t').collect();
            let want = match parts[0] {
                "good" => format!("entry '{}'", parts[1]),
                _ => format!("entry '{}' is malformed ({};", parts[1], parts[2]),
            };
            assert!(msgs.contains(&want), "{value:?}: {want} not in\n{msgs}");
        }
        assert!(
            global_text(&v, "intake-list")
                .starts_with(&format!("PROPOLIS_SENSOR_LOGS: {entries} entries")),
            "{value:?}: {}",
            global_text(&v, "intake-list")
        );
    }
}

#[test]
fn a_missing_alert_library_exits_70_and_upgrade_still_finishes() {
    let fx = Fx::new();
    let lone = fx.p("lone");
    std::fs::create_dir_all(&lone).unwrap();
    let script = lone.join("config-check.sh");
    std::fs::copy(SCRIPT, &script).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy(LISTENERS_LIB, lone.join("listeners-lib.sh")).unwrap();
    std::fs::write(
        lone.join("install-bins"),
        format!("INSTALL_BINS=({})\n", install_bins().join(" ")),
    )
    .unwrap();
    let error = "error: alert library not found (or too old) beside config-check.sh or at /usr/local/sbin/propolis-alert-lib";
    let old_lib = std::fs::read_to_string(ALERT_LIB)
        .unwrap()
        .replace("\nPA_LIB_VERSION=", "\nPA_LIB_VERSION=0\nPA_OLD_VERSION=");
    fx.write("libs/old-lib.sh", &old_lib);
    let old = fx.p("libs/old-lib.sh").display().to_string();
    let missing = fx.p("libs/none.sh").display().to_string();

    // The seam names a file that is not there.
    let r = fx.run_script(&script, &[], &[("PROPOLIS_CC_ALERT_LIB", &missing)]);
    assert_eq!(r.code, 70, "{}{}", r.out, r.err);
    assert!(r.err.contains(error), "{}", r.err);
    assert!(r.out.is_empty(), "{}", r.out);
    // --report-only does not hide it: the library is not a finding.
    let r = fx.run_script(
        &script,
        &["--report-only"],
        &[("PROPOLIS_CC_ALERT_LIB", &missing)],
    );
    assert_eq!(r.code, 70);
    // The seam comes first, and a library older than the script needs is refused.
    std::fs::copy(ALERT_LIB, lone.join("alert-lib.sh")).unwrap();
    let r = fx.run_script(&script, &[], &[("PROPOLIS_CC_ALERT_LIB", &old)]);
    assert_eq!(r.code, 70, "{}", r.err);
    assert!(r.err.contains(error), "{}", r.err);
    // Without the seam, the copy beside the script is found.
    let r = fx.run_script(&script, &[], &[("PROPOLIS_CC_ALERT_LIB", "")]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    // ...before the installed path, so an old one beside it stops the run.
    std::fs::copy(&old, lone.join("alert-lib.sh")).unwrap();
    let r = fx.run_script(&script, &[], &[("PROPOLIS_CC_ALERT_LIB", "")]);
    assert_eq!(r.code, 70, "{}", r.err);
    std::fs::remove_file(lone.join("alert-lib.sh")).unwrap();

    // A library that cannot be used is exit 70 and the error line however it fails: an unbound
    // variable at its top level (which under set -u would end the shell itself), an exit at its
    // top level, or the current version without one of the functions the check calls.
    let shipped = std::fs::read_to_string(ALERT_LIB).unwrap();
    for (name, body) in [
        ("unbound", format!("{shipped}\n: \"$CC_UNDEFINED_THING\"\n")),
        ("exits", format!("{shipped}\nexit 0\n")),
        ("no-read-as", format!("{shipped}\nunset -f pa_read_as\n")),
    ] {
        fx.write(&format!("libs/{name}.sh"), &body);
        let lib = fx.p(&format!("libs/{name}.sh")).display().to_string();
        for args in [vec![], vec!["--report-only"]] {
            let r = fx.run_script(&script, &args, &[("PROPOLIS_CC_ALERT_LIB", &lib)]);
            assert_eq!(r.code, 70, "{name} {args:?}: {}{}", r.out, r.err);
            assert!(r.err.contains(error), "{name} {args:?}: {}", r.err);
            assert!(r.out.is_empty(), "{name} {args:?}: {}", r.out);
        }
    }

    // A library this account cannot read (mode 0000; as root, the run drops to nobody).
    fx.write("libs/unreadable.sh", &shipped);
    let unreadable = fx.p("libs/unreadable.sh");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    let wrapper: Vec<&str> = if is_root() {
        std::fs::set_permissions(fx.p(""), std::fs::Permissions::from_mode(0o755)).unwrap();
        vec![
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]
    } else {
        vec![]
    };
    let r = fx.run_script_under(
        &script,
        &wrapper,
        &[],
        &[
            ("PROPOLIS_CC_ALERT_LIB", &unreadable.display().to_string()),
            ("PROPOLIS_CC_EUID", "1000"),
        ],
    );
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(r.code, 70, "unreadable: {}{}", r.out, r.err);
    assert!(r.err.contains(error), "unreadable: {}", r.err);

    // What the environment hands down is not taken for the library: exported functions and a
    // version, with a library that defines the functions but no version, and one that has the
    // version but defines no function.
    let exported: Vec<(String, String)> = [
        "pa_init",
        "pa_env_get",
        "pa_read_as",
        "pa_sensor_logs",
        "pa_cleanup",
    ]
    .iter()
    .map(|f| (format!("BASH_FUNC_{f}%%"), "() {  :\n}".to_string()))
    .collect();
    let no_version = shipped.replace("\nPA_LIB_VERSION=", "\nPA_NOT_THE_VERSION=");
    for (name, body) in [
        ("no-version", no_version),
        ("no-functions", "PA_LIB_VERSION=1\n".to_string()),
    ] {
        fx.write(&format!("libs/{name}.sh"), &body);
        let lib = fx.p(&format!("libs/{name}.sh")).display().to_string();
        let mut env: Vec<(&str, &str)> = exported
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        env.push(("PA_LIB_VERSION", "9"));
        env.push(("PROPOLIS_CC_ALERT_LIB", &lib));
        let r = fx.run_script(&script, &[], &env);
        assert_eq!(r.code, 70, "{name}: {}{}", r.out, r.err);
        assert!(r.err.contains(error), "{name}: {}", r.err);
    }

    // No seam and no library beside the script: the installed path is the last place looked.
    let text = std::fs::read_to_string(SCRIPT).unwrap();
    let seam = text
        .find("CC_ALERT_LIB=\"$PROPOLIS_CC_ALERT_LIB\"")
        .unwrap();
    let beside = text
        .find("CC_ALERT_LIB=\"$SCRIPT_DIR/alert-lib.sh\"")
        .unwrap();
    let installed = text
        .find("CC_ALERT_LIB=/usr/local/sbin/propolis-alert-lib")
        .unwrap();
    assert!(
        seam < beside && beside < installed,
        "the lookup order is seam, beside the script, installed"
    );
    if Path::new("/usr/local/sbin/propolis-alert-lib").exists() {
        eprintln!(
            "note: this host has /usr/local/sbin/propolis-alert-lib, so the fallback run was not made; the lookup order was checked from the script text"
        );
    } else {
        let r = fx.run_script(&script, &[], &[("PROPOLIS_CC_ALERT_LIB", "")]);
        assert_eq!(r.code, 70, "fallback: {}{}", r.out, r.err);
        assert!(r.err.contains(error), "fallback: {}", r.err);
    }

    // upgrade.sh's last line runs the check as it is written there, and still finishes.
    let upgrade = std::fs::read_to_string(UPGRADE).unwrap();
    let last = upgrade
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap()
        .to_string();
    let out = Command::new(BASH)
        .arg("-c")
        .arg(&last)
        .env_clear()
        .env(
            "PATH",
            format!("{}:{}", fx.p("stubs").display(), fx.p("tools").display()),
        )
        .env("SCRIPT_DIR", &lone)
        .env("PROPOLIS_CC_ALERT_LIB", &missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{last}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("warning: config-check.sh itself failed to run"),
        "{stdout}"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains(error));
}

/// The `alert-channel` G row (state and text) and the F lines of a --tsv run.
fn alert_channel(r: &Run) -> (String, String, Vec<String>) {
    let mut state = String::new();
    let mut text = String::new();
    let mut ids = Vec::new();
    for line in r.out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] == "G" && f.get(1) == Some(&"alert-channel") {
            state = f[2].to_string();
            text = f[3].to_string();
        }
        if f[0] == "F" {
            ids.push(f[2].to_string());
        }
    }
    (state, text, ids)
}

/// The alert channel is judged from the stored anonymous-read check alone, with no request: a
/// fresh refusal is ok and the run stays green; a topic the check found readable is
/// alert-topic-readable (a warning, so exit 1) with the class and the check's age and never the
/// topic; a check never made for this target reads skip with when it will be made, leaving the
/// exit status as it was; a check that could not be made (stale, without a definite answer, or a
/// file that cannot be read) leaves the row unknown with its limit line (exit 1), never ok; and a
/// run that is not root cannot read it at all.
#[test]
fn the_alert_channel_reads_the_stored_check_and_is_unknown_without_one() {
    let fx = Fx::new();
    let r = fx.run(&["--tsv"]);
    assert_eq!(r.code, 0, "{}", r.out);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        ("ok", "the topic refuses anonymous reads (the stored check)")
    );

    fx.readcheck("readable");
    let r = fx.run(&["--tsv"]);
    assert_eq!(r.code, 1, "{}", r.out);
    let (state, _, ids) = alert_channel(&r);
    assert_eq!(state, "warn");
    assert_eq!(ids, ["alert-topic-readable"], "{}", r.out);
    let human = fx.run(&[]);
    assert!(
        human.out.contains("the alert topic answered an anonymous read (readable, checked 10 min ago): anyone who knows its name reads the alerts, the daemon's titles name this host's software, and today's failure hook sends this host's name and the failed unit (legacy)"),
        "{}",
        human.out
    );
    assert!(human.out.contains("restrict read access to the topic, or move to a topic only you can read, then run: sudo propolis-status --setup"));
    assert!(
        !human.out.contains("propolis-ops"),
        "the topic is never printed"
    );

    let unknown = |fx: &Fx, why: &str| {
        let r = fx.run(&["--tsv"]);
        assert_eq!(r.code, 1, "{why}: {}", r.out);
        let (state, _, ids) = alert_channel(&r);
        assert_eq!(state, "unknown", "{why}: {}", r.out);
        assert!(ids.is_empty(), "{why}: {ids:?}");
        assert!(
            r.out
                .lines()
                .any(|l| l.starts_with("L\tanonymous read not checked yet")),
            "{why}: {}",
            r.out
        );
    };
    // Never checked (right after an install or an upgrade, before the witness's first hourly
    // pass, or after the target changed) is a check not yet made: skip, with the exit status as
    // it was before the row existed and no limit line.
    let never = |fx: &Fx, why: &str| {
        let r = fx.run(&["--tsv"]);
        assert_eq!(r.code, 0, "{why}: {}", r.out);
        let (state, text, ids) = alert_channel(&r);
        assert_eq!(
            (state.as_str(), text.as_str()),
            (
                "skip",
                "anonymous read never checked for this target: the witness's hourly pass checks it within the hour; sudo propolis-status --setup checks it now"
            ),
            "{why}: {}",
            r.out
        );
        assert!(ids.is_empty(), "{why}: {ids:?}");
        assert!(
            !r.out.lines().any(|l| l.starts_with("L\tanonymous read")),
            "{why}: {}",
            r.out
        );
    };
    std::fs::remove_file(fx.p("alert-root/var/lib/propolis/witness/readcheck")).unwrap();
    never(&fx, "no stored check");
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{a}/0000aaaa/1\ttransient\t{d}/0000aaaa/1\trefused\t-\t403\t403\tboth\t403\n",
            a = NOW - 600,
            d = NOW - 90_000
        ),
    );
    unknown(&fx, "a refusal decided over a day ago");
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t0000000000000000\t{s}/0000aaaa/1\trefused\t{s}/0000aaaa/1\trefused\t-\t403\t403\tboth\t403\n",
            s = NOW - 600
        ),
    );
    never(&fx, "a check of another target only");
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}/0000aaaa/1\ttransient\t-\t-\t-\t000\t000\tboth\t000\n",
            s = NOW - 600
        ),
    );
    unknown(&fx, "a check that got no definite answer");
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        "not a state file\n",
    );
    unknown(&fx, "a file that cannot be read");

    let r = fx.run_with(&["--tsv"], &[("PROPOLIS_CC_EUID", "1000")]);
    let (state, _, _) = alert_channel(&r);
    assert_eq!(state, "unknown");
    assert!(
        r.out.lines().any(|l| l == "L\talert channel not checked: /var/lib/propolis/witness is not readable as this user; run as root"),
        "{}",
        r.out
    );
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    for word in ["curl", "pa_readcheck_run", "pa_send"] {
        assert!(!script.contains(word), "config-check names {word}");
    }
}

/// The alert channel warns, never passes, where the gate holds detail back for a reason the
/// operator can fix: a single box with no push target, a refusal over plain http (anyone on the
/// path could have given it), and a collector whose token can read its topic.
#[test]
fn the_alert_channel_warns_without_a_target_over_http_and_with_a_reading_token_on_a_collector() {
    let fx = Fx::new();
    let env = fx.read("etc/propolis.env");
    let without: String = env
        .lines()
        .filter(|l| !l.starts_with("PROPOLIS_OPS_NTFY_"))
        .map(|l| format!("{l}\n"))
        .collect();
    fx.write("etc/propolis.env", &without);
    let r = fx.run(&["--tsv"]);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        ("warn", "no push target"),
        "{}",
        r.out
    );

    fx.write(
        "etc/propolis.env",
        &env.replace(
            "PROPOLIS_OPS_NTFY_URL=https://",
            "PROPOLIS_OPS_NTFY_URL=http://",
        ),
    );
    let s = format!("{}/0000aaaa/1", NOW - 600);
    let binding = &sha256_hex("http://ntfy.example.invalid\npropolis-ops\n")[..16];
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{binding}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n"
        ),
    );
    let r = fx.run(&["--tsv"]);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        ("warn", "the topic is not proven private (insecure)"),
        "{}",
        r.out
    );

    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
    );
    fx.write(
        "alert-root/var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\treads\t403\t403\tboth\t403\n"
        ),
    );
    let r = fx.run_script(&script, &["--tsv"], &[]);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        ("warn", "the topic is not proven private (token-reads)"),
        "{}",
        r.out
    );
}

/// On a collector the failure hook still posts to this host's target, so a readable topic is
/// still named, without the daemon's part; a collector without a target is ok as it is.
#[test]
fn a_collector_names_a_readable_hook_topic_without_the_daemon() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    let r = fx.run_script(&script, &["--tsv"], &[]);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        (
            "ok",
            "no push target (a collector's default: its failure hook writes to the journal)"
        ),
        "{}",
        r.out
    );
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
    );
    fx.readcheck("readable");
    let r = fx.run_script(&script, &[], &[]);
    assert!(
        r.out.contains("the alert topic answered an anonymous read (readable, checked 10 min ago): anyone who knows its name reads the alerts, and today's failure hook sends this host's name and the failed unit (legacy)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("the daemon's titles"), "{}", r.out);
}

/// On a collector no daemon runs, so a push setting the shell senders ignore as invalid is
/// said to be used as written by today's failure hook alone. And a collector whose shell senders
/// find no target while the hook's own reader finds a URL and a topic is not the collector's
/// quiet default: the hook still posts, which the row says.
#[test]
fn a_collector_says_what_its_failure_hook_still_does_without_naming_a_daemon() {
    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
    );
    let r = fx.run_script(&script, &[], &[]);
    let etc = fx.p("etc").display().to_string();
    let want = format!(
        "PROPOLIS_OPS_NTFY_URL in {etc}/propolis.env is not valid (an http:// or https:// URL with a host and no blanks): the status command and the witness ignore it, while today's failure hook still uses it as written; see sudo propolis-status --setup"
    );
    assert!(r.out.contains(&want), "{want} not in:\n{}", r.out);
    assert!(!r.out.contains("and the daemon"), "{}", r.out);

    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n  PROPOLIS_OPS_NTFY_URL=\n",
    );
    let r = fx.run_script(&script, &["--tsv"], &[]);
    let (state, text, _) = alert_channel(&r);
    assert_eq!(
        (state.as_str(), text.as_str()),
        (
            "warn",
            "no push target for the shell senders; today's failure hook still posts (see sudo propolis-status --setup)"
        ),
        "{}",
        r.out
    );
}

/// alert-topic-readable names today's failure hook as sending to the topic only where the hook's
/// own reader finds this URL and topic. With the topic on an indented line the library reads it
/// (and systemd, for the daemon) and the hook does not: on a single box the finding keeps the
/// daemon's part alone, and on a collector it names neither sender.
#[test]
fn a_readable_topic_names_the_failure_hook_only_where_the_hook_posts_there() {
    let fx = Fx::new();
    let env = std::fs::read_to_string(fx.p("etc/propolis.env")).unwrap();
    fx.write(
        "etc/propolis.env",
        &env.replace("PROPOLIS_OPS_NTFY_TOPIC=", "  PROPOLIS_OPS_NTFY_TOPIC="),
    );
    fx.readcheck("readable");
    let r = fx.run(&[]);
    assert!(
        r.out.contains("the alert topic answered an anonymous read (readable, checked 10 min ago): anyone who knows its name reads the alerts, and the daemon's titles name this host's software"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("today's failure hook sends"), "{}", r.out);
    fx.readcheck("redirect");
    let r = fx.run(&[]);
    assert!(
        r.out.contains("the alert topic is not proven private: an anonymous read got a redirect (redirect, checked 10 min ago); the daemon's titles name this host's software there"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("today's failure hook sends"), "{}", r.out);

    let fx = Fx::new();
    let script = healthy_collector(&fx);
    fx.write(
        "etc/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\n  PROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
    );
    fx.readcheck("readable");
    let r = fx.run_script(&script, &[], &[]);
    assert!(
        r.out.contains("the alert topic answered an anonymous read (readable, checked 10 min ago): anyone who knows its name reads what this host pushes there"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("today's failure hook sends"), "{}", r.out);
    assert!(!r.out.contains("the daemon's titles"), "{}", r.out);
    fx.readcheck("not_found");
    let r = fx.run_script(&script, &[], &[]);
    assert!(
        r.out.contains("the alert topic is not proven private: an anonymous read got not found (404) (not_found, checked 10 min ago)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("today's failure hook sends"), "{}", r.out);
    assert!(!r.out.contains("the daemon's titles"), "{}", r.out);
}

/// alert-topic-readable says that anyone who knows the topic's name reads the alerts only for
/// the class readable. For every other definite answer but a refusal it says that the topic is
/// not proven private and what the answer was, without claiming anyone can read it.
#[test]
fn a_topic_that_is_not_proven_private_is_not_called_readable_by_anyone() {
    for (class, answer) in [
        ("redirect", "a redirect"),
        ("not_found", "not found (404)"),
        ("not_ntfy", "an answer that is not ntfy's"),
        ("unexpected", "an answer this check does not know"),
    ] {
        let fx = Fx::new();
        fx.readcheck(class);
        let r = fx.run(&[]);
        assert_eq!(r.code, 1, "{class}: {}", r.out);
        let want = format!(
            "the alert topic is not proven private: an anonymous read got {answer} ({class}, checked 10 min ago); the daemon's titles name this host's software there, and today's failure hook sends this host's name and the failed unit (legacy)"
        );
        assert!(r.out.contains(&want), "{want} not in:\n{}", r.out);
        assert!(
            !r.out.contains("anyone who knows its name"),
            "{class}: {}",
            r.out
        );
        let r = fx.run(&["--tsv"]);
        let (state, text, ids) = alert_channel(&r);
        assert_eq!(state, "warn", "{class}");
        assert_eq!(text, format!("topic not proven private ({class})"));
        assert_eq!(ids, ["alert-topic-readable"], "{class}");
    }
}

/// A shell sender's setting that the library ignores as invalid is named with its file and its
/// rule, never its value: a token with a blank in propolis.env, a heartbeat URL over plain http
/// in alert.env (which wins for that key).
#[test]
fn an_invalid_alert_setting_is_named_with_its_file_and_never_its_value() {
    let fx = Fx::new();
    let env = fx.read("etc/propolis.env");
    fx.write(
        "etc/propolis.env",
        &format!("{env}PROPOLIS_OPS_NTFY_TOKEN=tk with-a-blank\n"),
    );
    fx.write(
        "etc/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/s3cret-path\n",
    );
    let r = fx.run(&[]);
    assert_eq!(r.code, 1, "{}", r.out);
    let etc = fx.p("etc").display().to_string();
    for want in [
        format!(
            "PROPOLIS_OPS_NTFY_TOKEN in {etc}/propolis.env is not valid (1 to 256 printable characters with no blank): the status command and the witness ignore it, while today's failure hook and the daemon still use it as written; see sudo propolis-status --setup"
        ),
        format!(
            "PROPOLIS_WITNESS_HEARTBEAT_URL in {etc}/alert.env is not valid (an https:// URL with no blanks): the witness ignores it and pings no dead-man check; see sudo propolis-status --setup"
        ),
    ] {
        assert!(r.out.contains(&want), "{want} not in:\n{}", r.out);
    }
    assert!(
        !r.out.contains("the default is used"),
        "today's hook and the daemon do not use a default: {}",
        r.out
    );
    for secret in ["with-a-blank", "s3cret-path", "hc.example.invalid"] {
        assert!(!r.out.contains(secret), "{secret} printed");
    }
    let r = fx.run(&["--tsv"]);
    let (state, _, ids) = alert_channel(&r);
    assert_eq!(state, "warn");
    let mine: Vec<&String> = ids.iter().filter(|i| i.starts_with("alert-")).collect();
    assert_eq!(
        mine,
        ["alert-setting-invalid", "alert-setting-invalid"],
        "{ids:?}"
    );
}
