//! Sources `deploy/alert-lib.sh` (the shared library of the shell alerting code) in `bash -c`
//! fixtures under a scratch root, with stub `hostname`, `systemctl`, `logger`, `setpriv` and
//! `stat` on `PATH` where a case needs one, and checks each function against the rules stated in
//! `deploy/alert-lib.sh`'s comments: how env files are read, which settings count as valid, how ids are salted and widened,
//! what the checkers accept, how ages survive a clock step or a reboot, how a read as another
//! account refuses links, FIFOs and oversized files, how state files are written, trimmed, locked
//! and read back, and that the library never sets a trap.
//!
//! `flock`, `sha256sum`, `od`, `timeout` and `mkfifo` are the real tools. Time comes from the
//! library's `PA_TEST_WALL`, `PA_TEST_BOOT` and `PA_TEST_UP` seam, and a read as another account
//! reads as the caller when the test does not run as root or sets `PA_TEST_READ_AS_SELF=1`, so the
//! cases pass whether they run as root or not.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const LIB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-lib.sh");

/// A fixed salt, so ids and the fallback alias are known values.
const SALT: &str = "0123456789abcdef0123456789abcdef";
const OTHER_SALT: &str = "fedcba9876543210fedcba9876543210";

/// 192 KiB, the size a writer trims `incidents` to.
const INCIDENTS_MAX: usize = 196_608;

const LOGGER_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
"#;

const HOSTNAME_STUB: &str = r#"#!/usr/bin/env bash
if [ "${1:-}" = -s ]; then echo Edge07; else echo Edge07.lab.example; fi
"#;

/// Records its argv; `systemctl is-enabled --quiet UNIT` succeeds for the units listed in
/// `STUB_ENABLED`, and every other verb fails.
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
[ "$1" = is-enabled ] || exit 1
unit="${!#}"
case " ${STUB_ENABLED:-} " in *" $unit "*) exit 0 ;; esac
exit 1
"#;

/// Records its argv and runs the command after `--` as the caller.
const SETPRIV_STUB: &str = r#"#!/usr/bin/env bash
printf 'setpriv %s\n' "$*" >> "$STUB_LOG"
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
exec "$@"
"#;

/// Answers `stat -c %s -- FILE` with the real size and records whether the descriptor numbered
/// `LOCKFD` is open in the process that ran it.
const STAT_FD_STUB: &str = r#"#!/usr/bin/env bash
s=closed
[ ! -e "/proc/self/fd/$LOCKFD" ] || s=open
printf 'fd %s\n' "$s" >> "$STUB_LOG"
wc -c < "${!#}"
"#;

/// Answers `stat -c %s -- FILE` after replacing FILE with a FIFO: the swap a hostile account
/// could make between the check and the read.
const STAT_SWAP_STUB: &str = r#"#!/usr/bin/env bash
f="${!#}"
rm -f -- "$f"
mkfifo -- "$f"
echo 5
"#;

/// Records whether descriptor 7 is open in the process that ran it and where its stdin and
/// stderr point.
const STAT_INHERIT_STUB: &str = r#"#!/usr/bin/env bash
s=closed
[ ! -e /proc/self/fd/7 ] || s=open
printf 'fd7 %s\nfd0 %s\nfd2 %s\n' "$s" "$(readlink /proc/self/fd/0)" "$(readlink /proc/self/fd/2)" >> "$STUB_LOG"
echo 5
"#;

/// A `stat` that outlives the five-second limit.
const STAT_SLOW_STUB: &str = r#"#!/usr/bin/env bash
sleep 6
echo 5
"#;

/// `id -u -- USER` and `id -g -- USER` answer 4242 and 4343; anything else is the real `id`.
const ID_STUB: &str = r#"#!/usr/bin/env bash
if [ "$1" = -u ] && [ "$2" = -- ]; then echo 4242
elif [ "$1" = -g ] && [ "$2" = -- ]; then echo 4343
else PATH=/usr/bin:/bin exec id "$@"; fi
"#;

/// Like `SETPRIV_STUB`, but first removes every permission from `CLOSE_DIR`: what a reader that
/// lost the group which reached that directory meets after the caller's own check passed.
const SETPRIV_CLOSING_STUB: &str = r#"#!/usr/bin/env bash
[ -z "${CLOSE_DIR:-}" ] || chmod 000 -- "$CLOSE_DIR"
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
exec "$@"
"#;

/// Records its argv and what `FINAL` holds at that moment, then exits with `SYNC_RC`.
const SYNC_STUB: &str = r#"#!/usr/bin/env bash
printf 'sync %s final=%s\n' "$*" "$(tr '\n' ' ' < "$FINAL" 2> /dev/null)" >> "$STUB_LOG"
exit "${SYNC_RC:-0}"
"#;

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    /// The value printed on the line `NAME=value`.
    fn get(&self, name: &str) -> String {
        let prefix = format!("{name}=");
        self.out
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("no {name}= line in:\n{}\nstderr:\n{}", self.out, self.err))
            .to_string()
    }
}

struct Fx {
    dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Fx {
    fn new() -> Self {
        Self::with_dir(tempfile::tempdir().unwrap())
    }

    /// A fixture directly under `/tmp` (mode 1777), whatever `TMPDIR` says: for cases that need
    /// another account to reach the scratch directory, or that look at the directories above it.
    fn in_tmp() -> Self {
        Self::with_dir(tempfile::tempdir_in("/tmp").unwrap())
    }

    fn with_dir(dir: tempfile::TempDir) -> Self {
        let root = dir.path().join("root");
        for d in [
            "var/lib/propolis/witness",
            "run/propolis-witness",
            "etc/propolis",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let bin = dir.path().join("bin");
        for (name, body) in [
            ("logger", LOGGER_STUB),
            ("hostname", HOSTNAME_STUB),
            ("systemctl", SYSTEMCTL_STUB),
        ] {
            write_exec(&bin.join(name), body);
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        Fx {
            dir,
            root,
            bin,
            log,
        }
    }

    /// A fixture whose salt is already there.
    fn salted(salt: &str) -> Self {
        let fx = Self::new();
        fx.write("var/lib/propolis/witness/id-salt", &format!("{salt}\n"));
        fx
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.p(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.p(rel)).unwrap()
    }

    /// A scratch directory outside the root, for files a case builds.
    fn scratch(&self) -> PathBuf {
        let d = self.dir.path().join("scratch");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }

    fn run(&self, script: &str) -> Run {
        self.run_env(script, &[])
    }

    /// Runs `script` after sourcing the library and calling `pa_init` on the root, under
    /// `set -u -o pipefail`, which is how the witness and the status command run.
    fn run_env(&self, script: &str, env: &[(&str, &str)]) -> Run {
        self.run_raw(
            &format!("set -u -o pipefail\nsource \"$LIB\"\npa_init \"$ROOT\"\n{script}"),
            env,
        )
    }

    fn run_raw(&self, script: &str, env: &[(&str, &str)]) -> Run {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(script)
            .env("PATH", path)
            .env("LIB", LIB)
            .env("ROOT", &self.root)
            .env("D", self.scratch())
            .env("STUB_LOG", &self.log)
            .env_remove("PA_TEST_WALL")
            .env_remove("PA_TEST_BOOT")
            .env_remove("PA_TEST_UP")
            .env_remove("PA_TEST_READ_AS_SELF")
            .env_remove("PA_TEST_UID")
            .env_remove("PA_ALIAS_SET")
            .env_remove("PA_LOCK_FD")
            .env_remove("PA_CLEANUP")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        let output = child.wait_with_output().unwrap();
        Run {
            code: output.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&output.stdout).into_owned(),
            err: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// The time seam: wall 1_000_000, boot `abcdef01`, 5000 s of uptime.
const NOW: [(&str, &str); 3] = [
    ("PA_TEST_WALL", "1000000"),
    ("PA_TEST_BOOT", "abcdef01"),
    ("PA_TEST_UP", "5000"),
];

/// The heartbeat URL is taken from alert.env over propolis.env and only when it is https; any
/// other value is held back with its reason and never offered for a request. An inherited
/// PA_PG_GUARD_KNOWN is dropped at load, so no caller's environment can vouch for a binary. A
/// stored journal cursor is used only in a cursor's form, and each journal class lists its texts.
#[test]
fn the_heartbeat_url_needs_https_and_a_cursor_needs_its_form() {
    let fx = Fx::new();
    let show = "pa_settings_load\necho \"state=$PA_HB_STATE\"\necho \"url=${PA_HB_URL:-none}\"\necho \"ops=$PA_OPS_ENABLED\"";
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/a\nPROPOLIS_OPS_ENABLED=Yes\n",
    );
    let r = fx.run(show);
    assert_eq!(
        (r.get("state"), r.get("url"), r.get("ops")),
        ("insecure".into(), "none".into(), "1".into())
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/b\n",
    );
    let r = fx.run(show);
    assert_eq!(
        (r.get("state"), r.get("url")),
        ("set".into(), "https://hc.example.invalid/b".into())
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=\"https://hc.example.invalid/c\\\"\n",
    );
    assert_eq!(fx.run(show).get("state"), "invalid");

    let r = fx.run_env(
        "echo \"known=${PA_PG_GUARD_KNOWN:-none}\"",
        &[("PA_PG_GUARD_KNOWN", "1/2/3")],
    );
    assert_eq!(r.get("known"), "none");

    let r = fx.run(
        "for c in 's=0123abcd;i=1f;b=89ef;m=2a;t=5;x=9' 's=1' 's=1;i=2 x' '../etc/shadow'; do\n\
         if pa_jcursor_ok \"$c\"; then echo \"c=ok\"; else echo \"c=no\"; fi\ndone\n\
         echo \"hook=$(pa_journal_patterns hook | wc -l)\"\n\
         pa_journal_patterns nosuch > /dev/null; echo \"none=$?\"",
    );
    let cs: Vec<&str> = r.out.lines().filter_map(|l| l.strip_prefix("c=")).collect();
    assert_eq!(cs, ["ok", "no", "no", "no"]);
    // Sixteen fields of 64 hex digits each have a cursor's form but pass the 512-byte cap.
    let long = (0..16u8)
        .map(|i| format!("{}={}", (b'a' + i) as char, "0123456789abcdef".repeat(4)))
        .collect::<Vec<_>>()
        .join(";");
    assert!(long.len() > 512);
    let capped = fx.run(&format!(
        "if pa_jcursor_ok '{long}'; then echo c=ok; else echo c=no; fi"
    ));
    assert_eq!(capped.get("c"), "no");
    assert_eq!(r.get("hook").trim(), "3");
    assert_eq!(r.get("none"), "1");
}

/// What the heartbeat request records for each answer: ok for any 2xx and a cause word for the
/// rest. A redirect is an answer from the server (never followed), not a failed connection.
#[test]
fn pa_heartbeat_get_names_each_answer_by_its_cause() {
    let fx = Fx::new();
    write_exec(
        &fx.bin.join("curl"),
        "#!/usr/bin/env bash\nprintf '%s' \"$HB_CODE\"\nexit \"${HB_RC:-0}\"\n",
    );
    for (code, rc, want) in [
        ("200", "0", "ok"),
        ("204", "0", "ok"),
        ("301", "0", "http.client"),
        ("307", "0", "http.client"),
        ("401", "0", "http.auth"),
        ("404", "0", "http.not_found"),
        ("429", "0", "http.rate"),
        ("418", "0", "http.client"),
        ("503", "0", "http.server"),
        ("000", "28", "net.timeout"),
        ("000", "7", "net.connect"),
        ("", "7", "net.connect"),
    ] {
        let r = fx.run_env(
            "PA_HB_URL=https://hc.example.invalid/x; pa_heartbeat_get; echo \"result=$PA_HB_RESULT\"",
            &[("HB_CODE", code), ("HB_RC", rc)],
        );
        assert_eq!(r.get("result"), want, "code {code:?} status {rc}");
    }
}

#[test]
fn sourcing_the_library_sets_an_integer_version_and_the_alert_env_name_and_running_it_refuses() {
    let fx = Fx::new();
    let r = fx.run("echo \"version=$PA_LIB_VERSION\"\necho \"env=$PA_ALERT_ENV_NAME\"");
    assert_eq!(r.code, 0, "{}", r.err);
    let version = r.get("version");
    assert!(
        !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()),
        "PA_LIB_VERSION must be an integer: {version}"
    );
    assert_eq!(version, "14");
    assert_eq!(r.get("env"), "alert.env");

    let direct = fx.run_raw("bash \"$LIB\"", &[]);
    assert_eq!(direct.code, 64, "{}", direct.err);
    assert!(
        direct.err.contains("alert-lib.sh is sourced, not run"),
        "{}",
        direct.err
    );
    assert_ne!(
        mode_of(Path::new(LIB)) & 0o111,
        0,
        "the library is committed executable until a caller sources it"
    );
    let executed = fx.run_raw("\"$LIB\"", &[]);
    assert_eq!(executed.code, 64, "{}", executed.err);
}

#[test]
fn the_library_sets_no_trap_and_pa_cleanup_removes_what_pa_cleanup_lists() {
    let fx = Fx::salted(SALT);
    let r = fx.run_raw(
        r#"set -u -o pipefail
source "$LIB"
echo "after-source=[$(trap -p)]"
pa_init "$ROOT"
: > "$PA_STATE/state.lock"
pa_lock 5
pa_state_write meta <<<"$(printf 'M\tclock\t1/-/0')"
printf 'x\n' | pa_write "$PA_STATE/observe"
pa_read_as "$(id -un)" "$PA_STATE/id-salt" 100 > /dev/null
pa_unlock
echo "after-calls=[$(trap -p)]"
: > "$D/a"; : > "$D/b"
PA_CLEANUP+=("$D/a" "$D/b")
pa_cleanup
[ -e "$D/a" ] || [ -e "$D/b" ] || echo removed=yes
echo "left=${#PA_CLEANUP[@]}"
trap 'echo bye' EXIT
source "$LIB"
pa_init "$ROOT"
pa_cleanup
echo "caller-trap=[$(trap -p EXIT)]"
"#,
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("after-source"), "[]");
    assert_eq!(r.get("after-calls"), "[]");
    assert_eq!(r.get("removed"), "yes");
    assert_eq!(r.get("left"), "0");
    assert_eq!(r.get("caller-trap"), "[trap -- 'echo bye' EXIT]");
}

#[test]
fn an_inherited_pa_cleanup_or_pa_lock_fd_is_ignored_and_a_value_the_shell_set_itself_is_kept() {
    let fx = Fx::new();
    let victim = fx.scratch().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    let r = fx.run_env(
        "pa_cleanup\n[ -e \"$D/victim\" ] && echo kept=yes",
        &[("PA_CLEANUP", victim.to_str().unwrap())],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.get("kept"),
        "yes",
        "pa_cleanup removes only what this shell listed"
    );

    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run(
        r#"flock -n "$PA_STATE/state.lock" env PA_LOCK_FD=9 bash -c '
    source "$LIB"; pa_init "$ROOT"
    rc=0; pa_lock 1 || rc=$?
    echo "inherited=$rc"
'
: > "$D/mine"
PA_CLEANUP+=("$D/mine")
pa_lock 5
held="$PA_LOCK_FD"
source "$LIB"
echo "list=${#PA_CLEANUP[@]}"
[ "$PA_LOCK_FD" = "$held" ] && echo fd=kept
if flock -n "$PA_STATE/state.lock" true; then echo other=free; else echo other=held; fi
pa_unlock
pa_cleanup
[ -e "$D/mine" ] || echo mine=removed
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.get("inherited"),
        "1",
        "an inherited descriptor number is not a lock: pa_lock waits for the real one"
    );
    assert_eq!(
        r.get("list"),
        "1",
        "sourcing again keeps the shell's own list"
    );
    assert_eq!(r.get("fd"), "kept");
    assert_eq!(r.get("other"), "held");
    assert_eq!(r.get("mine"), "removed");
}

#[test]
fn pa_init_sets_umask_077_so_a_plain_redirect_creates_mode_0600() {
    let fx = Fx::new();
    let r = fx.run_raw(
        "umask 022\nsource \"$LIB\"\npa_init \"$ROOT\"\necho \"umask=$(umask)\"\n: > \"$D/plain\"",
        &[],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("umask"), "0077");
    assert_eq!(mode_of(&fx.scratch().join("plain")), 0o600);
}

#[test]
fn the_library_works_under_a_callers_errexit_and_nounset() {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example\n",
    );
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run_raw(
        r#"set -euo pipefail
source "$LIB"
pa_init "$ROOT"
pa_now
pa_env_get MISSING "$ROOT/etc/propolis/nothing.env" > /dev/null
pa_settings_load
pa_salt_ensure
pa_id unit sensor-ssh.service > /dev/null
pa_alias > /dev/null
pa_role > /dev/null
pa_ok_field x
pa_lock 5
pa_state_write meta <<<"$(printf 'M\tprofile_last\tlegacy')"
pa_state_read meta > /dev/null
pa_clock_check
pa_unlock
pa_sensor_logs "ssh:/var/log/a.log"
echo reached=yes
"#,
        &NOW,
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.out, r.err);
    assert_eq!(r.get("reached"), "yes");
}

/// Runs `pa_env_get K` on one file holding `body` and returns the value, the complex flag and
/// whether any line assigned K.
fn env_get_one(fx: &Fx, body: &str) -> (String, String, bool) {
    std::fs::write(fx.scratch().join("one.env"), body).unwrap();
    let r = fx.run(
        "pa_env_get K \"$D/one.env\" > /dev/null\n\
         printf 'value=[%s]\\ncomplex=%s\\nsrc=%s\\n' \"$PA_ENV_VALUE\" \"$PA_ENV_COMPLEX\" \"$PA_ENV_SRC\"\n\
         printf 'printed=[%s]\\n' \"$(pa_env_get K \"$D/one.env\")\"",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let value = r.get("value");
    assert_eq!(
        r.get("printed"),
        value,
        "the printed value and PA_ENV_VALUE agree"
    );
    let value = value
        .strip_prefix('[')
        .unwrap()
        .strip_suffix(']')
        .unwrap()
        .to_string();
    (value, r.get("complex"), !r.get("src").is_empty())
}

#[test]
fn pa_env_get_reads_each_line_shape_the_way_systemd_does() {
    let fx = Fx::new();
    for (body, want) in [
        ("K=plain\n", Some("plain")),
        ("   K=indented\n", Some("indented")),
        ("\tK=tabbed\n", Some("tabbed")),
        ("K = spaced\n", Some("spaced")),
        ("K=trailing  \t\n", Some("trailing")),
        ("K=crlf\r\n", Some("crlf")),
        ("K=\"two words\"\n", Some("two words")),
        ("K='single'\n", Some("single")),
        ("K=\"it's\"\n", Some("it's")),
        ("K=\"\"\n", Some("")),
        ("K=\n", Some("")),
        ("K=a=b\n", Some("a=b")),
        ("K=no newline at the end", Some("no newline at the end")),
        ("#K=commented\n", None),
        ("  # K=commented\n", None),
        (" ; K=semicolon\n", None),
        ("KK=longer\nK2=other\nk=lower\n", None),
        ("just text\n", None),
    ] {
        let (value, complex, found) = env_get_one(&fx, body);
        match want {
            Some(want) => {
                assert!(found, "{body:?} assigns K");
                assert_eq!(value, want, "{body:?}");
                assert_eq!(complex, "0", "{body:?} is not complex");
            }
            None => {
                assert!(!found, "{body:?} does not assign K");
                assert_eq!(value, "", "{body:?}");
            }
        }
    }
}

#[test]
fn pa_env_get_takes_the_last_assignment_in_the_last_file_that_has_one() {
    let fx = Fx::new();
    let d = fx.scratch();
    std::fs::write(d.join("a.env"), "K=a1\nK=a2\n").unwrap();
    std::fs::write(d.join("b.env"), "K=b1\n").unwrap();
    std::fs::write(d.join("c.env"), "OTHER=c1\n").unwrap();
    let r = fx.run(
        "echo \"abc=$(pa_env_get K \"$D/a.env\" \"$D/b.env\" \"$D/c.env\")\"\n\
         echo \"ba=$(pa_env_get K \"$D/b.env\" \"$D/a.env\")\"\n\
         pa_env_get K \"$D/a.env\" \"$D/b.env\" \"$D/c.env\" > /dev/null\n\
         echo \"src=${PA_ENV_SRC##*/}\"\n\
         echo \"missing=[$(pa_env_get K \"$D/none.env\")]\"",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("abc"), "b1");
    assert_eq!(r.get("ba"), "a2");
    assert_eq!(r.get("src"), "b.env");
    assert_eq!(r.get("missing"), "[]");
}

#[test]
fn pa_env_get_flags_a_backslash_or_an_unmatched_quote_and_prints_the_raw_value() {
    let fx = Fx::new();
    for (body, raw) in [
        ("K=back\\slash\n", "back\\slash"),
        ("K=\"unterminated\n", "\"unterminated"),
        ("K=unopened'\n", "unopened'"),
        ("K=it's\n", "it's"),
        ("K='a'b'\n", "'a'b'"),
        ("K=\"\n", "\""),
        ("K=\"esc\\\"aped\"  \n", "\"esc\\\"aped\""),
    ] {
        let (value, complex, found) = env_get_one(&fx, body);
        assert!(found, "{body:?}");
        assert_eq!(complex, "1", "{body:?} sets PA_ENV_COMPLEX");
        assert_eq!(value, raw, "{body:?} prints the raw value");
    }
    // The flag belongs to the chosen line only: a later plain assignment clears it.
    let (value, complex, _) = env_get_one(&fx, "K=back\\slash\nK=fine\n");
    assert_eq!((value.as_str(), complex.as_str()), ("fine", "0"));

    // systemd joins a line to the one before it when that one ends in an escaping backslash (a
    // comment line too) or leaves a quote open, and a CR ends a line: in each case it does not
    // read the chosen line on its own, so the reading is flagged.
    for (body, raw) in [
        ("OTHER=abc\\\nK=ops\n", "ops"),
        ("# note \\\nK=ops\n", "ops"),
        ("N=\"first\nK=ops\nend\"\n", "ops"),
        // An escaped quote does not close a double-quoted value.
        ("N=\"a\\\"\nK=ops\nend\"\n", "ops"),
        // A value can close one quote and open another, which stays open.
        ("N=\"a\" \"b\nK=ops\nc\"\n", "ops"),
        ("N='a' 'b\nK=ops\nc'\n", "ops"),
        // A backslash escapes the newline inside double quotes too.
        ("N=\"a\\\nK=ops\nb\"\n", "ops"),
        // A CR ends a line wherever it sits, in the chosen line or in another one.
        ("K=old\rK=new\n", "new"),
        ("K=old\nA=x\rK=new\n", "new"),
        ("A=x\rK=new\rB=y\n", "new"),
    ] {
        let (value, complex, found) = env_get_one(&fx, body);
        assert!(found, "{body:?}");
        assert_eq!(complex, "1", "{body:?} sets PA_ENV_COMPLEX");
        assert_eq!(value, raw, "{body:?} prints the raw value");
    }
    // An escaped backslash ends nothing, a quote closed before K leaves K its own line, a blank
    // line ends a continued value, a backslash means nothing inside single quotes, and a quote
    // inside an unquoted value opens nothing.
    for body in [
        "OTHER=abc\\\\\nK=ops\n",
        "N=\"first\"\nK=ops\n",
        "N=\"first\nend\"\nK=ops\n",
        "N='a b'\n# note\nK=ops\n",
        "OTHER=abc\\\n\nK=ops\n",
        "N=\"a\\\"b\"\nK=ops\n",
        "N=\"a\\\\\"\nK=ops\n",
        "N='a\\'\nK=ops\n",
        "N=it's\nK=ops\n",
        "N=a\"b\nK=ops\n",
        "N=\"a\" 'b'\nK=ops\n",
        "N=x\r\nK=ops\r\n",
    ] {
        let (value, complex, _) = env_get_one(&fx, body);
        assert_eq!((value.as_str(), complex.as_str()), ("ops", "0"), "{body:?}");
    }
}

#[test]
fn pa_env_get_counts_an_unreadable_file_as_absent_and_names_it() {
    let fx = Fx::new();
    let d = fx.scratch();
    std::fs::write(d.join("a.env"), "K=from-a\n").unwrap();
    // A directory in place of the file cannot be read as one, by root or anyone else.
    std::fs::create_dir_all(d.join("dir.env")).unwrap();
    let r = fx.run(
        "pa_env_get K \"$D/a.env\" \"$D/dir.env\" \"$D/none.env\" > /dev/null\n\
         echo \"value=$PA_ENV_VALUE\"\n\
         echo \"unreadable=$PA_ENV_UNREADABLE\"\n\
         pa_env_get K \"$D/a.env\" \"$D/none.env\" > /dev/null\n\
         echo \"clean=[$PA_ENV_UNREADABLE]\"",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("value"), "from-a");
    assert_eq!(r.get("unreadable"), d.join("dir.env").display().to_string());
    assert_eq!(
        r.get("clean"),
        "[]",
        "a missing file is absent, not unreadable"
    );

    // A link to nothing is named, not skipped as missing.
    std::os::unix::fs::symlink(d.join("nowhere.env"), d.join("dangling.env")).unwrap();
    let r = fx.run(
        "pa_env_get K \"$D/a.env\" \"$D/dangling.env\" > /dev/null\n\
         echo \"value=$PA_ENV_VALUE\"\n\
         echo \"unreadable=$PA_ENV_UNREADABLE\"",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("value"), "from-a");
    assert_eq!(
        r.get("unreadable"),
        d.join("dangling.env").display().to_string()
    );

    // A regular file the caller may not read must not end a caller running under errexit. Root
    // reads a mode-0000 file, so this part needs another account.
    std::fs::write(d.join("closed.env"), "K=from-closed\n").unwrap();
    std::fs::set_permissions(d.join("closed.env"), std::fs::Permissions::from_mode(0o000)).unwrap();
    if is_root() {
        eprintln!("skipped the mode-0000 env file case: root can read any file");
    } else {
        let r = fx.run_raw(
            "set -euo pipefail\nsource \"$LIB\"\npa_init \"$ROOT\"\n\
             pa_env_get K \"$D/a.env\" \"$D/closed.env\" > /dev/null\n\
             echo \"value=$PA_ENV_VALUE\"\n\
             echo \"unreadable=$PA_ENV_UNREADABLE\"",
            &[],
        );
        assert_eq!(r.code, 0, "{}", r.err);
        assert_eq!(r.get("value"), "from-a");
        assert_eq!(
            r.get("unreadable"),
            d.join("closed.env").display().to_string()
        );
    }
}

const SETTINGS_DUMP: &str = r#"pa_settings_load
for v in PA_URL PA_TOPIC PA_TOKEN PA_TARGET PA_TARGET_SRC PA_D_URL PA_D_TOPIC PA_D_TARGET PA_INVALID; do
    printf '%s=%s\n' "$v" "${!v}"
done
"#;

#[test]
fn pa_settings_load_keeps_valid_values_and_ignores_invalid_ones_by_name() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL = https://ntfy.example/\n\
         PROPOLIS_OPS_NTFY_TOPIC=\"ops-alerts_1\"\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_abc!~\n",
    );
    let r = fx.run(SETTINGS_DUMP);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("PA_URL"), "https://ntfy.example");
    assert_eq!(r.get("PA_TOPIC"), "ops-alerts_1");
    assert_eq!(r.get("PA_TOKEN"), "tk_abc!~");
    assert_eq!(r.get("PA_TARGET"), "1");
    assert_eq!(r.get("PA_TARGET_SRC"), "propolis.env");
    assert_eq!(r.get("PA_D_URL"), "https://ntfy.example");
    assert_eq!(r.get("PA_D_TOPIC"), "ops-alerts_1");
    assert_eq!(r.get("PA_D_TARGET"), "1");
    assert_eq!(r.get("PA_INVALID"), "");

    // http:// is a valid target (today's daemon and hook accept it).
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=http://10.0.0.5:8080/ntfy\nPROPOLIS_OPS_NTFY_TOPIC=ops\n",
    );
    let r = fx.run(SETTINGS_DUMP);
    assert_eq!(r.get("PA_URL"), "http://10.0.0.5:8080/ntfy");
    assert_eq!(r.get("PA_TOKEN"), "");
    assert_eq!(r.get("PA_TARGET"), "1");

    let long_topic = "t".repeat(65);
    let long_token = "k".repeat(257);
    for (url, topic, token) in [
        ("ftp://ntfy.example", "has space", "two words"),
        ("https://", &long_topic, &long_token),
        ("https://ntfy.example/a b", "ops/alerts", "tab\there"),
        ("ntfy.example", "caf\u{e9}", "tok\u{202e}en"),
    ] {
        fx.write(
            "etc/propolis/propolis.env",
            &format!(
                "PROPOLIS_OPS_NTFY_URL={url}\nPROPOLIS_OPS_NTFY_TOPIC={topic}\nPROPOLIS_OPS_NTFY_TOKEN={token}\n"
            ),
        );
        let r = fx.run_env(SETTINGS_DUMP, &[("LC_ALL", "C.UTF-8")]);
        assert_eq!(r.code, 0, "{}", r.err);
        for v in ["PA_URL", "PA_TOPIC", "PA_TOKEN", "PA_TARGET_SRC"] {
            assert_eq!(r.get(v), "", "{v} for {url:?} {topic:?} {token:?}");
        }
        assert_eq!(r.get("PA_TARGET"), "0", "{url:?}");
        assert_eq!(r.get("PA_D_TARGET"), "0", "{url:?}");
        let invalid = r.get("PA_INVALID");
        for key in [
            "PROPOLIS_OPS_NTFY_URL",
            "PROPOLIS_OPS_NTFY_TOPIC",
            "PROPOLIS_OPS_NTFY_TOKEN",
        ] {
            assert!(invalid.split(' ').any(|k| k == key), "{key} in {invalid:?}");
        }
    }

    // An empty assignment is unset, not invalid.
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=\nPROPOLIS_OPS_NTFY_TOPIC=ops\n",
    );
    let r = fx.run(SETTINGS_DUMP);
    assert_eq!(r.get("PA_INVALID"), "");
    assert_eq!(r.get("PA_TARGET"), "0");
}

/// Every setting of the shell senders, with the file each came from.
const SETTINGS_ALL: &str = r#"pa_settings_load
for v in PA_URL PA_TOPIC PA_TOKEN PA_TARGET PA_TARGET_SRC PA_TARGET_SPLIT PA_URL_SRC PA_TOPIC_SRC \
    PA_D_URL PA_D_TOPIC PA_D_TOKEN PA_D_TARGET PA_INVALID PA_INVALID_IN PA_D_INVALID \
    PA_ALIAS_SET PA_ALIAS_SRC PA_DAILY_AT PA_DAILY_SRC PA_HB_STATE PA_PROFILE PA_PROFILE_STATE PA_PROFILE_SRC; do
    printf '%s=%s\n' "$v" "${!v}"
done
"#;

/// The URL and the topic make a target only when one file sets both: alert.env's URL with
/// propolis.env's topic, or the reverse, is no target at all (and no target source), and the
/// daemon's target, which is propolis.env's alone, is untouched by it.
#[test]
fn a_target_whose_url_and_topic_come_from_different_files_is_no_target() {
    let fx = Fx::new();
    let split = |propolis: &str, alert: &str| {
        fx.write("etc/propolis/propolis.env", propolis);
        fx.write("etc/propolis/alert.env", alert);
        let r = fx.run(SETTINGS_ALL);
        assert_eq!(r.code, 0, "{}", r.err);
        r
    };
    let r = split(
        "PROPOLIS_OPS_NTFY_TOPIC=from-propolis\n",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\n",
    );
    assert_eq!(
        (r.get("PA_URL"), r.get("PA_TOPIC")),
        ("https://alert.example".into(), "from-propolis".into())
    );
    assert_eq!(r.get("PA_TARGET"), "0");
    assert_eq!(r.get("PA_TARGET_SRC"), "");
    assert_eq!(r.get("PA_TARGET_SPLIT"), "1");
    assert_eq!(
        (r.get("PA_URL_SRC"), r.get("PA_TOPIC_SRC")),
        ("alert.env".into(), "propolis.env".into())
    );
    assert_eq!(r.get("PA_D_TARGET"), "0");

    let r = split(
        "PROPOLIS_OPS_NTFY_URL=https://daemon.example\n",
        "PROPOLIS_OPS_NTFY_TOPIC=from-alert\n",
    );
    assert_eq!(r.get("PA_TARGET"), "0");
    assert_eq!(r.get("PA_TARGET_SRC"), "");
    assert_eq!(r.get("PA_TARGET_SPLIT"), "1");

    // A whole target in propolis.env and only a URL in alert.env: the shell senders have none,
    // the daemon keeps its own.
    let r = split(
        "PROPOLIS_OPS_NTFY_URL=https://daemon.example\nPROPOLIS_OPS_NTFY_TOPIC=dtopic\n",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\n",
    );
    assert_eq!(r.get("PA_TARGET"), "0");
    assert_eq!(r.get("PA_TARGET_SPLIT"), "1");
    assert_eq!(r.get("PA_D_TARGET"), "1");
    assert_eq!(r.get("PA_D_URL"), "https://daemon.example");

    // Both in one file: a target, and no split.
    let r = split(
        "PROPOLIS_OPS_NTFY_TOPIC=from-propolis\n",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\nPROPOLIS_OPS_NTFY_TOPIC=from-alert\n",
    );
    assert_eq!(r.get("PA_TARGET"), "1");
    assert_eq!(r.get("PA_TARGET_SRC"), "alert.env");
    assert_eq!(r.get("PA_TARGET_SPLIT"), "0");
}

/// alert.env wins over propolis.env for each setting of the shell senders it assigns: the target,
/// the alias, the daily time and the heartbeat URL. The token goes with the target's file, so a
/// token written for propolis.env's server never goes to alert.env's. The daemon's target and
/// token (PA_D_*) are propolis.env's alone, and today's failure hook is compared with those.
#[test]
fn alert_env_wins_over_propolis_env_for_the_shell_senders_and_the_daemon_target_stays_propolis_env()
{
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://daemon.example\nPROPOLIS_OPS_NTFY_TOPIC=dtopic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_daemon\nPROPOLIS_OPS_HOST_ALIAS=north-relay\n\
         PROPOLIS_OPS_DAILY_AT=07:00\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example/\nPROPOLIS_OPS_NTFY_TOPIC=atopic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_alert\nPROPOLIS_OPS_HOST_ALIAS=south-relay\n\
         PROPOLIS_OPS_DAILY_AT=09:15\n",
    );
    let r = fx.run(&format!(
        "{SETTINGS_ALL}if pa_hook_differs; then echo differs=1; else echo differs=0; fi\n\
         echo \"hook_url=$PA_HOOK_URL\""
    ));
    assert_eq!(r.code, 0, "{}", r.err);
    for (k, v) in [
        ("PA_URL", "https://alert.example"),
        ("PA_TOPIC", "atopic"),
        ("PA_TOKEN", "tk_alert"),
        ("PA_TARGET", "1"),
        ("PA_TARGET_SRC", "alert.env"),
        ("PA_D_URL", "https://daemon.example"),
        ("PA_D_TOPIC", "dtopic"),
        ("PA_D_TOKEN", "tk_daemon"),
        ("PA_D_TARGET", "1"),
        ("PA_ALIAS_SET", "south-relay"),
        ("PA_ALIAS_SRC", "alert.env"),
        ("PA_DAILY_AT", "09:15"),
        ("PA_DAILY_SRC", "alert.env"),
    ] {
        assert_eq!(r.get(k), v, "{k}");
    }
    assert_eq!(
        (r.get("differs"), r.get("hook_url")),
        ("0".into(), "https://daemon.example".into()),
        "today's hook is compared with the daemon's target, not with alert.env"
    );

    // alert.env with a target and no token: the post carries none, not propolis.env's.
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\nPROPOLIS_OPS_NTFY_TOPIC=atopic\n",
    );
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(r.get("PA_TOKEN"), "");
    assert_eq!(r.get("PA_D_TOKEN"), "tk_daemon");
    assert_eq!(
        (r.get("PA_ALIAS_SET"), r.get("PA_ALIAS_SRC")),
        ("north-relay".into(), "propolis.env".into())
    );
    assert_eq!(r.get("PA_DAILY_SRC"), "propolis.env");

    // alert.env without a target leaves propolis.env's in place for the shell senders too.
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hb.example/x\n",
    );
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(r.get("PA_TARGET_SRC"), "propolis.env");
    assert_eq!(r.get("PA_TOKEN"), "tk_daemon");
    assert_eq!(r.get("PA_HB_STATE"), "set");

    // A key alert.env leaves empty is not set there: a template copied with empty lines does not
    // blank what propolis.env sets.
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=\nPROPOLIS_OPS_NTFY_TOPIC=\nPROPOLIS_OPS_NTFY_TOKEN=\nPROPOLIS_OPS_HOST_ALIAS=\n",
    );
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(r.get("PA_TARGET_SRC"), "propolis.env");
    assert_eq!(r.get("PA_TOKEN"), "tk_daemon");
    assert_eq!(r.get("PA_ALIAS_SET"), "north-relay");

    // A value alert.env assigns wins even when it is invalid: the shell senders ignore it and fall
    // back to no value, never to propolis.env's, and the file is named with it.
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=alert.example\nPROPOLIS_OPS_NTFY_TOPIC=atopic\n",
    );
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(r.get("PA_URL"), "");
    assert_eq!(r.get("PA_TARGET"), "0");
    assert_eq!(r.get("PA_INVALID"), "PROPOLIS_OPS_NTFY_URL");
    assert_eq!(r.get("PA_INVALID_IN"), "PROPOLIS_OPS_NTFY_URL=alert.env");
    assert_eq!(r.get("PA_D_INVALID"), "");
    assert_eq!(r.get("PA_D_TARGET"), "1");
}

/// PROPOLIS_ALERT_PROFILE is read (alert.env over propolis.env) and validated: legacy and v2 are
/// its values, anything else is invalid and read as legacy. Whatever the file says, this release
/// runs legacy: only the test seam PA_TEST_PROFILE turns v2 on, and only under a non-empty root,
/// which no unit and no script passes, so a production run cannot reach it.
#[test]
fn the_profile_is_read_and_validated_and_only_the_test_seam_under_a_root_reaches_v2() {
    let fx = Fx::new();
    let profile = |propolis: &str, alert: Option<&str>, env: &[(&str, &str)]| {
        fx.write("etc/propolis/propolis.env", propolis);
        match alert {
            Some(a) => fx.write("etc/propolis/alert.env", a),
            None => {
                let _ = std::fs::remove_file(fx.p("etc/propolis/alert.env"));
            }
        }
        let r = fx.run_env(SETTINGS_ALL, env);
        assert_eq!(r.code, 0, "{}", r.err);
        (
            r.get("PA_PROFILE"),
            r.get("PA_PROFILE_STATE"),
            r.get("PA_PROFILE_SRC"),
        )
    };
    let t = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
    assert_eq!(profile("", None, &[]), t("legacy", "unset", ""));
    assert_eq!(
        profile("PROPOLIS_ALERT_PROFILE=legacy\n", None, &[]),
        t("legacy", "legacy", "propolis.env")
    );
    assert_eq!(
        profile("PROPOLIS_ALERT_PROFILE=v2\n", None, &[]),
        t("legacy", "v2", "propolis.env"),
        "v2 is read, and not in force in this release"
    );
    for bad in ["V2", "v3", "legacy2", "\"v2 \"x", "on"] {
        assert_eq!(
            profile(&format!("PROPOLIS_ALERT_PROFILE={bad}\n"), None, &[]),
            t("legacy", "invalid", "propolis.env"),
            "{bad}"
        );
    }
    assert_eq!(
        profile(
            "PROPOLIS_ALERT_PROFILE=v2\n",
            Some("PROPOLIS_ALERT_PROFILE=legacy\n"),
            &[]
        ),
        t("legacy", "legacy", "alert.env"),
        "alert.env wins"
    );
    assert_eq!(
        profile("", None, &[("PA_TEST_PROFILE", "v2")]),
        t("v2", "unset", ""),
        "the seam under a root"
    );
    assert_eq!(
        profile("", None, &[("PA_TEST_PROFILE", "other")]),
        t("legacy", "unset", ""),
        "the seam takes only a profile's name"
    );
    // pa_init with an empty root, which is how every unit and script runs it: the seam is ignored.
    let r = fx.run_raw(
        &format!("set -u -o pipefail\nsource \"$LIB\"\npa_init ''\n{SETTINGS_ALL}"),
        &[("PA_TEST_PROFILE", "v2")],
    );
    assert_eq!(r.get("PA_PROFILE"), "legacy", "{}", r.err);
}

/// On a collector, and on a host whose role cannot be told, the gate holds pointer unless the
/// credential a post carries (the token, or without one the user and password in the URL) is
/// proven unable to read the topic, or there is none. An answer of unknown, a stored answer about
/// another credential, and a line from before credentials were named all hold pointer; a single
/// box is not held by this rule.
#[test]
fn on_a_collector_the_gate_holds_pointer_unless_the_credential_a_post_carries_is_proven_noread() {
    let fx = Fx::salted(SALT);
    let fresh = "999000/abcdef01/4000";
    let gate = |url: &str, token: &str, tk: &str, cred: &str, role: &str| -> String {
        let mut env = format!("PROPOLIS_OPS_NTFY_URL={url}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n");
        if !token.is_empty() {
            env.push_str(&format!("PROPOLIS_OPS_NTFY_TOKEN={token}\n"));
        }
        fx.write("etc/propolis/propolis.env", &env);
        let r = fx.run_env(
            &format!(
                "pa_settings_load\nb=\"$(pa_readcheck_binding \"$PA_URL\" \"$PA_TOPIC\")\"\n\
                 c='{cred}'; [ \"$c\" != cur ] || c=\"$(pa_cred_fp \"$PA_URL\" \"$PA_TOKEN\")\"\n\
                 tab=$'\\t'\n\
                 printf '#readcheck v1 g=1\\nR\\t%s\\t{fresh}\\trefused\\t{fresh}\\trefused\\t{tk}\\t403\\t403\\tboth\\t403%s\\n' \
                 \"$b\" \"${{c:+$tab$c}}\" > \"$PA_STATE/readcheck\"\n\
                 PA_ROLE={role}; echo \"gate=$(pa_gate)\""
            ),
            &NOW,
        );
        r.get("gate")
    };
    let https = "https://ntfy.invalid";
    let tok = "tk_x";
    assert_eq!(
        gate(https, tok, "unknown", "cur", "collector"),
        "pointer:token-unknown"
    );
    assert_eq!(gate(https, tok, "noread", "cur", "collector"), "full");
    assert_eq!(
        gate(https, tok, "reads", "cur", "collector"),
        "pointer:token-reads"
    );
    assert_eq!(
        gate(https, tok, "noread", "", "collector"),
        "pointer:token-unknown",
        "a line that does not say which credential it is about"
    );
    assert_eq!(
        gate(https, tok, "noread", "token:00000000", "collector"),
        "pointer:token-unknown",
        "an answer about another token"
    );
    assert_eq!(
        gate(https, tok, "unknown", "cur", "unknown"),
        "pointer:token-unknown",
        "a role that cannot be told"
    );
    assert_eq!(gate(https, tok, "unknown", "cur", "single"), "full");
    assert_eq!(
        gate(https, "", "reads", "token:00000000", "collector"),
        "full",
        "no credential: nothing a post carries can read"
    );
    let creds = "https://alice:pw@ntfy.invalid";
    assert_eq!(gate(creds, "", "noread", "cur", "collector"), "full");
    assert_eq!(
        gate(creds, "", "unknown", "cur", "collector"),
        "pointer:token-unknown"
    );
    assert_eq!(
        gate(creds, "", "-", "", "collector"),
        "pointer:token-unknown",
        "credentials in the URL that were never asked"
    );
    assert_eq!(
        gate("http://ntfy.invalid", tok, "unknown", "cur", "collector"),
        "pointer:insecure"
    );
}

/// A credential's answer is about the credential it was asked with: the stored line names it by
/// kind and a salted hash (token:<8 hex>, or url:<8 hex> for a user and password in the URL),
/// appended as the last field, and names none when nothing was carried, so the line is the one an
/// older release wrote. On a transient attempt a fresh definite answer about the credential is
/// kept, never replaced by the stored one; an unknown answer keeps a stored definite one only when
/// that one is about the same credential.
#[test]
fn the_stored_line_names_its_credential_and_a_transient_attempt_keeps_a_fresh_credential_answer() {
    let fx = Fx::salted(SALT);
    let k8 = fx.run("pa_token8 tk_x").out;
    assert!(k8.len() == 8, "{k8}");
    let old = |tk: &str, cred: &str| {
        fx.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=3\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\t{tk}\t403\t403\tboth\t403{cred}\n"
            ),
        );
    };
    let merge = |class: &str, tk: &str, fp: &str| {
        fx.run_env(
            &format!(
                "pa_now; have=0; _pa_rc_line shell && have=1\n\
                 PA_RC_CLASS={class} PA_RC_TOKEN={tk} PA_RC_JSON=503 PA_RC_RAW=403 PA_RC_SSE=403\n\
                 pa_readcheck_merge both {RC_BINDING} \"$have\" '{fp}'"
            ),
            &NOW,
        )
        .out
    };
    let cur = format!("token:{k8}");
    old("reads", &format!("\t{cur}"));
    assert_eq!(
        merge("transient", "noread", &cur),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\ttransient\t999000/abcdef01/4000\trefused\tnoread\t403\t403\tboth\t403\t{cur}\n"
        ),
        "a fresh noread on a transient attempt is kept"
    );
    assert_eq!(
        merge("transient", "unknown", &cur),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\ttransient\t999000/abcdef01/4000\trefused\treads\t403\t403\tboth\t403\t{cur}\n"
        ),
        "an unknown answer keeps the stored one about the same token"
    );
    assert_eq!(
        merge("refused", "unknown", "token:00000000"),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\trefused\t1000000/abcdef01/5000\trefused\tunknown\t503\t403\tboth\t403\ttoken:00000000\n"
        ),
        "a stored answer about another token is not carried over"
    );
    old("-", "");
    assert_eq!(
        merge("refused", "-", "-"),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\trefused\t1000000/abcdef01/5000\trefused\t-\t503\t403\tboth\t403\n"
        ),
        "no credential: the line an older release wrote"
    );
    let r = fx.run_env(
        "pa_settings_load; PA_URL=https://alice:pw@ntfy.invalid PA_TOKEN=\n\
         echo \"url=$(pa_cred_fp \"$PA_URL\" '')\"\necho \"tok=$(pa_cred_fp \"$PA_URL\" tk_x)\"\n\
         echo \"none=$(pa_cred_fp https://ntfy.invalid '')\"",
        &NOW,
    );
    assert_eq!(r.get("tok"), cur, "a token replaces any user in the URL");
    assert_eq!(r.get("none"), "-");
    let url = r.get("url");
    assert!(
        url.starts_with("url:") && url.len() == 12 && !url.contains("alice"),
        "{url}"
    );
    // Without a salt nothing can be named, and nothing then matches.
    let bare = Fx::new();
    let r = bare
        .run("rc=0; v=\"$(pa_cred_fp https://ntfy.invalid tk_x)\" || rc=$?; echo \"v=$v rc=$rc\"");
    assert_eq!(r.get("v"), "? rc=1");
}

/// Over plain http a credential's read changes no decision (the gate never gives full there), and
/// the request would carry it in clear: the three anonymous GETs are made and the credential is
/// not asked, which the run says.
#[test]
fn no_request_carrying_a_credential_is_made_over_plain_http() {
    let fx = Fx::new();
    fx.with_curl();
    let show = "pa_readcheck_run \"$U\" '{T}' \"$K\"\necho \"class=$PA_RC_CLASS token=$PA_RC_TOKEN cred=$PA_RC_CRED asked=$PA_RC_CRED_ASKED\"";
    let show = show.replace("{T}", RC_TOPIC);
    let deny = "403|text/plain|";
    let env = |u: &'static str, k: &'static str| {
        vec![
            ("U", u),
            ("K", k),
            ("RC_JSON", deny),
            ("RC_RAW", deny),
            ("RC_SSE", deny),
            ("RC_TOKEN_ANSWER", "401||"),
        ]
    };
    let r = fx.run_env(&show, &env("http://ntfy.invalid", "tk_x"));
    assert_eq!(
        r.get("class"),
        "refused token=unknown cred=token asked=0",
        "{}",
        r.err
    );
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        3
    );
    assert!(!fx.log().contains("header file holds the token"));
    let r = fx.run_env(&show, &env("http://alice:pw@ntfy.invalid", ""));
    assert_eq!(r.get("class"), "refused token=unknown cred=url asked=0");
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        6
    );
    let r = fx.run_env(&show, &env("https://ntfy.invalid", "tk_x"));
    assert_eq!(r.get("class"), "refused token=noread cred=token asked=1");
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        10
    );
}

/// The banner reads an anonymous refusal as proven where the gate holds pointer only for want of
/// knowing what a collector's credential reads: the alert words go on to VERIFIED, as for a token
/// that reads.
#[test]
fn the_banner_on_a_collector_whose_credential_is_not_known_still_says_the_refusal_is_proven() {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN=tk_x\n"
        ),
    );
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\tunknown\t403\t403\tboth\t403\n"
        ),
    );
    let r = fx.run_env(
        "PA_ROLE=collector; pa_settings_load; echo \"gate=$(pa_gate)\"; pa_banner",
        &NOW,
    );
    assert_eq!(r.get("gate"), "pointer:token-unknown", "{}", r.err);
    assert!(
        r.out
            .contains("[propolis 13:46 UTC] alerts: NOT VERIFIED (never)\n"),
        "{}",
        r.out
    );
}

/// A test page proves the shell target: with the target in alert.env, VERIFIED is about that
/// target and its token, and today's failure hook, which posts to propolis.env's target, reading
/// propolis.env its own way does not undo it (it does where the shell target is propolis.env's).
#[test]
fn verified_follows_the_shell_target_from_alert_env_and_not_todays_hooks_reading() {
    let fx = Fx::salted(SALT);
    // The hook reads no indented line: its reading of propolis.env differs from the library's.
    fx.write(
        "etc/propolis/propolis.env",
        "  PROPOLIS_OPS_NTFY_URL=https://daemon.example\nPROPOLIS_OPS_NTFY_TOPIC=dtopic\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN=tk_x\n"
        ),
    );
    let show = "pa_settings_load\nb=\"$(pa_readcheck_binding \"$PA_URL\" \"$PA_TOPIC\")\"\n\
                k=\"$(pa_token8 \"$PA_TOKEN\")\"\n\
                printf '#testpage v1 g=1\\nT\\tabc123\\t999000/abcdef01/4000\\t%s\\t%s\\tok\\t999100/abcdef01/4100\\t0\\n' \"$b\" \"$k\" > \"$PA_STATE/testpage\"\n\
                pa_settings_load; echo \"v=$(pa_verified)\"";
    let r = fx.run_env(show, &NOW);
    assert_eq!(r.get("v"), "VERIFIED 15 min", "{}", r.err);
    // The same page with the target moved back to propolis.env no longer matches it.
    std::fs::remove_file(fx.p("etc/propolis/alert.env")).unwrap();
    let r = fx.run_env("pa_settings_load; echo \"v=$(pa_verified)\"", &NOW);
    assert_eq!(r.get("v"), "NOT VERIFIED (changed)");
}

/// A token goes only with the target of its own file: where alert.env sets a token and no target,
/// the shell senders post to propolis.env's target with propolis.env's token, and the token in
/// alert.env is named as ignored so the operator does not take it for the one in use.
#[test]
fn a_token_in_alert_env_without_a_target_there_is_ignored_and_named_as_ignored() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://daemon.example\nPROPOLIS_OPS_NTFY_TOPIC=dtopic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_daemon\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_TOKEN=tk_alert\n",
    );
    let show = format!("{SETTINGS_ALL}echo \"PA_TOKEN_IGNORED=$PA_TOKEN_IGNORED\"");
    let r = fx.run(&show);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("PA_TARGET_SRC"), "propolis.env");
    assert_eq!(
        r.get("PA_TOKEN"),
        "tk_daemon",
        "the token of the target's own file"
    );
    assert_eq!(r.get("PA_TOKEN_IGNORED"), "1");
    // With the whole target in alert.env its token is the one used, and nothing is ignored.
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\nPROPOLIS_OPS_NTFY_TOPIC=atopic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_alert\n",
    );
    let r = fx.run(&show);
    assert_eq!(r.get("PA_TOKEN"), "tk_alert");
    assert_eq!(r.get("PA_TOKEN_IGNORED"), "0");
    std::fs::remove_file(fx.p("etc/propolis/alert.env")).unwrap();
    let r = fx.run(&show);
    assert_eq!(r.get("PA_TOKEN_IGNORED"), "0");
}

/// An alert.env that is a directory, or a link to a file that does not exist, sets nothing: every
/// setting falls back to propolis.env, the token with the target.
#[test]
fn an_alert_env_that_is_a_directory_or_a_dangling_link_falls_back_to_propolis_env() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://daemon.example\nPROPOLIS_OPS_NTFY_TOPIC=dtopic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_daemon\n",
    );
    std::fs::create_dir_all(fx.p("etc/propolis/alert.env")).unwrap();
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        (r.get("PA_TARGET_SRC"), r.get("PA_TOKEN")),
        ("propolis.env".into(), "tk_daemon".into()),
        "a directory"
    );
    std::fs::remove_dir(fx.p("etc/propolis/alert.env")).unwrap();
    std::os::unix::fs::symlink(
        fx.p("etc/propolis/missing.env"),
        fx.p("etc/propolis/alert.env"),
    )
    .unwrap();
    let r = fx.run(SETTINGS_ALL);
    assert_eq!(
        (r.get("PA_TARGET_SRC"), r.get("PA_TOKEN")),
        ("propolis.env".into(), "tk_daemon".into()),
        "a dangling link"
    );
}

/// A transient attempt keeps a stored token class only while the stored line is about the
/// credential the attempt was made with. A line that names another credential, or none (every
/// line an older release wrote), is not carried over: the attempt's credential is stored with the
/// class unknown, so the light pass stops asking until the hourly pass and the gate holds pointer
/// meanwhile. An unknown answer with no credential named keeps nothing either.
#[test]
fn a_transient_attempt_over_a_line_about_another_credential_stores_unknown_with_the_current_one() {
    let fx = Fx::salted(SALT);
    let k8 = fx.run("pa_token8 tk_x").out;
    let cur = format!("token:{k8}");
    let old = format!(
        "#readcheck v1 g=3\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\tnoread\t403\t403\tboth\t403\n"
    );
    let merge = |class: &str, fp: &str| {
        fx.write("var/lib/propolis/witness/readcheck", &old);
        fx.run_env(
            &format!(
                "pa_now; have=0; _pa_rc_line shell && have=1\n\
                 PA_RC_CLASS={class} PA_RC_TOKEN=unknown PA_RC_JSON=503 PA_RC_RAW=403 PA_RC_SSE=403\n\
                 pa_readcheck_merge both {RC_BINDING} \"$have\" '{fp}'"
            ),
            &NOW,
        )
        .out
    };
    assert_eq!(
        merge("transient", &cur),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\ttransient\t999000/abcdef01/4000\trefused\tunknown\t403\t403\tboth\t403\t{cur}\n"
        ),
        "an older line names no credential: its noread is not kept for this one"
    );
    assert_eq!(
        merge("refused", ""),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\trefused\t1000000/abcdef01/5000\trefused\tunknown\t503\t403\tboth\t403\n"
        ),
        "a credential that cannot be named keeps no stored answer"
    );
}

/// The stored token class is kept through an unknown answer only when the token GET got no
/// answer (000, 429, a 5xx). A definite answer that is not a refusal (a redirect, a 404) stores
/// unknown, and the gate on a collector then holds pointer.
#[test]
fn a_definite_token_answer_that_is_not_a_refusal_replaces_a_stored_noread() {
    let fx = Fx::salted(SALT);
    fx.with_curl();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN=tk_x\n"
        ),
    );
    let run = |answer: &str| {
        let script = format!(
            "pa_settings_load; pa_now\n\
             cur=\"$(pa_cred_fp \"$PA_URL\" \"$PA_TOKEN\")\"\n\
             printf '#readcheck v1 g=1\\nR\\t{RC_BINDING}\\t999000/abcdef01/4000\\trefused\\t999000/abcdef01/4000\\trefused\\tnoread\\t403\\t403\\tboth\\t403\\t%s\\n' \"$cur\" > \"$PA_STATE/readcheck\"\n\
             pa_readcheck_run \"$PA_URL\" \"$PA_TOPIC\" \"$PA_TOKEN\"\n\
             have=0; _pa_rc_line shell && have=1\n\
             line=\"$(pa_readcheck_merge both {RC_BINDING} \"$have\" \"$cur\")\"\n\
             printf '#readcheck v1 g=2\\n%s\\n' \"$line\" > \"$PA_STATE/readcheck\"\n\
             IFS=$'\\t' read -r -a f <<< \"$line\"\n\
             echo \"tk=${{f[6]}}\"; PA_ROLE=collector; echo \"gate=$(pa_gate)\""
        );
        let deny = "403|text/plain|";
        fx.run_env(
            &script,
            &[
                NOW[0],
                NOW[1],
                NOW[2],
                ("RC_JSON", deny),
                ("RC_RAW", deny),
                ("RC_SSE", deny),
                ("RC_TOKEN_ANSWER", answer),
            ],
        )
    };
    for answer in ["302||", "404||"] {
        let r = run(answer);
        assert_eq!(r.get("tk"), "unknown", "{answer}: {}", r.err);
        assert_eq!(r.get("gate"), "pointer:token-unknown", "{answer}");
    }
    for answer in ["503||", "000||", "429||"] {
        let r = run(answer);
        assert_eq!(r.get("tk"), "noread", "{answer}: {}", r.err);
        assert_eq!(r.get("gate"), "full", "{answer}");
    }
}

/// With no target for the shell senders (a URL in alert.env and the topic left in propolis.env,
/// or a topic alert.env sets that is not valid) the daemon and today's failure hook still post to
/// propolis.env's target: the banner says what is known of that topic, READABLE included, and
/// where it is not known that today's hook still posts, never `journal only`.
#[test]
fn the_banner_without_a_shell_target_judges_the_topic_todays_hook_still_posts_to() {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n"),
    );
    let line = |class: &str, role: &str| {
        fx.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=1\nR\t{RC_BINDING}\t999000/abcdef01/4000\t{class}\t999000/abcdef01/4000\t{class}\t-\t200\t200\t{role}\t200\n"
            ),
        );
    };
    let alerts = || {
        let r = fx.run_env("pa_banner", &NOW);
        assert_eq!(r.code, 0, "{}", r.err);
        r.out
            .lines()
            .nth(1)
            .unwrap_or_default()
            .trim_start_matches("[propolis 13:46 UTC] ")
            .to_string()
    };
    for alert in [
        "PROPOLIS_OPS_NTFY_URL=https://other.invalid\n",
        "PROPOLIS_OPS_NTFY_URL=https://other.invalid\nPROPOLIS_OPS_NTFY_TOPIC=not a topic\n",
    ] {
        fx.write("etc/propolis/alert.env", alert);
        for role in ["both", "daemon"] {
            line("readable", role);
            assert_eq!(
                alerts(),
                "alerts: topic READABLE by anyone",
                "{alert} {role}"
            );
        }
        line("redirect", "both");
        assert_eq!(alerts(), "alerts: topic not proven private (redirect)");
        line("refused", "both");
        assert_eq!(
            alerts(),
            "alerts: no shell target; failure hook still posts"
        );
    }
    // Nothing that posts: the journal is where failure alerts go.
    fx.write("etc/propolis/propolis.env", "");
    assert_eq!(alerts(), "alerts: NO PUSH TARGET (journal only)");
}

/// The role's two questions wait for systemd as they always did, unless the caller says how long
/// it can: only the failure hook's v2 child, which has a time limit, bounds them, so a slow PID 1
/// cannot change the role the witness, the status command or config-check see.
#[test]
fn pa_role_bounds_its_questions_only_for_a_caller_that_says_how_long() {
    let fx = Fx::new();
    let calls = fx.p("timeout-calls");
    write_exec(
        &fx.bin.join("timeout"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> '{}'\nshift\nexec \"$@\"\n",
            calls.display()
        ),
    );
    let enabled = [("STUB_ENABLED", "propolis.service")];
    let r = fx.run_env("echo \"role=$(pa_role)\"", &enabled);
    assert_eq!(r.get("role"), "single", "{}", r.err);
    assert!(
        !calls.exists(),
        "{}",
        std::fs::read_to_string(&calls).unwrap_or_default()
    );
    let r = fx.run_env("echo \"role=$(PA_ROLE_WAIT=3 pa_role)\"", &enabled);
    assert_eq!(r.get("role"), "single", "{}", r.err);
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap(),
        "3 systemctl is-enabled --quiet propolis.service\n\
         3 systemctl is-enabled --quiet gateway.service\n"
    );
    // A wait that is not a plain count of seconds, or is 0 (which timeout reads as no limit), is
    // no wait; and one inherited from the environment is not the caller's: a shell that exported
    // it must not change how the witness or the status command ask.
    std::fs::remove_file(&calls).unwrap();
    for script in [
        "echo \"role=$(PA_ROLE_WAIT=3s pa_role)\"",
        "echo \"role=$(PA_ROLE_WAIT=0 pa_role)\"",
        "echo \"role=$(pa_role)\"",
    ] {
        let r = fx.run_env(
            script,
            &[("STUB_ENABLED", "propolis.service"), ("PA_ROLE_WAIT", "5")],
        );
        assert_eq!(r.get("role"), "single", "{script}: {}", r.err);
        assert!(
            !calls.exists(),
            "{script}: {}",
            std::fs::read_to_string(&calls).unwrap_or_default()
        );
    }
}

#[test]
fn pa_role_follows_which_units_are_enabled_and_whether_shipper_env_exists() {
    let fx = Fx::new();
    let role = |enabled: &str| {
        let r = fx.run_env("echo \"role=$(pa_role)\"", &[("STUB_ENABLED", enabled)]);
        assert_eq!(r.code, 0, "{}", r.err);
        r.get("role")
    };
    assert_eq!(role("propolis.service"), "single");
    assert_eq!(
        fx.log(),
        "systemctl is-enabled --quiet propolis.service\n\
         systemctl is-enabled --quiet gateway.service\n",
        "the role follows what is enabled, not what is running"
    );
    assert_eq!(role("propolis.service gateway.service"), "control");
    assert_eq!(role("gateway.service"), "gateway");
    assert_eq!(role(""), "unknown");
    fx.write(
        "etc/propolis/shipper.env",
        "PROPOLIS_SHIPPER_GATEWAY=gw:7000\n",
    );
    assert_eq!(role(""), "collector");
    assert_eq!(
        role("propolis.service"),
        "single",
        "the daemon makes it no collector"
    );
}

#[test]
fn pa_alias_refuses_the_hostname_propolis_honey_and_bad_shapes_and_its_fallback_never_uses_the_hostname()
 {
    let fx = Fx::salted(SALT);
    let alias = |set: &str| {
        let r = fx.run_env(
            "pa_alias > /dev/null\necho \"alias=$PA_ALIAS\"\necho \"rejected=$PA_ALIAS_REJECTED\"",
            &[("PA_ALIAS_SET", set)],
        );
        assert_eq!(r.code, 0, "{}", r.err);
        (r.get("alias"), r.get("rejected"))
    };
    let fallback = "host-908b";
    assert_eq!(alias(""), (fallback.to_string(), "0".to_string()));
    assert_eq!(
        alias("north-relay"),
        ("north-relay".to_string(), "0".to_string())
    );
    for refused in [
        "edge07",
        "edge07.lab.example",
        "my-propolis-1",
        "honeypot",
        "ab",
        "1abc",
        "Upper-case",
        "under_score",
        "a-very-long-alias-of-thirty-three",
        "caf\u{e9}-box",
    ] {
        let (got, rejected) = alias(refused);
        assert_eq!(got, fallback, "{refused:?} is refused");
        assert_eq!(rejected, "1", "{refused:?} is a rejected setting");
        assert!(!got.to_lowercase().contains("edge07"), "{got}");
    }

    let r = fx.run("echo \"printed=$(pa_alias)\"");
    assert_eq!(r.get("printed"), fallback);

    // The fallback follows the salt, not the host: another salt, another alias.
    let other = Fx::salted(OTHER_SALT);
    let r = other.run("echo \"printed=$(pa_alias)\"");
    assert_eq!(r.get("printed"), "host-5d62");

    // Without a salt there is no alias to print.
    let unsalted = Fx::new();
    let r = unsalted.run("rc=0; pa_alias > /dev/null || rc=$?; echo \"rc=$rc\"");
    assert_eq!(r.get("rc"), "1");

    // A full hostname with no dots passes the shape, so it is refused by name, as is the short
    // name it differs from.
    let dotless = Fx::salted(SALT);
    write_exec(
        &dotless.bin.join("hostname"),
        "#!/usr/bin/env bash\nif [ \"${1:-}\" = -s ]; then echo ebox; else echo EdgeBox; fi\n",
    );
    for set in ["edgebox", "ebox"] {
        let r = dotless.run_env(
            "pa_alias > /dev/null\necho \"alias=$PA_ALIAS\"\necho \"rejected=$PA_ALIAS_REJECTED\"",
            &[("PA_ALIAS_SET", set)],
        );
        assert_eq!(r.code, 0, "{}", r.err);
        assert_eq!(r.get("alias"), fallback, "{set:?} names the host");
        assert_eq!(r.get("rejected"), "1", "{set:?}");
    }
}

#[test]
fn pa_id_is_salted_and_five_hex_digits_behind_the_kind_prefix() {
    let ids = |fx: &Fx| {
        let r = fx.run(
            "for k in unit source collector vendor mount finding; do\n\
                 printf '%s=%s\\n' \"$k\" \"$(pa_id \"$k\" sensor-ssh.service)\"\n\
             done\n\
             echo \"ssh=$(pa_id source ssh)\"\n\
             rc=0; pa_id label x > /dev/null || rc=$?; echo \"badkind=$rc\"",
        );
        assert_eq!(r.code, 0, "{}", r.err);
        r
    };
    let r = ids(&Fx::salted(SALT));
    assert_eq!(r.get("unit"), "u80dd6");
    assert_eq!(r.get("ssh"), "s4ae9c");
    for (kind, prefix) in [
        ("unit", 'u'),
        ("source", 's'),
        ("collector", 'c'),
        ("vendor", 'v'),
        ("mount", 'm'),
        ("finding", 'f'),
    ] {
        let id = r.get(kind);
        assert_eq!(id.len(), 6, "{kind}: {id}");
        assert!(id.starts_with(prefix), "{kind}: {id}");
        assert!(
            id[1..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{kind}: {id}"
        );
    }
    assert_ne!(r.get("badkind"), "0");

    let other = ids(&Fx::salted(OTHER_SALT));
    assert_eq!(other.get("unit"), "u40f44", "another salt renames every id");

    let unsalted = Fx::new().run("rc=0; v=$(pa_id unit x) || rc=$?; echo \"rc=$rc v=$v\"");
    assert_eq!(unsalted.get("rc"), "1 v=-");
}

#[test]
fn pa_id_table_widens_two_ids_that_collide_within_one_kind_to_eight_hex_digits() {
    let fx = Fx::salted(SALT);
    // sensor-394.service and sensor-824.service share their first five hex digits under SALT.
    let r = fx.run(
        "printf 'unit\\tsensor-394.service\\nunit\\tsensor-824.service\\nunit\\tsensor-ssh.service\\n\
         source\\tssh\\nunit\\tsensor-ssh.service\\nlabel\\tignored\\n' | pa_id_table",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let rows: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        rows,
        [
            "ueddb2dc9\tunit\tsensor-394.service",
            "ueddb2ab6\tunit\tsensor-824.service",
            "u80dd6\tunit\tsensor-ssh.service",
            "s4ae9c\tsource\tssh",
        ],
        "{}",
        r.out
    );

    // sensor-2242.service (a unit) and label39 (a source) share their first five hex digits under
    // SALT, found by brute force over sha256(salt NUL kind NUL name). Their prefixes already tell
    // them apart, so neither is widened. The last row has no trailing newline and still counts.
    let r = fx.run(
        "printf 'unit\\tsensor-2242.service\\nunit\\tsensor-ssh.service\\nsource\\tlabel39' | pa_id_table",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let rows: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        rows,
        [
            "u8c9f9\tunit\tsensor-2242.service",
            "u80dd6\tunit\tsensor-ssh.service",
            "s8c9f9\tsource\tlabel39",
        ],
        "{}",
        r.out
    );
}

#[test]
fn pa_salt_ensure_creates_the_salt_once_with_mode_0600_and_never_replaces_it() {
    let fx = Fx::new();
    let r = fx.run("umask 022\npa_salt_ensure\necho rc=$?");
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let salt = fx.read("var/lib/propolis/witness/id-salt");
    let salt = salt.trim_end();
    assert_eq!(salt.len(), 32, "{salt}");
    assert!(salt.bytes().all(|b| b.is_ascii_hexdigit()), "{salt}");
    assert_eq!(mode_of(&fx.p("var/lib/propolis/witness/id-salt")), 0o600);
    let r = fx.run("pa_salt_ensure\necho rc=$?");
    assert_eq!(r.get("rc"), "0");
    assert_eq!(fx.read("var/lib/propolis/witness/id-salt").trim_end(), salt);
}

#[test]
fn pa_ref_is_six_random_hex_digits() {
    let fx = Fx::new();
    let r = fx.run("for i in 1 2 3; do echo \"ref$i=$(pa_ref)\"; done");
    assert_eq!(r.code, 0, "{}", r.err);
    let refs: Vec<String> = (1..=3).map(|i| r.get(&format!("ref{i}"))).collect();
    for r in &refs {
        assert_eq!(r.len(), 6, "{r}");
        assert!(r.bytes().all(|b| b.is_ascii_hexdigit()), "{r}");
    }
    assert!(
        !(refs[0] == refs[1] && refs[1] == refs[2]),
        "three draws from /dev/urandom are not all equal: {refs:?}"
    );
}

#[test]
fn pa_ok_field_pa_ok_line_and_pa_plain_id_accept_exactly_their_character_sets() {
    let fx = Fx::new();
    let script = format!(
        r#"t() {{ if "$1" "$2"; then echo "$3=yes"; else echo "$3=no"; fi; }}
t pa_ok_field 'unit:sensor-ssh.service' f-key
t pa_ok_field 'w#12' f-id
t pa_ok_field '1000/abcdef01/5' f-stamp
t pa_ok_field 'a,b%c=d+e@f' f-punct
t pa_ok_field '-' f-dash
t pa_ok_field '' f-empty
t pa_ok_field '{f128}' f-128
t pa_ok_field '{f128}x' f-129
t pa_ok_field 'a b' f-space
t pa_ok_field $'a\tb' f-tab
t pa_ok_field 'a;b' f-semicolon
t pa_ok_field $'a\e[1m' f-escape
t pa_ok_field $'a\xe2\x80\xaeb' f-bidi
t pa_ok_field $'a\xffb' f-byte
t pa_ok_line '' l-empty
t pa_ok_line 'unit u1a2b3 failed (3 restarts); see ~/x' l-text
t pa_ok_line '{l200}' l-200
t pa_ok_line '{l200}x' l-201
t pa_ok_line $'a\tb' l-tab
t pa_ok_line $'a\rb' l-cr
t pa_ok_line $'a\xe2\x80\xaeb' l-bidi
t pa_ok_line $'caf\xc3\xa9' l-latin
t pa_plain_id 'collector-01.lab' p-name
t pa_plain_id 'a_b-c.D9' p-chars
t pa_plain_id '' p-empty
t pa_plain_id '{p64}' p-64
t pa_plain_id '{p64}x' p-65
t pa_plain_id 'a/b' p-slash
t pa_plain_id 'a b' p-space
t pa_plain_id 'a:b' p-colon
t pa_plain_id $'a\xe2\x80\xaeb' p-bidi
"#,
        f128 = "f".repeat(128),
        l200 = "l".repeat(200),
        p64 = "p".repeat(64),
    );
    for locale in ["C", "C.UTF-8"] {
        let r = fx.run_env(&script, &[("LC_ALL", locale)]);
        assert_eq!(r.code, 0, "{}", r.err);
        for (label, want) in [
            ("f-key", "yes"),
            ("f-id", "yes"),
            ("f-stamp", "yes"),
            ("f-punct", "yes"),
            ("f-dash", "yes"),
            ("f-empty", "no"),
            ("f-128", "yes"),
            ("f-129", "no"),
            ("f-space", "no"),
            ("f-tab", "no"),
            ("f-semicolon", "no"),
            ("f-escape", "no"),
            ("f-bidi", "no"),
            ("f-byte", "no"),
            ("l-empty", "yes"),
            ("l-text", "yes"),
            ("l-200", "yes"),
            ("l-201", "no"),
            ("l-tab", "no"),
            ("l-cr", "no"),
            ("l-bidi", "no"),
            ("l-latin", "no"),
            ("p-name", "yes"),
            ("p-chars", "yes"),
            ("p-empty", "no"),
            ("p-64", "yes"),
            ("p-65", "no"),
            ("p-slash", "no"),
            ("p-space", "no"),
            ("p-colon", "no"),
            ("p-bidi", "no"),
        ] {
            assert_eq!(r.get(label), want, "{label} under LC_ALL={locale}");
        }
    }
}

#[test]
fn pa_clean_untrusted_replaces_control_and_non_ascii_bytes_cuts_lines_and_marks_each_one() {
    let fx = Fx::new();
    let r = fx.run_env(
        r#"printf 'ok line\n\033[31mred\r\nbidi \342\200\256 x\nlong-line-%s\nfifth line\n' "$(printf 'y%.0s' {1..50})" \
    | pa_clean_untrusted 20 4"#,
        &[("LC_ALL", "C.UTF-8")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines,
        [
            "[untrusted] ok line",
            "[untrusted] ?[31mred?",
            "[untrusted] bidi ??? x",
            "[untrusted] long-line-yyyyyyyyyy",
        ],
        "{:?}",
        r.out
    );

    // MAX and LINES are whole numbers from 1: anything else would reach cut or sed as a program.
    let r = fx.run(
        r#"for args in '0 4' 'x 4' "20 '1p;w $D/written'" "''"; do
    eval "set -- $args"
    rc=0; out=$(printf 'line\n' | pa_clean_untrusted "$@") || rc=$?
    echo "[$args]=$rc [$out]"
done
rc=0; out=$(printf 'line\n' | pa_clean_untrusted) || rc=$?
echo "none=$rc [$out]"
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    for label in ["[0 4]", "[x 4]", "['']", "none"] {
        assert_eq!(r.get(label), "2 []", "{label}");
    }
    let sed = r
        .out
        .lines()
        .find(|l| l.contains("1p;w"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(sed.ends_with("=2 []"), "{sed}");
    assert!(!fx.scratch().join("written").exists());
}

#[test]
fn pa_now_takes_all_three_test_values_together_or_reads_the_host() {
    let fx = Fx::new();
    let dump = "pa_now\necho \"stamp=$PA_STAMP\"\necho \"wall=$PA_WALL\"";
    let r = fx.run_env(dump, &NOW);
    assert_eq!(r.get("stamp"), "1000000/abcdef01/5000");

    // Two of the three are not the seam: the host's clock is read.
    let r = fx.run_env(
        dump,
        &[("PA_TEST_WALL", "1000000"), ("PA_TEST_BOOT", "abcdef01")],
    );
    assert_ne!(r.get("wall"), "1000000");
    let stamp = r.get("stamp");
    let parts: Vec<&str> = stamp.split('/').collect();
    assert_eq!(parts.len(), 3, "{stamp}");
    assert!(parts[0].parse::<u64>().unwrap() > 1_000_000, "{stamp}");
    assert!(
        parts[1] == "-" || (parts[1].len() == 8 && parts[1].bytes().all(|b| b.is_ascii_hexdigit())),
        "{stamp}"
    );
    assert!(parts[2].parse::<u64>().is_ok(), "{stamp}");
}

#[test]
fn pa_age_uses_uptime_within_a_boot_wall_time_across_boots_and_minus_one_otherwise() {
    let fx = Fx::new();
    let r = fx.run_env(
        r#"pa_now
a() { printf '%s=%s\n' "$1" "$(pa_age "$2")"; }
a same 999000/abcdef01/4000
a same-clock-stepped 1999000/abcdef01/4000
a other 990000/12345678/100
a other-future 2000000/12345678/1
a same-future 999000/abcdef01/6000
a unknown-boot 990000/-/100
a malformed x
a short-boot 1/abc/3
a empty ''
"#,
        &NOW,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("same"), "1000");
    assert_eq!(
        r.get("same-clock-stepped"),
        "1000",
        "within a boot a clock step changes nothing"
    );
    assert_eq!(r.get("other"), "10000");
    assert_eq!(r.get("other-future"), "-1");
    assert_eq!(r.get("same-future"), "-1");
    assert_eq!(r.get("unknown-boot"), "10000");
    assert_eq!(r.get("malformed"), "-1");
    assert_eq!(r.get("short-boot"), "-1");
    assert_eq!(r.get("empty"), "-1");

    // Leading zeros are decimal, never octal (8 and 9 are not octal digits).
    let r = fx.run_env(
        r#"pa_now
echo "same=$(pa_age 0999000/abcdef01/0900)"
echo "other=$(pa_age 0990000/12345678/0100)"
"#,
        &[
            ("PA_TEST_WALL", "01000000"),
            ("PA_TEST_BOOT", "abcdef01"),
            ("PA_TEST_UP", "05000"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("same"), "4100");
    assert_eq!(r.get("other"), "10000");

    // An unknown boot now and an unknown boot then are not the same boot.
    let r = fx.run_env(
        "pa_now\necho \"age=$(pa_age 990000/-/100)\"",
        &[
            ("PA_TEST_WALL", "1000000"),
            ("PA_TEST_BOOT", "-"),
            ("PA_TEST_UP", "5000"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("age"), "10000", "wall time, not uptime");
}

fn meta_value(meta: &str, key: &str) -> Option<String> {
    meta.lines().rev().find_map(|l| {
        let mut f = l.split('\t');
        (f.next() == Some("M") && f.next() == Some(key)).then(|| f.next().unwrap().to_string())
    })
}

#[test]
fn pa_clock_check_records_a_300_second_step_and_ignores_60_seconds() {
    let check = |fx: &Fx, wall: &str, up: &str| {
        let r = fx.run_env(
            ": > \"$PA_STATE/state.lock\"\npa_lock 5\npa_now\npa_clock_check\necho rc=$?\npa_unlock",
            &[
                ("PA_TEST_WALL", wall),
                ("PA_TEST_BOOT", "abcdef01"),
                ("PA_TEST_UP", up),
            ],
        );
        assert_eq!(r.get("rc"), "0", "{}", r.err);
        fx.read("var/lib/propolis/witness/meta")
    };

    let fx = Fx::new();
    let meta = check(&fx, "1000", "100");
    assert_eq!(
        meta_value(&meta, "clock").as_deref(),
        Some("1000/abcdef01/100")
    );
    assert_eq!(meta_value(&meta, "clock_step"), None);
    // 400 s of wall time in 100 s of uptime: the clock was stepped forward by 300 s.
    let meta = check(&fx, "1400", "200");
    assert_eq!(
        meta_value(&meta, "clock_step").as_deref(),
        Some("1400/abcdef01/200/+300")
    );
    assert_eq!(
        meta_value(&meta, "clock").as_deref(),
        Some("1400/abcdef01/200")
    );
    // And back by 300 s.
    let meta = check(&fx, "1200", "300");
    assert_eq!(
        meta_value(&meta, "clock_step").as_deref(),
        Some("1200/abcdef01/300/-300")
    );
    assert_eq!(
        meta.lines()
            .filter(|l| l.starts_with("M\tclock_step\t"))
            .count(),
        1,
        "one value per key: {meta}"
    );

    let fx = Fx::new();
    check(&fx, "1000", "100");
    let meta = check(&fx, "1160", "200");
    assert_eq!(
        meta_value(&meta, "clock_step"),
        None,
        "60 s is drift, not a step"
    );
    assert_eq!(
        meta_value(&meta, "clock").as_deref(),
        Some("1160/abcdef01/200")
    );
}

#[test]
fn pa_clock_check_compares_only_within_one_boot_and_steps_beyond_120_seconds() {
    let check = |fx: &Fx, wall: &str, boot: &str, up: &str| {
        let r = fx.run_env(
            ": > \"$PA_STATE/state.lock\"\npa_lock 5\npa_now\npa_clock_check\necho rc=$?\npa_unlock",
            &[
                ("PA_TEST_WALL", wall),
                ("PA_TEST_BOOT", boot),
                ("PA_TEST_UP", up),
            ],
        );
        assert_eq!(r.get("rc"), "0", "{}", r.err);
        let meta = fx.read("var/lib/propolis/witness/meta");
        (
            meta_value(&meta, "clock").unwrap_or_default(),
            meta_value(&meta, "clock_step"),
        )
    };

    // A reboot restarts uptime: 600 s of wall time against 30 s of uptime is not a step.
    let fx = Fx::new();
    check(&fx, "1000", "abcdef01", "100");
    assert_eq!(
        check(&fx, "1600", "12345678", "30"),
        ("1600/12345678/30".to_string(), None),
        "another boot"
    );

    // Within one boot: more than 120 s is a step, 120 s is not.
    for (wall, step) in [
        ("1221", Some("+121")),
        ("1220", None),
        ("979", Some("-121")),
    ] {
        let fx = Fx::new();
        check(&fx, "1000", "abcdef01", "100");
        let (clock, got) = check(&fx, wall, "abcdef01", "200");
        assert_eq!(clock, format!("{wall}/abcdef01/200"));
        assert_eq!(
            got,
            step.map(|s| format!("{wall}/abcdef01/200/{s}")),
            "wall {wall}"
        );
    }

    // An unknown boot matches nothing, not even another unknown boot.
    let fx = Fx::new();
    check(&fx, "1000", "-", "100");
    assert_eq!(
        check(&fx, "1400", "-", "200"),
        ("1400/-/200".to_string(), None)
    );

    // Leading zeros in the stored clock and the time now are decimal.
    let fx = Fx::new();
    check(&fx, "0999000", "abcdef01", "0900");
    assert_eq!(
        check(&fx, "01000000", "abcdef01", "01100").1.as_deref(),
        Some("01000000/abcdef01/01100/+800")
    );
}

#[test]
fn pa_hms_prints_utc_whatever_the_time_zone_and_pa_dur_prints_minutes_hours_or_days() {
    let fx = Fx::new();
    let r = fx.run_env(
        r#"echo "hms=$(pa_hms 3661)"
echo "bad=$(pa_hms x)"
for s in 0 59 2640 3600 9060 86399 259200 -5; do echo "dur$s=$(pa_dur "$s")"; done
"#,
        // A POSIX zone string needs no tzdata, so the zone applies on any host.
        &[("TZ", "JST-9")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("hms"), "01:01:01");
    assert_eq!(r.get("bad"), "?");
    assert_eq!(r.get("dur0"), "0 min");
    assert_eq!(r.get("dur59"), "0 min");
    assert_eq!(r.get("dur2640"), "44 min");
    assert_eq!(r.get("dur3600"), "1 h");
    assert_eq!(r.get("dur9060"), "2 h 31 min");
    assert_eq!(r.get("dur86399"), "23 h 59 min");
    assert_eq!(r.get("dur259200"), "3 d");
    assert_eq!(r.get("dur-5"), "?");
}

#[test]
fn pa_read_as_refuses_a_fifo_and_a_link_and_an_oversized_file() {
    let fx = Fx::new();
    let r = fx.run_env(
        r#"printf 'hello world' > "$D/f"
mkfifo "$D/fifo"
ln -s "$D/f" "$D/link"
me=$(id -un)
r() { local rc=0 out; out=$(pa_read_as "$me" "$1" "$2") || rc=$?; printf '%s=%s [%s]\n' "$3" "$rc" "$out"; }
r "$D/f" 100 whole
r "$D/f" 11 exact
r "$D/f" 10 oversized
r "$D/fifo" 100 fifo
r "$D/link" 100 link
r "$D/fifo" 0 fifo-test
r "$D/missing" 100 missing
r "$D/f" x badmax
: > "$D/empty"
r "$D/empty" 100 empty
r "$D/empty" 0 empty-test
"#,
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("empty"), "0 []", "an empty file is a regular file");
    assert_eq!(
        r.get("empty-test"),
        "0 []",
        "an empty file the reader can open is readable"
    );
    assert_eq!(r.get("whole"), "0 [hello world]");
    assert_eq!(r.get("exact"), "0 [hello world]");
    assert_eq!(r.get("oversized"), "4 []");
    assert_eq!(r.get("fifo"), "3 []");
    assert_eq!(r.get("link"), "3 []");
    assert_eq!(r.get("fifo-test"), "3 []");
    assert_eq!(r.get("missing"), "3 []");
    assert_eq!(r.get("badmax"), "1 []");
}

#[test]
fn pa_read_as_returns_5_when_a_fifo_is_swapped_in_after_the_check() {
    let fx = Fx::new();
    let swap_bin = fx.dir.path().join("swap-bin");
    write_exec(&swap_bin.join("stat"), STAT_SWAP_STUB);
    let r = fx.run_env(
        &format!(
            r#"printf 'hello' > "$D/f"
export PATH="{}:$PATH"
rc=0; pa_read_as "$(id -un)" "$D/f" 100 > /dev/null || rc=$?
echo "rc=$rc"
[ -p "$D/f" ] && echo swapped=yes
"#,
            swap_bin.display()
        ),
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.get("swapped"), "yes", "{}", r.err);
    assert_eq!(
        r.get("rc"),
        "5",
        "a FIFO that blocks the read ends at the timeout"
    );
}

#[test]
fn pa_read_as_with_max_zero_opens_the_file_as_the_reader() {
    // As root the read drops to `nobody` with the real setpriv, so the scratch directory must be
    // one `nobody` can reach: directly under /tmp, whatever TMPDIR says, then opened to 0755. As
    // another user it reads as that user.
    let fx = Fx::in_tmp();
    for d in [fx.dir.path().to_path_buf(), fx.scratch()] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let d = fx.scratch();
    if is_root() {
        // The account's own groups, as the library's drop takes them: its primary group is
        // `nogroup` on Debian and `nobody` on Fedora.
        let reach = Command::new("setpriv")
            .args(["--reuid=nobody", "--init-groups", "test", "-x"])
            .arg(&d)
            .status();
        if !matches!(reach, Ok(s) if s.success()) {
            eprintln!(
                "skipped: nobody cannot reach {} on this host ({reach:?})",
                d.display()
            );
            return;
        }
    }
    std::fs::write(d.join("readable"), "x").unwrap();
    std::fs::set_permissions(d.join("readable"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(d.join("closed"), "x").unwrap();
    std::fs::set_permissions(d.join("closed"), std::fs::Permissions::from_mode(0o000)).unwrap();
    // A readable file in a directory the reader cannot enter: what a reader that lost the
    // supplementary group of a 0750 sensor log directory meets.
    std::fs::create_dir_all(d.join("locked")).unwrap();
    std::fs::write(d.join("locked/inner"), "x").unwrap();
    std::fs::set_permissions(
        d.join("locked/inner"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(d.join("locked"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let r = if is_root() {
        fx.run(
            r#"r() { local rc=0 out; out=$(pa_read_as nobody "$1" "$2") || rc=$?; printf '%s=%s [%s]\n' "$3" "$rc" "$out"; }
r "$D/readable" 0 readable
r "$D/closed" 0 closed
r "$D/locked/inner" 0 locked-test
r "$D/locked/inner" 100 locked-read
r "$D/locked/missing" 0 locked-missing
"#,
        )
    } else {
        // The caller's own check needs the directory open, so the setpriv stub closes it after
        // that check and before the reader runs.
        write_exec(&fx.bin.join("setpriv"), SETPRIV_CLOSING_STUB);
        fx.run_env(
            r#"r() {
    local rc=0 out
    out=$(CLOSE_DIR="${4:-}" pa_read_as "$(id -un)" "$1" "$2") || rc=$?
    chmod 0700 "$D/locked"
    printf '%s=%s [%s]\n' "$3" "$rc" "$out"
}
r "$D/readable" 0 readable
r "$D/closed" 0 closed
r "$D/locked/inner" 0 locked-test "$D/locked"
r "$D/locked/inner" 100 locked-read "$D/locked"
r "$D/locked/missing" 0 locked-missing
"#,
            &[("PA_TEST_UID", "0")],
        )
    };
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("readable"), "0 []");
    assert_eq!(
        r.get("closed"),
        "6 []",
        "a mode-0000 file is not readable by the reader"
    );
    assert_eq!(
        r.get("locked-test"),
        "6 []",
        "a regular file the reader cannot reach is unreadable, not a planted link"
    );
    assert_eq!(r.get("locked-read"), "1 []");
    assert_eq!(
        r.get("locked-missing"),
        "3 []",
        "a missing file is still not a regular file"
    );
}

#[test]
fn the_drop_to_another_account_keeps_its_groups_and_closes_the_lock_descriptor() {
    let source = std::fs::read_to_string(LIB).unwrap();
    let setpriv: Vec<&str> = source
        .lines()
        .filter(|l| l.contains("setpriv ") && !l.trim_start().starts_with('#'))
        .collect();
    assert!(
        !setpriv.is_empty(),
        "the library drops privileges with setpriv"
    );
    for line in &setpriv {
        assert!(line.contains("--init-groups"), "{line}");
        assert!(line.contains("--no-new-privs"), "{line}");
    }
    assert!(
        !source.contains("--clear-groups"),
        "clearing the groups would make every sensor log unreadable to the drop"
    );
    assert!(
        source.contains("{PA_LOCK_FD}>&-"),
        "the child closes the lock"
    );

    // The effective uid comes from the PA_TEST_UID seam under a test root, so the drop runs the
    // same way whether the test runs as root or not; `id` answers 4242 and 4343 for the reader.
    let fx = Fx::new();
    write_exec(&fx.bin.join("setpriv"), SETPRIV_STUB);
    write_exec(&fx.bin.join("stat"), STAT_FD_STUB);
    write_exec(&fx.bin.join("id"), ID_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let file = fx.scratch().join("f");
    let r = fx.run_env(
        r#"printf 'hello' > "$D/f"
pa_lock 5
export LOCKFD="$PA_LOCK_FD"
stat -c %s -- "$D/f" > /dev/null
echo control-done=yes
rc=0; out=$(pa_read_as reader "$D/f" 100) || rc=$?
echo "read=$rc [$out]"
pa_unlock
"#,
        &[("PA_TEST_UID", "0")],
    );
    assert_eq!(r.get("control-done"), "yes", "{}", r.err);
    assert_eq!(r.get("read"), "0 [hello]", "{}", r.err);
    let log = fx.log();
    let fd_lines: Vec<&str> = log.lines().filter(|l| l.starts_with("fd ")).collect();
    assert_eq!(
        fd_lines,
        ["fd open", "fd closed"],
        "the caller holds the lock and the reading child does not: {log}"
    );
    assert_eq!(
        log.matches("setpriv ").count(),
        1,
        "one drop for one read: {log}"
    );
    let drop = &log[log.find("setpriv ").unwrap()..];
    assert!(
        drop.starts_with(
            "setpriv --reuid=4242 --regid=4343 --init-groups --no-new-privs -- bash -c "
        ),
        "{log}"
    );
    assert!(
        drop.contains(&format!(" _ {} 100\nfd closed\n", file.display())),
        "the program's arguments are the file and the cap: {log}"
    );

    // Any other uid reads as the caller, and so does PA_TEST_READ_AS_SELF=1.
    for env in [
        vec![("PA_TEST_UID", "1000")],
        vec![("PA_TEST_UID", "0"), ("PA_TEST_READ_AS_SELF", "1")],
    ] {
        std::fs::write(&fx.log, b"").unwrap();
        let r = fx.run_env(
            "rc=0; out=$(pa_read_as reader \"$D/f\" 100) || rc=$?\necho \"read=$rc [$out]\"",
            &env,
        );
        assert_eq!(r.get("read"), "0 [hello]", "{env:?}: {}", r.err);
        assert!(!fx.log().contains("setpriv"), "{env:?}: {}", fx.log());
    }

    // Without a test root the seam is ignored and the real uid decides.
    std::fs::write(&fx.log, b"").unwrap();
    let fake = if is_root() { "1000" } else { "0" };
    let r = fx.run_raw(
        "source \"$LIB\"\npa_init \"\"\n\
         rc=0; out=$(pa_read_as \"$(id -un)\" \"$D/f\" 100) || rc=$?\necho \"read=$rc [$out]\"",
        &[("PA_TEST_UID", fake)],
    );
    assert_eq!(r.get("read"), "0 [hello]", "{}", r.err);
    assert_eq!(
        fx.log().contains("setpriv "),
        is_root(),
        "PA_TEST_UID={fake} without a root: {}",
        fx.log()
    );
}

#[test]
fn the_child_run_as_another_account_inherits_no_descriptor_and_no_terminal() {
    let fx = Fx::new();
    let swap_bin = fx.dir.path().join("inherit-bin");
    write_exec(&swap_bin.join("stat"), STAT_INHERIT_STUB);
    let r = fx.run_env(
        &format!(
            r#"printf 'hello' > "$D/f"
export PATH="{}:$PATH"
exec 7< "$D/f"
exec 0< "$D/f"
[ -e /proc/self/fd/7 ] && echo caller7=open
rc=0; pa_stat_as "$(id -un)" %s "$D/f" > /dev/null || rc=$?
echo "rc=$rc"
"#,
            swap_bin.display()
        ),
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.get("caller7"), "open", "{}", r.err);
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(
        fx.log(),
        "fd7 closed\nfd0 /dev/null\nfd2 /dev/null\n",
        "the child gets only stdout from the caller"
    );
}

#[test]
fn pa_stat_as_returns_5_when_stat_outlives_the_timeout() {
    let fx = Fx::new();
    let slow_bin = fx.dir.path().join("slow-bin");
    write_exec(&slow_bin.join("stat"), STAT_SLOW_STUB);
    let r = fx.run_env(
        &format!(
            "export PATH=\"{}:$PATH\"\nrc=0; pa_stat_as \"$(id -un)\" %s \"$D\" > /dev/null || rc=$?\necho \"rc=$rc\"",
            slow_bin.display()
        ),
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.get("rc"), "5", "{}", r.err);
}

#[test]
fn pa_stat_as_does_not_follow_a_link() {
    let fx = Fx::new();
    let r = fx.run_env(
        r#"printf 'hello' > "$D/f"
ln -s "$D/f" "$D/link"
echo "file=$(pa_stat_as "$(id -un)" %F "$D/f")"
echo "link=$(pa_stat_as "$(id -un)" %F "$D/link")"
echo "size=$(pa_stat_as "$(id -un)" %s "$D/f")"
"#,
        &[("PA_TEST_READ_AS_SELF", "1")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("file"), "regular file");
    assert_eq!(r.get("link"), "symbolic link");
    assert_eq!(r.get("size"), "5");
}

#[test]
fn pa_trusted_exec_fails_on_a_group_writable_parent_and_names_it() {
    let fx = Fx::new();
    fx.write("usr/local/bin/propolis", "#!/bin/sh\n");
    for (rel, mode) in [
        ("usr", 0o755),
        ("usr/local", 0o755),
        ("usr/local/bin", 0o755),
        ("usr/local/bin/propolis", 0o755),
    ] {
        std::fs::set_permissions(fx.p(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(fx.p("usr/local/bin/propolis"), fx.p("usr/local/bin/linked"))
        .unwrap();
    let check = |rel: &str| {
        let r = fx.run(&format!(
            "rc=0; pa_trusted_exec \"$ROOT/{rel}\" || rc=$?\necho \"rc=$rc\"\necho \"why=$PA_UNTRUSTED\""
        ));
        assert_eq!(r.code, 0, "{}", r.err);
        (r.get("rc"), r.get("why"))
    };
    let real_root = fx.root.canonicalize().unwrap().display().to_string();

    assert_eq!(
        check("usr/local/bin/propolis"),
        ("0".to_string(), String::new())
    );

    let (rc, why) = check("usr/local/bin/linked");
    assert_eq!(rc, "1");
    assert!(
        why.ends_with("usr/local/bin/linked: a symbolic link"),
        "{why}"
    );

    let (rc, why) = check("usr/local/bin/missing");
    assert_eq!(rc, "1");
    assert!(
        why.ends_with("usr/local/bin/missing: not a regular file"),
        "{why}"
    );

    std::fs::set_permissions(fx.p("usr/local"), std::fs::Permissions::from_mode(0o775)).unwrap();
    let (rc, why) = check("usr/local/bin/propolis");
    assert_eq!(rc, "1");
    assert!(
        why.starts_with(&format!("{real_root}/usr/local: group-writable (")),
        "{why}"
    );
    assert!(why.ends_with(" 775)"), "{why}");

    // The directory the walk starts in is checked like the ones below it, and comes first.
    std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o775)).unwrap();
    let (rc, why) = check("usr/local/bin/propolis");
    assert_eq!(rc, "1");
    assert!(
        why.starts_with(&format!("{real_root}: group-writable (")),
        "{why}"
    );
    std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o755)).unwrap();

    std::fs::set_permissions(fx.p("usr/local"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(
        fx.p("usr/local/bin/propolis"),
        std::fs::Permissions::from_mode(0o757),
    )
    .unwrap();
    let (rc, why) = check("usr/local/bin/propolis");
    assert_eq!(rc, "1");
    assert!(
        why.starts_with(&format!(
            "{real_root}/usr/local/bin/propolis: world-writable ("
        )),
        "{why}"
    );
    std::fs::set_permissions(
        fx.p("usr/local/bin/propolis"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // A link among the directories: whoever can write the directory that holds it can point it
    // elsewhere after the check, so that directory is checked too.
    for (dir, mode) in [("opt", 0o775), ("srv", 0o755)] {
        std::fs::create_dir_all(fx.p(dir)).unwrap();
        std::fs::set_permissions(fx.p(dir), std::fs::Permissions::from_mode(mode)).unwrap();
        std::os::unix::fs::symlink("../usr/local/bin", fx.p(&format!("{dir}/tools"))).unwrap();
    }
    let (rc, why) = check("opt/tools/propolis");
    assert_eq!(rc, "1", "{why}");
    assert!(
        why.starts_with(&format!("{real_root}/opt: group-writable (")),
        "{why}"
    );
    assert_eq!(
        check("srv/tools/propolis"),
        ("0".to_string(), String::new()),
        "a link held by a trusted directory is trusted"
    );

    // A link whose target leads through another link: the directory holding that second link is
    // on the way too, whichever path names the file.
    for (dir, mode) in [("chain", 0o755), ("loose", 0o775)] {
        std::fs::create_dir_all(fx.p(dir)).unwrap();
        std::fs::set_permissions(fx.p(dir), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::os::unix::fs::symlink("../usr/local/bin", fx.p("loose/b")).unwrap();
    std::os::unix::fs::symlink("../loose/b", fx.p("chain/tools")).unwrap();
    for rel in ["chain/tools/propolis", "loose/b/propolis"] {
        let (rc, why) = check(rel);
        assert_eq!(rc, "1", "{rel}: {why}");
        assert!(
            why.starts_with(&format!("{real_root}/loose: group-writable (")),
            "{rel}: {why}"
        );
    }
    // The same chain through trusted directories passes, with a relative or an absolute target.
    std::os::unix::fs::symlink("../srv/tools", fx.p("chain/again")).unwrap();
    std::os::unix::fs::symlink(fx.p("srv/tools"), fx.p("chain/absolute")).unwrap();
    std::os::unix::fs::symlink("../usr/./local//bin/", fx.p("chain/untidy")).unwrap();
    for rel in [
        "chain/again/propolis",
        "chain/absolute/propolis",
        "chain/untidy/propolis",
        "chain/../usr/local/bin/propolis",
    ] {
        assert_eq!(check(rel), ("0".to_string(), String::new()), "{rel}");
    }
    // The file reached through a trusted link is still refused when it is itself a link.
    let (rc, why) = check("srv/tools/linked");
    assert_eq!(rc, "1");
    assert!(why.ends_with("srv/tools/linked: a symbolic link"), "{why}");

    // Ownership. Under a test root that root's owner stands for root. For another user the
    // foreign directory is one outside the root that root owns; for root it is one handed to
    // another account. The file outside the root is /etc/passwd, a regular file on every host:
    // /usr/bin/env is a link to a multi-call binary on some distributions.
    std::os::unix::fs::symlink("/etc", fx.p("chain/sys")).unwrap();
    let (rc, why) = check("chain/sys/passwd");
    if is_root() {
        assert_eq!((rc.as_str(), why.as_str()), ("0", ""));
        std::os::unix::fs::chown(fx.p("usr/local"), Some(65534), None).unwrap();
        let (rc, why) = check("usr/local/bin/propolis");
        assert_eq!(rc, "1");
        assert!(
            why.starts_with(&format!("{real_root}/usr/local: not owned by root (")),
            "{why}"
        );
    } else {
        assert_eq!(rc, "1");
        assert!(
            why.starts_with("/etc: not owned by root (root:root "),
            "{why}"
        );
    }
}

#[test]
fn pa_trusted_exec_walks_to_the_real_root_when_no_test_root_is_given() {
    let fx = Fx::in_tmp();
    std::fs::set_permissions(fx.scratch(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(fx.scratch().join("tool"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        fx.scratch().join("tool"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let check = |path: &str| {
        let r = fx.run_raw(
            &format!(
                "timeout 5 bash -c 'source \"$LIB\"; pa_init \"\"; rc=0; pa_trusted_exec \"$1\" || rc=$?; \
                 echo \"rc=$rc\"; echo \"why=$PA_UNTRUSTED\"' _ {path}"
            ),
            &[],
        );
        assert_eq!(r.code, 0, "the walk ends at /: {}", r.err);
        (r.get("rc"), r.get("why"))
    };
    // A file root owns under directories root owns, and a regular file on every host (a program
    // such as /usr/bin/env is a link on some distributions, and a link is refused).
    assert_eq!(check("/etc/passwd"), ("0".to_string(), String::new()));
    // The walk goes down from /, so /tmp is the first directory that fails, for root and for any
    // other user alike.
    let (rc, why) = check("\"$D/tool\"");
    assert_eq!(rc, "1", "{why}");
    assert_eq!(why, "/tmp: group-writable (root:root 1777)");
}

#[test]
fn pa_write_leaves_no_temporary_file_on_failure_and_writes_mode_0600_whatever_the_umask() {
    let fx = Fx::new();
    let state = fx.p("var/lib/propolis/witness");
    std::fs::write(state.join("observe"), "old\n").unwrap();
    std::fs::set_permissions(
        state.join("observe"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    // A non-empty directory where the file should be: the rename fails after the temporary
    // file was written.
    std::fs::create_dir_all(state.join("meta/blocker")).unwrap();
    let r = fx.run(
        r#"umask 000
rc=0; printf 'x\n' | pa_write "$PA_STATE/meta" || rc=$?
echo "failed=$rc"
rc=0; printf 'new\n' | pa_write "$PA_STATE/observe" || rc=$?
echo "replaced=$rc"
rc=0; printf 'fresh\n' | pa_write "$PA_STATE/testpage" || rc=$?
echo "created=$rc"
rc=0; printf 'x\n' | pa_write "$PA_STATE/no-such-dir/meta" || rc=$?
echo "nodir=$rc"
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("failed"), "1");
    assert_eq!(r.get("replaced"), "0");
    assert_eq!(r.get("created"), "0");
    assert_eq!(r.get("nodir"), "1");
    let leftovers: Vec<String> = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(fx.read("var/lib/propolis/witness/observe"), "new\n");
    assert_eq!(mode_of(&state.join("observe")), 0o600);
    assert_eq!(mode_of(&state.join("testpage")), 0o600);
}

#[test]
fn pa_write_flushes_the_temporary_file_before_the_rename_and_a_failed_flush_keeps_the_old_file() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("sync"), SYNC_STUB);
    let state = fx.p("var/lib/propolis/witness");
    let observe = state.join("observe");
    std::fs::write(&observe, "old\n").unwrap();
    let script = "echo \"pid=$$\"\nrc=0; printf 'new\\n' | pa_write \"$PA_STATE/observe\" || rc=$?\necho \"rc=$rc\"";
    let final_path = observe.to_str().unwrap();

    let r = fx.run_env(script, &[("FINAL", final_path)]);
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let pid = r.get("pid");
    assert_eq!(
        fx.log(),
        format!(
            "sync -- {o}.tmp.{pid} final=old \nsync -- {s} final=new \n",
            o = observe.display(),
            s = state.display()
        ),
        "the new content is on disk before the rename publishes it, and the rename after"
    );
    assert_eq!(fx.read("var/lib/propolis/witness/observe"), "new\n");

    std::fs::write(&fx.log, b"").unwrap();
    let r = fx.run_env(script, &[("FINAL", final_path), ("SYNC_RC", "1")]);
    assert_eq!(r.get("rc"), "1", "{}", r.err);
    assert_eq!(fx.log().lines().count(), 1, "{}", fx.log());
    assert_eq!(
        fx.read("var/lib/propolis/witness/observe"),
        "new\n",
        "a write that could not be flushed is not published"
    );
    let leftovers: Vec<String> = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_state_write_larger_than_readers_accept_fails_and_keeps_the_old_file() {
    let fx = Fx::new();
    let old = write_incidents(&fx, &i_line(0, "open", None));
    let mut body = String::from("N\t4000\n");
    let mut n = 1;
    while body.len() <= 1_048_576 {
        body.push_str(&i_line(n, "open", None));
        n += 1;
    }
    std::fs::write(fx.scratch().join("big.body"), &body).unwrap();
    let r = fx.run(
        ": > \"$PA_STATE/state.lock\"\npa_lock 5\n\
         rc=0; pa_state_write incidents < \"$D/big.body\" || rc=$?\necho \"rc=$rc where=$PA_WHERE\"\n\
         pa_state_read incidents > \"$D/read.out\"\npa_unlock",
    );
    assert_eq!(
        r.get("rc"),
        "1 where=none",
        "open records alone over 1 MiB cannot be trimmed, so the write fails: {}",
        r.err
    );
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), old);
    assert_eq!(
        std::fs::read_to_string(fx.scratch().join("read.out")).unwrap(),
        i_line(0, "open", None),
        "the old file is still read"
    );
    let names: Vec<String> = std::fs::read_dir(fx.p("var/lib/propolis/witness"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".unreadable.") || n.contains(".tmp."))
        .collect();
    assert!(names.is_empty(), "{names:?}");
    assert!(!fx.p("run/propolis-witness/fallback/incidents").exists());
}

/// A stamp at `wall`.
fn stamp(wall: u64) -> String {
    format!("{wall}/abcdef01/5")
}

/// One `I` line with all 34 fields, about 330 bytes.
fn i_line(n: usize, state: &str, resolved: Option<u64>) -> String {
    let resolved = resolved.map(stamp).unwrap_or_else(|| "-".to_string());
    let key = format!("unit:sensor-{n:05}-{}.service", "k".repeat(100));
    let first = stamp(1000);
    let fields: Vec<String> = [
        format!("w#{n}"),
        key,
        "unit-failed".into(),
        "listen".into(),
        "u12345".into(),
        "PAGE".into(),
        state.into(),
        first.clone(),
        first.clone(),
        first.clone(),
        "proc.exit".into(),
        first.clone(),
        "-".into(),
        "1".into(),
        first.clone(),
        "open".into(),
        "1".into(),
        "0".into(),
        "-".into(),
        "-".into(),
        resolved,
        "-".into(),
        "0".into(),
        "-".into(),
        "-".into(),
        "-".into(),
        "-".into(),
        "-".into(),
        "0".into(),
        "-".into(),
        "1".into(),
        "-".into(),
        "-".into(),
        "-".into(),
    ]
    .into();
    assert_eq!(fields.len(), 34);
    format!("I\t{}\n", fields.join("\t"))
}

/// One `W` line withheld at `wall`, about 200 bytes.
fn w_line(wall: u64) -> String {
    format!(
        "W\t{}\tabcd1234\topen\t1\tu12345\tbudget-{wall}-{}\n",
        stamp(wall),
        "r".repeat(150)
    )
}

/// Writes `body` as `incidents` through `pa_state_write` and returns what landed on disk.
fn write_incidents(fx: &Fx, body: &str) -> String {
    write_incidents_after(fx, "", body)
}

/// `write_incidents`, with `prelude` run after `pa_init` and before the write.
fn write_incidents_after(fx: &Fx, prelude: &str, body: &str) -> String {
    std::fs::write(fx.scratch().join("incidents.body"), body).unwrap();
    let r = fx.run(&format!(
        "{prelude}\n: > \"$PA_STATE/state.lock\"\npa_lock 5\n\
         pa_state_write incidents < \"$D/incidents.body\"\necho \"rc=$? where=$PA_WHERE\"\npa_unlock"
    ));
    assert_eq!(r.get("rc"), "0 where=persistent", "{}", r.err);
    fx.read("var/lib/propolis/witness/incidents")
}

fn ids_in(text: &str, state: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.starts_with("I\t"))
        .filter(|l| l.split('\t').nth(7) == Some(state))
        .map(|l| l.split('\t').nth(1).unwrap().to_string())
        .collect()
}

/// The length, newline included, of the longest line of `body` that `written` lost.
fn longest_dropped(body: &str, written: &str) -> usize {
    let kept: std::collections::HashSet<&str> = written.lines().collect();
    body.lines()
        .filter(|l| !kept.contains(l))
        .map(|l| l.len() + 1)
        .max()
        .expect("some line was dropped")
}

fn w_walls(text: &str) -> Vec<u64> {
    text.lines()
        .filter(|l| l.starts_with("W\t"))
        .map(|l| {
            l.split('\t')
                .nth(1)
                .unwrap()
                .split('/')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect()
}

#[test]
fn incidents_written_past_192_kib_lose_withheld_lines_oldest_first_before_any_record() {
    let fx = Fx::new();
    let mut body = String::from("N\t40\n");
    for n in 0..20 {
        body.push_str(&i_line(n, "resolved", Some(5000 + n as u64)));
    }
    for n in 20..25 {
        body.push_str(&i_line(n, "open", None));
    }
    body.push_str(&i_line(25, "pending", None));
    // Newest first in the file, so file order and age order disagree.
    for wall in (2000..3000u64).rev() {
        body.push_str(&w_line(wall));
    }
    assert!(body.len() > INCIDENTS_MAX + 4096, "{}", body.len());
    // A umask set after pa_init does not reach the trimmed file.
    let written = write_incidents_after(&fx, "umask 022", &body);
    assert_eq!(mode_of(&fx.p("var/lib/propolis/witness/incidents")), 0o600);
    assert!(written.len() <= INCIDENTS_MAX, "{}", written.len());
    assert!(
        written.len() > INCIDENTS_MAX - longest_dropped(&body, &written),
        "the trim stops as soon as the file fits: {}",
        written.len()
    );
    assert!(
        written.starts_with("#incidents v1 g=1\nN\t40\n"),
        "{}",
        &written[..40]
    );
    assert_eq!(
        ids_in(&written, "resolved").len(),
        20,
        "no record goes while W lines remain"
    );
    assert_eq!(ids_in(&written, "open").len(), 5);
    assert_eq!(ids_in(&written, "pending").len(), 1);
    let walls = w_walls(&written);
    assert!(!walls.is_empty() && walls.len() < 1000, "{}", walls.len());
    let oldest_kept = *walls.iter().min().unwrap();
    assert_eq!(
        walls.len() as u64,
        3000 - oldest_kept,
        "exactly the oldest W lines went"
    );
    assert!(walls.contains(&2999));
    assert_eq!(walls.first(), Some(&2999), "the survivors keep their order");
}

#[test]
fn incidents_trimmed_past_the_withheld_lines_lose_resolved_records_oldest_first_and_never_an_open_one()
 {
    let fx = Fx::new();
    let mut body = String::from("N\t900\n");
    for wall in 2000..2200u64 {
        body.push_str(&w_line(wall));
    }
    // Resolved records in an order unrelated to their resolve times.
    for n in 0..700 {
        let resolved = 10_000 + ((n * 389) % 700) as u64;
        body.push_str(&i_line(n, "resolved", Some(resolved)));
    }
    for n in 700..710 {
        body.push_str(&i_line(n, "open", None));
    }
    for n in 710..715 {
        body.push_str(&i_line(n, "pending", None));
    }
    for n in 715..718 {
        body.push_str(&i_line(n, "acked", None));
    }
    assert!(body.len() > INCIDENTS_MAX + 40_000, "{}", body.len());
    let written = write_incidents(&fx, &body);
    assert!(written.len() <= INCIDENTS_MAX, "{}", written.len());
    assert!(
        written.len() > INCIDENTS_MAX - longest_dropped(&body, &written),
        "the trim stops as soon as the file fits: {}",
        written.len()
    );
    assert!(w_walls(&written).is_empty(), "every W line goes first");
    assert_eq!(ids_in(&written, "open").len(), 10);
    assert_eq!(ids_in(&written, "pending").len(), 5);
    assert_eq!(ids_in(&written, "acked").len(), 3);
    let resolved_walls: Vec<u64> = written
        .lines()
        .filter(|l| l.starts_with("I\t") && l.split('\t').nth(7) == Some("resolved"))
        .map(|l| {
            l.split('\t')
                .nth(21)
                .unwrap()
                .split('/')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    assert!(
        !resolved_walls.is_empty() && resolved_walls.len() < 700,
        "{}",
        resolved_walls.len()
    );
    let oldest_kept = *resolved_walls.iter().min().unwrap();
    assert_eq!(
        resolved_walls.len() as u64,
        10_700 - oldest_kept,
        "exactly the records resolved longest ago went"
    );

    // Open records alone over the limit are written whole: they are never trimmed.
    let fx = Fx::new();
    let mut body = String::from("N\t700\n");
    for n in 0..700 {
        body.push_str(&i_line(n, "open", None));
    }
    assert!(body.len() > INCIDENTS_MAX);
    let written = write_incidents(&fx, &body);
    assert_eq!(ids_in(&written, "open").len(), 700);

    // A file under the limit is written byte for byte, withheld and resolved lines included.
    let fx = Fx::new();
    let mut body = String::from("N\t400\n");
    let mut n = 0;
    while body.len() < 150 * 1024 {
        body.push_str(&w_line(2000 + n as u64));
        body.push_str(&i_line(n, "resolved", Some(9000 + n as u64)));
        n += 1;
    }
    assert!(body.len() < INCIDENTS_MAX - 1024);
    let written = write_incidents(&fx, &body);
    assert_eq!(written, format!("#incidents v1 g=1\n{body}"));
}

#[test]
fn pa_lock_times_out_while_another_process_holds_the_lock() {
    let fx = Fx::new();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run(
        r#"flock -n "$PA_STATE/state.lock" bash -c '
    source "$LIB"; pa_init "$ROOT"
    rc=0; pa_lock 1 || rc=$?
    echo "rc=$rc"
    echo "fd=[$PA_LOCK_FD]"
'
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "1");
    assert_eq!(
        r.get("fd"),
        "[]",
        "a lock not taken leaves no descriptor open"
    );
}

#[test]
fn pa_lock_works_with_a_read_only_lock_file_and_falls_back_to_run() {
    let fx = Fx::new();
    let lock = fx.p("var/lib/propolis/witness/state.lock");
    std::fs::write(&lock, "").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
    let probe = r#"rc=0; pa_lock 1 || rc=$?
echo "rc=$rc"
if flock -n "$1" true; then echo other=free; else echo other=held; fi
pa_unlock
if flock -n "$1" true; then echo after=free; else echo after=held; fi
"#;
    let r = fx.run(&format!("set -- \"$PA_STATE/state.lock\"\n{probe}"));
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "0");
    assert_eq!(r.get("other"), "held", "the lock is really held");
    assert_eq!(r.get("after"), "free");
    assert!(!fx.p("run/propolis-witness/state.lock").exists());

    // Without the persistent lock file the lock lives in /run, created 0600.
    std::fs::remove_file(&lock).unwrap();
    let r = fx.run(&format!(
        "umask 022\nset -- \"$PA_RUN/state.lock\"\n{probe}"
    ));
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("other"), "held");
    assert_eq!(mode_of(&fx.p("run/propolis-witness/state.lock")), 0o600);
    assert!(
        !lock.exists(),
        "the library never creates the persistent lock"
    );
}

#[test]
fn a_nested_pa_lock_returns_3_and_leaves_the_outer_lock_held() {
    let fx = Fx::new();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run(
        r#"inner() { local rc=0; pa_lock 1 || rc=$?; echo "inner=$rc"; [ "$rc" = 0 ] || return 1; pa_unlock; }
pa_lock 1
outer="$PA_LOCK_FD"
rc=0; inner || rc=$?
echo "inner-rc=$rc"
[ "$PA_LOCK_FD" = "$outer" ] && echo fd=same
if flock -n "$PA_STATE/state.lock" true; then echo other=free; else echo other=held; fi
pa_unlock
if flock -n "$PA_STATE/state.lock" true; then echo after=free; else echo after=held; fi
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("inner"), "3", "already held");
    assert_eq!(r.get("inner-rc"), "1");
    assert_eq!(r.get("fd"), "same");
    assert_eq!(
        r.get("other"),
        "held",
        "the nested use released nothing the outer caller holds"
    );
    assert_eq!(r.get("after"), "free", "the outermost owner unlocks");
}

#[test]
fn pa_lock_takes_the_default_wait_for_a_bad_value_and_returns_2_with_no_lock_file() {
    let fx = Fx::new();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run(
        r#"for w in abc 99999; do
    rc=0; pa_lock "$w" || rc=$?
    echo "$w=$rc"
    pa_unlock
done
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.get("abc"),
        "0",
        "a wait that is not a number becomes 10 s, not a flock usage error"
    );
    assert_eq!(r.get("99999"), "0");

    std::fs::remove_file(fx.p("var/lib/propolis/witness/state.lock")).unwrap();
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    let r = fx.run("rc=0; pa_lock 1 || rc=$?\necho \"rc=$rc\"\necho \"fd=[$PA_LOCK_FD]\"");
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "2", "no lock file can be opened");
    assert_eq!(r.get("fd"), "[]");
}

#[test]
fn pa_state_read_picks_the_copy_with_the_higher_generation() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v1 g=3\nM\tprofile_last\tpersistent\n",
    );
    fx.write(
        "run/propolis-witness/fallback/meta",
        "#meta v1 g=5\nM\tprofile_last\tfallback\n",
    );
    let r = fx.run("pa_state_read meta");
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.out, "M\tprofile_last\tfallback\n");

    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v1 g=12\nM\tprofile_last\tpersistent\n",
    );
    let r = fx.run("pa_state_read meta");
    assert_eq!(
        r.out, "M\tprofile_last\tpersistent\n",
        "12 is higher than 5"
    );

    let r = fx.run("pa_state_read observe; echo \"rc=$?\"");
    assert_eq!(r.out, "rc=0\n", "a missing file reads as empty");
    let r = fx.run("rc=0; pa_state_read heartbeat || rc=$?; echo \"rc=$rc\"");
    assert_eq!(
        r.get("rc"),
        "2",
        "only the six state files are read this way"
    );
}

#[test]
fn pa_state_write_falls_back_to_run_and_moves_back_when_the_disk_accepts_writes_again() {
    let fx = Fx::new();
    let state = fx.p("var/lib/propolis/witness");
    std::fs::remove_dir_all(&state).unwrap();
    // A file where the directory should be makes every write into it fail, for root too.
    std::fs::write(&state, "").unwrap();
    let write = |value: &str| {
        let r = fx.run(&format!(
            "rc=0; pa_state_write meta <<<\"$(printf 'M\\tprofile_last\\t{value}')\" || rc=$?\n\
             echo \"rc=$rc\"\necho \"where=$PA_WHERE\""
        ));
        (r.get("rc"), r.get("where"), r.err)
    };
    let (rc, where_, err) = write("one");
    assert_eq!((rc.as_str(), where_.as_str()), ("0", "run"), "{err}");
    assert_eq!(
        fx.read("run/propolis-witness/fallback/meta"),
        "#meta v1 g=1\nM\tprofile_last\tone\n"
    );
    assert_eq!(mode_of(&fx.p("run/propolis-witness/fallback")), 0o700);
    assert_eq!(mode_of(&fx.p("run/propolis-witness/fallback/meta")), 0o600);
    write("two");
    assert!(
        fx.read("run/propolis-witness/fallback/meta")
            .starts_with("#meta v1 g=2\n")
    );

    std::fs::remove_file(&state).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let (rc, where_, err) = write("three");
    assert_eq!((rc.as_str(), where_.as_str()), ("0", "persistent"), "{err}");
    assert_eq!(
        fx.read("var/lib/propolis/witness/meta"),
        "#meta v1 g=3\nM\tprofile_last\tthree\n",
        "the generation continues from the fallback copy"
    );
    assert!(!fx.p("run/propolis-witness/fallback/meta").exists());

    // Neither place writable: nothing persists.
    std::fs::remove_dir_all(&state).unwrap();
    std::fs::write(&state, "").unwrap();
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    std::fs::write(fx.p("run/propolis-witness"), "").unwrap();
    let (rc, where_, _) = write("four");
    assert_eq!((rc.as_str(), where_.as_str()), ("1", "none"));
}

#[test]
fn an_unreadable_state_file_is_renamed_and_the_reader_starts_empty() {
    let fx = Fx::new();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let read_at = |wall: &str| {
        let r = fx.run_env(
            "pa_lock 5\npa_state_read meta; echo \"rc=$?\"\npa_unlock",
            &[
                ("PA_TEST_WALL", wall),
                ("PA_TEST_BOOT", "abcdef01"),
                ("PA_TEST_UP", "5000"),
            ],
        );
        assert_eq!(r.code, 0, "{}", r.err);
        r.out
    };
    let unreadable_copies = || {
        let mut names: Vec<String> = std::fs::read_dir(fx.p("var/lib/propolis/witness"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("meta.unreadable."))
            .collect();
        names.sort();
        names
    };

    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v2 g=9\nM\tclock\t1/-/0\n",
    );
    assert_eq!(read_at("1000"), "rc=0\n");
    assert!(!fx.p("var/lib/propolis/witness/meta").exists());
    assert_eq!(unreadable_copies(), ["meta.unreadable.1000"]);
    let log = fx.log();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("-t propolis-witness"), "{log}");
    assert!(log.contains("meta"), "{log}");

    fx.write("var/lib/propolis/witness/meta", "M\tclock\t1/-/0\n");
    assert_eq!(read_at("2000"), "rc=0\n", "no header");
    assert_eq!(
        unreadable_copies(),
        ["meta.unreadable.2000"],
        "only the newest is kept"
    );

    fx.write("var/lib/propolis/witness/meta", "#observe v1 g=1\n");
    assert_eq!(read_at("3000"), "rc=0\n", "another file's header");
    assert_eq!(unreadable_copies(), ["meta.unreadable.3000"]);

    let mut big = String::from("#meta v1 g=1\n");
    while big.len() <= 1_048_576 {
        big.push_str(&format!("M\tk{}\t{}\n", big.len(), "v".repeat(100)));
    }
    fx.write("var/lib/propolis/witness/meta", &big);
    assert_eq!(read_at("4000"), "rc=0\n", "over 1 MiB");
    assert_eq!(unreadable_copies(), ["meta.unreadable.4000"]);
    assert_eq!(fx.log().lines().count(), 4);
}

#[test]
fn a_lockless_reader_leaves_an_unreadable_state_file_in_place_and_names_it() {
    let fx = Fx::new();
    let damaged = "#meta v2 g=9\nM\tclock\t1/-/0\n";
    fx.write("var/lib/propolis/witness/meta", damaged);
    let r = fx.run_env(
        "pa_state_read meta > \"$D/out\"\necho \"rc=$?\"\necho \"out=[$(cat \"$D/out\")]\"\n\
         echo \"unreadable=$PA_STATE_UNREADABLE\"",
        &NOW,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "0");
    assert_eq!(r.get("out"), "[]", "the reader starts empty");
    assert_eq!(r.get("unreadable"), "meta");
    assert_eq!(
        fx.read("var/lib/propolis/witness/meta"),
        damaged,
        "a reader without the lock writes nothing"
    );
    assert_eq!(fx.log(), "");

    // A link in place of the state file is not followed, even to a valid file.
    std::fs::remove_file(fx.p("var/lib/propolis/witness/meta")).unwrap();
    let valid = fx.scratch().join("valid-meta");
    std::fs::write(&valid, "#meta v1 g=1\nM\tclock\t1/-/0\n").unwrap();
    std::os::unix::fs::symlink(&valid, fx.p("var/lib/propolis/witness/meta")).unwrap();
    let r = fx.run_env(
        "pa_state_read meta > \"$D/out\"\necho \"out=[$(cat \"$D/out\")]\"\n\
         echo \"unreadable=$PA_STATE_UNREADABLE\"",
        &NOW,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("out"), "[]");
    assert_eq!(r.get("unreadable"), "meta");
    assert!(fx.p("var/lib/propolis/witness/meta").is_symlink());
}

#[test]
fn a_state_file_that_cannot_be_set_aside_is_logged_once_without_claiming_a_copy() {
    let fx = Fx::new();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let damaged = "M\tclock\t1/-/0\n";
    fx.write("var/lib/propolis/witness/meta", damaged);
    // A non-empty directory where the copy would go makes the rename fail, for root too, as a
    // read-only state directory would.
    std::fs::create_dir_all(fx.p("var/lib/propolis/witness/meta.unreadable.1000000/blocker"))
        .unwrap();
    let r = fx.run_env(
        "pa_lock 5\npa_state_read meta\npa_state_read meta\necho done=yes\npa_unlock",
        &NOW,
    );
    assert_eq!(r.get("done"), "yes", "{}", r.err);
    let log = fx.log();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(!log.contains("kept as"), "{log}");
    assert!(log.contains("could not be set aside"), "{log}");
    assert_eq!(fx.read("var/lib/propolis/witness/meta"), damaged);
}

#[test]
fn a_600_kib_state_file_is_still_read() {
    let fx = Fx::new();
    let mut body = String::new();
    let mut n = 0;
    while body.len() < 600 * 1024 {
        body.push_str(&format!("M\tk{n}\t{}\n", "v".repeat(100)));
        n += 1;
    }
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=7\n{body}"),
    );
    let r = fx.run("pa_state_read meta");
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.out, body);
    assert!(fx.p("var/lib/propolis/witness/meta").exists());
    assert_eq!(fx.log(), "");
}

#[test]
fn fields_a_newer_minor_revision_appends_are_ignored() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v1 g=4\nM\tclock\t1000/abcdef01/100\tappended\tfields\nQ\tan unknown\trecord type\n",
    );
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run_env(
        "pa_lock 5\npa_now\npa_clock_check\necho rc=$?\npa_unlock",
        &[
            ("PA_TEST_WALL", "1400"),
            ("PA_TEST_BOOT", "abcdef01"),
            ("PA_TEST_UP", "200"),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let meta = fx.read("var/lib/propolis/witness/meta");
    assert!(meta.starts_with("#meta v1 g=5\n"), "{meta}");
    assert_eq!(
        meta_value(&meta, "clock_step").as_deref(),
        Some("1400/abcdef01/200/+300"),
        "the stored clock was read without its appended fields: {meta}"
    );
    assert!(
        meta.contains("Q\tan unknown\trecord type\n"),
        "a record type this version does not know is kept for the version that does: {meta}"
    );
}

#[test]
fn pa_sensor_logs_parses_the_daemons_grammar() {
    let fx = Fx::new();
    let r = fx.run(
        r#"pa_sensor_logs ' ssh:/var/log/propolis/ssh/ssh.log , http:/x.log,, bad ,:/y, z:,a:/p:q'
for i in "${!PA_LOG_LABEL[@]}"; do echo "label$i=${PA_LOG_LABEL[$i]} ${PA_LOG_PATH[$i]}"; done
for i in "${!PA_LOG_BAD[@]}"; do echo "bad$i=${PA_LOG_BAD[$i]}|${PA_LOG_BAD_WHY[$i]}"; done
echo "labels=${#PA_LOG_LABEL[@]} bad=${#PA_LOG_BAD[@]}"
pa_sensor_logs ''
echo "empty=${#PA_LOG_LABEL[@]} ${#PA_LOG_BAD[@]}"
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("labels"), "3 bad=3");
    assert_eq!(r.get("label0"), "ssh /var/log/propolis/ssh/ssh.log");
    assert_eq!(r.get("label1"), "http /x.log");
    assert_eq!(r.get("label2"), "a /p:q", "split on the first colon");
    assert_eq!(r.get("bad0"), "bad|no ':' separator");
    assert_eq!(r.get("bad1"), ":/y|empty label");
    assert_eq!(r.get("bad2"), "z:|label with no path");
    assert_eq!(
        r.get("empty"),
        "0 0",
        "a second call starts from empty arrays"
    );

    // The daemon trims with str::trim, which removes every Unicode White_Space character: VT and
    // FF, and U+00A0 and U+3000 among the non-ASCII ones. U+200B is not White_Space, so it stays.
    let r = fx.run(
        r#"pa_sensor_logs $'ssh:/a,\vftp:/c\f,\xc2\xa0http:/b\xe3\x80\x80,\xe2\x80\x8bdns:/d'
for i in "${!PA_LOG_LABEL[@]}"; do printf 'label%s=[%s] [%s]\n' "$i" "${PA_LOG_LABEL[$i]}" "${PA_LOG_PATH[$i]}"; done
echo "bad=${#PA_LOG_BAD[@]}"
"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("bad"), "0");
    assert_eq!(r.get("label0"), "[ssh] [/a]");
    assert_eq!(r.get("label1"), "[ftp] [/c]");
    assert_eq!(r.get("label2"), "[http] [/b]");
    assert_eq!(r.get("label3"), "[\u{200b}dns] [/d]");
}

/// The fields of every `I` record in `incidents`, numbered as the format numbers them: index 0
/// is the record type, 1 the id, 2 the key, and so on to 34.
fn incident_records(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| l.starts_with("I\t"))
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

#[test]
fn pa_cause_maps_every_row_of_the_cause_map() {
    let fx = Fx::new();
    for (result, status, panics, want) in [
        ("exit-code", "1", "0", "proc.exit:1"),
        ("exit-code", "199", "0", "proc.exit:199"),
        ("exit-code", "244", "0", "proc.exit:244"),
        ("exit-code", "200", "0", "proc.sandbox:200"),
        ("exit-code", "226", "0", "proc.sandbox:226"),
        ("exit-code", "243", "0", "proc.sandbox:243"),
        ("exit-code", "101", "2", "proc.panic"),
        ("exit-code", "226", "1", "proc.sandbox:226"),
        ("signal", "9", "0", "proc.signal:9"),
        ("signal", "KILL", "0", "proc.signal:9"),
        ("core-dump", "SIGSEGV", "0", "proc.signal:11"),
        ("core-dump", "6", "1", "proc.panic"),
        ("signal", "31", "0", "proc.sigsys"),
        ("core-dump", "SYS", "0", "proc.sigsys"),
        // The syscall filter is named even when the run also logged a panic line.
        ("signal", "31", "1", "proc.sigsys"),
        ("core-dump", "SYS", "2", "proc.sigsys"),
        ("oom-kill", "9", "0", "proc.oom"),
        ("timeout", "-", "0", "proc.timeout"),
        ("watchdog", "-", "0", "proc.watchdog"),
        ("start-limit-hit", "-", "0", "proc.start_limit"),
        ("resources", "-", "0", "proc.resources"),
        ("success", "0", "0", "unknown"),
        ("", "", "", "unknown"),
        ("exit-code", "1; touch /tmp/x", "0", "unknown"),
        ("exit-code", "1234", "0", "unknown"),
        ("signal", "NOT A SIGNAL", "0", "unknown"),
        ("signal", "999", "0", "unknown"),
        ("exit-code", "3", "lots", "proc.exit:3"),
    ] {
        let r = fx.run_env(
            "out=\"$(pa_cause \"$R\" \"$S\" \"$P\")\"\npa_cause \"$R\" \"$S\" \"$P\" > /dev/null\n\
             echo \"out=$out\"\necho \"var=$PA_CAUSE\"",
            &[("R", result), ("S", status), ("P", panics)],
        );
        assert_eq!(r.code, 0, "{result} {status}: {}", r.err);
        assert_eq!(r.get("out"), want, "{result:?} {status:?} {panics:?}");
        assert_eq!(r.get("var"), want, "{result:?} {status:?} {panics:?}");
    }
}

#[test]
fn every_cause_pa_cause_prints_passes_pa_ok_field_and_its_class_is_the_part_before_the_dot() {
    let fx = Fx::new();
    let r = fx.run(
        r#"for row in "exit-code 3" "exit-code 226" "signal 9" "signal 31" "oom-kill -" "timeout -" "nothing -"; do
    set -- $row
    pa_cause "$1" "$2" 0 > /dev/null
    if pa_ok_field "$PA_CAUSE"; then echo "ok ${PA_CAUSE%%.*}"; else echo "bad $PA_CAUSE"; fi
done"#,
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.out.lines().collect::<Vec<_>>(),
        vec![
            "ok proc",
            "ok proc",
            "ok proc",
            "ok proc",
            "ok proc",
            "ok proc",
            "ok unknown"
        ]
    );
}

#[test]
fn pa_unit_map_gives_each_unit_its_stage_tier_and_reserve() {
    let fx = Fx::new();
    for (unit, want) in [
        ("sensor-ssh.service", "listen PAGE yes -"),
        ("propolis.service", "intake PAGE no daemon-down"),
        ("shipper.service", "ship ACT no -"),
        ("gateway.service", "gateway ACT no -"),
        ("propolis-logrotate.service", "source ACT no -"),
        ("propolis-backup.service", "backup ACT no -"),
        ("propolis-witness@light.service", "witness ACT no -"),
        ("ssh.service", "host ACT no -"),
        ("propolis-alert@x.service", "host ACT no -"),
    ] {
        let r = fx.run_env(
            "pa_unit_map \"$U\"\necho \"m=$PA_UNIT_STAGE $PA_UNIT_TIER $PA_UNIT_LISTENER $PA_UNIT_RESERVE\"",
            &[("U", unit)],
        );
        assert_eq!(r.code, 0, "{unit}: {}", r.err);
        assert_eq!(r.get("m"), want, "{unit}");
    }
}

/// The marker upgrade.sh and rollback.sh write, in the two-line form they write it.
fn maintenance_marker(until: u64, boot: &str, reason: &str) -> String {
    format!("#maintenance v1 g=1\nX\t{until}\t{boot}\t{reason}\n")
}

#[test]
fn pa_maint_active_holds_only_for_this_boot_and_at_most_two_hours_ahead() {
    for (body, active) in [
        (maintenance_marker(1_003_600, "abcdef01", "upgrade"), true),
        (maintenance_marker(1_007_200, "abcdef01", "rollback"), true),
        (maintenance_marker(1_000_060, "abcdef01", "manual"), true),
        (maintenance_marker(1_007_201, "abcdef01", "upgrade"), false),
        (maintenance_marker(1_000_000, "abcdef01", "upgrade"), false),
        (maintenance_marker(999_000, "abcdef01", "upgrade"), false),
        (maintenance_marker(1_003_600, "12345678", "upgrade"), false),
        (maintenance_marker(1_003_600, "-", "upgrade"), false),
        (maintenance_marker(1_003_600, "abcdef01", "party"), false),
        (
            "#maintenance v2 g=1\nX\t1003600\tabcdef01\tupgrade\n".to_string(),
            false,
        ),
        ("X\t1003600\tabcdef01\tupgrade\n".to_string(), false),
        (String::new(), false),
    ] {
        let fx = Fx::new();
        fx.write("run/propolis-witness/maintenance", &body);
        let r = fx.run_env(
            "if pa_maint_active; then echo \"active=yes $PA_MAINT_REASON $PA_MAINT_UNTIL\"; else echo active=no; fi",
            &NOW,
        );
        assert_eq!(r.code, 0, "{}", r.err);
        let got = r.get("active");
        assert_eq!(got.starts_with("yes"), active, "{body:?}: {got}");
        if active {
            let reason = body.trim_end().rsplit('\t').next().unwrap();
            assert!(got.contains(reason), "{got}");
        }
    }

    // No marker, or something that is not a regular file in its place, is no maintenance.
    let fx = Fx::new();
    let r = fx.run_env("pa_maint_active && echo active=yes || echo active=no", &NOW);
    assert_eq!(r.get("active"), "no");
    let target = fx.scratch().join("marker");
    std::fs::write(
        &target,
        maintenance_marker(1_003_600, "abcdef01", "upgrade"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, fx.p("run/propolis-witness/maintenance")).unwrap();
    let r = fx.run_env("pa_maint_active && echo active=yes || echo active=no", &NOW);
    assert_eq!(r.get("active"), "no", "a link is never followed");
}

/// Sets the attributes a firing gives a record and applies TX to `unit:sensor-ssh.service`.
const TRANSITION: &str = r#"pa_now
PA_REC_KIND="${KIND:-unit-failed}" PA_REC_STAGE="${STAGE:-listen}" PA_REC_INST="${INST-u12345}" PA_REC_TIER="${TIER:-PAGE}"
PA_REC_CAUSE="${CAUSE:-proc.exit:1}" PA_REC_NR="${NR-4}" PA_REC_OUT="${OUT:-delivered}" PA_REC_FLAG="${FLAG:-}"
pa_incident_load
pa_incident_transition "${KEY:-unit:sensor-ssh.service}" "$TX"
echo "done=$PA_TX_DONE tx=$PA_TX"
rc=0; pa_incident_put || rc=$?
echo "rc=$rc where=$PA_WHERE"
"#;

#[test]
fn a_first_sighting_writes_one_pending_record_and_nothing_v2_would_push() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "pending")]);
    assert_eq!(r.get("done"), "pending tx=-", "{}", r.err);
    assert_eq!(r.get("rc"), "0 where=persistent");
    let text = fx.read("var/lib/propolis/witness/incidents");
    assert!(text.starts_with("#incidents v1 g=1\nN\t2\n"), "{text}");
    let records = incident_records(&text);
    assert_eq!(records.len(), 1, "{text}");
    let f = &records[0];
    assert_eq!(f.len(), 35, "34 fields after the type: {f:?}");
    let stamp = "1000000/abcdef01/5000";
    assert_eq!(f[1], "w#1");
    assert_eq!(f[2], "unit:sensor-ssh.service");
    assert_eq!(f[3], "unit-failed");
    assert_eq!(f[4], "listen");
    assert_eq!(f[5], "u12345");
    assert_eq!(f[6], "PAGE");
    assert_eq!(f[7], "pending");
    assert_eq!(f[8], stamp, "first_seen");
    assert_eq!(f[9], "-", "not opened");
    assert_eq!(f[10], stamp, "onset");
    assert_eq!(f[11], "proc.exit:1");
    assert_eq!(f[12], stamp, "cause_since");
    assert_eq!(f[14], "0", "sends");
    assert_eq!(f[17], "0", "delivered_open");
    assert_eq!(f[29], "0", "would_push");
    assert_eq!(f[30], "-", "flags");
    assert_eq!(f[31], "1", "occ");
    assert_eq!(f[32], "4", "nr_seen");
    assert_eq!(f[33], "delivered", "legacy_out");
    assert_eq!(f[34], "-", "count");
    assert!(
        f[1..].iter().all(|v| !v.is_empty()),
        "no field is empty: {f:?}"
    );
    assert_eq!(mode_of(&fx.p("var/lib/propolis/witness/incidents")), 0o600);
}

#[test]
fn an_open_counts_one_would_push_and_a_repeat_only_raises_occ() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "open")]);
    assert_eq!(r.get("done"), "open tx=open", "{}", r.err);
    let later = [
        ("PA_TEST_WALL", "1000300"),
        ("PA_TEST_BOOT", "abcdef01"),
        ("PA_TEST_UP", "5300"),
    ];
    for out in ["cooldown", "undelivered"] {
        let r = fx.run_env(
            TRANSITION,
            &[later[0], later[1], later[2], ("TX", "open"), ("OUT", out)],
        );
        assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    }
    let text = fx.read("var/lib/propolis/witness/incidents");
    let records = incident_records(&text);
    assert_eq!(records.len(), 1, "one record per key: {text}");
    let f = &records[0];
    assert_eq!(f[1], "w#1", "a repeat keeps the id");
    assert_eq!(f[7], "open");
    assert_eq!(f[9], "1000000/abcdef01/5000", "opened at the first firing");
    assert_eq!(f[29], "1", "only the open counts as a push v2 would make");
    assert_eq!(f[31], "3", "occ counts every firing");
    assert_eq!(f[33], "undelivered", "legacy_out is the latest firing's");
    assert_eq!(f[12], "1000000/abcdef01/5000", "the cause did not change");

    // A different cause is recorded with its own time, and is still not a new incident.
    let r = fx.run_env(
        TRANSITION,
        &[
            later[0],
            later[1],
            later[2],
            ("TX", "open"),
            ("CAUSE", "proc.signal:9"),
        ],
    );
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    let records = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
    assert_eq!(records[0][11], "proc.signal:9");
    assert_eq!(records[0][12], "1000300/abcdef01/5300");
    assert_eq!(records[0][29], "1");
}

#[test]
fn a_pending_record_opens_when_an_open_follows_and_another_key_gets_the_next_id() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "pending")]);
    assert_eq!(r.get("done"), "pending tx=-", "{}", r.err);
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "pending")]);
    assert_eq!(r.get("done"), "occ tx=-", "a second sighting only counts");
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "open")]);
    assert_eq!(r.get("done"), "open tx=open", "{}", r.err);
    let r = fx.run_env(
        TRANSITION,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("TX", "open"),
            ("KEY", "unit:propolis-backup.service"),
            ("TIER", "ACT"),
        ],
    );
    assert_eq!(r.get("done"), "open tx=open", "{}", r.err);
    let text = fx.read("var/lib/propolis/witness/incidents");
    assert!(text.contains("\nN\t3\n"), "{text}");
    let records = incident_records(&text);
    assert_eq!(records.len(), 2, "{text}");
    assert_eq!(records[0][1], "w#1");
    assert_eq!(records[0][7], "open");
    assert_eq!(records[0][31], "3");
    assert_eq!(records[0][29], "1");
    assert_eq!(records[1][1], "w#2");
    assert_eq!(records[1][2], "unit:propolis-backup.service");
}

#[test]
fn a_notice_open_is_recorded_without_a_would_push_and_a_flag_is_added_once() {
    let fx = Fx::salted(SALT);
    for _ in 0..2 {
        let r = fx.run_env(
            TRANSITION,
            &[
                NOW[0],
                NOW[1],
                NOW[2],
                ("TX", "open"),
                ("TIER", "NOTICE"),
                ("KIND", "rotation-skipped"),
                ("FLAG", "maint"),
            ],
        );
        assert_eq!(r.get("rc"), "0 where=persistent", "{}", r.err);
    }
    let records = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
    assert_eq!(records[0][29], "0", "a NOTICE never pushes");
    assert_eq!(records[0][30], "maint");
}

#[test]
fn a_value_that_fails_pa_ok_field_is_written_as_a_question_mark_and_a_bad_key_is_refused() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(
        TRANSITION,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("TX", "pending"),
            ("CAUSE", "proc exit\t1"),
            ("NR", ""),
        ],
    );
    assert_eq!(r.get("rc"), "0 where=persistent", "{}", r.err);
    let records = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
    assert_eq!(records[0].len(), 35);
    assert_eq!(records[0][11], "?");
    assert_eq!(records[0][32], "-", "an absent value is `-`");

    let r = fx.run_env(
        TRANSITION,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("TX", "pending"),
            ("KEY", "unit:bad name.service"),
        ],
    );
    assert_ne!(r.get("rc"), "0 where=persistent", "{}", r.out);
    assert_eq!(
        incident_records(&fx.read("var/lib/propolis/witness/incidents")).len(),
        1
    );
}

#[test]
fn records_written_by_a_newer_revision_keep_their_extra_fields_and_other_lines() {
    let fx = Fx::salted(SALT);
    let fields: Vec<String> = (1..=34)
        .map(|i| match i {
            1 => "w#7".to_string(),
            2 => "unit:sensor-ssh.service".to_string(),
            7 => "open".to_string(),
            29 => "1".to_string(),
            31 => "1".to_string(),
            _ => "-".to_string(),
        })
        .collect();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=9\nN\t8\nI\t{}\tfield35\nW\t1/abcdef01/1\tdeadbeef\topen\t1\t-\tbudget\nQ\tunknown\n",
            fields.join("\t")
        ),
    );
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "open")]);
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    let text = fx.read("var/lib/propolis/witness/incidents");
    assert!(text.starts_with("#incidents v1 g=10\nN\t8\n"), "{text}");
    let records = incident_records(&text);
    assert_eq!(records[0][1], "w#7");
    assert_eq!(records[0][31], "2");
    assert_eq!(records[0].get(35).map(String::as_str), Some("field35"));
    assert!(
        text.contains("\nW\t1/abcdef01/1\tdeadbeef\topen\t1\t-\tbudget\n"),
        "{text}"
    );
    assert!(text.contains("\nQ\tunknown\n"), "{text}");
}

/// Answers `systemctl show ... -- UNIT` from `$STUB_SHOW`; every other call fails.
const SYSTEMCTL_SHOW_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
[ "$1" = show ] && [ -n "${STUB_SHOW:-}" ] || exit 1
printf '%b' "$STUB_SHOW"
"#;

/// Prints `$STUB_JOURNAL` for any query and records it.
const JOURNALCTL_RUN_STUB: &str = r#"#!/usr/bin/env bash
printf 'journalctl %s\n' "$*" >> "$STUB_LOG"
printf '%b' "${STUB_JOURNAL:-}"
"#;

const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn pa_hook_record_writes_what_todays_hook_did_with_systemds_cause() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
    write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let show = format!(
        "Result=exit-code\\nExecMainCode=1\\nExecMainStatus=2\\nInvocationID={INVOCATION}\\nRestart=no\\nType=oneshot\\nNRestarts=0\\n"
    );
    let r = fx.run_env(
        "rc=0; pa_hook_record || rc=$?\necho \"rc=$rc\"",
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", "propolis-backup.service"),
            ("PA_HOOK_OUT", "undelivered"),
            ("PA_HOOK_T0", "3"),
            ("STUB_SHOW", &show),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert!(r.out.trim() == "rc=0", "it prints nothing: {}", r.out);
    let records = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
    assert_eq!(records.len(), 1);
    let f = &records[0];
    assert_eq!(f[2], "unit:propolis-backup.service");
    assert_eq!(f[3], "unit-failed");
    assert_eq!(f[4], "backup");
    assert_eq!(f[6], "ACT");
    assert_eq!(
        f[7], "open",
        "a unit that does not restart itself opens at once"
    );
    assert_eq!(f[11], "proc.exit:2");
    assert_eq!(f[33], "undelivered");
    assert_eq!(
        f[5], "-",
        "inst: an id widened against every configured unit is the witness's to give"
    );
    assert!(
        fx.p("var/lib/propolis/witness/id-salt").exists(),
        "the first root writer makes the salt"
    );
    let log = fx.log();
    assert!(
        log.contains("systemctl show -p Result,ExecMainCode,ExecMainStatus,InvocationID,Restart,Type,NRestarts -- propolis-backup.service"),
        "{log}"
    );
    assert!(
        log.contains(&format!(
            "journalctl -q -o cat _SYSTEMD_UNIT=propolis-backup.service _SYSTEMD_INVOCATION_ID={INVOCATION}"
        )),
        "{log}"
    );
    assert!(
        !log.contains("logger"),
        "a written record logs nothing: {log}"
    );
}

#[test]
fn pa_hook_record_takes_monitor_variables_over_systemctl_and_refuses_hostile_values() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
    write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let show = "Result=exit-code\\nExecMainStatus=2\\nRestart=always\\nNRestarts=7\\n";
    let r = fx.run_env(
        "pa_hook_record; echo rc=$?",
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", "sensor-ssh.service"),
            ("PA_HOOK_OUT", "delivered"),
            ("PA_HOOK_T0", "1"),
            ("STUB_SHOW", show),
            ("MONITOR_SERVICE_RESULT", "signal"),
            ("MONITOR_EXIT_CODE", "killed"),
            ("MONITOR_EXIT_STATUS", "SYS"),
            ("MONITOR_INVOCATION_ID", INVOCATION),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let f = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0].clone();
    assert_eq!(f[11], "proc.sigsys");
    assert_eq!(f[7], "pending", "a restarting unit is a first sighting");
    assert_eq!(f[32], "7");

    // Hostile values from the environment are never written or run.
    let fx = Fx::new();
    write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
    write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run_env(
        "pa_hook_record; echo rc=$?",
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", "sensor-ssh.service"),
            ("PA_HOOK_OUT", "delivered;rm"),
            ("PA_HOOK_T0", "1"),
            ("MONITOR_SERVICE_RESULT", "exit-code"),
            ("MONITOR_EXIT_STATUS", "1$(touch $D/pwned)"),
            ("MONITOR_INVOCATION_ID", "x _SYSTEMD_UNIT=other"),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let f = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0].clone();
    assert_eq!(f[11], "unknown");
    assert_eq!(f[33], "-", "an outcome outside the closed list is `-`");
    assert!(!fx.scratch().join("pwned").exists());
    assert!(
        !fx.log().contains("_SYSTEMD_UNIT=other"),
        "an invocation id that is not 32 hex digits never reaches journalctl: {}",
        fx.log()
    );
}

#[test]
fn pa_hook_record_spools_when_the_lock_is_held_and_logs_only_when_nothing_could_be_written() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
    write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let r = fx.run_env(
        r#"flock -n "$PA_STATE/state.lock" bash -c 'source "$LIB"; pa_init "$ROOT"; pa_hook_record; echo rc=$?'"#,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", "propolis.service"),
            ("PA_HOOK_OUT", "journal"),
            ("PA_HOOK_T0", "1"),
            ("MONITOR_SERVICE_RESULT", "oom-kill"),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert!(!fx.p("var/lib/propolis/witness/incidents").exists());
    let spool = fx.read("var/lib/propolis/witness/hook/propolis.service");
    let stamp = "1000000/abcdef01/5000";
    assert_eq!(
        spool,
        format!("#hook v1 g=1\nH\t{stamp}\t{stamp}\t1\toom-kill\t-\t-\tproc.oom\t-\tjournal\n")
    );
    assert_eq!(
        mode_of(&fx.p("var/lib/propolis/witness/hook/propolis.service")),
        0o600
    );
    assert!(!fx.log().contains("logger"), "{}", fx.log());

    // A second spooled firing keeps the first time and counts.
    std::fs::write(&fx.log, b"").unwrap();
    let later = [
        ("PA_TEST_WALL", "1000100"),
        ("PA_TEST_BOOT", "abcdef01"),
        ("PA_TEST_UP", "5100"),
    ];
    let r = fx.run_env(
        "pa_hook_record; echo rc=$?",
        &[
            later[0],
            later[1],
            later[2],
            ("PA_HOOK_UNIT", "propolis.service"),
            ("PA_HOOK_OUT", "cooldown"),
            ("PA_HOOK_T0", "71"),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(
        fx.read("var/lib/propolis/witness/hook/propolis.service"),
        format!(
            "#hook v1 g=2\nH\t{stamp}\t1000100/abcdef01/5100\t2\t-\t-\t-\tunknown\t-\tcooldown\n"
        ),
        "past 70 s the record goes to the spool at once, with no systemctl or journal read"
    );
    assert!(!fx.log().contains("systemctl"), "{}", fx.log());

    // With nowhere to write, one line under propolis-witness says so.
    let fx = Fx::new();
    std::fs::remove_dir_all(fx.p("var/lib/propolis/witness")).unwrap();
    std::fs::write(fx.p("var/lib/propolis/witness"), "not a directory").unwrap();
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    std::fs::write(fx.p("run/propolis-witness"), "not a directory").unwrap();
    let r = fx.run_env(
        "pa_hook_record; echo rc=$?",
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", "propolis.service"),
            ("PA_HOOK_OUT", "delivered"),
            ("PA_HOOK_T0", "1"),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let log = fx.log();
    let lines: Vec<&str> = log.lines().filter(|l| l.starts_with("logger")).collect();
    assert_eq!(lines.len(), 1, "{log}");
    assert!(
        lines[0].starts_with(
            "logger -p daemon.notice -t propolis-witness incident not recorded for propolis.service: "
        ),
        "{log}"
    );
}

/// A firing at a lower tier than the open incident it repeats (a routine rotation skip after a
/// refused rotation) only counts: the kind, stage, tier and cause recorded stay, so an open fault
/// is never relabelled as a NOTICE. A firing at the same or a higher tier takes its own.
#[test]
fn a_lower_tier_firing_on_an_open_incident_only_counts_and_keeps_what_was_recorded() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:propolis-logrotate.service");
    let r = fx.run_env(
        TRANSITION,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            key,
            ("TX", "open"),
            ("TIER", "ACT"),
            ("STAGE", "source"),
            ("CAUSE", "guard.no_space"),
        ],
    );
    assert_eq!(r.get("done"), "open tx=open", "{}", r.err);
    let later = [
        ("PA_TEST_WALL", "1000300"),
        ("PA_TEST_BOOT", "abcdef01"),
        ("PA_TEST_UP", "5300"),
    ];
    let r = fx.run_env(
        TRANSITION,
        &[
            later[0],
            later[1],
            later[2],
            key,
            ("TX", "open"),
            ("TIER", "NOTICE"),
            ("KIND", "rotation-skipped"),
            ("STAGE", "source"),
            ("CAUSE", "guard.behind"),
            ("OUT", "cooldown"),
            ("FLAG", "maint"),
        ],
    );
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    let f = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0].clone();
    assert_eq!(
        (f[3].as_str(), f[4].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "source", "ACT", "guard.no_space")
    );
    assert_eq!(f[12], "1000000/abcdef01/5000", "cause_since");
    assert_eq!(f[29], "1", "would_push");
    assert_eq!(f[31], "2", "occ");
    assert_eq!(f[33], "cooldown", "legacy_out is still the latest firing's");
    assert_eq!(f[30], "maint", "the flag is still added");

    // The same tier with another cause, then a higher tier, each take the firing's own.
    let r = fx.run_env(
        TRANSITION,
        &[
            later[0],
            later[1],
            later[2],
            key,
            ("TX", "open"),
            ("TIER", "ACT"),
            ("STAGE", "source"),
            ("CAUSE", "proc.exit:1"),
        ],
    );
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    let f = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0].clone();
    assert_eq!(f[11], "proc.exit:1");
    let r = fx.run_env(
        TRANSITION,
        &[
            later[0],
            later[1],
            later[2],
            key,
            ("TX", "open"),
            ("TIER", "PAGE"),
        ],
    );
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    let f = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0].clone();
    assert_eq!(f[6], "PAGE");
    assert_eq!(f[31], "4");
}

/// A repeat fills an opaque id the record did not have yet, and never replaces one it has.
#[test]
fn a_repeat_fills_an_unset_inst_and_keeps_a_set_one() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(
        TRANSITION,
        &[NOW[0], NOW[1], NOW[2], ("TX", "pending"), ("INST", "-")],
    );
    assert_eq!(r.get("done"), "pending tx=-", "{}", r.err);
    let inst =
        |fx: &Fx| incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0][5].clone();
    assert_eq!(inst(&fx), "-");
    let r = fx.run_env(
        TRANSITION,
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("TX", "pending"),
            ("INST", "u12345"),
        ],
    );
    assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
    assert_eq!(inst(&fx), "u12345");
    for other in ["uabcde", "-"] {
        let r = fx.run_env(
            TRANSITION,
            &[NOW[0], NOW[1], NOW[2], ("TX", "pending"), ("INST", other)],
        );
        assert_eq!(r.get("done"), "occ tx=-", "{}", r.err);
        assert_eq!(inst(&fx), "u12345", "{other}");
    }
}

/// The first 12 hex digits of sha256(TEXT), as config-check keys a finding.
fn k12(text: &str) -> String {
    use std::io::Write;
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..12].to_string()
}

/// One `I` line with id `id`, key `key`, kind `kind` and state `state`; every other field `-`
/// or 0.
fn record_line(id: &str, key: &str, kind: &str, state: &str) -> String {
    let fields: Vec<String> = (1..=34)
        .map(|i| match i {
            1 => id.to_string(),
            2 => key.to_string(),
            3 => kind.to_string(),
            6 => "ACT".to_string(),
            7 => state.to_string(),
            14 | 17 | 18 | 23 | 29 => "0".to_string(),
            31 => "1".to_string(),
            _ => "-".to_string(),
        })
        .collect();
    format!("I\t{}\n", fields.join("\t"))
}

/// A sensor that fails while config-check's `noconfig` finding for it is open or pending has no
/// bind configured: it is recorded as unit-nobind at ACT. A resolved finding, or one for another
/// sensor, leaves the ordinary listener failure at PAGE.
#[test]
fn a_sensor_failing_under_an_open_noconfig_finding_is_recorded_as_unit_nobind() {
    let show =
        "Result=exit-code\\nExecMainCode=1\\nExecMainStatus=1\\nRestart=always\\nNRestarts=3\\n";
    let ssh = format!("finding:noconfig:{}", k12("noconfig:sensor-ssh"));
    let http = format!("finding:noconfig:{}", k12("noconfig:sensor-http"));
    for (finding_key, state, want) in [
        (&ssh, "open", ("unit-nobind", "ACT", "listen")),
        (&ssh, "pending", ("unit-nobind", "ACT", "listen")),
        (&ssh, "acked", ("unit-nobind", "ACT", "listen")),
        (&ssh, "resolved", ("unit-failed", "PAGE", "listen")),
        (&http, "open", ("unit-failed", "PAGE", "listen")),
    ] {
        let fx = Fx::new();
        write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
        write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
        fx.write("var/lib/propolis/witness/state.lock", "");
        fx.write(
            "var/lib/propolis/witness/incidents",
            &format!(
                "#incidents v1 g=1\nN\t2\n{}",
                record_line("w#1", finding_key, "finding", state)
            ),
        );
        let r = fx.run_env(
            "pa_hook_record; echo rc=$?",
            &[
                NOW[0],
                NOW[1],
                NOW[2],
                ("PA_HOOK_UNIT", "sensor-ssh.service"),
                ("PA_HOOK_OUT", "delivered"),
                ("PA_HOOK_T0", "1"),
                ("STUB_SHOW", show),
            ],
        );
        assert_eq!(r.get("rc"), "0", "{}", r.err);
        let records = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
        let f = records
            .iter()
            .find(|f| f[2] == "unit:sensor-ssh.service")
            .unwrap_or_else(|| panic!("no record for the sensor: {records:?}"));
        assert_eq!(
            (f[3].as_str(), f[6].as_str(), f[4].as_str()),
            want,
            "{finding_key} {state}"
        );
        assert_eq!(records.len(), 2, "the finding's record stays as it was");
    }
}

/// Two configured sensors whose 5-hex ids collide under this salt: the hook sees only the one
/// that failed, so it cannot widen the id, and writes `-` for the witness to fill rather than an
/// id the walk would show differently.
#[test]
fn the_hook_never_stores_a_five_hex_id_that_collides_with_another_units() {
    let fx = Fx::salted(SALT);
    write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
    write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
    fx.write("var/lib/propolis/witness/state.lock", "");
    let (a, b) = ("sensor-c495.service", "sensor-c1059.service");
    let r = fx.run_env(
        "echo \"a=$(pa_id unit \"$A\")\"\necho \"b=$(pa_id unit \"$B\")\"\n\
         printf 'unit\\t%s\\nunit\\t%s\\n' \"$A\" \"$B\" | pa_id_table | while IFS=$'\\t' read -r id _ n; do echo \"table $n=$id\"; done",
        &[("A", a), ("B", b)],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("a"), r.get("b"), "the two names collide in 5 hex");
    let widened = r.get(&format!("table {a}"));
    assert_eq!(widened.len(), 9, "pa_id_table widens both: {}", r.out);

    let show =
        "Result=exit-code\\nExecMainCode=1\\nExecMainStatus=1\\nRestart=always\\nNRestarts=1\\n";
    let r = fx.run_env(
        "pa_hook_record; echo rc=$?",
        &[
            NOW[0],
            NOW[1],
            NOW[2],
            ("PA_HOOK_UNIT", a),
            ("PA_HOOK_OUT", "delivered"),
            ("PA_HOOK_T0", "1"),
            ("STUB_SHOW", show),
        ],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let inst = incident_records(&fx.read("var/lib/propolis/witness/incidents"))[0][5].clone();
    assert!(
        inst == "-" || inst == widened,
        "inst {inst}: neither `-` nor the widened {widened}"
    );
}

/// A unit name is what systemd itself would call a unit: a type after the last dot, a prefix that
/// does not start with `@`, an instance after an `@` when there is one, within the characters the
/// failure hook accepts and 200 bytes.
#[test]
fn pa_unit_name_ok_accepts_exactly_the_names_systemd_gives_a_unit() {
    let fx = Fx::new();
    let long = format!("{}.service", "a".repeat(192));
    let script = format!(
        r#"t() {{ if pa_unit_name_ok "$1"; then echo "$2=yes"; else echo "$2=no"; fi; }}
t 'sensor-ssh.service' plain
t 'propolis-witness@light.service' instance
t 'a@b@c.timer' two-at
t '-.mount' dash
t 'a.b.socket' dotted
t '{long}' len-200
t '{long}a' len-201
t 'sensor-ssh' no-type
t 'test' word
t 'a.conf' other-type
t '@a.service' at-first
t 'a@.service' template
t '.a.service' dot-first
t 'a/b.service' slash
t 'a b.service' space
t $'a\tb.service' tab
t 'a\x2db.service' backslash
t '' empty
"#
    );
    let r = fx.run(&script);
    assert_eq!(r.code, 0, "{}", r.err);
    for name in ["plain", "instance", "two-at", "dash", "dotted", "len-200"] {
        assert_eq!(r.get(name), "yes", "{name}");
    }
    for name in [
        "len-201",
        "no-type",
        "word",
        "other-type",
        "at-first",
        "template",
        "dot-first",
        "slash",
        "space",
        "tab",
        "backslash",
        "empty",
    ] {
        assert_eq!(r.get(name), "no", "{name}");
    }
}

/// A word that is not a unit name (a leading dot, a slash, a tab, no unit type, a template) is
/// refused before anything is written, whether the step would record or spool, with one line
/// saying so. `sensor-ssh` is what a hand-started `propolis-alert@sensor-ssh.service` passes:
/// systemd would answer for it as `sensor-ssh.service`, so a record under the bare word could
/// never be judged.
#[test]
fn pa_hook_record_refuses_a_unit_name_systemd_never_gives_before_writing_anything() {
    for unit in [
        "..",
        ".x",
        "a/b",
        "a\tb.service",
        "sensor-ssh",
        "@a.service",
        "a@.service",
        "a.conf",
    ] {
        for t0 in ["1", "71"] {
            let fx = Fx::new();
            write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
            write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
            fx.write("var/lib/propolis/witness/state.lock", "");
            let r = fx.run_env(
                "pa_hook_record; echo rc=$?",
                &[
                    NOW[0],
                    NOW[1],
                    NOW[2],
                    ("PA_HOOK_UNIT", unit),
                    ("PA_HOOK_OUT", "delivered"),
                    ("PA_HOOK_T0", t0),
                ],
            );
            assert_eq!(r.get("rc"), "0", "{unit:?} {t0}: {}", r.err);
            for dir in [
                "var/lib/propolis/witness/hook",
                "run/propolis-witness/fallback",
            ] {
                let entries: Vec<_> = std::fs::read_dir(fx.p(dir))
                    .map(|d| d.flatten().map(|e| e.path()).collect())
                    .unwrap_or_default();
                assert!(entries.is_empty(), "{unit:?} {t0}: {entries:?}");
            }
            assert!(
                !fx.p("var/lib/propolis/witness/incidents").exists(),
                "{unit:?} {t0}"
            );
            let log = fx.log();
            let lines: Vec<&str> = log.lines().filter(|l| l.starts_with("logger")).collect();
            assert_eq!(lines.len(), 1, "{unit:?} {t0}: {log}");
            assert!(
                lines[0].ends_with("the unit name is not one systemd gives"),
                "{log}"
            );
        }
    }
}

/// With 512 records open or pending a new one is not written, and one line says so; with one of
/// them resolved, that one makes room.
#[test]
fn a_new_incident_past_512_open_records_is_not_written_unless_a_resolved_one_makes_room() {
    let show =
        "Result=exit-code\\nExecMainCode=1\\nExecMainStatus=1\\nRestart=always\\nNRestarts=1\\n";
    let run = |fx: &Fx| {
        let r = fx.run_env(
            "pa_hook_record; echo rc=$?",
            &[
                NOW[0],
                NOW[1],
                NOW[2],
                ("PA_HOOK_UNIT", "sensor-ssh.service"),
                ("PA_HOOK_OUT", "delivered"),
                ("PA_HOOK_T0", "1"),
                ("STUB_SHOW", show),
            ],
        );
        assert_eq!(r.get("rc"), "0", "{}", r.err);
    };
    let setup = |first_state: &str, first_resolved: Option<u64>| {
        let fx = Fx::salted(SALT);
        write_exec(&fx.bin.join("systemctl"), SYSTEMCTL_SHOW_STUB);
        write_exec(&fx.bin.join("journalctl"), JOURNALCTL_RUN_STUB);
        fx.write("var/lib/propolis/witness/state.lock", "");
        let mut body = String::from("#incidents v1 g=1\nN\t513\n");
        body.push_str(&i_line(1, first_state, first_resolved));
        for n in 2..=512 {
            body.push_str(&i_line(n, "open", None));
        }
        fx.write("var/lib/propolis/witness/incidents", &body);
        (fx, body)
    };

    let (fx, before) = setup("open", None);
    run(&fx);
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
    let log = fx.log();
    let lines: Vec<&str> = log.lines().filter(|l| l.starts_with("logger")).collect();
    assert_eq!(lines.len(), 1, "{log}");
    assert!(
        lines[0].ends_with("512 incidents are open or pending (notpersisted)"),
        "{log}"
    );

    let (fx, _) = setup("resolved", Some(2000));
    run(&fx);
    let text = fx.read("var/lib/propolis/witness/incidents");
    let records = incident_records(&text);
    assert_eq!(records.len(), 512);
    assert!(
        records.iter().all(|f| f[1] != "w#1"),
        "the resolved record made room"
    );
    let new: Vec<&Vec<String>> = records
        .iter()
        .filter(|f| f[2] == "unit:sensor-ssh.service")
        .collect();
    assert_eq!(new.len(), 1, "{text}");
    assert_eq!(new[0][1], "w#513");
    assert!(!fx.log().contains("logger"), "{}", fx.log());
}

/// The next number is never below one past the highest id in use: a damaged `N` line cannot hand
/// out an id twice.
#[test]
fn a_next_number_below_an_id_in_use_is_raised_past_it() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t1\n{}",
            record_line("w#7", "unit:other.service", "unit-failed", "open")
        ),
    );
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "pending")]);
    assert_eq!(r.get("done"), "pending tx=-", "{}", r.err);
    let text = fx.read("var/lib/propolis/witness/incidents");
    assert!(text.contains("\nN\t9\n"), "{text}");
    let records = incident_records(&text);
    let new = records
        .iter()
        .find(|f| f[2] == "unit:sensor-ssh.service")
        .unwrap();
    assert_eq!(new[1], "w#8");
}

/// One key, one record: a firing for a key whose record is resolved replaces that record with a
/// new incident under the next id (a reopen is the witness's, in a later increment).
#[test]
fn a_firing_for_a_resolved_key_replaces_its_record_with_a_new_incident() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t4\n{}{}",
            record_line("w#2", "unit:other.service", "unit-failed", "open"),
            record_line("w#3", "unit:sensor-ssh.service", "unit-failed", "resolved")
        ),
    );
    let r = fx.run_env(TRANSITION, &[NOW[0], NOW[1], NOW[2], ("TX", "pending")]);
    assert_eq!(r.get("done"), "pending tx=-", "{}", r.err);
    let text = fx.read("var/lib/propolis/witness/incidents");
    assert!(text.contains("\nN\t5\n"), "{text}");
    let records = incident_records(&text);
    assert_eq!(records.len(), 2, "{text}");
    let f = records
        .iter()
        .find(|f| f[2] == "unit:sensor-ssh.service")
        .unwrap();
    assert_eq!(f[1], "w#4");
    assert_eq!(f[7], "pending");
    assert_eq!(f[31], "1", "occ starts again");
    assert_eq!(f[21], "-", "not resolved");
}

// ---- the database probe and the push scheduler -------------------------------------------------

/// A stand-in for `/usr/local/bin/propolis`: it carries pg-exec's guard string, writes each
/// argument on its own line and the `DATABASE_URL` it was given to `STUB_LOG`, then prints
/// `PG_OUT`, writes `PG_ERR` to stderr, sleeps `PG_SLEEP` seconds and exits `PG_RC`.
const PROPOLIS_PG_STUB: &str = r#"#!/usr/bin/env bash
# propolis pg-exec: DATABASE_URL is not set
{ printf 'argv\n'; for a in "$@"; do printf 'arg[%s]\n' "$a"; done; printf 'url[%s]\n' "${DATABASE_URL:-}"; } >> "$STUB_LOG"
[ -z "${PG_SLEEP:-}" ] || sleep "$PG_SLEEP"
[ -z "${PG_OUT:-}" ] || printf '%s\n' "$PG_OUT"
[ -z "${PG_ERR:-}" ] || printf '%s\n' "$PG_ERR" >&2
exit "${PG_RC:-0}"
"#;

/// Puts `body` at the daemon binary's path under the root, with every directory on the way
/// 0755, so the trust check passes unless a case loosens one.
fn install_daemon_binary(fx: &Fx, body: &str) {
    write_exec(&fx.p("usr/local/bin/propolis"), body);
    for rel in ["usr", "usr/local", "usr/local/bin"] {
        std::fs::set_permissions(fx.p(rel), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o755)).unwrap();
}

const PG_PROBE: &str = r#"rc=0
out="$(pa_pg "${T:-10}" 'SELECT 1')" || rc=$?
pa_pg "${T:-10}" 'SELECT 1' > /dev/null
echo "rc=$rc"
echo "out=$out"
echo "var=$PA_PG_OUT"
echo "cause=$PA_PG_CAUSE"
echo "why=$PA_PG_WHY"
echo "where=$PA_PG_WHERE"
"#;

#[test]
fn pa_pg_gives_the_url_only_in_the_environment_and_asks_for_a_read_only_bounded_session() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write(
        "etc/propolis/fleet-listeners.env",
        "DATABASE_URL=postgres://early@db.example.invalid/x\n",
    );
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis:s3cret@localhost/propolis\n",
    );
    let r = fx.run_env(
        "rc=0\npa_pg 10 'SELECT 1' 'SELECT 2' > /dev/null || rc=$?\necho \"rc=$rc\"\necho \"cause=$PA_PG_CAUSE\"\necho \"where=$PA_PG_WHERE\"\nPA_PG_APP=propolis-status pa_pg 10 'SELECT 3' > /dev/null",
        &[("PG_OUT", "1")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "0");
    assert_eq!(r.get("cause"), "-");
    assert_eq!(r.get("where"), "local");
    let log = fx.log();
    let first: Vec<&str> = log.split("argv\n").nth(1).unwrap().lines().collect();
    assert_eq!(
        first,
        vec![
            "arg[pg-exec]",
            "arg[psql]",
            "arg[-X]",
            "arg[-A]",
            "arg[-t]",
            "arg[-q]",
            "arg[-w]",
            "arg[-v]",
            "arg[ON_ERROR_STOP=1]",
            "arg[-d]",
            "arg[connect_timeout=5 application_name=propolis-witness options='-c statement_timeout=5000 -c default_transaction_read_only=on']",
            "arg[-c]",
            "arg[SELECT 1]",
            "arg[-c]",
            "arg[SELECT 2]",
            "url[postgres://propolis:s3cret@localhost/propolis]",
        ],
        "propolis.env is read after fleet-listeners.env, as systemd loads them"
    );
    assert!(
        log.contains("application_name=propolis-status "),
        "a caller names its own session: {log}"
    );
    assert!(
        !log.lines()
            .filter(|l| l.starts_with("arg["))
            .any(|l| l.contains("s3cret") || l.contains("postgres://")),
        "the URL never reaches a command line: {log}"
    );
}

#[test]
fn pa_pg_prints_what_psql_printed_and_keeps_it_in_a_variable() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis@db.example.invalid:5433/propolis\n",
    );
    let r = fx.run_env(PG_PROBE, &[("PG_OUT", "9812440|1763133664")]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "0");
    assert_eq!(r.get("out"), "9812440|1763133664");
    assert_eq!(r.get("var"), "9812440|1763133664");
    assert_eq!(r.get("where"), "remote");
}

/// Each row of the classification table, from psql's exit status and stderr. psql's stderr is
/// kept for a person to read, never matched beyond these fixed texts.
#[test]
fn pa_pg_classifies_each_failure_by_its_status_and_fixed_texts() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis@/propolis?host=/run/postgresql\n",
    );
    for (rc, err, cause) in [
        ("124", "", "db.timeout"),
        ("2", "psql: error: timeout expired", "db.timeout"),
        ("126", "", "tool.exec"),
        ("127", "", "tool.exec"),
        (
            "127",
            "propolis pg-exec: cannot run psql: No such file or directory",
            "tool.exec",
        ),
        (
            "2",
            "psql: error: could not open file: Permission denied",
            "tool.exec",
        ),
        (
            "2",
            "psql: error: FATAL:  password authentication failed for user \"propolis\"",
            "db.auth",
        ),
        (
            "2",
            "psql: error: FATAL:  Peer authentication failed for user \"propolis\"",
            "db.auth",
        ),
        (
            "2",
            "psql: error: FATAL:  no pg_hba.conf entry for host",
            "db.auth",
        ),
        (
            "2",
            "psql: error: FATAL:  role \"propolis\" does not exist",
            "db.auth",
        ),
        (
            "2",
            "psql: error: connection to server on socket \"/run/postgresql/.s.PGSQL.5432\" failed: fe_sendauth: no password supplied",
            "db.auth",
        ),
        (
            "2",
            "psql: error: connection to server failed: Connection refused",
            "db.unreachable",
        ),
        (
            "2",
            "psql: error: could not translate host name \"db\" to address",
            "db.unreachable",
        ),
        ("2", "psql: error: something new", "db.unreachable"),
        (
            "1",
            "propolis pg-exec: DATABASE_URL is not set",
            "config.invalid",
        ),
        (
            "1",
            "propolis pg-exec: DATABASE_URL is not a postgres URL",
            "config.invalid",
        ),
        ("3", "ERROR:  relation \"event\" does not exist", "unknown"),
    ] {
        let r = fx.run_env(PG_PROBE, &[("PG_RC", rc), ("PG_ERR", err)]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert_eq!(r.get("rc"), "1", "exit {rc} {err:?}");
        assert_eq!(r.get("cause"), cause, "exit {rc} {err:?}");
        assert_eq!(r.get("where"), "local");
    }
}

#[test]
fn pa_pg_keeps_psqls_stderr_for_a_person_and_never_prints_it() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis@localhost/propolis\n",
    );
    let r = fx.run_env(
        "pa_pg 10 'SELECT 1'\necho\necho \"err=$(printf '%s' \"$PA_PG_ERR\" | tr '\\n' '|')\"",
        &[("PG_RC", "2"), ("PG_ERR", "line one\nline two")],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("err"), "line one|line two");
    assert!(!r.out.lines().next().unwrap().contains("line"), "{}", r.out);
    assert!(!r.err.contains("line one"), "{}", r.err);
}

#[test]
fn pa_pg_stops_a_probe_that_outlives_its_time_limit() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis@localhost/propolis\n",
    );
    let started = std::time::Instant::now();
    let r = fx.run_env(PG_PROBE, &[("PG_SLEEP", "30"), ("T", "1")]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("cause"), "db.timeout");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "two probes of 1 s each took {:?}",
        started.elapsed()
    );
}

/// An older binary without pg-exec would start the daemon as root, so it is never run; nor is a
/// binary in a directory another account can write, nor anything when no URL is set.
#[test]
fn pa_pg_never_runs_a_binary_without_pg_exec_an_untrusted_one_or_one_without_a_url() {
    let fx = Fx::new();
    install_daemon_binary(&fx, &PROPOLIS_PG_STUB.replace("propolis pg-exec:", "old:"));
    fx.write(
        "etc/propolis/propolis.env",
        "DATABASE_URL=postgres://propolis@localhost/propolis\n",
    );
    let r = fx.run_env(PG_PROBE, &[]);
    assert_eq!(r.get("rc"), "1");
    assert_eq!(r.get("cause"), "tool.exec");
    assert_eq!(r.get("why"), "daemon binary predates pg-exec");
    assert!(!fx.log().contains("argv"), "{}", fx.log());

    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    std::fs::set_permissions(
        fx.p("usr/local/bin"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.run_env(PG_PROBE, &[]);
    assert_eq!(r.get("cause"), "tool.exec");
    assert!(
        r.get("why").starts_with("not trusted: ")
            && r.get("why").contains("usr/local/bin: group-writable"),
        "{}",
        r.get("why")
    );
    assert!(!fx.log().contains("argv"), "{}", fx.log());

    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    fx.write("etc/propolis/propolis.env", "# no URL\n");
    let r = fx.run_env(PG_PROBE, &[]);
    assert_eq!(r.get("rc"), "1");
    assert_eq!(r.get("cause"), "config.invalid");
    assert_eq!(r.get("why"), "DATABASE_URL is not set");
    assert!(!fx.log().contains("argv"), "{}", fx.log());
}

#[test]
fn pa_pg_tells_a_local_database_from_a_remote_one_by_the_urls_host() {
    let fx = Fx::new();
    install_daemon_binary(&fx, PROPOLIS_PG_STUB);
    for (url, where_) in [
        ("postgres://propolis@/propolis", "local"),
        ("postgres://propolis:pw@localhost:5432/propolis", "local"),
        ("postgresql://propolis@127.0.0.1/propolis", "local"),
        ("postgres://propolis@[::1]:5432/propolis", "local"),
        ("postgres://propolis@%2Frun%2Fpostgresql/propolis", "local"),
        (
            "postgres://propolis@db/propolis?host=/run/postgresql",
            "local",
        ),
        ("postgres://propolis@10.0.0.5/propolis", "remote"),
        (
            "postgres://propolis@db.example.invalid:5432/propolis",
            "remote",
        ),
        ("postgres://propolis@[2001:db8::5]/propolis", "remote"),
    ] {
        fx.write(
            "etc/propolis/propolis.env",
            &format!("DATABASE_URL={url}\n"),
        );
        let r = fx.run_env(PG_PROBE, &[]);
        assert_eq!(r.get("where"), where_, "{url}");
    }
}

const SCHEDULER: &str = r#"rc=0
pa_push_scheduler > /dev/null || rc=$?
echo "rc=$rc"
echo "printed=$(pa_push_scheduler)"
echo "kind=$PA_SCHED"
echo "count=$PA_SCHED_N"
"#;

#[test]
fn pa_push_scheduler_finds_an_uncommented_cron_line_in_any_of_the_crontab_places() {
    let fx = Fx::new();
    let r = fx.run(SCHEDULER);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.get("rc"), "0");
    assert_eq!(r.get("printed"), "none 0");

    fx.write(
        "etc/cron.d/propolis",
        "# 5 * * * * propolis-blocklist /usr/local/lib/propolis/blocklist-sync.sh\n",
    );
    assert_eq!(fx.run(SCHEDULER).get("printed"), "none 0");

    for (i, rel) in [
        "etc/crontab",
        "etc/cron.d/propolis",
        "var/spool/cron/crontabs/propolis-blocklist",
        "var/spool/cron/propolis-blocklist",
    ]
    .into_iter()
    .enumerate()
    {
        fx.write(
            rel,
            "SHELL=/bin/sh\n  5 * * * * /usr/local/lib/propolis/blocklist-sync.sh\n",
        );
        let r = fx.run(SCHEDULER);
        assert_eq!(r.get("kind"), "cron", "{rel}");
        assert_eq!(r.get("count"), (i + 1).to_string(), "{rel}");
    }
}

#[test]
fn pa_push_scheduler_counts_a_service_only_when_its_timer_is_enabled() {
    let fx = Fx::new();
    fx.write(
        "etc/systemd/system/blocklist-push.service",
        "[Service]\nUser=propolis-blocklist\nExecStart=/usr/local/lib/propolis/blocklist-sync.sh\n",
    );
    fx.write(
        "etc/systemd/system/blocklist-push.timer",
        "[Timer]\nOnCalendar=hourly\n",
    );
    assert_eq!(fx.run(SCHEDULER).get("printed"), "none 0");
    let r = fx.run_env(SCHEDULER, &[("STUB_ENABLED", "blocklist-push.timer")]);
    assert_eq!(r.get("printed"), "timer 1");
    assert!(
        fx.log()
            .contains("systemctl is-enabled --quiet blocklist-push.timer"),
        "{}",
        fx.log()
    );
}

/// A link, a directory or an oversized file is never read as root; a file that cannot be read
/// makes the answer unknown (status 1), never `none`.
#[test]
fn pa_push_scheduler_reads_only_regular_files_and_says_when_it_could_not_read_one() {
    let fx = Fx::new();
    fx.write(
        "scratch-target",
        "5 * * * * /usr/local/lib/propolis/blocklist-sync.sh\n",
    );
    std::fs::create_dir_all(fx.p("etc/cron.d")).unwrap();
    std::os::unix::fs::symlink(fx.p("scratch-target"), fx.p("etc/cron.d/linked")).unwrap();
    std::fs::create_dir_all(fx.p("var/spool/cron/crontabs")).unwrap();
    let r = fx.run(SCHEDULER);
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("printed"), "none 0");

    fx.write("etc/cron.d/huge", &"#".repeat(70_000));
    let r = fx.run(SCHEDULER);
    assert_eq!(r.get("rc"), "1");
    assert_eq!(r.get("printed"), "none 0");
}

/// Under pipefail a `grep -q` that stops at the first match would kill the writers before it
/// and fail the pipeline, so a match early in a crontab near the size cap would be missed.
#[test]
fn pa_push_scheduler_finds_a_cron_line_at_the_top_of_a_crontab_near_the_size_cap() {
    let fx = Fx::new();
    let mut text =
        String::from("5 * * * * propolis-blocklist /usr/local/lib/propolis/blocklist-sync.sh\n");
    while text.len() + 20 <= 65_536 {
        text.push_str("0 0 * * * /bin/true\n");
    }
    fx.write("etc/cron.d/propolis", &text);
    let r = fx.run(SCHEDULER);
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("printed"), "cron 1");

    let mut unit = String::from("[Service]\nExecStart=/usr/local/lib/propolis/blocklist-sync.sh\n");
    while unit.len() + 20 <= 65_536 {
        unit.push_str("# padding padding.\n");
    }
    std::fs::remove_file(fx.p("etc/cron.d/propolis")).unwrap();
    fx.write("etc/systemd/system/blocklist-push.service", &unit);
    let r = fx.run_env(SCHEDULER, &[("STUB_ENABLED", "blocklist-push.timer")]);
    assert_eq!(r.get("printed"), "timer 1", "{}", r.err);
}

// ---- the record-mode lifecycle -------------------------------------------------------------------

/// The time seam `secs` seconds after `NOW`, in the same boot.
fn at(secs: u64) -> [(&'static str, String); 3] {
    [
        ("PA_TEST_WALL", (1_000_000 + secs).to_string()),
        ("PA_TEST_BOOT", "abcdef01".to_string()),
        ("PA_TEST_UP", (5000 + secs).to_string()),
    ]
}

/// The stamp the library writes `secs` seconds after `NOW`.
fn stamp_at(secs: u64) -> String {
    format!("{}/abcdef01/{}", 1_000_000 + secs, 5000 + secs)
}

/// Applies TX to KEY (default `unit:sensor-ssh.service`) with the firing's attributes from the
/// environment, keeps the result in memory and writes the file once.
const LIFE: &str = r#"pa_now
PA_REC_KIND="${KIND:-unit-failed}" PA_REC_STAGE="${STAGE:-listen}" PA_REC_INST="${INST-u12345}" PA_REC_TIER="${TIER:-PAGE}"
PA_REC_CAUSE="${CAUSE-proc.exit:1}" PA_REC_NR="${NR-4}" PA_REC_OUT="${OUT:-delivered}" PA_REC_FLAG="${FLAG:-}" PA_REC_PROOF="${PROOF:-}"
pa_incident_load
rc=0; pa_incident_transition "${KEY:-unit:sensor-ssh.service}" "$TX" || rc=$?
echo "tx=$rc $PA_TX_DONE $PA_TX"
prc=0; pa_incident_set || prc=$?
[ "$prc" != 0 ] || pa_incident_write || prc=$?
echo "put=$prc"
"#;

/// Runs LIFE at `secs` with TX and the extra variables, and returns what it printed for `tx`.
fn life(fx: &Fx, secs: u64, tx: &str, extra: &[(&str, &str)]) -> String {
    let now = at(secs);
    let mut env: Vec<(&str, &str)> = now.iter().map(|(k, v)| (*k, v.as_str())).collect();
    env.push(("TX", tx));
    env.extend_from_slice(extra);
    let r = fx.run_env(LIFE, &env);
    assert_eq!(r.get("put"), "0", "{tx} at {secs}: {}", r.err);
    r.get("tx")
}

/// The one record of `key` in the incidents file.
fn the_record(fx: &Fx, key: &str) -> Vec<String> {
    incident_records(&fx.read("var/lib/propolis/witness/incidents"))
        .into_iter()
        .find(|f| f[2] == key)
        .unwrap_or_else(|| panic!("no record of {key}"))
}

/// In the legacy profile the whole lifecycle runs and sends nothing: an open schedules its
/// reminders at 1 h, 4 h and 12 h for a PAGE, at 4 h and 12 h for an ACT, none for a NOTICE, and
/// each reminder that comes due is one more message v2 would have sent.
#[test]
fn the_reminder_schedule_is_one_four_and_twelve_hours_for_a_page_and_four_and_twelve_for_an_act() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    assert_eq!(life(&fx, 0, "open", &[key]), "0 open open");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[16], "open", "last_tx");
    assert_eq!(f[18], "0", "reminders");
    assert_eq!(f[19], stamp_at(3600), "next_due");
    assert_eq!(f[29], "1", "would_push");

    // Not due yet: nothing happens.
    assert_eq!(life(&fx, 3599, "remind", &[key]), "3 - -");
    for (secs, next, pushed) in [
        (3600, stamp_at(14_400), "2"),
        (14_400, stamp_at(43_200), "3"),
        (43_200, "-".to_string(), "4"),
    ] {
        assert_eq!(life(&fx, secs, "remind", &[key]), "0 remind remind");
        let f = the_record(&fx, "unit:sensor-ssh.service");
        assert_eq!(f[19], next, "next_due after the reminder at {secs}");
        assert_eq!(f[29], pushed, "would_push after the reminder at {secs}");
        assert_eq!(f[16], "remind");
    }
    assert_eq!(
        life(&fx, 90_000, "remind", &[key]),
        "3 - -",
        "no fourth reminder"
    );

    let act = ("KEY", "unit:propolis-backup.service");
    assert_eq!(
        life(&fx, 0, "open", &[act, ("TIER", "ACT"), ("STAGE", "backup")]),
        "0 open open"
    );
    assert_eq!(
        the_record(&fx, "unit:propolis-backup.service")[19],
        stamp_at(14_400)
    );
    assert_eq!(life(&fx, 14_400, "remind", &[act]), "0 remind remind");
    assert_eq!(
        the_record(&fx, "unit:propolis-backup.service")[19],
        stamp_at(43_200)
    );

    let notice = ("KEY", "unit:propolis-logrotate.service");
    life(
        &fx,
        0,
        "open",
        &[notice, ("TIER", "NOTICE"), ("KIND", "rotation-skipped")],
    );
    let f = the_record(&fx, "unit:propolis-logrotate.service");
    assert_eq!((f[19].as_str(), f[29].as_str()), ("-", "0"));

    let nobind = ("KEY", "unit:sensor-http.service");
    life(
        &fx,
        0,
        "open",
        &[nobind, ("TIER", "ACT"), ("KIND", "unit-nobind")],
    );
    assert_eq!(
        the_record(&fx, "unit:sensor-http.service")[19],
        "-",
        "unit-nobind has no reminders"
    );
}

/// A resolve needs a proof from the closed list and an open or acked record; it counts as a
/// message v2 would have sent only when the open was one.
#[test]
fn a_resolve_records_its_proof_and_counts_only_where_the_open_counted() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[key]);
    assert_eq!(
        life(&fx, 700, "resolve", &[key, ("PROOF", "lucky")]),
        "2 - -",
        "a proof outside the closed list is refused"
    );
    assert_eq!(
        life(&fx, 700, "resolve", &[key, ("PROOF", "active10")]),
        "0 resolve resolve"
    );
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[7], "resolved");
    assert_eq!(f[21], stamp_at(700), "resolved");
    assert_eq!(f[22], "active10", "proof");
    assert_eq!(f[16], "resolve");
    assert_eq!(f[19], "-", "nothing more to remind");
    assert_eq!(f[29], "2", "the open and the resolve");
    assert_eq!(
        life(&fx, 800, "resolve", &[key, ("PROOF", "active10")]),
        "3 - -",
        "a resolved record does not resolve again"
    );

    let notice = ("KEY", "unit:propolis-logrotate.service");
    life(
        &fx,
        0,
        "open",
        &[notice, ("TIER", "NOTICE"), ("KIND", "rotation-skipped")],
    );
    assert_eq!(
        life(&fx, 400, "resolve", &[notice, ("PROOF", "nextrun")]),
        "0 resolve -"
    );
    assert_eq!(the_record(&fx, "unit:propolis-logrotate.service")[29], "0");

    let pending = ("KEY", "unit:sensor-http.service");
    life(&fx, 0, "pending", &[pending]);
    assert_eq!(
        life(&fx, 400, "resolve", &[pending, ("PROOF", "active10")]),
        "3 - -",
        "a first sighting is dropped or opened, never resolved"
    );
}

/// A pending first sighting that healed leaves no record behind; an open one cannot be dropped.
#[test]
fn a_dropped_first_sighting_leaves_no_record_and_an_open_record_cannot_be_dropped() {
    let fx = Fx::salted(SALT);
    life(&fx, 0, "pending", &[("KEY", "unit:sensor-ssh.service")]);
    life(&fx, 0, "open", &[("KEY", "unit:sensor-http.service")]);
    assert_eq!(
        life(&fx, 300, "drop", &[("KEY", "unit:sensor-ssh.service")]),
        "0 drop -"
    );
    assert_eq!(
        life(&fx, 300, "drop", &[("KEY", "unit:sensor-http.service")]),
        "3 - -"
    );
    assert_eq!(
        life(&fx, 300, "drop", &[("KEY", "unit:nosuch.service")]),
        "1 - -"
    );
    let text = fx.read("var/lib/propolis/witness/incidents");
    let records = incident_records(&text);
    assert_eq!(records.len(), 1, "{text}");
    assert_eq!(records[0][2], "unit:sensor-http.service");
    assert!(
        text.contains("\nN\t3\n"),
        "an id is never handed out twice: {text}"
    );
}

/// The same fault back within max(2 x (resolved - opened), 30 min) of its resolve is a reopen of
/// the same id, with its acknowledgement cleared; later it is a new incident. The third reopen
/// within 24 h holds the next resolve until the proof has held an hour.
#[test]
fn a_fault_back_within_its_reopen_window_reopens_the_same_id_and_the_third_reopen_holds_the_resolve()
 {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    let proof = ("PROOF", "active10");
    life(&fx, 0, "open", &[key]);
    life(&fx, 600, "resolve", &[key, proof]);
    // Window: max(2 x 600, 1800) = 1800 s after the resolve.
    assert_eq!(life(&fx, 2400, "open", &[key]), "0 open reopen");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[1], "w#1", "same id");
    assert_eq!(f[7], "open");
    assert_eq!(f[16], "reopen");
    assert_eq!(f[23], "1", "reopens");
    assert_eq!(f[24], stamp_at(2400), "reopen_first");
    assert_eq!(f[21], "-", "no longer resolved");
    assert_eq!(f[9], stamp_at(2400), "opened again");
    assert_eq!(f[19], stamp_at(2400 + 3600), "reminders start again");
    assert_eq!(f[29], "3", "open, resolve, reopen");

    for (resolve_at, open_at) in [(2500, 2600), (2700, 2800)] {
        life(&fx, resolve_at, "resolve", &[key, proof]);
        assert_eq!(life(&fx, open_at, "open", &[key]), "0 open reopen");
    }
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[23], "3");
    assert_eq!(f[25], stamp_at(2800), "the third reopen sets hold_until");
    assert_eq!(
        life(&fx, 2800 + 3599, "resolve", &[key, proof]),
        "4 - -",
        "held for an hour"
    );
    assert_eq!(
        life(&fx, 2800 + 3600, "resolve", &[key, proof]),
        "0 resolve resolve"
    );

    // Past the window it is a new incident under the next id.
    let resolved_at = 2800 + 3600;
    assert_eq!(
        life(&fx, resolved_at + 1_000_000, "open", &[key]),
        "0 open open"
    );
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[1], "w#2");
}

/// A first sighting of a fault that is back within the window stays the same record: opened, it
/// is a reopen; dropped (the restart healed), the record is resolved again as it was.
#[test]
fn a_first_sighting_inside_the_reopen_window_keeps_the_record_and_a_drop_puts_it_back() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[key]);
    life(&fx, 600, "resolve", &[key, ("PROOF", "active10")]);
    assert_eq!(life(&fx, 900, "pending", &[key]), "0 pending -");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!((f[1].as_str(), f[7].as_str()), ("w#1", "pending"));
    assert_eq!(life(&fx, 1200, "drop", &[key]), "0 drop -");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[7], "resolved");
    assert_eq!(f[21], stamp_at(600), "the resolve it had");
    assert_eq!(f[29], "2", "nothing counted for the healed restart");

    life(&fx, 1300, "pending", &[key]);
    assert_eq!(life(&fx, 1600, "open", &[key]), "0 open reopen");
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[1], "w#1");
}

/// The maint flag describes the sighting a record is judged on. A fault back inside the reopen
/// window with no marker is not planned work because an earlier episode of the same record came
/// under one; a sighting that does come under a marker is flagged again.
#[test]
fn a_first_sighting_inside_the_reopen_window_carries_the_maint_flag_of_this_sighting_only() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    let has_maint = |fx: &Fx| {
        the_record(fx, "unit:sensor-ssh.service")[30]
            .split(',')
            .any(|x| x == "maint")
    };
    life(&fx, 0, "pending", &[key, ("FLAG", "maint")]);
    life(&fx, 100, "open", &[key]);
    assert!(has_maint(&fx), "the first episode came under a marker");
    life(&fx, 700, "resolve", &[key, ("PROOF", "active10")]);

    assert_eq!(life(&fx, 1000, "pending", &[key]), "0 pending -");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!((f[1].as_str(), f[7].as_str()), ("w#1", "pending"));
    assert!(!has_maint(&fx), "no marker this time: {}", f[30]);

    life(&fx, 1100, "drop", &[key]);
    life(&fx, 1200, "pending", &[key, ("FLAG", "maint")]);
    assert!(has_maint(&fx), "this sighting came under a marker");
}

/// A first sighting kept inside the reopen window is judged on what the hook read this time:
/// its NRestarts replaces the count of the first open, and its time is the record's onset, or
/// one healed restart would read as a unit that kept failing.
#[test]
fn a_first_sighting_inside_the_reopen_window_takes_the_count_and_the_time_of_this_sighting() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[key, ("NR", "0")]);
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[32], "0");
    life(&fx, 600, "resolve", &[key, ("PROOF", "active10")]);
    assert_eq!(
        life(&fx, 900, "pending", &[key, ("NR", "7")]),
        "0 pending -"
    );
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!((f[1].as_str(), f[7].as_str()), ("w#1", "pending"));
    assert_eq!(f[32], "7", "nr_seen of this sighting");
    assert_eq!(f[10], stamp_at(900), "onset of this sighting");
}

/// The reopen window is twice as long as the incident was open (at least 30 minutes): open for
/// 3000 s, the same fault 5000 s after the resolve reopens the same id, and 6100 s after it is a
/// new incident.
#[test]
fn the_reopen_window_is_twice_the_time_the_incident_was_open() {
    let fx = Fx::salted(SALT);
    let proof = ("PROOF", "active10");
    let inside = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[inside]);
    life(&fx, 3000, "resolve", &[inside, proof]);
    assert_eq!(life(&fx, 8000, "open", &[inside]), "0 open reopen");
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[1], "w#1");

    let outside = ("KEY", "unit:sensor-http.service");
    life(&fx, 0, "open", &[outside]);
    life(&fx, 3000, "resolve", &[outside, proof]);
    assert_eq!(life(&fx, 9100, "open", &[outside]), "0 open open");
    assert_eq!(the_record(&fx, "unit:sensor-http.service")[1], "w#3");
}

/// Reopens are counted within 24 h of the first: three spread over more than a day start the
/// count again and never hold the resolve.
#[test]
fn three_reopens_spread_over_more_than_a_day_never_hold_the_resolve() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    let proof = ("PROOF", "active10");
    life(&fx, 0, "open", &[key]);
    life(&fx, 600, "resolve", &[key, proof]);
    assert_eq!(life(&fx, 1000, "open", &[key]), "0 open reopen");
    life(&fx, 41_000, "resolve", &[key, proof]);
    assert_eq!(life(&fx, 50_000, "open", &[key]), "0 open reopen");
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[23], "2");
    life(&fx, 90_000, "resolve", &[key, proof]);
    assert_eq!(life(&fx, 100_000, "open", &[key]), "0 open reopen");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!(f[23], "1", "the count starts again a day after the first");
    assert_eq!(f[24], stamp_at(100_000), "reopen_first");
    assert_eq!(f[25], "-", "no hold");
}

/// A reminder that comes due long after its time (the timer was stopped, or the schedule was
/// given to an old record) is one reminder: the offsets that went by meanwhile are skipped, so
/// the next pass sends no second one.
#[test]
fn a_reminder_late_by_several_offsets_is_recorded_once_and_the_missed_ones_are_skipped() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[key]);
    assert_eq!(life(&fx, 50_000, "remind", &[key]), "0 remind remind");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!((f[19].as_str(), f[29].as_str()), ("-", "2"));
    assert_eq!(f[18], "1", "the skipped reminders are not counted");
    assert_eq!(life(&fx, 50_300, "remind", &[key]), "3 - -");
    assert_eq!(the_record(&fx, "unit:sensor-ssh.service")[29], "2");

    let late = ("KEY", "unit:sensor-http.service");
    life(&fx, 0, "open", &[late]);
    assert_eq!(life(&fx, 20_000, "remind", &[late]), "0 remind remind");
    let f = the_record(&fx, "unit:sensor-http.service");
    assert_eq!(f[19], stamp_at(43_200), "the 12 h reminder is still ahead");
    assert_eq!(f[18], "1", "the skipped reminder is not counted");
    assert_eq!(life(&fx, 20_300, "remind", &[late]), "3 - -");
    assert_eq!(life(&fx, 43_200, "remind", &[late]), "0 remind remind");
    let f = the_record(&fx, "unit:sensor-http.service");
    assert_eq!((f[18].as_str(), f[19].as_str()), ("2", "-"), "{f:?}");
}

/// An acknowledged record is past its reminders: one whose next reminder is due gets none.
#[test]
fn an_acknowledged_record_is_never_reminded() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:sensor-ssh.service");
    life(&fx, 0, "open", &[key]);
    let text = fx.read("var/lib/propolis/witness/incidents");
    let acked: String = text
        .lines()
        .map(|l| {
            let mut f: Vec<&str> = l.split('\t').collect();
            if f[0] == "I" {
                f[7] = "acked";
            }
            format!("{}\n", f.join("\t"))
        })
        .collect();
    fx.write("var/lib/propolis/witness/incidents", &acked);
    assert_eq!(life(&fx, 4000, "remind", &[key]), "3 - -");
    let f = the_record(&fx, "unit:sensor-ssh.service");
    assert_eq!((f[7].as_str(), f[29].as_str()), ("acked", "1"));
}

/// A change is counted when the cause changes class (the part before the dot) or the tier
/// rises; a new code within the class, or a cause learnt where it was unknown, is not one.
#[test]
fn a_change_of_cause_class_or_a_rising_tier_counts_and_a_change_within_the_class_does_not() {
    let fx = Fx::salted(SALT);
    let key = ("KEY", "unit:propolis-logrotate.service");
    let act = [("TIER", "ACT"), ("STAGE", "source")];
    life(&fx, 0, "open", &[key, act[0], act[1], ("CAUSE", "unknown")]);
    assert_eq!(
        life(
            &fx,
            300,
            "change",
            &[key, act[0], act[1], ("CAUSE", "proc.exit:1")]
        ),
        "0 occ -",
        "learning the cause is not a change"
    );
    assert_eq!(
        life(
            &fx,
            600,
            "change",
            &[key, act[0], act[1], ("CAUSE", "proc.signal:9")]
        ),
        "0 occ -"
    );
    let f = the_record(&fx, "unit:propolis-logrotate.service");
    assert_eq!(f[11], "proc.signal:9");
    assert_eq!(f[12], stamp_at(600), "cause_since");
    assert_eq!(f[29], "1");
    assert_eq!(
        life(
            &fx,
            900,
            "change",
            &[key, act[0], act[1], ("CAUSE", "guard.no_space")]
        ),
        "0 change change"
    );
    let f = the_record(&fx, "unit:propolis-logrotate.service");
    assert_eq!((f[16].as_str(), f[29].as_str()), ("change", "2"));
    assert_eq!(
        life(
            &fx,
            1200,
            "change",
            &[key, ("TIER", "PAGE"), ("CAUSE", "guard.no_space")]
        ),
        "0 change change"
    );
    assert_eq!(
        the_record(&fx, "unit:propolis-logrotate.service")[6],
        "PAGE"
    );
    assert_eq!(
        life(
            &fx,
            1500,
            "change",
            &[key, ("TIER", "ACT"), ("CAUSE", "guard.no_space")]
        ),
        "0 occ -",
        "a tier never falls"
    );
    assert_eq!(
        the_record(&fx, "unit:propolis-logrotate.service")[6],
        "PAGE"
    );
}

/// Late parent: a child that is already open takes a parent that appears later; from then on it
/// is neither reminded nor counted, and its resolve folds into the parent's.
#[test]
fn a_late_parent_takes_an_open_child_which_then_counts_nothing_more() {
    let fx = Fx::salted(SALT);
    life(&fx, 0, "open", &[("KEY", "unit:propolis.service")]);
    life(&fx, 300, "open", &[("KEY", "db:local")]);
    let fold = |child: &str, parent: &str| {
        let now = at(400);
        let mut env: Vec<(&str, &str)> = now.iter().map(|(k, v)| (*k, v.as_str())).collect();
        env.push(("CHILD", child));
        env.push(("PARENT", parent));
        let r = fx.run_env(
            "pa_now\npa_incident_load\nrc=0; pa_incident_fold \"$CHILD\" \"$PARENT\" || rc=$?\necho \"fold=$rc\"\n\
             [ \"$rc\" != 0 ] || { pa_incident_set && pa_incident_write; }",
            &env,
        );
        r.get("fold")
    };
    assert_eq!(fold("unit:propolis.service", "w#9"), "1", "no such parent");
    assert_eq!(
        fold("unit:propolis.service", "w#1"),
        "1",
        "not its own parent"
    );
    assert_eq!(fold("unit:propolis.service", "w#2"), "0");
    let f = the_record(&fx, "unit:propolis.service");
    assert_eq!(f[13], "w#2", "parent");
    assert_eq!(f[30], "folded", "flags");
    assert_eq!(f[19], "-", "no reminders");
    assert_eq!(f[29], "1", "folding sends nothing");
    assert_eq!(
        life(&fx, 3600, "remind", &[("KEY", "unit:propolis.service")]),
        "3 - -"
    );
    assert_eq!(
        life(
            &fx,
            3700,
            "change",
            &[
                ("KEY", "unit:propolis.service"),
                ("CAUSE", "db.unreachable")
            ]
        ),
        "0 occ -",
        "a folded child sends no change"
    );
    assert_eq!(
        life(
            &fx,
            3800,
            "resolve",
            &[("KEY", "unit:propolis.service"), ("PROOF", "active10")]
        ),
        "0 resolve -"
    );
    assert_eq!(the_record(&fx, "unit:propolis.service")[29], "1");
}

/// The first-sighting rule for a unit that restarts itself: systemd raises NRestarts after the
/// hook read it, so one healed restart is NRestarts n + 1 and is dropped; n + 2 means it failed
/// again. Under 60 s of uptime on one sample waits a pass; on two it opens. Not active opens.
#[test]
fn the_first_sighting_rule_drops_one_healed_restart_opens_a_second_and_waits_once_under_a_minute() {
    let fx = Fx::new();
    for (seen, nr, up, prev, want) in [
        ("4", "5", "300", "?", "drop"),
        ("4", "4", "300", "200", "drop"),
        ("4", "6", "300", "200", "open"),
        ("4", "5", "-", "300", "open"),
        ("4", "5", "20", "600", "wait"),
        ("4", "5", "20", "?", "wait"),
        ("4", "5", "20", "30", "open"),
        ("4", "5", "20", "-", "open"),
        ("-", "9", "300", "?", "drop"),
        ("-", "9", "20", "40", "open"),
        ("-", "9", "-", "?", "open"),
        ("4", "", "300", "?", "drop"),
        ("4", "5", "60", "30", "drop"),
    ] {
        let r = fx.run_env(
            "echo \"judge=$(pa_first_sighting \"$SEEN\" \"$NRN\" \"$UPF\" \"$PREV\")\"",
            &[("SEEN", seen), ("NRN", nr), ("UPF", up), ("PREV", prev)],
        );
        assert_eq!(
            r.get("judge"),
            want,
            "seen {seen} nr {nr} up {up} prev {prev}: {}",
            r.err
        );
    }
}

/// `--maint` writes the marker through the library: reason, end and boot, 0600, read back by
/// pa_maint_active; 0 removes it whatever wrote it; out-of-range values write nothing.
#[test]
fn pa_maint_write_writes_a_manual_marker_pa_maint_active_honours_and_zero_removes_it() {
    let fx = Fx::new();
    let r = fx.run_env(
        "umask 000; rc=0; pa_maint_write manual 30 || rc=$?; echo \"rc=$rc\"\n\
         pa_maint_active && echo \"active=$PA_MAINT_REASON $PA_MAINT_UNTIL\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("active"), "manual 1001800");
    let marker = fx.p("run/propolis-witness/maintenance");
    assert_eq!(
        fx.read("run/propolis-witness/maintenance"),
        "#maintenance v1 g=1\nX\t1001800\tabcdef01\tmanual\n"
    );
    assert_eq!(mode_of(&marker), 0o600);
    for bad in [
        ("manual", "121"),
        ("manual", "-1"),
        ("manual", "x"),
        ("party", "5"),
    ] {
        let r = fx.run_env(
            "rc=0; pa_maint_write \"$R\" \"$M\" || rc=$?; echo \"rc=$rc\"",
            &[NOW[0], NOW[1], NOW[2], ("R", bad.0), ("M", bad.1)],
        );
        assert_eq!(r.get("rc"), "2", "{bad:?}");
    }
    assert!(
        fx.read("run/propolis-witness/maintenance")
            .contains("1001800")
    );
    fx.write(
        "run/propolis-witness/maintenance",
        &maintenance_marker(1_003_600, "abcdef01", "upgrade"),
    );
    let r = fx.run_env(
        "rc=0; pa_maint_write manual 0 || rc=$?; echo \"rc=$rc\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0");
    assert!(!marker.exists(), "0 removes any marker");
    let r = fx.run_env(
        "rc=0; pa_maint_write manual 0 || rc=$?; echo \"rc=$rc\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "nothing to remove is not a failure");
    // Without a boot id the marker could never hold, so it is not written.
    let r = fx.run_env(
        "rc=0; pa_maint_write manual 5 || rc=$?; echo \"rc=$rc\"",
        &[NOW[0], ("PA_TEST_BOOT", "-"), NOW[2]],
    );
    assert_eq!(r.get("rc"), "1");
    assert!(!marker.exists());
}

/// Resolved records go seven days after their resolve and withheld lines after 48 hours; open,
/// acked and pending records always stay.
#[test]
fn pa_incident_prune_drops_week_old_resolved_records_and_two_day_old_withheld_lines() {
    let fx = Fx::salted(SALT);
    // Stamps of an earlier boot, so their ages come from the wall clock.
    let earlier = |wall: u64| format!("{wall}/12345678/5");
    let resolved_at = |line: String, wall: u64| {
        let mut f: Vec<String> = line.trim_end().split('\t').map(str::to_string).collect();
        f[21] = earlier(wall);
        f.join("\t") + "\n"
    };
    let withheld = |wall: u64| format!("W\t{}\tabcd1234\topen\t1\tu12345\tbudget\n", earlier(wall));
    let body = format!(
        "N\t9\n{}{}{}{}{}",
        record_line("w#1", "unit:a.service", "unit-failed", "open"),
        resolved_at(
            record_line("w#2", "unit:b.service", "unit-failed", "resolved"),
            1_000_000 - 604_801
        ),
        resolved_at(
            record_line("w#3", "unit:c.service", "unit-failed", "resolved"),
            1_000_000 - 604_000
        ),
        withheld(1_000_000 - 172_801),
        withheld(1_000_000 - 3600),
    );
    write_incidents(&fx, &body);
    let r = fx.run_env(
        "pa_now\npa_lock 5\npa_incident_load\npa_incident_prune\npa_incident_write; echo \"rc=$?\"\npa_unlock",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let text = fx.read("var/lib/propolis/witness/incidents");
    let ids: Vec<String> = incident_records(&text)
        .iter()
        .map(|f| f[1].clone())
        .collect();
    assert_eq!(ids, ["w#1", "w#3"], "{text}");
    assert_eq!(w_walls(&text), vec![1_000_000 - 3600], "{text}");
}

/// The banner file is replaced whole, mode 0600 whatever the umask, and leaves no temporary file.
#[test]
fn pa_banner_write_replaces_the_banner_whole_with_mode_0600() {
    let fx = Fx::salted(SALT);
    std::fs::create_dir_all(fx.p("run/motd.d")).unwrap();
    let r = fx.run_env(
        "umask 000; rc=0; pa_banner_write || rc=$?; echo \"rc=$rc\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let banner = fx.p("run/motd.d/propolis");
    assert_eq!(mode_of(&banner), 0o600);
    let text = fx.read("run/motd.d/propolis");
    assert_eq!(text.lines().count(), 4, "{text}");
    assert!(text.starts_with("[propolis 13:46 UTC] "), "{text}");
    let left: Vec<_> = std::fs::read_dir(fx.p("run/motd.d"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["propolis"], "no temporary file is left");

    std::fs::remove_dir_all(fx.p("run/motd.d")).unwrap();
    let r = fx.run_env("rc=0; pa_banner_write || rc=$?; echo \"rc=$rc\"", &NOW);
    assert_eq!(r.get("rc"), "1", "a missing directory is not created");
    assert!(!fx.p("run/motd.d").exists());
}

/// A banner line longer than 78 bytes would wrap on a terminal and push the next one out of
/// sight; it is replaced by `(line withheld)`, and the lines around it stay.
#[test]
fn a_banner_line_past_78_bytes_is_withheld_and_the_others_kept() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(
        "_pa_undelivered_count() { printf '%s' 123456789012345678; }\npa_banner",
        &NOW,
    );
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines.len(), 4, "{}\n{}", r.out, r.err);
    assert_eq!(lines[2], "[propolis 13:46 UTC] (line withheld)");
    assert!(
        lines[1].starts_with("[propolis 13:46 UTC] alerts: "),
        "{}",
        r.out
    );
    assert!(lines.iter().all(|l| l.len() <= 78), "{}", r.out);
}

// ---- the anonymous-read check and the gate ------------------------------------------------------

/// The read check's target in these cases, and the first 16 hex of sha256(URL LF TOPIC LF).
const RC_URL: &str = "https://ntfy.invalid";
const RC_TOPIC: &str = "t0p1c-secret";
const RC_TOKEN: &str = "tk_s3cret-value";
const RC_BINDING: &str = "74f3449395001972";
const RC_BINDING_HTTP: &str = "24be4e16a628c14e";

/// Records its argv and its environment, then answers the URL named in the `-K` config file from
/// `RC_JSON`, `RC_RAW` or `RC_SSE` (by endpoint) or `RC_TOKEN_ANSWER` (when a `-H @file` header
/// file with content is given), each `code|content type|body`: the body goes to the `-o` file and
/// the code and type to stdout in the `-w` form asked for. A host other than ntfy.invalid makes
/// it exit 7 and log `bad host`.
const CURL_RC_STUB: &str = r#"#!/usr/bin/env bash
{ printf 'curl'; printf ' [%s]' "$@"; printf '\n'; env | sed 's/^/env /'; } >> "$STUB_LOG"
conf="" hdr="" out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -K) conf="$2"; shift ;;
        -H) hdr="${2#@}"; shift ;;
        -o) out="$2"; shift ;;
    esac
    shift
done
url="$(sed -n 's/^url = "\(.*\)"$/\1/p' "$conf")"
case "$url" in
    https://ntfy.invalid/* | http://ntfy.invalid/*) ;;
    *) echo "bad host" >> "$STUB_LOG"; exit 7 ;;
esac
ep="${url##*/}"
ep="${ep%%\?*}"
if [ -n "${MODES_LOG:-}" ]; then
    for f in "$conf" "$out" ${hdr:+"$hdr"}; do stat -c %a -- "$f" >> "$MODES_LOG"; done
fi
if [ -n "$hdr" ] && [ -s "$hdr" ]; then
    grep -q '^Authorization: Bearer ' "$hdr" && echo "header file holds the token" >> "$STUB_LOG"
    v="${RC_TOKEN_ANSWER:-}"
else
    case "$ep" in json) v="${RC_JSON:-}" ;; raw) v="${RC_RAW:-}" ;; sse) v="${RC_SSE:-}" ;; esac
fi
IFS='|' read -r code ct body <<< "$v"
printf '%b' "$body" > "$out"
printf '%s\t%s' "$code" "$ct"
"#;

impl Fx {
    fn with_curl(&self) {
        write_exec(&self.bin.join("curl"), CURL_RC_STUB);
    }
}

/// One answer of each row of the classification table, through pa_readcheck_class: the status
/// code, the content type up to its `;`, and for json whether the body is ntfy's.
#[test]
fn pa_readcheck_class_follows_every_row_of_the_classification_table() {
    let fx = Fx::new();
    let d = fx.scratch();
    std::fs::write(d.join("empty"), "").unwrap();
    std::fs::write(
        d.join("ntfy"),
        "{\"id\":\"a1\",\"time\":1}\n{\"id\":\"b2\",\"time\":2}\n",
    )
    .unwrap();
    std::fs::write(d.join("html"), "<html>sign in</html>\n").unwrap();
    std::fs::write(
        d.join("big"),
        format!("{{\"id\":\"{}\"}}\n", "x".repeat(70_000)),
    )
    .unwrap();
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        ("json", "401", "", "empty", "refused"),
        ("raw", "403", "text/html", "html", "refused"),
        (
            "json",
            "200",
            "application/x-ndjson; charset=utf-8",
            "empty",
            "readable",
        ),
        ("json", "200", "application/json", "ntfy", "readable"),
        ("json", "200", "Application/X-NDJSON", "ntfy", "readable"),
        ("json", "200", "application/x-ndjson", "html", "not_ntfy"),
        ("json", "200", "application/x-ndjson", "big", "not_ntfy"),
        (
            "json",
            "200",
            "text/html; charset=utf-8",
            "empty",
            "not_ntfy",
        ),
        (
            "raw",
            "200",
            "text/plain; charset=utf-8",
            "html",
            "readable",
        ),
        ("raw", "200", "application/json", "empty", "not_ntfy"),
        ("sse", "200", "text/event-stream", "html", "readable"),
        ("sse", "200", "text/plain", "empty", "not_ntfy"),
        ("json", "301", "", "empty", "redirect"),
        ("json", "302", "", "empty", "redirect"),
        ("json", "303", "", "empty", "redirect"),
        ("json", "307", "", "empty", "redirect"),
        ("json", "308", "", "empty", "redirect"),
        ("json", "404", "", "empty", "not_found"),
        ("json", "429", "", "empty", "transient"),
        ("json", "500", "", "empty", "transient"),
        ("json", "503", "", "empty", "transient"),
        ("json", "000", "", "empty", "transient"),
        ("json", "204", "", "empty", "unexpected"),
        ("json", "418", "", "empty", "unexpected"),
        ("json", "xxx", "", "empty", "unexpected"),
        ("json", "20", "", "empty", "unexpected"),
    ];
    for (ep, code, ct, body, want) in cases {
        let r = fx.run_env(
            &format!("echo \"class=$(pa_readcheck_class '{ep}' '{code}' '{ct}' \"$D/{body}\")\""),
            &[],
        );
        assert_eq!(
            r.get("class"),
            *want,
            "{ep} {code} {ct:?} {body}: {}",
            r.err
        );
    }
}

/// pa_readcheck_run combines the three answers: any transient makes the attempt transient, three
/// refusals make it refused, and otherwise it takes the class of the first answer that was not
/// refused. The token check sorts the token into reads, noread or unknown, and is not made
/// without a token.
#[test]
fn pa_readcheck_run_combines_the_three_answers_and_classifies_the_token() {
    let fx = Fx::new();
    fx.with_curl();
    let script = format!(
        "pa_readcheck_run '{RC_URL}' '{RC_TOPIC}' \"$TOKEN\"\n\
         echo \"class=$PA_RC_CLASS\"; echo \"codes=$PA_RC_JSON/$PA_RC_RAW/$PA_RC_SSE\"\n\
         echo \"token=$PA_RC_TOKEN\"; echo \"cause=$PA_RC_CAUSE\""
    );
    let deny = "403|text/plain|forbidden";
    let ndjson = "200|application/x-ndjson|";
    let cases: &[(&str, &str, &str, &str, &str, &str)] = &[
        (deny, deny, deny, "", "refused", "-"),
        (deny, "503||", deny, "", "transient", "-"),
        ("000||", deny, deny, "", "transient", "-"),
        (deny, "200|text/plain|", "302||", "", "readable", "-"),
        (deny, "302||", "200|text/event-stream|", "", "redirect", "-"),
        (ndjson, deny, deny, "", "readable", "-"),
        ("200|text/html|<form>", deny, deny, "", "not_ntfy", "-"),
        ("404||", "404||", "404||", "", "not_found", "-"),
        (deny, deny, "418||", "", "unexpected", "-"),
        (deny, deny, deny, RC_TOKEN, "refused", "reads"),
    ];
    for (json, raw, sse, token, class, tok) in cases {
        let r = fx.run_env(
            &script,
            &[
                ("RC_JSON", json),
                ("RC_RAW", raw),
                ("RC_SSE", sse),
                ("RC_TOKEN_ANSWER", ndjson),
                ("TOKEN", token),
            ],
        );
        assert_eq!(r.get("class"), *class, "{json} {raw} {sse}: {}", r.err);
        assert_eq!(r.get("token"), *tok, "{json} {raw} {sse}");
        assert_eq!(r.get("cause"), "-");
    }
    let r = fx.run_env(
        &script,
        &[
            ("RC_JSON", deny),
            ("RC_RAW", deny),
            ("RC_SSE", deny),
            ("RC_TOKEN_ANSWER", "401||"),
            ("TOKEN", RC_TOKEN),
        ],
    );
    assert_eq!(r.get("token"), "noread");
    assert_eq!(r.get("codes"), "403/403/403");
    let r = fx.run_env(
        &script,
        &[
            ("RC_JSON", deny),
            ("RC_RAW", deny),
            ("RC_SSE", deny),
            ("RC_TOKEN_ANSWER", "200|text/html|<p>"),
            ("TOKEN", RC_TOKEN),
        ],
    );
    assert_eq!(r.get("token"), "unknown");
    let calls = fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    assert_eq!(
        calls,
        3 * 9 + 4 * 3,
        "three GETs each, a fourth with a token"
    );
    assert!(!fx.log().contains("bad host"), "{}", fx.log());
    // -q first, so no .curlrc can add to the request; https or http only; no redirect followed.
    for call in fx.log().lines().filter(|l| l.starts_with("curl ")) {
        assert!(call.starts_with("curl [-q] "), "{call}");
        assert!(call.contains(" [--proto] [=https,http]"), "{call}");
        assert!(
            !call.contains("[-L]") && !call.contains("[--location"),
            "{call}"
        );
    }
}

/// The topic and the token are secrets: they reach curl through files (a config file for the
/// URL, a header file for the token), never through its arguments or its environment; the files
/// are 0600 while they exist and are gone when the check returns; and nothing the check prints
/// names them or carries the answer's body.
#[test]
fn the_read_check_never_puts_the_topic_or_the_token_on_a_command_line_or_in_an_environment() {
    let fx = Fx::new();
    fx.with_curl();
    let probe = fx.scratch().join("modes");
    let tmp = fx.scratch().join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let r = fx.run_env(
        &format!(
            "PA_TOKEN='{RC_TOKEN}'\n\
             pa_readcheck_run '{RC_URL}' '{RC_TOPIC}' '{RC_TOKEN}'; echo \"class=$PA_RC_CLASS\""
        ),
        &[
            ("MODES_LOG", probe.to_str().unwrap()),
            ("TMPDIR", tmp.to_str().unwrap()),
            (
                "RC_JSON",
                "200|application/x-ndjson|{\"id\":\"zzz-body-marker\"}",
            ),
            ("RC_RAW", "403||"),
            ("RC_SSE", "403||"),
            ("RC_TOKEN_ANSWER", "401||"),
        ],
    );
    assert_eq!(r.get("class"), "readable", "{}", r.err);
    let log = fx.log();
    assert!(log.contains("header file holds the token"), "{log}");
    for secret in [RC_TOPIC, RC_TOKEN] {
        assert!(
            !log.contains(secret),
            "{secret} reached curl's argv or environment: {log}"
        );
    }
    for secret in [RC_TOPIC, RC_TOKEN, "zzz-body-marker"] {
        assert!(
            !r.out.contains(secret) && !r.err.contains(secret),
            "{secret} printed"
        );
    }
    let modes = std::fs::read_to_string(&probe).unwrap();
    assert!(
        !modes.is_empty() && modes.lines().all(|m| m == "600"),
        "every file curl was handed is 0600: {modes}"
    );
    let left: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
    assert!(left.is_empty(), "temporary files left: {left:?}");
}

/// Without curl the check cannot run: the attempt is transient (it never counts as an answer)
/// with the cause tool.exec.
#[test]
fn a_read_check_without_curl_is_transient_with_the_cause_tool_exec() {
    let fx = Fx::new();
    let r = fx.run_env(
        &format!(
            "PATH=/nonexistent\nrc=0; pa_readcheck_run '{RC_URL}' '{RC_TOPIC}' '' || rc=$?\n\
             echo \"rc=$rc class=$PA_RC_CLASS cause=$PA_RC_CAUSE\""
        ),
        &[],
    );
    assert!(
        r.out.contains("rc=1 class=transient cause=tool.exec"),
        "{}{}",
        r.out,
        r.err
    );
}

/// A transient attempt with the same binding changes only the attempt fields, so a 503 never
/// undoes a definite refusal; a definite answer replaces both; a new binding replaces the line.
#[test]
fn pa_readcheck_merge_keeps_a_definite_answer_through_a_transient_attempt() {
    let fx = Fx::new();
    let old = format!(
        "#readcheck v1 g=3\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\tnoread\t403\t403\tboth\t403\n"
    );
    fx.write("var/lib/propolis/witness/readcheck", &old);
    let merge = |class: &str, binding: &str| {
        fx.run_env(
            &format!(
                "pa_now; have=0; _pa_rc_line shell && have=1\n\
                 PA_RC_CLASS={class} PA_RC_TOKEN=- PA_RC_JSON=503 PA_RC_RAW=403 PA_RC_SSE=403\n\
                 pa_readcheck_merge both {binding} \"$have\""
            ),
            &NOW,
        )
        .out
    };
    assert_eq!(
        merge("transient", RC_BINDING),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\ttransient\t999000/abcdef01/4000\trefused\tnoread\t403\t403\tboth\t403\n"
        )
    );
    assert_eq!(
        merge("readable", RC_BINDING),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\treadable\t1000000/abcdef01/5000\treadable\t-\t503\t403\tboth\t403\n"
        )
    );
    assert_eq!(
        merge("transient", RC_BINDING_HTTP),
        format!(
            "R\t{RC_BINDING_HTTP}\t1000000/abcdef01/5000\ttransient\t-\t-\t-\t503\t403\tboth\t403\n"
        )
    );
}

/// A token GET that got no answer (a timeout, a 429 or a 5xx leaves the token class unknown) never
/// undoes a proven `reads`, even when the three anonymous GETs of the same attempt were definite:
/// the merged line keeps `reads`, and the gate on a collector stays pointer:token-reads.
#[test]
fn a_token_get_without_an_answer_keeps_a_stored_reads_and_the_collector_gate_stays_pointer() {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN={RC_TOKEN}\n"
        ),
    );
    let fp = format!("token:{}", fx.run(&format!("pa_token8 {RC_TOKEN}")).out);
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=3\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\treads\t403\t403\tboth\t403\t{fp}\n"
        ),
    );
    let r = fx.run_env(
        &format!(
            "pa_now; have=0; _pa_rc_line shell && have=1\n\
             PA_RC_CLASS=refused PA_RC_TOKEN=unknown PA_RC_JSON=403 PA_RC_RAW=403 PA_RC_SSE=403\n\
             line=\"$(pa_readcheck_merge both {RC_BINDING} \"$have\" {fp})\"\n\
             echo \"line=$line\"\n\
             printf '#readcheck v1 g=4\\n%s\\n' \"$line\" > \"$PA_STATE/readcheck\"\n\
             pa_settings_load; PA_ROLE=collector; echo \"gate=$(pa_gate)\""
        ),
        &NOW,
    );
    assert_eq!(
        r.get("line"),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\trefused\t1000000/abcdef01/5000\trefused\treads\t403\t403\tboth\t403\t{fp}"
        ),
        "{}",
        r.err
    );
    assert_eq!(r.get("gate"), "pointer:token-reads", "{}", r.err);
}

/// Each rule of the gate, with one case that passes it (the gate goes on to the next rule, and
/// the last case is full) and one that fails it with its reason word.
#[test]
fn pa_gate_gives_full_only_when_every_rule_holds_and_names_the_rule_that_failed() {
    let fx = Fx::new();
    let line = |binding: &str, astamp: &str, dstamp: &str, dclass: &str, token: &str| {
        format!(
            "#readcheck v1 g=1\nR\t{binding}\t{astamp}\ttransient\t{dstamp}\t{dclass}\t{token}\t403\t403\tboth\t403\n"
        )
    };
    let fresh = "999000/abcdef01/4000";
    let gate = |env_file: &str, readcheck: Option<&str>, extra: &str| {
        fx.write("etc/propolis/propolis.env", env_file);
        match readcheck {
            Some(r) => fx.write("var/lib/propolis/witness/readcheck", r),
            None => {
                let _ = std::fs::remove_file(fx.p("var/lib/propolis/witness/readcheck"));
            }
        }
        fx.run_env(
            &format!("pa_settings_load; {extra}\necho \"gate=$(pa_gate)\""),
            &NOW,
        )
        .get("gate")
    };
    let https = format!("PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n");
    let http =
        format!("PROPOLIS_OPS_NTFY_URL=http://ntfy.invalid\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n");
    let good = line(RC_BINDING, fresh, fresh, "refused", "noread");
    // Rule 1: a target.
    assert_eq!(gate("", Some(&good), ""), "none:notarget");
    // Rule 2: the detail setting.
    assert_eq!(
        gate(&https, Some(&good), "PA_DETAIL=pointer"),
        "pointer:detail-pointer"
    );
    // Rule 3: a stored line, bound to this target.
    assert_eq!(gate(&https, None, ""), "pointer:never");
    assert_eq!(
        gate(
            &https,
            Some(&line(RC_BINDING_HTTP, fresh, fresh, "refused", "-")),
            ""
        ),
        "pointer:unbound"
    );
    // Rule 4: a definite refusal.
    assert_eq!(
        gate(&https, Some(&line(RC_BINDING, fresh, "-", "-", "-")), ""),
        "pointer:never"
    );
    for class in [
        "readable",
        "not_ntfy",
        "redirect",
        "not_found",
        "unexpected",
    ] {
        assert_eq!(
            gate(
                &https,
                Some(&line(RC_BINDING, fresh, fresh, class, "-")),
                ""
            ),
            format!("pointer:{class}")
        );
    }
    assert_eq!(
        gate(
            &https,
            Some(&line(RC_BINDING, fresh, fresh, "bogus", "-")),
            ""
        ),
        "pointer:unexpected"
    );
    // Rule 5: decided within 24 h, and not in the future.
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                fresh,
                "913000/0000aaaa/1",
                "refused",
                "-"
            )),
            ""
        ),
        "pointer:stale"
    );
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                fresh,
                "1000000/abcdef01/6000",
                "refused",
                "-"
            )),
            ""
        ),
        "pointer:stale"
    );
    // Rule 6: an attempt within 3 h.
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                "980000/0000aaaa/1",
                fresh,
                "refused",
                "-"
            )),
            ""
        ),
        "pointer:stale"
    );
    // An attempt dated ahead of the clock in this boot is no proof the checker is alive; the
    // bound itself is inclusive: 10800 s passes, 10801 s does not.
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                "1000000/abcdef01/6000",
                fresh,
                "refused",
                "-"
            )),
            ""
        ),
        "pointer:stale"
    );
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                "989200/0000aaaa/1",
                fresh,
                "refused",
                "-"
            )),
            ""
        ),
        "full"
    );
    assert_eq!(
        gate(
            &https,
            Some(&line(
                RC_BINDING,
                "989199/0000aaaa/1",
                fresh,
                "refused",
                "-"
            )),
            ""
        ),
        "pointer:stale"
    );
    // Rule 7: on a collector, a token that cannot read the topic. The stored answer is the one
    // about the token configured now.
    let https = format!("{https}PROPOLIS_OPS_NTFY_TOKEN={RC_TOKEN}\n");
    fx.write("var/lib/propolis/witness/id-salt", &format!("{SALT}\n"));
    let fp = format!("token:{}", fx.run(&format!("pa_token8 {RC_TOKEN}")).out);
    let reads = line(RC_BINDING, fresh, fresh, "refused", "reads")
        .replace("\t403\n", &format!("\t403\t{fp}\n"));
    assert_eq!(
        gate(&https, Some(&reads), "PA_ROLE=collector"),
        "pointer:token-reads"
    );
    assert_eq!(gate(&https, Some(&reads), "PA_ROLE=single"), "full");
    // The gate finds the role itself when its caller has not set one, so a collector is never
    // taken for another host because nobody said so; a host whose role cannot be told (systemd
    // not answering here) is held to the collector's rule.
    write_exec(&fx.bin.join("systemctl"), "#!/usr/bin/env bash\nexit 1\n");
    fx.write(
        "etc/propolis/shipper.env",
        "SHIPPER_GATEWAY=gw.invalid:8443\n",
    );
    assert_eq!(
        gate(&https, Some(&reads), "unset PA_ROLE"),
        "pointer:token-reads",
        "a collector, with no role set by the caller"
    );
    std::fs::remove_file(fx.p("etc/propolis/shipper.env")).unwrap();
    assert_eq!(
        gate(&https, Some(&reads), "unset PA_ROLE"),
        "pointer:token-reads",
        "a host whose role cannot be told"
    );
    assert_eq!(
        gate(
            &https,
            Some(
                &line(RC_BINDING, fresh, fresh, "refused", "noread")
                    .replace("\t403\n", &format!("\t403\t{fp}\n"))
            ),
            "unset PA_ROLE"
        ),
        "full",
        "the role matters only when the token is not proven unable to read"
    );
    // Rule 8: https.
    assert_eq!(
        gate(
            &http,
            Some(&line(RC_BINDING_HTTP, fresh, fresh, "refused", "-")),
            ""
        ),
        "pointer:insecure"
    );
    let good = good.replace("\t403\n", &format!("\t403\t{fp}\n"));
    assert_eq!(gate(&https, Some(&good), ""), "full");
}

/// pa_finding_inst recovers a finding's instance only by matching: a unit by the hash of
/// `<id>:<unit>`, a listener by its row's scope, a log by the hash of `<id>:<path>`; a finding it
/// cannot place gives nothing, and no name that fails the checks is printed.
#[test]
fn pa_finding_inst_matches_units_scopes_and_log_paths_and_otherwise_gives_nothing() {
    let fx = Fx::new();
    let k12 = |s: &str| {
        let r = fx.run_raw(&format!("printf '%s' '{s}' | sha256sum | cut -c1-12"), &[]);
        r.out.trim().to_string()
    };
    let unit_k = k12("unit-down:sensor-ssh");
    let log_k = k12("intake-wrongpath:/var/log/propolis/ssh/events.jsonl");
    let r = fx.run_env(
        &format!(
            "PA_FI_UNITS=(sensor-http sensor-ssh)\n\
             PA_FI_SCOPE=(ssh/tcp 'x/y') PA_FI_UNIT=(sensor-ssh 'bad unit')\n\
             pa_sensor_logs 'ssh:/var/log/propolis/ssh/events.jsonl,http:/var/log/propolis/http/events.jsonl'\n\
             echo \"a=$(pa_finding_inst unit unit-down {unit_k} sensor-ssh)\"\n\
             echo \"b=$(pa_finding_inst unit unit-down 000000000000 sensor-ssh)\"\n\
             echo \"c=$(pa_finding_inst scope listen-none - ssh/tcp)\"\n\
             echo \"d=$(pa_finding_inst scope listen-none - x/y)\"\n\
             echo \"e=$(pa_finding_inst logpath intake-wrongpath {log_k} ssh/tcp)\"\n\
             echo \"f=$(pa_finding_inst logpath intake-absent {log_k} ssh/tcp)\"\n\
             echo \"g=$(pa_finding_inst unit unit-down 'not-hex' sensor-ssh)\""
        ),
        &[],
    );
    assert_eq!(r.get("a"), "unit\tsensor-ssh.service", "{}", r.err);
    assert_eq!(r.get("b"), "");
    assert_eq!(r.get("c"), "unit\tsensor-ssh.service");
    assert_eq!(
        r.get("d"),
        "",
        "a unit name that is not one is never printed"
    );
    assert_eq!(r.get("e"), "source\tssh");
    assert_eq!(r.get("f"), "", "another finding's hash does not match");
    assert_eq!(r.get("g"), "");
}

/// The banner's alert part follows the stored read check of the target in use: READABLE for a
/// definite answer other than refused (the shell's or the daemon's), whether a test page got
/// through (VERIFIED or NOT VERIFIED) for a refusal, and not checked yet for no answer or one
/// bound to another target.
#[test]
fn the_banner_says_readable_refuses_or_not_checked_from_the_stored_read_check() {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n"),
    );
    let alerts = |readcheck: Option<String>| {
        match readcheck {
            Some(r) => fx.write("var/lib/propolis/witness/readcheck", &r),
            None => {
                let _ = std::fs::remove_file(fx.p("var/lib/propolis/witness/readcheck"));
            }
        }
        let r = fx.run_env("pa_banner", &NOW);
        r.out.lines().nth(1).unwrap_or_default().to_string()
    };
    let line = |binding: &str, class: &str| {
        Some(format!(
            "#readcheck v1 g=1\nR\t{binding}\t999000/abcdef01/4000\t{class}\t999000/abcdef01/4000\t{class}\t-\t403\t403\tboth\t403\n"
        ))
    };
    assert_eq!(
        alerts(None),
        "[propolis 13:46 UTC] alerts: topic not checked yet"
    );
    assert_eq!(
        alerts(line(RC_BINDING, "refused")),
        "[propolis 13:46 UTC] alerts: NOT VERIFIED (never)",
        "a proven refusal leaves whether a test page got through to say"
    );
    assert_eq!(
        alerts(line(RC_BINDING, "readable")),
        "[propolis 13:46 UTC] alerts: topic READABLE by anyone"
    );
    assert_eq!(
        alerts(line(RC_BINDING_HTTP, "readable")),
        "[propolis 13:46 UTC] alerts: topic not checked yet",
        "a result for another target says nothing about this one"
    );
}

/// The banner claims a refusal only where the gate holds it proven. A refusal decided over a day
/// ago, or a checker whose last attempt is over three hours old, reads `topic check is stale`,
/// and a refusal over plain HTTP (which anyone on the path could have answered) reads `topic not
/// proven private (plain http)`: a check did run in each case, so `not checked yet` would be
/// untrue. A fresh refusal over https goes on to whether a test page got through, and so does
/// one on a collector whose token can read, since the anonymous refusal itself is proven there.
#[test]
fn the_banner_claims_a_refusal_only_when_the_gate_holds_it_proven() {
    let fx = Fx::salted(SALT);
    let https = format!("PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n");
    let http =
        format!("PROPOLIS_OPS_NTFY_URL=http://ntfy.invalid\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n");
    let alerts = |env_file: &str, binding: &str, astamp: &str, dstamp: &str, token: &str| {
        fx.write("etc/propolis/propolis.env", env_file);
        fx.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=1\nR\t{binding}\t{astamp}\trefused\t{dstamp}\trefused\t{token}\t403\t403\tboth\t403\n"
            ),
        );
        let r = fx.run_env("PA_ROLE=collector; pa_banner", &NOW);
        r.out.lines().nth(1).unwrap_or_default().to_string()
    };
    let fresh = "999000/abcdef01/4000";
    let refuses = "[propolis 13:46 UTC] alerts: NOT VERIFIED (never)";
    let stale = "[propolis 13:46 UTC] alerts: topic check is stale";
    let plain = "[propolis 13:46 UTC] alerts: topic not proven private (plain http)";
    assert_eq!(alerts(&https, RC_BINDING, fresh, fresh, "-"), refuses);
    assert_eq!(
        alerts(&https, RC_BINDING, fresh, fresh, "reads"),
        refuses,
        "a token that reads does not undo the anonymous refusal"
    );
    assert_eq!(
        alerts(&https, RC_BINDING, fresh, "910000/0000aaaa/1", "-"),
        stale,
        "a refusal decided 25 h ago"
    );
    assert_eq!(
        alerts(&https, RC_BINDING, "989199/0000aaaa/1", fresh, "-"),
        stale,
        "a last attempt 3 h 1 s ago"
    );
    assert_eq!(
        alerts(&http, RC_BINDING_HTTP, fresh, fresh, "-"),
        plain,
        "a refusal over plain HTTP proves nothing"
    );
}

/// One GiB, in bytes.
const GIB: u64 = 1_073_741_824;

/// Runs `pa_vol_project` at NOW (wall 1_000_000) on samples of another boot, so their ages come
/// from the wall clock, given as `(hours before NOW, free bytes)`, and prints the three results.
fn project(fx: &Fx, samples: &[(u64, u64)], now_avail: u64) -> (String, String, String) {
    let input: String = samples
        .iter()
        .map(|(h, a)| format!("{}/0000aaaa/1\t{a}\n", 1_000_000 - h * 3600))
        .collect();
    fx.write("input", &input);
    let r = fx.run_env(
        &format!(
            "pa_vol_project 1000000/abcdef01/5000 {now_avail} < \"$ROOT/input\"; echo \"rc=$?\"\n\
             echo \"span=$PA_VOL_SPAN\"; echo \"rate=$PA_VOL_RATE\"; echo \"hours=$PA_VOL_HOURS\""
        ),
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    (r.get("span"), r.get("rate"), r.get("hours"))
}

/// A volume's projection needs samples over 72 hours and a free space that fell over that span:
/// 71 hours of a steady fall of 1 GiB an hour give none, 73 hours give 19 hours to the last GiB of
/// 20, and a week in which the free space grew gives none whatever the last day did.
#[test]
fn the_projection_needs_seventy_two_hours_of_samples_and_a_positive_seven_day_rate() {
    let fx = Fx::new();
    let falling =
        |hours: u64| -> Vec<(u64, u64)> { (1..=hours).map(|h| (h, (20 + h) * GIB)).collect() };
    let (span, rate, hours) = project(&fx, &falling(71), 20 * GIB);
    assert_eq!(
        (span.as_str(), rate.as_str(), hours.as_str()),
        ("255600", "-", "-")
    );
    let (_, rate, hours) = project(&fx, &falling(73), 20 * GIB);
    assert_eq!((rate.as_str(), hours.as_str()), ("1048576", "19"));
    // Six days of growth, then a fall of 5 GiB in the last day: the week still grew.
    let mut grew: Vec<(u64, u64)> = (25..=168).map(|h| (h, 10 * GIB)).collect();
    grew.extend((1..=24).map(|h| (h, 25 * GIB + h * GIB / 5)));
    let (_, rate, hours) = project(&fx, &grew, 25 * GIB);
    assert_eq!((rate.as_str(), hours.as_str()), ("-", "-"));
}

/// A nightly backup writes a set and prunes the oldest, so the free space dips for an hour and
/// comes back: over a week that is no fall at all, though a sample of the last day dipped. A step
/// that stays (the first set, or a one-off copy) on a roomy volume projects nothing near.
#[test]
fn a_nightly_backup_is_a_step_and_not_a_trend() {
    let fx = Fx::new();
    let sawtooth: Vec<(u64, u64)> = (1..=168)
        .map(|h| (h, if h % 24 == 5 { 28 * GIB } else { 30 * GIB }))
        .collect();
    let (_, rate, hours) = project(&fx, &sawtooth, 30 * GIB);
    assert_eq!((rate.as_str(), hours.as_str()), ("-", "-"));
    let step: Vec<(u64, u64)> = (1..=168)
        .map(|h| (h, if h <= 3 { 28 * GIB } else { 30 * GIB }))
        .collect();
    let (_, _, hours) = project(&fx, &step, 28 * GIB);
    let hours: u64 = hours.parse().unwrap();
    assert!(
        hours > 72,
        "a 2 GiB step with 28 GiB free projected {hours} h"
    );
}

/// A host that was off for a day: three days of samples end over a day before NOW. The fall of
/// 24 GiB is spread over the 96 hours that really passed (80 hours to the last GiB of 21, no
/// trigger), not over the 72 samples, which would have made it about 60.
#[test]
fn a_host_that_was_off_for_a_day_measures_the_fall_over_the_time_that_passed() {
    let fx = Fx::new();
    let gap: Vec<(u64, u64)> = (25..=96).map(|h| (h, 21 * GIB + h * GIB / 4)).collect();
    let (span, rate, hours) = project(&fx, &gap, 21 * GIB);
    assert_eq!(
        (span.as_str(), rate.as_str(), hours.as_str()),
        ("345600", "262144", "80")
    );
    let r = fx.run(&format!(
        "pa_vol_judge {} {} 1000 900 15 80; echo \"c=$PA_VOL_C soon=$PA_VOL_SOON\"",
        200 * GIB,
        21 * GIB
    ));
    assert_eq!(r.get("c"), "0 soon=0");
}

/// The triggers of one sample: a filesystem that reports no inodes (btrfs) has no inode trigger,
/// a free share under the setting is filling, under 1.5 GiB free or 2% of the inodes is full soon,
/// sizes past 2^53 are judged without overflow, and a number of more than 18 digits is unknown and
/// never a trigger.
#[test]
fn a_filesystem_that_reports_no_inodes_has_no_inode_trigger() {
    let fx = Fx::new();
    let judge = |args: &str| -> String {
        let r = fx.run(&format!(
            "pa_vol_judge {args}; echo \"r=$? $PA_VOL_A$PA_VOL_B$PA_VOL_C$PA_VOL_SOON $PA_VOL_CAUSE\""
        ));
        r.get("r")
    };
    let big = 100 * GIB;
    assert_eq!(judge(&format!("{big} {} 0 0 15 -", 50 * GIB)), "0 0000 -");
    assert_eq!(
        judge(&format!("{big} {} 1000 50 15 -", 50 * GIB)),
        "0 0100 vol.inodes"
    );
    assert_eq!(
        judge(&format!("{big} {} 1000 10 15 -", 50 * GIB)),
        "0 0101 vol.inodes"
    );
    assert_eq!(
        judge(&format!("{big} {} 0 0 15 -", 10 * GIB)),
        "0 1000 vol.low"
    );
    assert_eq!(judge(&format!("{big} {} 0 0 15 -", GIB)), "0 1001 vol.low");
    assert_eq!(
        judge(&format!("{big} {} 0 0 15 40", 50 * GIB)),
        "0 0010 vol.projected"
    );
    assert_eq!(
        judge(&format!("{big} {} 0 0 15 11", 50 * GIB)),
        "0 0011 vol.projected"
    );
    assert_eq!(
        judge("900000000000000000 100000000000000000 0 0 15 -"),
        "0 1000 vol.low"
    );
    assert_eq!(judge("9000000000000000000 1 0 0 15 -"), "2 0000 -");
    assert_eq!(
        judge(&format!("{big} {} 0 0 15 soon", 50 * GIB)),
        "2 0000 -"
    );
}

/// The floor of a gibibyte and a half free is a size, and a filesystem smaller than about that is
/// under it even when empty: such a store is full soon only when it is also under half free, so
/// a small dedicated volume with room is not a standing page.
#[test]
fn a_small_filesystem_that_is_mostly_free_is_not_full_soon() {
    let fx = Fx::new();
    let judge = |args: &str| -> String {
        let r = fx.run(&format!(
            "pa_vol_judge {args}; echo \"r=$? $PA_VOL_A$PA_VOL_B$PA_VOL_C$PA_VOL_SOON $PA_VOL_CAUSE\""
        ));
        r.get("r")
    };
    let mib = GIB / 1024;
    // 1 GiB, 900 MiB free: under the floor, mostly free.
    assert_eq!(judge(&format!("{GIB} {} 0 0 15 -", 900 * mib)), "0 0000 -");
    // 2 GiB, 800 MiB free: under the floor and under half free.
    assert_eq!(
        judge(&format!("{} {} 0 0 15 -", 2 * GIB, 800 * mib)),
        "0 0001 vol.low"
    );
    // 1 GiB, 100 MiB free: short of its share as well.
    assert_eq!(
        judge(&format!("{GIB} {} 0 0 15 -", 100 * mib)),
        "0 1001 vol.low"
    );
    // A large one under the floor, as before.
    assert_eq!(
        judge(&format!("{} {GIB} 0 0 15 -", 100 * GIB)),
        "0 1001 vol.low"
    );
}

/// The rate `pa_vol_project` reaches from the free space `then` and `now` (bytes) `secs` apart, in
/// KiB an hour, as it computes it.
fn kib_rate(then: u64, now: u64, secs: u64) -> u64 {
    (then / 1024 - now / 1024) * 3600 / secs
}

/// The projection takes the larger of the week's rate and the last day's: a week falling 0.1
/// GiB an hour, then 1 GiB an hour over the last 20 hours, projects at the last day's rate. The
/// last day's rate counts only over at least 12 hours of samples: with only the last 2 hours in
/// the day, the week's rate stands.
#[test]
fn the_projection_takes_the_last_day_s_rate_when_faster_and_only_over_twelve_hours() {
    let fx = Fx::new();
    let tenth = GIB / 10;
    let now = 100 * GIB;
    let at = |h: u64| -> u64 {
        if h <= 20 {
            now + h * GIB
        } else {
            now + 20 * GIB + (h - 20) * tenth
        }
    };
    let week: Vec<(u64, u64)> = (1..=168).map(|h| (h, at(h))).collect();
    let (_, rate, hours) = project(&fx, &week, now);
    let day = kib_rate(at(24), now, 86_400);
    let seven = kib_rate(at(168), now, 168 * 3600);
    assert!(day > seven, "{day} {seven}");
    assert_eq!(rate, day.to_string());
    assert_eq!(hours, ((now / 1024 - 1_048_576) / day).to_string());

    let mut short: Vec<(u64, u64)> = (25..=168).map(|h| (h, at(h))).collect();
    short.extend([(1, at(1)), (2, at(2))]);
    let (_, rate, _) = project(&fx, &short, now);
    assert_eq!(rate, seven.to_string());
}

/// A one-off copy is one step, and it counts in the last day's rate until it is a day old: 1.4 TB
/// written 2 hours ago on a week that held 2 TB free projects the volume full within 12 hours,
/// while the same step 25 hours ago leaves only the week's slower rate.
#[test]
fn a_one_off_copy_counts_in_the_last_day_s_rate_until_it_is_a_day_old() {
    let fx = Fx::new();
    let tb: u64 = 1_000_000_000_000;
    let after = 2 * tb - 1_400_000_000_000;
    let step = |ago: u64| -> Vec<(u64, u64)> {
        (1..=168)
            .map(|h| (h, if h <= ago { after } else { 2 * tb }))
            .collect()
    };
    let (_, rate, hours) = project(&fx, &step(2), after);
    assert_eq!(rate, kib_rate(2 * tb, after, 86_400).to_string());
    let hours: u64 = hours.parse().unwrap();
    assert!(hours < 12, "{hours}");
    let (_, rate, hours) = project(&fx, &step(25), after);
    assert_eq!(rate, kib_rate(2 * tb, after, 168 * 3600).to_string());
    let hours: u64 = hours.parse().unwrap();
    assert!(hours > 12, "{hours}");
}

/// `pa_vol_stores` names every store the witness samples and the walk maps, once each: the fixed
/// paths, the gateway's spool from gateway.env, the backups from the backup unit's Environment
/// property (its last PROPOLIS_BACKUP_DIR), the data directory as the postgres account's and the
/// configured log directories as the propolis account's. A value out of form leaves the default,
/// and a property or file that could not be read marks the list as not fully known.
#[test]
fn the_store_list_takes_the_backup_unit_s_directory_the_gateway_spool_and_the_log_directories() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/gateway.env",
        "PROPOLIS_GATEWAY_SPOOL_DIR=/srv/gw\n",
    );
    let list = |args: &str| -> Run {
        fx.run(&format!(
            "pa_sensor_logs 'ssh:/srv/logs/ssh.jsonl,http:/var/log/propolis/http.jsonl,odd:rel.jsonl'\n\
             pa_vol_stores {args}\n\
             for i in \"${{!PA_VOL_STORE[@]}}\"; do\n\
                 echo \"s=${{PA_VOL_STORE[$i]}}|${{PA_VOL_STORE_AS[$i]}}|${{PA_VOL_STORE_LOG[$i]}}\"\n\
             done\n\
             echo \"known=$PA_VOL_STORE_KNOWN\""
        ))
    };
    let stores = |r: &Run| -> Vec<String> {
        r.out
            .lines()
            .filter_map(|l| l.strip_prefix("s="))
            .map(str::to_string)
            .collect()
    };
    let r = list(
        "'A=1 PROPOLIS_BACKUP_DIR=/old PROPOLIS_BACKUP_DIR=/srv/b' /var/lib/postgresql/16/main",
    );
    assert_eq!(
        stores(&r),
        [
            "/var/lib/propolis||0",
            "/var/log/propolis||1",
            "/var/spool/propolis||0",
            "/srv/gw||0",
            "/var/log/journal||0",
            "/srv/b||0",
            "/var/lib/postgresql/16/main|postgres|0",
            "/srv/logs|propolis|1",
        ],
        "{}",
        r.err
    );
    assert_eq!(r.get("known"), "1");

    fx.write(
        "etc/propolis/gateway.env",
        "PROPOLIS_GATEWAY_SPOOL_DIR=/srv/../gw\n",
    );
    let r = list("'PROPOLIS_BACKUP_DIR=/srv/../etc' ''");
    let s = stores(&r);
    assert!(
        s.contains(&"/var/spool/propolis/gateway||0".to_string()),
        "{s:?}"
    );
    assert!(s.contains(&"/var/backups/propolis||0".to_string()), "{s:?}");
    assert!(
        !s.iter().any(|p| p.contains("..") || p.contains("postgres")),
        "{s:?}"
    );
    assert_eq!(r.get("known"), "1");

    let r = list("'?' ''");
    assert!(stores(&r).contains(&"/var/backups/propolis||0".to_string()));
    assert_eq!(r.get("known"), "0");

    // A gateway.env that is there but cannot be read (here not a regular file).
    std::fs::remove_file(fx.p("etc/propolis/gateway.env")).unwrap();
    std::fs::create_dir(fx.p("etc/propolis/gateway.env")).unwrap();
    let r = list("'' ''");
    assert!(stores(&r).contains(&"/var/spool/propolis/gateway||0".to_string()));
    assert_eq!(r.get("known"), "0");
}

// ---- the sender, the test page's budget and its shape ------------------------------------------

/// Records its argv and environment in `STUB_LOG`, copies the config file it is given (with its
/// mode) to `$D/conf` and its stdin to `$D/body`, and prints `SEND_CODE` (nothing when it is
/// `none`, as a curl that got no answer prints none).
const CURL_SEND_STUB: &str = r#"#!/usr/bin/env bash
{ printf 'curl'; printf ' [%s]' "$@"; printf '\n'; env | sed 's/^/env /'; } >> "$STUB_LOG"
conf=""
prev=""
for a in "$@"; do [ "$prev" != -K ] || conf="$a"; prev="$a"; done
{ stat -c %a -- "$conf"; cat -- "$conf"; } > "$D/conf"
cat > "$D/body"
[ "${SEND_CODE:-200}" = none ] || printf '%s' "${SEND_CODE:-200}"
"#;

// The token comes from a file, not the environment, so curl's environment can be checked for it.
const SEND_SCRIPT: &str = "PA_TARGET=1 PA_URL='https://ntfy.invalid' PA_TOPIC='t0p1c-secret' PA_TOKEN=\"$(cat \"$D/token\")\"\n\
     pa_send \"$TITLE\" \"$PRIO\" < <(printf '%b' \"$BODY\"); echo \"rc=$?\"\n\
     echo \"result=$PA_SEND_RESULT\"\n\
     echo \"traps=$(trap -p)\"\n\
     for f in \"${PA_CLEANUP[@]}\"; do [ ! -e \"$f\" ] || echo \"left=$f\"; done\n\
     echo \"listed=${#PA_CLEANUP[@]}\"";

fn send(fx: &Fx, title: &str, prio: &str, body: &str, token: &str, code: &str) -> Run {
    std::fs::write(fx.scratch().join("token"), token).unwrap();
    fx.run_env(
        SEND_SCRIPT,
        &[
            ("TITLE", title),
            ("PRIO", prio),
            ("BODY", body),
            ("SEND_CODE", code),
        ],
    )
}

/// pa_send hands curl one config file and nothing else on its command line: the URL with the
/// topic, the title, the priority and the token's header are in that file (0600 while it exists,
/// listed for the caller's cleanup and gone when pa_send returns), never in curl's arguments or
/// environment. A double quote or a backslash in a value is escaped so it cannot end the string;
/// the body goes on stdin, cut to 1024 bytes. The library sets no trap.
#[test]
fn pa_send_keeps_the_topic_and_the_token_in_a_config_file_and_off_the_command_line() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("curl"), CURL_SEND_STUB);
    let token = "tk_s3cret\"\\value";
    let r = send(
        &fx,
        "host-1a2b: test page \"q\" \\ x",
        "3",
        "line one\\nline two\\n",
        token,
        "200",
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("result"), "ok");
    assert_eq!(r.get("traps"), "", "the library sets no trap");
    assert!(!r.out.contains("left="), "{}", r.out);
    assert_eq!(r.get("listed"), "1");
    let calls: Vec<String> = fx
        .log()
        .lines()
        .filter(|l| l.starts_with("curl "))
        .map(String::from)
        .collect();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("curl [-q] [-K] ["), "{}", calls[0]);
    assert_eq!(calls[0].matches('[').count(), 3, "{}", calls[0]);
    for secret in ["t0p1c-secret", "tk_s3cret"] {
        assert!(
            !fx.log().contains(secret),
            "{secret} on curl's command line or in its environment"
        );
    }
    let conf = std::fs::read_to_string(fx.scratch().join("conf")).unwrap();
    let mut lines = conf.lines();
    assert_eq!(lines.next(), Some("600"));
    let rest: Vec<&str> = lines.collect();
    for want in [
        "url = \"https://ntfy.invalid/t0p1c-secret\"",
        "header = \"Title: host-1a2b: test page \\\"q\\\" \\\\ x\"",
        "header = \"Priority: 3\"",
        "header = \"Authorization: Bearer tk_s3cret\\\"\\\\value\"",
        "silent",
        "show-error",
        "output = \"/dev/null\"",
        "write-out = \"%{http_code}\"",
        "connect-timeout = 5",
        "max-time = 15",
        "retry = 1",
        "retry-max-time = 20",
        "proto = \"=https,http\"",
        "data-binary = \"@-\"",
    ] {
        assert!(rest.contains(&want), "{want} not in:\n{conf}");
    }
    assert!(
        !conf.contains("Tags:") && !conf.contains("location"),
        "{conf}"
    );
    assert_eq!(
        std::fs::read_to_string(fx.scratch().join("body")).unwrap(),
        "line one\nline two"
    );
    let long = "x".repeat(150) + "\\n";
    send(&fx, "t", "3", &long.repeat(10), "", "200");
    let body = std::fs::read_to_string(fx.scratch().join("body")).unwrap();
    assert_eq!(body.len(), 1024, "the body is cut to 1024 bytes");
    let conf = std::fs::read_to_string(fx.scratch().join("conf")).unwrap();
    assert!(
        !conf.contains("Authorization"),
        "no token, no header: {conf}"
    );
}

/// The answer's class: 2xx ok; 408, 429, 5xx and no answer transient; every other 4xx perm; and
/// norender, with no call made, for a title or body line outside printable ASCII or past 200
/// bytes, a priority outside 1 to 5, or a value that cannot be written into the config file;
/// notarget without a target.
#[test]
fn pa_send_classifies_each_answer_and_refuses_what_it_cannot_send_safely() {
    let fx = Fx::new();
    write_exec(&fx.bin.join("curl"), CURL_SEND_STUB);
    for (code, want) in [
        ("200", "ok"),
        ("204", "ok"),
        ("400", "perm:400"),
        ("401", "perm:401"),
        ("403", "perm:403"),
        ("404", "perm:404"),
        ("413", "perm:413"),
        ("408", "transient:408"),
        ("429", "transient:429"),
        ("500", "transient:500"),
        ("503", "transient:503"),
        ("302", "transient:302"),
        ("none", "transient:000"),
        ("2000", "transient:000"),
    ] {
        let r = send(&fx, "t", "3", "b", "", code);
        assert_eq!(r.get("result"), want, "{code}");
        assert_eq!(r.get("rc"), if want == "ok" { "0" } else { "1" }, "{code}");
    }
    let calls = fx.log().matches("curl [").count();
    for (title, prio, body, token) in [
        ("t\u{1b}[31m", "3", "b", ""),
        ("t", "0", "b", ""),
        ("t", "6", "b", ""),
        ("t", "x", "b", ""),
        ("", "3", "b", ""),
        ("t", "3", "ok\\n\\x1b[2J", ""),
        ("t", "3", &"y".repeat(201), ""),
        ("t", "3", "b", "tk\u{7}bell"),
    ] {
        let r = send(&fx, title, prio, body, token, "200");
        assert_eq!(
            r.get("result"),
            "norender",
            "{title:?} {prio} {body:?} {token:?}"
        );
    }
    assert_eq!(
        fx.log().matches("curl [").count(),
        calls,
        "norender makes no call"
    );
    let r = fx.run_env(
        "PA_TARGET=0; pa_send t 3 < /dev/null; echo \"result=$PA_SEND_RESULT\"",
        &[],
    );
    assert_eq!(r.get("result"), "notarget");
}

/// The test page carries the alias and the code and nothing else, at priority 3; any other
/// message, a code not of 6 hex and a host with no salt yet render nothing. pa_url_shown keeps a
/// URL's scheme and host and drops a user, a path and a query.
#[test]
fn the_test_page_renders_the_alias_and_the_code_only_and_a_url_shows_its_host_only() {
    let fx = Fx::salted(SALT);
    let r = fx.run(
        "pa_render full test 0a1b2c; echo \"rc=$?\"; echo \"title=$PA_TITLE\"; echo \"prio=$PA_PRIO\"; echo \"body=$PA_BODY\"\n\
         pa_render full open 0a1b2c; echo \"open=$?\"\n\
         pa_render full test 0A1B2C; echo \"upper=$?\"\n\
         pa_render full test 0a1b2; echo \"short=$?\"",
    );
    let alias = fx.run("pa_alias").out;
    assert!(alias.starts_with("host-"), "{alias}");
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("title"), format!("{alias}: test page 0a1b2c"));
    assert_eq!(r.get("prio"), "3");
    assert_eq!(
        r.get("body"),
        format!("Type back on {alias}: status --ack-test 0a1b2c")
    );
    for k in ["open", "upper", "short"] {
        assert_eq!(r.get(k), "1", "{k}");
    }
    let unsalted = Fx::new();
    assert_eq!(
        unsalted
            .run("pa_render full test 0a1b2c; echo \"rc=$?\"")
            .get("rc"),
        "1"
    );
    for (url, shown) in [
        ("https://ntfy.example.org", "https://ntfy.example.org"),
        (
            "https://u:pw@ntfy.example.org:8443/topic?auth=x",
            "https://ntfy.example.org:8443",
        ),
        ("http://[::1]:80/a", "http://[::1]:80"),
        ("ntfy.example.org/topic", "the target"),
        ("ftp://x", "the target"),
    ] {
        let r = fx.run_env("echo \"shown=$(pa_url_shown \"$U\")\"", &[("U", url)]);
        assert_eq!(r.get("shown"), shown, "{url}");
    }
}

/// The class test admits three in 24 hours, counting every attempt that was or may have been sent
/// (sending, ok, perm, transient, and pending while the hook may still be running) and none that
/// sent nothing (norender, nocurl, notarget), none over a day old and none dated ahead of the
/// clock, and no line of another class. An incident class with no record behind its key admits
/// nothing, and a class the budget does not know admits nothing. pa_ledger_add drops lines over
/// 48 h old, and pa_ledger_result updates only the pending line it names.
#[test]
fn the_budget_admits_three_test_pages_a_day_and_counts_no_other_class_against_them() {
    let fx = Fx::new();
    let line = |stamp: &str, class: &str, result: &str| {
        format!("L\t{stamp}\t{class}\t-\topen\tfull\t{result}\tstatus\n")
    };
    let admit = |ledger: &str| -> String {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{ledger}"),
        );
        fx.run_env("pa_budget_admit test - open 1; echo", &NOW)
            .out
            .trim()
            .to_string()
    };
    let recent = "999000/abcdef01/4000";
    let just_now = "999950/abcdef01/4950";
    let old = "900000/0000aaaa/1";
    let future = "1000500/abcdef01/5500";
    assert_eq!(admit(""), "admit");
    let two = line(recent, "test", "ok") + &line(recent, "test", "transient:503");
    assert_eq!(admit(&two), "admit");
    assert_eq!(
        admit(&(two.clone() + &line(just_now, "test", "pending"))),
        "withhold:test-cap",
        "a pending line the hook may still be sending counts"
    );
    assert_eq!(
        admit(&(two.clone() + &line(recent, "test", "sending"))),
        "withhold:test-cap"
    );
    assert_eq!(
        admit(&(two.clone() + &line(recent, "test", "perm:403"))),
        "withhold:test-cap"
    );
    for idle in ["norender", "nocurl", "notarget", "nomatch"] {
        assert_eq!(
            admit(&(two.clone() + &line(recent, "test", idle))),
            "admit",
            "{idle}"
        );
    }
    assert_eq!(
        admit(&(two.clone() + &line(old, "test", "ok"))),
        "admit",
        "over a day old"
    );
    assert_eq!(
        admit(&(two.clone() + &line(future, "test", "ok"))),
        "admit",
        "ahead of the clock"
    );
    assert_eq!(
        admit(&(two.clone() + &line(recent, "daily", "ok"))),
        "admit",
        "another class"
    );
    for class in ["pool", "reserve", "stage1", "incident"] {
        let r = fx.run_env(
            &format!("pa_incident_load; pa_budget_admit {class} k open 1; echo"),
            &NOW,
        );
        assert!(r.out.starts_with("withhold:unknown"), "{class}: {}", r.out);
    }
    for class in ["bulk", "-", ""] {
        let r = fx.run_env(&format!("pa_budget_admit '{class}' k open 1; echo"), &NOW);
        assert!(r.out.starts_with("withhold:class"), "{class}: {}", r.out);
    }
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    assert_eq!(
        fx.run_env("pa_budget_admit test - open 1; echo", &NOW)
            .out
            .trim(),
        "withhold:ledger",
        "a ledger that cannot be read counts as full"
    );

    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=4\n{}{}X\tkept\n",
            line("800000/0000aaaa/1", "test", "ok"),
            line(recent, "test", "pending")
        ),
    );
    let r = fx.run_env(
        &format!(
            "pa_ledger_add test - open pointer pending status; echo \"add=$? $PA_LEDGER_STAMP\"\n\
             pa_ledger_result {recent} test ok hook; echo \"res=$?\"\n\
             pa_ledger_result {recent} test perm:403 hook; echo \"again=$?\""
        ),
        &NOW,
    );
    assert_eq!(r.get("add"), "0 1000000/abcdef01/5000", "{}", r.err);
    assert_eq!(r.get("res"), "0");
    assert_eq!(r.get("again"), "1", "only a pending line takes a result");
    let ledger = fx.read("var/lib/propolis/witness/send-ledger");
    assert!(ledger.starts_with("#send-ledger v1 g=6\n"), "{ledger}");
    assert!(
        !ledger.contains("800000/"),
        "a line over 48 h old goes: {ledger}"
    );
    assert!(
        ledger.contains(&format!("L\t{recent}\ttest\t-\topen\tfull\tok\thook\n")),
        "{ledger}"
    );
    assert!(ledger.contains("L\t1000000/abcdef01/5000\ttest\t-\topen\tpointer\tpending\tstatus\n"));
    assert!(
        ledger.contains("X\tkept\n"),
        "a line of a type this release does not know stays"
    );
    assert_eq!(
        mode_of(&fx.p("var/lib/propolis/witness/send-ledger")),
        0o600
    );
}

/// The hook claims a page as sending before it sends, so a ledger line still pending once the
/// hook's whole time (120 s) has passed was never sent: three of them, left by a failure-alert
/// unit that does not run, do not spend the day. Three pages that went out still do, and a claim
/// counts whatever its age. pa_budget_next says when the next page is allowed: when the first
/// counted line stops counting (a pending one at 120 s, any other when it leaves the 24-hour
/// window), as HH:MM UTC, rounded up to the minute.
#[test]
fn pending_lines_past_the_hooks_time_stop_counting_and_a_claim_always_counts() {
    let fx = Fx::new();
    let three = |stamps: &[(&str, &str)]| -> Run {
        let mut text = "#send-ledger v1 g=1\n".to_string();
        for (stamp, result) in stamps {
            text.push_str(&format!(
                "L\t{stamp}\ttest\t-\topen\tfull\t{result}\tstatus\n"
            ));
        }
        fx.write("var/lib/propolis/witness/send-ledger", &text);
        fx.run_env(
            "echo \"admit=$(pa_budget_admit test - open 1)\"; echo \"next=$(pa_budget_next test)\"",
            &NOW,
        )
    };
    let young = "999900/abcdef01/4900";
    let past = "999820/abcdef01/4820";
    let hour = "996400/abcdef01/1400";
    let long_ago = "950000/0000aaaa/1";
    let r = three(&[(young, "pending"), (young, "pending"), (young, "pending")]);
    assert_eq!(r.get("admit"), "withhold:test-cap", "{}", r.err);
    let r = three(&[(past, "pending"), (past, "pending"), (past, "pending")]);
    assert_eq!(r.get("admit"), "admit", "three minutes on: {}", r.err);
    let r = three(&[(hour, "ok"), (hour, "ok"), (past, "ok")]);
    assert_eq!(r.get("admit"), "withhold:test-cap");
    assert_eq!(r.get("next"), "12:47", "{}", r.err);
    let r = three(&[(long_ago, "sending"), (hour, "ok"), (past, "pending")]);
    assert_eq!(
        r.get("admit"),
        "admit",
        "the old pending line is not counted"
    );
    let r = three(&[
        (long_ago, "sending"),
        (hour, "transient:503"),
        (young, "perm:403"),
    ]);
    assert_eq!(r.get("admit"), "withhold:test-cap");
    assert_eq!(r.get("next"), "23:54", "the oldest counted line: {}", r.err);

    // At 08:00:30 UTC: two pages delivered 20 h and 19 h ago, and an attempt 30 s ago whose
    // unit has not run. The pending line stops counting at 120 s, so the next page is allowed at
    // 08:02 today, not when the 20 h old line leaves tomorrow.
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\n\
         L\t1799928030/abcdef01/828030\ttest\t-\topen\tfull\tok\tstatus\n\
         L\t1799931630/abcdef01/831630\ttest\t-\topen\tfull\tok\tstatus\n\
         L\t1800000000/abcdef01/900000\ttest\t-\topen\tfull\tpending\tstatus\n",
    );
    let r = fx.run_env(
        "echo \"admit=$(pa_budget_admit test - open 1)\"; echo \"next=$(pa_budget_next test)\"",
        &[
            ("PA_TEST_WALL", "1800000030"),
            ("PA_TEST_BOOT", "abcdef01"),
            ("PA_TEST_UP", "900030"),
        ],
    );
    assert_eq!(r.get("admit"), "withhold:test-cap", "{}", r.err);
    assert_eq!(
        r.get("next"),
        "08:02",
        "when the pending line stops counting: {}",
        r.err
    );
}

/// Every request the library makes (the read check's GETs, the heartbeat and pa_send's post)
/// tells curl `globoff` in its config file, so a brace or a bracket in the URL is sent as written,
/// as one request, never expanded into several.
#[test]
fn every_library_request_turns_curl_url_globbing_off_and_keeps_braces_as_written() {
    let fx = Fx::new();
    write_exec(
        &fx.bin.join("curl"),
        "#!/usr/bin/env bash\nprev=\"\"\nfor a in \"$@\"; do\n    if [ \"$prev\" = -K ]; then { echo '---'; cat -- \"$a\"; } >> \"$D/confs\"; fi\n    prev=\"$a\"\ndone\ncat > /dev/null\nprintf '403'\n",
    );
    let url = "https://ntfy.invalid/base{a,b}/[1-2]";
    let r = fx.run_env(
        "pa_readcheck_run \"$U\" t0p1c tk_x > /dev/null\n\
         PA_HB_URL=\"$U\" pa_heartbeat_get\n\
         PA_TARGET=1 PA_URL=\"$U\" PA_TOPIC=t0p1c PA_TOKEN=''; pa_send t 3 < <(printf 'b')\n\
         echo done=1",
        &[("U", url)],
    );
    assert_eq!(r.get("done"), "1", "{}", r.err);
    let confs = std::fs::read_to_string(fx.scratch().join("confs")).unwrap();
    let files: Vec<&str> = confs.split("---\n").filter(|c| !c.is_empty()).collect();
    // Three anonymous GETs and one with the token, the heartbeat, and the post.
    assert_eq!(files.len(), 6, "{confs}");
    for file in &files {
        assert!(
            file.lines().any(|l| l == "globoff"),
            "no globoff in:\n{file}"
        );
        let line = file.lines().find(|l| l.starts_with("url = ")).unwrap();
        assert!(
            line.starts_with(&format!("url = \"{url}")),
            "the URL is not as written: {line}"
        );
    }
}

/// PROPOLIS_OPS_DAILY_AT is `off` or HH:MM on the 24-hour clock; anything else, a line systemd
/// may read otherwise among them, keeps the default 08:41 and says so. PROPOLIS_OPS_HOST_ALIAS
/// reaches pa_alias, which takes it only in its allowed form and never the host's name. Neither
/// setting is listed among the push settings today's failure hook and the daemon also read.
#[test]
fn the_daily_time_and_the_alias_are_read_from_propolis_env_and_a_time_out_of_form_keeps_the_default()
 {
    let fx = Fx::salted(SALT);
    let show = "pa_settings_load\necho \"at=$PA_DAILY_AT\"\necho \"state=$PA_DAILY_STATE\"\n\
                echo \"invalid=${PA_INVALID:-none}\"\npa_alias > /dev/null\n\
                echo \"alias=$PA_ALIAS\"\necho \"rejected=$PA_ALIAS_REJECTED\"\necho \"astate=$PA_ALIAS_STATE\"";
    let base =
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c\n";
    let read = |extra: &str| -> (String, String, String) {
        fx.write("etc/propolis/propolis.env", &format!("{base}{extra}"));
        let r = fx.run(show);
        assert_eq!(r.get("invalid"), "none", "{extra:?}");
        (r.get("at"), r.get("state"), r.get("alias"))
    };
    let fallback = "host-908b".to_string();
    assert_eq!(
        read(""),
        ("08:41".into(), "default".into(), fallback.clone())
    );
    assert_eq!(
        read("PROPOLIS_OPS_DAILY_AT=off\n"),
        ("off".into(), "set".into(), fallback.clone())
    );
    assert_eq!(read("PROPOLIS_OPS_DAILY_AT = 23:59\n").0, "23:59");
    assert_eq!(read("PROPOLIS_OPS_DAILY_AT=00:00\n").0, "00:00");
    for bad in [
        "7:05", "24:00", "08:60", "08:41:00", "0841", "\"08:41", "offline", "noon", "off-peak",
        "no_daily", "0:30",
    ] {
        assert_eq!(
            read(&format!("PROPOLIS_OPS_DAILY_AT={bad}\n")),
            ("08:41".into(), "invalid".into(), fallback.clone()),
            "{bad:?}"
        );
    }
    // Whatever an operator writes to turn the message off turns it off: the word in any letter
    // case, the words used for off elsewhere, and a word with a comment or a stray quote beside
    // it. Read any other way, the operator would go on getting a message they tried to stop.
    for off in [
        "Off",
        "OFF",
        "oFf",
        "false",
        "No",
        "n",
        "0",
        "none",
        "NEVER",
        "stop",
        "disable",
        "disabled",
        "off # stop it",
        "off;",
        "\"off",
        "'off' ",
    ] {
        assert_eq!(
            read(&format!("PROPOLIS_OPS_DAILY_AT={off}\n")),
            ("off".into(), "set".into(), fallback.clone()),
            "{off:?}"
        );
    }
    assert_eq!(
        read("PROPOLIS_OPS_HOST_ALIAS=north-relay\n").2,
        "north-relay"
    );
    fx.write(
        "etc/propolis/propolis.env",
        &format!("{base}PROPOLIS_OPS_HOST_ALIAS=edge07\n"),
    );
    let r = fx.run(show);
    assert_eq!(
        (r.get("alias"), r.get("rejected"), r.get("astate")),
        (fallback.clone(), "1".into(), "set".into()),
        "the host's own name is refused"
    );
    fx.write(
        "etc/propolis/propolis.env",
        &format!("{base}PROPOLIS_OPS_HOST_ALIAS=\"north-relay\\\"\n"),
    );
    let r = fx.run(show);
    assert_eq!(
        (r.get("alias"), r.get("astate")),
        (fallback, "invalid".into())
    );
}

/// The daily message is due once the host's local time of day is past PROPOLIS_OPS_DAILY_AT, on
/// a local date it was not sent on, and at least 20 hours after the last one. The witness runs
/// with TZ=UTC, so the zone is the one it was started with (PA_HOST_TZ), here a zone an hour or
/// two east of UTC with summer time, written as a POSIX rule so no zone file is needed: across a
/// change of day and across both changes of summer time (a 23-hour and a 25-hour day).
#[test]
fn the_daily_message_is_due_once_a_local_day_past_its_time_and_twenty_hours_after_the_last() {
    let fx = Fx::new();
    const CET: &str = "CET-1CEST,M3.5.0,M10.5.0/3";
    let due = |tz: &str, at: &str, wall: u64, last_date: &str, last_wall: Option<i64>| -> String {
        let last = match last_wall {
            Some(w) => format!("{w}/00000000/1"),
            None => "-".to_string(),
        };
        let r = fx.run_env(
            "PA_DAILY_AT=\"$AT\"\n\
             if pa_daily_due \"$LD\" \"$LS\"; then rc=0; else rc=1; fi\n\
             echo \"got=$rc $PA_DAILY_WHY ${PA_LOCAL_DATE:-nodate}\"",
            &[
                ("PA_HOST_TZ", tz),
                ("AT", at),
                ("LD", last_date),
                ("LS", &last),
                ("PA_TEST_WALL", &wall.to_string()),
                ("PA_TEST_BOOT", "abcdef01"),
                ("PA_TEST_UP", "5000"),
            ],
        );
        r.get("got")
    };
    // 2027-01-15 08:00 UTC, 09:00 in the zone.
    let jan = 1_800_000_000u64;
    assert_eq!(due(CET, "08:50", jan, "", None), "0 due 2027-01-15");
    assert_eq!(
        due("UTC0", "08:50", jan, "", None),
        "1 early 2027-01-15",
        "in UTC it is 08:00"
    );
    assert_eq!(
        due(CET, "08:50", jan + 300, "2027-01-15", Some(jan as i64)),
        "1 sent 2027-01-15"
    );
    // The next day at 08:50 in the zone, 23 h 50 min on.
    assert_eq!(
        due(CET, "08:50", jan + 85_800, "2027-01-15", Some(jan as i64)),
        "0 due 2027-01-16"
    );
    // 00:40 in the zone on the 16th is still the 15th in UTC; a new local day, but under 20 h.
    assert_eq!(
        due(CET, "00:30", jan + 56_400, "2027-01-15", Some(jan as i64)),
        "1 soon 2027-01-16"
    );
    assert_eq!(
        due(CET, "00:30", jan + 72_000, "2027-01-15", Some(jan as i64)),
        "0 due 2027-01-16"
    );
    // Summer time begins on Sunday 2027-03-28: 08:45 on Saturday is 07:45 UTC, 08:50 on Sunday
    // 06:50 UTC, 23 h 5 min later. Without summer time 06:50 UTC would read 07:50.
    let sat = 1_806_133_500u64;
    let sun = 1_806_216_600u64;
    assert_eq!(due(CET, "08:41", sat, "", None), "0 due 2027-03-27");
    assert_eq!(
        due(CET, "08:41", sun, "2027-03-27", Some(sat as i64)),
        "0 due 2027-03-28"
    );
    assert_eq!(
        due(CET, "08:41", sun - 900, "2027-03-27", Some(sat as i64)),
        "1 early 2027-03-28"
    );
    // Summer time ends on Sunday 2027-10-31: 08:45 on Saturday is 06:45 UTC; on Sunday 07:35 UTC
    // is 08:35, not yet the time, and 07:45 UTC is 08:45, 25 h after Saturday's.
    let sat = 1_824_878_700u64;
    let sun = 1_824_968_700u64;
    assert_eq!(due(CET, "08:41", sat, "", None), "0 due 2027-10-30");
    assert_eq!(
        due(CET, "08:41", sun - 600, "2027-10-30", Some(sat as i64)),
        "1 early 2027-10-31"
    );
    assert_eq!(
        due(CET, "08:41", sun, "2027-10-30", Some(sat as i64)),
        "0 due 2027-10-31"
    );
    // Off is never due. A last stamp from another boot dated ahead of the clock (only a wall clock
    // that was ahead before the boot can leave one) counts as none, as the ledger counts such a
    // line, so the message is not held back for as long as the clock was ahead; the local date
    // still holds a second one back on the same day. One out of form is no stamp either, the
    // send ledger's own count still standing behind it.
    assert_eq!(due(CET, "off", jan, "", None), "1 off nodate");
    assert_eq!(
        due(CET, "08:50", jan, "2027-01-14", Some(jan as i64 + 600)),
        "0 due 2027-01-15"
    );
    assert_eq!(
        due(CET, "08:50", jan, "2027-01-14", Some(jan as i64 + 259_200)),
        "0 due 2027-01-15"
    );
    assert_eq!(
        due(CET, "08:50", jan, "2027-01-15", Some(jan as i64 + 600)),
        "1 sent 2027-01-15"
    );
    let r = fx.run_env(
        "PA_DAILY_AT=08:50\nif pa_daily_due 2027-01-14 '?'; then echo got=due; else echo \"got=$PA_DAILY_WHY\"; fi",
        &[
            ("PA_HOST_TZ", CET),
            ("PA_TEST_WALL", &jan.to_string()),
            ("PA_TEST_BOOT", "abcdef01"),
            ("PA_TEST_UP", "5000"),
        ],
    );
    assert_eq!(r.get("got"), "due");
}

/// The class daily admits one message 20 hours after the last one the ledger counts: sending,
/// ok, perm and transient lines, and a pending one under 120 s old. A line that sent nothing and
/// another class's lines do not count; a ledger that cannot be read admits nothing.
#[test]
fn the_daily_class_admits_one_message_twenty_hours_after_the_last_it_counts() {
    let fx = Fx::new();
    let admit = |ledger: &str| -> String {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{ledger}"),
        );
        fx.run_env("pa_budget_admit daily - daily 1; echo", &NOW)
            .out
            .trim()
            .to_string()
    };
    let line = |age: u64, class: &str, result: &str| {
        format!(
            "L\t{}/abcdef01/{}\t{class}\t-\tdaily\tfull\t{result}\tlight\n",
            1_000_000 - age,
            5000u64.saturating_sub(age).max(1)
        )
    };
    // Ages past the boot's 5000 s of uptime are dated in another boot, by the wall clock.
    let old = |age: u64, result: &str| {
        format!(
            "L\t{}/0000aaaa/1\tdaily\t-\tdaily\tfull\t{result}\tlight\n",
            1_000_000 - age
        )
    };
    assert_eq!(admit(""), "admit");
    for result in ["sending", "ok", "perm:403", "transient:000"] {
        assert_eq!(
            admit(&line(3600, "daily", result)),
            "withhold:daily-cap",
            "{result}"
        );
        assert_eq!(
            admit(&old(68_400, result)),
            "withhold:daily-cap",
            "{result} 19 h ago"
        );
        assert_eq!(admit(&old(75_600, result)), "admit", "{result} 21 h ago");
    }
    assert_eq!(admit(&line(60, "daily", "pending")), "withhold:daily-cap");
    assert_eq!(admit(&line(200, "daily", "pending")), "admit");
    for idle in ["norender", "nocurl", "notarget", "noclaim"] {
        assert_eq!(admit(&line(60, "daily", idle)), "admit", "{idle}");
    }
    assert_eq!(admit(&line(60, "test", "ok")), "admit", "another class");
    assert_eq!(
        admit("L\t1000500/0000aaaa/1\tdaily\t-\tdaily\tfull\tok\tlight\n"),
        "admit",
        "a line dated ahead of the clock counts nothing"
    );
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    assert_eq!(
        fx.run_env("pa_budget_admit daily - daily 1; echo", &NOW)
            .out
            .trim(),
        "withhold:ledger"
    );
}

/// The daily message: title `<alias>: daily`, priority 2, and in its body only counts, opaque
/// incident ids, VERIFIED, the profile and the state. The notice count is of notices opened in
/// the last 24 hours, not standing ones, and no line says `daemon not verified`, which nothing
/// before the daemon's own test page could clear. The legacy profile adds what v2 would have
/// pushed in 24 hours, counted from the times each record keeps. Nothing in it comes from a
/// record's key, kind, cause or instance, nor from the host's name. Collectors are counted on a
/// control node only. Pointer mode renders no daily message.
#[test]
fn the_daily_message_holds_counts_ids_verified_and_the_state_and_no_name() {
    let fx = Fx::salted(SALT);
    let at = |ago: u64| format!("{}/abcdef01/{}", 1_000_000 - ago, 5000 - ago.min(4999));
    let far = |ago: u64| format!("{}/0000aaaa/1", 1_000_000 - ago);
    // Fields 1 to 34; the planted words sit where a record keeps names and causes.
    let rec = |id: &str,
               key: &str,
               kind: &str,
               tier: &str,
               state: &str,
               opened: &str,
               resolved: &str,
               reminders: &str,
               wp: &str| {
        let f: Vec<String> = [
            id,
            key,
            kind,
            "listen",
            "uplanted",
            tier,
            state,
            opened,
            opened,
            opened,
            "proc.exit:1",
            opened,
            "-",
            "0",
            "-",
            "open",
            "0",
            reminders,
            "-",
            "-",
            resolved,
            "-",
            "0",
            "-",
            "-",
            "-",
            "-",
            "-",
            wp,
            "-",
            "1",
            "-",
            "delivered",
            "-",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(f.len(), 34);
        format!("I\t{}\n", f.join("\t"))
    };
    let incidents = [
        rec(
            "w#3",
            "unit:sensor-plantedname.service",
            "unit-failed",
            "PAGE",
            "open",
            &at(1800),
            "-",
            "0",
            "1",
        ),
        // Opened 30 h ago: its 4 h reminder came 26 h ago, its 12 h one 18 h ago.
        rec(
            "w#5",
            "finding:plantedfinding:0123456789ab",
            "plantedkind",
            "ACT",
            "open",
            &far(108_000),
            "-",
            "2",
            "3",
        ),
        rec(
            "w#7",
            "spool:cplanted",
            "spool-quiet",
            "NOTICE",
            "open",
            &at(3600),
            "-",
            "0",
            "0",
        ),
        rec(
            "w#8",
            "finding:standing:0123456789ab",
            "ops-no-heartbeat",
            "NOTICE",
            "open",
            &far(259_200),
            "-",
            "0",
            "0",
        ),
        // Opened 1 h 10 min ago and resolved 10 min ago: the open and the resolve.
        rec(
            "w#9",
            "unit:shipper.service",
            "unit-failed",
            "ACT",
            "resolved",
            &at(4200),
            &at(600),
            "0",
            "2",
        ),
        rec(
            "w#10",
            "db:local",
            "db-unreachable",
            "PAGE",
            "resolved",
            &far(400_000),
            &far(259_200),
            "0",
            "2",
        ),
        // An id out of form is counted as open but never copied into the body.
        rec(
            "w#3planted",
            "finding:other:0123456789ab",
            "ops-no-push",
            "NOTICE",
            "open",
            &far(259_200),
            "-",
            "0",
            "0",
        ),
    ]
    .concat();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t11\n{incidents}W\t{}\tplanted\n",
            at(3600)
        ),
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=2\nM\tclock_step\t{}/+300\nM\tplanted\tplantedvalue\n",
            at(3600)
        ),
    );
    let render = "PA_WHERE=persistent; PA_ROLE=\"$ROLE\"; PA_DAILY_LISTED=4\n\
                  pa_settings_load\n\
                  if pa_render full daily -; then echo rc=0; else echo rc=1; fi\n\
                  printf 'title=%s\\nprio=%s\\n' \"$PA_TITLE\" \"$PA_PRIO\"\n\
                  printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'\n\
                  if pa_render pointer daily -; then echo pointer=0; else echo pointer=1; fi";
    let r = fx.run_env(render, &[NOW[0], NOW[1], NOW[2], ("ROLE", "single")]);
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    let alias = fx.run("pa_alias").out;
    assert_eq!(r.get("title"), format!("{alias}: daily"));
    assert_eq!(r.get("prio"), "2");
    let body: Vec<&str> = r
        .out
        .lines()
        .filter_map(|l| l.strip_prefix("body="))
        .collect();
    assert_eq!(
        body,
        [
            "open: 5 (PAGE 1, ACT 1) w#3 w#5 w#7 w#8",
            "resolved 24 h: 1; withheld by budget 24 h: 1",
            "new notices 24 h: 1; clock step +300 s",
            "alerts: NOT VERIFIED (never); profile legacy",
            "v2 would have pushed 4 in 24 h",
            "state: persisted",
            "Do: status",
        ],
        "{}",
        r.out
    );
    assert_eq!(r.get("pointer"), "1");
    for word in [
        "planted",
        "edge07",
        "propolis",
        "honey",
        "daemon not verified",
        "proc.exit",
    ] {
        assert!(!r.out.to_lowercase().contains(word), "{word}: {}", r.out);
    }

    let r = fx.run_env(
        &render.replace("PA_WHERE=persistent", "PA_WHERE=run"),
        &[NOW[0], NOW[1], NOW[2], ("ROLE", "control")],
    );
    let body: Vec<&str> = r
        .out
        .lines()
        .filter_map(|l| l.strip_prefix("body="))
        .collect();
    assert_eq!(
        &body[5..],
        [
            "collectors: 4 listed, 1 quiet",
            "state: not persisted (run)",
            "Do: status"
        ],
        "{}",
        r.out
    );

    // A clock step with anything after its offset is out of form, and is left out whole.
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=3\nM\tclock_step\t{}/+300planted\n", at(3600)),
    );
    let r = fx.run_env(render, &[NOW[0], NOW[1], NOW[2], ("ROLE", "single")]);
    let body: Vec<&str> = r
        .out
        .lines()
        .filter_map(|l| l.strip_prefix("body="))
        .collect();
    assert_eq!(body.get(2), Some(&"new notices 24 h: 1"), "{}", r.out);
    assert!(!r.out.contains("planted"), "{}", r.out);
}

/// A stamp `ago` seconds before the library tests' NOW, in this boot while it is under the boot's
/// uptime, else in another boot (dated by the wall clock alone).
fn lib_at(ago: u64) -> String {
    if ago < 5000 {
        format!("{}/abcdef01/{}", 1_000_000 - ago, 5000 - ago)
    } else {
        format!("{}/0000aaaa/1", 1_000_000 - ago)
    }
}

/// An `incidents` record of 34 fields for the daily message's counts: an open ACT record whose
/// times are all `lib_at(1800)`, reminded 0 times, would_push 9, with the fields in `set`
/// (numbered from 1 after the `I`, as the library numbers them) replaced.
fn daily_record(set: &[(usize, &str)]) -> String {
    let stamp = lib_at(1800);
    let t = stamp.as_str();
    let mut f: Vec<String> = [
        "w#1",
        "unit:sensor-x.service",
        "unit-failed",
        "listen",
        "-",
        "ACT",
        "open",
        t,
        t,
        t,
        "proc.exit:1",
        t,
        "-",
        "0",
        "-",
        "open",
        "0",
        "0",
        "-",
        "-",
        "-",
        "-",
        "0",
        "-",
        "-",
        "-",
        "-",
        "-",
        "9",
        "-",
        "1",
        "-",
        "delivered",
        "-",
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    for (i, v) in set {
        f[i - 1] = v.to_string();
    }
    assert_eq!(f.len(), 34);
    format!("I\t{}\n", f.join("\t"))
}

/// The daily message's body over these records (and meta, when given), as lines.
fn daily_body(fx: &Fx, records: &[String], prelude: &str) -> Vec<String> {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        &format!(
            "PA_WHERE=persistent; PA_ROLE=single\npa_settings_load\n{prelude}\n\
             if pa_render full daily -; then echo rc=0; else echo rc=1; fi\n\
             printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'"
        ),
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}\n{}", r.out, r.err);
    r.out
        .lines()
        .filter_map(|l| l.strip_prefix("body="))
        .map(str::to_string)
        .collect()
}

/// Of twelve open records, PAGE, ACT and NOTICE mixed in the file's order, the body counts all
/// twelve and names exactly ten: every PAGE first, then every ACT, then NOTICEs until ten.
#[test]
fn the_daily_message_names_ten_open_ids_page_first_then_act_then_notice() {
    let fx = Fx::salted(SALT);
    let tiers = ["NOTICE", "ACT", "PAGE"];
    let records: Vec<String> = (1..=12)
        .map(|n| {
            let id = format!("w#{n}");
            daily_record(&[(1, &id), (6, tiers[n % 3])])
        })
        .collect();
    let body = daily_body(&fx, &records, "");
    assert_eq!(
        body[0],
        "open: 12 (PAGE 4, ACT 4) w#2 w#5 w#8 w#11 w#1 w#4 w#7 w#10 w#3 w#6"
    );
}

/// What v2 would have pushed in 24 hours, record by record: an ACT record opened 13 hours ago and
/// never reminded counts its open alone, not the 4 h and 12 h reminders it has not had; a record
/// whose times give two is held to its would_push of one; a child folded under a parent and a
/// duplicate count nothing; a change of cause in the last 24 hours counts one.
#[test]
fn the_daily_v2_count_takes_only_reminders_had_holds_to_would_push_and_skips_folded_and_duplicates()
{
    let fx = Fx::salted(SALT);
    let v2 =
        |rec: &[(usize, &str)]| -> String { daily_body(&fx, &[daily_record(rec)], "")[4].clone() };
    let open13 = lib_at(46_800);
    assert_eq!(
        v2(&[(9, &open13)]),
        "v2 would have pushed 1 in 24 h",
        "only the open"
    );
    assert_eq!(
        v2(&[(9, &open13), (18, "2")]),
        "v2 would have pushed 3 in 24 h",
        "the open and both reminders it had"
    );
    let resolved = lib_at(600);
    assert_eq!(
        v2(&[(7, "resolved"), (21, &resolved), (29, "1")]),
        "v2 would have pushed 1 in 24 h",
        "two by its times, held to its would_push"
    );
    assert_eq!(
        v2(&[(7, "resolved"), (21, &resolved), (29, "2")]),
        "v2 would have pushed 2 in 24 h"
    );
    assert_eq!(
        v2(&[(13, "w#3")]),
        "v2 would have pushed 0 in 24 h",
        "folded"
    );
    assert_eq!(
        v2(&[(30, "dup")]),
        "v2 would have pushed 0 in 24 h",
        "duplicate"
    );
    let old = lib_at(108_000);
    let since = lib_at(7200);
    assert_eq!(
        v2(&[(9, &old), (16, "change"), (12, &since)]),
        "v2 would have pushed 1 in 24 h",
        "a change of cause"
    );
    assert_eq!(
        v2(&[(9, &old), (16, "open"), (12, &since)]),
        "v2 would have pushed 0 in 24 h"
    );
}

/// An acknowledged PAGE still counts as open; VERIFIED reads `VERIFIED <dur> (shell)`, and an
/// answer of pa_verified in neither of its forms reads as not verified, never as itself; a
/// damaged incidents file gives `open: ?` rather than a count of nothing; a clock step older than
/// a day is left out.
#[test]
fn the_daily_message_counts_acked_records_reads_verified_in_its_forms_and_says_when_state_is_unreadable()
 {
    let fx = Fx::salted(SALT);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c\n",
    );
    let acked = [daily_record(&[(1, "w#4"), (6, "PAGE"), (7, "acked")])];
    let body = daily_body(&fx, &acked, "");
    assert_eq!(body[0], "open: 1 (PAGE 1, ACT 0) w#4");
    assert_eq!(body[3], "alerts: NOT VERIFIED (never); profile legacy");

    let r = fx.run_env(
        "pa_settings_load\necho \"bind=$(pa_readcheck_binding \"$PA_URL\" \"$PA_TOPIC\")\"",
        &NOW,
    );
    fx.write(
        "var/lib/propolis/witness/testpage",
        &format!(
            "#testpage v1 g=1\nT\tabc123\t{}\t{}\t-\tok\t{}\t0\n",
            lib_at(4000),
            r.get("bind"),
            lib_at(3600)
        ),
    );
    let body = daily_body(&fx, &acked, "");
    assert!(
        body[3].starts_with("alerts: VERIFIED ") && body[3].ends_with(" (shell); profile legacy"),
        "{}",
        body[3]
    );
    let body = daily_body(&fx, &acked, "pa_verified() { printf 'plantedjunk'; }");
    assert_eq!(body[3], "alerts: NOT VERIFIED (unreadable); profile legacy");

    fx.write("var/lib/propolis/witness/incidents", "garbage\n");
    let r = fx.run_env(
        "PA_WHERE=persistent; PA_ROLE=single\npa_settings_load\n\
         if pa_render full daily -; then echo rc=0; else echo rc=1; fi\n\
         printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'",
        &NOW,
    );
    assert_eq!(r.get("body"), "open: ? (state unreadable)", "{}", r.out);

    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=3\nM\tclock_step\t{}/+300\n", lib_at(108_000)),
    );
    let body = daily_body(&fx, &acked, "");
    assert_eq!(body[2], "new notices 24 h: 0");
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=4\nM\tclock_step\t{}/-120\n",
            lib_at(108_000 - 30_000)
        ),
    );
    let body = daily_body(&fx, &acked, "");
    assert_eq!(body[2], "new notices 24 h: 0; clock step -120 s");
}

/// pa_render checks every line of the daily message's body before it is sent: a line over 200
/// bytes or one holding a control byte leaves nothing to send (status 1, PA_BODY empty).
#[test]
fn a_daily_body_with_a_long_line_or_a_control_byte_is_not_rendered() {
    let fx = Fx::salted(SALT);
    for (name, line) in [
        ("long", "printf '%0201d\\n' 0"),
        ("control", "printf 'open: 0\\033[2J\\n'"),
    ] {
        let r = fx.run_env(
            &format!(
                "_pa_render_daily() {{ printf 'open: 0\\n'; {line}; printf 'Do: status\\n'; }}\n\
                 if pa_render full daily -; then echo rc=0; else echo rc=1; fi\n\
                 echo \"body=${{#PA_BODY}} title=${{#PA_TITLE}}\""
            ),
            &NOW,
        );
        assert_eq!(r.get("rc"), "1", "{name}");
        assert_eq!(r.get("body"), "0 title=0", "{name}");
    }
    let r = fx.run_env(
        "_pa_render_daily() { printf 'open: 0\\n%0200d\\n' 0; }\n\
         if pa_render full daily -; then echo rc=0; else echo rc=1; fi",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "a line of 200 bytes is allowed");
}

/// The read check is anonymous: user and password written into PROPOLIS_OPS_NTFY_URL would make
/// curl send them as Basic credentials, and a 401 for those would pass for a refusal of anonymous
/// reads. They are taken off every URL the check requests; the binding keeps the URL as set.
#[test]
fn the_read_check_takes_credentials_written_in_the_url_off_every_request() {
    let fx = Fx::new();
    write_exec(
        &fx.bin.join("curl"),
        "#!/usr/bin/env bash\nprev=\"\"\nfor a in \"$@\"; do\n    if [ \"$prev\" = -K ]; then { echo '---'; cat -- \"$a\"; } >> \"$D/confs\"; fi\n    prev=\"$a\"\ndone\nprintf '403\\ttext/plain'\n",
    );
    for url in [
        "https://alice:pw@ntfy.example.invalid",
        "https://alice@ntfy.example.invalid",
        "http://a:b@c@ntfy.example.invalid/base",
    ] {
        let _ = std::fs::remove_file(fx.scratch().join("confs"));
        let r = fx.run_env(
            "pa_readcheck_run \"$U\" t tk_x\necho \"class=$PA_RC_CLASS\"",
            &[("U", url)],
        );
        assert_eq!(r.get("class"), "refused", "{}", r.err);
        let confs = std::fs::read_to_string(fx.scratch().join("confs")).unwrap();
        let files: Vec<&str> = confs.split("---\n").filter(|c| !c.is_empty()).collect();
        // Over plain http the token is not asked: it would travel in clear and decide nothing.
        let want = if url.starts_with("http://") { 3 } else { 4 };
        assert_eq!(files.len(), want, "{confs}");
        let base = if url.ends_with("/base") {
            "http://ntfy.example.invalid/base/t/"
        } else {
            "https://ntfy.example.invalid/t/"
        };
        for file in &files {
            let line = file.lines().find(|l| l.starts_with("url = ")).unwrap();
            assert!(!line.contains("alice") && !line.contains('@'), "{line}");
            assert!(line.starts_with(&format!("url = \"{base}")), "{line}");
        }
    }
    // The host ends at the first `/`, `?` or `#`: an `@` after that is no user, and what stands
    // behind it is never taken for the host the check asks.
    let _ = std::fs::remove_file(fx.scratch().join("confs"));
    let r = fx.run_env(
        "pa_readcheck_run \"$U\" t ''\necho \"cred=$PA_RC_CRED\"",
        &[("U", "https://ntfy.example.invalid?x@other.invalid")],
    );
    assert_eq!(r.get("cred"), "-", "{}", r.err);
    let confs = std::fs::read_to_string(fx.scratch().join("confs")).unwrap();
    let urls: Vec<&str> = confs.lines().filter(|l| l.starts_with("url = ")).collect();
    assert_eq!(urls.len(), 3, "{confs}");
    for line in urls {
        assert!(
            line.starts_with("url = \"https://ntfy.example.invalid?x@other.invalid/t/"),
            "{line}"
        );
    }
}

/// A user and password in the URL are what a post from this host carries when no token is set.
/// So after the three anonymous requests, which never hold them, one more asks whether they can
/// read the topic, with the URL as set, and its answer is kept where the token's would be: on a
/// collector a credential that reads holds the gate at pointer. A token, when set, is what a post
/// carries instead, and is the one asked; with neither nothing more is asked.
#[test]
fn credentials_written_in_the_url_are_asked_whether_they_can_read_the_topic() {
    let fx = Fx::new();
    // 200 to a request whose URL holds the user, 403 to every other; `$D/answer` turns that off.
    write_exec(
        &fx.bin.join("curl"),
        "#!/usr/bin/env bash\nprev=\"\" conf=\"\"\nfor a in \"$@\"; do\n    if [ \"$prev\" = -K ]; then conf=\"$a\"; { echo '---'; cat -- \"$a\"; } >> \"$D/confs\"; fi\n    prev=\"$a\"\ndone\nif [ ! -e \"$D/deny\" ] && grep -q 'alice' -- \"$conf\" 2> /dev/null; then\n    printf '200\\tapplication/x-ndjson'\nelse\n    printf '403\\ttext/plain'\nfi\n",
    );
    let show = "pa_readcheck_run \"$U\" t \"$K\"\necho \"class=$PA_RC_CLASS\"\necho \"token=$PA_RC_TOKEN\"\necho \"cred=$PA_RC_CRED\"";
    let confs = |fx: &Fx| -> Vec<String> {
        std::fs::read_to_string(fx.scratch().join("confs"))
            .unwrap()
            .split("---\n")
            .filter(|c| !c.is_empty())
            .map(|c| {
                c.lines()
                    .find(|l| l.starts_with("url = "))
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    let url = "https://alice:pw@ntfy.example.invalid";

    let r = fx.run_env(show, &[("U", url), ("K", "")]);
    assert_eq!(
        (r.get("class"), r.get("token"), r.get("cred")),
        ("refused".into(), "reads".into(), "url".into()),
        "{}",
        r.err
    );
    let asked = confs(&fx);
    assert_eq!(asked.len(), 4, "{asked:?}");
    for line in &asked[..3] {
        assert!(!line.contains("alice") && !line.contains('@'), "{line}");
    }
    assert_eq!(
        asked[3],
        "url = \"https://alice:pw@ntfy.example.invalid/t/json?poll=1&since=1s\""
    );

    std::fs::write(fx.scratch().join("deny"), b"").unwrap();
    std::fs::remove_file(fx.scratch().join("confs")).unwrap();
    let r = fx.run_env(show, &[("U", url), ("K", "")]);
    assert_eq!(
        (r.get("class"), r.get("token"), r.get("cred")),
        ("refused".into(), "noread".into(), "url".into()),
        "{}",
        r.err
    );
    std::fs::remove_file(fx.scratch().join("deny")).unwrap();

    // A token is what the post carries when one is set: it is asked, never the URL's user.
    std::fs::remove_file(fx.scratch().join("confs")).unwrap();
    let r = fx.run_env(show, &[("U", url), ("K", "tk_x")]);
    assert_eq!(
        (r.get("token"), r.get("cred")),
        ("noread".into(), "token".into()),
        "{}",
        r.err
    );
    let asked = confs(&fx);
    assert_eq!(asked.len(), 4, "{asked:?}");
    for line in &asked {
        assert!(!line.contains("alice"), "{line}");
    }

    // Neither: three anonymous requests and nothing kept for a credential.
    std::fs::remove_file(fx.scratch().join("confs")).unwrap();
    let r = fx.run_env(show, &[("U", "https://ntfy.example.invalid"), ("K", "")]);
    assert_eq!(
        (r.get("token"), r.get("cred")),
        ("-".into(), "-".into()),
        "{}",
        r.err
    );
    assert_eq!(confs(&fx).len(), 3);
}

/// A zone file of one fixed offset east of UTC, `XPT` at +01:00, in the TZif form the C library
/// reads: no transitions, one local time type, and the POSIX rule after the data.
fn tzif_plus_one() -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..2 {
        v.extend_from_slice(b"TZif2");
        v.extend_from_slice(&[0u8; 15]);
        for count in [0u32, 0, 0, 0, 1, 4] {
            v.extend_from_slice(&count.to_be_bytes());
        }
        v.extend_from_slice(&3600i32.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(b"XPT\0");
    }
    v.extend_from_slice(b"\nXPT-1\n");
    v
}

/// Production units set no TZ, so when the witness was started without one the host's
/// /etc/localtime decides the daily time, not the TZ=UTC the witness sets for everything else:
/// under a root the zone file is the root's, here one an hour east of UTC, and without a root the
/// answer is the host's own, as `date` gives it with TZ unset. A zone passed in PA_HOST_TZ wins.
#[test]
fn without_a_zone_passed_the_daily_time_is_read_in_the_hosts_localtime_not_in_utc() {
    let fx = Fx::new();
    std::fs::write(fx.p("etc/localtime"), tzif_plus_one()).unwrap();
    let show = "export TZ=UTC0\nunset PA_HOST_TZ\npa_local_time 1800000000\n\
                echo \"got=$PA_LOCAL_DATE $PA_LOCAL_HM\"";
    assert_eq!(fx.run(show).get("got"), "2027-01-15 09:00");
    assert_eq!(
        fx.run_env(&show.replace("unset PA_HOST_TZ", "PA_HOST_TZ=UTC0"), &[])
            .get("got"),
        "2027-01-15 08:00"
    );
    let host = Command::new("env")
        .args(["-u", "TZ", "date", "-d", "@1800000000", "+%F %H:%M"])
        .output()
        .unwrap();
    let host = String::from_utf8_lossy(&host.stdout).trim().to_string();
    let r = fx.run_raw(
        &format!("set -u -o pipefail\nsource \"$LIB\"\npa_init ''\n{show}"),
        &[],
    );
    assert_eq!(r.get("got"), host);
}

/// When `hostname` cannot answer, the alias is compared with the kernel's host name instead, and
/// when no name can be read at all no alias is taken: an alias equal to the host's name must never
/// reach the channel because the tool that would have told them apart is missing.
#[test]
fn an_alias_is_refused_when_it_is_the_kernels_host_name_or_no_host_name_can_be_read() {
    let fx = Fx::salted(SALT);
    write_exec(&fx.bin.join("hostname"), "#!/usr/bin/env bash\nexit 1\n");
    let kernel = fx.scratch().join("kernel-hostname");
    std::fs::write(&kernel, "Edge07.lab.example\n").unwrap();
    let show = "pa_settings_load\npa_alias > /dev/null\n\
                echo \"alias=$PA_ALIAS rejected=$PA_ALIAS_REJECTED\"";
    let alias = |value: &str, seam: Option<&Path>| -> String {
        fx.write(
            "etc/propolis/propolis.env",
            &format!("PROPOLIS_OPS_HOST_ALIAS={value}\n"),
        );
        let seam = seam.map(|p| p.display().to_string());
        let env: Vec<(&str, &str)> = seam
            .as_deref()
            .map(|p| vec![("PA_TEST_KERNEL_HOSTNAME", p)])
            .unwrap_or_default();
        fx.run_env(show, &env).get("alias")
    };
    assert_eq!(
        alias("edge07", Some(&kernel)),
        "host-908b rejected=1",
        "the kernel's short name"
    );
    assert_eq!(
        alias("north-relay", Some(&kernel)),
        "north-relay rejected=0"
    );
    let missing = fx.scratch().join("no-such-file");
    assert_eq!(
        alias("north-relay", Some(&missing)),
        "host-908b rejected=1",
        "no name could be read"
    );
    // Without the seam the kernel's own file is read.
    let own = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap()
        .trim()
        .to_lowercase();
    let short = own.split('.').next().unwrap().to_string();
    let fits = |a: &str| {
        (3..=32).contains(&a.len())
            && a.starts_with(|c: char| c.is_ascii_lowercase())
            && a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !a.contains("propolis")
            && !a.contains("honey")
    };
    if fits(&short) {
        assert_eq!(alias(&short, None), "host-908b rejected=1", "{short}");
    } else {
        assert_eq!(alias("north-relay", None), "north-relay rejected=0");
    }
}

// ---- incident messages and the whole send budget ----------------------------------------------

/// 1000 s before `NOW`, in the same boot: the times of the records below.
const INC_T: &str = "999000/abcdef01/4000";
/// One hour after `NOW`: the next reminder of the records below (14:46 UTC).
const INC_DUE: &str = "1003600/abcdef01/8600";

/// An `incidents` record of 34 fields: by default the open PAGE record of a failed sensor (id
/// w#3, instance u1a2b3, cause proc.exit:1, every time `INC_T`, the next reminder `INC_DUE`,
/// recorded by the hook), with the fields in `set` (numbered from 1, as the library numbers them)
/// replaced.
fn inc_rec(set: &[(usize, &str)]) -> String {
    let mut f: Vec<String> = [
        "w#3",
        "unit:sensor-ssh.service",
        "unit-failed",
        "listen",
        "u1a2b3",
        "PAGE",
        "open",
        INC_T,
        INC_T,
        INC_T,
        "proc.exit:1",
        INC_T,
        "-",
        "0",
        "-",
        "open",
        "0",
        "0",
        INC_DUE,
        "-",
        "-",
        "-",
        "0",
        "-",
        "-",
        "-",
        "-",
        "-",
        "1",
        "-",
        "1",
        "-",
        "delivered",
        "-",
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    for (i, v) in set {
        f[i - 1] = v.to_string();
    }
    format!("I\t{}\n", f.join("\t"))
}

/// The same record, resolved at `NOW` by the proof `PROOF`, its open delivered (a RESOLVED follows
/// only an open that got through).
fn inc_resolved(proof: &str, set: &[(usize, &str)]) -> String {
    let mut all: Vec<(usize, &str)> = vec![
        (7, "resolved"),
        (21, "1000000/abcdef01/5000"),
        (22, proof),
        (19, "-"),
        (17, "1"),
    ];
    all.extend_from_slice(set);
    inc_rec(&all)
}

struct Msg {
    rc: String,
    title: String,
    prio: String,
    body: Vec<String>,
    out: String,
}

/// Renders transition TX of incident ID over RECORDS (the incidents file after its N line) and
/// the extra lines `rest` (W lines), with `observe` as the observe file when it is not empty.
fn render_with(
    fx: &Fx,
    records: &[String],
    observe: &str,
    tx: &str,
    id: &str,
    was: &str,
    env: &[(&str, &str)],
) -> Msg {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    if !observe.is_empty() {
        fx.write(
            "var/lib/propolis/witness/observe",
            &format!("#observe v1 g=1\n{observe}"),
        );
    }
    let mut all: Vec<(&str, &str)> = NOW.to_vec();
    all.extend_from_slice(env);
    all.push(("TX", tx));
    all.push(("ID", id));
    all.push(("WAS", was));
    let r = fx.run_env(
        "PA_ROLE=\"${ROLE:-single}\"\npa_incident_load\n\
         if pa_render full \"$TX\" \"$ID\" \"$WAS\"; then echo rc=0; else echo rc=1; fi\n\
         printf 'title=%s\\nprio=%s\\n' \"$PA_TITLE\" \"$PA_PRIO\"\n\
         printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'",
        &all,
    );
    Msg {
        rc: r.get("rc"),
        title: r.get("title"),
        prio: r.get("prio"),
        body: r
            .out
            .lines()
            .filter_map(|l| l.strip_prefix("body="))
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        out: r.out.clone(),
    }
}

fn render(fx: &Fx, records: &[String], tx: &str, id: &str, was: &str) -> Msg {
    render_with(fx, records, "", tx, id, was, &[])
}

/// The key hash the ledger and the W lines name a key by.
fn keyhash(fx: &Fx, key: &str) -> String {
    fx.run_env("_pa_keyhash \"$K\"", &[("K", key)])
        .out
        .trim()
        .to_string()
}

/// The full-mode text of each transition of a PAGE incident, an ACT open, an acknowledged open,
/// a change, a reopen, a reminder and a resolve, as the message contract gives them: the closed
/// phrases, the opaque instance, times in UTC, `status <stage>` and the runbook key, the
/// lifecycle line with the next reminder and the flags; RESOLVED at priority 2 with its proof
/// words and the folded checks that wait for their next run; NO FURTHER LOSS for gateway-dup,
/// whose open counts the records the gateway lost.
#[test]
fn every_incident_shape_renders_the_full_mode_text_of_its_transition() {
    let fx = Fx::salted(SALT);
    let open = render(&fx, &[inc_rec(&[])], "open", "w#3", "");
    assert_eq!(open.rc, "0", "{}", open.out);
    assert_eq!(open.title, "PAGE host-908b - listen: unit u1a2b3 failed");
    assert_eq!(open.prio, "5");
    assert_eq!(
        open.body,
        [
            "Since 13:30:00 UTC (16 min) - detected 13:30:00 UTC",
            "Why: process exited (proc.exit 1), seen by hook@host-908b, known; last change: none in 24 h",
            "Where: host-908b (single), stage 1 of 10, u1a2b3",
            "Impact: not capturing on u1a2b3; evidence not measured",
            "Do: status listen - runbook listen-down",
            "w#3 opened - next reminder 14:46 UTC",
        ]
    );

    let daemon = inc_rec(&[
        (2, "unit:propolis.service"),
        (3, "daemon-down"),
        (4, "intake"),
        (5, "-"),
        (11, "db.unreachable"),
        (33, "-"),
    ]);
    let change = render(
        &fx,
        std::slice::from_ref(&daemon),
        "change",
        "w#3",
        "proc.exit:1",
    );
    assert_eq!(change.rc, "0", "{}", change.out);
    assert_eq!(
        change.title,
        "PAGE host-908b - intake: monitor and intake down (changed)"
    );
    assert_eq!(
        change.body,
        [
            "Since 13:30:00 UTC (16 min) - detected 13:30:00 UTC",
            "Why: database not answering (db.unreachable), seen by witness@host-908b, known; last change: none in 24 h",
            "Where: host-908b (single), stage 5 of 10, not known here",
            "Impact: nothing reaches the ledger; evidence not measured",
            "Do: status intake - runbook daemon-down",
            "w#3 changed: proc.exit 1 -> db.unreachable - next reminder 14:46 UTC",
        ]
    );

    let reopen = render(&fx, &[inc_rec(&[(23, "2")])], "reopen", "w#3", "");
    assert_eq!(
        reopen.title,
        "PAGE host-908b - listen: unit u1a2b3 failed (again)"
    );
    assert_eq!(
        reopen.body.last().unwrap(),
        "w#3 reopened (2 in 24 h) - next reminder 14:46 UTC"
    );
    let remind = render(&fx, &[inc_rec(&[(18, "1")])], "remind", "w#3", "");
    assert_eq!(
        remind.title,
        "PAGE host-908b - listen: unit u1a2b3 failed (still, 16 min)"
    );
    assert_eq!(
        remind.body.last().unwrap(),
        "w#3 reminder 1 of 3 - next reminder 14:46 UTC"
    );
    assert_eq!(remind.prio, "5");

    let act = render(
        &fx,
        &[inc_rec(&[
            (2, "unit:shipper.service"),
            (4, "ship"),
            (6, "ACT"),
            (7, "acked"),
        ])],
        "open",
        "w#3",
        "",
    );
    assert_eq!(act.title, "ACT host-908b - ship: unit u1a2b3 failed");
    assert_eq!(act.prio, "3");
    assert_eq!(
        act.body[3],
        "Impact: no new evidence from u1a2b3; evidence held"
    );
    assert_eq!(act.body[4], "Do: status ship - runbook ship-down");
    assert_eq!(
        act.body[5], "w#3 opened - next reminder none",
        "an acknowledged incident is not reminded"
    );
    let remind_act = render(
        &fx,
        &[inc_rec(&[(6, "ACT"), (18, "2")])],
        "remind",
        "w#3",
        "",
    );
    assert_eq!(remind_act.prio, "3");
    assert!(remind_act.body[5].starts_with("w#3 reminder 2 of 2 "));

    // A resolve, with one oneshot child still folded under it.
    let child = inc_rec(&[
        (1, "w#4"),
        (2, "unit:propolis-backup.service"),
        (4, "backup"),
        (6, "ACT"),
        (13, "w#3"),
        (30, "folded"),
    ]);
    let resolved = render(
        &fx,
        &[inc_resolved("active10", &[]), child.clone()],
        "resolve",
        "w#3",
        "",
    );
    assert_eq!(resolved.rc, "0", "{}", resolved.out);
    assert_eq!(
        resolved.title,
        "RESOLVED host-908b - listen: unit u1a2b3 failed"
    );
    assert_eq!(resolved.prio, "2");
    assert_eq!(
        resolved.body,
        [
            "Proof: running 10 min without a restart at 13:46:40 UTC, after 16 min",
            "Cause was: process exited (proc.exit 1)",
            "1 folded checks wait for their next run",
            "w#3 resolved",
        ]
    );
    let parent_open = render(&fx, &[inc_rec(&[]), child], "open", "w#3", "");
    assert!(
        parent_open.body[5].ends_with(" - folded 1"),
        "{:?}",
        parent_open.body
    );

    let dup = inc_rec(&[
        (2, "gwdup:c1a2b3"),
        (3, "gateway-dup"),
        (4, "gateway"),
        (5, "c1a2b3"),
        (6, "ACT"),
        (11, "gw.dup"),
        (33, "-"),
    ]);
    let observe = format!("P\tseen:gwdup:c1a2b3\t{INC_T}\tok\t-\t42\n");
    let m = render_with(
        &fx,
        std::slice::from_ref(&dup),
        &observe,
        "open",
        "w#3",
        "",
        &[],
    );
    assert_eq!(
        m.title,
        "ACT host-908b - gateway: rebuilt batch dropped from c1a2b3"
    );
    assert_eq!(
        m.body[3],
        "Impact: no new evidence from c1a2b3; evidence lost (counted) 42 records"
    );
    assert_eq!(m.body[4], "Do: status gateway - runbook gateway-dup");
    let m = render(
        &fx,
        &[inc_resolved(
            "quiet24",
            &[
                (2, "gwdup:c1a2b3"),
                (3, "gateway-dup"),
                (4, "gateway"),
                (5, "c1a2b3"),
                (6, "ACT"),
                (11, "gw.dup"),
            ],
        )],
        "resolve",
        "w#3",
        "",
    );
    assert_eq!(
        m.title,
        "NO FURTHER LOSS host-908b - gateway: rebuilt batch dropped from c1a2b3"
    );
    assert_eq!(
        m.body[0],
        "Proof: no further loss in 24 h at 13:46:40 UTC, after 16 min"
    );
    assert!(!m.out.contains("RESOLVED"), "{}", m.out);

    // Every flag, and the last change the hourly pass recorded before the onset.
    let kh = keyhash(&fx, "unit:sensor-ssh.service");
    let w = format!("W\t{INC_T}\t{kh}\topen\t1\tu1a2b3\tpool\n");
    let flagged = inc_rec(&[(30, "maint,notpersisted,cannotverify,dup,hookspool")]);
    let observe = "H\t/etc/propolis/propolis.env\t0123456789abcdef\t998400/abcdef01/3400\t01234567\t999900/abcdef01/4900\t-\n";
    let m = render_with(
        &fx,
        &[flagged, w.clone(), w],
        observe,
        "open",
        "w#3",
        "",
        &[("ROLE", "control")],
    );
    assert_eq!(
        m.body[1],
        "Why: process exited (proc.exit 1), seen by hook@host-908b, known; last change: config 10 min before onset"
    );
    assert_eq!(
        m.body[2],
        "Where: host-908b (control), stage 1 of 10, u1a2b3"
    );
    assert_eq!(
        m.body[5],
        "w#3 opened - next reminder 14:46 UTC - budget held 2, not persisted, maint, cannot verify, daemon also reports this"
    );
}

/// The proof words of every proof code, never the code; the phrase of each of config-check's
/// sixteen page rows with its instance, and with `a listener` or `a source` where the instance
/// is not known, each the phrase deploy/witness.sh's table gives that row; the folded unlisted
/// collectors named or counted.
#[test]
fn the_proof_words_and_the_sixteen_finding_phrases_come_from_their_closed_tables() {
    let fx = Fx::salted(SALT);
    for (code, words) in [
        ("active10", "running 10 min without a restart"),
        ("nextrun", "next run succeeded"),
        ("disabled", "disabled on purpose"),
        ("quiet30", "no restart for 30 min"),
        ("ready2", "monitor ready twice"),
        ("db2", "database answered twice"),
        ("sent2xx", "an alert got through"),
        ("clean2", "clean on two checks"),
        ("pushed", "public push seen"),
        ("persist2", "state written to disk again"),
        ("spool2", "collector arriving again"),
        ("quiet24", "no further loss in 24 h"),
        ("ended", "backup run ended"),
        ("pulled", "off-host copy taken"),
        ("room2", "room again on two checks"),
        ("fresh2", "witness pass running again"),
        ("restart", "seen after restart"),
    ] {
        let m = render(&fx, &[inc_resolved(code, &[])], "resolve", "w#3", "");
        assert_eq!(m.rc, "0", "{code}: {}", m.out);
        assert_eq!(
            m.body[0],
            format!("Proof: {words} at 13:46:40 UTC, after 16 min")
        );
        if !words.contains(code) {
            assert!(!m.out.contains(code), "{code}: {}", m.out);
        }
    }
    let m = render(&fx, &[inc_resolved("bogus", &[])], "resolve", "w#3", "");
    assert_eq!(m.rc, "1", "a proof outside the table renders nothing");

    let witness = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/witness.sh"
    ))
    .unwrap();
    let rows: Vec<Vec<String>> = witness
        .lines()
        .filter(|l| l.split('|').nth(1) == Some("page"))
        .map(|l| l.split('|').map(str::to_string).collect())
        .collect();
    assert_eq!(rows.len(), 16, "the page rows of WITNESS_CC_TABLE");
    for row in &rows {
        let (id, tier, stage, rule, phrase) = (&row[0], &row[2], &row[3], &row[5], &row[6]);
        let key = format!("finding:{id}:0123456789ab");
        let (inst, fallback) = match rule.as_str() {
            "logpath" => ("s1a2b3", "a source"),
            "fold" => ("c1a2b3", "a collector"),
            _ => ("u1a2b3", "a listener"),
        };
        let rec = |i: &str, count: &str| {
            inc_rec(&[
                (2, &key),
                (3, "finding"),
                (4, stage),
                (5, i),
                (6, tier),
                (11, "config.finding"),
                (34, count),
            ])
        };
        let m = render(&fx, &[rec(inst, "1")], "open", "w#3", "");
        assert_eq!(m.rc, "0", "{id}: {}", m.out);
        assert_eq!(
            m.title,
            format!(
                "{tier} host-908b - {stage}: {}",
                phrase.replace("<inst>", inst)
            ),
            "{id}"
        );
        assert_eq!(m.body[4], format!("Do: status {stage} - runbook finding"));
        assert!(
            !m.out.contains(id.as_str()),
            "{id} is never sent: {}",
            m.out
        );
        let m = render(&fx, &[rec("-", "-")], "open", "w#3", "");
        let want = if rule == "fold" {
            "? collectors not listed".to_string()
        } else {
            phrase.replace("<inst>", fallback)
        };
        assert_eq!(
            m.title,
            format!("{tier} host-908b - {stage}: {want}"),
            "{id}"
        );
        if rule == "fold" {
            for (count, want) in [
                ("3", "3 collectors not listed"),
                ("20+", "20+ collectors not listed"),
            ] {
                let m = render(&fx, &[rec("-", count)], "open", "w#3", "");
                assert_eq!(m.title, format!("{tier} host-908b - {stage}: {want}"));
            }
        }
    }
    let m = render(
        &fx,
        &[inc_rec(&[
            (2, "finding:ops-push-half:0123456789ab"),
            (3, "finding"),
        ])],
        "open",
        "w#3",
        "",
    );
    assert_eq!(m.rc, "1", "a finding that is not a page row has no phrase");
}

/// Every pushable kind on the key it is recorded under, for the size and planted-word cases.
const KINDS: [(&str, &str, &str, &str, &str); 25] = [
    (
        "unit-failed",
        "unit:sensor-ssh.service",
        "listen",
        "PAGE",
        "u",
    ),
    (
        "unit-crashloop",
        "unit:sensor-ssh.service",
        "listen",
        "PAGE",
        "u",
    ),
    (
        "unit-nobind",
        "unit:sensor-ssh.service",
        "listen",
        "ACT",
        "u",
    ),
    (
        "unit-failed",
        "unit:propolis-backup.service",
        "backup",
        "ACT",
        "u",
    ),
    (
        "unit-failed",
        "unit:propolis-logrotate.service",
        "source",
        "ACT",
        "u",
    ),
    (
        "unit-failed",
        "unit:propolis-witness@light.service",
        "witness",
        "ACT",
        "u",
    ),
    ("unit-failed", "unit:other.service", "host", "ACT", "u"),
    (
        "daemon-down",
        "unit:propolis.service",
        "intake",
        "PAGE",
        "u",
    ),
    ("daemon-degraded", "ready:local", "intake", "ACT", "-"),
    ("db-unreachable", "db:local", "ledger", "PAGE", "-"),
    ("db-readonly", "db:recovery", "ledger", "PAGE", "-"),
    ("db-xid", "dbstate:xid", "ledger", "ACT", "-"),
    ("db-slots", "dbstate:slots", "ledger", "ACT", "-"),
    ("alert-path", "alert:shell", "alert", "PAGE", "-"),
    (
        "finding",
        "finding:danger:0123456789ab",
        "listen",
        "PAGE",
        "u",
    ),
    ("push-failing", "push:timer", "publish", "ACT", "-"),
    ("push-unscheduled", "push:none", "publish", "ACT", "-"),
    ("spool-quiet", "spool:c1a2b3", "ship", "ACT", "c"),
    ("gateway-dup", "gwdup:c1a2b3", "gateway", "ACT", "c"),
    ("ship-failing", "ship:local", "ship", "ACT", "-"),
    ("backup-hung", "backup:run", "backup", "ACT", "-"),
    ("volume-filling", "vol:m1a2b3", "host", "ACT", "m"),
    ("volume-full-soon", "vol:m1a2b3", "host", "PAGE", "m"),
    ("witness-stale", "witness:hourly", "witness", "ACT", "-"),
    ("cc-stopped", "tool:config-check", "witness", "ACT", "-"),
];

/// The five transitions, each with the record state it applies to and the proof of a resolve.
fn shape_record(tx: &str, set: &[(usize, &str)]) -> String {
    if tx == "resolve" {
        inc_resolved("active10", set)
    } else {
        inc_rec(set)
    }
}

const SHAPES: [&str; 5] = ["open", "change", "reopen", "remind", "resolve"];

/// A recognisable word in every field of a record the renderer reads, in a finding's key, in the
/// W lines and the observe file it reads, in meta, in the env files, in the environment and in the
/// host name reaches no title and no body of any shape: only closed phrases, ids matched to their
/// form, counts and times are written. Neither the word propolis, the host name, the topic, the
/// token nor a URL is ever in a message, though the daemon's own key names propolis.service.
#[test]
fn a_planted_word_in_any_field_or_state_file_never_reaches_a_title_or_a_body() {
    let fx = Fx::salted(SALT);
    write_exec(
        &fx.bin.join("hostname"),
        "#!/usr/bin/env bash\necho plantedhost\n",
    );
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://plantedurl.example\nPROPOLIS_OPS_NTFY_TOPIC=plantedtopic\nPROPOLIS_OPS_NTFY_TOKEN=tk_plantedtoken\n",
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v1 g=1\nM\tclock\tplantedmeta\nM\twhere\tplantedmeta\n",
    );
    let planted = "plantedword";
    let banned = [
        planted,
        "plantedhost",
        "plantedurl",
        "plantedtopic",
        "plantedtoken",
        "plantedmeta",
        "propolis",
        "://",
        "ssh",
        "Edge07",
    ];
    let kh_word = "plantedword";
    let w = format!("W\t{INC_T}\t{kh_word}\topen\t1\t{planted}\t{planted}\n");
    let observe = format!(
        "H\t/etc/propolis/{planted}.env\t{planted}\t998400/abcdef01/3400\t{planted}\t{planted}\t{planted}\n\
         P\tseen:gwdup:c1a2b3\t{INC_T}\t{planted}\t{planted}\t{planted}\n\
         P\tseen:{planted}\t{INC_T}\tok\t-\t{planted}\n\
         U\tsensor-{planted}.service\t{INC_T}\t{planted}\t{planted}\t{planted}\n\
         R\tsensor-{planted}.service\t{INC_T}\t{planted}\n\
         Z\tm1a2b3\t{planted}\t{planted}\t{planted}\t{planted}\t{planted}\n\
         Z\tm1a2b3\t{INC_T}\t{planted}\t{planted}\n\
         S\t{planted}\t{planted}\n"
    );
    // Every pushable kind, and besides them the folded unlisted collectors (whose count field only
    // that row reads) and an intake finding, each open and acknowledged.
    let mut kinds: Vec<(&str, String, &str, &str)> = KINDS
        .iter()
        .map(|(kind, key, stage, tier, _)| {
            (*kind, key.replace("ssh", "plantedword"), *stage, *tier)
        })
        .collect();
    kinds.push((
        "finding",
        "finding:spool-unlisted:all".to_string(),
        "gateway",
        "ACT",
    ));
    kinds.push((
        "finding",
        format!("finding:intake-absent:{planted}"),
        "intake",
        "ACT",
    ));
    for (kind, key, stage, tier) in &kinds {
        for tx in SHAPES {
            for state in ["open", "acked"] {
                if state == "acked" && (tx == "remind" || tx == "resolve") {
                    continue;
                }
                // Every field the renderer tolerates holds the word; those it checks hold a value
                // of their form, so the message is rendered and its text can be searched. The
                // 35th field, which a newer writer appends, holds it too.
                let delivered = if tx == "resolve" { "1" } else { planted };
                let mut set: Vec<(usize, &str)> = vec![
                    (2, key),
                    (3, kind),
                    (4, stage),
                    (5, planted),
                    (6, tier),
                    (8, planted),
                    (13, planted),
                    (14, planted),
                    (15, planted),
                    (17, delivered),
                    (20, planted),
                    (24, planted),
                    (25, planted),
                    (26, planted),
                    (27, planted),
                    (28, planted),
                    (29, planted),
                    (31, planted),
                    (32, planted),
                    (33, planted),
                    (34, planted),
                ];
                let cause = if *kind == "alert-path" {
                    format!("http.{planted}:{planted}")
                } else {
                    format!("{planted}:1")
                };
                let flags = format!("{planted},maint");
                set.push((11, &cause));
                set.push((30, &flags));
                if tx != "resolve" {
                    set.push((7, state));
                }
                let rec = shape_record(tx, &set).replace('\n', &format!("\t{planted}\n"));
                let child = inc_rec(&[
                    (1, "w#9"),
                    (2, planted),
                    (3, planted),
                    (13, "w#3"),
                    (4, planted),
                ]);
                let m = render_with(
                    &fx,
                    &[rec, child, w.clone()],
                    &observe,
                    tx,
                    "w#3",
                    &format!("{planted}:2"),
                    &[
                        ("PROPOLIS_OPS_NTFY_TOPIC", "plantedtopic"),
                        ("PA_ALIAS_SET", "plantedhost"),
                    ],
                );
                assert_eq!(m.rc, "0", "{key} {tx} {state}: {}", m.out);
                for b in banned {
                    assert!(
                        !m.out.to_lowercase().contains(&b.to_lowercase()),
                        "{key} {tx} {state}: {b} reached the message:\n{}",
                        m.out
                    );
                }
            }
        }
    }
    // A key that names a finding id outside the page rows, a kind, a stage or a tier outside the
    // tables: nothing is rendered at all.
    for set in [
        vec![(2, "finding:plantedword:0123456789ab"), (3, "finding")],
        vec![(3, planted)],
        vec![(4, planted)],
        vec![(6, planted)],
        vec![(7, planted)],
    ] {
        for tx in SHAPES {
            let m = render(&fx, &[shape_record(tx, &set)], tx, "w#3", "");
            assert_eq!(m.rc, "1", "{set:?} {tx}: {}", m.out);
            assert_eq!(m.title, "");
            assert!(m.body.is_empty(), "{set:?} {tx}");
        }
    }
}

/// Each field a record holds, fed a value out of its form (a tab, a control byte, 300 bytes, a
/// newline, a leading dash, an escape sequence), either stops the message or reads as not known;
/// the value itself is never passed through, and every line of what is rendered is printable
/// ASCII.
#[test]
fn a_field_out_of_its_form_stops_the_message_or_reads_as_not_known_and_never_passes_through() {
    let fx = Fx::salted(SALT);
    let long = "z".repeat(300);
    let values = [
        "a\tbplant".to_string(),
        "x\u{1}y".to_string(),
        long.clone(),
        "line\nnlplant".to_string(),
        "-dash".to_string(),
        "\u{1b}[31mred".to_string(),
    ];
    let marks = [
        "bplant",
        "x\u{1}",
        &long[..60],
        "nlplant",
        "-dash",
        "\u{1b}",
    ];
    // Each field over the default record, and the fields only one kind reads over that kind: the
    // restart count over a crash loop, the cause (bare, and after an HTTP class) over the alert
    // path, the count over the folded unlisted collectors.
    let crashloop = [(3, "unit-crashloop")];
    let alert = [
        (2, "alert:shell"),
        (3, "alert-path"),
        (4, "alert"),
        (5, "-"),
    ];
    let unlisted = [
        (2, "finding:spool-unlisted:all"),
        (3, "finding"),
        (4, "gateway"),
        (5, "-"),
        (6, "ACT"),
    ];
    type Fields<'a> = &'a [(usize, &'a str)];
    let mut cases: Vec<(Fields, usize, &str)> = Vec::new();
    for field in [
        1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13, 18, 19, 21, 22, 23, 30, 31, 33, 34,
    ] {
        cases.push((&[], field, ""));
    }
    cases.push((&crashloop, 31, ""));
    cases.push((&alert, 11, ""));
    cases.push((&alert, 11, "http.auth:"));
    cases.push((&unlisted, 34, ""));
    let observe = "U\tsensor-ssh.service\t999000/abcdef01/4000\t9\tabcdef01\tactive\t-\t1\t-\n\
                   R\tsensor-ssh.service\t999000/abcdef01/4000\t3\n";
    for tx in SHAPES {
        for (base, field, prefix) in &cases {
            for (v, mark) in values.iter().zip(marks) {
                let v = format!("{prefix}{v}");
                let mut set = base.to_vec();
                set.push((*field, v.as_str()));
                let rec = shape_record(tx, &set);
                let m = render_with(&fx, &[rec], observe, tx, "w#3", &v, &[]);
                let text = format!("{}\n{}", m.title, m.body.join("\n"));
                if m.rc == "1" {
                    assert_eq!(text.trim(), "", "{tx} {base:?} field {field}");
                    continue;
                }
                assert!(
                    !text.contains(mark),
                    "{tx} {base:?} field {field} passed {v:?} through:\n{text}"
                );
                for line in text.lines() {
                    assert!(
                        line.len() <= 200 && line.bytes().all(|b| (b' '..=b'~').contains(&b)),
                        "{tx} {base:?} field {field}: {line:?}"
                    );
                }
            }
        }
    }
    // The id asked for must be an incident id; the cause before a change reads not known.
    let m = render(&fx, &[inc_rec(&[])], "open", "-w#3", "");
    assert_eq!(m.rc, "1");
    let m = render(&fx, &[inc_rec(&[])], "change", "w#3", "proc.exit:1\u{1b}");
    assert!(
        m.body[5].starts_with("w#3 changed: not known here -> proc.exit 1"),
        "{:?}",
        m.body
    );
    let m = render(&fx, &[inc_rec(&[(11, "unknown")])], "open", "w#3", "");
    assert_eq!(
        m.body[1],
        "Why: not known here, seen by hook@host-908b, not known here; last change: none in 24 h"
    );
    let m = render(&fx, &[inc_rec(&[(5, "-")])], "open", "w#3", "");
    assert_eq!(m.title, "PAGE host-908b - listen: unit ? failed");
    assert_eq!(
        m.body[2],
        "Where: host-908b (single), stage 1 of 10, not known here"
    );
    assert_eq!(m.body[3], "Impact: not known here; evidence not measured");
}

/// A record whose tier, kind, state or stage the tables do not know, a NOTICE among them, renders
/// nothing for any transition and is admitted nothing: no ledger line is written and the record
/// is left as it was. So does a record with an empty field, which no writer makes: the fields
/// after it cannot be placed, and one read a place early must not pass for the field it is not.
#[test]
fn a_record_the_tables_do_not_know_renders_nothing_and_is_admitted_nothing() {
    let fx = Fx::salted(SALT);
    for set in [
        vec![(16, ""), (17, "1")],
        vec![(13, "")],
        vec![(34, "")],
        vec![(6, "NOTICE")],
        vec![(6, "-")],
        vec![(6, "page")],
        vec![(3, "tool-unusable"), (6, "NOTICE")],
        vec![(3, "db-locks")],
        vec![(3, "bogus")],
        vec![(7, "pending")],
        vec![(7, "-")],
        vec![(4, "stage11")],
    ] {
        for tx in SHAPES {
            let rec = shape_record(tx, &set);
            let m = render(&fx, std::slice::from_ref(&rec), tx, "w#3", "");
            assert_eq!(m.rc, "1", "{set:?} {tx}: {}", m.out);
            let before = fx.read("var/lib/propolis/witness/incidents");
            let r = fx.run_env(
                &format!(
                    "pa_incident_load\necho \"budget=$(pa_budget_admit incident unit:sensor-ssh.service {tx} 0)\"\n\
                     echo \"admit=$(pa_incident_admit unit:sensor-ssh.service {tx} 0 full light)\""
                ),
                &NOW,
            );
            assert_eq!(r.get("budget"), "withhold:unknown", "{set:?} {tx}");
            assert_eq!(r.get("admit"), "withhold:unknown", "{set:?} {tx}");
            assert!(
                !fx.p("var/lib/propolis/witness/send-ledger").exists(),
                "{set:?} {tx}: no ledger line"
            );
            assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
        }
    }
    // A transition the state does not allow: a reminder of an acknowledged record, a resolve of
    // an open one, an open of a resolved one, and NEW 1 on anything but an open.
    for (state, tx, new) in [
        ("acked", "remind", "0"),
        ("open", "resolve", "0"),
        ("resolved", "open", "1"),
        ("open", "change", "1"),
    ] {
        let rec = inc_rec(&[(7, state), (22, "active10")]);
        let m = render(&fx, std::slice::from_ref(&rec), tx, "w#3", "");
        // NEW is the budget's alone: a change renders whatever NEW the caller has.
        assert_eq!(
            m.rc,
            if new == "1" && tx != "open" { "0" } else { "1" },
            "{state} {tx}"
        );
        let r = fx.run_env(
            &format!("pa_incident_load; pa_budget_admit incident unit:sensor-ssh.service {tx} {new}; echo"),
            &NOW,
        );
        assert_eq!(r.out.trim(), "withhold:unknown", "{state} {tx} {new}");
    }
}

/// With a 32-character alias, 8-hex instances, the longest ids, causes, counts, durations and
/// every flag, every shape of every kind keeps its headline to 80 characters by its fixed rule,
/// every line within the sender's 200-byte line rule and the body (with the newline the sender
/// adds) within the 1024 bytes it cuts at, so the sender never cuts a line; and so does the daily
/// message naming ten ids.
#[test]
fn every_shape_fits_the_senders_line_and_body_limits_with_the_longest_values() {
    let fx = Fx::salted(SALT);
    let alias = "a234567890-234567890-234567890-z";
    assert_eq!(alias.len(), 32);
    let id = "w#999999999";
    // The onset 23 h 59 min ago in an earlier boot, and a change 23 h 59 min before it.
    let onset = "913660/0000aaaa/1";
    let observe = "H\t/usr/local/bin/x\t0123456789abcdef\t827320/0000bbbb/1\t01234567\t-\t-\n\
                   P\tseen:gwdup:c12345678\t999000/abcdef01/4000\tok\t-\t999999999\n\
                   U\tsensor-ssh.service\t999000/abcdef01/4000\t999999999\tabcdef01\tactive\t-\t1\t-\n\
                   R\tsensor-ssh.service\t999000/abcdef01/4000\t0\n";
    let mut shortened = 0;
    for (kind, key, stage, tier, prefix) in KINDS {
        let inst = if prefix == "-" {
            "-".to_string()
        } else {
            format!("{prefix}12345678")
        };
        let key = key
            .replace("c1a2b3", "c12345678")
            .replace("m1a2b3", "m12345678");
        let kh = keyhash(&fx, &key);
        for tx in SHAPES {
            let mut records = vec![shape_record(
                tx,
                &[
                    (1, id),
                    (2, &key),
                    (3, kind),
                    (4, stage),
                    (5, &inst),
                    (6, tier),
                    (8, onset),
                    (9, onset),
                    (10, onset),
                    (
                        11,
                        if kind == "alert-path" {
                            "http.not_found:404"
                        } else {
                            "proc.sandbox:243"
                        },
                    ),
                    (18, "999999999"),
                    (23, "999999999"),
                    (30, "maint,notpersisted,cannotverify,dup"),
                    (31, "999999999"),
                    (33, "-"),
                    (34, "20+"),
                ],
            )];
            for n in 0..120 {
                records.push(inc_rec(&[
                    (1, &format!("w#{}", 1000 + n)),
                    (2, &format!("unit:c{n}.service")),
                    (13, id),
                ]));
            }
            for _ in 0..1000 {
                records.push(format!("W\t{INC_T}\t{kh}\topen\t1\t-\tpool\n"));
            }
            let m = render_with(
                &fx,
                &records,
                observe,
                tx,
                id,
                "proc.sandbox:243",
                &[("PA_ALIAS_SET", alias), ("ROLE", "collector")],
            );
            assert_eq!(m.rc, "0", "{kind} {tx}: {}", m.out);
            assert!(
                m.title.len() <= 80,
                "{kind} {tx}: {} ({})",
                m.title,
                m.title.len()
            );
            assert!(m.title.contains(alias), "{}", m.title);
            if !m.title.contains(&format!(" - {stage}: ")) {
                shortened += 1;
            }
            let body = m.body.join("\n");
            assert!(body.len() < 1024, "{kind} {tx}: {} bytes", body.len());
            for line in &m.body {
                assert!(line.len() <= 200, "{kind} {tx}: {line} ({})", line.len());
            }
            if tx != "resolve" {
                assert!(
                    m.body[5].contains("budget held 999,") && m.body[5].contains("folded 120,"),
                    "{}",
                    m.body[5]
                );
            }
        }
    }
    assert!(shortened > 0, "the headline rule was exercised");

    let records: Vec<String> = (0..12)
        .map(|n| daily_record(&[(1, &format!("w#99999999{}", n % 10)), (6, "PAGE")]))
        .collect();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        "PA_WHERE=persistent; PA_ROLE=control\npa_settings_load\n\
         pa_render full daily - && printf '%s\\n' \"$PA_BODY\"",
        &[
            ("PA_TEST_WALL", "1000000"),
            ("PA_TEST_BOOT", "abcdef01"),
            ("PA_TEST_UP", "5000"),
            ("PA_ALIAS_SET", alias),
            ("PA_DAILY_LISTED", "999999"),
        ],
    );
    assert!(
        r.out.starts_with("open: 12 (PAGE 12, ACT 0) w#999999990"),
        "{}",
        r.out
    );
    assert!(r.out.len() < 1024);
    assert!(r.out.lines().all(|l| l.len() <= 200));
}

/// The test page and the daily message are rendered exactly as before this release: the same
/// title, priority and body, held here against fixed text.
#[test]
fn the_test_page_and_the_daily_message_keep_their_title_priority_and_body() {
    let fx = Fx::salted(SALT);
    let r = fx.run_env(
        "pa_render full test 0a1b2c && printf 'title=%s\\nprio=%s\\nbody=%s\\n' \"$PA_TITLE\" \"$PA_PRIO\" \"$PA_BODY\"",
        &NOW,
    );
    assert_eq!(
        r.out,
        "title=host-908b: test page 0a1b2c\nprio=3\nbody=Type back on host-908b: status --ack-test 0a1b2c\n"
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t40\n{}{}",
            daily_record(&[]),
            daily_record(&[(1, "w#2"), (6, "PAGE"), (7, "resolved"), (21, &lib_at(60))])
        ),
    );
    let r = fx.run_env(
        "PA_WHERE=persistent; PA_ROLE=single\npa_settings_load\n\
         pa_render full daily - && printf 'title=%s\\nprio=%s\\n%s\\n' \"$PA_TITLE\" \"$PA_PRIO\" \"$PA_BODY\"",
        &NOW,
    );
    assert_eq!(
        r.out,
        "title=host-908b: daily\nprio=2\n\
         open: 1 (PAGE 0, ACT 1) w#1\n\
         resolved 24 h: 1; withheld by budget 24 h: 0\n\
         new notices 24 h: 0\n\
         alerts: NOT VERIFIED (never); profile legacy\n\
         v2 would have pushed 3 in 24 h\n\
         state: persisted\n\
         Do: status\n"
    );
}

/// A ledger line of CLASS for key hash KH, AGO seconds before `NOW` (in this boot under 5000 s,
/// in an earlier one beyond).
fn ledger_line(class: &str, kh: &str, ago: u64, result: &str) -> String {
    format!(
        "L\t{}\t{class}\t{kh}\topen\tfull\t{result}\tlight\n",
        lib_at(ago)
    )
}

/// The verdict of `pa_budget_admit incident KEY TX NEW` and the class it admits under, over
/// RECORDS and the ledger LINES.
fn admit_over(
    fx: &Fx,
    records: &[String],
    lines: &[String],
    key: &str,
    tx: &str,
    new: &str,
) -> String {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{}", lines.concat()),
    );
    let r = fx.run_env(
        &format!("pa_incident_load\npa_budget_admit incident '{key}' {tx} {new} > /dev/null\necho \"v=$PA_ADMIT_VERDICT $PA_ADMIT_AS\""),
        &NOW,
    );
    r.get("v").trim().to_string()
}

fn lines_of(n: usize, class: &str, kh: &str, ago: u64) -> Vec<String> {
    (0..n).map(|_| ledger_line(class, kh, ago, "ok")).collect()
}

/// The order of checks for an incident message: a reserve kind at PAGE opens, changes and reopens
/// from the reserve whatever the pool holds, and once the reserve is spent goes through the pool
/// rules; no other kind spends it; a key past six pushes a day is withheld except for the open of
/// a new incident; a listener is held to two of the pool's four an hour and, except for a new
/// open, eight of its sixteen a day; the pool holds at four an hour and sixteen a day.
#[test]
fn the_budget_decides_an_incident_message_by_the_order_of_its_checks() {
    let fx = Fx::salted(SALT);
    let db = inc_rec(&[
        (2, "db:local"),
        (3, "db-unreachable"),
        (4, "ledger"),
        (5, "-"),
    ]);
    let other = "00000000";
    let full_pool = lines_of(4, "pool", other, 600);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &full_pool,
            "db:local",
            "open",
            "1"
        ),
        "admit reserve"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &full_pool,
            "db:local",
            "change",
            "0"
        ),
        "admit reserve"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &full_pool,
            "db:local",
            "remind",
            "0"
        ),
        "withhold:pool",
        "a reminder never comes from the reserve"
    );
    let spent = lines_of(1, "reserve", other, 600);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &spent,
            "db:local",
            "open",
            "1"
        ),
        "admit pool"
    );
    let spent_and_full = [spent.clone(), full_pool.clone()].concat();
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &spent_and_full,
            "db:local",
            "open",
            "1"
        ),
        "withhold:pool"
    );
    let day = lines_of(4, "reserve", other, 7200);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &day,
            "db:local",
            "open",
            "1"
        ),
        "admit pool"
    );

    // Only the closed reserve kinds, at PAGE, on their own keys.
    for (set, key) in [
        (vec![], "unit:sensor-ssh.service"),
        (
            vec![(2, "unit:other.service"), (3, "daemon-down"), (4, "intake")],
            "unit:other.service",
        ),
        (
            vec![
                (2, "db:local"),
                (3, "db-unreachable"),
                (4, "ledger"),
                (6, "ACT"),
            ],
            "db:local",
        ),
        (
            vec![(2, "finding:danger:0123456789ab"), (3, "finding")],
            "finding:danger:0123456789ab",
        ),
        (
            vec![(2, "vol:m1a2b3"), (3, "volume-full-soon"), (4, "host")],
            "vol:m1a2b3",
        ),
        (
            vec![(2, "db:recovery"), (3, "db-readonly"), (4, "ledger")],
            "db:recovery",
        ),
    ] {
        let v = admit_over(&fx, &[inc_rec(&set)], &[], key, "open", "1");
        assert!(v == "admit pool" || v == "admit stage1", "{key}: {v}");
    }
    for (set, key) in [
        (
            vec![
                (2, "unit:propolis.service"),
                (3, "daemon-down"),
                (4, "intake"),
            ],
            "unit:propolis.service",
        ),
        (
            vec![
                (2, "unit:propolis.service"),
                (3, "unit-crashloop"),
                (4, "intake"),
            ],
            "unit:propolis.service",
        ),
        (
            vec![(2, "alert:shell"), (3, "alert-path"), (4, "alert")],
            "alert:shell",
        ),
        (
            vec![(2, "db:remote"), (3, "db-unreachable"), (4, "ledger")],
            "db:remote",
        ),
    ] {
        assert_eq!(
            admit_over(&fx, &[inc_rec(&set)], &full_pool, key, "reopen", "0"),
            "admit reserve",
            "{key}"
        );
    }

    // The key cap, which a new incident's open passes.
    let ship = inc_rec(&[(2, "unit:shipper.service"), (4, "ship"), (6, "ACT")]);
    let kh = keyhash(&fx, "unit:shipper.service");
    let six = lines_of(6, "pool", &kh, 7200);
    for tx in ["remind", "change", "reopen", "resolve"] {
        let rec = if tx == "resolve" {
            inc_resolved(
                "active10",
                &[(2, "unit:shipper.service"), (4, "ship"), (6, "ACT")],
            )
        } else {
            ship.clone()
        };
        assert_eq!(
            admit_over(&fx, &[rec], &six, "unit:shipper.service", tx, "0"),
            "withhold:key-cap",
            "{tx}"
        );
    }
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &six,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &six,
            "unit:shipper.service",
            "open",
            "0"
        ),
        "withhold:key-cap"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &six[..5],
            "unit:shipper.service",
            "remind",
            "0"
        ),
        "admit pool"
    );

    // Stage 1.
    let sensor = inc_rec(&[]);
    let s = "unit:sensor-ssh.service";
    let hour2 = lines_of(2, "stage1", other, 600);
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sensor), &hour2, s, "open", "1"),
        "withhold:stage1-cap"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &hour2,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool"
    );
    let day8 = lines_of(8, "stage1", other, 7200);
    let sent = inc_rec(&[(14, "1"), (17, "1")]);
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sent), &day8, s, "remind", "0"),
        "withhold:stage1-cap"
    );
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sensor), &day8, s, "open", "1"),
        "admit stage1"
    );
    let listen_finding = inc_rec(&[(2, "finding:danger:0123456789ab"), (3, "finding")]);
    assert_eq!(
        admit_over(
            &fx,
            &[listen_finding],
            &hour2,
            "finding:danger:0123456789ab",
            "open",
            "1"
        ),
        "withhold:stage1-cap",
        "a listen-stage finding is a listener"
    );

    // A late open: the first reminder of a listener incident whose open was never admitted has
    // an allowance of its own, one an hour and four a day, whatever the stage-1 caps, the pool
    // and the key hold; once it is spent the reminder goes on through the ordinary rules.
    let thirty = lines_of(30, "stage1", other, 7200);
    let skh = keyhash(&fx, s);
    let six_s = lines_of(6, "stage1", &skh, 7200);
    for (n, lines) in [&Vec::new(), &hour2, &thirty, &full_pool, &six_s]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            admit_over(&fx, std::slice::from_ref(&sensor), lines, s, "remind", "0"),
            "admit late",
            "ledger {n}"
        );
    }
    let late_hour = lines_of(1, "late", other, 600);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &late_hour,
            s,
            "remind",
            "0"
        ),
        "admit stage1",
        "one late open an hour, then the ordinary rules"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &[late_hour.clone(), hour2.clone()].concat(),
            s,
            "remind",
            "0"
        ),
        "withhold:stage1-cap"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &[late_hour.clone(), six_s.clone()].concat(),
            s,
            "remind",
            "0"
        ),
        "withhold:key-cap"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &[lines_of(3, "late", other, 7200), hour2.clone()].concat(),
            s,
            "remind",
            "0"
        ),
        "admit late"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &[lines_of(4, "late", other, 7200), hour2.clone()].concat(),
            s,
            "remind",
            "0"
        ),
        "withhold:stage1-cap",
        "four late opens a day"
    );
    // Only a reminder of a listener that has had no message is one: a count of sends that is not
    // a plain 0 is not read as none.
    for (rec, tx) in [
        (sent.clone(), "remind"),
        (inc_rec(&[(14, "2")]), "remind"),
        (inc_rec(&[(14, "-")]), "remind"),
        (inc_rec(&[(14, "00")]), "remind"),
        (inc_rec(&[(17, "1")]), "remind"),
        (sensor.clone(), "change"),
        (sensor.clone(), "reopen"),
    ] {
        assert_eq!(
            admit_over(&fx, &[rec], &hour2, s, tx, "0"),
            "withhold:stage1-cap",
            "{tx}"
        );
    }
    // Any listener has it, whatever its tier: a sensor unit at ACT, a finding of the listen stage.
    assert_eq!(
        admit_over(&fx, &[inc_rec(&[(6, "ACT")])], &hour2, s, "remind", "0"),
        "admit late"
    );
    assert_eq!(
        admit_over(
            &fx,
            &[inc_rec(&[
                (2, "finding:danger:0123456789ab"),
                (3, "finding")
            ])],
            &hour2,
            "finding:danger:0123456789ab",
            "remind",
            "0"
        ),
        "admit late"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &full_pool,
            "unit:shipper.service",
            "remind",
            "0"
        ),
        "withhold:pool",
        "no other kind has a late open"
    );
    // A late line counts against its key and against nothing else.
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sent),
            &lines_of(6, "late", &skh, 7200),
            s,
            "remind",
            "0"
        ),
        "withhold:key-cap"
    );
    let late_many = lines_of(4, "late", other, 600);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&sensor),
            &late_many,
            s,
            "open",
            "1"
        ),
        "admit stage1"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &late_many,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool"
    );

    // The pool, with listener lines counted to the sub-cap.
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &full_pool,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "withhold:pool"
    );
    let day16 = lines_of(16, "pool", other, 7200);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &day16,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "withhold:pool"
    );
    let busy = [
        lines_of(7, "pool", other, 7200),
        lines_of(20, "stage1", other, 7200),
    ]
    .concat();
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &busy,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool"
    );
    let busier = [
        lines_of(8, "pool", other, 7200),
        lines_of(20, "stage1", other, 7200),
    ]
    .concat();
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &busier,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "withhold:pool"
    );
    let hourly = [
        lines_of(2, "pool", other, 600),
        lines_of(1, "stage1", other, 600),
    ]
    .concat();
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &hourly,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool"
    );
    let reserve_many = lines_of(30, "reserve", other, 7200);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &reserve_many,
            "unit:shipper.service",
            "open",
            "1"
        ),
        "admit pool",
        "reserve lines never count against the pool"
    );
}

/// An account that crashes sensors in bursts or reopens cheap incidents all day: with thirty
/// listener pushes in the day and two in the last hour, a new listener's open is held while the
/// hour is full, and a new incident of any other kind goes out at once; the reserve is never spent
/// by any of it. With fewer than the day's sixteen, a new listener's open goes out once the hour
/// has room.
#[test]
fn an_account_crashing_sensors_spends_neither_the_reserve_nor_the_room_of_other_kinds() {
    let fx = Fx::salted(SALT);
    let other = "00000000";
    let mut day: Vec<String> = (1..=30)
        .map(|n| ledger_line("stage1", other, 3600 + n * 2400, "ok"))
        .collect();
    day.extend(lines_of(2, "stage1", other, 1200));
    let sensor = inc_rec(&[(2, "unit:sensor-new.service")]);
    let s = "unit:sensor-new.service";
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sensor), &day, s, "open", "1"),
        "withhold:stage1-cap"
    );
    let mut later: Vec<String> = (1..=13)
        .map(|n| ledger_line("stage1", other, 3600 + n * 2400, "ok"))
        .collect();
    later.extend(lines_of(2, "stage1", other, 3700));
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sensor), &later, s, "open", "1"),
        "admit stage1"
    );
    later.push(ledger_line("stage1", other, 7200, "ok"));
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&sensor), &later, s, "open", "1"),
        "withhold:stage1-cap",
        "sixteen listener pushes in the day are the most there can be, new opens included"
    );
    let backup = inc_rec(&[
        (2, "backup:run"),
        (3, "backup-hung"),
        (4, "backup"),
        (5, "-"),
        (6, "ACT"),
    ]);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&backup),
            &day,
            "backup:run",
            "open",
            "1"
        ),
        "admit pool"
    );
    let finding = inc_rec(&[
        (2, "finding:backup-stale:0123456789ab"),
        (3, "finding"),
        (4, "backup"),
        (6, "ACT"),
    ]);
    assert_eq!(
        admit_over(
            &fx,
            &[finding],
            &day,
            "finding:backup-stale:0123456789ab",
            "open",
            "1"
        ),
        "admit pool"
    );

    // Admissions of listener transitions, one after another, never write a reserve line.
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\n",
    );
    let records: Vec<String> = (0..6)
        .map(|n| {
            inc_rec(&[
                (1, &format!("w#{n}")),
                (2, &format!("unit:sensor-s{n}.service")),
            ])
        })
        .collect();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        "for n in 0 1 2 3 4 5; do pa_incident_load; echo \"v$n=$(pa_incident_admit unit:sensor-s$n.service open 1 full light)\"; done",
        &NOW,
    );
    assert_eq!(r.get("v0"), "admit", "{}", r.err);
    assert_eq!(r.get("v1"), "admit");
    assert_eq!(r.get("v2"), "withhold:stage1-cap");
    let ledger = fx.read("var/lib/propolis/witness/send-ledger");
    assert_eq!(ledger.matches("\tstage1\t").count(), 2, "{ledger}");
    assert!(!ledger.contains("\treserve\t"), "{ledger}");
}

/// The exempt classes have their own caps and count against nothing else: storm one in six
/// hours, summary one an hour and twelve a day, switch one a day, pointer two an hour and
/// forty-eight a day. pa_budget_next says when the next has room.
#[test]
fn the_exempt_classes_keep_their_own_caps_and_say_when_the_next_has_room() {
    let fx = Fx::salted(SALT);
    let other = "00000000";
    let verdict = |lines: &[String], class: &str| -> (String, String) {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{}", lines.concat()),
        );
        let r = fx.run_env(
            &format!("echo \"v=$(pa_budget_admit {class} - - 0)\"; echo \"next=$(pa_budget_next {class})\""),
            &NOW,
        );
        (r.get("v"), r.get("next"))
    };
    assert_eq!(
        verdict(&lines_of(1, "storm", other, 5 * 3600), "storm").0,
        "withhold:storm-cap"
    );
    assert_eq!(
        verdict(&lines_of(1, "storm", other, 7 * 3600), "storm").0,
        "admit"
    );
    let (v, next) = verdict(&lines_of(1, "summary", other, 1800), "summary");
    assert_eq!(v, "withhold:summary-cap");
    assert_eq!(next, "14:17", "half an hour on, rounded up to the minute");
    assert_eq!(
        verdict(&lines_of(12, "summary", other, 7200), "summary").0,
        "withhold:summary-cap"
    );
    let (v, next) = verdict(&lines_of(11, "summary", other, 7200), "summary");
    assert_eq!(v, "admit");
    assert_eq!(next, "13:47", "room now");
    assert_eq!(
        verdict(&lines_of(1, "switch", other, 80000), "switch").0,
        "withhold:switch-cap"
    );
    assert_eq!(
        verdict(&lines_of(2, "pointer", other, 600), "pointer").0,
        "withhold:pointer-cap"
    );
    assert_eq!(
        verdict(&lines_of(48, "pointer", other, 7200), "pointer").0,
        "withhold:pointer-cap"
    );
    assert_eq!(
        verdict(&lines_of(47, "pointer", other, 7200), "pointer").0,
        "admit"
    );
    let crowd = [
        lines_of(40, "storm", other, 600),
        lines_of(40, "summary", other, 600),
        lines_of(40, "pointer", other, 600),
        lines_of(40, "test", other, 600),
        lines_of(40, "daily", other, 600),
    ]
    .concat();
    let ship = inc_rec(&[(2, "unit:shipper.service"), (4, "ship"), (6, "ACT")]);
    assert_eq!(
        admit_over(&fx, &[ship], &crowd, "unit:shipper.service", "open", "1"),
        "admit pool"
    );
    let pools = lines_of(30, "pool", other, 600);
    assert_eq!(
        verdict(&pools, "summary").0,
        "admit",
        "pool lines never count against an exempt class"
    );
}

/// What the budget counts: one line per admitted message whose result says it was or may have
/// been sent (pending, sending, ok, perm, transient); never one that sent nothing. A line dated
/// ahead of the clock is expired, one from another boot is aged by the wall clock, a stamp or a
/// result out of form counts as nothing, and a ledger that cannot be read admits nothing.
#[test]
fn the_budget_counts_only_lines_that_may_have_been_sent_and_ages_them_by_the_clock_rules() {
    let fx = Fx::salted(SALT);
    let other = "00000000";
    let ship = inc_rec(&[(2, "unit:shipper.service"), (4, "ship"), (6, "ACT")]);
    let key = "unit:shipper.service";
    let three = lines_of(3, "pool", other, 600);
    for result in ["pending", "sending", "ok", "perm:403", "transient:503"] {
        let lines = [three.clone(), vec![ledger_line("pool", other, 600, result)]].concat();
        assert_eq!(
            admit_over(&fx, std::slice::from_ref(&ship), &lines, key, "open", "1"),
            "withhold:pool",
            "{result}"
        );
    }
    let pending_old = [
        three.clone(),
        vec![ledger_line("pool", other, 3000, "pending")],
    ]
    .concat();
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &pending_old,
            key,
            "open",
            "1"
        ),
        "withhold:pool",
        "a pending incident line counts for its whole window"
    );
    for result in [
        "norender", "nocurl", "notarget", "noclaim", "lockbusy", "nomatch", "perm:abc", "ok2", "-",
    ] {
        let lines = [three.clone(), vec![ledger_line("pool", other, 600, result)]].concat();
        assert_eq!(
            admit_over(&fx, std::slice::from_ref(&ship), &lines, key, "open", "1"),
            "admit pool",
            "{result}"
        );
    }
    let ahead =
        vec![format!("L\t1000500/abcdef01/5500\tpool\t{other}\topen\tfull\tok\tlight\n"); 4];
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&ship), &ahead, key, "open", "1"),
        "admit pool",
        "ahead of the clock"
    );
    let other_boot =
        vec![format!("L\t998200/0000aaaa/999999\tpool\t{other}\topen\tfull\tok\tlight\n"); 4];
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &other_boot,
            key,
            "open",
            "1"
        ),
        "withhold:pool",
        "another boot, 30 minutes ago by the wall clock, whatever its uptime says"
    );
    let old_boot =
        vec![format!("L\t900000/0000aaaa/1\tpool\t{other}\topen\tfull\tok\tlight\n"); 16];
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&ship),
            &old_boot,
            key,
            "open",
            "1"
        ),
        "admit pool"
    );
    for bad in [
        "99x000/abcdef01/4000",
        "999000/abcdef01/40 0",
        "999000/ABCDEF01/4000",
        "-",
        "999000",
    ] {
        let lines = vec![format!("L\t{bad}\tpool\t{other}\topen\tfull\tok\tlight\n"); 4];
        assert_eq!(
            admit_over(&fx, std::slice::from_ref(&ship), &lines, key, "open", "1"),
            "admit pool",
            "{bad}"
        );
    }
    // A key hash out of form never counts toward a key.
    let kh = keyhash(&fx, key);
    let six = lines_of(6, "pool", &kh.to_uppercase(), 7200);
    assert_eq!(
        admit_over(&fx, std::slice::from_ref(&ship), &six, key, "remind", "0"),
        "admit pool"
    );
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    for class in ["incident", "storm", "summary", "switch", "pointer"] {
        let r = fx.run_env(
            &format!("pa_incident_load; pa_budget_admit {class} {key} open 1; echo"),
            &NOW,
        );
        assert_eq!(r.out.trim(), "withhold:ledger", "{class}");
    }
}

/// An admitted incident message is made retryable before anything is sent: one pending ledger
/// line naming the incident and the attempt, then the record's pending_tx, pending_since, sends
/// and last_sent. A withheld one writes nothing; a record that cannot be written gives the line
/// back as noclaim, which the budget does not count.
#[test]
fn an_admission_writes_one_pending_line_and_then_sets_pending_tx_before_the_send() {
    let fx = Fx::salted(SALT);
    let key = "unit:sensor-ssh.service";
    let kh = keyhash(&fx, key);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", inc_rec(&[(14, "2")])),
    );
    let r = fx.run_env(
        &format!("pa_incident_load; echo \"v=$(pa_incident_admit {key} open 1 full light)\""),
        &NOW,
    );
    assert_eq!(r.get("v"), "admit", "{}", r.err);
    let stamp = "1000000/abcdef01/5000";
    assert_eq!(
        fx.read("var/lib/propolis/witness/send-ledger"),
        format!(
            "#send-ledger v1 g=1\nL\t{stamp}\tstage1\t{kh}\topen\tfull\tpending\tlight\tw#3\t{stamp}\n"
        )
    );
    let rec = incident_records(&fx.read("var/lib/propolis/witness/incidents"));
    let f = &rec[0];
    assert_eq!(
        (f[14].as_str(), f[15].as_str()),
        ("3", stamp),
        "sends and last_sent"
    );
    assert_eq!(
        (f[26].as_str(), f[27].as_str()),
        ("open", stamp),
        "pending_tx and pending_since"
    );

    // Withheld: nothing written.
    let full: String = lines_of(2, "stage1", "00000000", 600).concat();
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{full}"),
    );
    let before = fx.read("var/lib/propolis/witness/incidents");
    let r = fx.run_env(
        &format!("pa_incident_load; echo \"v=$(pa_incident_admit {key} remind 0 full light)\""),
        &NOW,
    );
    assert_eq!(r.get("v"), "withhold:stage1-cap");
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
    assert_eq!(
        fx.read("var/lib/propolis/witness/send-ledger"),
        format!("#send-ledger v1 g=1\n{full}")
    );

    // A record that cannot be written: the line is given back.
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\n",
    );
    let r = fx.run_env(
        &format!("pa_incident_load; pa_incident_write() {{ return 1; }}; echo \"v=$(pa_incident_admit {key} open 1 full hook)\""),
        &NOW,
    );
    assert_eq!(r.get("v"), "withhold:noclaim");
    let ledger = fx.read("var/lib/propolis/witness/send-ledger");
    assert!(ledger.contains("\tnoclaim\thook\tw#3\t"), "{ledger}");
    let r = fx.run_env(
        &format!("pa_incident_load; echo \"v=$(pa_budget_admit incident {key} open 1)\"; echo \"n=$(_pa_ledger_ages stage1 | wc -l)\""),
        &NOW,
    );
    assert_eq!(r.get("n"), "0", "a line given back is not counted");
    assert_eq!(r.get("v"), "admit");
    for (mode, sender) in [("bulk", "light"), ("full", "cron")] {
        let r = fx.run_env(
            &format!("pa_incident_load; pa_incident_admit {key} open 1 {mode} {sender}; echo"),
            &NOW,
        );
        assert_eq!(r.out.trim(), "withhold:unknown", "{mode} {sender}");
    }
}

/// Whether a pending transition may be sent again now: not under 120 s since it was admitted or
/// last tried, not once an hour has passed since it was admitted; an admission time out of form has
/// expired and one ahead of the clock waits for the clock to pass it; a last attempt out of form is
/// none, and one ahead of the clock is none only when it is known to come from another boot.
#[test]
fn the_retry_decision_waits_120_seconds_and_gives_up_after_an_hour() {
    let fx = Fx::new();
    let due = |since: &str, tried: &str| -> String {
        fx.run_env(
            &format!("echo \"d=$(pa_retry_due '{since}' '{tried}')\"; echo \"rc=$?\""),
            &NOW,
        )
        .get("d")
    };
    assert_eq!(due("999940/abcdef01/4940", "-"), "wait");
    assert_eq!(due("999870/abcdef01/4870", "-"), "due");
    assert_eq!(due("999870/abcdef01/4870", "999970/abcdef01/4970"), "wait");
    assert_eq!(due("999870/abcdef01/4870", "999870/abcdef01/4870"), "due");
    assert_eq!(due("996401/abcdef01/1401", "-"), "due");
    assert_eq!(due("996400/abcdef01/1400", "-"), "expired");
    assert_eq!(
        due("1000100/abcdef01/5100", "-"),
        "wait",
        "ahead of the clock: retried once the clock passes it"
    );
    assert_eq!(due("999870/abcdef01", "-"), "expired");
    assert_eq!(due("plantedword", "-"), "expired");
    assert_eq!(
        due("999870/abcdef01/4870", "1000100/abcdef01/5100"),
        "wait",
        "an attempt ahead of the clock in this boot may still be sending"
    );
    assert_eq!(
        due("999870/abcdef01/4870", "1000100/0000bbbb/5100"),
        "due",
        "an attempt ahead of the clock from another boot ended with that boot"
    );
    assert_eq!(due("999870/abcdef01/4870", "garbage"), "due");
    assert_eq!(
        due("999800/0000aaaa/9", "-"),
        "due",
        "another boot, by the wall clock"
    );
    assert_eq!(due("990000/0000aaaa/4999", "-"), "expired");
    let r = fx.run_env(
        "pa_retry_due 999870/abcdef01/4870 - > /dev/null; echo \"rc=$?\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "0");
    let r = fx.run_env(
        "pa_retry_due 999940/abcdef01/4940 - > /dev/null; echo \"rc=$?\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "1");
}

/// A retry updates the ledger line of its own transition (result pending again, the sender, the
/// time of the attempt) and adds none, so it is never counted again; a line that ended ok or perm
/// is not retried, and a result is written only to the line of the key and transition it names,
/// though two transitions admitted in one pass share a stamp.
#[test]
fn a_retry_updates_its_own_line_and_is_never_counted_again() {
    let fx = Fx::salted(SALT);
    let a = keyhash(&fx, "unit:shipper.service");
    let b = keyhash(&fx, "backup:run");
    let s = "999800/abcdef01/4800";
    let ledger = format!(
        "#send-ledger v1 g=1\n\
         L\t{s}\tpool\t{a}\topen\tfull\ttransient:503\tlight\tw#3\t{s}\n\
         L\t{s}\tpool\t{b}\topen\tfull\tpending\tlight\tw#4\t{s}\n\
         L\t{s}\tpool\t00000000\tremind\tfull\tok\tlight\tw#5\t{s}\n"
    );
    fx.write("var/lib/propolis/witness/send-ledger", &ledger);
    let r = fx.run_env(
        &format!(
            "pa_ledger_retry {s} {a} open hourly; echo \"retry=$?\"\n\
             pa_ledger_retry {s} 00000000 remind hourly; echo \"ended=$?\"\n\
             pa_ledger_retry {s} {a} change hourly; echo \"other=$?\""
        ),
        &NOW,
    );
    assert_eq!(r.get("retry"), "0", "{}", r.err);
    assert_eq!(r.get("ended"), "1", "an ok line is not retried");
    assert_eq!(r.get("other"), "1");
    let now = "1000000/abcdef01/5000";
    let after = fx.read("var/lib/propolis/witness/send-ledger");
    assert_eq!(
        after,
        format!(
            "#send-ledger v1 g=2\n\
             L\t{s}\tpool\t{a}\topen\tfull\tpending\thourly\tw#3\t{now}\n\
             L\t{s}\tpool\t{b}\topen\tfull\tpending\tlight\tw#4\t{s}\n\
             L\t{s}\tpool\t00000000\tremind\tfull\tok\tlight\tw#5\t{s}\n"
        )
    );
    // Three lines before and after: one more message has room in the hour.
    let ship = inc_rec(&[
        (1, "w#9"),
        (2, "unit:other.service"),
        (4, "host"),
        (6, "ACT"),
    ]);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{ship}"),
    );
    let r = fx.run_env(
        "pa_incident_load; echo \"v=$(pa_budget_admit incident unit:other.service open 1)\"",
        &NOW,
    );
    assert_eq!(r.get("v"), "admit");
    let r = fx.run_env(
        &format!(
            "pa_ledger_result {s} - ok light {b} open; echo \"res=$?\"\n\
             pa_ledger_result {s} - ok light {b} open; echo \"again=$?\""
        ),
        &NOW,
    );
    assert_eq!(r.get("res"), "0");
    assert_eq!(r.get("again"), "1");
    let after = fx.read("var/lib/propolis/witness/send-ledger");
    assert!(
        after.contains(&format!(
            "L\t{s}\tpool\t{b}\topen\tfull\tok\tlight\tw#4\t{s}\n"
        )),
        "{after}"
    );
    assert!(
        after.contains(&format!(
            "L\t{s}\tpool\t{a}\topen\tfull\tpending\thourly\tw#3\t{now}\n"
        )),
        "{after}"
    );
}

/// The default open record rendered over OBSERVE (written as the observe file whatever it holds),
/// with the fields in `set` replaced.
fn open_over(fx: &Fx, set: &[(usize, &str)], observe: &str) -> Msg {
    render_with(fx, &[inc_rec(set)], observe, "open", "w#3", "", &[])
}

/// An observe file that holds nothing the renderer reads.
const NO_OBSERVE: &str = "X\tnothing\n";

/// The last change is read from the stamp the witness writes third on an H line (`H path sha16
/// changed keys8 seen before`), never from the key-name hash beside it, and the path selects its
/// word: env files and the other configuration are config, Propolis's unit files are unit, and
/// the installed binaries and the scripts under /usr/local/sbin and /usr/local/lib/propolis are
/// binary.
#[test]
fn the_last_change_is_read_from_the_witness_h_line_and_names_config_unit_or_binary() {
    let fx = Fx::salted(SALT);
    let why = |observe: &str| open_over(&fx, &[], observe).body[1].clone();
    let line = |path: &str, changed: &str| {
        format!("H\t{path}\t0123456789abcdef\t{changed}\t01234567\t999900/abcdef01/4900\t-\n")
    };
    let prefix = "Why: process exited (proc.exit 1), seen by hook@host-908b, known; last change: ";
    for (path, changed, want) in [
        (
            "/etc/propolis/propolis.env",
            "998400/abcdef01/3400",
            "config 10 min before onset",
        ),
        (
            "/usr/local/lib/propolis/alert-lib.sh",
            "998700/abcdef01/3700",
            "binary 5 min before onset",
        ),
        (
            "/usr/local/sbin/propolis-status",
            "998700/abcdef01/3700",
            "binary 5 min before onset",
        ),
        (
            "/usr/local/bin/propolis",
            "998700/abcdef01/3700",
            "binary 5 min before onset",
        ),
        (
            "/etc/systemd/system/sensor-ssh.service",
            "998400/abcdef01/3400",
            "unit 10 min before onset",
        ),
        ("/etc/propolis/propolis.env", "-", "none in 24 h"),
    ] {
        assert_eq!(
            why(&line(path, changed)),
            format!("{prefix}{want}"),
            "{path}"
        );
    }
    let both = format!(
        "{}{}",
        line("/etc/propolis/propolis.env", "998400/abcdef01/3400"),
        line(
            "/usr/local/lib/propolis/alert-lib.sh",
            "998700/abcdef01/3700"
        )
    );
    assert_eq!(why(&both), format!("{prefix}binary 5 min before onset"));
}

/// A gateway-dup counts its loss from the observe line kept under its own record key, the
/// unlisted collectors' included, whose instance is not known; the loss is permanent, so where no
/// count can be read it is not measured, never held.
#[test]
fn a_gateway_dup_counts_its_loss_by_its_record_key_and_never_says_evidence_held() {
    let fx = Fx::salted(SALT);
    let dup = |key: &str, inst: &str| {
        vec![
            (2, key.to_string()),
            (3, "gateway-dup".to_string()),
            (4, "gateway".to_string()),
            (5, inst.to_string()),
            (6, "ACT".to_string()),
            (11, "gw.dup".to_string()),
            (33, "-".to_string()),
        ]
    };
    let set = |v: &Vec<(usize, String)>| -> Vec<(usize, String)> { v.clone() };
    let over = |v: Vec<(usize, String)>, observe: &str| {
        let s: Vec<(usize, &str)> = v.iter().map(|(i, x)| (*i, x.as_str())).collect();
        open_over(&fx, &s, observe)
    };
    let unlisted = dup("gwdup:unlisted", "-");
    let m = over(
        set(&unlisted),
        &format!("P\tseen:gwdup:unlisted\t{INC_T}\tok\t-\t42\n"),
    );
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(
        m.body[3],
        "Impact: not known here; evidence lost (counted) 42 records"
    );
    let listed = dup("gwdup:c1a2b3", "c1a2b3");
    let m = over(set(&listed), NO_OBSERVE);
    assert_eq!(
        m.body[3],
        "Impact: no new evidence from c1a2b3; evidence not measured"
    );
    let m = over(
        set(&listed),
        &format!("P\tseen:gwdup:c1a2b3\t{INC_T}\tok\t-\t4x2\n"),
    );
    assert_eq!(
        m.body[3],
        "Impact: no new evidence from c1a2b3; evidence not measured"
    );
    assert!(!m.out.contains("held"), "{}", m.out);
}

/// A RESOLVED follows only an open that got through: a resolved record whose open was never
/// delivered is withheld as undelivered (a word the caller does not count as a withheld message)
/// and renders nothing; delivered, it is admitted and rendered.
#[test]
fn a_resolve_of_an_open_never_delivered_is_withheld_as_undelivered_and_not_rendered() {
    let fx = Fx::salted(SALT);
    let key = "unit:sensor-ssh.service";
    for (delivered, verdict, rc) in [
        ("0", "withhold:undelivered", "1"),
        ("?", "withhold:undelivered", "1"),
        ("1", "admit stage1", "0"),
    ] {
        let rec = inc_resolved("active10", &[(17, delivered)]);
        assert_eq!(
            admit_over(&fx, std::slice::from_ref(&rec), &[], key, "resolve", "0"),
            verdict,
            "{delivered}"
        );
        let m = render(&fx, std::slice::from_ref(&rec), "resolve", "w#3", "");
        assert_eq!(m.rc, rc, "{delivered}: {}", m.out);
        if rc == "1" {
            assert_eq!((m.title.as_str(), m.body.len()), ("", 0));
        }
    }
    let rec = inc_resolved("active10", &[(17, "0")]);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{rec}"),
    );
    std::fs::remove_file(fx.p("var/lib/propolis/witness/send-ledger")).unwrap();
    let r = fx.run_env(
        &format!("pa_incident_load; echo \"v=$(pa_incident_admit {key} resolve 0 full light)\""),
        &NOW,
    );
    assert_eq!(r.get("v"), "withhold:undelivered");
    assert!(!fx.p("var/lib/propolis/witness/send-ledger").exists());
}

/// Who saw an incident: the hook when the record carries the flag the hook's path sets
/// (`hookopen`, or `hookspool` for a firing the hook spooled), or, from a record the legacy hook
/// wrote, its outcome; the witness otherwise. A later witness sighting that resets the outcome
/// leaves the flag, so a hook-opened incident still says hook.
#[test]
fn who_saw_an_incident_comes_from_the_hooks_flag_and_never_from_a_reset_outcome() {
    let fx = Fx::salted(SALT);
    for (flags, out, who) in [
        ("hookopen", "-", "hook"),
        ("maint,hookspool", "-", "hook"),
        ("-", "delivered", "hook"),
        ("-", "-", "witness"),
        ("hookopenx", "-", "witness"),
        ("cannotverify", "-", "witness"),
    ] {
        let m = open_over(&fx, &[(30, flags), (33, out)], NO_OBSERVE);
        assert!(
            m.body[1].contains(&format!(", seen by {who}@host-908b, ")),
            "{flags} {out}: {}",
            m.body[1]
        );
    }
}

/// Pointer mode is a class of its own, which the profile switch brings: an incident message is
/// admitted here in full mode only, and a pointer asked for writes nothing.
#[test]
fn an_incident_message_is_admitted_in_full_mode_only() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", inc_rec(&[])),
    );
    let before = fx.read("var/lib/propolis/witness/incidents");
    let r = fx.run_env(
        "pa_incident_load; echo \"v=$(pa_incident_admit unit:sensor-ssh.service open 1 pointer light)\"",
        &NOW,
    );
    assert_eq!(r.get("v"), "withhold:unknown");
    assert!(!fx.p("var/lib/propolis/witness/send-ledger").exists());
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
}

/// The Impact line of each of config-check's sixteen page rows names what its stage stops, with
/// the instance: an intake finding concerns one source, whose evidence stops while the rest still
/// reaches the ledger; the daemon's and the database's kinds stop everything.
#[test]
fn the_impact_line_of_each_page_row_names_what_its_stage_stops() {
    let fx = Fx::salted(SALT);
    let witness = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/witness.sh"
    ))
    .unwrap();
    let rows: Vec<Vec<String>> = witness
        .lines()
        .filter(|l| l.split('|').nth(1) == Some("page"))
        .map(|l| l.split('|').map(str::to_string).collect())
        .collect();
    assert_eq!(rows.len(), 16);
    for row in &rows {
        let (id, tier, stage, rule) = (&row[0], &row[2], &row[3], &row[5]);
        let inst = match rule.as_str() {
            "logpath" => "s1a2b3",
            "fold" => "c1a2b3",
            _ => "u1a2b3",
        };
        let want = match stage.as_str() {
            "listen" => format!("not capturing on {inst}"),
            "gateway" | "intake" => format!("no new evidence from {inst}"),
            "source" => "rotation not done".to_string(),
            "backup" => "backup not taken".to_string(),
            "alert" => "alerts may not arrive".to_string(),
            other => panic!("a page row on stage {other}"),
        };
        let key = format!("finding:{id}:0123456789ab");
        let m = open_over(
            &fx,
            &[
                (2, &key),
                (3, "finding"),
                (4, stage),
                (5, inst),
                (6, tier),
                (11, "config.finding"),
            ],
            NO_OBSERVE,
        );
        assert!(
            m.body[3].starts_with(&format!("Impact: {want}; evidence ")),
            "{id}: {}",
            m.body[3]
        );
    }
    for set in [
        vec![
            (2, "unit:propolis.service"),
            (3, "daemon-down"),
            (4, "intake"),
        ],
        vec![(2, "unit:propolis.service"), (4, "intake")],
        vec![(2, "ready:local"), (3, "daemon-degraded"), (4, "intake")],
        vec![(2, "db:local"), (3, "db-unreachable"), (4, "ledger")],
    ] {
        let m = open_over(&fx, &set, NO_OBSERVE);
        assert!(
            m.body[3].starts_with("Impact: nothing reaches the ledger; "),
            "{set:?}: {}",
            m.body[3]
        );
    }
}

/// A crash loop's headline counts the restarts the witness judged it on (the unit's NRestarts on
/// its last sample less its baseline), never the record's occurrences, and `?` where no count can
/// be read: never a made-up 0.
#[test]
fn a_crash_loop_counts_the_restarts_the_witness_judged_on_never_its_occurrences() {
    let fx = Fx::salted(SALT);
    let title = |observe: &str| open_over(&fx, &[(3, "unit-crashloop"), (31, "2")], observe).title;
    let obs = |u: &str, r: &str| {
        format!(
            "U\tsensor-ssh.service\t{INC_T}\t{u}\tabcdef01\tactive\t-\t1\t-\n\
             R\tsensor-ssh.service\t{INC_T}\t{r}\n\
             U\tsensor-other.service\t{INC_T}\t99\tabcdef01\tactive\t-\t1\t-\n"
        )
    };
    let head = "PAGE host-908b - listen: unit u1a2b3 restarting";
    assert_eq!(title(&obs("10", "4")), format!("{head} (6 restarts)"));
    for (u, r) in [("1x", "4"), ("10", "-"), ("10", "12"), ("10", "10")] {
        assert_eq!(title(&obs(u, r)), format!("{head} (? restarts)"), "{u} {r}");
    }
    assert_eq!(title(NO_OBSERVE), format!("{head} (? restarts)"));
}

/// The lifecycle line's flags: `folded` counts only children still pending, open or acknowledged
/// under this id, never a resolved one or the record itself; `budget held` counts only the W lines
/// of this key since this incident opened, never those of an earlier incident of the same key.
#[test]
fn the_lifecycle_flags_count_only_children_still_folded_and_holds_since_this_open() {
    let fx = Fx::salted(SALT);
    let child = |state: &str| {
        inc_rec(&[
            (1, "w#4"),
            (2, "unit:propolis-backup.service"),
            (4, "backup"),
            (6, "ACT"),
            (7, state),
            (13, "w#3"),
            (30, "folded"),
        ])
    };
    let plain = "w#3 opened - next reminder 14:46 UTC";
    let last = |records: &[String]| render(&fx, records, "open", "w#3", "").body[5].clone();
    assert_eq!(last(&[inc_rec(&[]), child("resolved")]), plain);
    assert_eq!(
        last(&[inc_rec(&[]), child("acked")]),
        format!("{plain} - folded 1")
    );
    assert_eq!(last(&[inc_rec(&[(13, "w#3")])]), plain);
    let kh = keyhash(&fx, "unit:sensor-ssh.service");
    let w = |at: &str| format!("W\t{at}\t{kh}\tremind\t0\tu1a2b3\tpool\n");
    assert_eq!(
        last(&[
            inc_rec(&[]),
            w("998000/abcdef01/3000"),
            w("980000/0000aaaa/1")
        ]),
        plain,
        "held before this open"
    );
    assert_eq!(
        last(&[inc_rec(&[]), w("998000/abcdef01/3000"), w(INC_T)]),
        format!("{plain} - budget held 1")
    );
}

/// The sixteen listener records of an attacker who crashes sensors at will.
fn attacker_records(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            inc_rec(&[
                (1, &format!("w#{}", 10 + i)),
                (2, &format!("unit:sensor-a{i}.service")),
            ])
        })
        .collect()
}

/// An attacker who opens a new listener incident whenever the budget lets him, every five minutes
/// for a day, fills the stage-1 hour and then the day's sixteen. A real listener that fails
/// meanwhile has its open withheld, but its first reminder, still failing an hour on and never
/// sent, goes out as its open would have, from the allowance kept for such opens: it is not held
/// for the day.
#[test]
fn a_listener_open_withheld_by_an_attack_goes_out_with_its_first_reminder() {
    let fx = Fx::salted(SALT);
    let mut records = attacker_records(8);
    for (i, step) in [26, 100, 230].iter().enumerate() {
        records.push(inc_rec(&[
            (1, &format!("w#{}", 20 + i)),
            (2, &format!("unit:sensor-r{step}.service")),
        ]));
    }
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        "for ((step = 0; step < 288; step++)); do\n\
         PA_TEST_WALL=$((1000000 + step * 300)) PA_TEST_UP=$((5000 + step * 300))\n\
         pa_now\n\
         pa_incident_load\n\
         v=\"$(pa_incident_admit \"unit:sensor-a$((step % 8)).service\" open 1 full light)\"\n\
         [ \"$v\" != admit ] || echo \"attack=$step\"\n\
         case \"$step\" in\n\
         26 | 100 | 230) pa_incident_load; echo \"open$step=$(pa_incident_admit \"unit:sensor-r$step.service\" open 1 full light)\" ;;\n\
         38 | 112 | 242) pa_incident_load; echo \"remind$((step - 12))=$(pa_incident_admit \"unit:sensor-r$((step - 12)).service\" remind 0 full light)\" ;;\n\
         esac\n\
         done",
        &NOW,
    );
    let attacks = r.out.lines().filter(|l| l.starts_with("attack=")).count();
    assert_eq!(attacks, 16, "{}\n{}", r.out, r.err);
    for step in [26, 100, 230] {
        assert_eq!(
            r.get(&format!("open{step}")),
            "withhold:stage1-cap",
            "{step}"
        );
        assert_eq!(r.get(&format!("remind{step}")), "admit", "{step}");
        let kh = keyhash(&fx, &format!("unit:sensor-r{step}.service"));
        assert!(
            fx.read("var/lib/propolis/witness/send-ledger")
                .contains(&format!("\tlate\t{kh}\tremind\t")),
            "{step}: admitted as a late open"
        );
    }
}

/// Listeners an attacker keeps down for hours, their opens withheld, while he also opens a new
/// listener incident every twenty minutes: their first reminders take the late allowance, one an
/// hour and four in the day, and nothing of the pool, so a new incident of another kind still
/// goes out at once six and sixteen hours into the attack, and the day stays within its bound.
#[test]
fn listeners_kept_down_take_four_late_opens_a_day_and_no_room_from_other_kinds() {
    let fx = Fx::salted(SALT);
    let mut records = attacker_records(8);
    for i in 0..10 {
        records.push(inc_rec(&[
            (1, &format!("w#{}", 50 + i)),
            (2, &format!("unit:sensor-h{i}.service")),
        ]));
    }
    records.push(inc_rec(&[
        (1, "w#60"),
        (2, "db:recovery"),
        (3, "db-readonly"),
        (4, "ledger"),
        (5, "-"),
    ]));
    records.push(inc_rec(&[
        (1, "w#61"),
        (2, "backup:run"),
        (3, "backup-hung"),
        (4, "backup"),
        (5, "-"),
        (6, "ACT"),
    ]));
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t70\n{}", records.concat()),
    );
    let r = fx.run_env(
        "for ((step = 0; step < 72; step++)); do\n\
         PA_TEST_WALL=$((1000000 + step * 1200)) PA_TEST_UP=$((5000 + step * 1200))\n\
         pa_now; pa_incident_load\n\
         pa_incident_admit \"unit:sensor-a$((step % 8)).service\" open 1 full light > /dev/null\n\
         if [ \"$((step % 3))\" = 0 ]; then\n\
         for h in 0 1 2 3 4 5 6 7 8 9; do\n\
         pa_incident_load; pa_incident_admit \"unit:sensor-h$h.service\" remind 0 full light > /dev/null\n\
         [ \"$PA_ADMIT_AS\" != late ] || echo \"late=$step:h$h\"\n\
         done\n\
         fi\n\
         case \"$step\" in\n\
         18) pa_incident_load; pa_incident_admit db:recovery open 1 full light > /dev/null; echo \"db=$PA_ADMIT_VERDICT $PA_ADMIT_AS\" ;;\n\
         50) pa_incident_load; pa_incident_admit backup:run open 1 full light > /dev/null; echo \"backup=$PA_ADMIT_VERDICT $PA_ADMIT_AS\" ;;\n\
         esac\n\
         done; echo done=1",
        &NOW,
    );
    assert_eq!(r.get("done"), "1", "{}", r.err);
    let late: Vec<&str> = r
        .out
        .lines()
        .filter_map(|l| l.strip_prefix("late="))
        .collect();
    // One an hour for four hours, each to an incident that has had no message yet.
    assert_eq!(late, ["0:h0", "3:h2", "6:h3", "9:h4"], "{}", r.out);
    assert_eq!(r.get("db"), "admit pool");
    assert_eq!(r.get("backup"), "admit pool");
    let ledger = fx.read("var/lib/propolis/witness/send-ledger");
    let count = |class: &str| ledger.matches(&format!("\t{class}\t")).count();
    assert_eq!(count("late"), 4, "{ledger}");
    assert_eq!(count("pool"), 2, "{ledger}");
    assert_eq!(count("stage1"), 16, "{ledger}");
    assert_eq!(count("reserve"), 0);
    assert!(ledger.lines().filter(|l| l.starts_with("L\t")).count() <= 32);
}

/// The day's incident pushes stay within the bound the budget records: at most sixteen listener
/// pushes, new opens included, at most four from the reserve, and with the pool's other kinds at
/// most twenty-eight (late opens, which this traffic has none of, add at most four), whether a
/// listener opens every five minutes alone or, every twenty minutes, alongside another kind and a
/// reserve kind.
#[test]
fn the_incident_pushes_of_a_day_stay_within_the_recorded_bound() {
    let fx = Fx::salted(SALT);
    let count = |class: &str| {
        fx.read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| {
                l.starts_with("L\t") && (class.is_empty() || l.contains(&format!("\t{class}\t")))
            })
            .count()
    };
    let mut records = attacker_records(8);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        "for ((step = 0; step < 288; step++)); do\n\
         PA_TEST_WALL=$((1000000 + step * 300)) PA_TEST_UP=$((5000 + step * 300))\n\
         pa_now; pa_incident_load\n\
         pa_incident_admit \"unit:sensor-a$((step % 8)).service\" open 1 full light > /dev/null\n\
         done; echo done=1",
        &NOW,
    );
    assert_eq!(r.get("done"), "1", "{}", r.err);
    assert_eq!(count("stage1"), 16, "listener opens alone");
    assert!(count("") <= 28);

    std::fs::remove_file(fx.p("var/lib/propolis/witness/send-ledger")).unwrap();
    for i in 0..8 {
        records.push(inc_rec(&[
            (1, &format!("w#{}", 30 + i)),
            (2, &format!("unit:other-o{i}.service")),
            (4, "host"),
            (6, "ACT"),
        ]));
    }
    records.push(inc_rec(&[
        (1, "w#39"),
        (2, "db:local"),
        (3, "db-unreachable"),
        (4, "ledger"),
        (5, "-"),
    ]));
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let r = fx.run_env(
        "for ((step = 0; step < 72; step++)); do\n\
         PA_TEST_WALL=$((1000000 + step * 1200)) PA_TEST_UP=$((5000 + step * 1200))\n\
         pa_now\n\
         for key in \"unit:sensor-a$((step % 8)).service\" \"unit:other-o$((step % 8)).service\" db:local; do\n\
         pa_incident_load; pa_incident_admit \"$key\" open 1 full light > /dev/null\n\
         done\n\
         done; echo done=1",
        &NOW,
    );
    assert_eq!(r.get("done"), "1", "{}", r.err);
    assert!(count("stage1") <= 16);
    assert_eq!(count("reserve"), 4);
    assert!(count("") <= 28, "{}", count(""));
}

/// The budget decides from what this read of the send ledger found: a damaged persistent copy
/// beside a readable fallback copy is counted from the fallback, and once the damaged copy is set
/// aside a second admission in the same process counts from what is left; a copy that cannot be
/// set aside (a read-only disk) does not withhold every later message while a fallback copy can be
/// read. With no readable copy at all, nothing is admitted.
#[test]
fn a_damaged_send_ledger_is_judged_from_this_read_and_a_readable_fallback_copy() {
    let fx = Fx::salted(SALT);
    let daemon = inc_rec(&[
        (2, "unit:propolis.service"),
        (3, "daemon-down"),
        (4, "intake"),
        (5, "-"),
    ]);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{daemon}"),
    );
    let twice = "pa_lock 5 || echo nolock=1\npa_incident_load\n\
                 pa_budget_admit incident unit:propolis.service open 1 > /dev/null; echo \"first=$PA_ADMIT_VERDICT $PA_ADMIT_AS\"\n\
                 pa_budget_admit incident unit:propolis.service open 1 > /dev/null; echo \"second=$PA_ADMIT_VERDICT $PA_ADMIT_AS\"\n\
                 pa_unlock";
    let aside = |fx: &Fx| {
        std::fs::read_dir(fx.p("var/lib/propolis/witness"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("send-ledger.unreadable.")
            })
            .count()
    };
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    fx.write(
        "run/propolis-witness/fallback/send-ledger",
        "#send-ledger v1 g=5\n",
    );
    let r = fx.run_env(twice, &NOW);
    assert_eq!(r.get("first"), "admit reserve", "{}", r.err);
    assert_eq!(r.get("second"), "admit reserve");
    assert_eq!(aside(&fx), 1, "the damaged copy is set aside");

    // A rename that fails leaves the damaged copy where it is: each process still counts from the
    // fallback.
    write_exec(
        &fx.bin.join("mv"),
        "#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in *.unreadable.*) exit 1 ;; esac; done\nPATH=\"${PATH#*:}\" exec mv \"$@\"\n",
    );
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    for _ in 0..2 {
        let r = fx.run_env(twice, &NOW);
        assert_eq!(r.get("first"), "admit reserve", "{}", r.err);
        assert_eq!(fx.read("var/lib/propolis/witness/send-ledger"), "garbage\n");
    }
    std::fs::remove_file(fx.bin.join("mv")).unwrap();

    // No readable copy: this read withholds; the copy is set aside, and the next counts from empty.
    std::fs::remove_file(fx.p("run/propolis-witness/fallback/send-ledger")).unwrap();
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    let r = fx.run_env(twice, &NOW);
    assert_eq!(r.get("first"), "withhold:ledger ");
    assert_eq!(r.get("second"), "admit reserve");

    // No readable copy, and a damaged one that can be neither set aside nor written over (a
    // read-only disk). A reader without the lock withholds and writes nothing. One that holds it
    // withholds too and leaves an empty ledger in /run, so the next read counts from that: the
    // block does not last for as long as the disk stays read-only.
    write_exec(
        &fx.bin.join("mv"),
        "#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in */var/lib/propolis/witness/send-ledger*) exit 1 ;; esac; done\nPATH=\"${PATH#*:}\" exec mv \"$@\"\n",
    );
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    let fallback = fx.p("run/propolis-witness/fallback/send-ledger");
    let r = fx.run_env(
        "pa_incident_load\npa_budget_admit incident unit:propolis.service open 1 > /dev/null; echo \"first=$PA_ADMIT_VERDICT\"",
        &NOW,
    );
    assert_eq!(r.get("first"), "withhold:ledger", "{}", r.err);
    assert!(
        !fallback.exists(),
        "a reader without the lock writes nothing"
    );
    let r = fx.run_env(twice, &NOW);
    assert_eq!(r.get("first"), "withhold:ledger ", "{}", r.err);
    assert_eq!(r.get("second"), "admit reserve", "{}", r.err);
    assert_eq!(fx.read("var/lib/propolis/witness/send-ledger"), "garbage\n");
    assert_eq!(
        std::fs::read_to_string(&fallback).unwrap(),
        "#send-ledger v1 g=1\n"
    );
    let r = fx.run_env(twice, &NOW);
    assert_eq!(r.get("first"), "admit reserve", "a later process");
    std::fs::remove_file(fx.bin.join("mv")).unwrap();

    // The same with the damage in the /run copy and no persistent copy at all: the empty ledger
    // is written whichever copy was damaged.
    write_exec(
        &fx.bin.join("mv"),
        "#!/usr/bin/env bash\nfor a in \"$@\"; do case \"$a\" in *.unreadable.*) exit 1 ;; esac; done\nPATH=\"${PATH#*:}\" exec mv \"$@\"\n",
    );
    std::fs::remove_file(fx.p("var/lib/propolis/witness/send-ledger")).unwrap();
    fx.write("run/propolis-witness/fallback/send-ledger", "garbage\n");
    let r = fx.run_env(twice, &NOW);
    assert_eq!(r.get("first"), "withhold:ledger ", "{}", r.err);
    assert_eq!(r.get("second"), "admit reserve", "{}", r.err);
    assert_eq!(
        fx.read("var/lib/propolis/witness/send-ledger"),
        "#send-ledger v1 g=1\n"
    );
    assert!(!fallback.exists(), "the damaged /run copy is gone");
    std::fs::remove_file(fx.bin.join("mv")).unwrap();
}

/// An admission whose ledger line or record cannot be written leaves nothing behind it: the
/// verdict says why, no class is named, the record in memory is as it was before (sends,
/// pending_tx and pending_since unchanged) and the files are as they were.
#[test]
fn an_admission_that_cannot_be_recorded_leaves_the_verdict_and_the_record_as_they_were() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", inc_rec(&[(14, "2")])),
    );
    let before = fx.read("var/lib/propolis/witness/incidents");
    let show = "pa_incident_admit unit:sensor-ssh.service open 1 full hook > /dev/null; echo \"rc=$?\"\n\
                echo \"v=$PA_ADMIT_VERDICT\"; echo \"as=${PA_ADMIT_AS:-none}\"\n\
                echo \"inc=${PA_INC[14]} ${PA_INC[26]} ${PA_INC[27]}\"\n\
                pa_incident_get unit:sensor-ssh.service; echo \"mem=${PA_INC[14]} ${PA_INC[26]} ${PA_INC[27]}\"";
    let r = fx.run_env(
        &format!("pa_incident_load\npa_incident_write() {{ return 1; }}\n{show}"),
        &NOW,
    );
    assert_eq!(r.get("rc"), "1", "{}", r.err);
    assert_eq!(r.get("v"), "withhold:noclaim");
    assert_eq!(r.get("as"), "none");
    assert_eq!(r.get("inc"), "2 - -");
    assert_eq!(r.get("mem"), "2 - -");
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
    std::fs::remove_file(fx.p("var/lib/propolis/witness/send-ledger")).unwrap();

    let r = fx.run_env(
        &format!("pa_incident_load\npa_ledger_add() {{ return 1; }}\n{show}"),
        &NOW,
    );
    assert_eq!(r.get("rc"), "1");
    assert_eq!(r.get("v"), "withhold:ledger");
    assert_eq!(r.get("as"), "none");
    assert_eq!(r.get("mem"), "2 - -");
    assert!(!fx.p("var/lib/propolis/witness/send-ledger").exists());
    assert_eq!(fx.read("var/lib/propolis/witness/incidents"), before);
}

/// The retry decision under a clock that is not to be trusted: with no boot id every age is by the
/// wall clock, so an attempt dated ahead of it after a step back may still be sending and is
/// waited for; an admission dated ahead of the clock from another boot (a host whose clock comes
/// up behind) waits until the clock passes it and is then retried, never dropped.
#[test]
fn the_retry_decision_waits_for_an_attempt_or_an_admission_dated_ahead_of_the_clock() {
    let fx = Fx::new();
    let due = |wall: &str, boot: &str, up: &str, since: &str, tried: &str| -> String {
        fx.run_env(
            &format!("echo \"d=$(pa_retry_due '{since}' '{tried}')\""),
            &[
                ("PA_TEST_WALL", wall),
                ("PA_TEST_BOOT", boot),
                ("PA_TEST_UP", up),
            ],
        )
        .get("d")
    };
    assert_eq!(due("1130", "-", "0", "1000/-/0", "1200/-/0"), "wait");
    assert_eq!(due("1330", "-", "0", "1000/-/0", "1200/-/0"), "due");
    assert_eq!(
        due("900", "bbbbbbbb", "20", "1000/aaaaaaaa/50", "-"),
        "wait"
    );
    assert_eq!(
        due("1200", "bbbbbbbb", "320", "1000/aaaaaaaa/50", "-"),
        "due"
    );
    assert_eq!(due("900", "bbbbbbbb", "20", "1000/aaaa/50", "-"), "expired");
}

/// A ledger line whose class field is not one closed word (a blank inside it from a damaged file)
/// is not counted, and nothing of it reaches the budget's arithmetic or its error output.
#[test]
fn a_ledger_line_whose_class_is_not_one_word_is_not_counted() {
    let fx = Fx::salted(SALT);
    let db = inc_rec(&[
        (2, "db:local"),
        (3, "db-unreachable"),
        (4, "ledger"),
        (5, "-"),
    ]);
    let bad = format!(
        "L\t{}\treserve pool\t00000000\topen\tfull\tok\tlight\n",
        lib_at(600)
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{db}"),
    );
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{bad}"),
    );
    let r = fx.run_env(
        "pa_incident_load\necho \"ages=$(_pa_ledger_ages reserve pool stage1 | wc -l)\"\n\
         pa_budget_admit incident db:local open 1 > /dev/null; echo \"v=$PA_ADMIT_VERDICT $PA_ADMIT_AS\"",
        &NOW,
    );
    assert_eq!(r.get("ages"), "0");
    assert_eq!(r.get("v"), "admit reserve");
    assert_eq!(r.err, "", "nothing on stderr");
}

/// The switch summary goes once per switch: a summary of an earlier switch does not hold back the
/// next switch's, while a second summary of the same switch is withheld. Without the time of the
/// switch the cap is one a day.
#[test]
fn a_switch_summary_goes_once_per_switch() {
    let fx = Fx::salted(SALT);
    let verdict = |meta: &str| {
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=1\n{meta}"),
        );
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!(
                "#send-ledger v1 g=1\n{}",
                ledger_line("switch", "-", 7200, "ok")
            ),
        );
        fx.run_env("echo \"v=$(pa_budget_admit switch - - 0)\"", &NOW)
            .get("v")
    };
    assert_eq!(
        verdict(&format!("M\tprofile_switched\t{}\n", lib_at(3600))),
        "admit",
        "a second switch"
    );
    assert_eq!(
        verdict(&format!("M\tprofile_switched\t{}\n", lib_at(10000))),
        "withhold:switch-cap",
        "the same switch"
    );
    assert_eq!(verdict(""), "withhold:switch-cap");
    assert_eq!(
        verdict("M\tprofile_switched\tplantedword\n"),
        "withhold:switch-cap"
    );
}

/// A volume's projected time is computed from the hourly pass's samples of its filesystem, as the
/// walk computes it: full of its last GiB at 18:20 UTC gives `full by 18:20 UTC` in the headline
/// and `evidence at risk by 18:20 UTC` (only the size ring says at risk), with the cause inferred;
/// no projection gives `?` and the evidence word of its tier.
#[test]
fn a_volume_full_soon_gives_the_projected_time_from_its_samples() {
    let fx = Fx::salted(SALT);
    let samples = "Z\tm1a2b3\t998400/abcdef01/3400\t100000000000\t1078984704\t1000\t900\n\
                   Z\tm1a2b3\t739200/0000aaaa/1\t100000000000\t1154482176\t1000\t900\n\
                   Z\tm9f9f9f\t998400/abcdef01/3400\t100000000000\t5\t1000\t900\n";
    fn vol<'a>(kind: &'a str, tier: &'a str) -> Vec<(usize, &'a str)> {
        vec![
            (2, "vol:m1a2b3"),
            (3, kind),
            (4, "host"),
            (5, "m1a2b3"),
            (6, tier),
            (11, "vol.projected"),
            (33, "-"),
        ]
    }
    let m = open_over(&fx, &vol("volume-full-soon", "PAGE"), samples);
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(
        m.title,
        "PAGE host-908b - host: volume m1a2b3 full by 18:20 UTC"
    );
    assert_eq!(
        m.body[1],
        "Why: filling at the current rate (vol.projected), seen by witness@host-908b, inferred; last change: none in 24 h"
    );
    assert_eq!(
        m.body[3],
        "Impact: not known here; evidence at risk by 18:20 UTC"
    );
    let m = open_over(&fx, &vol("volume-filling", "ACT"), samples);
    assert_eq!(m.title, "ACT host-908b - host: volume m1a2b3 filling");
    assert_eq!(
        m.body[3],
        "Impact: not known here; evidence at risk by 18:20 UTC"
    );
    let m = open_over(&fx, &vol("volume-full-soon", "PAGE"), NO_OBSERVE);
    assert_eq!(m.title, "PAGE host-908b - host: volume m1a2b3 full by ?");
    assert_eq!(m.body[3], "Impact: not known here; evidence not measured");

    // A projected time that has already passed (under an hour was left at the newest sample,
    // taken 45 minutes ago) is not printed: with no date beside it, it would read as tomorrow's.
    let past = "Z\tm1a2b3\t997300/abcdef01/2300\t100000000000\t1073741824\t1000\t900\n\
                Z\tm1a2b3\t738100/0000aaaa/1\t100000000000\t1154482176\t1000\t900\n";
    let m = open_over(&fx, &vol("volume-full-soon", "PAGE"), past);
    assert_eq!(m.title, "PAGE host-908b - host: volume m1a2b3 full by ?");
    assert_eq!(m.body[3], "Impact: not known here; evidence not measured");
}

/// A child that opened on its own after its parent resolved says what it was folded under, by the
/// former parent's id kept in the field a newer writer appends; a value out of an id's form there
/// is never shown, and only the open says it.
#[test]
fn an_unfolded_childs_open_says_what_it_was_folded_under() {
    let fx = Fx::salted(SALT);
    let with = |v: &str| inc_rec(&[]).replace('\n', &format!("\t{v}\n"));
    let m = render(&fx, &[with("w#1")], "open", "w#3", "");
    assert_eq!(
        m.body[5],
        "w#3 opened - next reminder 14:46 UTC - was folded under w#1"
    );
    for v in ["plantedword", "w#1x", "-"] {
        let m = render(&fx, &[with(v)], "open", "w#3", "");
        assert_eq!(m.body[5], "w#3 opened - next reminder 14:46 UTC", "{v}");
    }
    let m = render(&fx, &[with("w#1")], "remind", "w#3", "");
    assert!(!m.out.contains("was folded"), "{}", m.out);
}

/// The alert path's HTTP code comes from the stored cause `http.<class>:<code>`, which the Why
/// line shows as the class's words and the code; a cause without a code shows `?`, and a cause
/// that is no HTTP answer (curl missing, no connection) names no HTTP code at all.
#[test]
fn the_alert_paths_http_code_comes_from_its_stored_cause() {
    let fx = Fx::salted(SALT);
    let path = |cause: &str| {
        open_over(
            &fx,
            &[
                (2, "alert:shell"),
                (3, "alert-path"),
                (4, "alert"),
                (5, "-"),
                (11, cause),
            ],
            NO_OBSERVE,
        )
    };
    let m = path("http.auth:403");
    assert_eq!(
        m.title,
        "PAGE host-908b - alert: alerts not leaving (HTTP 403)"
    );
    assert!(
        m.body[1].starts_with("Why: refused for authorisation (http.auth 403), seen by "),
        "{}",
        m.body[1]
    );
    assert_eq!(
        path("http.auth").title,
        "PAGE host-908b - alert: alerts not leaving (HTTP ?)"
    );
    for cause in ["nocurl", "net.connect", "unknown"] {
        assert_eq!(
            path(cause).title,
            "PAGE host-908b - alert: alerts not leaving",
            "{cause}"
        );
    }
}

/// The hook's one message when it cannot take the lock is rendered from the firing's own
/// attributes, without a stored record: a full-mode open whose lifecycle line starts `(id pending)
/// opened`, within the line and size rules, with nothing planted in the attributes passed through;
/// anything but a unit kind's open renders nothing.
#[test]
fn the_hooks_message_without_the_lock_says_its_id_is_pending() {
    let fx = Fx::salted(SALT);
    let run = |tx: &str, kind: &str, inst: &str, cause: &str| {
        let r = fx.run_env(
            &format!(
                "PA_ROLE=single PA_REC_KIND={kind} PA_REC_STAGE=listen PA_REC_INST={inst} PA_REC_TIER=PAGE PA_REC_CAUSE={cause}\n\
                 if pa_render full {tx} -; then echo rc=0; else echo rc=1; fi\n\
                 printf 'title=%s\\n' \"$PA_TITLE\"; printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'"
            ),
            &NOW,
        );
        let body: Vec<String> = r
            .out
            .lines()
            .filter_map(|l| l.strip_prefix("body="))
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        (r.get("rc"), r.get("title"), body, r.out)
    };
    let (rc, title, body, out) = run("open", "unit-failed", "u1a2b3", "proc.exit:1");
    assert_eq!(rc, "0", "{out}");
    assert_eq!(title, "PAGE host-908b - listen: unit u1a2b3 failed");
    assert_eq!(
        body,
        [
            "Since 13:46:40 UTC (0 min) - detected 13:46:40 UTC",
            "Why: process exited (proc.exit 1), seen by hook@host-908b, known; last change: none in 24 h",
            "Where: host-908b (single), stage 1 of 10, u1a2b3",
            "Impact: not capturing on u1a2b3; evidence not measured",
            "Do: status listen - runbook listen-down",
            "(id pending) opened - next reminder none",
        ]
    );
    assert!(body.join("\n").len() < 1024 && body.iter().all(|l| l.len() <= 200));
    let (rc, title, _, out) = run("open", "unit-failed", "plantedword", "plantedword:1");
    assert_eq!(rc, "0", "{out}");
    assert_eq!(title, "PAGE host-908b - listen: unit ? failed");
    assert!(!out.contains("plantedword"), "{out}");
    for (tx, kind) in [
        ("remind", "unit-failed"),
        ("open", "finding"),
        ("open", "bogus"),
    ] {
        let (rc, title, body, _) = run(tx, kind, "u1a2b3", "proc.exit:1");
        assert_eq!(
            (rc.as_str(), title.as_str(), body.len()),
            ("1", "", 0),
            "{tx} {kind}"
        );
    }
}

/// A body line that fails the line rule is replaced by `(line withheld)` and the rest of the
/// message goes as it is; a title that fails it stops the whole message.
#[test]
fn a_body_line_out_of_the_line_rule_is_withheld_and_a_bad_title_stops_the_message() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", inc_rec(&[])),
    );
    let run = |seam: &str| {
        let r = fx.run_env(
            &format!(
                "PA_ROLE=single\npa_incident_load\n{seam}\n\
                 if pa_render full open w#3; then echo rc=0; else echo rc=1; fi\n\
                 printf 'title=%s\\n' \"$PA_TITLE\"; printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'"
            ),
            &NOW,
        );
        let body: Vec<String> = r
            .out
            .lines()
            .filter_map(|l| l.strip_prefix("body="))
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        (r.get("rc"), r.get("title"), body)
    };
    let (rc, title, body) = run("_pa_impact() { printf 'x%.0s' {1..250}; }");
    assert_eq!(rc, "0");
    assert_eq!(title, "PAGE host-908b - listen: unit u1a2b3 failed");
    assert_eq!(
        body,
        [
            "Since 13:30:00 UTC (16 min) - detected 13:30:00 UTC",
            "Why: process exited (proc.exit 1), seen by hook@host-908b, known; last change: none in 24 h",
            "Where: host-908b (single), stage 1 of 10, u1a2b3",
            "(line withheld)",
            "Do: status listen - runbook listen-down",
            "w#3 opened - next reminder 14:46 UTC",
        ]
    );
    let (rc, title, body) = run("_pa_what() { printf 'unit\\001x'; }");
    assert_eq!((rc.as_str(), title.as_str(), body.len()), ("1", "", 0));
}

/// Further cases of the budget's order: a unit-failed record on the daemon's key at PAGE is a
/// reserve kind; the reserve's day holds four, so three two hours old leave room and four send a
/// reserve kind through the pool; the hour's listener lines count against the pool's hour only up
/// to the sub-cap of two.
#[test]
fn the_reserve_day_and_the_stage1_hour_count_to_their_limits() {
    let fx = Fx::salted(SALT);
    let other = "00000000";
    let daemon_unit = inc_rec(&[
        (2, "unit:propolis.service"),
        (3, "unit-failed"),
        (4, "intake"),
        (5, "-"),
    ]);
    assert_eq!(
        admit_over(
            &fx,
            &[daemon_unit],
            &lines_of(4, "pool", other, 600),
            "unit:propolis.service",
            "open",
            "1"
        ),
        "admit reserve"
    );
    let db = inc_rec(&[
        (2, "db:local"),
        (3, "db-unreachable"),
        (4, "ledger"),
        (5, "-"),
    ]);
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &lines_of(3, "reserve", other, 7200),
            "db:local",
            "open",
            "1"
        ),
        "admit reserve"
    );
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&db),
            &lines_of(4, "reserve", other, 7200),
            "db:local",
            "open",
            "1"
        ),
        "admit pool"
    );
    let ship = inc_rec(&[(2, "unit:shipper.service"), (4, "ship"), (6, "ACT")]);
    let hour = [
        lines_of(3, "stage1", other, 600),
        lines_of(1, "pool", other, 600),
    ]
    .concat();
    assert_eq!(
        admit_over(&fx, &[ship], &hour, "unit:shipper.service", "open", "1"),
        "admit pool"
    );
}

/// A retry of a line still pending (its sender killed before it wrote a result) rewrites that
/// line's sender and the time of the attempt and adds none.
#[test]
fn a_retry_of_a_line_still_pending_rewrites_it_and_adds_none() {
    let fx = Fx::salted(SALT);
    let s = "999800/abcdef01/4800";
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\nL\t{s}\tpool\tabcdef12\topen\tfull\tpending\tlight\tw#4\t{s}\n"
        ),
    );
    let r = fx.run_env(
        &format!("pa_ledger_retry {s} abcdef12 open hourly; echo \"rc=$?\""),
        &NOW,
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(
        fx.read("var/lib/propolis/witness/send-ledger"),
        format!(
            "#send-ledger v1 g=2\nL\t{s}\tpool\tabcdef12\topen\tfull\tpending\thourly\tw#4\t1000000/abcdef01/5000\n"
        )
    );
}

/// When the next summary has room is the later of the times its two caps free: the hour's one
/// line half an hour old frees at 14:17, the day's twelve when the oldest leaves the day, at 15:34.
#[test]
fn the_next_summary_has_room_at_the_later_of_its_two_caps() {
    let fx = Fx::salted(SALT);
    let other = "00000000";
    let lines = [
        vec![ledger_line("summary", other, 80000, "ok")],
        lines_of(10, "summary", other, 7200),
        vec![ledger_line("summary", other, 1800, "ok")],
    ]
    .concat();
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{}", lines.concat()),
    );
    let r = fx.run_env("echo \"next=$(pa_budget_next summary)\"", &NOW);
    assert_eq!(r.get("next"), "15:34");
}

/// No message is rendered without an alias: with neither the id salt nor a configured alias there
/// is none, and nothing is set.
#[test]
fn an_incident_message_without_a_salt_or_an_alias_is_not_rendered() {
    let fx = Fx::new();
    let m = render(&fx, &[inc_rec(&[])], "open", "w#3", "");
    assert_eq!(m.rc, "1", "{}", m.out);
    assert_eq!(
        (m.title.as_str(), m.prio.as_str(), m.body.len()),
        ("", "", 0)
    );
}

/// A role word out of the closed list (a planted word, an escape sequence, 300 bytes) reads
/// `unknown` and is never shown.
#[test]
fn a_role_out_of_its_list_reads_unknown() {
    let fx = Fx::salted(SALT);
    let long = "z".repeat(300);
    for role in ["plantedword", "\u{1b}[31mred", long.as_str()] {
        let m = render_with(
            &fx,
            &[inc_rec(&[])],
            NO_OBSERVE,
            "open",
            "w#3",
            "",
            &[("ROLE", role)],
        );
        assert_eq!(
            m.body[2],
            "Where: host-908b (unknown), stage 1 of 10, u1a2b3"
        );
        assert!(!m.out.contains(&role[..8]), "{}", m.out);
    }
}

/// The incident renderer, the incident budget, the retry code and the result of an incident
/// message have two callers outside their own definitions: the failure hook's v2 path in the
/// library (pa_hook_v2 and the _pa_hv2_ functions it calls) and the witness's send step
/// (send_expire, send_admit, send_claim, send_one, send_post). No other script in deploy/
/// renders an incident message, asks the budget about a class other than the test page's and the daily message's, or
/// admits, retries or writes the result of an incident message, and no script but the failure
/// hook names pa_hook_v2 or pa_hook_profile: the hook starts the v2 child once, after the
/// decision child (pa_hook_profile), which a run without a test root cannot pass
/// (pa_hook_profile_is_legacy_without_a_test_root_whatever_the_env_files_and_the_seam_say). The
/// witness's send step admits, retries, drops and posts only while SEND_V2 is 1, which only
/// send_init sets, from the profile in force, which is legacy without a test root; its part that
/// decides whether a pending transition is due or dropped (send_expire) asks pa_retry_due and no
/// other guarded function. The witness's list of the library functions it needs is the one line
/// of names this test passes over. The storm notice and the summary have one caller outside the
/// library, the witness's notice step: notice_since reads their meta keys (pa_meta_value),
/// notice_claim renders and admits them (pa_render, pa_notice_admit), notice_step writes the
/// result and the key (pa_notice_close), and notice_step does nothing unless SEND_V2 is 1, the
/// pass retries (sends for the host) and the gate is full. The switch summary and the pointer
/// message (their renderers, the W-line reader, the result written alone, the meta key writer)
/// are called by no script at all: no other function renders a notice (pa_render with a class
/// other than the test page's and the daily message's), asks the budget about its class, or names
/// one of their functions.
#[test]
fn only_the_hooks_v2_path_and_the_witness_send_step_call_the_incident_code() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");
    let mut found = Vec::new();
    let mut hook_lines: Vec<(usize, String)> = Vec::new();
    let mut seen = 0;
    // The library's own chain from each entry point to the code behind it, and the v2 path.
    let allowed_in_lib = |f: &str| {
        matches!(
            f,
            "pa_incident_admit"
                | "pa_budget_admit"
                | "pa_render"
                | "pa_budget_next"
                | "pa_hook_v2"
                | "pa_incident_result"
                | "_pa_render_withheld"
                | "pa_notice_admit"
                | "pa_notice_close"
        ) || f.starts_with("_pa_hv2_")
    };
    // Which of the guarded names each part of the witness's send step may use: send_expire, which
    // only decides whether a pending transition is due, dropped or left, asks pa_retry_due alone;
    // notice_claim renders. The notices' admission, result and key reader are checked against a
    // table of their own (notice_calls_out_of_place), which no send-step function is in.
    let allowed_in_witness = |f: &str, name: &str| match f {
        "send_expire" => name == "pa_retry_due",
        "send_admit" | "send_claim" | "send_one" | "send_post" => true,
        "notice_claim" => name == "pa_render",
        _ => false,
    };
    let witness = std::fs::read_to_string(format!("{dir}/witness.sh")).unwrap();
    let sets: Vec<&str> = witness
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && l.contains("SEND_V2=1"))
        .collect();
    assert_eq!(
        sets,
        ["[ \"${PA_PROFILE:-legacy}\" != v2 ] || SEND_V2=1"],
        "SEND_V2 is set only from the profile"
    );
    let post = witness
        .split("\nsend_post() {\n")
        .nth(1)
        .and_then(|rest| rest.lines().find(|l| !l.trim_start().starts_with("local ")))
        .unwrap_or("");
    assert_eq!(post.trim(), "[ \"$SEND_V2\" = 1 ] || return 0");
    let admit = witness.split("\nsend_admit() {\n").nth(1).unwrap_or("");
    assert!(
        admit.contains("if [ \"$SEND_V2\" != 1 ] || [ \"$SEND_GATE\" != full ]; then"),
        "send_admit admits nothing under legacy"
    );
    let notice: Vec<&str> = witness
        .split("\nnotice_step() {\n")
        .nth(1)
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("local "))
        .take(2)
        .collect();
    assert_eq!(
        notice,
        [
            "[ \"$SEND_V2\" = 1 ] || return 0",
            "[ \"$SEND_RETRY\" = 1 ] && [ \"$SEND_GATE\" = full ] && [ \"$SEND_LEDGER_BAD\" = 0 ] || return 0"
        ],
        "the notice step does nothing under legacy, on a pass that does not send for the host, \
         or with the gate short of full"
    );
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".sh") {
            continue;
        }
        seen += 1;
        let text = std::fs::read_to_string(&path).unwrap();
        let mut function = String::new();
        let mut in_list = false;
        for (n, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if let Some(f) = t.strip_suffix("() {")
                && !line.starts_with(' ')
            {
                function = f.to_string();
                continue;
            }
            if t.starts_with('#') {
                continue;
            }
            if name != "alert-lib.sh" && (t.contains("pa_hook_v2") || t.contains("pa_hook_profile"))
            {
                if name == "alert.sh" {
                    hook_lines.push((n, t.to_string()));
                } else {
                    found.push(format!("{name}: {t}"));
                }
            }
            if name == "alert-lib.sh" && allowed_in_lib(&function) {
                continue;
            }
            // The witness's list of the library functions it needs, a line of names alone inside
            // its WITNESS_LIB_FUNCS="..." assignment, calls nothing.
            if name == "witness.sh" && (in_list || t.starts_with("WITNESS_LIB_FUNCS=\"")) {
                in_list = !t.ends_with('"');
                if t.trim_start_matches("WITNESS_LIB_FUNCS=\"")
                    .trim_end_matches('"')
                    .split_whitespace()
                    .all(|w| w.starts_with("pa_"))
                {
                    continue;
                }
            }
            let allowed = |f: &str| name == "witness.sh" && allowed_in_witness(&function, f);
            for f in [
                "pa_incident_admit",
                "pa_retry_due",
                "pa_ledger_retry",
                "pa_incident_result",
                "_pa_render_incident",
                "_pa_budget_incident",
            ] {
                if t.contains(f) && !allowed(f) {
                    found.push(format!("{name}: {t}"));
                }
            }
            // The switch summary, the pointer message and the meta key writer have no caller at
            // all outside the library; the admission, the result with its key and the key reader
            // of the storm notice and the summary only the witness's notice step.
            for f in [
                "_pa_render_withheld",
                "_pa_render_switch",
                "pa_withheld_since",
                "pa_notice_result",
                "pa_meta_put",
            ] {
                if t.contains(f) {
                    found.push(format!("{name}: {t}"));
                }
            }
            if name != "witness.sh" {
                for f in NOTICE_STEP_NAMES {
                    if t.contains(f) {
                        found.push(format!("{name}: {t}"));
                    }
                }
            }
            // Each use of a function, wherever it stands on the line (after `$(`, `if`, `!` or
            // an assignment), with the words that follow it: a list of names is no call.
            for f in ["pa_render", "pa_budget_admit", "pa_budget_next"] {
                if allowed(f) {
                    continue;
                }
                for (at, _) in t.match_indices(f) {
                    let before = t[..at].chars().last();
                    if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                        continue;
                    }
                    let rest = &t[at + f.len()..];
                    if !rest.starts_with(' ') {
                        continue;
                    }
                    let args: Vec<&str> = rest
                        .split_whitespace()
                        .map(|a| a.trim_end_matches([')', '"']))
                        .collect();
                    let first = args.first().copied().unwrap_or("");
                    if first.starts_with("pa_") {
                        continue;
                    }
                    let class = if f == "pa_render" {
                        args.get(1).copied().unwrap_or("")
                    } else {
                        first
                    };
                    if class != "test" && class != "daily" {
                        found.push(format!("{name}: {t}"));
                    }
                }
            }
        }
    }
    assert!(seen >= 6, "the scripts in deploy/");
    found.extend(notice_calls_out_of_place(&witness));
    assert!(found.is_empty(), "calls of the new code: {found:#?}");
    // In the hook: the decision first, then the v2 child, once each.
    let profile: Vec<usize> = hook_lines
        .iter()
        .filter(|(_, t)| t.contains("pa_hook_profile"))
        .map(|(n, _)| *n)
        .collect();
    let v2: Vec<usize> = hook_lines
        .iter()
        .filter(|(_, t)| t.contains("pa_hook_v2"))
        .map(|(n, _)| *n)
        .collect();
    assert_eq!((profile.len(), v2.len()), (1, 1), "{hook_lines:#?}");
    assert!(
        profile[0] < v2[0],
        "the decision comes first: {hook_lines:#?}"
    );
}

/// The library functions of the storm notice and the summary that only the witness's notice step
/// may name, each in one function of it.
const NOTICE_STEP_NAMES: [&str; 3] = ["pa_notice_admit", "pa_notice_close", "pa_meta_value"];

/// Every line of the witness TEXT that names one of NOTICE_STEP_NAMES outside its one function:
/// notice_since reads the keys (pa_meta_value), notice_claim admits (pa_notice_admit) and
/// notice_step writes the result and the key (pa_notice_close). The send step's functions, which
/// may use the incident code, are refused these like every other function. The list of the
/// library functions the witness needs is passed over, as it calls nothing.
fn notice_calls_out_of_place(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut function = String::new();
    let mut in_list = false;
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(f) = t.strip_suffix("() {")
            && !line.starts_with(' ')
        {
            function = f.to_string();
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        if in_list || t.starts_with("WITNESS_LIB_FUNCS=\"") {
            in_list = !t.ends_with('"');
            continue;
        }
        for f in NOTICE_STEP_NAMES {
            let own = match f {
                "pa_meta_value" => "notice_since",
                "pa_notice_admit" => "notice_claim",
                _ => "notice_step",
            };
            if t.contains(f) && function != own {
                found.push(format!("{function}: {t}"));
            }
        }
    }
    found
}

/// The notices' admission, result and key reader are refused in each function of the incident
/// send step, which may call the incident code: a copy of the witness with one of them planted in
/// send_admit, send_claim, send_one or send_post fails the check, and the shipped witness passes.
#[test]
fn the_notice_functions_are_refused_in_the_send_step_and_in_every_function_but_their_own() {
    let witness = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/witness.sh"
    ))
    .unwrap();
    assert_eq!(
        notice_calls_out_of_place(&witness),
        Vec::<String>::new(),
        "the shipped witness"
    );
    for host in ["send_admit", "send_claim", "send_one", "send_post"] {
        let head = format!("\n{host}() {{\n");
        assert!(witness.contains(&head), "{host}");
        for f in NOTICE_STEP_NAMES {
            let planted = witness.replacen(
                &head,
                &format!("{head}    {f} storm \"$SEND_SENDER\" > /dev/null || true\n"),
                1,
            );
            let found = notice_calls_out_of_place(&planted);
            assert_eq!(found.len(), 1, "{f} in {host}: {found:#?}");
            assert!(found[0].starts_with(&format!("{host}: {f} ")), "{found:#?}");
        }
    }
    // In a notice function that is not its own, too.
    let planted = witness.replacen(
        "\nnotice_since() {\n",
        "\nnotice_since() {\n    pa_notice_close x storm ok light || true\n",
        1,
    );
    assert_eq!(notice_calls_out_of_place(&planted).len(), 1);
}

/// The decision child of the failure hook: pa_hook_profile ends 0 only when profile v2 is in
/// force, else 10. With an empty root, which is how every unit runs it, it is 10 whatever both env
/// files say and whatever the test seam says; under the test root with the seam it is 0, and a
/// unit name systemd would not give is 10 even then, so today's message reports it.
#[test]
fn pa_hook_profile_is_legacy_without_a_test_root_whatever_the_env_files_and_the_seam_say() {
    let fx = Fx::new();
    fx.write("etc/propolis/propolis.env", "PROPOLIS_ALERT_PROFILE=v2\n");
    fx.write("etc/propolis/alert.env", "PROPOLIS_ALERT_PROFILE=v2\n");
    let decide =
        "rc=0\npa_hook_profile || rc=$?\necho \"rc=$rc\"\necho \"state=${PA_PROFILE_STATE:-}\"";
    let unit = ("PA_HOOK_UNIT", "sensor-ssh.service");
    let seam = ("PA_TEST_PROFILE", "v2");
    // An empty root, with the env files read from the fixture so that both say v2.
    let r = fx.run_raw(
        &format!(
            "set -u -o pipefail\nsource \"$LIB\"\npa_init ''\nPA_ENV_DIR=\"$ROOT/etc/propolis\"\n{decide}"
        ),
        &[unit, seam],
    );
    assert_eq!(
        (r.get("rc"), r.get("state")),
        ("10".into(), "v2".into()),
        "{}",
        r.err
    );
    let r = fx.run_env(decide, &[unit, seam]);
    assert_eq!(r.get("rc"), "0", "the seam under a test root: {}", r.err);
    let r = fx.run_env(decide, &[unit]);
    assert_eq!(r.get("rc"), "10", "no seam: {}", r.err);
    for bad in ["sensor-ssh", "", "bad unit"] {
        let r = fx.run_env(decide, &[("PA_HOOK_UNIT", bad), seam]);
        assert_eq!(r.get("rc"), "10", "{bad:?}: {}", r.err);
    }
}

/// The result of a post is written by one function for the failure hook and the witness alike:
/// its ledger line takes the result and the sender; the record's pending transition ends unless
/// the result is transient, and only while it is still that transition (its stamp); ok marks the
/// incident delivered for an open, a reopen or a reminder (the record's field 17), so an open that was
/// withheld is delivered by the late reminder that got through and its RESOLVED can follow, while
/// a change that got through leaves an open the operator never had undelivered. Only the hook's
/// own sends set the hook's delivered stamp: the witness cannot write there.
#[test]
fn the_result_of_a_send_is_one_rule_for_the_hook_and_the_witness() {
    let fx = Fx::salted(SALT);
    let s = "999800/abcdef01/4800";
    let other = "999700/abcdef01/4700";
    let keys = [
        "unit:sensor-ssh.service",
        "unit:sensor-http.service",
        "unit:sensor-ftp.service",
        "unit:sensor-dns.service",
        "unit:sensor-tftp.service",
        "unit:sensor-smtp.service",
    ];
    let kh: Vec<String> = keys.iter().map(|k| keyhash(&fx, k)).collect();
    let rec = |id: &str, key: &str, tx: &str, since: &str| {
        inc_rec(&[
            (1, id),
            (2, key),
            (17, "0"),
            (14, "1"),
            (26, tx),
            (27, since),
        ])
    };
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=1\nN\t20\n{}{}{}{}{}{}",
            rec("w#3", keys[0], "change", s),
            rec("w#4", keys[1], "open", s),
            rec("w#5", keys[2], "remind", s),
            rec("w#6", keys[3], "open", other),
            rec("w#7", keys[4], "open", s),
            rec("w#8", keys[5], "remind", s),
        ),
    );
    let line = |k: &str, tx: &str, id: &str| {
        format!("L\t{s}\tpool\t{k}\t{tx}\tfull\tpending\tlight\t{id}\t{s}\n")
    };
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}{}{}{}{}{}",
            line(&kh[0], "change", "w#3"),
            line(&kh[1], "open", "w#4"),
            line(&kh[2], "remind", "w#5"),
            line(&kh[3], "open", "w#6"),
            line(&kh[4], "open", "w#7"),
            line(&kh[5], "remind", "w#8"),
        ),
    );
    let script = format!(
        "pa_incident_result {k0} {s} pool {h0} change ok light; echo \"a=$? $PA_RESULT_STAMP\"\n\
         pa_incident_result {k1} {s} pool {h1} open transient:503 hourly; echo \"b=$?\"\n\
         pa_incident_result {k2} {s} pool {h2} remind perm:403 light; echo \"c=$?\"\n\
         pa_incident_result {k3} {s} pool {h3} open ok light; echo \"d=$?\"\n\
         pa_incident_result {k4} {s} pool {h4} open ok hook; echo \"e=$? $PA_RESULT_STAMP\"\n\
         pa_incident_result {k5} {s} pool {h5} remind ok light; echo \"f=$?\"",
        k0 = keys[0],
        k1 = keys[1],
        k2 = keys[2],
        k3 = keys[3],
        k4 = keys[4],
        k5 = keys[5],
        h0 = kh[0],
        h1 = kh[1],
        h2 = kh[2],
        h3 = kh[3],
        h4 = kh[4],
        h5 = kh[5],
    );
    let r = fx.run_env(&script, &NOW);
    assert_eq!(r.get("a"), "0 -", "{}", r.err);
    assert_eq!(r.get("b"), "0");
    assert_eq!(r.get("c"), "0");
    assert_eq!(r.get("e"), "0 ok");
    assert_eq!(r.get("f"), "0");
    let state = fx.read("var/lib/propolis/witness/incidents");
    let field = |id: &str, n: usize| {
        state
            .lines()
            .find(|l| l.starts_with(&format!("I\t{id}\t")))
            .map(|l| l.split('\t').nth(n).unwrap_or("").to_string())
            .unwrap_or_default()
    };
    // (delivered_open, pending_tx, pending_since)
    let got = |id: &str| (field(id, 17), field(id, 26), field(id, 27));
    let done = || ("1".to_string(), "-".to_string(), "-".to_string());
    assert_eq!(
        got("w#3"),
        ("0".into(), "-".into(), "-".into()),
        "a change that got through ends it and leaves the open undelivered"
    );
    assert_eq!(
        got("w#8"),
        done(),
        "a reminder that got through delivers it"
    );
    assert_eq!(
        got("w#4"),
        ("0".into(), "open".into(), s.into()),
        "transient keeps it for the retry"
    );
    assert_eq!(
        got("w#5"),
        ("0".into(), "-".into(), "-".into()),
        "a refusal ends it"
    );
    assert_eq!(
        got("w#6"),
        ("0".into(), "open".into(), other.into()),
        "another admission's transition is kept"
    );
    assert_eq!(got("w#7"), done());
    let ledger = fx.read("var/lib/propolis/witness/send-ledger");
    let results: Vec<(String, String)> = ledger
        .lines()
        .filter(|l| l.starts_with("L\t"))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[6].to_string(), f[7].to_string())
        })
        .collect();
    let want: Vec<(String, String)> = [
        ("ok", "light"),
        ("transient:503", "hourly"),
        ("perm:403", "light"),
        ("ok", "light"),
        ("ok", "hook"),
        ("ok", "light"),
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    assert_eq!(results, want, "{ledger}");
    // The hook's delivered stamp for the unit: set by the hook's send, never by the witness's.
    assert!(fx.p("run/propolis-alert/sensor-tftp.service").exists());
    assert!(!fx.p("run/propolis-alert/sensor-ssh.service").exists());
    assert!(!fx.p("run/propolis-alert/sensor-dns.service").exists());
}

/// A message that has already gone, the hook's send without the lock, is charged to the class the
/// budget would have given its record, whatever room there is: the reserve for a reserve kind at
/// PAGE on its own key, stage1 for a listener, else the pool.
#[test]
fn a_message_that_has_gone_is_charged_to_the_class_its_kind_would_have_had() {
    let fx = Fx::salted(SALT);
    for (args, want) in [
        ("unit:propolis.service daemon-down PAGE intake", "reserve"),
        ("unit:propolis.service daemon-down ACT intake", "pool"),
        ("db:local db-unreachable PAGE ledger", "reserve"),
        ("alert:shell alert-path PAGE alert", "reserve"),
        ("unit:sensor-ssh.service unit-failed PAGE listen", "stage1"),
        ("finding:danger:0123456789ab finding PAGE listen", "stage1"),
        ("unit:shipper.service unit-failed ACT ship", "pool"),
        ("unit:gateway.service unit-failed ACT gateway", "pool"),
    ] {
        let r = fx.run_env(&format!("echo \"c=$(pa_budget_class {args})\""), &NOW);
        assert_eq!(r.get("c"), want, "{args}: {}", r.err);
    }
}

// ---- the notices and the pointer message ---------------------------------------------------------

/// The shell target's settings, loaded, and a stored readcheck line that proves the target
/// refuses anonymous reads, fresh at `NOW`: with nothing else in the way the gate is full.
const FULL_GATE: &str = "pa_settings_load\nb=\"$(pa_readcheck_binding \"$PA_URL\" \"$PA_TOPIC\")\"\n\
     printf '#readcheck v1 g=1\\nR\\t%s\\t999000/abcdef01/4000\\trefused\\t999000/abcdef01/4000\\trefused\\t-\\t403\\t403\\tboth\\t403\\n' \
     \"$b\" > \"$PA_STATE/readcheck\"\nPA_ROLE=single\n";

const TARGET_ENV: &str =
    "PROPOLIS_OPS_NTFY_URL=https://ntfy.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n";

/// PROPOLIS_OPS_PUSH_DETAIL can only take detail away: unset, empty and `auto` leave the gate to
/// decide, and every other value, `full` among them, a value with a blank, one with a control
/// byte, one of 300 bytes and one systemd would read otherwise, means pointer. A PA_DETAIL the
/// caller's environment holds is no setting. The setting belongs to profile v2, which the test
/// seam selects here.
#[test]
fn the_push_detail_setting_can_only_narrow_what_is_sent_and_only_auto_or_nothing_leaves_full() {
    let fx = Fx::salted(SALT);
    let long = "a".repeat(300);
    let cases: Vec<(Option<String>, &str, &str, &str)> = vec![
        (None, "auto", "unset", "full"),
        (Some(String::new()), "auto", "unset", "full"),
        (Some("auto".into()), "auto", "auto", "full"),
        (Some("'auto'".into()), "auto", "auto", "full"),
        (
            Some("pointer".into()),
            "pointer",
            "pointer",
            "pointer:detail-pointer",
        ),
        (
            Some("full".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (
            Some("FULL".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (
            Some("AUTO".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (
            Some("auto full".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (
            Some("auto\x01".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (
            Some("auto\\".into()),
            "pointer",
            "invalid",
            "pointer:detail-pointer",
        ),
        (Some(long), "pointer", "invalid", "pointer:detail-pointer"),
    ];
    for (value, detail, state, gate) in cases {
        let mut env = TARGET_ENV.to_string();
        if let Some(v) = &value {
            env.push_str(&format!("PROPOLIS_OPS_PUSH_DETAIL={v}\n"));
        }
        fx.write("etc/propolis/propolis.env", &env);
        let mut all = NOW.to_vec();
        all.push(("PA_DETAIL", "auto"));
        all.push(("PA_TEST_PROFILE", "v2"));
        let r = fx.run_env(
            &format!(
                "{FULL_GATE}echo \"detail=$PA_DETAIL\"\necho \"state=$PA_DETAIL_STATE\"\n\
                 echo \"gate=$(pa_gate)\""
            ),
            &all,
        );
        assert_eq!(
            (r.get("detail"), r.get("state"), r.get("gate")),
            (detail.to_string(), state.to_string(), gate.to_string()),
            "{value:?}: {}",
            r.err
        );
    }
}

/// Under the legacy profile, which is every host's, the detail setting changes nothing: pointer
/// mode is profile v2's, and a host that writes the key, in form or not, keeps the gate the
/// anonymous-read check gives, so the daily message goes as before. What the file says is still
/// recorded (PA_DETAIL_STATE), for the report that comes with the switch.
#[test]
fn under_the_legacy_profile_the_push_detail_setting_changes_nothing() {
    let fx = Fx::salted(SALT);
    for (value, state) in [
        ("pointer", "pointer"),
        ("full", "invalid"),
        ("AUTO", "invalid"),
        ("auto full", "invalid"),
        ("auto", "auto"),
    ] {
        // A profile line that names v2 changes nothing either: this release honours none.
        fx.write(
            "etc/propolis/propolis.env",
            &format!("{TARGET_ENV}PROPOLIS_ALERT_PROFILE=v2\nPROPOLIS_OPS_PUSH_DETAIL={value}\n"),
        );
        for seam in [None, Some("legacy")] {
            let mut all = NOW.to_vec();
            if let Some(p) = seam {
                all.push(("PA_TEST_PROFILE", p));
            }
            let r = fx.run_env(
                &format!(
                    "{FULL_GATE}echo \"profile=$PA_PROFILE\"\necho \"detail=$PA_DETAIL\"\n\
                     echo \"state=$PA_DETAIL_STATE\"\necho \"gate=$(pa_gate)\""
                ),
                &all,
            );
            assert_eq!(
                (
                    r.get("profile"),
                    r.get("detail"),
                    r.get("state"),
                    r.get("gate")
                ),
                (
                    "legacy".to_string(),
                    "auto".to_string(),
                    state.to_string(),
                    "full".to_string()
                ),
                "{value} {seam:?}: {}",
                r.err
            );
        }
    }
}

/// The detail setting follows the precedence of every other setting of the shell senders, key by
/// key: alert.env when it gives the key a value, else propolis.env, whichever file holds the
/// target. So `pointer` in propolis.env holds a target alert.env gives to pointer mode, and an
/// empty line in alert.env does not lift it.
#[test]
fn the_push_detail_setting_is_read_from_alert_env_over_propolis_env_whatever_file_holds_the_target()
{
    let fx = Fx::salted(SALT);
    for (alert_extra, env_extra, detail, src) in [
        (
            "",
            "PROPOLIS_OPS_PUSH_DETAIL=pointer\n",
            "pointer",
            "propolis.env",
        ),
        (
            "PROPOLIS_OPS_PUSH_DETAIL=\n",
            "PROPOLIS_OPS_PUSH_DETAIL=pointer\n",
            "pointer",
            "propolis.env",
        ),
        (
            "PROPOLIS_OPS_PUSH_DETAIL=auto\n",
            "PROPOLIS_OPS_PUSH_DETAIL=pointer\n",
            "auto",
            "alert.env",
        ),
        (
            "PROPOLIS_OPS_PUSH_DETAIL=pointer\n",
            "PROPOLIS_OPS_PUSH_DETAIL=auto\n",
            "pointer",
            "alert.env",
        ),
        ("", "", "auto", ""),
    ] {
        fx.write(
            "etc/propolis/alert.env",
            &format!("{TARGET_ENV}{alert_extra}"),
        );
        fx.write("etc/propolis/propolis.env", env_extra);
        let mut all = NOW.to_vec();
        all.push(("PA_TEST_PROFILE", "v2"));
        let r = fx.run_env(
            &format!(
                "{FULL_GATE}echo \"detail=$PA_DETAIL\"\necho \"src=$PA_DETAIL_SRC\"\n\
                 echo \"target=$PA_TARGET_SRC\"\necho \"gate=$(pa_gate)\""
            ),
            &all,
        );
        let gate = if detail == "auto" {
            "full"
        } else {
            "pointer:detail-pointer"
        };
        assert_eq!(
            (
                r.get("detail"),
                r.get("src"),
                r.get("target"),
                r.get("gate")
            ),
            (
                detail.to_string(),
                src.to_string(),
                "alert.env".to_string(),
                gate.to_string()
            ),
            "{alert_extra:?} {env_extra:?}: {}",
            r.err
        );
    }
}

/// An hour before `NOW`, in the same boot: the stamp a notice lists what was withheld since.
const SINCE: &str = "996400/abcdef01/1400";
/// Ten minutes before `NOW`, after `SINCE`.
const W_T: &str = "999400/abcdef01/4400";

/// An open record of incident `w#<n>` on KEY at TIER, instance INST.
fn nrec(n: usize, key: &str, tier: &str, inst: &str) -> String {
    let id = format!("w#{n}");
    inc_rec(&[(1, &id), (2, key), (5, inst), (6, tier)])
}

/// The key of the n-th sensor of a fixture.
fn nkey(n: usize) -> String {
    format!("unit:sensor-n{n}.service")
}

/// An opaque instance id for the n-th sensor of a fixture.
fn ninst(n: usize) -> String {
    format!("u{:05x}", 0xa0000 + n)
}

/// A W line at stamp AT for KEYHASH.
fn wline(at: &str, kh: &str, tx: &str, new: &str) -> String {
    format!("W\t{at}\t{kh}\t{tx}\t{new}\t-\tpool\n")
}

/// What pa_withheld_since gives over RECORDS (and their W lines) for SINCE.
fn withheld(fx: &Fx, records: &[String], since: &str) -> Run {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let mut env = NOW.to_vec();
    env.push(("SINCE", since));
    fx.run_env(
        "pa_incident_load\npa_withheld_since \"$SINCE\"\n\
         printf 'n=%s\\nnames=%s\\nmore=%s\\npage=%s\\npagemore=%s\\n' \
         \"$PA_WH_N\" \"$PA_WH_NEW\" \"$PA_WH_MORE\" \"$PA_WH_PAGE\" \"$PA_WH_PAGE_MORE\"",
        &env,
    )
}

/// Renders a notice: `pa_render MODE TX ID` over RECORDS, with the send ledger LEDGER (its lines
/// after the header) when it is not empty.
fn notice(fx: &Fx, records: &[String], ledger: &str, mode: &str, tx: &str, id: &str) -> Msg {
    notice_with(fx, records, ledger, "", mode, tx, id)
}

/// `notice`, with the shell lines PRE run first.
fn notice_with(
    fx: &Fx,
    records: &[String],
    ledger: &str,
    pre: &str,
    mode: &str,
    tx: &str,
    id: &str,
) -> Msg {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    if !ledger.is_empty() {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{ledger}"),
        );
    }
    let mut all: Vec<(&str, &str)> = NOW.to_vec();
    all.push(("MODE", mode));
    all.push(("TX", tx));
    all.push(("ID", id));
    let r = fx.run_env(
        &format!(
            "{pre}PA_ROLE=single\npa_incident_load\n\
             if pa_render \"$MODE\" \"$TX\" \"$ID\"; then echo rc=0; else echo rc=1; fi\n\
             printf 'title=%s\\nprio=%s\\n' \"$PA_TITLE\" \"$PA_PRIO\"\n\
             printf '%s\\n' \"$PA_BODY\" | sed 's/^/body=/'"
        ),
        &all,
    );
    Msg {
        rc: r.get("rc"),
        title: r.get("title"),
        prio: r.get("prio"),
        body: r
            .out
            .lines()
            .filter_map(|l| l.strip_prefix("body="))
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        out: format!("{}{}", r.out, r.err),
    }
}

/// The reader counts every W line stamped after the stamp it is given, names the instances of the
/// new incidents among them in the order they were withheld, ten at most, and counts the rest; a
/// withheld change or reminder is counted and names nothing, and a line from before the stamp is
/// not counted. A stamp out of form, or one ahead of the clock, would make the count say less, so
/// with either every W line is counted.
#[test]
fn the_withheld_reader_counts_the_w_lines_after_a_stamp_and_names_ten_new_incidents_at_most() {
    let fx = Fx::salted(SALT);
    let mut records: Vec<String> = (1..=12)
        .map(|n| nrec(n, &nkey(n), "ACT", &ninst(n)))
        .collect();
    let kh: Vec<String> = (0..=12).map(|n| keyhash(&fx, &nkey(n))).collect();
    records.push(wline("990000/00000000/100", &kh[12], "open", "1"));
    for h in &kh[1..=11] {
        records.push(wline(W_T, h, "open", "1"));
    }
    records.push(wline(W_T, &kh[1], "remind", "0"));
    let r = withheld(&fx, &records, SINCE);
    let ten: Vec<String> = (1..=10).map(ninst).collect();
    assert_eq!(r.get("n"), "12", "{}", r.err);
    assert_eq!(r.get("names"), ten.join(" "));
    assert_eq!(r.get("more"), "1");
    assert_eq!(r.get("page"), "");
    for since in ["-", "garbage", "1000600/abcdef01/5600"] {
        let r = withheld(&fx, &records, since);
        assert_eq!(r.get("n"), "13", "{since}: {}", r.err);
        assert_eq!(r.get("more"), "2", "{since}");
    }
}

/// A W line names an incident only through a whole record its key hash names, of a tier the tables
/// know: a line whose record is gone, not whole or of an unknown tier, a line with a field out of
/// form (its stamp, its key hash, its transition, its new flag), an empty field or a field too
/// few is counted, never named and never taken for a PAGE. One that still says it withheld the
/// open of a new incident (its transition and new flag in their places and in form) is counted
/// among the new incidents not named, so the notice never says fewer were withheld.
#[test]
fn a_w_line_whose_record_is_gone_or_not_whole_or_out_of_form_is_counted_and_never_named() {
    let fx = Fx::salted(SALT);
    let whole = nrec(1, &nkey(1), "PAGE", &ninst(1));
    let broken = nrec(2, &nkey(2), "PAGE", &ninst(2)).replace("\tlisten\t", "\t\tlisten\t");
    let bogus = nrec(3, &nkey(3), "BOGUS", &ninst(3));
    let kh1 = keyhash(&fx, &nkey(1));
    let lines = [
        wline(W_T, &keyhash(&fx, &nkey(9)), "open", "1"),
        wline(W_T, &keyhash(&fx, &nkey(2)), "open", "1"),
        wline(W_T, &keyhash(&fx, &nkey(3)), "open", "1"),
        wline(W_T, "zzzzzzzz", "open", "1"),
        wline("garbage", &kh1, "open", "1"),
        wline(W_T, &kh1, "planted", "1"),
        wline(W_T, &kh1, "open", "2"),
        format!("W\t{W_T}\t{kh1}\t\topen\t1\t-\tpool\n"),
        format!("W\t{W_T}\t{kh1}\topen\t1\n"),
    ];
    let mut records = vec![whole, broken, bogus];
    records.extend(lines.iter().cloned());
    let r = withheld(&fx, &records, SINCE);
    assert_eq!(r.get("n"), "9", "{}", r.err);
    assert_eq!(r.get("names"), "");
    assert_eq!(r.get("more"), "5");
    assert_eq!((r.get("page"), r.get("pagemore")), ("".into(), "0".into()));
    // The same line in form names the PAGE incident.
    records.push(wline(W_T, &kh1, "open", "1"));
    let r = withheld(&fx, &records, SINCE);
    assert_eq!(r.get("names"), ninst(1), "{}", r.err);
    assert_eq!(r.get("page"), ninst(1));
}

/// The storm notice and the summary: the alias, the count of what was withheld since the stamp
/// and its time, the instances of the new incidents with the rest counted, and when the next
/// summary may go (the summary counts itself, so its next is an hour on). Priority 3. Nothing
/// withheld renders no notice.
#[test]
fn the_storm_notice_and_the_summary_render_their_count_their_new_incidents_and_the_next_summary() {
    let fx = Fx::salted(SALT);
    let mut records: Vec<String> = (1..=12)
        .map(|n| nrec(n, &nkey(n), "ACT", &ninst(n)))
        .collect();
    for n in 1..=12 {
        records.push(wline(W_T, &keyhash(&fx, &nkey(n)), "open", "1"));
    }
    records.push(wline(W_T, &keyhash(&fx, &nkey(1)), "remind", "0"));
    let ten: Vec<String> = (1..=10).map(ninst).collect();
    let storm = notice(&fx, &records, "", "full", "storm", SINCE);
    assert_eq!(storm.rc, "0", "{}", storm.out);
    assert_eq!(storm.title, "host-908b: alert budget reached");
    assert_eq!(storm.prio, "3");
    assert_eq!(
        storm.body,
        [
            format!(
                "Withheld: 13 messages since 12:46 UTC; new incidents: {} and 2 more",
                ten.join(" ")
            ),
            "Next summary 13:47 UTC. Do: status".to_string(),
        ]
    );
    let summary = notice(&fx, &records, "", "full", "summary", SINCE);
    assert_eq!(summary.rc, "0", "{}", summary.out);
    assert_eq!(
        summary.title,
        "host-908b: 13 messages withheld in the last hour"
    );
    assert_eq!(summary.prio, "3");
    assert_eq!(summary.body[0], storm.body[0]);
    assert_eq!(summary.body[1], "Next summary 14:47 UTC. Do: status");
    assert_eq!(summary.body.len(), 2);
    // One withheld reminder, no new incident.
    let one = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        wline(W_T, &keyhash(&fx, &nkey(1)), "remind", "0"),
    ];
    let m = notice(&fx, &one, "", "full", "summary", SINCE);
    assert_eq!(m.title, "host-908b: 1 message withheld in the last hour");
    assert_eq!(
        m.body[0],
        "Withheld: 1 message since 12:46 UTC; new incidents: none"
    );
    // A day's summaries spent: the next is when the oldest of them leaves the day.
    let ledger: String = (0..12)
        .map(|i| {
            format!(
                "L\t{}/00000000/0\tsummary\t-\tsummary\tfull\tok\tlight\n",
                920_000 + i * 3600
            )
        })
        .collect();
    let m = notice(&fx, &one, &ledger, "full", "storm", SINCE);
    assert_eq!(m.body[1], "Next summary 15:34 UTC. Do: status", "{}", m.out);
    // Nothing withheld since the stamp: no notice.
    let none = vec![nrec(1, &nkey(1), "ACT", &ninst(1))];
    for tx in ["storm", "summary"] {
        let m = notice(&fx, &none, "", "full", tx, SINCE);
        assert_eq!((m.rc.as_str(), m.title.as_str()), ("1", ""), "{tx}");
    }
}

/// The PAGE rule: a withheld open of a PAGE incident names the first such instance in the title,
/// adds a first body line that lists them, and raises the priority to 5, wherever its W line sits
/// among the others and however many there are; the two lines of the notice follow unchanged.
#[test]
fn a_withheld_open_of_a_page_incident_names_it_at_priority_five_wherever_its_w_line_sits() {
    let fx = Fx::salted(SALT);
    let page_key = "unit:sensor-page.service";
    let page_inst = "ud0ead";
    for others in [0usize, 5, 30] {
        for pos in [0, others / 2, others] {
            let mut records: Vec<String> = (1..=others)
                .map(|n| nrec(n, &nkey(n), "ACT", &ninst(n)))
                .collect();
            records.push(nrec(99, page_key, "PAGE", page_inst));
            let mut ws: Vec<String> = (1..=others)
                .map(|n| wline(W_T, &keyhash(&fx, &nkey(n)), "open", "1"))
                .collect();
            ws.insert(pos, wline(W_T, &keyhash(&fx, page_key), "open", "1"));
            records.extend(ws);
            for tx in ["storm", "summary"] {
                let m = notice(&fx, &records, "", "full", tx, SINCE);
                assert_eq!(m.rc, "0", "{others} {pos} {tx}: {}", m.out);
                assert_eq!(m.title, format!("host-908b: PAGE withheld {page_inst}"));
                assert_eq!(m.prio, "5");
                assert_eq!(m.body[0], format!("PAGE withheld: {page_inst}"));
                assert!(
                    m.body[1].starts_with(&format!("Withheld: {} message", others + 1)),
                    "{:?}",
                    m.body
                );
                assert_eq!(m.body.len(), 3);
            }
        }
    }
    // Eleven PAGE opens: ten named, the rest counted, the title names the first withheld.
    let mut records: Vec<String> = (1..=11)
        .map(|n| nrec(n, &nkey(n), "PAGE", &ninst(n)))
        .collect();
    for n in (1..=11).rev() {
        records.push(wline(W_T, &keyhash(&fx, &nkey(n)), "open", "1"));
    }
    let m = notice(&fx, &records, "", "full", "storm", SINCE);
    let names: Vec<String> = (2..=11).rev().map(ninst).collect();
    assert_eq!(m.title, format!("host-908b: PAGE withheld {}", ninst(11)));
    assert_eq!(
        m.body[0],
        format!("PAGE withheld: {} and 1 more", names.join(" "))
    );
}

/// The PAGE rule follows the record and the transition, never anything else: a withheld change,
/// reminder or resolve of a PAGE incident, a withheld open of an ACT incident, a W line whose key
/// hash names no record and one whose record's tier the tables do not know raise no priority and
/// put no PAGE in the title.
#[test]
fn only_a_withheld_open_of_a_known_page_record_raises_the_priority_of_a_notice() {
    let fx = Fx::salted(SALT);
    let page = nrec(1, &nkey(1), "PAGE", &ninst(1));
    let act = nrec(2, &nkey(2), "ACT", &ninst(2));
    let bogus = nrec(3, &nkey(3), "page", &ninst(3));
    let (kh1, kh2, kh3) = (
        keyhash(&fx, &nkey(1)),
        keyhash(&fx, &nkey(2)),
        keyhash(&fx, &nkey(3)),
    );
    for w in [
        wline(W_T, &kh1, "change", "0"),
        wline(W_T, &kh1, "remind", "0"),
        wline(W_T, &kh1, "resolve", "0"),
        wline(W_T, &kh2, "open", "1"),
        wline(W_T, &keyhash(&fx, &nkey(7)), "open", "1"),
        wline(W_T, &kh3, "open", "1"),
    ] {
        let records = vec![page.clone(), act.clone(), bogus.clone(), w.clone()];
        for tx in ["storm", "summary"] {
            let m = notice(&fx, &records, "", "full", tx, SINCE);
            assert_eq!(m.rc, "0", "{w:?} {tx}: {}", m.out);
            assert_eq!(m.prio, "3", "{w:?} {tx}");
            assert!(!m.title.contains("PAGE"), "{}", m.title);
            assert!(m.body[0].starts_with("Withheld: 1 message"), "{:?}", m.body);
        }
    }
}

/// The switch summary: the open and acknowledged incidents, PAGE first, then ACT, then NOTICE,
/// one line each with the incident id, the tier, the stage word and the instance, ten at most and
/// the rest counted, then `Do: status`; priority 3. A resolved or pending record is not listed.
#[test]
fn the_switch_summary_lists_the_open_incidents_ten_at_most_and_counts_the_rest() {
    let fx = Fx::salted(SALT);
    let mut records: Vec<String> = Vec::new();
    for n in 1..=4 {
        records.push(nrec(n, &nkey(n), "ACT", &ninst(n)));
    }
    for n in 5..=12 {
        records.push(nrec(n, &nkey(n), "PAGE", &ninst(n)));
    }
    records.push(inc_rec(&[
        (1, "w#13"),
        (2, "db:local"),
        (3, "db-unreachable"),
        (4, "ledger"),
        (5, "-"),
        (6, "NOTICE"),
        (7, "acked"),
    ]));
    records.push(inc_rec(&[
        (1, "w#14"),
        (2, "unit:a.service"),
        (7, "resolved"),
    ]));
    records.push(inc_rec(&[
        (1, "w#15"),
        (2, "unit:b.service"),
        (7, "pending"),
    ]));
    let m = notice(&fx, &records, "", "full", "switch", "-");
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(m.title, "host-908b: alerting on; 13 open");
    assert_eq!(m.prio, "3");
    let mut want: Vec<String> = (5..=12)
        .map(|n| format!("w#{n} PAGE listen {}", ninst(n)))
        .collect();
    want.push(format!("w#1 ACT listen {}", ninst(1)));
    want.push(format!("w#2 ACT listen {}", ninst(2)));
    want.push("and 3 more".to_string());
    want.push("Do: status".to_string());
    assert_eq!(m.body, want);
    let small = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        inc_rec(&[
            (1, "w#2"),
            (2, "db:local"),
            (3, "db-unreachable"),
            (4, "ledger"),
            (5, "-"),
        ]),
    ];
    let m = notice(&fx, &small, "", "full", "switch", "-");
    assert_eq!(m.title, "host-908b: alerting on; 2 open");
    assert_eq!(
        m.body,
        [
            "w#2 PAGE ledger -",
            &format!("w#1 ACT listen {}", ninst(1)),
            "Do: status"
        ]
    );
    let m = notice(&fx, &[], "", "full", "switch", "-");
    assert_eq!(m.title, "host-908b: alerting on; 0 open");
    assert_eq!(m.body, ["Do: status"]);
}

/// The pointer message: the alias and the ref, priority 4, nothing else; a ref not of 6 hex, or a
/// mode other than pointer, renders nothing.
#[test]
fn the_pointer_message_carries_the_alias_and_the_ref_and_nothing_else() {
    let fx = Fx::salted(SALT);
    let m = notice(&fx, &[], "", "pointer", "pointer", "0a1b2c");
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(m.title, "host-908b: needs attention");
    assert_eq!(m.prio, "4");
    assert_eq!(m.body, ["Run the status command on host-908b. ref 0a1b2c"]);
    for (mode, id) in [
        ("full", "0a1b2c"),
        ("pointer", "0A1B2C"),
        ("pointer", "0a1b2"),
        ("pointer", "-"),
        ("pointer", "0a1b2c\n"),
    ] {
        let m = notice(&fx, &[], "", mode, "pointer", id);
        assert_eq!(
            (m.rc.as_str(), m.title.as_str()),
            ("1", ""),
            "{mode} {id:?}"
        );
    }
    for tx in ["storm", "summary", "switch"] {
        let m = notice(&fx, &[], "", "pointer", tx, SINCE);
        assert_eq!(m.rc, "1", "{tx} in pointer mode");
    }
}

const PLANT: &str = "plantedword";

/// What a notice may never carry, whatever the state files hold.
const PLANT_BANNED: [&str; 7] = [
    PLANT,
    "plantedhost",
    "propolis",
    "sensor",
    "Edge07",
    "://",
    "t0p1c",
];

/// A fixture whose host name, env files (read by `notice_env`), meta and send ledger hold the
/// planted word in every field, the alias the host name (which is refused, so the fallback alias
/// stands), and the records and W lines a notice reads: an in-form PAGE record and an in-form ACT
/// record whose every other field holds the word, a PAGE and an ACT record otherwise in form
/// whose incident id and instance both hold the word, a record of nothing but the word, and W
/// lines for each with the word in every field they keep beside those a line is matched by.
fn planted_fixture() -> (Fx, Vec<String>) {
    let fx = Fx::salted(SALT);
    write_exec(
        &fx.bin.join("hostname"),
        "#!/usr/bin/env bash\necho plantedhost\n",
    );
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "{TARGET_ENV}PROPOLIS_OPS_NTFY_TOKEN=tk_{PLANT}\nPROPOLIS_OPS_PUSH_DETAIL={PLANT}\n\
             PROPOLIS_OPS_HOST_ALIAS=plantedhost\n"
        ),
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tclock\t{PLANT}\nM\tstorm_last\t{PLANT}\nM\tsummary_last\t{PLANT}\n\
             M\tpointer_last\t{PLANT}\nM\tprofile_last\t{PLANT}\nM\tprofile_switched\t{PLANT}\n\
             M\t{PLANT}\t{PLANT}\n"
        ),
    );
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\nL\t{INC_T}\tsummary\t{PLANT}\t{PLANT}\t{PLANT}\tok\t{PLANT}\t{PLANT}\n\
             L\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\n"
        ),
    );
    let page_key = format!("unit:sensor-{PLANT}.service");
    let act_key = format!("finding:{PLANT}:0123456789ab");
    let mut planted_fields: Vec<(usize, &str)> = (2..=34).map(|i| (i, PLANT)).collect();
    planted_fields.retain(|(i, _)| ![2, 4, 6, 7].contains(i));
    let mut page: Vec<(usize, &str)> = planted_fields.clone();
    page.extend([
        (1, "w#1"),
        (2, page_key.as_str()),
        (4, "listen"),
        (6, "PAGE"),
        (7, "open"),
    ]);
    let mut act: Vec<(usize, &str)> = planted_fields.clone();
    act.extend([
        (1, "w#2"),
        (2, act_key.as_str()),
        (4, "gateway"),
        (5, "u1a2b3"),
        (6, "ACT"),
        (7, "open"),
    ]);
    let all: Vec<(usize, &str)> = (1..=34).map(|i| (i, PLANT)).collect();
    let extra = format!("\t{PLANT}\n");
    let (page_id_key, act_id_key) = (nkey(81), nkey(82));
    let records = vec![
        inc_rec(&page).replace('\n', &extra),
        inc_rec(&act).replace('\n', &extra),
        inc_rec(&all),
        planted_id_rec(&page_id_key, "PAGE"),
        planted_id_rec(&act_id_key, "ACT"),
        wline(W_T, &keyhash(&fx, &page_id_key), "open", "1"),
        wline(W_T, &keyhash(&fx, &act_id_key), "open", "1"),
        format!(
            "W\t{W_T}\t{}\topen\t1\t{PLANT}\t{PLANT}\t{PLANT}\n",
            keyhash(&fx, &page_key)
        ),
        format!(
            "W\t{W_T}\t{}\topen\t1\t{PLANT}\t{PLANT}\n",
            keyhash(&fx, &act_key)
        ),
        format!(
            "W\t{W_T}\t{}\topen\t1\t{PLANT}\t{PLANT}\n",
            keyhash(&fx, PLANT)
        ),
        format!("W\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\t{PLANT}\n"),
        format!("{PLANT}\t{PLANT}\n"),
    ];
    (fx, records)
}

/// A whole, open record on KEY at TIER whose incident id and instance both hold the planted word,
/// every other field in form.
fn planted_id_rec(key: &str, tier: &str) -> String {
    inc_rec(&[(1, PLANT), (2, key), (5, PLANT), (6, tier)])
}

fn assert_nothing_planted(m: &Msg, what: &str) {
    let text = format!("{}\n{}", m.title, m.body.join("\n"));
    for word in PLANT_BANNED {
        assert!(!text.contains(word), "{what}: {word} in:\n{text}");
    }
}

/// A planted word in every field of every record, W line, meta value and ledger line the storm
/// notice reads, in the env files, the alias and the host name reaches neither its title nor its
/// body: the record whose instance is out of form is named by its incident id, one whose id and
/// instance are both out of form is counted and not named, the tier is the record's, the times
/// and counts are digits.
#[test]
fn a_planted_word_in_any_field_never_reaches_the_storm_notice() {
    let (fx, records) = planted_fixture();
    for since in [SINCE, PLANT] {
        let m = notice_env(&fx, &records, "full", "storm", since);
        assert_eq!(m.rc, "0", "{}", m.out);
        assert_eq!(m.title, "host-908b: PAGE withheld w#1");
        assert_eq!(m.prio, "5");
        assert_eq!(m.body[0], "PAGE withheld: w#1");
        assert!(
            m.body[1].starts_with("Withheld: 6 messages since "),
            "{:?}",
            m.body
        );
        assert!(
            m.body[1].ends_with("new incidents: w#1 u1a2b3 and 3 more"),
            "{:?}",
            m.body
        );
        assert_nothing_planted(&m, "storm");
    }
}

/// The same planted words never reach the hourly summary.
#[test]
fn a_planted_word_in_any_field_never_reaches_the_summary() {
    let (fx, records) = planted_fixture();
    for since in [SINCE, PLANT] {
        let m = notice_env(&fx, &records, "full", "summary", since);
        assert_eq!(m.rc, "0", "{}", m.out);
        assert_eq!(m.title, "host-908b: PAGE withheld w#1");
        assert_eq!(m.body[0], "PAGE withheld: w#1");
        assert!(m.body[2].starts_with("Next summary "), "{:?}", m.body);
        assert_nothing_planted(&m, "summary");
    }
}

/// A PAGE record whose incident id and instance both hold the planted word names nothing and
/// raises no priority, in the storm notice and the summary alike.
#[test]
fn a_page_record_whose_id_and_instance_are_planted_raises_no_priority_and_names_nothing() {
    let fx = Fx::salted(SALT);
    let key = nkey(81);
    let records = vec![
        planted_id_rec(&key, "PAGE"),
        wline(W_T, &keyhash(&fx, &key), "open", "1"),
    ];
    for tx in ["storm", "summary"] {
        let m = notice_env(&fx, &records, "full", tx, SINCE);
        assert_eq!(m.rc, "0", "{tx}: {}", m.out);
        assert_eq!(m.prio, "3", "{tx}");
        assert!(!m.title.contains("PAGE"), "{tx}: {}", m.title);
        assert!(
            m.body[0].ends_with("new incidents: 1 not named"),
            "{tx}: {:?}",
            m.body
        );
        assert_nothing_planted(&m, tx);
    }
}

/// The same planted words never reach the switch summary: the ACT record is listed by its id,
/// tier, stage word and instance; the PAGE record, whose instance holds the word, and the two
/// whose id and instance hold it are counted and not listed; the record of nothing but the word
/// is not counted open.
#[test]
fn a_planted_word_in_any_field_never_reaches_the_switch_summary() {
    let (fx, records) = planted_fixture();
    let m = notice_env(&fx, &records, "full", "switch", "-");
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(m.title, "host-908b: alerting on; 4 open");
    assert_eq!(
        m.body,
        ["w#2 ACT gateway u1a2b3", "and 3 more", "Do: status"]
    );
    assert_nothing_planted(&m, "switch");
}

/// The same planted words never reach the pointer message, which reads none of them.
#[test]
fn a_planted_word_in_any_field_never_reaches_the_pointer_message() {
    let (fx, records) = planted_fixture();
    let m = notice_env(&fx, &records, "pointer", "pointer", "0a1b2c");
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(m.title, "host-908b: needs attention");
    assert_eq!(m.body, ["Run the status command on host-908b. ref 0a1b2c"]);
    assert_nothing_planted(&m, "pointer");
}

/// Values out of form, each carrying the marker `zqx`: a tab, a control byte, a newline, 300
/// bytes, a leading dash, an escape sequence.
fn bad_values() -> Vec<String> {
    vec![
        "zqx\tzqx".into(),
        "zqx\x01".into(),
        "zqx\nzqx".into(),
        "zqx".repeat(100),
        "-zqx".into(),
        "\x1b[31mzqx".into(),
    ]
}

/// The notice rendered with one field out of form either is refused or names nothing from it: the
/// marker is in neither its title nor its body, and every line is printable ASCII of 200 bytes at
/// most.
fn assert_refused_or_clean(m: &Msg, what: &str) {
    let text = format!("{}\n{}", m.title, m.body.join("\n"));
    assert!(!text.contains("zqx"), "{what}: {text:?}");
    for line in text.lines() {
        assert!(
            line.len() <= 200 && line.bytes().all(|b| (0x20..0x7f).contains(&b)),
            "{what}: {line:?}"
        );
    }
    if m.rc != "0" {
        assert_eq!((m.title.as_str(), m.body.len()), ("", 0), "{what}");
    }
}

/// For a storm notice or a summary: each field of the in-form PAGE record and of its W line in
/// turn given each value out of form, and the stamp the notice lists since.
fn withheld_out_of_form(tx: &str) {
    let fx = Fx::salted(SALT);
    let key = nkey(1);
    for bad in bad_values() {
        let kh = keyhash(&fx, &key);
        let mut cases: Vec<(String, Vec<String>, String)> = Vec::new();
        for field in [1usize, 2, 5, 6, 7] {
            let id = if field == 1 {
                bad.clone()
            } else {
                "w#1".into()
            };
            let k = if field == 2 { bad.clone() } else { key.clone() };
            let inst = if field == 5 { bad.clone() } else { ninst(1) };
            let tier = if field == 6 {
                bad.clone()
            } else {
                "PAGE".into()
            };
            let state = if field == 7 {
                bad.clone()
            } else {
                "open".into()
            };
            let rec = inc_rec(&[(1, &id), (2, &k), (5, &inst), (6, &tier), (7, &state)]);
            let kh = if field == 2 {
                keyhash(&fx, &bad)
            } else {
                kh.clone()
            };
            cases.push((
                format!("record field {field}"),
                vec![rec, wline(W_T, &kh, "open", "1")],
                SINCE.into(),
            ));
        }
        let rec = nrec(1, &key, "PAGE", &ninst(1));
        for field in 1usize..=6 {
            let mut w = [
                W_T.to_string(),
                kh.clone(),
                "open".into(),
                "1".into(),
                ninst(9),
                "pool".into(),
            ];
            w[field - 1] = bad.clone();
            cases.push((
                format!("W field {field}"),
                vec![rec.clone(), format!("W\t{}\n", w.join("\t"))],
                SINCE.into(),
            ));
        }
        cases.push((
            "since".into(),
            vec![rec.clone(), wline(W_T, &kh, "open", "1")],
            bad.clone(),
        ));
        for (what, records, since) in cases {
            let m = notice(&fx, &records, "", "full", tx, &since);
            assert_refused_or_clean(&m, &format!("{tx} {what} {bad:?}"));
        }
    }
    // A value that holds an id's form inside a longer string, in the incident id, the instance
    // or both: never named, and never taken for a PAGE when the record cannot be named at all.
    let kh = keyhash(&fx, &key);
    for near in near_miss_values() {
        for fields in [&[1usize][..], &[5], &[1, 5]] {
            let id = if fields.contains(&1) { near } else { "w#1" };
            let inst = if fields.contains(&5) {
                near.to_string()
            } else {
                ninst(1)
            };
            let rec = inc_rec(&[(1, id), (2, &key), (5, &inst), (6, "PAGE")]);
            let m = notice(
                &fx,
                &[rec, wline(W_T, &kh, "open", "1")],
                "",
                "full",
                tx,
                SINCE,
            );
            let text = format!("{}\n{}", m.title, m.body.join("\n"));
            assert_eq!(m.rc, "0", "{tx} {fields:?} {near:?}: {}", m.out);
            assert!(!text.contains(near), "{tx} {fields:?} {near:?}: {text}");
            if fields.contains(&1) {
                assert_eq!(m.prio, "3", "{tx} {fields:?} {near:?}: {text}");
            } else {
                assert_eq!(m.title, "host-908b: PAGE withheld w#1", "{near:?}");
            }
        }
    }
}

/// Values that hold an instance id's or an incident id's form inside a longer string.
fn near_miss_values() -> [&'static str; 6] {
    [
        "u1a2b3x",
        "xu1a2b3",
        "u1a2b3-zqx",
        "w#1x",
        "zqxw#12",
        "w#12 zqx",
    ]
}

#[test]
fn a_value_out_of_form_in_any_field_the_storm_notice_reads_is_refused_or_counted_and_not_named() {
    withheld_out_of_form("storm");
}

#[test]
fn a_value_out_of_form_in_any_field_the_summary_reads_is_refused_or_counted_and_not_named() {
    withheld_out_of_form("summary");
}

/// For the switch summary: each field it lists (the id, the tier, the stage word, the instance)
/// and the state, in turn given each value out of form: the record is counted or not, never
/// listed with the value.
#[test]
fn a_value_out_of_form_in_any_field_the_switch_summary_reads_is_counted_and_not_named() {
    let fx = Fx::salted(SALT);
    for bad in bad_values() {
        for field in [1usize, 4, 5, 6, 7] {
            let mut set: Vec<(usize, String)> = vec![
                (1, "w#1".into()),
                (2, nkey(1)),
                (4, "listen".into()),
                (5, ninst(1)),
                (6, "ACT".into()),
                (7, "open".into()),
            ];
            for s in set.iter_mut() {
                if s.0 == field {
                    s.1 = bad.clone();
                }
            }
            let set: Vec<(usize, &str)> = set.iter().map(|(i, v)| (*i, v.as_str())).collect();
            let m = notice(&fx, &[inc_rec(&set)], "", "full", "switch", "-");
            assert_refused_or_clean(&m, &format!("switch field {field} {bad:?}"));
            assert!(
                !m.body.iter().any(|l| l.starts_with("w#1")),
                "{field} {bad:?}: {:?}",
                m.body
            );
        }
    }
    // A value that holds an id's form inside a longer string, in the incident id, the instance
    // or both: the record is counted and never listed.
    for near in near_miss_values() {
        for fields in [&[1usize][..], &[5], &[1, 5]] {
            let id = if fields.contains(&1) { near } else { "w#1" };
            let inst = if fields.contains(&5) {
                near.to_string()
            } else {
                ninst(1)
            };
            let rec = inc_rec(&[(1, id), (2, &nkey(1)), (5, &inst), (6, "ACT")]);
            let m = notice(&fx, &[rec], "", "full", "switch", "-");
            assert_eq!(m.rc, "0", "{fields:?} {near:?}: {}", m.out);
            assert_eq!(m.body, ["and 1 more", "Do: status"], "{fields:?} {near:?}");
        }
    }
}

/// For the pointer message: a ref out of form is refused, and an alias out of form gives way to
/// the fallback alias.
#[test]
fn a_value_out_of_form_given_to_the_pointer_message_is_refused_or_replaced() {
    let fx = Fx::salted(SALT);
    for bad in bad_values() {
        let m = notice(&fx, &[], "", "pointer", "pointer", &bad);
        assert_refused_or_clean(&m, &format!("ref {bad:?}"));
        assert_eq!(m.rc, "1");
        // A newline makes the line before it a value in form, which is the alias written.
        if bad.contains('\n') {
            continue;
        }
        fx.write(
            "etc/propolis/propolis.env",
            &format!("PROPOLIS_OPS_HOST_ALIAS={bad}\n"),
        );
        let mut env = NOW.to_vec();
        env.push(("TX", "pointer"));
        let r = fx.run_env(
            "pa_settings_load\npa_render pointer pointer 0a1b2c\n\
             printf 'title=%s\\nbody=%s\\n' \"$PA_TITLE\" \"$PA_BODY\"",
            &env,
        );
        assert_eq!(r.get("title"), "host-908b: needs attention", "{bad:?}");
        assert_eq!(
            r.get("body"),
            "Run the status command on host-908b. ref 0a1b2c"
        );
    }
    fx.write("etc/propolis/propolis.env", "");
}

/// Every new shape fits the sender's rules at its largest: the longest alias, ten ids of nine
/// characters and counts of five digits keep every line within the 200 bytes of the line rule
/// with room for more digits, and the body under the 1024 bytes the sender cuts at.
#[test]
fn every_notice_fits_the_line_rule_and_the_senders_cut_at_its_largest() {
    let fx = Fx::salted(SALT);
    let alias = format!("a{}", "z".repeat(31));
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_HOST_ALIAS={alias}\n"),
    );
    let mut records = Vec::new();
    let inst = |n: usize| format!("u{:08x}", 0xabc0_0000usize + n);
    for n in 0..30 {
        let id = format!("w#{}", 999_999_900 + n);
        let key = nkey(n);
        let i = inst(n);
        records.push(inc_rec(&[
            (1, &id),
            (2, &key),
            (4, "publish"),
            (5, &i),
            (6, "PAGE"),
        ]));
    }
    for n in 0..30 {
        records.push(wline(W_T, &keyhash(&fx, &nkey(n)), "open", "1"));
    }
    let filler = wline(W_T, "0badc0de", "remind", "0");
    for _ in 0..9970 {
        records.push(filler.clone());
    }
    let check = |m: &Msg, what: &str| {
        assert_eq!(m.rc, "0", "{what}: {}", m.out);
        assert!(m.title.len() <= 180, "{what}: {}", m.title);
        for l in &m.body {
            assert!(l.len() <= 180, "{what}: {} bytes: {l}", l.len());
        }
        assert!(m.body.join("\n").len() < 1024, "{what}");
    };
    for tx in ["storm", "summary"] {
        let m = notice_env(&fx, &records, "full", tx, SINCE);
        check(&m, tx);
        assert!(
            m.body[1].starts_with("Withheld: 10000 messages"),
            "{:?}",
            m.body
        );
        assert!(m.body[0].ends_with(" and 20 more"), "{:?}", m.body);
        assert!(m.body[1].ends_with(" and 20 more"), "{:?}", m.body);
        assert_eq!(
            m.body[0].split(' ').filter(|w| w.starts_with('u')).count(),
            10
        );
    }
    let m = notice_env(&fx, &records, "full", "switch", "-");
    check(&m, "switch");
    assert_eq!(m.title, format!("{alias}: alerting on; 30 open"));
    assert_eq!(m.body.len(), 12);
    assert_eq!(m.body[10], "and 20 more");
    let m = notice_env(&fx, &records, "pointer", "pointer", "0a1b2c");
    check(&m, "pointer");
    assert_eq!(m.title, format!("{alias}: needs attention"));
}

/// `notice` with the settings loaded first, so the alias the env file sets is the one used.
fn notice_env(fx: &Fx, records: &[String], mode: &str, tx: &str, id: &str) -> Msg {
    notice_with(fx, records, "", "pa_settings_load\n", mode, tx, id)
}

const EMPTY_LEDGER: &str = "#send-ledger v1 g=1\n";

/// The send ledger's lines after its header.
fn ledger_body(fx: &Fx) -> Vec<String> {
    let text =
        std::fs::read_to_string(fx.p("var/lib/propolis/witness/send-ledger")).unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with("L\t"))
        .map(str::to_string)
        .collect()
}

/// A summary that names a withheld open or reopen of a PAGE incident is held back only by the
/// hour: the day's twelve summaries, which a storm that lasts or a server that fails can spend,
/// must not leave a dead listener unnamed until the next storm notice, up to six hours on. One
/// that names none keeps the day's cap, the hour's cap holds either way, and the word changes
/// nothing for any other class.
#[test]
fn a_summary_that_names_a_withheld_page_is_held_only_by_the_hour() {
    let fx = Fx::salted(SALT);
    let line = |class: &str, mode: &str, ago: u64| {
        format!(
            "L\t{}\t{class}\t-\t{class}\t{mode}\tok\tlight\n",
            lib_at(ago)
        )
    };
    let admit = |ledger: &str, args: &str| {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{ledger}"),
        );
        fx.run_env(
            &format!("pa_lock 5\npa_notice_admit {args} > /dev/null\necho \"v=$PA_ADMIT_VERDICT\""),
            &NOW,
        )
        .get("v")
    };
    // Twelve summaries in the last day, the newest 61 minutes old.
    let spent: String = (0..12)
        .map(|i| line("summary", "full", 3660 + i * 6000))
        .collect();
    assert_eq!(admit(&spent, "summary light"), "withhold:summary-cap");
    assert_eq!(admit(&spent, "summary light page"), "admit");
    assert_eq!(
        admit(&spent, "summary light planted"),
        "withhold:summary-cap"
    );
    // Inside the hour the cap holds, PAGE or not.
    let recent = format!("{spent}{}", line("summary", "full", 3540));
    assert_eq!(admit(&recent, "summary light page"), "withhold:summary-cap");
    // No other class takes the word.
    assert_eq!(
        admit(&line("storm", "full", 600), "storm light page"),
        "withhold:storm-cap"
    );
    // 48 pointer messages in the last day and none inside the hour: the day's cap alone holds
    // the next one, and the word must not lift it.
    let pointers: String = (0..48)
        .map(|i| line("pointer", "pointer", 3660 + i * 1500))
        .collect();
    assert_eq!(admit(&pointers, "pointer light"), "withhold:pointer-cap");
    assert_eq!(
        admit(&pointers, "pointer light page"),
        "withhold:pointer-cap"
    );
    // One switch summary two hours ago, the time of the switch not known: one a day.
    assert_eq!(
        admit(&line("switch", "full", 7200), "switch light page"),
        "withhold:switch-cap"
    );
}

/// Each exempt class is admitted by its own cap alone, with one ledger line written under the lock
/// before the post, claimed (`sending`) as the daily message's is, in mode full for the notices
/// and pointer for the pointer message, and its result written after the post. A second message
/// inside the class's window is withheld by its cap; a line that cannot be written sends nothing;
/// an unknown class or sender is refused before anything is read.
#[test]
fn a_notice_is_claimed_in_the_ledger_before_its_post_and_its_result_written_after() {
    let fx = Fx::salted(SALT);
    for (class, mode, second) in [
        ("storm", "full", "withhold:storm-cap"),
        ("summary", "full", "withhold:summary-cap"),
        ("switch", "full", "withhold:switch-cap"),
        ("pointer", "pointer", "admit"),
    ] {
        fx.write("var/lib/propolis/witness/send-ledger", EMPTY_LEDGER);
        let r = fx.run_env(
            &format!(
                "pa_lock 5\npa_notice_admit {class} light > \"$D/v\"\n\
                 echo \"v=$(cat \"$D/v\") $PA_ADMIT_VERDICT\"\necho \"stamp=$PA_NOTICE_STAMP\"\npa_unlock\n\
                 rc=0; pa_notice_result \"$PA_NOTICE_STAMP\" {class} ok light || rc=$?\necho \"rc=$rc\""
            ),
            &NOW,
        );
        assert_eq!(r.get("v"), "admit admit", "{class}: {}", r.err);
        assert_eq!(r.get("stamp"), "1000000/abcdef01/5000");
        assert_eq!(r.get("rc"), "0");
        assert_eq!(
            ledger_body(&fx),
            [format!(
                "L\t1000000/abcdef01/5000\t{class}\t-\t{class}\t{mode}\tok\tlight"
            )],
            "{class}"
        );
        // A second one now: the class's own cap, after the first was admitted and counted.
        let r = fx.run_env(
            &format!("pa_lock 5\npa_notice_admit {class} hourly > /dev/null\necho \"v=$PA_ADMIT_VERDICT\"\necho \"stamp=$PA_NOTICE_STAMP\""),
            &NOW,
        );
        assert_eq!(r.get("v"), second, "{class}");
        if second != "admit" {
            assert_eq!(r.get("stamp"), "", "{class}");
            assert_eq!(ledger_body(&fx).len(), 1, "{class}");
        }
        // A line that cannot be written: nothing admitted, nothing to post.
        fx.write("var/lib/propolis/witness/send-ledger", EMPTY_LEDGER);
        let r = fx.run_env(
            &format!(
                "pa_lock 5\n_pa_ledger_put() {{ return 1; }}\nrc=0; pa_notice_admit {class} light > /dev/null || rc=$?\n\
                 echo \"v=$PA_ADMIT_VERDICT rc=$rc\"\necho \"stamp=$PA_NOTICE_STAMP\""
            ),
            &NOW,
        );
        assert_eq!(r.get("v"), "withhold:ledger rc=1", "{class}");
        assert_eq!(r.get("stamp"), "");
    }
    for (args, want) in [
        ("daily light", "withhold:class"),
        ("pool light", "withhold:class"),
        ("storm planted", "withhold:unknown"),
        ("storm", "withhold:unknown"),
    ] {
        let r = fx.run_env(
            &format!("pa_lock 5\npa_notice_admit {args} > /dev/null\necho \"v=$PA_ADMIT_VERDICT\""),
            &NOW,
        );
        assert_eq!(r.get("v"), want, "{args}");
    }
    // A result for a class that is not one of the four, or one whose line is gone, writes nothing.
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\nL\t1000000/abcdef01/5000\tdaily\t-\tdaily\tfull\tsending\tlight\n",
    );
    let r = fx.run_env(
        "rc=0; pa_notice_result 1000000/abcdef01/5000 daily ok light || rc=$?; echo \"a=$rc\"\n\
         rc=0; pa_notice_result 1000000/abcdef01/5000 storm ok light || rc=$?; echo \"b=$rc\"",
        &NOW,
    );
    assert_eq!((r.get("a"), r.get("b")), ("2".into(), "1".into()));
    assert!(ledger_body(&fx)[0].ends_with("\tsending\tlight"));
}

/// The exempt classes and the incident classes never count against each other: with the pool, the
/// listener caps and a key spent, every notice and the pointer are admitted; with every exempt
/// class spent, an incident message is admitted. A claimed or pending line of an exempt class
/// counts within each window of its own cap, whatever its result, as a sent one does.
#[test]
fn the_exempt_classes_and_the_incident_classes_never_count_against_each_other() {
    let fx = Fx::salted(SALT);
    let rec = nrec(1, &nkey(1), "PAGE", &ninst(1));
    let kh = keyhash(&fx, &nkey(1));
    let mut spent: Vec<String> = Vec::new();
    spent.extend(lines_of(16, "pool", "00000000", 600));
    spent.extend(lines_of(16, "stage1", &kh, 600));
    spent.extend(lines_of(4, "reserve", "00000000", 600));
    spent.extend(lines_of(4, "late", &kh, 600));
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&rec),
            &spent,
            &nkey(1),
            "reopen",
            "0"
        ),
        "withhold:key-cap"
    );
    for class in ["storm", "summary", "switch", "pointer"] {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{}", spent.concat()),
        );
        let r = fx.run_env(
            &format!(
                "pa_lock 5\npa_notice_admit {class} light > /dev/null\necho \"v=$PA_ADMIT_VERDICT\""
            ),
            &NOW,
        );
        assert_eq!(r.get("v"), "admit", "{class}");
    }
    let mut exempt: Vec<String> = Vec::new();
    for class in ["storm", "summary", "switch", "pointer"] {
        exempt.extend(lines_of(48, class, "-", 600));
    }
    assert_eq!(
        admit_over(
            &fx,
            std::slice::from_ref(&rec),
            &exempt,
            &nkey(1),
            "open",
            "1"
        ),
        "admit stage1"
    );
    // A claimed or pending line counts as a sent one, for as long as its window holds it.
    for (class, result, ago, want) in [
        ("storm", "pending", 21_000, "withhold:storm-cap"),
        ("storm", "sending", 21_000, "withhold:storm-cap"),
        ("storm", "pending", 21_700, "admit"),
        ("summary", "pending", 3_000, "withhold:summary-cap"),
        ("summary", "sending", 3_700, "admit"),
        ("switch", "sending", 80_000, "withhold:switch-cap"),
        ("switch", "pending", 86_500, "admit"),
        ("pointer", "norender", 60, "admit"),
    ] {
        let line = ledger_line(class, "-", ago, result);
        let doubled = if class == "pointer" {
            format!("{line}{line}")
        } else {
            line
        };
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{doubled}"),
        );
        let r = fx.run_env(
            &format!(
                "pa_lock 5\npa_notice_admit {class} light > /dev/null\necho \"v=$PA_ADMIT_VERDICT\""
            ),
            &NOW,
        );
        assert_eq!(r.get("v"), want, "{class} {result} {ago}");
    }
}

/// Each meta key of the notices is read only in its form: storm_last, summary_last and
/// profile_switched a stamp not ahead of the clock, pointer_last such a stamp and a ref of 6 hex,
/// profile_last legacy or v2; anything else reads as nothing. A value out of form is never
/// written, a key outside the five is refused, and pointer_last is never written by pa_meta_put:
/// it stands for a pointer that arrived, which only a pointer's result may record.
#[test]
fn each_meta_key_of_the_notices_is_read_and_written_only_in_its_form() {
    let fx = Fx::salted(SALT);
    let past = lib_at(600);
    let ahead = "1000300/abcdef01/5300";
    for (key, value, read) in [
        ("storm_last", past.clone(), true),
        ("storm_last", ahead.to_string(), false),
        ("storm_last", "plantedword".into(), false),
        ("summary_last", past.clone(), true),
        ("summary_last", format!("{past}/0a1b2c"), false),
        ("profile_switched", past.clone(), true),
        ("profile_switched", "".into(), false),
        ("pointer_last", format!("{past}/0a1b2c"), true),
        ("pointer_last", past.clone(), false),
        ("pointer_last", format!("{ahead}/0a1b2c"), false),
        ("pointer_last", format!("{past}/0a1b2"), false),
        ("profile_last", "legacy".into(), true),
        ("profile_last", "v2".into(), true),
        ("profile_last", "V2".into(), false),
        ("profile_last", "v2 ".into(), false),
    ] {
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=1\nM\t{key}\t{value}\n"),
        );
        let mut env = NOW.to_vec();
        env.push(("K", key));
        env.push(("V", &value));
        let r = fx.run_env(
            "rc=0; v=\"$(pa_meta_value \"$K\")\" || rc=$?; echo \"v=$v\"; echo \"rc=$rc\"\n\
             pa_lock 5; rm -f \"$PA_STATE/meta\"; rc=0; pa_meta_put \"$K\" \"$V\" || rc=$?; echo \"put=$rc\"\n\
             echo \"stored=$(cat \"$PA_STATE/meta\" 2> /dev/null | grep -c '^M')\"",
            &env,
        );
        if read {
            assert_eq!(
                (r.get("v"), r.get("rc")),
                (value.clone(), "0".into()),
                "{key} {value:?}"
            );
            // pointer_last is for the step that records a pointer's result, not pa_meta_put.
            let put = if key == "pointer_last" {
                ("2".to_string(), "0".to_string())
            } else {
                ("0".to_string(), "1".to_string())
            };
            assert_eq!((r.get("put"), r.get("stored")), put, "{key} {value:?}");
        } else {
            assert_eq!(
                (r.get("v"), r.get("rc")),
                ("".into(), "1".into()),
                "{key} {value:?}"
            );
        }
        if !read && value != ahead && !value.starts_with(ahead) {
            assert_eq!(
                (r.get("put"), r.get("stored")),
                ("2".into(), "0".into()),
                "{key} {value:?}"
            );
        }
    }
    let r = fx.run_env(
        "rc=0; pa_meta_value clock || rc=$?; echo \"a=$rc\"; rc=0; pa_meta_put clock x || rc=$?; echo \"b=$rc\"",
        &NOW,
    );
    assert_eq!((r.get("a"), r.get("b")), ("2".into(), "2".into()));
}

// ---- what a W line says ------------------------------------------------------------------------

/// `nrec`, with its last open (field 9) at OPENED.
fn nrec_opened(n: usize, key: &str, tier: &str, inst: &str, opened: &str) -> String {
    let id = format!("w#{n}");
    inc_rec(&[(1, &id), (2, key), (5, inst), (6, tier), (9, opened)])
}

/// A W line at stamp AT for KEYHASH with the instance and the reason it keeps.
fn wline_full(at: &str, kh: &str, tx: &str, new: &str, inst: &str, reason: &str) -> String {
    format!("W\t{at}\t{kh}\t{tx}\t{new}\t{inst}\t{reason}\n")
}

/// A W line stamped exactly at the stamp a notice lists since is counted: a line written in the
/// same second as the notice before it may come after it, and counting it twice errs toward
/// more. For the withheld open of a PAGE incident the notice names it at priority 5.
#[test]
fn a_w_line_stamped_exactly_at_the_stamp_a_notice_lists_since_is_counted_and_keeps_the_page_rule() {
    let fx = Fx::salted(SALT);
    let records = vec![
        nrec_opened(1, &nkey(1), "PAGE", &ninst(1), "996000/abcdef01/1000"),
        wline(SINCE, &keyhash(&fx, &nkey(1)), "open", "1"),
    ];
    let r = withheld(&fx, &records, SINCE);
    assert_eq!(
        (r.get("n"), r.get("page")),
        ("1".to_string(), ninst(1)),
        "{}",
        r.err
    );
    for tx in ["storm", "summary"] {
        let m = notice(&fx, &records, "", "full", tx, SINCE);
        assert_eq!(m.prio, "5", "{tx}: {}", m.out);
        assert_eq!(m.title, format!("host-908b: PAGE withheld {}", ninst(1)));
    }
}

/// pa_w_line stamps the line when it is written, not when the caller's pass began, and leaves the
/// caller's own stamp as it was, so a line written after a notice always counts after it.
#[test]
fn pa_w_line_stamps_the_line_with_the_time_it_is_written_and_restores_the_callers_stamp() {
    let fx = Fx::salted(SALT);
    let key = nkey(1);
    let r = withheld_script(
        &fx,
        &[],
        "PA_WALL=999400 PA_BOOT=abcdef01 PA_UP=4400 PA_STAMP=999400/abcdef01/4400\n\
         rc=0; pa_w_line \"$K\" reopen 0 u0a0001 stage1-cap || rc=$?\necho \"rc=$rc\"\n\
         echo \"now=$PA_STAMP $PA_WALL $PA_BOOT $PA_UP\"\n\
         for l in \"${_PA_INC_REST[@]}\"; do [[ $l != W$'\\t'* ]] || echo \"w=$l\"; done",
        &[("K", key.as_str())],
    );
    assert_eq!(r.get("rc"), "0", "{}", r.err);
    assert_eq!(r.get("now"), "999400/abcdef01/4400 999400 abcdef01 4400");
    assert_eq!(
        r.get("w"),
        format!(
            "W\t1000000/abcdef01/5000\t{}\treopen\t0\tu0a0001\tstage1-cap",
            keyhash(&fx, &key)
        )
    );
}

/// Runs SCRIPT after the records RECORDS are loaded, with ENV beside the test clock.
fn withheld_script(fx: &Fx, records: &[String], script: &str, env: &[(&str, &str)]) -> Run {
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t40\n{}", records.concat()),
    );
    let mut all = NOW.to_vec();
    all.extend(env.iter().copied());
    fx.run_env(&format!("pa_incident_load\n{script}"), &all)
}

/// A pass that began before a summary was claimed and withholds a message after it: its W line,
/// written by pa_w_line, is counted by the next summary, which lists since the claim.
#[test]
fn a_w_line_written_after_a_summary_was_claimed_is_counted_by_the_next_summary() {
    let fx = Fx::salted(SALT);
    fx.write("var/lib/propolis/witness/send-ledger", EMPTY_LEDGER);
    let key = nkey(1);
    let r = withheld_script(
        &fx,
        &[nrec(1, &key, "PAGE", &ninst(1))],
        "pa_lock 5\npa_notice_admit summary hourly > /dev/null\nS=\"$PA_NOTICE_STAMP\"\n\
         PA_WALL=999400 PA_BOOT=abcdef01 PA_UP=4400 PA_STAMP=999400/abcdef01/4400\n\
         PA_TEST_WALL=1000060 PA_TEST_UP=5060\n\
         pa_w_line \"$K\" open 1 \"$I\" pool\npa_now\npa_withheld_since \"$S\"\n\
         echo \"s=$S\"\necho \"n=$PA_WH_N\"\necho \"page=$PA_WH_PAGE\"",
        &[("K", key.as_str()), ("I", ninst(1).as_str())],
    );
    assert_eq!(r.get("s"), "1000000/abcdef01/5000", "{}", r.err);
    assert_eq!((r.get("n"), r.get("page")), ("1".to_string(), ninst(1)));
}

/// A withheld reopen of a PAGE incident keeps the PAGE rule: a dead listener whose reopen the
/// stage-1 cap holds back is named in the title and the first line at priority 5, and is not a
/// new incident. A withheld reopen of an ACT incident stays at priority 3.
#[test]
fn a_withheld_reopen_of_a_page_incident_names_it_at_priority_five_and_is_no_new_incident() {
    let fx = Fx::salted(SALT);
    let inst = ninst(1);
    let page = vec![
        nrec(1, &nkey(1), "PAGE", &inst),
        wline_full(
            W_T,
            &keyhash(&fx, &nkey(1)),
            "reopen",
            "0",
            &inst,
            "stage1-cap",
        ),
    ];
    for tx in ["storm", "summary"] {
        let m = notice(&fx, &page, "", "full", tx, SINCE);
        assert_eq!(m.rc, "0", "{tx}: {}", m.out);
        assert_eq!(m.title, format!("host-908b: PAGE withheld {inst}"), "{tx}");
        assert_eq!(m.prio, "5", "{tx}");
        assert_eq!(m.body[0], format!("PAGE withheld: {inst}"), "{tx}");
        assert!(
            m.body[1].ends_with("new incidents: none"),
            "{tx}: {:?}",
            m.body
        );
    }
    let act = vec![
        nrec(2, &nkey(2), "ACT", &ninst(2)),
        wline_full(
            W_T,
            &keyhash(&fx, &nkey(2)),
            "reopen",
            "0",
            &ninst(2),
            "key-cap",
        ),
    ];
    for tx in ["storm", "summary"] {
        let m = notice(&fx, &act, "", "full", tx, SINCE);
        assert_eq!(m.prio, "3", "{tx}: {}", m.out);
        assert!(!m.title.contains("PAGE"), "{tx}: {}", m.title);
    }
    // A reopen line that says it is new (a line no writer makes) is still no new incident.
    let odd = vec![
        nrec(1, &nkey(1), "PAGE", &inst),
        nrec(2, &nkey(2), "ACT", &ninst(2)),
        wline_full(
            W_T,
            &keyhash(&fx, &nkey(1)),
            "reopen",
            "1",
            &inst,
            "stage1-cap",
        ),
        wline_full(
            W_T,
            &keyhash(&fx, &nkey(2)),
            "reopen",
            "1",
            &ninst(2),
            "key-cap",
        ),
    ];
    for tx in ["storm", "summary"] {
        let m = notice(&fx, &odd, "", "full", tx, SINCE);
        assert_eq!(m.title, format!("host-908b: PAGE withheld {inst}"), "{tx}");
        assert_eq!(m.prio, "5", "{tx}");
        assert!(
            m.body[1].ends_with("new incidents: none"),
            "{tx}: {:?}",
            m.body
        );
    }
}

/// A summary's title says `in the last hour` only when it lists what was withheld since a stamp
/// about an hour old; over a longer span (the day's summaries were spent, the pass was down) or
/// a stamp that cannot be placed it names the time its count starts at, as its body does, and
/// with no time to name it gives the count alone.
#[test]
fn a_summary_over_more_than_an_hour_names_the_time_it_counts_from_in_its_title() {
    let fx = Fx::salted(SALT);
    let recs = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        wline(W_T, &keyhash(&fx, &nkey(1)), "open", "1"),
    ];
    let m = notice(&fx, &recs, "", "full", "summary", SINCE);
    assert_eq!(m.title, "host-908b: 1 message withheld in the last hour");
    let m = notice(&fx, &recs, "", "full", "summary", &lib_at(4000));
    assert_eq!(m.title, "host-908b: 1 message withheld since 12:40 UTC");
    assert!(m.body[0].starts_with("Withheld: 1 message since 12:40 UTC"));
    let m = notice(&fx, &recs, "", "full", "summary", "-");
    assert_eq!(m.title, "host-908b: 1 message withheld since 13:36 UTC");
    let odd = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        format!(
            "W\tnot-a-stamp\t{}\topen\t1\t-\tpool\n",
            keyhash(&fx, &nkey(1))
        ),
    ];
    let m = notice(&fx, &odd, "", "full", "summary", "-");
    assert_eq!(m.title, "host-908b: 1 message withheld");
    // The edge of `the last hour`: 65 minutes, and a second past it.
    let m = notice(&fx, &recs, "", "full", "summary", &lib_at(3900));
    assert_eq!(m.title, "host-908b: 1 message withheld in the last hour");
    let m = notice(&fx, &recs, "", "full", "summary", &lib_at(3901));
    assert_eq!(m.title, "host-908b: 1 message withheld since 12:41 UTC");
}

/// In the library one function adds a W line to the records in memory, stamped at the moment it
/// is written, and the failure hook's path writes its withheld transitions through it: a line
/// added anywhere else would carry the stamp its caller took when it began, which can fall
/// before a notice claimed in between and so never be listed. Beside it only the reader of the
/// file adds a line it does not judge. The witness builds no line of its own either: its one
/// writer of a W line, w_line, writes through pa_w_line, and nothing else in it adds to the lines
/// in memory or names a W line's fields.
#[test]
fn the_library_and_the_witness_add_a_w_line_in_one_place_and_both_senders_write_through_it() {
    let deploy = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");
    let lib = std::fs::read_to_string(format!("{deploy}/alert-lib.sh")).unwrap();
    let witness = std::fs::read_to_string(format!("{deploy}/witness.sh")).unwrap();
    let mut function = String::new();
    let mut witness_calls = Vec::new();
    let mut witness_adders = Vec::new();
    for line in witness.lines() {
        let t = line.trim_start();
        if let Some(f) = t.strip_suffix("() {")
            && !line.starts_with(' ')
        {
            function = f.to_string();
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        if t.contains("_PA_INC_REST+=")
            || t.contains("_PA_INC_REST=(")
            || t.contains("\"W\"")
            || t.contains("'W'")
        {
            witness_adders.push(format!("{function}: {t}"));
        }
        // A call stands first on its line; the witness's list of the library functions it needs
        // names it among others.
        if t.starts_with("pa_w_line ") {
            witness_calls.push(function.clone());
        }
    }
    assert!(
        witness_adders.is_empty(),
        "the witness adds no W line itself: {witness_adders:#?}"
    );
    assert_eq!(
        witness_calls,
        ["w_line"],
        "the witness's w_line writes through pa_w_line"
    );
    let mut function = String::new();
    let mut adders = Vec::new();
    let mut hook_calls = 0;
    for line in lib.lines() {
        let t = line.trim_start();
        if let Some(f) = t.strip_suffix("() {")
            && !line.starts_with(' ')
        {
            function = f.to_string();
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        if t.contains("_PA_INC_REST+=") {
            adders.push(function.clone());
        }
        if function == "pa_hook_v2" && t.starts_with("pa_w_line ") {
            hook_calls += 1;
        }
    }
    assert_eq!(adders, ["pa_incident_load", "pa_w_line"]);
    assert_eq!(
        hook_calls, 1,
        "pa_hook_v2 writes its W line through pa_w_line"
    );
}

/// A line of this boot comes after every stamp of an earlier boot, whatever the wall clock says:
/// a host whose clock came up behind after a restart must not lose what it withheld since.
#[test]
fn a_w_line_of_this_boot_counts_after_a_stamp_of_an_earlier_boot_whatever_its_wall_clock_says() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let rec = nrec(1, &nkey(1), "ACT", &ninst(1));
    let since = "999000/0000aaaa/50";
    for (at, want) in [
        ("998500/abcdef01/4000", "1"),
        ("999500/abcdef01/4000", "1"),
        ("998500/0000aaaa/20", "0"),
        ("999500/0000aaaa/60", "1"),
    ] {
        let r = withheld(&fx, &[rec.clone(), wline(at, &kh, "remind", "0")], since);
        assert_eq!(r.get("n"), want, "{at}: {}", r.err);
    }
}

/// A W line that is not whole (an empty field or too few, which no writer makes) is still placed
/// by its stamp when that is in form, so an old one is not counted again by every later notice
/// and a summary cannot say `in the last hour` over lines of two days ago. One whose stamp cannot
/// be placed is counted, as before.
#[test]
fn a_w_line_that_is_not_whole_is_counted_only_from_the_stamp_a_notice_lists_since() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let rec = nrec(1, &nkey(1), "ACT", &ninst(1));
    let broken = |at: &str| format!("W\t{at}\t{kh}\topen\t1\t\tpool\n");
    let short = |at: &str| format!("W\t{at}\t{kh}\topen\n");
    for (lines, want) in [
        (vec![broken(&lib_at(4500)), short(&lib_at(4500))], "0"),
        (vec![broken(&lib_at(144_000)), short(&lib_at(144_000))], "0"),
        (vec![broken(W_T), short(W_T)], "2"),
        (vec![format!("W\t\t{kh}\topen\t1\t-\tpool\n")], "1"),
    ] {
        let mut records = vec![rec.clone()];
        records.extend(lines.iter().cloned());
        let r = withheld(&fx, &records, SINCE);
        assert_eq!(r.get("n"), want, "{lines:?}: {}", r.err);
    }
    let records = vec![
        rec,
        broken(&lib_at(144_000)),
        short(&lib_at(4500)),
        wline(W_T, &kh, "open", "1"),
    ];
    let m = notice(&fx, &records, "", "full", "summary", SINCE);
    assert_eq!(m.title, "host-908b: 1 message withheld in the last hour");
}

/// A W line whose stamp is ahead of the clock is kept only while its wall time is within two
/// days of the wall clock: one further off (a stamp of this boot with an uptime not yet reached
/// and a wall time of ten days ago, or a wall time three days ahead) can never age out by the
/// usual rule, and every notice would count it for good.
#[test]
fn the_bounds_of_the_incidents_file_drop_a_w_line_stamped_far_from_the_wall_clock() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let records = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        wline("136000/abcdef01/9000", &kh, "remind", "0"),
        wline("1259300/0000aaaa/1", &kh, "remind", "0"),
        wline("1003600/0000aaaa/1", &kh, "change", "0"),
        wline(W_T, &kh, "remind", "0"),
    ];
    let r = withheld_script(
        &fx,
        &records,
        "pa_incident_prune\nfor l in \"${_PA_INC_REST[@]}\"; do [[ $l != W$'\\t'* ]] || echo \"w=${l//$'\\t'/ }\"; done",
        &[],
    );
    let kept: Vec<&str> = r.out.lines().filter_map(|l| l.strip_prefix("w=")).collect();
    assert_eq!(
        kept,
        [
            format!("W 1003600/0000aaaa/1 {kh} change 0 - pool"),
            format!("W {W_T} {kh} remind 0 - pool"),
        ],
        "{}",
        r.err
    );
}

/// A notice's result that cannot take the lock writes nothing: status 2, and the line stays
/// claimed and counted, so the class's cap still holds the next one back.
#[test]
fn a_notice_result_without_the_lock_leaves_its_line_claimed_and_counted() {
    let fx = Fx::salted(SALT);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\nL\t1000000/abcdef01/5000\tstorm\t-\tstorm\tfull\tsending\tlight\n",
    );
    let r = fx.run_env(
        "pa_lock() { return 1; }\nrc=0; pa_notice_result 1000000/abcdef01/5000 storm ok light || rc=$?\n\
         echo \"rc=$rc\"",
        &NOW,
    );
    assert_eq!(r.get("rc"), "2", "{}", r.err);
    assert_eq!(
        ledger_body(&fx),
        ["L\t1000000/abcdef01/5000\tstorm\t-\tstorm\tfull\tsending\tlight"]
    );
    let r = fx.run_env(
        "pa_lock 5\npa_notice_admit storm light > /dev/null\necho \"v=$PA_ADMIT_VERDICT\"",
        &NOW,
    );
    assert_eq!(r.get("v"), "withhold:storm-cap", "{}", r.err);
}

/// A storm notice or a summary that got ok moves its meta key (storm_last, summary_last) to the
/// stamp of its claim, in the locked section that writes its result and under one lock: the
/// next notice lists what was withheld from that claim on, a line written while the post was in
/// flight among it. Any other result, a claimed line that is gone and a lock not had leave the key
/// as it was, so the next notice lists those lines again. The switch summary and the pointer
/// message keep no key here: their results are written as pa_notice_result writes them. The claim
/// is fifty seconds before the clock at the close, as a post takes time: the key is the claim's
/// stamp, never one taken when the result is written, which would pass over a line written while
/// the post was in flight.
#[test]
fn a_notice_that_got_ok_keeps_its_claim_as_its_meta_key_and_any_other_result_keeps_the_old_one() {
    let fx = Fx::salted(SALT);
    let claim = "999950/abcdef01/4950";
    let old = "999000/abcdef01/4000";
    let counted = "orig_pa_lock() { :; }\neval \"orig_$(declare -f pa_lock)\"\n\
                   pa_lock() { echo x >> \"$D/locks\"; orig_pa_lock \"$@\"; }\nrm -f \"$D/locks\"\n";
    for (class, result, want_rc, keeps) in [
        ("storm", "ok", "0", true),
        ("summary", "ok", "0", true),
        ("storm", "transient:503", "0", false),
        ("summary", "perm:403", "0", false),
        ("storm", "transient:000", "0", false),
        ("switch", "ok", "0", false),
        ("pointer", "ok", "0", false),
    ] {
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!(
                "#send-ledger v1 g=1\nL\t{claim}\t{class}\t-\t{class}\tfull\tsending\tlight\n"
            ),
        );
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=1\nM\tstorm_last\t{old}\nM\tsummary_last\t{old}\n"),
        );
        let r = fx.run_env(
            &format!(
                "{counted}rc=0; pa_notice_close {claim} {class} {result} light || rc=$?\n\
                 echo \"rc=$rc\"\necho \"locks=$(wc -l < \"$D/locks\")\"\n\
                 echo \"storm=$(_pa_meta_get storm_last)\"\necho \"summary=$(_pa_meta_get summary_last)\"\n\
                 echo \"pointer=$(_pa_meta_get pointer_last)\""
            ),
            &NOW,
        );
        assert_eq!(r.get("rc"), want_rc, "{class} {result}: {}", r.err);
        assert_eq!(r.get("locks").trim(), "1", "{class} {result}: one lock");
        assert_eq!(
            ledger_body(&fx),
            [format!(
                "L\t{claim}\t{class}\t-\t{class}\tfull\t{result}\tlight"
            )],
            "{class} {result}"
        );
        let want = |k: &str| {
            if keeps && k == class { claim } else { old }
        };
        assert_eq!(r.get("storm"), want("storm"), "{class} {result}");
        assert_eq!(r.get("summary"), want("summary"), "{class} {result}");
        assert_eq!(r.get("pointer"), "", "{class} {result}");
    }
    // An ok whose claimed line is gone (a damaged ledger replaced by an empty one): the result
    // cannot be written, so the key stays and the lines are listed again.
    fx.write("var/lib/propolis/witness/send-ledger", EMPTY_LEDGER);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tstorm_last\t{old}\n"),
    );
    let r = fx.run_env(
        &format!(
            "rc=0; pa_notice_close {claim} storm ok light || rc=$?\necho \"rc=$rc\"\n\
             echo \"storm=$(_pa_meta_get storm_last)\""
        ),
        &NOW,
    );
    assert_eq!(
        (r.get("rc"), r.get("storm")),
        ("1".into(), old.into()),
        "{}",
        r.err
    );
    // Without the lock nothing is written: the line stays claimed and the key as it was.
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\nL\t{claim}\tstorm\t-\tstorm\tfull\tsending\tlight\n"),
    );
    let r = fx.run_env(
        &format!(
            "pa_lock() {{ return 1; }}\nrc=0; pa_notice_close {claim} storm ok light || rc=$?\n\
             echo \"rc=$rc\"\necho \"storm=$(_pa_meta_get storm_last)\""
        ),
        &NOW,
    );
    assert_eq!(
        (r.get("rc"), r.get("storm")),
        ("2".into(), old.into()),
        "{}",
        r.err
    );
    assert!(ledger_body(&fx)[0].ends_with("\tsending\tlight"));
    // A class that is not one of the four writes nothing.
    let r = fx.run_env(
        &format!("rc=0; pa_notice_close {claim} daily ok light || rc=$?\necho \"rc=$rc\""),
        &NOW,
    );
    assert_eq!(r.get("rc"), "2");
}

/// Two withheld opens of one PAGE incident are two messages and one name.
#[test]
fn two_w_lines_for_one_page_record_are_counted_twice_and_named_once() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let records = vec![
        nrec(1, &nkey(1), "PAGE", &ninst(1)),
        wline(W_T, &kh, "open", "1"),
        wline(W_T, &kh, "open", "1"),
    ];
    let r = withheld(&fx, &records, SINCE);
    assert_eq!(r.get("n"), "2", "{}", r.err);
    assert_eq!(
        (r.get("names"), r.get("page"), r.get("more")),
        (ninst(1), ninst(1), "0".to_string())
    );
}

/// A notice sent whole or not at all: a body of lines each in form but 1024 bytes or more is
/// refused and leaves no title, priority or body; one under that is set.
#[test]
fn a_notice_body_of_valid_lines_past_the_senders_cut_is_refused_whole() {
    let fx = Fx::salted(SALT);
    let line = format!("line {}", "x".repeat(95));
    let long = vec![line.clone(); 11].join("\n");
    let short = vec![line; 9].join("\n");
    assert!(long.len() >= 1100);
    for (body, want) in [(long, "1"), (short, "0")] {
        let r = fx.run_env(
            "PA_TITLE=old PA_PRIO=3 PA_BODY=old\nrc=0; _pa_render_check 'host-908b: x' \"$B\" || rc=$?\n\
             echo \"rc=$rc\"\necho \"title=$PA_TITLE\"\necho \"len=${#PA_BODY}\"",
            &[("B", body.as_str())],
        );
        assert_eq!(r.get("rc"), want, "{}", r.err);
        if want == "1" {
            assert_eq!((r.get("title"), r.get("len")), ("".into(), "0".into()));
        } else {
            assert_eq!(r.get("title"), "host-908b: x");
            assert_eq!(r.get("len"), body.len().to_string());
        }
    }
}

/// Within one boot the lines are placed by uptime, which a clock step cannot move: a line whose
/// wall clock stepped back is counted when its uptime is after the stamp, and one whose wall
/// clock is later but whose uptime is earlier is not. A line of an earlier boot predates every
/// stamp of this one, whatever its wall clock says.
#[test]
fn within_one_boot_w_lines_are_placed_by_uptime_and_a_line_of_an_earlier_boot_predates_the_stamp() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let rec = nrec(1, &nkey(1), "ACT", &ninst(1));
    let since = "999400/abcdef01/4400";
    for (at, want) in [
        ("990000/abcdef01/4500", "1"),
        ("999500/abcdef01/4300", "0"),
        ("1000500/0000aaaa/1", "0"),
    ] {
        let r = withheld(&fx, &[rec.clone(), wline(at, &kh, "remind", "0")], since);
        assert_eq!(r.get("n"), want, "{at}: {}", r.err);
    }
}

/// A line whose stamp is out of form is dropped by the bounds of the file, so it cannot keep a
/// summary due for good; a line in form stays, one ahead of the clock among them.
#[test]
fn the_bounds_of_the_incidents_file_drop_a_w_line_whose_stamp_is_out_of_form() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let records = vec![
        nrec(1, &nkey(1), "ACT", &ninst(1)),
        wline("garbage", &kh, "open", "1"),
        wline(W_T, &kh, "remind", "0"),
        wline("1000500/abcdef01/5500", &kh, "change", "0"),
    ];
    let r = withheld_script(
        &fx,
        &records,
        "pa_incident_prune\nfor l in \"${_PA_INC_REST[@]}\"; do [[ $l != W$'\\t'* ]] || echo \"w=${l//$'\\t'/ }\"; done",
        &[],
    );
    let kept: Vec<&str> = r.out.lines().filter_map(|l| l.strip_prefix("w=")).collect();
    assert_eq!(
        kept,
        [
            format!("W {W_T} {kh} remind 0 - pool"),
            format!("W 1000500/abcdef01/5500 {kh} change 0 - pool"),
        ],
        "{}",
        r.err
    );
}

/// A W line names the record its key holds only when the line is not older than that record's
/// last open: an earlier line is of an earlier incident on the same key, which a new one
/// replaced, and is counted unnamed, raising no priority.
#[test]
fn a_w_line_older_than_its_records_last_open_is_counted_and_not_named() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let rec = nrec_opened(1, &nkey(1), "PAGE", &ninst(1), "999500/abcdef01/4500");
    let early = vec![rec.clone(), wline("999400/abcdef01/4400", &kh, "open", "1")];
    let r = withheld(&fx, &early, SINCE);
    assert_eq!(
        (r.get("n"), r.get("page"), r.get("names"), r.get("more")),
        ("1".into(), "".into(), "".into(), "1".into()),
        "{}",
        r.err
    );
    let m = notice(&fx, &early, "", "full", "storm", SINCE);
    assert_eq!(m.prio, "3", "{}", m.out);
    let late = vec![rec, wline("999600/abcdef01/4600", &kh, "open", "1")];
    let m = notice(&fx, &late, "", "full", "storm", SINCE);
    assert_eq!(m.prio, "5", "{}", m.out);
    assert_eq!(m.title, format!("host-908b: PAGE withheld {}", ninst(1)));
}

/// A key hash two records share names neither: the line is counted among the new incidents not
/// named, and is no PAGE.
#[test]
fn a_w_line_whose_key_two_records_share_is_counted_and_not_named() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let records = vec![
        nrec(1, &nkey(1), "PAGE", &ninst(1)),
        nrec(2, &nkey(1), "PAGE", &ninst(2)),
        wline(W_T, &kh, "open", "1"),
    ];
    let r = withheld(&fx, &records, SINCE);
    assert_eq!(
        (r.get("n"), r.get("names"), r.get("more"), r.get("page")),
        ("1".into(), "".into(), "1".into(), "".into()),
        "{}",
        r.err
    );
}

/// New incidents none of which can be named are counted in words of their own.
#[test]
fn a_storm_notice_over_new_incidents_none_of_which_can_be_named_counts_them() {
    let fx = Fx::salted(SALT);
    let records: Vec<String> = (1..=5)
        .map(|n| wline(W_T, &keyhash(&fx, &nkey(n)), "open", "1"))
        .collect();
    let m = notice(&fx, &records, "", "full", "storm", SINCE);
    assert_eq!(m.rc, "0", "{}", m.out);
    assert_eq!(
        m.body[0],
        "Withheld: 5 messages since 12:46 UTC; new incidents: 5 not named"
    );
}

/// With a stamp that cannot be placed, the notice says since the earliest line it counted, or
/// `?` when no line's stamp can be placed either.
#[test]
fn a_notice_over_a_stamp_out_of_form_says_since_its_earliest_line_or_a_question_mark() {
    let fx = Fx::salted(SALT);
    let kh = keyhash(&fx, &nkey(1));
    let rec = nrec(1, &nkey(1), "ACT", &ninst(1));
    let dated = vec![
        rec.clone(),
        wline("999360/abcdef01/4360", &kh, "remind", "0"),
        wline("996960/abcdef01/1960", &kh, "remind", "0"),
    ];
    let m = notice(&fx, &dated, "", "full", "summary", "garbage");
    assert!(
        m.body[0].starts_with("Withheld: 2 messages since 12:56 UTC;"),
        "{:?} {}",
        m.body,
        m.out
    );
    let undated = vec![
        rec,
        wline("garbage", &kh, "remind", "0"),
        wline("x/y/z", &kh, "remind", "0"),
    ];
    let m = notice(&fx, &undated, "", "full", "summary", "garbage");
    assert!(
        m.body[0].starts_with("Withheld: 2 messages since ? UTC;"),
        "{:?} {}",
        m.body,
        m.out
    );
}
