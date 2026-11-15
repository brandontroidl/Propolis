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
    assert_eq!(version, "6");
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

#[test]
fn pa_settings_load_reads_only_propolis_env_so_a_target_never_comes_from_two_files() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_TOPIC=from-propolis\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example\nPROPOLIS_OPS_NTFY_TOPIC=from-alert\n",
    );
    let r = fx.run(SETTINGS_DUMP);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.get("PA_URL"),
        "",
        "alert.env is not read before the v2 senders exist"
    );
    assert_eq!(r.get("PA_TOPIC"), "from-propolis");
    assert_eq!(r.get("PA_TARGET"), "0");
    assert_eq!(r.get("PA_TARGET_SRC"), "");
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
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL={RC_URL}\nPROPOLIS_OPS_NTFY_TOPIC={RC_TOPIC}\n"),
    );
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=3\nR\t{RC_BINDING}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\treads\t403\t403\tboth\t403\n"
        ),
    );
    let r = fx.run_env(
        &format!(
            "pa_now; have=0; _pa_rc_line shell && have=1\n\
             PA_RC_CLASS=refused PA_RC_TOKEN=unknown PA_RC_JSON=403 PA_RC_RAW=403 PA_RC_SSE=403\n\
             line=\"$(pa_readcheck_merge both {RC_BINDING} \"$have\")\"\n\
             echo \"line=$line\"\n\
             printf '#readcheck v1 g=4\\n%s\\n' \"$line\" > \"$PA_STATE/readcheck\"\n\
             pa_settings_load; PA_ROLE=collector; echo \"gate=$(pa_gate)\""
        ),
        &NOW,
    );
    assert_eq!(
        r.get("line"),
        format!(
            "R\t{RC_BINDING}\t1000000/abcdef01/5000\trefused\t1000000/abcdef01/5000\trefused\treads\t403\t403\tboth\t403"
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
    // Rule 7: on a collector, a token that cannot read the topic.
    let reads = line(RC_BINDING, fresh, fresh, "refused", "reads");
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
            Some(&line(RC_BINDING, fresh, fresh, "refused", "noread")),
            "unset PA_ROLE"
        ),
        "full",
        "the role matters only when the token reads"
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
/// definite answer other than refused (the shell's or the daemon's), refuses anonymous reads for
/// a refusal, and not checked yet for no answer or one bound to another target.
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
        "[propolis 13:46 UTC] alerts: topic refuses anonymous reads"
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
/// untrue. A fresh refusal over https still reads `refuses anonymous reads`, and so does one on
/// a collector whose token can read, since the anonymous refusal itself is proven there.
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
    let refuses = "[propolis 13:46 UTC] alerts: topic refuses anonymous reads";
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
