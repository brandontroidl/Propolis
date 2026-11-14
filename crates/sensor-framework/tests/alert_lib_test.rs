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
    assert_eq!(version, "1");
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
    // another account.
    std::os::unix::fs::symlink("/usr/bin", fx.p("chain/sys")).unwrap();
    let (rc, why) = check("chain/sys/env");
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
            why.starts_with("/usr: not owned by root (root:root "),
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
    assert_eq!(check("/usr/bin/env"), ("0".to_string(), String::new()));
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
