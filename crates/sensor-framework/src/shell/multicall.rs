//! `toybox` and `toolbox`: the Android shell's multi-call binaries, which `/system/bin` advertises
//! and which route `<binary> <applet> [args]` to the applet's own handler, the way `busybox` does.
//!
//! Pure routing: an applet runs through the handler the registry already holds for it, so nothing
//! here reads a file, starts a process or opens a socket. Only the Android shell has them; on bash
//! they are "not found".
//!
//! No toybox or toolbox applet list was captured from a device. The bare listings are the names
//! the persona's own `/system/bin` advertises, split by who provides them. The test module
//! reconciles both lists against the filesystem listing, so they cannot drift from it.
//!
//! The persona announces Android 6.0.1, so the reference for what toybox links into `/system/bin`
//! is toybox's `Android.mk` at tag `android-6.0.1_r81` (`ALL_TOOLS`), and for what its applets
//! print `toys/*` of that tag, not a newer release. That file links `getprop`, `setprop` and
//! `ifconfig` from toybox, and `system/core/toolbox` of the same tag has no source for any of
//! them (its `OUR_TOOLS` are `df getevent iftop ioctl ionice log ls lsof mount nandread
//! newfs_msdos ps prlimit renice sendevent start stop top uptime watchprops`, plus `dd` and `du`),
//! so they are toybox applets here and answer in toybox's words. Other names below still differ
//! from those two files and are not changed: `df`, `du`, `ls`, `mount` and `uptime` are toolbox's
//! at that tag, and `nc`, `ping` and `reboot` are in neither. Everything below the persona's own
//! facts and those sources is `[unverified]`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::{CommandKind, Registry};
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};

pub(super) fn register(r: &mut Registry) {
    r.register_if("toybox", android, HandlerId::Toybox, FakeShell::cmd_toybox);
    r.register_if(
        "toolbox",
        android,
        HandlerId::Toolbox,
        FakeShell::cmd_toolbox,
    );
}

fn android(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh
}

/// The toybox-backed names of the advertised `/system/bin`.
///
/// The text, hashing and file tools a loader uses to check what it staged (`wc`, `md5sum`,
/// `sha1sum`, `head`, `tail`, `cut`, `tr`, `od`, `which`, `id`, `mkdir`, `cp`, `mv`, `rm`,
/// `sleep`) are in `ALL_TOOLS` of toybox's `Android.mk` at tag `android-6.0.1_r81`, which is what
/// links them into `/system/bin`. `base64` and `sha256sum` are NOT there: that release compiles
/// `base64` (reachable as `toybox base64`) but links neither, and has no `sha256sum` at all; both
/// are linked from Android 7.0 and 8.0 on. They are listed anyway, deliberately, because the
/// ADB bots this sensor exists to catch target devices that have them, and a phone that answers
/// "not found" sends the loader away before it stages anything. `xxd` is linked from 7.0 as well
/// and is left out; `dd` is a toolbox (NetBSD) tool on this release whose summary line is not
/// modeled, so it stays "not found".
pub(super) const TOYBOX_APPLETS: [&str; 39] = [
    "base64",
    "cat",
    "chmod",
    "cp",
    "cut",
    "date",
    "df",
    "du",
    "env",
    "find",
    "free",
    "getprop",
    "head",
    "hostname",
    "id",
    "ifconfig",
    "ls",
    "md5sum",
    "mkdir",
    "mount",
    "mv",
    "nc",
    "netstat",
    "od",
    "ping",
    "reboot",
    "rm",
    "route",
    "setprop",
    "sha1sum",
    "sha256sum",
    "sleep",
    "stat",
    "tail",
    "tr",
    "umount",
    "uptime",
    "wc",
    "which",
];

/// Whether the registry entry named by `parts[0]` exists on this shell: every Ubuntu tool, and on
/// the phone the names [`TOYBOX_APPLETS`] lists. For the tools the two personas share a handler for.
pub(super) fn bare_applet(shell: &FakeShell, parts: &[&str]) -> bool {
    match shell.flavor {
        ShellFlavor::Bash => true,
        ShellFlavor::AndroidSh => parts
            .first()
            .map(|name| name.rsplit('/').next().unwrap_or(name))
            .is_some_and(|name| TOYBOX_APPLETS.contains(&name)),
    }
}

/// The toolbox-backed names of the advertised `/system/bin`. `ps` and `top` are in `OUR_TOOLS` of
/// `system/core/toolbox/Android.mk` at tag `android-6.0.1_r81`; toybox took them over later.
pub(super) const TOOLBOX_APPLETS: [&str; 2] = ["ps", "top"];

/// Shell builtins that toybox also provides as applets and that only print or answer a status,
/// so running them nested leaves the session's shell untouched. The other builtins (`cd`, `exit`,
/// `export`, `set`, ...) change the shell itself and are not applets of anything.
pub(super) const PURE_BUILTINS: [&str; 6] = ["echo", "pwd", "true", "false", "test", "["];

/// Names the shell answers that are not applets of either multi-call binary: BusyBox and its
/// `ash`, `su` (a binary of its own), and the fetchers, which a stock toybox does not build. The
/// URL capture is separate from dispatch (it also scans the raw line), so refusing the fetcher
/// here still records the attempted download.
const NOT_APPLETS: [&str; 7] = ["busybox", "su", "wget", "curl", "tftp", "ftpget", "ash"];

struct Multicall {
    applets: &'static [&'static str],
    /// The other multi-call binary, which is a file but not one of this binary's applets.
    sibling: &'static str,
    /// [unverified] the not-found line for a name that is no applet.
    unknown: fn(&str) -> String,
    /// Names the shell models that this binary is known not to have: the registry would run them
    /// from either binary, which only the other one's source justifies.
    lacks: &'static [&'static str],
}

/// [unverified] toybox's `Unknown command` wording, from its source, not a capture.
fn toybox_unknown(applet: &str) -> String {
    format!("toybox: Unknown command {applet}\n")
}

/// [unverified] toolbox's `no such tool` wording, not a capture.
fn toolbox_unknown(applet: &str) -> String {
    format!("toolbox: no such tool {applet}\n")
}

const TOYBOX: Multicall = Multicall {
    applets: &TOYBOX_APPLETS,
    sibling: "toolbox",
    unknown: toybox_unknown,
    lacks: &[],
};

const TOOLBOX: Multicall = Multicall {
    applets: &TOOLBOX_APPLETS,
    sibling: "toybox",
    unknown: toolbox_unknown,
    // `system/core/toolbox` at tag `android-6.0.1_r81` has no source for these three.
    lacks: &["getprop", "setprop", "ifconfig"],
};

impl Multicall {
    /// [unverified] what a bare invocation prints: the applet names, one per line on standard
    /// output, with no banner or version line (none was captured).
    fn listing(&self) -> String {
        self.applets
            .iter()
            .map(|name| format!("{name}\n"))
            .collect()
    }
}

impl FakeShell {
    pub(super) fn cmd_toybox(&mut self, parts: &[&str]) -> CommandResult {
        self.multicall(parts, &TOYBOX)
    }

    pub(super) fn cmd_toolbox(&mut self, parts: &[&str]) -> CommandResult {
        self.multicall(parts, &TOOLBOX)
    }

    /// Whether `applet`, a name from the line, runs as an applet: a bare name (a multi-call binary
    /// resolves by bare name, like busybox) that dispatch answers as a file, or as one of the
    /// builtins in [`PURE_BUILTINS`], and that is not in [`NOT_APPLETS`] or the sibling binary.
    fn runs_as_applet(&self, applet: &str, tool: &Multicall) -> bool {
        if applet.contains('/')
            || applet == tool.sibling
            || NOT_APPLETS.contains(&applet)
            || tool.lacks.contains(&applet)
        {
            return false;
        }
        match Registry::builtin().kind(applet, self) {
            Some(CommandKind::External) => true,
            Some(CommandKind::Builtin) => PURE_BUILTINS.contains(&applet),
            Some(CommandKind::Unresolved) | None => false,
        }
    }

    /// Bare: the applet listing. `<applet> ...`: the applet's own handler when the shell has one;
    /// a listed applet no handler models succeeds silently (it exists, and its behavior is not
    /// captured, so nothing is invented); any other name gets the binary's not-found line, status
    /// 1 [unverified]. Re-entry goes through `dispatch_nested`, so `toybox toybox toybox ...` is
    /// cut at the shell's depth cap and bounded by the line's work allowance.
    fn multicall(&mut self, parts: &[&str], tool: &Multicall) -> CommandResult {
        let Some(rest) = parts.get(1..).filter(|rest| !rest.is_empty()) else {
            return CommandResult::stdout(tool.listing());
        };
        let applet = rest.first().copied().unwrap_or_default();
        if self.runs_as_applet(applet, tool) {
            return self.dispatch_nested(rest);
        }
        if tool.applets.contains(&applet) {
            return CommandResult::silent(0);
        }
        CommandResult::stderr(1, (tool.unknown)(applet))
    }
}
