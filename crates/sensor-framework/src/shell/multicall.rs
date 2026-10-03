//! `toybox` and `toolbox`: the Android shell's multi-call binaries, which `/system/bin` advertises
//! and which route `<binary> <applet> [args]` to the applet's own handler, the way `busybox` does.
//!
//! Pure routing: an applet runs through the handler the registry already holds for it, so nothing
//! here reads a file, starts a process or opens a socket. Only the Android shell has them; on bash
//! they are "not found".
//!
//! No toybox or toolbox applet list was captured for this device. The bare listings are therefore
//! not an AOSP list from memory: they are the names the persona's own `/system/bin` already
//! advertises, split by who the persona's code already says provides them (`getprop` and `setprop`
//! are toolbox commands, see `android.rs`; the other advertised utilities are toybox's). The test
//! module reconciles both lists against the filesystem listing, so they cannot drift from it.
//! Everything below the persona's own facts is marked `[unverified]`.
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
pub(super) const TOYBOX_APPLETS: [&str; 16] = [
    "cat", "chmod", "date", "df", "du", "env", "free", "hostname", "ls", "mount", "netstat",
    "ping", "reboot", "route", "umount", "uptime",
];

/// The toolbox-backed names of the advertised `/system/bin`. `ps`, `top` and `ifconfig` are
/// toolbox's on Android 6 [unverified]; toybox took them over in a later release.
pub(super) const TOOLBOX_APPLETS: [&str; 5] = ["getprop", "setprop", "ps", "top", "ifconfig"];

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
};

const TOOLBOX: Multicall = Multicall {
    applets: &TOOLBOX_APPLETS,
    sibling: "toybox",
    unknown: toolbox_unknown,
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
        if applet.contains('/') || applet == tool.sibling || NOT_APPLETS.contains(&applet) {
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
