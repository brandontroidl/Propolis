//! `trap`: handlers stored and listed as bash 5.1.16 and dash 0.5.11 list them, and the `EXIT`
//! handler run when the shell that set it ends.
//!
//! The emulator delivers no signal, so a handler for one only has to be kept and listed: setting,
//! resetting (`trap - INT`, `trap INT`), ignoring (`trap '' INT`) and the listing (`trap`,
//! `trap -p`, bash's `trap -l`) are exact. What does run is what a shell runs by itself: the `EXIT`
//! handler, when `exit` or `logout` ends a shell, when a script, a subshell, a pipeline stage or a
//! command substitution ends, and a signal a script sends its own shell (`kill -USR1 $$`).
//! `DEBUG`, `ERR` and `RETURN` are bash's own pseudo-signals; they are kept and listed but not run
//! [not modeled]. No handler runs when `exec` replaces the shell, as in the real one.
//!
//! A handler is text, parsed when it runs, so it is bounded: at most [`COMMAND_MAX`] bytes each and
//! 68 of them (one per signal), which count against the connection's content allowance. A subshell
//! lists the handlers of the shell it was made from until it changes one, runs none of them, and
//! keeps the signals that were ignored; a shell started from bash lists the ignored signals only.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::procs::{bash_signal_list, signal_name};
use super::registry::Registry;
use super::{BudgetHit, CommandResult, FakeShell, Flow, HandlerId};

/// The key of `EXIT` (signal 0), and of bash's three pseudo-signals, after the real ones.
pub(super) const EXIT: u16 = 0;
pub(super) const DEBUG: u16 = 65;
const ERR: u16 = 66;
const RETURN: u16 = 67;

/// Longest handler text kept.
const COMMAND_MAX: usize = 4096;

pub(super) fn register(r: &mut Registry) {
    r.register_builtin("trap", HandlerId::Trap, FakeShell::builtin_trap);
}

/// The handlers one shell holds, by signal.
pub(super) type Traps = std::collections::BTreeMap<u16, String>;

/// Quote a handler the way the listing does: bash closes the quote around a quote (`'\''`), dash
/// and mksh reopen it in double quotes.
fn quoted(text: &str, bash: bool) -> String {
    let inner = if bash {
        text.replace('\'', "'\\''")
    } else {
        text.replace('\'', "'\"'\"'")
    };
    format!("'{inner}'")
}

/// bash's name for a key in a listing: `EXIT`, `SIGHUP`, the number for 32 and 33, `DEBUG`.
fn bash_name(key: u16) -> String {
    match key {
        EXIT => "EXIT".to_string(),
        DEBUG => "DEBUG".to_string(),
        ERR => "ERR".to_string(),
        RETURN => "RETURN".to_string(),
        n => signal_name(u32::from(n)).map_or_else(|| n.to_string(), |name| format!("SIG{name}")),
    }
}

/// dash's name for a key: the bare name, or the number where dash has no name (16, 32, 33).
fn dash_name(key: u16) -> String {
    match key {
        EXIT => "EXIT".to_string(),
        16 => "16".to_string(),
        n => signal_name(u32::from(n)).unwrap_or_else(|| n.to_string()),
    }
}

/// The key a bash spec names: a number from 0 to 64, `EXIT`, `DEBUG`, `ERR`, `RETURN`, or a signal
/// name with or without `SIG`, in either case.
fn bash_spec(spec: &str) -> Option<u16> {
    if !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_digit()) {
        return spec.parse::<u16>().ok().filter(|n| *n <= 64);
    }
    let upper = spec.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    match bare {
        "EXIT" => Some(EXIT),
        "DEBUG" => Some(DEBUG),
        "ERR" => Some(ERR),
        "RETURN" => Some(RETURN),
        _ => (1..=64u16).find(|n| signal_name(u32::from(*n)).is_some_and(|name| name == bare)),
    }
}

/// The key a dash spec names: a decimal number from 0 to 64 (leading zeros allowed), `EXIT`, or a
/// bare signal name in either case. dash has no `SIG` prefix, no `STKFLT`, and no pseudo-signals.
fn dash_spec(spec: &str) -> Option<u16> {
    if !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_digit()) {
        let digits = spec.trim_start_matches('0');
        if digits.is_empty() {
            return Some(0);
        }
        return digits.parse::<u16>().ok().filter(|n| *n <= 64);
    }
    let upper = spec.to_ascii_uppercase();
    if upper == "EXIT" {
        return Some(EXIT);
    }
    (1..=64u16)
        .filter(|n| *n != 16)
        .find(|n| signal_name(u32::from(*n)).is_some_and(|name| name == upper))
}

impl FakeShell {
    fn trap_spec(&self, spec: &str) -> Option<u16> {
        if self.is_bash() {
            bash_spec(spec)
        } else {
            dash_spec(spec)
        }
    }

    fn trap_name(&self, key: u16) -> String {
        if self.is_bash() {
            bash_name(key)
        } else {
            dash_name(key)
        }
    }

    /// The handlers the running shell lists: a subshell's are those of the shell it came from
    /// until it changes one.
    fn trap_table(&self) -> &Traps {
        let state = self.state();
        state.trap_view.as_ref().unwrap_or(&state.traps)
    }

    fn trap_lines(&self, keys: &[u16]) -> String {
        let bash = self.is_bash();
        let table = self.trap_table();
        let mut out = String::new();
        for (key, action) in table {
            if keys.is_empty() || keys.contains(key) {
                out.push_str(&format!(
                    "trap -- {} {}\n",
                    quoted(action, bash),
                    self.trap_name(*key)
                ));
            }
        }
        out
    }

    /// Store, ignore or reset the handler of `key`. False when the text is too long to keep.
    fn trap_set(&mut self, key: u16, action: Option<&str>) -> bool {
        let cap = usize::try_from(self.budget().limits().owned_bytes).unwrap_or(usize::MAX);
        let state = self.state();
        let before = state.traps.get(&key).map_or(0, String::len);
        let after = state
            .owned_bytes()
            .saturating_sub(before)
            .saturating_add(action.map_or(0, str::len));
        if action.is_some_and(|text| text.len() > COMMAND_MAX) || after > cap {
            self.record_hit(BudgetHit::OwnedBytes);
            return false;
        }
        let state = self.state_mut();
        match action {
            Some(text) => {
                state.traps.insert(key, text.to_string());
            }
            None => {
                state.traps.remove(&key);
            }
        }
        true
    }

    /// `trap [-lp] [[ACTION] SIGNAL...]`
    pub(super) fn builtin_trap(&mut self, parts: &[&str]) -> CommandResult {
        let bash = self.is_bash();
        let mut args = parts.get(1..).unwrap_or(&[]);
        let (mut names, mut print) = (false, false);
        // Leading options. bash has -l and -p; dash has none, and its refusal ends the shell.
        while let Some(arg) = args.first() {
            if *arg == "--" {
                args = args.get(1..).unwrap_or(&[]);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                match flag {
                    'l' if bash => names = true,
                    'p' if bash => print = true,
                    other if bash => {
                        return CommandResult::stderr(
                            2,
                            format!(
                                "{}trap: usage: trap [-lp] [[arg] signal_spec ...]\n",
                                self.shell_error(format_args!("trap: -{other}: invalid option"))
                            ),
                        );
                    }
                    other => {
                        return self.dash_fatal(2, format_args!("trap: Illegal option -{other}"));
                    }
                }
            }
            args = args.get(1..).unwrap_or(&[]);
        }
        if names {
            return CommandResult::stdout(bash_signal_list());
        }
        if args.is_empty() {
            return CommandResult::stdout(self.trap_lines(&[]));
        }
        if print {
            return self.trap_print(args);
        }
        if bash && args == ["-"] {
            return CommandResult::stderr(2, "trap: usage: trap [-lp] [[arg] signal_spec ...]\n");
        }
        // A lone operand, or one that is itself a signal, means every operand is a signal to reset.
        let reset_all = args.len() == 1
            || if bash {
                args.first()
                    .is_some_and(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
            } else {
                args.first().is_some_and(|a| dash_spec(a).is_some())
            };
        let (action, specs) = match (reset_all, args.split_first()) {
            (false, Some((action, specs))) => (Some(*action), specs),
            _ => (None, args),
        };
        let action = action.filter(|text| *text != "-");
        // A subshell that changes a handler stops listing its parent's.
        self.state_mut().trap_view = None;
        let mut out = CommandResult::silent(0);
        let mut failed = false;
        for spec in specs {
            let Some(key) = self.trap_spec(spec) else {
                let message = if bash {
                    self.shell_error(format_args!("trap: {spec}: invalid signal specification"))
                } else {
                    format!("trap: {spec}: bad trap\n")
                };
                out.append(CommandResult::stderr(1, message));
                failed = true;
                // dash stops at the first signal it cannot read.
                if !bash {
                    break;
                }
                continue;
            };
            if !self.trap_set(key, action) {
                failed = true;
            }
        }
        out.status = u8::from(failed);
        out
    }

    /// `trap -p SIGNAL...`
    fn trap_print(&mut self, specs: &[&str]) -> CommandResult {
        let mut out = CommandResult::silent(0);
        let mut keys = Vec::new();
        let mut failed = false;
        for spec in specs {
            match self.trap_spec(spec) {
                Some(key) => keys.push(key),
                None => {
                    out.append(CommandResult::stderr(
                        1,
                        self.shell_error(format_args!(
                            "trap: {spec}: invalid signal specification"
                        )),
                    ));
                    failed = true;
                }
            }
        }
        if !keys.is_empty() {
            out.append(CommandResult::stdout(self.trap_lines(&keys)));
        }
        out.status = u8::from(failed);
        out
    }

    /// Run handler text in the shell that is running, as a shell does when a trap fires.
    fn run_trap_text(&mut self, text: &str) -> CommandResult {
        let max_depth = self.budget().limits().max_depth;
        if !self.depth.try_enter(max_depth) {
            self.record_hit(BudgetHit::Depth);
            self.note_depth();
            return CommandResult::silent(1);
        }
        self.note_depth();
        let dialect = self.grammar();
        let parsed =
            super::parse::parse_unit(text, true, max_depth, dialect, &mut self.line, 1, &[]);
        self.sync_budget_trace();
        let mut result = self.execute_unit(parsed, 1, Some(text));
        self.depth.leave();
        if result.flow != Flow::ExitSubshell {
            result.flow = Flow::None;
        }
        result
    }

    /// The shell that is running ends with the status in `result`: run its `EXIT` handler, once,
    /// after what it printed. The status stays what it was unless the handler itself exits.
    ///
    /// Returns the status the handler's own last command left, when a handler ran.
    pub(super) fn append_exit_trap(&mut self, result: &mut CommandResult) -> Option<u8> {
        let action = self.state_mut().traps.remove(&EXIT)?;
        if action.is_empty() {
            return None;
        }
        let status = result.status;
        self.state_mut().last_status = status;
        self.state_mut().exiting = true;
        let mut trap = self.run_trap_text(&action);
        self.state_mut().exiting = false;
        let exited = trap.stop_line || trap.flow == Flow::ExitSubshell || trap.close_session;
        trap.flow = Flow::None;
        let kept = if exited { trap.status } else { status };
        let left = trap.status;
        result.append(trap);
        result.status = kept;
        Some(left)
    }

    /// The `DEBUG` or `ERR` handler of the running shell, when one may run now: not while another
    /// handler runs, and not inside a function, which does not inherit them.
    fn pseudo_trap(&self, key: u16) -> Option<String> {
        let state = self.state();
        if state.in_trap || !state.calls.is_empty() || !self.is_bash() {
            return None;
        }
        state
            .traps
            .get(&key)
            .filter(|text| !text.is_empty())
            .cloned()
    }

    /// Run a `DEBUG` or `ERR` handler with `$?` as `status`, which the handler does not change.
    fn run_pseudo_trap(&mut self, text: &str, status: u8) -> CommandResult {
        self.state_mut().in_trap = true;
        self.state_mut().last_status = status;
        let result = self.run_trap_text(text);
        let state = self.state_mut();
        state.in_trap = false;
        state.last_status = status;
        result
    }

    /// bash runs the `DEBUG` handler before each simple command, and before each trip of a `for`
    /// and a `case`; what it prints comes first.
    pub(super) fn debug_before(&mut self) -> Option<CommandResult> {
        let text = self.pseudo_trap(DEBUG)?;
        let status = self.state().last_status;
        let mut result = self.run_pseudo_trap(&text, status);
        result.status = status;
        Some(result)
    }

    /// bash runs the `ERR` handler after a simple command, a pipeline or a subshell fails where
    /// nothing tests its status (the caller says whether anything does).
    pub(super) fn err_after(&mut self, status: u8) -> Option<CommandResult> {
        if status == 0 || self.state().err_ignore > 0 {
            return None;
        }
        let text = self.pseudo_trap(ERR)?;
        let mut result = self.run_pseudo_trap(&text, status);
        result.status = status;
        Some(result)
    }

    /// A signal sent to this shell's own process: its handler runs now, an ignored signal does
    /// nothing. `None` when the shell has no handler for it.
    pub(super) fn deliver_to_self(&mut self, signal: u32) -> Option<CommandResult> {
        let key = u16::try_from(signal)
            .ok()
            .filter(|n| (1..=64).contains(n))?;
        let action = self.state().traps.get(&key)?.clone();
        if action.is_empty() {
            return Some(CommandResult::silent(0));
        }
        let mut result = self.run_trap_text(&action);
        result.status = 0;
        Some(result)
    }
}
