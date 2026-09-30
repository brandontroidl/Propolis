//! `readlink`: the target of a symlink, and with `-f`, `-e` or `-m` the canonical physical path.
//!
//! Both answers come from the filesystem model: [`FakeFs::link_target`] returns a link's stored
//! target one level deep, and [`FakeFs::canonicalize`] follows every link with the same resolver
//! every other path goes through. The one link the filesystem cannot hold is `/proc/self/exe`,
//! which names the executable of the process that reads it, so it goes through
//! [`FakeShell::resolve_reading`] with `readlink` (or busybox, for the applet) as the reader, the
//! rule the byte readers use.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::Canonical;

const TRY: &str = "Try 'readlink --help' for more information.\n";

pub(super) fn register(r: &mut Registry) {
    // The phone's toolbox has no recorded answer for readlink, and it answers "not found" today.
    r.register_if(
        "readlink",
        ubuntu,
        HandlerId::Readlink,
        FakeShell::cmd_readlink,
    );
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

#[derive(Default)]
struct Options {
    /// `-f`, `-e`, `-m`: the last one given wins.
    canonical: Option<Canonical>,
    no_newline: bool,
    verbose: bool,
    zero: bool,
}

/// What the flags and operands of one invocation asked for, or the error text it prints.
fn parse<'a>(args: &[&'a str]) -> Result<(Options, Vec<&'a str>), String> {
    let mut options = Options::default();
    let mut operands = Vec::new();
    let mut ended = false;
    for &arg in args {
        if ended || arg == "-" || !arg.starts_with('-') {
            operands.push(arg);
        } else if arg == "--" {
            ended = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            match long {
                "canonicalize" => options.canonical = Some(Canonical::ParentsExist),
                "canonicalize-existing" => options.canonical = Some(Canonical::Existing),
                "canonicalize-missing" => options.canonical = Some(Canonical::AllowMissing),
                "no-newline" => options.no_newline = true,
                "verbose" => options.verbose = true,
                "quiet" | "silent" => options.verbose = false,
                "zero" => options.zero = true,
                _ => return Err(format!("readlink: unrecognized option '{arg}'\n{TRY}")),
            }
        } else {
            for flag in arg.chars().skip(1) {
                match flag {
                    'f' => options.canonical = Some(Canonical::ParentsExist),
                    'e' => options.canonical = Some(Canonical::Existing),
                    'm' => options.canonical = Some(Canonical::AllowMissing),
                    'n' => options.no_newline = true,
                    'v' => options.verbose = true,
                    'q' | 's' => options.verbose = false,
                    'z' => options.zero = true,
                    other => {
                        return Err(format!("readlink: invalid option -- '{other}'\n{TRY}"));
                    }
                }
            }
        }
    }
    Ok((options, operands))
}

/// `arg` the way GNU tools quote a name in a diagnostic: bare unless it holds a character the
/// shell would treat specially. [unverified] beyond the bare case; not captured.
fn quoted(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-+,:@%=~".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{arg}'")
    }
}

impl FakeShell {
    /// `readlink [-femnvqsz] FILE...`. Status 1 when any operand gave nothing to print.
    pub(super) fn cmd_readlink(&mut self, parts: &[&str]) -> CommandResult {
        let (options, operands) = match parse(parts.get(1..).unwrap_or(&[])) {
            Ok(parsed) => parsed,
            Err(text) => return CommandResult::stderr(1, text),
        };
        if operands.is_empty() {
            return CommandResult::stderr(1, format!("readlink: missing operand\n{TRY}"));
        }
        let reader = self.reader_of(parts.first().copied().unwrap_or("readlink"));
        // GNU drops -n when there is more than one line to end.
        let terminated = !options.no_newline || operands.len() > 1;
        let end = if options.zero { "\0" } else { "\n" };

        let mut out = String::new();
        let mut errors = String::new();
        let mut failed = false;
        for arg in operands {
            match self.readlink_operand(arg, &options, reader) {
                Ok(text) => {
                    out.push_str(&text);
                    if terminated {
                        out.push_str(end);
                    }
                }
                Err(reason) => {
                    failed = true;
                    if options.verbose {
                        errors.push_str(&format!("readlink: {}: {reason}\n", quoted(arg)));
                    }
                }
            }
        }
        let mut result = CommandResult::stdout(out);
        result.append(CommandResult::stderr(u8::from(failed), errors));
        result.status = u8::from(failed);
        result
    }

    /// One operand: what to print, or the errno text behind the empty answer.
    fn readlink_operand(
        &mut self,
        arg: &str,
        options: &Options,
        reader: &str,
    ) -> Result<String, &'static str> {
        const MISSING: &str = "No such file or directory";
        if arg.is_empty() {
            return Err(MISSING);
        }
        self.charge_work(len_u64(arg.len()));
        // `/proc/self/exe` and `/proc/<shell pid>/exe` are links the filesystem does not store:
        // `resolve_reading` knows the executable behind them, and returns the path unchanged for
        // anything else.
        let typed = self.resolve_logical(arg);
        let read = self.resolve_reading(arg, Some(reader));
        let exe_link = read != typed;

        let absolute = if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{arg}", self.cwd().trim_end_matches('/'))
        };
        match options.canonical {
            Some(mode) => {
                let path = if exe_link { read } else { absolute };
                self.fs.canonicalize(&path, mode).ok_or(MISSING)
            }
            None if exe_link => Ok(read),
            None => {
                // A trailing slash makes the kernel follow the link, so it reads as its target
                // directory (or file), not as a link.
                let followed = arg.len() > 1 && arg.ends_with('/');
                let link = if followed {
                    None
                } else {
                    self.fs.link_target(&absolute)
                };
                link.ok_or_else(|| {
                    if self
                        .fs
                        .canonicalize(&absolute, Canonical::Existing)
                        .is_some()
                    {
                        "Invalid argument"
                    } else {
                        MISSING
                    }
                })
            }
        }
    }
}
