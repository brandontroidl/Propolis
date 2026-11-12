//! `basename` and `dirname`: a loader builds architecture-specific download paths with them
//! (`wget http://host/$(basename $0).$arch`, `cd $(dirname $0)`).
//!
//! Both are purely lexical, as GNU's are: they split the text of their operands and never touch
//! the filesystem, so a path that does not exist splits like one that does. `realpath`, which does
//! resolve through the modeled filesystem, lives with `readlink`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};

pub(super) fn register(r: &mut Registry) {
    // The phone's toolbox has no recorded answer for these, and it answers "not found" today.
    r.register_if(
        "basename",
        ubuntu,
        HandlerId::Basename,
        FakeShell::cmd_basename,
    );
    r.register_if(
        "dirname",
        ubuntu,
        HandlerId::Dirname,
        FakeShell::cmd_dirname,
    );
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// The last component of `path` with trailing slashes dropped; `/` for a path of only slashes and
/// empty for an empty path.
fn base_name(path: &str) -> &str {
    if path.is_empty() {
        return "";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// `name` without `suffix`, when it ends with it and is not all of it. `/` keeps its suffix.
fn strip_suffix<'a>(name: &'a str, suffix: &str) -> &'a str {
    if name == "/" || name.len() <= suffix.len() {
        return name;
    }
    name.strip_suffix(suffix).unwrap_or(name)
}

/// Everything before the last component, trailing slashes dropped: `.` for a path with no
/// directory part and `/` when the directory is the root.
fn dir_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return if path.starts_with('/') { "/" } else { "." };
    }
    let Some(cut) = trimmed.rfind('/') else {
        return ".";
    };
    let dir = trimmed.get(..cut).unwrap_or("").trim_end_matches('/');
    if dir.is_empty() { "/" } else { dir }
}

#[derive(Default)]
struct Options<'a> {
    multiple: bool,
    zero: bool,
    suffix: Option<&'a str>,
    operands: Vec<&'a str>,
}

/// The command line of `tool` (`basename` also takes `-a` and `-s`), the tool's own error text, or
/// `None` for `--help` and `--version`, which are not modeled.
fn parse<'a>(tool: &str, args: &[&'a str]) -> Result<Option<Options<'a>>, String> {
    let try_help = format!("Try '{tool} --help' for more information.\n");
    let base = tool == "basename";
    let mut options = Options::default();
    let mut ended = false;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if ended || arg == "-" || !arg.starts_with('-') {
            options.operands.push(arg);
        } else if arg == "--" {
            ended = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            match long {
                "zero" => options.zero = true,
                "multiple" if base => options.multiple = true,
                "suffix" if base => {
                    let Some(&value) = args.get(i) else {
                        return Err(format!(
                            "{tool}: option '--suffix' requires an argument\n{try_help}"
                        ));
                    };
                    i = i.saturating_add(1);
                    options.suffix = Some(value);
                    options.multiple = true;
                }
                "help" | "version" => return Ok(None),
                _ => match long.strip_prefix("suffix=") {
                    Some(value) if base => {
                        options.suffix = Some(value);
                        options.multiple = true;
                    }
                    _ => {
                        return Err(format!("{tool}: unrecognized option '{arg}'\n{try_help}"));
                    }
                },
            }
        } else {
            let cluster = arg.get(1..).unwrap_or("");
            for (at, flag) in cluster.char_indices() {
                match flag {
                    'z' => options.zero = true,
                    'a' if base => options.multiple = true,
                    's' if base => {
                        let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
                        let value = if attached.is_empty() {
                            let Some(&next) = args.get(i) else {
                                return Err(format!(
                                    "{tool}: option requires an argument -- 's'\n{try_help}"
                                ));
                            };
                            i = i.saturating_add(1);
                            next
                        } else {
                            attached
                        };
                        options.suffix = Some(value);
                        options.multiple = true;
                        break;
                    }
                    other => {
                        return Err(format!("{tool}: invalid option -- '{other}'\n{try_help}"));
                    }
                }
            }
        }
    }
    Ok(Some(options))
}

fn missing_operand(tool: &str) -> CommandResult {
    CommandResult::stderr(
        1,
        format!("{tool}: missing operand\nTry '{tool} --help' for more information.\n"),
    )
}

fn terminated(names: impl IntoIterator<Item = String>, zero: bool) -> CommandResult {
    let end = if zero { '\0' } else { '\n' };
    let mut out = String::new();
    for name in names {
        out.push_str(&name);
        out.push(end);
    }
    CommandResult::stdout(out)
}

impl FakeShell {
    /// `basename NAME [SUFFIX]`, `basename -a NAME...` and `basename -s SUFFIX NAME...`, with `-z`.
    pub(super) fn cmd_basename(&mut self, parts: &[&str]) -> CommandResult {
        let options = match parse("basename", parts.get(1..).unwrap_or(&[])) {
            Ok(Some(options)) => options,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        if options.operands.is_empty() {
            return missing_operand("basename");
        }
        let (names, suffix) = if options.multiple {
            (options.operands.as_slice(), options.suffix)
        } else if let Some(&extra) = options.operands.get(2) {
            return CommandResult::stderr(
                1,
                format!(
                    "basename: extra operand '{extra}'\nTry 'basename --help' for more information.\n"
                ),
            );
        } else {
            (
                options.operands.get(..1).unwrap_or(&[]),
                options.operands.get(1).copied(),
            )
        };
        terminated(
            names.iter().map(|name| {
                let base = base_name(name);
                suffix.map_or(base, |s| strip_suffix(base, s)).to_string()
            }),
            options.zero,
        )
    }

    /// `dirname [-z] NAME...`.
    pub(super) fn cmd_dirname(&mut self, parts: &[&str]) -> CommandResult {
        let options = match parse("dirname", parts.get(1..).unwrap_or(&[])) {
            Ok(Some(options)) => options,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        if options.operands.is_empty() {
            return missing_operand("dirname");
        }
        terminated(
            options
                .operands
                .iter()
                .map(|name| dir_name(name).to_string()),
            options.zero,
        )
    }
}
