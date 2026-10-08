//! `touch`, `mv`, `ln`, `rmdir` and `chattr`: the rest of the commands a loader or a persistence
//! script uses to change the filesystem the session sees (`touch /tmp/.x`, `mv x /usr/bin/y`,
//! `ln -sf`, `rmdir`, and `chattr -ia .ssh` before it replaces the key directory).
//!
//! All of it edits the per-session overlay of [`FakeFs`](crate::fakefs::FakeFs) and nothing else:
//! no process starts, nothing reaches the host, and every node, byte and name is charged to the
//! connection budget by the same `FakeFs` calls `cp`, `rm` and `mkdir` use. `chattr` lives here
//! rather than beside `chmod` because it shares this file's option scanner, path handling and
//! error wording, and `chmod` has none of that to reuse.
//!
//! Wording: the Ubuntu persona answers as coreutils 8.32 does (`cannot touch 'x': ...`); the phone
//! answers in toybox's `tool: name: reason` form. Neither was recorded for these commands, so the
//! wording is [unverified] against the reference systems.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::trace::FsEffect;
use super::{
    CommandResult, FakeShell, HandlerId, ShellFlavor, budget_refusal_text, command_basename,
};
use crate::fakefs::{ATTR_APPEND_ONLY, ATTR_IMMUTABLE, AttrChange, FileKind, FsError};

pub(super) fn register(r: &mut Registry) {
    // Present on both personas, as `cp`, `rm` and `mkdir` are.
    r.register("touch", HandlerId::Touch, FakeShell::cmd_touch);
    r.register("mv", HandlerId::Mv, FakeShell::cmd_mv);
    r.register("ln", HandlerId::Ln, FakeShell::cmd_ln);
    r.register("rmdir", HandlerId::Rmdir, FakeShell::cmd_rmdir);
    // e2fsprogs: the phone has no such tool.
    r.register_if("chattr", ubuntu, HandlerId::Chattr, FakeShell::cmd_chattr);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// Directories a recursive move or `chattr -R` descends before giving up, so a deep tree built
/// in the overlay cannot grow the call stack.
const MAX_TREE_DEPTH: u32 = 24;

/// Nodes one `chattr -R` visits.
const MAX_WALK: u32 = 4096;

const NO_SUCH: &str = "No such file or directory";
const NO_SPACE: &str = "No space left on device";

/// One option a command accepts: its short letter (also the key the long names map to), and
/// whether it takes a value.
struct Opt {
    short: char,
    long: &'static [&'static str],
    value: bool,
}

impl Opt {
    const fn flag(short: char, long: &'static [&'static str]) -> Self {
        Self {
            short,
            long,
            value: false,
        }
    }

    const fn valued(short: char, long: &'static [&'static str]) -> Self {
        Self {
            short,
            long,
            value: true,
        }
    }
}

/// The options a command line carried, in order, and its operands.
struct Parsed<'a> {
    seen: Vec<(char, Option<&'a str>)>,
    operands: Vec<&'a str>,
}

impl<'a> Parsed<'a> {
    fn has(&self, short: char) -> bool {
        self.seen.iter().any(|(seen, _)| *seen == short)
    }

    fn value(&self, short: char) -> Option<&'a str> {
        self.seen
            .iter()
            .rev()
            .find(|(seen, _)| *seen == short)
            .and_then(|(_, value)| *value)
    }
}

/// Split `args` into options and operands, GNU style: options may follow operands, `--` ends them
/// and a lone `-` is an operand. Returns the tool's own error text for a bad option, or `None` for
/// `--help` and `--version`, which are not modeled.
fn scan<'a>(tool: &str, args: &[&'a str], spec: &[Opt]) -> Result<Option<Parsed<'a>>, String> {
    let try_help = format!("Try '{tool} --help' for more information.\n");
    let mut parsed = Parsed {
        seen: Vec::new(),
        operands: Vec::new(),
    };
    let mut ended = false;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if ended || arg == "-" || !arg.starts_with('-') {
            parsed.operands.push(arg);
        } else if arg == "--" {
            ended = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            if name == "help" || name == "version" {
                return Ok(None);
            }
            let Some(opt) = spec.iter().find(|opt| opt.long.contains(&name)) else {
                return Err(format!("{tool}: unrecognized option '{arg}'\n{try_help}"));
            };
            if opt.value {
                let value = match attached {
                    Some(value) => value,
                    None => {
                        let Some(&next) = args.get(i) else {
                            return Err(format!(
                                "{tool}: option '--{name}' requires an argument\n{try_help}"
                            ));
                        };
                        i = i.saturating_add(1);
                        next
                    }
                };
                parsed.seen.push((opt.short, Some(value)));
            } else if attached.is_some() {
                return Err(format!(
                    "{tool}: option '--{name}' doesn't allow an argument\n{try_help}"
                ));
            } else {
                parsed.seen.push((opt.short, None));
            }
        } else {
            let cluster = arg.get(1..).unwrap_or("");
            for (at, flag) in cluster.char_indices() {
                let Some(opt) = spec.iter().find(|opt| opt.short == flag) else {
                    return Err(format!("{tool}: invalid option -- '{flag}'\n{try_help}"));
                };
                if !opt.value {
                    parsed.seen.push((flag, None));
                    continue;
                }
                let attached = cluster
                    .get(at.saturating_add(flag.len_utf8())..)
                    .unwrap_or("");
                let value = if attached.is_empty() {
                    let Some(&next) = args.get(i) else {
                        return Err(format!(
                            "{tool}: option requires an argument -- '{flag}'\n{try_help}"
                        ));
                    };
                    i = i.saturating_add(1);
                    next
                } else {
                    attached
                };
                parsed.seen.push((flag, Some(value)));
                break;
            }
        }
    }
    Ok(Some(parsed))
}

const TOUCH_OPTS: &[Opt] = &[
    Opt::flag('c', &["no-create"]),
    Opt::flag('a', &[]),
    Opt::flag('m', &[]),
    Opt::flag('f', &[]),
    Opt::flag('h', &["no-dereference"]),
    Opt::valued('d', &["date"]),
    Opt::valued('t', &[]),
    Opt::valued('r', &["reference"]),
    Opt::valued('w', &["time"]),
];

const MV_OPTS: &[Opt] = &[
    Opt::flag('f', &["force"]),
    Opt::flag('n', &["no-clobber"]),
    Opt::flag('v', &["verbose"]),
    Opt::flag('i', &["interactive"]),
    Opt::flag('T', &["no-target-directory"]),
    Opt::flag('u', &["update"]),
    Opt::flag('b', &["backup"]),
    Opt::valued('t', &["target-directory"]),
    Opt::valued('S', &["suffix"]),
];

const LN_OPTS: &[Opt] = &[
    Opt::flag('s', &["symbolic"]),
    Opt::flag('f', &["force"]),
    Opt::flag('n', &["no-dereference"]),
    Opt::flag('v', &["verbose"]),
    Opt::flag('T', &["no-target-directory"]),
    Opt::flag('r', &["relative"]),
    Opt::flag('i', &["interactive"]),
    Opt::flag('b', &["backup"]),
    Opt::flag('L', &["logical"]),
    Opt::flag('P', &["physical"]),
    Opt::valued('t', &["target-directory"]),
    Opt::valued('S', &["suffix"]),
];

const RMDIR_OPTS: &[Opt] = &[
    Opt::flag('p', &["parents"]),
    Opt::flag('v', &["verbose"]),
    Opt::flag('I', &["ignore-fail-on-non-empty"]),
];

/// The kernel's wording for an error from the filesystem.
fn reason(error: &FsError) -> &'static str {
    match error {
        FsError::ReadOnly => "Read-only file system",
        FsError::Exists => "File exists",
        FsError::NotADirectory => "Not a directory",
        FsError::IsADirectory => "Is a directory",
        FsError::TooManyLinks => "Too many levels of symbolic links",
        other => budget_refusal_text(other).unwrap_or(NO_SUCH),
    }
}

/// The last component of `text`, trailing slashes dropped; empty for `/` and for nothing.
fn base_of(text: &str) -> &str {
    command_basename(text.trim_end_matches('/'))
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

/// `text` without its last component, or `None` when it has no directory part left (`rmdir -p`).
fn parent_text(text: &str) -> Option<&str> {
    let trimmed = text.trim_end_matches('/');
    let cut = trimmed.rfind('/')?;
    let parent = trimmed.get(..cut)?.trim_end_matches('/');
    if parent.is_empty() {
        None
    } else {
        Some(parent)
    }
}

fn missing_operand(tool: &str, after: Option<&str>) -> CommandResult {
    let what = match after {
        Some(name) => format!("missing destination file operand after '{name}'"),
        None => "missing file operand".to_string(),
    };
    CommandResult::stderr(
        1,
        format!("{tool}: {what}\nTry '{tool} --help' for more information.\n"),
    )
}

/// What a command wrote: its standard output, then its errors, with status 1 when it complained.
fn finish(out: String, err: String) -> CommandResult {
    let mut result = CommandResult::silent(0);
    if !out.is_empty() {
        result.append(CommandResult::stdout(out));
    }
    if !err.is_empty() {
        result.append(CommandResult::stderr(1, err));
    }
    result
}

impl FakeShell {
    /// One error line: coreutils' `tool: what 'name': reason`, or toybox's `tool: name: reason`.
    fn fault(&self, tool: &str, gnu: &str, raw: &str, why: &str) -> String {
        if self.flavor == ShellFlavor::AndroidSh {
            format!("{tool}: {raw}: {why}\n")
        } else {
            format!("{tool}: {gnu}: {why}\n")
        }
    }

    pub(super) fn traced_symlink(&mut self, path: &str, target: &str) -> Result<(), FsError> {
        let result = self.fs.create_symlink(path, target);
        match &result {
            Ok(()) => self.trace_fs(FsEffect::Created {
                path: path.to_string(),
                bytes: target.len(),
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    /// `touch [-c] FILE...`. A missing file is created empty in the overlay, by the call a
    /// redirection uses, so every refusal is the same. An existing file is left as it is: no
    /// modification time is modeled, so `-a`, `-m`, `-d`, `-t` and `-r` are accepted and ignored.
    pub(super) fn cmd_touch(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let parsed = match scan("touch", args, TOUCH_OPTS) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        if parsed.operands.is_empty() {
            return missing_operand("touch", None);
        }
        let create = !parsed.has('c');
        let mut err = String::new();
        for &name in &parsed.operands {
            // `touch -` is the standard output, not a file.
            if name == "-" {
                continue;
            }
            let path = self.resolve_logical(name);
            let gnu = format!("cannot touch '{name}'");
            match self.fs.stat(&path, true) {
                Some(stat) if stat.read_only => {
                    err.push_str(&self.fault("touch", &gnu, name, "Read-only file system"));
                }
                Some(_) => {}
                None if !create => {}
                None => {
                    if let Err(error) = self.traced_create(&path) {
                        err.push_str(&self.fault("touch", &gnu, name, reason(&error)));
                    }
                }
            }
        }
        finish(String::new(), err)
    }

    /// `rmdir [-pv] DIR...`: only an empty directory goes. `-p` then tries each parent named in
    /// the operand.
    pub(super) fn cmd_rmdir(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let parsed = match scan("rmdir", args, RMDIR_OPTS) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        if parsed.operands.is_empty() {
            return missing_operand("rmdir", None);
        }
        let parents = parsed.has('p');
        let verbose = parsed.has('v');
        let ignore_non_empty = parsed.has('I');
        let mut out = String::new();
        let mut err = String::new();
        for &operand in &parsed.operands {
            let mut current = operand;
            let mut first = true;
            loop {
                match self.remove_empty_dir(current) {
                    Ok(()) => {
                        if verbose {
                            out.push_str(&format!("rmdir: removing directory, '{current}'\n"));
                        }
                    }
                    Err("Directory not empty") if ignore_non_empty => break,
                    Err(why) => {
                        let verb = if first {
                            "failed to remove"
                        } else {
                            "failed to remove directory"
                        };
                        let gnu = format!("{verb} '{current}'");
                        err.push_str(&self.fault("rmdir", &gnu, current, why));
                        break;
                    }
                }
                first = false;
                match parent_text(current) {
                    Some(parent) if parents => current = parent,
                    _ => break,
                }
            }
        }
        finish(out, err)
    }

    /// Remove the directory `text` names if it is empty; the refusal's kernel wording if not.
    fn remove_empty_dir(&mut self, text: &str) -> Result<(), &'static str> {
        let path = self.resolve_logical(text);
        let Some(stat) = self.fs.stat(&path, false) else {
            return Err(NO_SUCH);
        };
        if stat.kind != FileKind::Directory {
            return Err("Not a directory");
        }
        if stat.read_only {
            return Err("Read-only file system");
        }
        if self
            .fs
            .list_dir(&path)
            .is_some_and(|names| !names.is_empty())
        {
            return Err("Directory not empty");
        }
        self.traced_remove(&path)
            .map(|_| ())
            .map_err(|error| reason(&error))
    }

    /// `ln [-sfnvT] TARGET [LINK]`, `ln [-sf] TARGET... DIR` and `ln -t DIR TARGET...`.
    ///
    /// A symbolic link stores its target text as typed and resolves nothing at creation. The
    /// model has no inode sharing, so a hard link is a second node holding a copy of the bytes
    /// (a later write to one does not show in the other). `-r`, `-b`, `-S`, `-i`, `-L` and `-P`
    /// are accepted and ignored.
    pub(super) fn cmd_ln(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let parsed = match scan("ln", args, LN_OPTS) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        let opts = LnOpts {
            symbolic: parsed.has('s'),
            force: parsed.has('f'),
            verbose: parsed.has('v'),
        };
        let mut operands = parsed.operands.clone();
        // The names to link, and where: a directory every link goes into, or the one link name.
        let (targets, into, link) = if let Some(dir) = parsed.value('t') {
            if operands.is_empty() {
                return missing_operand("ln", None);
            }
            (operands, Some(dir), None)
        } else {
            let dest = match operands.len() {
                0 => return missing_operand("ln", None),
                1 => None,
                _ => operands.pop(),
            };
            let Some(dest) = dest else {
                let single = operands.first().copied().unwrap_or("");
                return self.link_all(&operands, None, Some(base_of(single)), opts);
            };
            if parsed.has('T') {
                if let Some(extra) = operands.get(1) {
                    return CommandResult::stderr(
                        1,
                        format!(
                            "ln: extra operand '{extra}'\nTry 'ln --help' for more information.\n"
                        ),
                    );
                }
                (operands, None, Some(dest))
            } else {
                let dest_path = self.resolve_logical(dest);
                let is_dir = if parsed.has('n')
                    && self
                        .fs
                        .stat(&dest_path, false)
                        .is_some_and(|stat| stat.kind == FileKind::Symlink)
                {
                    false
                } else {
                    self.fs.is_dir(&dest_path)
                };
                if is_dir {
                    (operands, Some(dest), None)
                } else if operands.len() > 1 {
                    let why = if self.fs.stat(&dest_path, true).is_some() {
                        "Not a directory"
                    } else {
                        NO_SUCH
                    };
                    let gnu = format!("target '{dest}'");
                    return CommandResult::stderr(1, self.fault("ln", &gnu, dest, why));
                } else {
                    (operands, None, Some(dest))
                }
            }
        };
        if let Some(dir) = into {
            let dir_path = self.resolve_logical(dir);
            if !self.fs.is_dir(&dir_path) {
                let why = if self.fs.stat(&dir_path, true).is_some() {
                    "Not a directory"
                } else {
                    NO_SUCH
                };
                let gnu = format!("target '{dir}'");
                return CommandResult::stderr(1, self.fault("ln", &gnu, dir, why));
            }
        }
        self.link_all(&targets, into, link, opts)
    }

    fn link_all(
        &mut self,
        targets: &[&str],
        into: Option<&str>,
        link: Option<&str>,
        opts: LnOpts,
    ) -> CommandResult {
        let mut out = String::new();
        let mut err = String::new();
        for &target in targets {
            let name = match (into, link) {
                (Some(dir), _) => join(dir, base_of(target)),
                (None, Some(link)) => link.to_string(),
                (None, None) => continue,
            };
            match self.link_one(target, &name, opts) {
                Ok(()) if opts.verbose => {
                    let arrow = if opts.symbolic { "->" } else { "=>" };
                    out.push_str(&format!("'{name}' {arrow} '{target}'\n"));
                }
                Ok(()) => {}
                Err(line) => err.push_str(&line),
            }
        }
        finish(out, err)
    }

    /// Make the link `name` to `target`; the whole error line when it cannot be made.
    fn link_one(&mut self, target: &str, name: &str, opts: LnOpts) -> Result<(), String> {
        let link_path = self.resolve_logical(name);
        let gnu = if opts.symbolic {
            format!("failed to create symbolic link '{name}'")
        } else {
            format!("failed to create hard link '{name}' => '{target}'")
        };
        let made = |shell: &Self, why: &str| shell.fault("ln", &gnu, name, why);
        let source_path = self.resolve_logical(target);
        let source = if opts.symbolic {
            None
        } else {
            let Some(stat) = self.fs.stat(&source_path, false) else {
                let gnu = format!("failed to access '{target}'");
                return Err(self.fault("ln", &gnu, target, NO_SUCH));
            };
            if stat.kind == FileKind::Directory {
                let gnu = format!("'{target}'");
                return Err(self.fault("ln", &gnu, target, "hard link not allowed for directory"));
            }
            Some(stat)
        };
        if let Some(existing) = self.fs.stat(&link_path, false) {
            if source
                .as_ref()
                .is_some_and(|s| s.physical == existing.physical)
            {
                let line = format!("ln: '{name}' and '{target}' are the same file\n");
                return Err(line);
            }
            if !opts.force {
                return Err(made(self, "File exists"));
            }
            if existing.kind == FileKind::Directory {
                let line = format!("ln: {name}: cannot overwrite directory\n");
                return Err(line);
            }
            if let Err(error) = self.traced_remove(&link_path) {
                return Err(made(self, reason(&error)));
            }
        }
        let created = match source {
            None => self.traced_symlink(&link_path, target),
            Some(stat) if stat.kind == FileKind::Symlink => {
                let held = self.fs.link_target(&source_path).unwrap_or_default();
                self.traced_symlink(&link_path, &held)
            }
            Some(_) => match self.fs.content_and_mode(&source_path) {
                Ok((blob, mode)) => self.traced_write_blob(&link_path, blob, mode),
                Err(error) => Err(error),
            },
        };
        created.map_err(|error| made(self, reason(&error)))
    }

    /// `mv [-fnvT] SRC DEST`, `mv SRC... DIR` and `mv -t DIR SRC...`, inside the overlay. A
    /// baked file is copied into the overlay at its new name and the old name is removed (a
    /// tombstone), so it is gone from `ls` and `cat`. Directories move with their contents.
    /// `-i`, `-u`, `-b` and `-S` are accepted and ignored; `-n` skips an existing name quietly.
    pub(super) fn cmd_mv(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let parsed = match scan("mv", args, MV_OPTS) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return CommandResult::silent(0),
            Err(text) => return CommandResult::stderr(1, text),
        };
        let mut sources = parsed.operands.clone();
        let dest = if let Some(dir) = parsed.value('t') {
            if sources.is_empty() {
                return missing_operand("mv", None);
            }
            dir
        } else {
            match sources.len() {
                0 => return missing_operand("mv", None),
                1 => return missing_operand("mv", sources.first().copied()),
                _ => match sources.pop() {
                    Some(dest) => dest,
                    None => return missing_operand("mv", None),
                },
            }
        };
        let dest_path = self.resolve_logical(dest);
        let dest_is_dir = !parsed.has('T') && self.fs.is_dir(&dest_path);
        let wants_dir = parsed.value('t').is_some() || sources.len() > 1;
        if parsed.has('T') && sources.len() > 1 {
            let extra = sources.get(1).copied().unwrap_or("");
            return CommandResult::stderr(
                1,
                format!("mv: extra operand '{extra}'\nTry 'mv --help' for more information.\n"),
            );
        }
        if wants_dir && !dest_is_dir {
            let gnu = format!("target '{dest}'");
            return CommandResult::stderr(1, self.fault("mv", &gnu, dest, "Not a directory"));
        }
        let verbose = parsed.has('v');
        let no_clobber = parsed.has('n');
        let mut out = String::new();
        let mut err = String::new();
        for &src in &sources {
            let src_path = self.resolve_logical(src);
            let (dst, dst_path) = if dest_is_dir {
                let base = base_of(src);
                if base.is_empty() {
                    let gnu = format!("cannot move '{src}' to '{dest}'");
                    err.push_str(&self.fault("mv", &gnu, src, "Device or resource busy"));
                    continue;
                }
                (join(dest, base), join(&dest_path, base))
            } else {
                (dest.to_string(), dest_path.clone())
            };
            match self.move_one(src, &dst, &src_path, &dst_path, no_clobber) {
                Ok(true) if verbose => out.push_str(&format!("renamed '{src}' -> '{dst}'\n")),
                Ok(_) => {}
                Err(line) => err.push_str(&line),
            }
        }
        finish(out, err)
    }

    /// Move `src_path` to `dst_path`. `Ok(false)` when `-n` left an existing name alone; the
    /// whole error line when the move is refused.
    fn move_one(
        &mut self,
        src: &str,
        dst: &str,
        src_path: &str,
        dst_path: &str,
        no_clobber: bool,
    ) -> Result<bool, String> {
        let Some(from) = self.fs.stat(src_path, false) else {
            let gnu = format!("cannot stat '{src}'");
            return Err(self.fault("mv", &gnu, src, NO_SUCH));
        };
        let moving = format!("cannot move '{src}' to '{dst}'");
        let to = self.fs.stat(dst_path, false);
        let from_dir = from.kind == FileKind::Directory;
        if let Some(to) = &to {
            if to.physical == from.physical {
                return Err(format!("mv: '{src}' and '{dst}' are the same file\n"));
            }
            if no_clobber {
                return Ok(false);
            }
            let to_dir = to.kind == FileKind::Directory;
            if to_dir && !from_dir {
                return Err(format!(
                    "mv: cannot overwrite directory '{dst}' with non-directory\n"
                ));
            }
            if from_dir && !to_dir {
                return Err(format!(
                    "mv: cannot overwrite non-directory '{dst}' with directory '{src}'\n"
                ));
            }
            if to_dir
                && self
                    .fs
                    .list_dir(dst_path)
                    .is_some_and(|names| !names.is_empty())
            {
                return Err(self.fault("mv", &moving, src, "Directory not empty"));
            }
        }
        let inside = format!("{}/", src_path.trim_end_matches('/'));
        if from_dir && (dst_path == src_path || dst_path.starts_with(&inside)) {
            return Err(format!(
                "mv: cannot move '{src}' to a subdirectory of itself, '{dst}'\n"
            ));
        }
        if from.read_only {
            return Err(self.fault("mv", &moving, src, "Read-only file system"));
        }
        if let Some(to) = &to
            && to.kind != FileKind::Directory
            && let Err(error) = self.traced_remove(dst_path)
        {
            return Err(self.fault("mv", &moving, src, reason(&error)));
        }
        let moved = if from_dir {
            self.move_tree(src_path, dst_path, 0)
        } else {
            self.copy_leaf(src_path, dst_path, from.kind)
                .and_then(|()| {
                    self.traced_remove(src_path)
                        .map(|_| ())
                        .map_err(|error| reason(&error))
                })
        };
        moved
            .map(|()| true)
            .map_err(|why| self.fault("mv", &moving, src, why))
    }

    /// A regular file or symlink at `src_path` as a new node at `dst_path`.
    fn copy_leaf(
        &mut self,
        src_path: &str,
        dst_path: &str,
        kind: FileKind,
    ) -> Result<(), &'static str> {
        match kind {
            FileKind::Regular => {
                let (blob, mode) = self
                    .fs
                    .content_and_mode(src_path)
                    .map_err(|error| reason(&error))?;
                self.traced_write_blob(dst_path, blob, mode)
                    .map_err(|error| reason(&error))?;
                self.copy_origin(src_path, dst_path);
                Ok(())
            }
            FileKind::Symlink => {
                let held = self.fs.link_target(src_path).ok_or(NO_SUCH)?;
                self.traced_symlink(dst_path, &held)
                    .map_err(|error| reason(&error))
            }
            FileKind::Directory | FileKind::CharDevice => Err("Operation not permitted"),
        }
    }

    /// Re-create the directory `src_path` and everything under it at `dst_path`, then remove the
    /// old tree. The node and byte budget stops a tree the connection has no room for, and the
    /// depth and line-work caps stop a deep one.
    fn move_tree(
        &mut self,
        src_path: &str,
        dst_path: &str,
        depth: u32,
    ) -> Result<(), &'static str> {
        if depth > MAX_TREE_DEPTH || !self.charge_work(1) {
            return Err(NO_SPACE);
        }
        match self.traced_make_dir(dst_path) {
            Ok(()) => {}
            Err(FsError::Exists) if self.fs.is_dir(dst_path) => {}
            Err(error) => return Err(reason(&error)),
        }
        let children = self.fs.list_dir(src_path).unwrap_or_default();
        for child in children {
            let from = join(src_path, &child);
            let to = join(dst_path, &child);
            match self.fs.stat(&from, false).map(|stat| stat.kind) {
                Some(FileKind::Directory) => {
                    self.move_tree(&from, &to, depth.saturating_add(1))?;
                }
                Some(kind) => self.copy_leaf(&from, &to, kind)?,
                None => {}
            }
        }
        self.traced_remove(src_path)
            .map(|_| ())
            .map_err(|error| reason(&error))
    }

    /// `chattr [-RVf] [+-=MODE]... FILE...`: the ext2 attribute letters, kept as stored bits on
    /// the overlay's nodes (`FakeFs::change_attrs`). Nothing here reaches a host attribute.
    /// Every standard letter is accepted; the bits are stored only, and no write, `rm` or `mv`
    /// consults `i` or `a` yet, so an immutable file is still replaceable.
    pub(super) fn cmd_chattr(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let usage = || {
            CommandResult::stderr(
                1,
                "Usage: chattr [-pRVf] [-+=aAcCdDeFijPsStTu] [-v version] files...\n",
            )
        };
        let mut changes: Vec<(AttrChange, u32)> = Vec::new();
        let mut files: Vec<&str> = Vec::new();
        let (mut recursive, mut quiet, mut ended) = (false, false, false);
        let mut i = 0usize;
        while let Some(&arg) = args.get(i) {
            i = i.saturating_add(1);
            let sign = arg.chars().next();
            let letters = arg.get(1..).unwrap_or("");
            if ended || arg == "-" || !matches!(sign, Some('-' | '+' | '=')) {
                files.push(arg);
                continue;
            }
            if arg == "--" {
                ended = true;
                continue;
            }
            if sign == Some('-')
                && !letters.is_empty()
                && letters.chars().all(|c| "RVfvp".contains(c))
            {
                for flag in letters.chars() {
                    match flag {
                        'R' => recursive = true,
                        'f' => quiet = true,
                        // `-v VERSION` and `-p PROJECT` take a value that no node here keeps.
                        'v' | 'p' => i = i.saturating_add(1),
                        _ => {}
                    }
                }
                continue;
            }
            let mut bits = 0u32;
            for letter in letters.chars() {
                let Some(bit) = attr_bit(letter) else {
                    return usage();
                };
                bits |= bit;
            }
            let change = match sign {
                Some('+') => AttrChange::Add,
                Some('-') => AttrChange::Remove,
                _ => AttrChange::Replace,
            };
            changes.push((change, bits));
        }
        if changes.is_empty() || files.is_empty() {
            return usage();
        }
        let mut err = String::new();
        let mut visited = 0u32;
        for name in files {
            let path = self.resolve_logical(name);
            self.chattr_walk(
                name,
                &path,
                &changes,
                recursive,
                (0, &mut visited),
                &mut err,
            );
        }
        if quiet && !err.is_empty() {
            return CommandResult::silent(1);
        }
        finish(String::new(), err)
    }

    /// Apply `changes` to `path`, then, for `-R`, to what is under it.
    fn chattr_walk(
        &mut self,
        name: &str,
        path: &str,
        changes: &[(AttrChange, u32)],
        recursive: bool,
        (depth, visited): (u32, &mut u32),
        err: &mut String,
    ) {
        *visited = visited.saturating_add(1);
        if *visited > MAX_WALK || !self.charge_work(1) {
            return;
        }
        for &(change, bits) in changes {
            if let Err(error) = self.fs.change_attrs(path, change, bits) {
                let line = match error {
                    FsError::NoSuchFile | FsError::NoSuchDirectory(_) => {
                        format!("chattr: {NO_SUCH} while trying to stat {name}\n")
                    }
                    other => format!("chattr: {} while setting flags on {name}\n", reason(&other)),
                };
                err.push_str(&line);
                return;
            }
        }
        let is_dir = self
            .fs
            .stat(path, false)
            .is_some_and(|stat| stat.kind == FileKind::Directory);
        if !(recursive && is_dir) || depth > MAX_TREE_DEPTH {
            return;
        }
        for child in self.fs.list_dir(path).unwrap_or_default() {
            let deeper = (depth.saturating_add(1), &mut *visited);
            self.chattr_walk(
                &join(name, &child),
                &join(path, &child),
                changes,
                recursive,
                deeper,
                err,
            );
        }
    }
}

#[derive(Clone, Copy)]
struct LnOpts {
    symbolic: bool,
    force: bool,
    verbose: bool,
}

/// The stored bit of one `chattr` letter, with the kernel's `FS_*_FL` values.
fn attr_bit(letter: char) -> Option<u32> {
    Some(match letter {
        'i' => ATTR_IMMUTABLE,
        'a' => ATTR_APPEND_ONLY,
        's' => 0x0000_0001,
        'u' => 0x0000_0002,
        'c' => 0x0000_0004,
        'S' => 0x0000_0008,
        'd' => 0x0000_0040,
        'A' => 0x0000_0080,
        'j' => 0x0000_4000,
        't' => 0x0000_8000,
        'D' => 0x0001_0000,
        'T' => 0x0002_0000,
        'e' => 0x0008_0000,
        'C' => 0x0080_0000,
        'P' => 0x2000_0000,
        'F' => 0x4000_0000,
        _ => return None,
    })
}
