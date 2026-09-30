//! The byte readers: `cat`, `head`, `more` and `hexdump`. Each reads the modeled bytes of a file
//! (or its standard input) and writes them back untouched: no text framing is added over binary,
//! so `cat /bin/ls | head -n 1` is the image up to and including its first `0x0a`, exactly as the
//! pty capture shows.
//!
//! Every read is bounded by the per-line work allowance, so a reader of a 2 MiB image or of
//! `/dev/zero` cannot hand back more than one allowance, and the line stops once its output has
//! spent what it had. Direct and BusyBox forms share these handlers: `/bin/busybox head` and
//! `head` resolve to the same registry entry.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::FsError;

/// How much of a file `head -n` asks the filesystem for at a time, so it stops reading at the
/// Nth newline instead of materializing the whole image.
const CHUNK: u64 = 4096;

/// The one `hexdump -e` format modeled: each byte as a raw character. Any other format is not
/// interpreted; see [`FakeShell::cmd_hexdump`].
const HEXDUMP_RAW_FORMAT: &str = "16/1 \"%c\"";

pub(super) fn register(r: &mut Registry) {
    r.register("cat", HandlerId::Cat, FakeShell::cmd_cat);
    // The phone's toolbox has no recorded answer for these, and it answers "not found" today.
    r.register_if("head", ubuntu, HandlerId::Head, FakeShell::cmd_head);
    r.register_if("more", ubuntu, HandlerId::More, FakeShell::cmd_more);
    r.register_if(
        "hexdump",
        ubuntu,
        HandlerId::Hexdump,
        FakeShell::cmd_hexdump,
    );
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// The window `[off, off + limit)` of `bytes`.
fn window(bytes: Vec<u8>, off: u64, limit: u64) -> Vec<u8> {
    let from = usize::try_from(off).unwrap_or(usize::MAX);
    let take = usize::try_from(limit).unwrap_or(usize::MAX);
    bytes
        .get(from..)
        .map(|rest| rest.iter().copied().take(take).collect())
        .unwrap_or_default()
}

fn errno_text(error: &FsError) -> &'static str {
    match error {
        FsError::IsADirectory => "Is a directory",
        _ => "No such file or directory",
    }
}

/// The operands of a command that concatenates files. `-` is standard input, `--` ends the
/// flags, and any other word starting with `-` (or `+` when `plus_flags`, for `more +N`) is a
/// flag this shell has no use for.
fn concat_operands<'a>(args: &[&'a str], plus_flags: bool) -> Vec<&'a str> {
    let mut ended = false;
    let mut operands = Vec::new();
    for &arg in args {
        if !ended && arg == "--" {
            ended = true;
            continue;
        }
        let flag =
            !ended && arg != "-" && (arg.starts_with('-') || (plus_flags && arg.starts_with('+')));
        if !flag {
            operands.push(arg);
        }
    }
    operands
}

#[derive(Clone, Copy)]
enum Tool {
    Cat,
    More,
}

impl FakeShell {
    /// Up to `limit` bytes of `path` from `off`, read by the process whose argv is `argv`: that
    /// process is what `/proc/self` names, so `/proc/self/exe` is its executable and
    /// `/proc/self/cmdline` its own argument vector (NUL-separated with a trailing NUL, no
    /// newline, as the kernel returns it). A missing `cmdline` is a classic honeypot tell that
    /// loaders check before delivering a payload. The shell's own `/proc/<pid>/cmdline` is the
    /// shell's argv.
    fn read_operand(
        &mut self,
        argv: &[&str],
        path: &str,
        off: u64,
        limit: u64,
    ) -> Result<Vec<u8>, FsError> {
        let own_cmdline = format!("/proc/{}/cmdline", self.state().pid);
        let typed = self.normalize_logical(path);
        if typed == "/proc/self/cmdline" {
            let mut out = argv.join("\0");
            out.push('\0');
            return Ok(window(out.into_bytes(), off, limit));
        }
        if typed == own_cmdline {
            let out = format!("{}\0", self.argv_zero());
            return Ok(window(out.into_bytes(), off, limit));
        }
        let reader = self.reader_of(argv.first().copied().unwrap_or("cat"));
        let resolved = self.resolve_reading(path, Some(reader));
        self.fs.read_range(&resolved, off, limit)
    }

    /// The most one read hands back: the line's whole allowance, as it always bounded a modeled
    /// image (busybox is 2 MiB, past `READ_CAP`). The bytes are charged to the line by the
    /// evaluator once the command returns, and a command reading several operands stops taking
    /// more once what it has already produced spent what the line had left.
    fn read_cap(&self) -> u64 {
        self.budget().limits().work_per_line
    }

    /// `cat`: every operand in order, standard input for `-` or no operand.
    pub(super) fn cmd_cat(&mut self, parts: &[&str]) -> CommandResult {
        let operands = concat_operands(parts.get(1..).unwrap_or(&[]), false);
        self.concatenate(parts, &operands, Tool::Cat)
    }

    /// `more`. Standard output here is never a terminal the shell can measure, so it copies its
    /// input through as `cat` does, which is what `more` does when its output is not a tty.
    ///
    /// TODO(terminal model): on a Telnet or SSH pty the real `more` is interactive: it pages the
    /// input at the session's rows, stops at `--More--` and reads the NEXT input line as its
    /// keystrokes (`No previous regular expression`, `Line too long`, `Pattern not found`, then
    /// the typed remainder reaches the shell). That needs a terminal rows input the shell does
    /// not have yet (pty README finding 6; S9/S10 spec blocker 3). Until then a recorded chain
    /// that pipes into `more` on a pty diverges from line one after it.
    pub(super) fn cmd_more(&mut self, parts: &[&str]) -> CommandResult {
        let operands = concat_operands(parts.get(1..).unwrap_or(&[]), true);
        self.concatenate(parts, &operands, Tool::More)
    }

    fn concatenate(&mut self, parts: &[&str], operands: &[&str], tool: Tool) -> CommandResult {
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        let cap = self.read_cap();
        let mut left = self.line.remaining();
        let sources: Vec<&str> = if operands.is_empty() {
            vec!["-"]
        } else {
            operands.to_vec()
        };
        for path in sources {
            if left == 0 {
                break;
            }
            let read = if path == "-" {
                Ok(self.stdin.take(cap))
            } else {
                self.read_operand(parts, path, 0, cap)
            };
            match (read, tool) {
                (Ok(bytes), _) => {
                    left = left.saturating_sub(len_u64(bytes.len()));
                    acc.append(CommandResult::stdout(bytes));
                }
                (Err(FsError::IsADirectory), Tool::More) => {
                    // [unverified] util-linux's wording, not captured.
                    acc.append(CommandResult::stdout(format!(
                        "\n*** {path}: directory ***\n\n"
                    )));
                }
                (Err(error), Tool::More) => {
                    failed = true;
                    // [unverified] util-linux's wording, not captured.
                    acc.append(CommandResult::stderr(
                        1,
                        format!("more: cannot open {path}: {}\n", errno_text(&error)),
                    ));
                }
                (Err(error), Tool::Cat) => {
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!("cat: {path}: {}\n", errno_text(&error)),
                    ));
                }
            }
        }
        acc.status = u8::from(failed);
        acc
    }

    /// `head`: the first N lines (`-n`, default 10) or bytes (`-c`) of standard input or of each
    /// file operand. Lines are `\n`-terminated, the newline is part of the line, and a final
    /// unterminated line is emitted as it is. A negative count (`-n -5`) is all but the last N.
    pub(super) fn cmd_head(&mut self, parts: &[&str]) -> CommandResult {
        let args = match parse_head(parts.get(1..).unwrap_or(&[])) {
            Ok(args) => args,
            Err(text) => return CommandResult::stderr(1, text),
        };
        let busybox = self.busybox_depth > 0;
        let sources: Vec<&str> = if args.files.is_empty() {
            vec!["-"]
        } else {
            args.files.clone()
        };
        let headers = args.verbose || (sources.len() > 1 && !args.quiet);
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        let mut printed_header = false;
        let cap = self.read_cap();
        let mut left = self.line.remaining();
        for path in sources {
            if left == 0 {
                break;
            }
            let read = if path == "-" {
                Ok(self.head_stdin(&args, cap))
            } else {
                self.head_file(parts, path, &args, cap)
            };
            match read {
                Ok(bytes) => {
                    if headers {
                        let name = if path == "-" { "standard input" } else { path };
                        let lead = if printed_header { "\n" } else { "" };
                        let header = format!("{lead}==> {name} <==\n");
                        left = left.saturating_sub(len_u64(header.len()));
                        acc.append(CommandResult::stdout(header));
                        printed_header = true;
                    }
                    left = left.saturating_sub(len_u64(bytes.len()));
                    acc.append(CommandResult::stdout(bytes));
                }
                Err(error) => {
                    failed = true;
                    // [unverified] the BusyBox wording for a directory, and GNU's exact quoting
                    // under a UTF-8 locale; the missing-file forms are the tools' own.
                    let text = match (&error, busybox) {
                        (FsError::IsADirectory, false) => {
                            format!("head: error reading '{path}': Is a directory\n")
                        }
                        (_, false) => format!(
                            "head: cannot open '{path}' for reading: {}\n",
                            errno_text(&error)
                        ),
                        (_, true) => format!("head: {path}: {}\n", errno_text(&error)),
                    };
                    acc.append(CommandResult::stderr(1, text));
                }
            }
        }
        acc.status = u8::from(failed);
        acc
    }

    fn head_stdin(&mut self, args: &HeadArgs<'_>, cap: u64) -> Vec<u8> {
        match (args.unit, args.count.all_but_last) {
            (Unit::Bytes, false) => self.stdin.take(args.count.n.min(cap)),
            (Unit::Lines, false) => {
                let mut out = Vec::new();
                for _ in 0..args.count.n {
                    if len_u64(out.len()) >= cap {
                        break;
                    }
                    let Some((line, ended)) = self.stdin.read_line() else {
                        break;
                    };
                    out.extend_from_slice(&line);
                    if ended {
                        out.push(b'\n');
                    }
                }
                out.truncate(clamp(cap));
                out
            }
            (unit, true) => without_last(self.stdin.take_rest(), unit, args.count.n),
        }
    }

    fn head_file(
        &mut self,
        argv: &[&str],
        path: &str,
        args: &HeadArgs<'_>,
        cap: u64,
    ) -> Result<Vec<u8>, FsError> {
        match (args.unit, args.count.all_but_last) {
            (Unit::Bytes, false) => self.read_operand(argv, path, 0, args.count.n.min(cap)),
            (Unit::Lines, false) => {
                // Asked for nothing, it still has to find out whether the file opens.
                let mut out = Vec::new();
                if args.count.n == 0 {
                    self.read_operand(argv, path, 0, 0)?;
                    return Ok(out);
                }
                let mut newlines = 0u64;
                loop {
                    let room = cap.saturating_sub(len_u64(out.len()));
                    if room == 0 {
                        break;
                    }
                    let chunk =
                        self.read_operand(argv, path, len_u64(out.len()), CHUNK.min(room))?;
                    if chunk.is_empty() {
                        break;
                    }
                    let mut end = chunk.len();
                    for (at, byte) in chunk.iter().enumerate() {
                        if *byte == b'\n' {
                            newlines = newlines.saturating_add(1);
                            if newlines == args.count.n {
                                end = at.saturating_add(1);
                                break;
                            }
                        }
                    }
                    out.extend(chunk.into_iter().take(end));
                    if newlines == args.count.n {
                        break;
                    }
                }
                Ok(out)
            }
            (unit, true) => {
                let all = self.read_operand(argv, path, 0, cap)?;
                Ok(without_last(all, unit, args.count.n))
            }
        }
    }

    /// `hexdump`, for the one form the recorded loaders run: `-e '16/1 "%c"'` with an optional
    /// `-n LENGTH`, which prints the bytes raw with no offset column and no trailing newline.
    /// That exact format is recognized, not interpreted. Any other format or option (or input
    /// the real tool would squeeze into a `*` line) is not modeled: it prints nothing and
    /// succeeds, never a dump this shell made up.
    pub(super) fn cmd_hexdump(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_hexdump(parts.get(1..).unwrap_or(&[])) else {
            return CommandResult::silent(0);
        };
        let want = plan.length.unwrap_or(u64::MAX).min(self.read_cap());
        let sources: Vec<&str> = if plan.files.is_empty() {
            vec!["-"]
        } else {
            plan.files.clone()
        };
        let mut data: Vec<u8> = Vec::new();
        let mut errors = CommandResult::silent(0);
        let mut failed = false;
        for path in sources {
            let room = want.saturating_sub(len_u64(data.len()));
            let read = if path == "-" {
                Ok(self.stdin.take(room))
            } else {
                self.read_operand(parts, path, 0, room)
            };
            match read {
                Ok(bytes) => data.extend(bytes),
                Err(error) => {
                    failed = true;
                    errors.append(CommandResult::stderr(
                        1,
                        format!("hexdump: {path}: {}\n", errno_text(&error)),
                    ));
                }
            }
        }
        // Without `-v` the real tool replaces a run of identical 16-byte groups by `*`.
        if !plan.verbose && repeats_a_group(&data) {
            return CommandResult::silent(0);
        }
        let mut acc = CommandResult::stdout(data);
        acc.append(errors);
        acc.status = u8::from(failed);
        acc
    }
}

fn clamp(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Whether two consecutive full 16-byte groups of `data` are identical.
fn repeats_a_group(data: &[u8]) -> bool {
    let mut groups = data.chunks_exact(16);
    let mut previous = groups.next();
    for group in groups {
        if previous == Some(group) {
            return true;
        }
        previous = Some(group);
    }
    false
}

struct HexdumpPlan<'a> {
    length: Option<u64>,
    files: Vec<&'a str>,
    verbose: bool,
}

/// The plan for a `hexdump` command line, or `None` when it is anything but the raw-character
/// format with (at most) `-n`, `-v` and file operands.
fn parse_hexdump<'a>(args: &[&'a str]) -> Option<HexdumpPlan<'a>> {
    let mut plan = HexdumpPlan {
        length: None,
        files: Vec::new(),
        verbose: false,
    };
    let mut formats = 0u32;
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
            continue;
        }
        if arg == "--" {
            options = false;
        } else if arg == "-v" {
            plan.verbose = true;
        } else if let Some(attached) = arg.strip_prefix("-e") {
            let format = if attached.is_empty() {
                let next = args.get(i).copied()?;
                i = i.saturating_add(1);
                next
            } else {
                attached
            };
            if format != HEXDUMP_RAW_FORMAT {
                return None;
            }
            formats = formats.saturating_add(1);
        } else if let Some(attached) = arg.strip_prefix("-n") {
            let text = if attached.is_empty() {
                let next = args.get(i).copied()?;
                i = i.saturating_add(1);
                next
            } else {
                attached
            };
            plan.length = Some(parse_plain_number(text)?);
        } else {
            return None;
        }
    }
    (formats == 1).then_some(plan)
}

fn parse_plain_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[derive(Clone, Copy)]
enum Unit {
    Lines,
    Bytes,
}

#[derive(Clone, Copy)]
struct Count {
    n: u64,
    /// `-n -5`: everything except the last `n`.
    all_but_last: bool,
}

struct HeadArgs<'a> {
    unit: Unit,
    count: Count,
    files: Vec<&'a str>,
    quiet: bool,
    verbose: bool,
}

const HEAD_TRY: &str = "Try 'head --help' for more information.\n";

fn head_count(text: &str, unit: Unit) -> Result<Count, String> {
    let bad = || {
        let what = match unit {
            Unit::Lines => "lines",
            Unit::Bytes => "bytes",
        };
        format!("head: invalid number of {what}: '{text}'\n")
    };
    let (all_but_last, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let split = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let (number, suffix) = digits.split_at(split);
    let base: u64 = number.parse().map_err(|_| bad())?;
    let multiplier: u64 = match suffix {
        "" => 1,
        "b" => 512,
        "kB" => 1_000,
        "k" | "K" => 1_024,
        "MB" => 1_000_000,
        "M" => 1_048_576,
        _ => return Err(bad()),
    };
    Ok(Count {
        n: base.saturating_mul(multiplier),
        all_but_last,
    })
}

/// `head`'s command line. The messages are GNU head's; the BusyBox applet's own wording for a
/// bad option is [unverified] and is not modeled apart from these.
fn parse_head<'a>(args: &[&'a str]) -> Result<HeadArgs<'a>, String> {
    let mut parsed = HeadArgs {
        unit: Unit::Lines,
        count: Count {
            n: 10,
            all_but_last: false,
        },
        files: Vec::new(),
        quiet: false,
        verbose: false,
    };
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            parsed.files.push(arg);
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "lines" | "bytes" => {
                    let unit = if name == "lines" {
                        Unit::Lines
                    } else {
                        Unit::Bytes
                    };
                    let value = match value {
                        Some(value) => value,
                        None => {
                            let next = args.get(i).copied().ok_or_else(|| {
                                format!("head: option '--{name}' requires an argument\n{HEAD_TRY}")
                            })?;
                            i = i.saturating_add(1);
                            next
                        }
                    };
                    parsed.unit = unit;
                    parsed.count = head_count(value, unit)?;
                }
                "quiet" | "silent" => parsed.quiet = true,
                "verbose" => parsed.verbose = true,
                _ => {
                    return Err(format!("head: unrecognized option '{arg}'\n{HEAD_TRY}"));
                }
            }
            continue;
        }
        let cluster = arg.get(1..).unwrap_or("");
        if !cluster.is_empty() && cluster.bytes().all(|b| b.is_ascii_digit()) {
            // The obsolete `-5` for `-n 5`.
            parsed.unit = Unit::Lines;
            parsed.count = head_count(cluster, Unit::Lines)?;
            continue;
        }
        for (at, flag) in cluster.char_indices() {
            match flag {
                'q' => parsed.quiet = true,
                'v' => parsed.verbose = true,
                'n' | 'c' => {
                    let unit = if flag == 'n' {
                        Unit::Lines
                    } else {
                        Unit::Bytes
                    };
                    let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
                    let value = if attached.is_empty() {
                        let next = args.get(i).copied().ok_or_else(|| {
                            format!("head: option requires an argument -- '{flag}'\n{HEAD_TRY}")
                        })?;
                        i = i.saturating_add(1);
                        next
                    } else {
                        attached
                    };
                    parsed.unit = unit;
                    parsed.count = head_count(value, unit)?;
                    break;
                }
                other => {
                    return Err(format!("head: invalid option -- '{other}'\n{HEAD_TRY}"));
                }
            }
        }
    }
    Ok(parsed)
}

/// `bytes` without its last `n` lines or bytes. A final line with no newline counts as a line.
fn without_last(mut bytes: Vec<u8>, unit: Unit, n: u64) -> Vec<u8> {
    match unit {
        Unit::Bytes => {
            let keep = bytes.len().saturating_sub(clamp(n));
            bytes.truncate(keep);
        }
        Unit::Lines => {
            let mut end = bytes.len();
            for _ in 0..n {
                if end == 0 {
                    break;
                }
                if end
                    .checked_sub(1)
                    .and_then(|last| bytes.get(last))
                    .is_some_and(|byte| *byte == b'\n')
                {
                    end = end.saturating_sub(1);
                }
                end = bytes
                    .get(..end)
                    .and_then(|kept| kept.iter().rposition(|byte| *byte == b'\n'))
                    .map_or(0, |at| at.saturating_add(1));
            }
            bytes.truncate(end);
        }
    }
    bytes
}
