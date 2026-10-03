//! `hostname`, `arch`, `nproc`, `date` and `uptime`: the host-identity and time commands an
//! enumeration script opens with.
//!
//! Every answer is read from facts the session already holds, so none can disagree with them: the
//! host name and machine are the persona's (the values `uname -n` and `uname -m` print), the core
//! count is the number of `processor` entries in the modeled `/proc/cpuinfo`, and every time is the
//! shell's own clock, never the system's, so a replay with a fixed clock prints the same bytes
//! each run. Nothing here starts a process, reads the host or opens a socket.
//!
//! `hostname`, `date` and `uptime` exist on both personas; `arch` and `nproc` are GNU coreutils
//! and exist on the Ubuntu one only (the phone answers them "not found"). The zone is UTC.
//!
//! Boot time is not state: the box "booted" at the start of a fixed-length window on the clock's
//! own timeline, a little before it, so `uptime` advances with the clock, repeats exactly under a
//! fixed one, and every session of the sensor sees the same machine rather than a fresh boot.
//!
//! No capture backs the wording below the persona's own facts; everything composed from
//! knowledge of procps, GNU coreutils or toybox rather than a recording is marked `[unverified]`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeDelta, Timelike, Utc};

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::persona;

pub(super) fn register(r: &mut Registry) {
    r.register("hostname", HandlerId::Hostname, FakeShell::cmd_hostname);
    r.register("date", HandlerId::Date, FakeShell::cmd_date);
    r.register("uptime", HandlerId::Uptime, FakeShell::cmd_uptime);
    r.register_if("arch", ubuntu, HandlerId::Arch, FakeShell::cmd_arch);
    r.register_if("nproc", ubuntu, HandlerId::Nproc, FakeShell::cmd_nproc);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// The most text one `date` format may expand to, so a width flag or a long format cannot make a
/// line's output grow without bound.
const OUT_MAX: usize = 4096;
/// The widest field width a format may ask for.
const WIDTH_MAX: usize = 64;
/// The most `/proc/cpuinfo` bytes `nproc` counts entries in.
const CPUINFO_MAX: u64 = 65_536;

/// The standard two-line tail of a coreutils option error.
pub(super) fn try_help(cmd: &str) -> String {
    format!("Try '{cmd} --help' for more information.\n")
}

/// The error for `arg`, an option `cmd` does not have (status 1 for GNU tools).
fn bad_option(cmd: &str, arg: &str) -> CommandResult {
    match arg.strip_prefix("--") {
        Some(_) => CommandResult::stderr(
            1,
            format!("{cmd}: unrecognized option '{arg}'\n{}", try_help(cmd)),
        ),
        None => bad_flag(cmd, arg.chars().nth(1).unwrap_or('-')),
    }
}

pub(super) fn bad_flag(cmd: &str, flag: char) -> CommandResult {
    CommandResult::stderr(
        1,
        format!("{cmd}: invalid option -- '{flag}'\n{}", try_help(cmd)),
    )
}

fn extra_operand(cmd: &str, arg: &str) -> CommandResult {
    CommandResult::stderr(
        1,
        format!("{cmd}: extra operand '{arg}'\n{}", try_help(cmd)),
    )
}

impl FakeShell {
    /// What `uname -n` prints: the persona's host name for this shell.
    fn persona_host(&self) -> String {
        match self.flavor {
            ShellFlavor::AndroidSh => persona::ANDROID_HOSTNAME.to_string(),
            ShellFlavor::Bash => persona::hostname(),
        }
    }

    /// What `uname -m` prints.
    fn persona_machine(&self) -> &'static str {
        match self.flavor {
            ShellFlavor::AndroidSh => persona::ANDROID_ARCH,
            ShellFlavor::Bash => persona::ARCH,
        }
    }

    pub(super) fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }
}

// -------------------------------------------------------------------------------------- hostname

impl FakeShell {
    /// `hostname [-s|-f|-d|-i|-I] | hostname NAME`. Naming the host is a bounded no-op that
    /// succeeds silently and leaves the name the persona holds [unverified].
    pub(super) fn cmd_hostname(&mut self, parts: &[&str]) -> CommandResult {
        let host = self.persona_host();
        let short = host.split('.').next().unwrap_or("").to_string();
        let mut answer: Option<String> = None;
        let mut setting = false;
        let mut options = true;
        let mut args = parts.get(1..).unwrap_or(&[]).iter().copied();
        while let Some(arg) = args.next() {
            if !options || arg == "-" || !arg.starts_with('-') {
                setting = true;
                continue;
            }
            if arg == "--" {
                options = false;
                continue;
            }
            if let Some(long) = arg.strip_prefix("--") {
                match long {
                    "short" => answer = Some(short.clone()),
                    "fqdn" | "long" => answer = Some(host.clone()),
                    "domain" => answer = Some(String::new()),
                    "ip-address" => answer = Some(self.hostname_address()),
                    "all-ip-addresses" => answer = Some(String::new()),
                    "file" => {
                        args.next();
                        setting = true;
                    }
                    _ => return bad_option("hostname", arg),
                }
                continue;
            }
            for flag in arg.get(1..).unwrap_or("").chars() {
                match flag {
                    's' => answer = Some(short.clone()),
                    'f' => answer = Some(host.clone()),
                    'd' => answer = Some(String::new()),
                    'i' => answer = Some(self.hostname_address()),
                    'I' => answer = Some(String::new()),
                    'b' => {}
                    'F' => {
                        args.next();
                        setting = true;
                    }
                    other => return bad_flag("hostname", other),
                }
            }
        }
        match answer {
            Some(text) => CommandResult::stdout(format!("{text}\n")),
            None if setting => CommandResult::silent(0),
            None => CommandResult::stdout(format!("{host}\n")),
        }
    }

    /// What the name resolves to through the hosts file the persona carries: Debian's `127.0.1.1`
    /// line for the Ubuntu box, loopback for the phone. `-I` lists interface addresses, and none
    /// is modeled, so it prints an empty line [unverified].
    fn hostname_address(&self) -> String {
        match self.flavor {
            ShellFlavor::AndroidSh => "127.0.0.1".to_string(),
            ShellFlavor::Bash => "127.0.1.1".to_string(),
        }
    }
}

// ------------------------------------------------------------------------------- arch and nproc

impl FakeShell {
    /// `arch`: the machine, as `uname -m` prints it. It has no options of its own.
    pub(super) fn cmd_arch(&mut self, parts: &[&str]) -> CommandResult {
        if let Some(arg) = parts.get(1..).unwrap_or(&[]).first() {
            return if arg.starts_with('-') && *arg != "-" {
                bad_option("arch", arg)
            } else {
                extra_operand("arch", arg)
            };
        }
        CommandResult::stdout(format!("{}\n", self.persona_machine()))
    }

    /// `nproc [--all] [--ignore=N]`: the `processor` entries of the modeled `/proc/cpuinfo`, at
    /// least one, less N when asked.
    pub(super) fn cmd_nproc(&mut self, parts: &[&str]) -> CommandResult {
        let mut ignore: usize = 0;
        let mut args = parts.get(1..).unwrap_or(&[]).iter().copied();
        while let Some(arg) = args.next() {
            let value = match arg {
                "--all" => continue,
                "--ignore" => match args.next() {
                    Some(value) => value,
                    None => {
                        return CommandResult::stderr(
                            1,
                            format!(
                                "nproc: option '--ignore' requires an argument\n{}",
                                try_help("nproc")
                            ),
                        );
                    }
                },
                _ => match arg.strip_prefix("--ignore=") {
                    Some(value) => value,
                    None if arg.starts_with('-') && arg != "-" => {
                        return bad_option("nproc", arg);
                    }
                    None => return extra_operand("nproc", arg),
                },
            };
            match value.parse::<usize>() {
                Ok(count) => ignore = count,
                Err(_) => {
                    return CommandResult::stderr(1, format!("nproc: invalid number: '{value}'\n"));
                }
            }
        }
        let cores = self.cpu_count().saturating_sub(ignore).max(1);
        CommandResult::stdout(format!("{cores}\n"))
    }

    /// How many `processor` entries `/proc/cpuinfo` holds. The field is lowercase on x86; the
    /// phone's capitalized `Processor` line is its model name, not a core.
    fn cpu_count(&self) -> usize {
        let bytes = self
            .fs
            .read_all("/proc/cpuinfo", CPUINFO_MAX)
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|line| {
                line.strip_prefix("processor")
                    .is_some_and(|rest| rest.trim_start().starts_with(':'))
            })
            .count()
    }
}

// ------------------------------------------------------------------------------------------ date

/// The `date` default layout (`Fri Oct  2 12:00:00 UTC 2026`).
const DATE_DEFAULT: &str = "%a %b %e %H:%M:%S %Z %Y";

/// Where the time `date` prints comes from.
enum Source<'a> {
    Now,
    Text(&'a str),
    Reference(&'a str),
    Set(&'a str),
}

enum Layout<'a> {
    Default,
    Custom(&'a str),
    Fixed(String),
}

fn invalid_date(text: &str) -> CommandResult {
    CommandResult::stderr(1, format!("date: invalid date '{text}'\n"))
}

/// [unverified] the `--iso-8601` / `--rfc-3339` layout for a precision word, `None` for a word
/// the tool does not accept.
fn iso_layout(precision: &str) -> Option<&'static str> {
    match precision {
        "" | "date" => Some("%Y-%m-%d"),
        "hours" => Some("%Y-%m-%dT%H+00:00"),
        "minutes" => Some("%Y-%m-%dT%H:%M+00:00"),
        "seconds" => Some("%Y-%m-%dT%H:%M:%S+00:00"),
        "ns" => Some("%Y-%m-%dT%H:%M:%S,%N+00:00"),
        _ => None,
    }
}

fn rfc3339_layout(precision: &str) -> Option<&'static str> {
    match precision {
        "date" => Some("%Y-%m-%d"),
        "seconds" => Some("%Y-%m-%d %H:%M:%S+00:00"),
        "ns" => Some("%Y-%m-%d %H:%M:%S.%N+00:00"),
        _ => None,
    }
}

fn bad_precision(option: &str, value: &str) -> CommandResult {
    CommandResult::stderr(
        1,
        format!(
            "date: invalid argument '{value}' for '--{option}'\nValid arguments are:\n  - 'hours'\n  \
             - 'minutes'\n  - 'date'\n  - 'seconds'\n  - 'ns'\n{}",
            try_help("date")
        ),
    )
}

impl FakeShell {
    pub(super) fn cmd_date(&mut self, parts: &[&str]) -> CommandResult {
        let mut layout = Layout::Default;
        let mut source = Source::Now;
        let mut operand: Option<&str> = None;
        let mut options = true;
        let mut args = parts.get(1..).unwrap_or(&[]).iter().copied();
        while let Some(arg) = args.next() {
            if !options || arg == "-" || !arg.starts_with('-') {
                if operand.is_some() {
                    return extra_operand("date", arg);
                }
                operand = Some(arg);
                continue;
            }
            if arg == "--" {
                options = false;
                continue;
            }
            if let Some(long) = arg.strip_prefix("--") {
                let (name, attached) = match long.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (long, None),
                };
                match name {
                    "utc" | "universal" | "debug" => {}
                    "rfc-email" | "rfc-2822" => {
                        layout = Layout::Fixed("%a, %d %b %Y %H:%M:%S %z".to_string());
                    }
                    "iso-8601" => match iso_layout(attached.unwrap_or("")) {
                        Some(text) => layout = Layout::Fixed(text.to_string()),
                        None => return bad_precision("iso-8601", attached.unwrap_or("")),
                    },
                    "rfc-3339" => match attached.and_then(rfc3339_layout) {
                        Some(text) => layout = Layout::Fixed(text.to_string()),
                        None => return bad_precision("rfc-3339", attached.unwrap_or("")),
                    },
                    "date" | "reference" | "set" | "file" => {
                        let Some(value) = attached.or_else(|| args.next()) else {
                            return CommandResult::stderr(
                                1,
                                format!(
                                    "date: option '--{name}' requires an argument\n{}",
                                    try_help("date")
                                ),
                            );
                        };
                        match name {
                            "date" => source = Source::Text(value),
                            "reference" => source = Source::Reference(value),
                            "set" => source = Source::Set(value),
                            _ => return CommandResult::silent(0),
                        }
                    }
                    _ => return bad_option("date", arg),
                }
                continue;
            }
            let body = arg.get(1..).unwrap_or("");
            for (at, flag) in body.char_indices() {
                let rest = body.get(at.saturating_add(flag.len_utf8())..).unwrap_or("");
                match flag {
                    'u' => {}
                    'R' => layout = Layout::Fixed("%a, %d %b %Y %H:%M:%S %z".to_string()),
                    'I' => {
                        match iso_layout(rest) {
                            Some(text) => layout = Layout::Fixed(text.to_string()),
                            None => return bad_precision("iso-8601", rest),
                        }
                        break;
                    }
                    'd' | 'r' | 's' | 'f' => {
                        let value = if rest.is_empty() {
                            args.next()
                        } else {
                            Some(rest)
                        };
                        let Some(value) = value else {
                            return CommandResult::stderr(
                                1,
                                format!(
                                    "date: option requires an argument -- '{flag}'\n{}",
                                    try_help("date")
                                ),
                            );
                        };
                        match flag {
                            'd' => source = Source::Text(value),
                            'r' => source = Source::Reference(value),
                            's' => source = Source::Set(value),
                            _ => return CommandResult::silent(0),
                        }
                        break;
                    }
                    other => return bad_flag("date", other),
                }
            }
        }
        if let Some(text) = operand {
            match text.strip_prefix('+') {
                Some(format) => layout = Layout::Custom(format),
                None if matches!(source, Source::Now) => {
                    // A bare operand is the set-the-clock form (`MMDDhhmm[[CC]YY][.ss]`).
                    let digits = text.chars().all(|c| c.is_ascii_digit() || c == '.');
                    if !digits || text.len() < 8 {
                        return invalid_date(text);
                    }
                    source = Source::Set(text);
                }
                None => return extra_operand("date", text),
            }
        }
        let now = self.now();
        let moment = match source {
            Source::Now => now,
            Source::Text(text) => match parse_date(text, now) {
                Some(moment) => moment,
                None => return invalid_date(text),
            },
            Source::Reference(path) => {
                let logical = self.normalize_logical(path);
                let stamp = self.fs.stat(&logical, true).map(|stat| stat.mtime);
                match stamp.and_then(|secs| DateTime::from_timestamp(secs, 0)) {
                    Some(moment) => moment,
                    None => {
                        return CommandResult::stderr(
                            1,
                            format!("date: {path}: No such file or directory\n"),
                        );
                    }
                }
            }
            Source::Set(text) => {
                if parse_date(text, now).is_none() && !text.chars().all(|c| c.is_ascii_digit()) {
                    return invalid_date(text);
                }
                // [unverified] the clock is the sensor's, and setting it changes nothing.
                return CommandResult::stderr(
                    1,
                    "date: cannot set date: Operation not permitted\n".to_string(),
                );
            }
        };
        let text = match layout {
            Layout::Default => expand(DATE_DEFAULT, &moment),
            Layout::Custom(format) => expand(format, &moment),
            Layout::Fixed(format) => expand(&format, &moment),
        };
        CommandResult::stdout(format!("{text}\n"))
    }
}

/// [unverified] the small grammar `date -d` accepts here: `now`, `today`, `yesterday`, `tomorrow`,
/// `@SECONDS`, `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]`, and `[+-]N unit[s] [ago]` for second, minute,
/// hour, day and week. GNU parses far more; anything else here is "invalid date" rather than a
/// guess.
fn parse_date(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let text = text.trim();
    match text {
        "now" | "today" => return Some(now),
        "yesterday" => return now.checked_sub_signed(TimeDelta::try_days(1)?),
        "tomorrow" => return now.checked_add_signed(TimeDelta::try_days(1)?),
        _ => {}
    }
    if let Some(seconds) = text.strip_prefix('@') {
        return DateTime::from_timestamp(seconds.parse::<i64>().ok()?, 0);
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
    }
    for layout in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"] {
        if let Ok(stamp) = NaiveDateTime::parse_from_str(text, layout) {
            return Some(stamp.and_utc());
        }
    }
    let mut words = text.split_whitespace();
    let count: i64 = words.next()?.parse().ok()?;
    let unit = words.next()?;
    let ago = match words.next() {
        None => false,
        Some("ago") => true,
        Some(_) => return None,
    };
    if words.next().is_some() || count.unsigned_abs() > 1_000_000 {
        return None;
    }
    let unit = unit.strip_suffix('s').unwrap_or(unit);
    let span = match unit {
        "sec" | "second" => TimeDelta::try_seconds(count)?,
        "min" | "minute" => TimeDelta::try_minutes(count)?,
        "hour" => TimeDelta::try_hours(count)?,
        "day" => TimeDelta::try_days(count)?,
        "week" => TimeDelta::try_weeks(count)?,
        _ => return None,
    };
    if ago {
        now.checked_sub_signed(span)
    } else {
        now.checked_add_signed(span)
    }
}

/// A numeric strftime field: its value, default width and default pad.
fn numeric(spec: char, t: &DateTime<Utc>) -> Option<(i64, usize, char)> {
    let year = i64::from(t.year());
    let weekday = i64::from(t.weekday().number_from_monday());
    let hour12 = i64::from(t.hour12().1);
    Some(match spec {
        'd' => (i64::from(t.day()), 2, '0'),
        'e' => (i64::from(t.day()), 2, ' '),
        'H' => (i64::from(t.hour()), 2, '0'),
        'k' => (i64::from(t.hour()), 2, ' '),
        'I' => (hour12, 2, '0'),
        'l' => (hour12, 2, ' '),
        'm' => (i64::from(t.month()), 2, '0'),
        'M' => (i64::from(t.minute()), 2, '0'),
        'S' => (i64::from(t.second()), 2, '0'),
        'y' => (year.rem_euclid(100), 2, '0'),
        'C' => (year.div_euclid(100), 2, '0'),
        'Y' => (year, 1, '0'),
        'j' => (i64::from(t.ordinal()), 3, '0'),
        'u' => (weekday, 1, '0'),
        'w' => (weekday.rem_euclid(7), 1, '0'),
        's' => (t.timestamp(), 1, '0'),
        'N' => (i64::from(t.timestamp_subsec_nanos()), 9, '0'),
        _ => return None,
    })
}

/// The text of a name or composite field, `None` for a letter that is neither.
fn textual(spec: char, t: &DateTime<Utc>) -> Option<String> {
    let name = |format: &str| t.format(format).to_string();
    Some(match spec {
        'a' => name("%a"),
        'A' => name("%A"),
        'b' | 'h' => name("%b"),
        'B' => name("%B"),
        'p' => name("%p"),
        'P' => name("%p").to_lowercase(),
        'Z' => "UTC".to_string(),
        'z' => "+0000".to_string(),
        'n' => "\n".to_string(),
        't' => "\t".to_string(),
        '%' => "%".to_string(),
        'F' => expand("%Y-%m-%d", t),
        'T' => expand("%H:%M:%S", t),
        'D' | 'x' => expand("%m/%d/%y", t),
        'R' => expand("%H:%M", t),
        'r' => expand("%I:%M:%S %p", t),
        'X' => expand("%H:%M:%S", t),
        'c' => expand("%a %b %e %H:%M:%S %Y", t),
        _ => return None,
    })
}

fn pad_to(text: String, width: usize, fill: char) -> String {
    let missing = width.saturating_sub(text.chars().count());
    let mut out = String::new();
    for _ in 0..missing {
        out.push(fill);
    }
    out.push_str(&text);
    out
}

/// Expand a `date` format against `t`: the strftime fields GNU supports for a fixed UTC moment,
/// with the `-`, `_`, `0` and `^` flags and a width. A field this does not know is copied through
/// as written, as GNU does for an unknown one. Weekly numbering (`%U %V %W %G`) is not modeled.
pub(super) fn expand(format: &str, t: &DateTime<Utc>) -> String {
    let mut out = String::new();
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if out.len() >= OUT_MAX {
            break;
        }
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut raw = String::from("%");
        let mut fill: Option<char> = None;
        let mut upper = false;
        let mut width: Option<usize> = None;
        let mut spec = None;
        for next in chars.by_ref() {
            raw.push(next);
            match next {
                '-' => fill = Some('\0'),
                '_' => fill = Some(' '),
                '0' if width.is_none() => fill = Some('0'),
                '^' => upper = true,
                '#' => {}
                digit if digit.is_ascii_digit() => {
                    let value = digit
                        .to_digit(10)
                        .map_or(0, |d| usize::try_from(d).unwrap_or(0));
                    width = Some(
                        width
                            .unwrap_or(0)
                            .saturating_mul(10)
                            .saturating_add(value)
                            .min(WIDTH_MAX),
                    );
                }
                other => {
                    spec = Some(other);
                    break;
                }
            }
        }
        let Some(spec) = spec else {
            out.push_str(&raw);
            break;
        };
        let field = if let Some((value, default_width, default_fill)) = numeric(spec, t) {
            let text = value.to_string();
            match fill {
                Some('\0') => text,
                chosen => pad_to(
                    text,
                    width.unwrap_or(default_width),
                    chosen.unwrap_or(default_fill),
                ),
            }
        } else if let Some(text) = textual(spec, t) {
            let text = if upper { text.to_uppercase() } else { text };
            match width {
                Some(width) => pad_to(text, width, if fill == Some('0') { '0' } else { ' ' }),
                None => text,
            }
        } else {
            raw
        };
        out.push_str(&field);
    }
    out.chars().take(OUT_MAX).collect()
}

// ---------------------------------------------------------------------------------------- uptime

/// The length of the window the box's "boot" repeats in: 14 days, so the uptime a session sees
/// stays within a couple of weeks, as a patched server's would [unverified].
const BOOT_WINDOW_SECS: i64 = 1_209_600;
/// How long the box has been up at the start of each window: 2h13m41s [unverified].
const BOOT_OFFSET_SECS: u64 = 8_021;

/// Seconds the box has been up at `now`.
pub(super) fn uptime_secs(now: &DateTime<Utc>) -> u64 {
    u64::try_from(now.timestamp().rem_euclid(BOOT_WINDOW_SECS))
        .unwrap_or(0)
        .saturating_add(BOOT_OFFSET_SECS)
}

/// [unverified] a load average that is small and moves with the clock, so repeated calls do not
/// print one frozen figure: `(1, 5, 15 minutes)` in hundredths.
pub(super) fn load_average(now: &DateTime<Utc>) -> String {
    let t = now.timestamp().rem_euclid(86_400 * 7);
    let hundredths =
        |base: i64, step: i64, span: i64| base.saturating_add(t.div_euclid(step).rem_euclid(span));
    let figure = |value: i64| format!("{}.{:02}", value.div_euclid(100), value.rem_euclid(100));
    format!(
        "{}, {}, {}",
        figure(hundredths(2, 5, 14)),
        figure(hundredths(3, 60, 9)),
        figure(hundredths(1, 300, 6))
    )
}

fn plural(count: u64, unit: &str) -> String {
    let s = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{s}")
}

/// procps' short form: `3 days,  3:17`, `1 day,  2:05`, ` 3:17`, `17 min`.
pub(super) fn uptime_short(secs: u64) -> String {
    let days = secs.checked_div(86_400).unwrap_or(0);
    let hours = (secs % 86_400).checked_div(3_600).unwrap_or(0);
    let minutes = (secs % 3_600).checked_div(60).unwrap_or(0);
    let mut out = String::new();
    if days > 0 {
        out.push_str(&format!("{}, ", plural(days, "day")));
    }
    if hours > 0 {
        out.push_str(&format!("{hours:2}:{minutes:02}"));
    } else {
        out.push_str(&format!("{minutes} min"));
    }
    out
}

/// procps' `-p` form: `3 days, 3 hours, 17 minutes`, zero parts left out.
fn uptime_pretty(secs: u64) -> String {
    let minutes_total = secs.checked_div(60).unwrap_or(0);
    let weeks = minutes_total.checked_div(10_080).unwrap_or(0);
    let days = (minutes_total % 10_080).checked_div(1_440).unwrap_or(0);
    let hours = (minutes_total % 1_440).checked_div(60).unwrap_or(0);
    let minutes = minutes_total % 60;
    let mut pieces = Vec::new();
    for (count, unit) in [
        (weeks, "week"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
    ] {
        if count > 0 {
            pieces.push(plural(count, unit));
        }
    }
    if pieces.is_empty() {
        pieces.push(plural(0, "minute"));
    }
    format!("up {}", pieces.join(", "))
}

impl FakeShell {
    /// `uptime [-p|-s]`, the procps layout: ` HH:MM:SS up <duration>,  1 user,  load average: a,
    /// b, c`. One user is the session itself [unverified]; options it does not model print the
    /// default line.
    pub(super) fn cmd_uptime(&mut self, parts: &[&str]) -> CommandResult {
        let now = self.now();
        let secs = uptime_secs(&now);
        let boot = i64::try_from(secs)
            .ok()
            .and_then(TimeDelta::try_seconds)
            .and_then(|span| now.checked_sub_signed(span))
            .unwrap_or(now);
        let args = parts.get(1..).unwrap_or(&[]);
        let line = if args.iter().any(|a| matches!(*a, "-p" | "--pretty")) {
            uptime_pretty(secs)
        } else if args.iter().any(|a| matches!(*a, "-s" | "--since")) {
            expand("%Y-%m-%d %H:%M:%S", &boot)
        } else {
            format!(
                "{} up {},  1 user,  load average: {}",
                expand(" %H:%M:%S", &now),
                uptime_short(secs),
                load_average(&now)
            )
        };
        CommandResult::stdout(format!("{line}\n"))
    }
}
