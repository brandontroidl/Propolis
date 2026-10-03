//! `free`, `df` and `du`: the resource-usage reads an enumeration script makes after `uname` and
//! `ps`, answered from the model the session already holds so none of them can disagree with it.
//!
//! `free` parses the modeled `/proc/meminfo` (the one source, so `free` and `cat /proc/meminfo`
//! cannot differ). `df` renders the persona's mount table with a canned capacity per real
//! filesystem; pseudo filesystems have no blocks and are listed only for `-a` or when named. `du`
//! sums the modeled nodes under each operand in a walk bounded in depth, in nodes visited and in
//! output, and charged to the line's work allowance. Nothing here reads the host or starts a
//! process.
//!
//! All three exist on both personas (coreutils and procps on Ubuntu, toybox on the phone). What the
//! phone's `free` prints is its own, simpler layout. An option a tool has that is not modeled
//! prints nothing and succeeds (the `wc` and `grep` convention), never a figure this shell made up;
//! an option the tool does not have gets its own error.
//!
//! No capture backs any figure or layout here: the capacities, the memory sizes and every phone
//! layout are composed from knowledge of the tools and are `[unverified]`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::hostinfo::{bad_flag, try_help};
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::fakefs::{FileKind, MountEntry, Stat};

pub(super) fn register(r: &mut Registry) {
    r.register("free", HandlerId::Free, FakeShell::cmd_free);
    r.register("df", HandlerId::Df, FakeShell::cmd_df);
    r.register("du", HandlerId::Du, FakeShell::cmd_du);
}

/// The most `/proc/meminfo` bytes `free` parses.
const MEMINFO_MAX: u64 = 65_536;
/// Directories `du` descends below an operand before counting a directory as its own block.
pub(super) const DU_DEPTH_MAX: u32 = 32;
/// Nodes one `du` run visits, across all its operands.
pub(super) const DU_VISIT_MAX: u32 = 2_048;
/// The most `du` output one run builds.
const DU_OUT_MAX: usize = 65_536;
/// The disk block `du` rounds a file up to, as ext4 allocates.
const BLOCK: u64 = 4_096;

// ------------------------------------------------------------------------------- option scanning

enum Tok<'a> {
    Short(char, Option<&'a str>),
    Long(&'static str, Option<&'a str>),
    Operand(&'a str),
}

/// What a command accepts on its line, for the scanner and for its error wording.
struct Syntax {
    cmd: &'static str,
    /// The phone's toybox words its option errors its own way and has no long options.
    android: bool,
    /// Short letters that take a value.
    valued: &'static str,
    /// Long names, with whether each takes a value.
    longs: &'static [(&'static str, bool)],
}

impl Syntax {
    fn unrecognized(&self, arg: &str) -> CommandResult {
        if self.android {
            let name = arg.trim_start_matches('-');
            CommandResult::stderr(1, format!("{}: Unknown option {name}\n", self.cmd))
        } else {
            CommandResult::stderr(
                1,
                format!(
                    "{}: unrecognized option '{arg}'\n{}",
                    self.cmd,
                    try_help(self.cmd)
                ),
            )
        }
    }

    fn bad_short(&self, flag: char) -> CommandResult {
        if self.android {
            CommandResult::stderr(1, format!("{}: Unknown option {flag}\n", self.cmd))
        } else {
            bad_flag(self.cmd, flag)
        }
    }

    fn missing_long(&self, name: &str) -> CommandResult {
        CommandResult::stderr(
            1,
            format!(
                "{}: option '--{name}' requires an argument\n{}",
                self.cmd,
                try_help(self.cmd)
            ),
        )
    }

    fn missing_short(&self, flag: char) -> CommandResult {
        if self.android {
            CommandResult::stderr(1, format!("{}: Missing argument to -{flag}\n", self.cmd))
        } else {
            CommandResult::stderr(
                1,
                format!(
                    "{}: option requires an argument -- '{flag}'\n{}",
                    self.cmd,
                    try_help(self.cmd)
                ),
            )
        }
    }
}

/// A long option by exact name or unique prefix, as getopt_long takes it.
fn resolve_long(
    given: &str,
    longs: &'static [(&'static str, bool)],
) -> Option<(&'static str, bool)> {
    if let Some(hit) = longs.iter().find(|(name, _)| *name == given) {
        return Some(*hit);
    }
    let mut matches = longs.iter().filter(|(name, _)| name.starts_with(given));
    let first = matches.next()?;
    matches.next().is_none().then_some(*first)
}

/// Split `args` GNU style: options may follow operands, `--` ends them, a lone `-` is an operand.
fn scan<'a>(args: &[&'a str], syn: &Syntax) -> Result<Vec<Tok<'a>>, CommandResult> {
    let mut toks = Vec::new();
    let mut ended = false;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if ended || arg == "-" || !arg.starts_with('-') {
            toks.push(Tok::Operand(arg));
            continue;
        }
        if arg == "--" {
            ended = true;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (given, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let Some((name, takes)) = resolve_long(given, syn.longs) else {
                return Err(syn.unrecognized(arg));
            };
            let value = if takes {
                let next = attached.or_else(|| args.get(i).copied());
                if attached.is_none() && next.is_some() {
                    i = i.saturating_add(1);
                }
                Some(next.ok_or_else(|| syn.missing_long(name))?)
            } else {
                None
            };
            toks.push(Tok::Long(name, value));
            continue;
        }
        let cluster = arg.get(1..).unwrap_or("");
        for (at, flag) in cluster.char_indices() {
            if !syn.valued.contains(flag) {
                toks.push(Tok::Short(flag, None));
                continue;
            }
            let rest = cluster
                .get(at.saturating_add(flag.len_utf8())..)
                .unwrap_or("");
            let value = if rest.is_empty() {
                let next = args.get(i).copied();
                if next.is_some() {
                    i = i.saturating_add(1);
                }
                next.ok_or_else(|| syn.missing_short(flag))?
            } else {
                rest
            };
            toks.push(Tok::Short(flag, Some(value)));
            break;
        }
    }
    Ok(toks)
}

// ------------------------------------------------------------------------------------ arithmetic

fn ceil_div(n: u64, d: u64) -> u64 {
    n.saturating_add(d.saturating_sub(1))
        .checked_div(d)
        .unwrap_or(0)
}

/// GNU's human-readable form with `--human-readable` / `--si` rounding: one decimal below ten, a
/// whole number above, always rounded up, no suffix below one unit (`0`, `512`, `1.1M`, `391M`).
fn human_ceil(bytes: u64, base: u64) -> String {
    let suffix: [&str; 6] = if base == 1000 {
        ["", "k", "M", "G", "T", "P"]
    } else {
        ["", "K", "M", "G", "T", "P"]
    };
    let n = u128::from(bytes);
    let base = u128::from(base);
    let mut power = 0usize;
    let mut unit = 1u128;
    while power < 5 && n >= unit.saturating_mul(base) {
        unit = unit.saturating_mul(base);
        power = power.saturating_add(1);
    }
    if power == 0 {
        return bytes.to_string();
    }
    let up = |scaled: u128| {
        scaled
            .saturating_add(unit.saturating_sub(1))
            .checked_div(unit)
            .unwrap_or(0)
    };
    let tenths = up(n.saturating_mul(10));
    let name = |p: usize| suffix.get(p).copied().unwrap_or("");
    if tenths < 100 {
        return format!("{}.{}{}", tenths / 10, tenths % 10, name(power));
    }
    let whole = up(n);
    if whole >= base && power < 5 {
        format!("1.0{}", name(power.saturating_add(1)))
    } else {
        format!("{whole}{}", name(power))
    }
}

// ------------------------------------------------------------------------------------------ free

/// What `/proc/meminfo` says that `free` shows, in KiB.
#[derive(Default)]
struct Mem {
    total: u64,
    free: u64,
    available: Option<u64>,
    buffers: u64,
    /// `Cached` plus `SReclaimable`, which procps counts as cache.
    cached: u64,
    /// `Cached` alone, which toybox counts.
    page_cache: u64,
    shmem: u64,
    swap_total: u64,
    swap_free: u64,
}

impl Mem {
    /// What procps calls used: the rest once free memory and the buffers and cache are taken off.
    fn used(&self) -> u64 {
        self.total
            .checked_sub(self.free)
            .and_then(|rest| rest.checked_sub(self.buffers))
            .and_then(|rest| rest.checked_sub(self.cached))
            .unwrap_or_else(|| self.total.saturating_sub(self.free))
    }

    fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

/// The figures of a `/proc/meminfo` body, `None` when it has no `MemTotal`.
fn parse_meminfo(text: &str) -> Option<Mem> {
    let mut mem = Mem::default();
    let mut reclaimable = 0u64;
    let mut seen = false;
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|word| word.parse::<u64>().ok())
        else {
            continue;
        };
        match name {
            "MemTotal" => {
                mem.total = value;
                seen = true;
            }
            "MemFree" => mem.free = value,
            "MemAvailable" => mem.available = Some(value),
            "Buffers" => mem.buffers = value,
            "Cached" => mem.page_cache = value,
            "SReclaimable" => reclaimable = value,
            "Shmem" => mem.shmem = value,
            "SwapTotal" => mem.swap_total = value,
            "SwapFree" => mem.swap_free = value,
            _ => {}
        }
    }
    mem.cached = mem.page_cache.saturating_add(reclaimable);
    seen.then_some(mem)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FreeUnit {
    Bytes,
    Kibi,
    Mebi,
    Gibi,
    Tebi,
    Human,
}

/// procps' `-h` form: the largest binary unit the value reaches, one decimal below ten, rounded to
/// nearest (`3.8Gi`, `322Mi`, `0B`).
fn human_nearest(bytes: u64) -> String {
    const NAMES: [&str; 6] = ["B", "Ki", "Mi", "Gi", "Ti", "Pi"];
    let n = u128::from(bytes);
    let mut power = 0usize;
    let mut unit = 1u128;
    while power < 5 && n >= unit.saturating_mul(1024) {
        unit = unit.saturating_mul(1024);
        power = power.saturating_add(1);
    }
    let name = |p: usize| NAMES.get(p).copied().unwrap_or("");
    if power == 0 {
        return format!("{bytes}B");
    }
    let nearest = |scaled: u128| {
        scaled
            .saturating_add(unit.checked_div(2).unwrap_or(0))
            .checked_div(unit)
            .unwrap_or(0)
    };
    let tenths = nearest(n.saturating_mul(10));
    if tenths < 100 {
        return format!("{}.{}{}", tenths / 10, tenths % 10, name(power));
    }
    let whole = nearest(n);
    if whole >= 1024 && power < 5 {
        format!("1.0{}", name(power.saturating_add(1)))
    } else {
        format!("{whole}{}", name(power))
    }
}

/// One value of a `free` table, in the unit the command line chose (a floor, as procps divides).
fn free_cell(kib: u64, unit: FreeUnit) -> String {
    match unit {
        FreeUnit::Bytes => kib.saturating_mul(1024).to_string(),
        FreeUnit::Kibi => kib.to_string(),
        FreeUnit::Mebi => (kib / 1024).to_string(),
        FreeUnit::Gibi => (kib / 1_048_576).to_string(),
        FreeUnit::Tebi => (kib / 1_073_741_824).to_string(),
        FreeUnit::Human => human_nearest(kib.saturating_mul(1024)),
    }
}

/// [unverified] procps-ng 3.3.17's usage text, written from memory for an option `free` lacks.
const FREE_USAGE: &str = "\nUsage:\n free [options]\n\nOptions:\n \
 -b, --bytes         show output in bytes\n     \
 --kilo          show output in kilobytes\n     \
 --mega          show output in megabytes\n     \
 --giga          show output in gigabytes\n     \
 --tera          show output in terabytes\n     \
 --peta          show output in petabytes\n \
 -k, --kibi          show output in kibibytes\n \
 -m, --mebi          show output in mebibytes\n \
 -g, --gibi          show output in gibibytes\n     \
 --tebi          show output in tebibytes\n     \
 --pebi          show output in pebibytes\n \
 -h, --human         show human-readable output\n     \
 --si            use powers of 1000 not 1024\n \
 -l, --lohi          show detailed low and high memory statistics\n \
 -t, --total         show total for RAM + Swap\n \
 -s, --seconds <secs>  repeat printing every N seconds\n \
 -c, --count <count>   repeat printing N times, then exit\n \
 -w, --wide          wide output\n\n     \
 --help     display this help and exit\n \
 -V, --version  output version information and exit\n\n\
 For more details see free(1).\n";

const FREE_LONGS: &[(&str, bool)] = &[
    ("bytes", false),
    ("kilo", false),
    ("mega", false),
    ("giga", false),
    ("tera", false),
    ("peta", false),
    ("kibi", false),
    ("mebi", false),
    ("gibi", false),
    ("tebi", false),
    ("pebi", false),
    ("human", false),
    ("si", false),
    ("lohi", false),
    ("total", false),
    ("seconds", true),
    ("count", true),
    ("wide", false),
    ("help", false),
    ("version", false),
];

const MEM_UNREADABLE: &str = "free: Error: /proc must be mounted\n  To mount /proc at boot you need an /etc/fstab line like:\n      proc   /proc   proc    defaults\n  In the meantime, run \"mount proc /proc -t proc\"\n";

impl FakeShell {
    /// The modeled `/proc/meminfo`, parsed. The same file `cat` reads, so a session that edits it
    /// sees `free` follow.
    fn read_meminfo(&self) -> Option<Mem> {
        let bytes = self.fs.read_all("/proc/meminfo", MEMINFO_MAX).ok()?;
        parse_meminfo(&String::from_utf8_lossy(&bytes))
    }

    /// `free [-b|-k|-m|-g|--tebi|-h] [-t] [-w]` on Ubuntu (procps-ng); the phone's toybox layout
    /// on Android. `-s`, `-c`, `-l`, `--si` and the decimal units are not modeled.
    pub(super) fn cmd_free(&mut self, parts: &[&str]) -> CommandResult {
        let android = self.flavor == ShellFlavor::AndroidSh;
        let syn = Syntax {
            cmd: "free",
            android,
            valued: if android { "" } else { "sc" },
            longs: if android { &[] } else { FREE_LONGS },
        };
        let toks = match scan(parts.get(1..).unwrap_or(&[]), &syn) {
            Ok(toks) => toks,
            Err(error) => return error,
        };
        let mut unit = if android {
            FreeUnit::Bytes
        } else {
            FreeUnit::Kibi
        };
        let (mut total, mut wide) = (false, false);
        let allowed = if android { "bkmgt" } else { "bkmghtwlscV" };
        for tok in &toks {
            match tok {
                Tok::Operand(_) => {}
                Tok::Short(flag, _) if !allowed.contains(*flag) => {
                    return if android {
                        syn.bad_short(*flag)
                    } else {
                        free_usage_error(*flag)
                    };
                }
                Tok::Short('b', _) | Tok::Long("bytes", _) => unit = FreeUnit::Bytes,
                Tok::Short('k', _) | Tok::Long("kibi", _) => unit = FreeUnit::Kibi,
                Tok::Short('m', _) | Tok::Long("mebi", _) => unit = FreeUnit::Mebi,
                Tok::Short('g', _) | Tok::Long("gibi", _) => unit = FreeUnit::Gibi,
                Tok::Short('t', _) if android => unit = FreeUnit::Tebi,
                Tok::Long("tebi", _) => unit = FreeUnit::Tebi,
                Tok::Short('h', _) | Tok::Long("human", _) => unit = FreeUnit::Human,
                Tok::Short('t', _) | Tok::Long("total", _) => total = true,
                Tok::Short('w', _) | Tok::Long("wide", _) => wide = true,
                Tok::Short(..) | Tok::Long(..) => return CommandResult::silent(0),
            }
        }
        let Some(mem) = self.read_meminfo() else {
            let text = if android {
                "free: /proc/meminfo: No such file or directory\n"
            } else {
                MEM_UNREADABLE
            };
            return CommandResult::stderr(1, text);
        };
        CommandResult::stdout(if android {
            toybox_free(&mem, unit)
        } else {
            procps_free(&mem, unit, total, wide)
        })
    }
}

fn free_usage_error(flag: char) -> CommandResult {
    CommandResult::stderr(1, format!("free: invalid option -- '{flag}'\n{FREE_USAGE}"))
}

/// procps-ng's table: a label column of eight, then every value right-aligned in twelve.
fn procps_free(mem: &Mem, unit: FreeUnit, total: bool, wide: bool) -> String {
    let c = |kib: u64| free_cell(kib, unit);
    let used = mem.used();
    let available = mem.available.unwrap_or_else(|| {
        mem.free
            .saturating_add(mem.buffers)
            .saturating_add(mem.cached)
    });
    let mut header: Vec<&str> = vec!["total", "used", "free", "shared"];
    let mut mem_row = vec![c(mem.total), c(used), c(mem.free), c(mem.shmem)];
    if wide {
        header.extend(["buffers", "cache"]);
        mem_row.extend([c(mem.buffers), c(mem.cached)]);
    } else {
        header.push("buff/cache");
        mem_row.push(c(mem.buffers.saturating_add(mem.cached)));
    }
    header.push("available");
    mem_row.push(c(available));
    let mut out = format!("{:8}", "");
    for name in &header {
        out.push_str(&format!("{name:>12}"));
    }
    out.push('\n');
    let line = |label: &str, cells: &[String]| {
        let mut row = format!("{label:<8}");
        for cell in cells {
            row.push_str(&format!("{cell:>12}"));
        }
        row.push('\n');
        row
    };
    out.push_str(&line("Mem:", &mem_row));
    let swap_used = mem.swap_used();
    out.push_str(&line(
        "Swap:",
        &[c(mem.swap_total), c(swap_used), c(mem.swap_free)],
    ));
    if total {
        out.push_str(&line(
            "Total:",
            &[
                c(mem.total.saturating_add(mem.swap_total)),
                c(used.saturating_add(swap_used)),
                c(mem.free.saturating_add(mem.swap_free)),
            ],
        ));
    }
    out
}

/// [unverified] the phone's `free`: the older procps layout (no available column, a `-/+
/// buffers/cache` row), in bytes unless a unit is given.
fn toybox_free(mem: &Mem, unit: FreeUnit) -> String {
    let c = |kib: u64| free_cell(kib, unit);
    let used = mem.total.saturating_sub(mem.free);
    let cache = mem.buffers.saturating_add(mem.page_cache);
    let mut out = format!(
        "{:>17}{:>11}{:>11}{:>11}{:>11}\n",
        "total", "used", "free", "shared", "buffers"
    );
    out.push_str(&format!(
        "{:<7}{:>10} {:>10} {:>10} {:>10} {:>10}\n",
        "Mem:",
        c(mem.total),
        c(used),
        c(mem.free),
        c(mem.shmem),
        c(mem.buffers)
    ));
    out.push_str(&format!(
        "{:<18}{:>10} {:>10}\n",
        "-/+ buffers/cache:",
        c(used.saturating_sub(cache)),
        c(mem.free.saturating_add(cache))
    ));
    out.push_str(&format!(
        "{:<7}{:>10} {:>10} {:>10}\n",
        "Swap:",
        c(mem.swap_total),
        c(mem.swap_used()),
        c(mem.swap_free)
    ));
    out
}

// -------------------------------------------------------------------------------------------- df

/// The canned capacity of one real filesystem, in KiB blocks [unverified].
struct Figures {
    point: &'static str,
    size: u64,
    used: u64,
    avail: u64,
}

const fn figures(point: &'static str, size: u64, used: u64, avail: u64) -> Figures {
    Figures {
        point,
        size,
        used,
        avail,
    }
}

/// One 20 GiB virtual disk with ext4's 5% reserve (so `used + avail` is a little under `size`), a
/// 100 MiB EFI partition, and the tmpfs and devtmpfs sizes the mount options already state. The
/// `/dev/shm` size is half of the `MemTotal` in `/proc/meminfo`.
const UBUNTU_DISKS: [Figures; 7] = [
    figures("/dev", 1_968_376, 0, 1_968_376),
    figures("/run", 402_244, 1_140, 401_104),
    figures("/", 20_134_592, 4_908_044, 14_219_818),
    figures("/dev/shm", 2_008_916, 0, 2_008_916),
    figures("/run/lock", 5_120, 0, 5_120),
    figures("/boot/efi", 106_858, 6_186, 100_672),
    figures("/run/user/0", 402_240, 0, 402_240),
];

/// A 16 GB Nexus 5: a small read-only system partition, the rest in `/data`, which the two FUSE
/// views of the emulated card report as their own.
const ANDROID_DISKS: [Figures; 8] = [
    figures("/", 937_704, 6_812, 930_892),
    figures("/dev", 931_668, 52, 931_616),
    figures("/system", 1_031_576, 930_912, 100_664),
    figures("/data", 12_251_376, 3_481_544, 8_769_832),
    figures("/cache", 677_232, 5_836, 671_396),
    figures("/persist", 6_892, 4_180, 2_712),
    figures("/storage/emulated", 12_251_376, 3_481_544, 8_769_832),
    figures("/sdcard", 12_251_376, 3_481_544, 8_769_832),
];

fn disks(flavor: ShellFlavor) -> &'static [Figures] {
    match flavor {
        ShellFlavor::Bash => &UBUNTU_DISKS,
        ShellFlavor::AndroidSh => &ANDROID_DISKS,
    }
}

#[derive(Clone, Copy)]
enum Scale {
    /// Counts of blocks of this many KiB, rounded up.
    Blocks(u64),
    /// `-h` (1024) or `-H` (1000).
    Human(u64),
}

struct DfPlan<'a> {
    all: bool,
    scale: Scale,
    with_type: bool,
    posix: bool,
    operands: Vec<&'a str>,
}

/// One filesystem as `df` lists it.
struct Row {
    source: String,
    fstype: String,
    size: u64,
    used: u64,
    avail: u64,
    mount: String,
    /// It has blocks. A pseudo filesystem has none and shows `-` for its use.
    real: bool,
}

fn row_of(flavor: ShellFlavor, entry: &MountEntry) -> Row {
    let found = disks(flavor).iter().find(|disk| disk.point == entry.point);
    Row {
        source: entry.source.to_string(),
        fstype: entry.fstype.to_string(),
        size: found.map_or(0, |disk| disk.size),
        used: found.map_or(0, |disk| disk.used),
        avail: found.map_or(0, |disk| disk.avail),
        mount: entry.point.to_string(),
        real: found.is_some(),
    }
}

#[derive(Default)]
struct Cells {
    source: String,
    fstype: String,
    size: String,
    used: String,
    avail: String,
    pct: String,
    mount: String,
}

fn df_cells(row: &Row, plan: &DfPlan<'_>) -> Cells {
    let number = |kib: u64| match plan.scale {
        Scale::Blocks(block) => ceil_div(kib, block).to_string(),
        Scale::Human(base) => human_ceil(kib.saturating_mul(1024), base),
    };
    let denominator = row.used.saturating_add(row.avail);
    let pct = if row.real && denominator > 0 {
        format!("{}%", ceil_div(row.used.saturating_mul(100), denominator))
    } else {
        "-".to_string()
    };
    Cells {
        source: row.source.clone(),
        fstype: row.fstype.clone(),
        size: number(row.size),
        used: number(row.used),
        avail: number(row.avail),
        pct,
        mount: row.mount.clone(),
    }
}

fn df_header(plan: &DfPlan<'_>) -> Cells {
    let (size, used, avail) = match plan.scale {
        Scale::Human(_) => ("Size", "Used", "Avail"),
        Scale::Blocks(1) if plan.posix => ("1024-blocks", "Used", "Available"),
        Scale::Blocks(1) => ("1K-blocks", "Used", "Available"),
        Scale::Blocks(_) => ("1M-blocks", "Used", "Available"),
    };
    Cells {
        source: "Filesystem".to_string(),
        fstype: "Type".to_string(),
        size: size.to_string(),
        used: used.to_string(),
        avail: avail.to_string(),
        pct: if plan.posix { "Capacity" } else { "Use%" }.to_string(),
        mount: "Mounted on".to_string(),
    }
}

fn df_text(rows: &[Row], plan: &DfPlan<'_>) -> String {
    let mut cells = vec![df_header(plan)];
    cells.extend(rows.iter().map(|row| df_cells(row, plan)));
    // Coreutils' minimum widths for the columns.
    let (m_source, m_type, m_size, m_used, m_avail, m_pct) = (14, 4, 5, 5, 5, 4);
    let widest = |floor: usize, pick: fn(&Cells) -> &String| {
        cells
            .iter()
            .map(|cell| pick(cell).chars().count())
            .fold(floor, usize::max)
    };
    let ws = widest(m_source, |c| &c.source);
    let wt = widest(m_type, |c| &c.fstype);
    let wz = widest(m_size, |c| &c.size);
    let wu = widest(m_used, |c| &c.used);
    let wa = widest(m_avail, |c| &c.avail);
    let wp = widest(m_pct, |c| &c.pct);
    let mut out = String::new();
    for cell in &cells {
        out.push_str(&format!("{:<ws$}", cell.source));
        if plan.with_type {
            out.push_str(&format!(" {:<wt$}", cell.fstype));
        }
        out.push_str(&format!(
            " {:>wz$} {:>wu$} {:>wa$} {:>wp$} {}\n",
            cell.size, cell.used, cell.avail, cell.pct, cell.mount
        ));
    }
    out
}

const DF_LONGS: &[(&str, bool)] = &[
    ("all", false),
    ("block-size", true),
    ("human-readable", false),
    ("si", false),
    ("inodes", false),
    ("kilobytes", false),
    ("local", false),
    ("no-sync", false),
    ("output", false),
    ("portability", false),
    ("sync", false),
    ("total", false),
    ("type", true),
    ("print-type", false),
    ("exclude-type", true),
    ("help", false),
    ("version", false),
];

impl FakeShell {
    /// The mount an operand of `df` names: the one under a path that exists, or the one whose
    /// source is the operand (`df /dev/sda1`).
    fn df_operand_mount(&mut self, operand: &str) -> Option<MountEntry> {
        if !operand.is_empty() {
            let logical = self.normalize_logical(operand);
            if let Some(entry) = self.fs.mount_of(&logical) {
                return Some(entry);
            }
        }
        self.fs
            .mounts()
            .iter()
            .find(|entry| entry.source == operand)
            .copied()
    }

    /// `df [-a] [-h|-H|-k|-m] [-T] [-P] [PATH...]`: one row per filesystem that has blocks, or the
    /// filesystem under each path. `-i`, `-t`, `-x`, `-B`, `--total` and `--output` are not
    /// modeled.
    pub(super) fn cmd_df(&mut self, parts: &[&str]) -> CommandResult {
        let android = self.flavor == ShellFlavor::AndroidSh;
        let syn = Syntax {
            cmd: "df",
            android,
            valued: if android { "t" } else { "Btx" },
            longs: if android { &[] } else { DF_LONGS },
        };
        let toks = match scan(parts.get(1..).unwrap_or(&[]), &syn) {
            Ok(toks) => toks,
            Err(error) => return error,
        };
        let mut plan = DfPlan {
            all: false,
            scale: Scale::Blocks(1),
            with_type: false,
            posix: false,
            operands: Vec::new(),
        };
        let allowed = if android { "aPkhHit" } else { "aTPhHkmlitxB" };
        for tok in &toks {
            match tok {
                Tok::Operand(path) => plan.operands.push(*path),
                Tok::Short(flag, _) if !allowed.contains(*flag) => return syn.bad_short(*flag),
                Tok::Short('a', _) | Tok::Long("all", _) => plan.all = true,
                Tok::Short('h', _) | Tok::Long("human-readable", _) => {
                    plan.scale = Scale::Human(1024);
                }
                Tok::Short('H', _) | Tok::Long("si", _) => plan.scale = Scale::Human(1000),
                Tok::Short('k', _) | Tok::Long("kilobytes", _) => plan.scale = Scale::Blocks(1),
                Tok::Short('m', _) => plan.scale = Scale::Blocks(1024),
                Tok::Short('T', _) | Tok::Long("print-type", _) => plan.with_type = true,
                Tok::Short('P', _) | Tok::Long("portability", _) => plan.posix = true,
                Tok::Short('l', _) | Tok::Long("local" | "sync" | "no-sync", _) => {}
                Tok::Short(..) | Tok::Long(..) => return CommandResult::silent(0),
            }
        }
        let flavor = self.flavor;
        let mut rows = Vec::new();
        let mut errors = String::new();
        if plan.operands.is_empty() {
            for entry in self.fs.mounts() {
                let row = row_of(flavor, entry);
                if plan.all || row.real {
                    rows.push(row);
                }
            }
        } else {
            let operands = plan.operands.clone();
            for operand in operands {
                match self.df_operand_mount(operand) {
                    Some(entry) => rows.push(row_of(flavor, &entry)),
                    None => errors.push_str(&format!("df: {operand}: No such file or directory\n")),
                }
            }
        }
        let mut result = if rows.is_empty() {
            CommandResult::silent(0)
        } else {
            CommandResult::stdout(df_text(&rows, &plan))
        };
        result.append(CommandResult::stderr(u8::from(!errors.is_empty()), errors));
        result
    }
}

// -------------------------------------------------------------------------------------------- du

#[derive(Clone, Copy)]
enum DuUnit {
    Kibi,
    Mebi,
    Bytes,
    Human,
}

struct DuPlan<'a> {
    all: bool,
    total: bool,
    summarize: bool,
    apparent: bool,
    unit: DuUnit,
    max_depth: Option<u32>,
    operands: Vec<&'a str>,
}

/// What one run has done so far: the lines it built and whether a bound stopped it.
#[derive(Default)]
struct Walk {
    visited: u32,
    out: String,
    /// A cap on nodes, depth or output cut the walk short; the sizes are of what was reached.
    capped: bool,
    /// The line's work allowance ran out.
    refused: bool,
}

const DU_LONGS: &[(&str, bool)] = &[
    ("all", false),
    ("apparent-size", false),
    ("block-size", true),
    ("bytes", false),
    ("total", false),
    ("dereference-args", false),
    ("max-depth", true),
    ("human-readable", false),
    ("inodes", false),
    ("count-links", false),
    ("dereference", false),
    ("no-dereference", false),
    ("separate-dirs", false),
    ("si", false),
    ("summarize", false),
    ("threshold", true),
    ("time", false),
    ("time-style", true),
    ("null", false),
    ("one-file-system", false),
    ("exclude", true),
    ("exclude-from", true),
    ("files0-from", true),
    ("help", false),
    ("version", false),
];

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// What one node adds, in bytes. Disk usage rounds a file up to whole blocks and charges a
/// directory one; apparent size is the length, a directory's being one block. A link or device
/// holds no blocks.
fn node_bytes(stat: &Stat, apparent: bool) -> u64 {
    match stat.kind {
        FileKind::Directory => BLOCK,
        FileKind::Regular if apparent => stat.size,
        FileKind::Regular => ceil_div(stat.size, BLOCK).saturating_mul(BLOCK),
        FileKind::Symlink if apparent => stat.size,
        FileKind::Symlink | FileKind::CharDevice => 0,
    }
}

fn du_size_text(bytes: u64, unit: DuUnit) -> String {
    match unit {
        DuUnit::Kibi => ceil_div(bytes, 1024).to_string(),
        DuUnit::Mebi => ceil_div(bytes, 1_048_576).to_string(),
        DuUnit::Bytes => bytes.to_string(),
        DuUnit::Human => human_ceil(bytes, 1024),
    }
}

impl FakeShell {
    /// The size of the node at `logical` and, for a directory, what is under it, printing a line
    /// for each node the options show. `None` when nothing is there. Bounded in depth, in nodes
    /// visited and in output, and each node costs the line one unit of work.
    fn du_node(
        &mut self,
        plan: &DuPlan<'_>,
        walk: &mut Walk,
        (logical, shown): (&str, &str),
        depth: u32,
        follow: bool,
    ) -> Option<u64> {
        if walk.visited >= DU_VISIT_MAX {
            walk.capped = true;
            return Some(0);
        }
        if !self.charge_work(1) {
            walk.refused = true;
            return Some(0);
        }
        walk.visited = walk.visited.saturating_add(1);
        let stat = self.fs.stat(logical, follow)?;
        let is_dir = stat.kind == FileKind::Directory;
        let mut size = node_bytes(&stat, plan.apparent);
        if is_dir && depth >= DU_DEPTH_MAX {
            walk.capped = true;
        } else if is_dir {
            // The real tool prints in directory order, which is the disk's; names sorted keep a
            // replay of one session byte-identical, as the overlay's own order is not stable.
            let mut names = self.fs.list_dir(logical).unwrap_or_default();
            names.sort_unstable();
            for child in names {
                if walk.capped || walk.refused {
                    break;
                }
                let below = (join(logical, &child), join(shown, &child));
                let added = self.du_node(
                    plan,
                    walk,
                    (&below.0, &below.1),
                    depth.saturating_add(1),
                    false,
                );
                size = size.saturating_add(added.unwrap_or(0));
            }
        }
        let limit = if plan.summarize {
            0
        } else {
            plan.max_depth.unwrap_or(u32::MAX)
        };
        if depth == 0 || (depth <= limit && (is_dir || plan.all)) {
            self.du_line(walk, size, shown, plan.unit);
        }
        Some(size)
    }

    fn du_line(&mut self, walk: &mut Walk, bytes: u64, name: &str, unit: DuUnit) {
        if walk.out.len() >= DU_OUT_MAX {
            walk.capped = true;
            return;
        }
        let text = du_size_text(bytes, unit);
        walk.out.push_str(&format!("{text}\t{name}\n"));
    }

    /// `du [-a] [-c] [-s] [-h|-k|-m|-b] [-d N|--max-depth=N] [--apparent-size] [PATH...]` over the
    /// modeled tree, `.` for no operand. A directory's own entries come before it, as the real
    /// tool prints them. The other options are not modeled, or (`-x`, `-L`, `-P`, `-l`, `-D`,
    /// `-H`) change nothing in a model with one filesystem and no hard links.
    pub(super) fn cmd_du(&mut self, parts: &[&str]) -> CommandResult {
        let android = self.flavor == ShellFlavor::AndroidSh;
        let syn = Syntax {
            cmd: "du",
            android,
            valued: if android { "d" } else { "dBtX" },
            longs: if android { &[] } else { DU_LONGS },
        };
        let toks = match scan(parts.get(1..).unwrap_or(&[]), &syn) {
            Ok(toks) => toks,
            Err(error) => return error,
        };
        let mut plan = DuPlan {
            all: false,
            total: false,
            summarize: false,
            apparent: false,
            unit: DuUnit::Kibi,
            max_depth: None,
            operands: Vec::new(),
        };
        let allowed = if android {
            "askmchxlHLd"
        } else {
            "abcdhkmsxLPlDHSBtX0"
        };
        for tok in &toks {
            match tok {
                Tok::Operand(path) => plan.operands.push(*path),
                Tok::Short(flag, _) if !allowed.contains(*flag) => return syn.bad_short(*flag),
                Tok::Short('a', _) | Tok::Long("all", _) => plan.all = true,
                Tok::Short('c', _) | Tok::Long("total", _) => plan.total = true,
                Tok::Short('s', _) | Tok::Long("summarize", _) => plan.summarize = true,
                Tok::Short('h', _) | Tok::Long("human-readable", _) => plan.unit = DuUnit::Human,
                Tok::Short('k', _) => plan.unit = DuUnit::Kibi,
                Tok::Short('m', _) => plan.unit = DuUnit::Mebi,
                Tok::Short('b', _) | Tok::Long("bytes", _) => {
                    plan.unit = DuUnit::Bytes;
                    plan.apparent = true;
                }
                Tok::Long("apparent-size", _) => plan.apparent = true,
                Tok::Short('d', Some(value)) | Tok::Long("max-depth", Some(value)) => {
                    match value.parse::<u32>() {
                        Ok(depth) => plan.max_depth = Some(depth),
                        Err(_) => {
                            return CommandResult::stderr(
                                1,
                                format!("du: invalid maximum depth '{value}'\n"),
                            );
                        }
                    }
                }
                Tok::Short('x' | 'L' | 'P' | 'l' | 'D' | 'H', _)
                | Tok::Long(
                    "dereference-args" | "count-links" | "dereference" | "no-dereference"
                    | "one-file-system",
                    _,
                ) => {}
                Tok::Short(..) | Tok::Long(..) => return CommandResult::silent(0),
            }
        }
        if plan.summarize && plan.all {
            return CommandResult::stderr(
                1,
                format!(
                    "du: cannot both summarize and show all entries\n{}",
                    try_help("du")
                ),
            );
        }
        if let (true, Some(depth)) = (plan.summarize, plan.max_depth.filter(|d| *d > 0)) {
            return CommandResult::stderr(
                1,
                format!(
                    "du: warning: summarizing conflicts with --max-depth={depth}\n{}",
                    try_help("du")
                ),
            );
        }
        let operands: Vec<&str> = if plan.operands.is_empty() {
            vec!["."]
        } else {
            plan.operands.clone()
        };
        let mut walk = Walk::default();
        let mut grand = 0u64;
        let mut errors = String::new();
        for operand in operands {
            let measured = if operand.is_empty() {
                None
            } else {
                let logical = self.normalize_logical(operand);
                // A link named on the command line is not followed unless it ends in a slash.
                self.du_node(
                    &plan,
                    &mut walk,
                    (&logical, operand),
                    0,
                    operand.ends_with('/'),
                )
            };
            match measured {
                Some(size) => grand = grand.saturating_add(size),
                None if android => {
                    errors.push_str(&format!("du: {operand}: No such file or directory\n"));
                }
                None => errors.push_str(&format!(
                    "du: cannot access '{operand}': No such file or directory\n"
                )),
            }
            if walk.refused {
                break;
            }
        }
        if plan.total {
            self.du_line(&mut walk, grand, "total", plan.unit);
        }
        let mut result = CommandResult::stdout(std::mem::take(&mut walk.out));
        result.append(CommandResult::stderr(u8::from(!errors.is_empty()), errors));
        if walk.refused {
            result.append(stopped());
        }
        result
    }
}
