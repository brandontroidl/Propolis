//! `stat` and `find`: the reads an enumeration script makes of the filesystem once `ls`
//! and `cat` have shown it what is there, answered from the modeled tree so none of them can
//! disagree with it.
//!
//! `stat` renders the metadata [`crate::fakefs::FakeFs::stat`] holds (mode, owner, size, mtime)
//! in GNU coreutils' layout and format directives. What the model has no field for is derived
//! from the node's physical path, so it is stable and equal for two names of one file: the inode,
//! the device number (from the mount table) and the link count of a directory (its subdirectories
//! plus two). The three timestamps are the node's modeled mtime, a constant of the persona, so a
//! replay prints the same bytes and nothing here calls the system clock. `find` walks the modeled tree in a walk bounded in depth, in nodes visited and in output, each
//! node charged to the line's work allowance, children sorted so a replay is byte-identical.
//!
//! `find` never runs anything: `-exec`, `-ok`, `-delete` and the other predicates that act or
//! need data the model lacks are not modeled, and a command line using one prints nothing and
//! succeeds (the `wc` and `grep` convention), never output this shell made up. Nothing here reads
//! the host or starts a process.
//!
//! `stat` and `find` exist on both personas (coreutils and findutils on Ubuntu, toybox on the
//! phone, BusyBox as an applet of either). There is no `file` command on any persona: the Ubuntu
//! 22.04 recording marks it absent (binaries table, 2026-09-29) and it is not a BusyBox applet.
//!
//! No capture backs any layout or wording here beyond the persona's own binaries: the formats are
//! composed from knowledge of the tools. Values marked `[unverified]` are the least certain.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::cmp::Ordering;

use chrono::DateTime;

use super::registry::Registry;
use super::sysres::{DU_DEPTH_MAX, DU_VISIT_MAX, Syntax, Tok, ceil_div, disks, scan};
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::{FileKind, MountEntry, Stat};

pub(super) fn register(r: &mut Registry) {
    r.register("stat", HandlerId::Stat, FakeShell::cmd_stat);
    r.register("find", HandlerId::Find, FakeShell::cmd_find);
}

/// Directories `find` descends below an operand, as `du` does.
pub(super) const FIND_DEPTH_MAX: u32 = DU_DEPTH_MAX;
/// Nodes one `find` run visits, across all its operands, as `du` does.
pub(super) const FIND_VISIT_MAX: u32 = DU_VISIT_MAX;
/// The most `find` output one run builds.
const FIND_OUT_MAX: usize = 65_536;
/// Children of one directory examined to count its subdirectories for `stat`'s link count.
const LINK_SCAN_MAX: usize = 4_096;
/// The block `stat` sizes a file in and rounds a directory to, as ext4 allocates.
const BLOCK: u64 = 4_096;

/// Whose wording a command answers in: coreutils, the phone's toybox, or a BusyBox applet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Gnu,
    Toybox,
    Busybox,
}

impl FakeShell {
    fn dialect(&self) -> Dialect {
        if self.busybox_depth > 0 {
            Dialect::Busybox
        } else if self.flavor == ShellFlavor::AndroidSh {
            Dialect::Toybox
        } else {
            Dialect::Gnu
        }
    }
}

// ----------------------------------------------------------------------------------- node facts

/// FNV-1a over `text`: the stable stand-in for a number the model has no field for.
fn fnv(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The mount governing `path`: the covering entry with the longest mount point.
fn mount_covering(mounts: &'static [MountEntry], path: &str) -> Option<MountEntry> {
    mounts
        .iter()
        .filter(|mount| {
            mount.point == "/"
                || path == mount.point
                || path
                    .strip_prefix(mount.point)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|mount| mount.point.len())
        .copied()
}

/// What `stat` shows as a node's size. A directory is one block on a disk filesystem and nothing on
/// a pseudo one; a file of `/proc` or `/sys` reports zero, as the kernel does for generated files.
fn shown_size(stat: &Stat, fstype: &str) -> u64 {
    match stat.kind {
        FileKind::Regular if matches!(fstype, "proc" | "sysfs") => 0,
        FileKind::Regular | FileKind::Symlink => stat.size,
        FileKind::Directory => match fstype {
            "ext4" | "rootfs" | "sdcardfs" => BLOCK,
            _ => 0,
        },
        FileKind::CharDevice => 0,
    }
}

/// 512-byte blocks: the size in whole 4 KiB pages, none for a short link (kept in the inode) or a
/// device.
fn blocks_of(kind: FileKind, size: u64) -> u64 {
    match kind {
        FileKind::Symlink if size < 60 => 0,
        FileKind::Regular | FileKind::Directory | FileKind::Symlink => {
            ceil_div(size, BLOCK).saturating_mul(8)
        }
        FileKind::CharDevice => 0,
    }
}

/// `st_dev` for a mount: `8:N` for an `sdaN` disk, `179:N` for an Android block device, and an
/// anonymous `0:N` for the rest [unverified: the numbers are plausible, not recorded].
fn device_of(mount: Option<&MountEntry>) -> u64 {
    let Some(mount) = mount else {
        return 0;
    };
    let pair = |major: u64, minor: u64| major.saturating_mul(256).saturating_add(minor);
    if let Some(n) = mount
        .source
        .strip_prefix("/dev/sda")
        .and_then(|n| n.parse::<u64>().ok())
    {
        return pair(8, n);
    }
    if mount.source.starts_with("/dev/block/") {
        return pair(179, (fnv(mount.source) % 32).saturating_add(1));
    }
    pair(0, (fnv(mount.point) % 40).saturating_add(20))
}

/// The major and minor of a modeled character device.
fn rdev_of(physical: &str) -> (u64, u64) {
    match physical {
        "/dev/null" => (1, 3),
        "/dev/zero" => (1, 5),
        "/dev/random" => (1, 8),
        "/dev/urandom" => (1, 9),
        "/dev/tty" => (5, 0),
        _ => (0, 0),
    }
}

fn inode_of(physical: &str) -> u64 {
    if physical == "/" {
        2
    } else {
        (fnv(physical) % 4_000_000).saturating_add(12)
    }
}

/// `-rwxr-xr-x` for `mode`, with `s`/`S` and `t`/`T` for the special bits.
fn mode_string(mode: u32, kind: FileKind) -> String {
    let mut out = String::with_capacity(10);
    out.push(match kind {
        FileKind::Regular => '-',
        FileKind::Directory => 'd',
        FileKind::Symlink => 'l',
        FileKind::CharDevice => 'c',
    });
    let bit = |mask: u32, ch: char| if mode & mask != 0 { ch } else { '-' };
    let exec =
        |x: u32, special: u32, set: char, unset: char| match (mode & x != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        };
    out.push(bit(0o400, 'r'));
    out.push(bit(0o200, 'w'));
    out.push(exec(0o100, 0o4000, 's', 'S'));
    out.push(bit(0o040, 'r'));
    out.push(bit(0o020, 'w'));
    out.push(exec(0o010, 0o2000, 's', 'S'));
    out.push(bit(0o004, 'r'));
    out.push(bit(0o002, 'w'));
    out.push(exec(0o001, 0o1000, 't', 'T'));
    out
}

/// `2024-01-01 00:00:00.000000000 +0000`: the zone is UTC.
fn stamp(secs: i64) -> String {
    DateTime::from_timestamp(secs, 0).map_or_else(
        || "1970-01-01 00:00:00.000000000 +0000".to_string(),
        |time| time.format("%Y-%m-%d %H:%M:%S%.9f %z").to_string(),
    )
}

fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Everything `stat` prints about one node.
struct Facts {
    /// The operand as typed.
    name: String,
    stat: Stat,
    size: u64,
    blocks: u64,
    io_block: u64,
    dev: u64,
    inode: u64,
    links: u64,
    rdev: (u64, u64),
    uid_name: String,
    gid_name: String,
    mount_point: String,
    /// A symlink's stored target, for a link not followed.
    link: Option<String>,
}

impl Facts {
    fn type_word(&self) -> &'static str {
        match self.stat.kind {
            FileKind::Regular if self.size == 0 => "regular empty file",
            FileKind::Regular => "regular file",
            FileKind::Directory => "directory",
            FileKind::Symlink => "symbolic link",
            FileKind::CharDevice => "character special file",
        }
    }

    /// `%N`: the name quoted, a link with its target.
    fn quoted_name(&self) -> String {
        match &self.link {
            Some(target) => format!("{} -> {}", quoted(&self.name), quoted(target)),
            None => quoted(&self.name),
        }
    }
}

impl FakeShell {
    fn user_name(&self, uid: u32) -> String {
        if self.flavor == ShellFlavor::AndroidSh {
            let name = match uid {
                0 => "root",
                1000 => "system",
                2000 => "shell",
                _ => "UNKNOWN",
            };
            return name.to_string();
        }
        let passwd = self.fs.read_all("/etc/passwd", 65_536).unwrap_or_default();
        String::from_utf8_lossy(&passwd)
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                fields.next()?;
                (fields.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
            })
            .unwrap_or_else(|| "UNKNOWN".to_string())
    }

    fn group_name(&self, gid: u32) -> String {
        let table: &[(u32, &str)] = if self.flavor == ShellFlavor::AndroidSh {
            &[(0, "root"), (1000, "system"), (2000, "shell")]
        } else {
            &[
                (0, "root"),
                (1, "daemon"),
                (2, "bin"),
                (3, "sys"),
                (4, "adm"),
                (5, "tty"),
                (6, "disk"),
                (8, "mail"),
                (27, "sudo"),
                (33, "www-data"),
                (100, "users"),
                (1000, "ubuntu"),
                (65534, "nogroup"),
            ]
        };
        table
            .iter()
            .find(|(id, _)| *id == gid)
            .map_or("UNKNOWN", |(_, name)| name)
            .to_string()
    }

    /// The subdirectories of `logical`, charged to the line; `Err` once its allowance is spent.
    fn subdir_count(&mut self, logical: &str) -> Result<u64, ()> {
        let names = self.fs.list_dir(logical).unwrap_or_default();
        if !self.charge_work(len_u64(names.len().min(LINK_SCAN_MAX))) {
            return Err(());
        }
        let mut count = 0u64;
        for name in names.iter().take(LINK_SCAN_MAX) {
            let child = if logical == "/" {
                format!("/{name}")
            } else {
                format!("{logical}/{name}")
            };
            if self
                .fs
                .stat(&child, false)
                .is_some_and(|stat| stat.kind == FileKind::Directory)
            {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// The facts of the node `typed` names; `Ok(None)` when nothing is there, `Err` once the
    /// line's allowance is spent.
    fn node_facts(&mut self, typed: &str, follow: bool) -> Result<Option<Facts>, ()> {
        // The empty name is no path, not the working directory.
        if typed.is_empty() {
            return Ok(None);
        }
        let logical = self.resolve_logical(typed);
        if !self.charge_work(1) {
            return Err(());
        }
        let Some(stat) = self.fs.stat(&logical, follow) else {
            return Ok(None);
        };
        let mount = mount_covering(self.fs.mounts(), &stat.physical);
        let fstype = mount.map_or("", |mount| mount.fstype);
        let size = shown_size(&stat, fstype);
        let links = if stat.kind == FileKind::Directory {
            self.subdir_count(&logical)?.saturating_add(2)
        } else {
            1
        };
        let link = if stat.kind == FileKind::Symlink {
            self.fs.link_target(&logical)
        } else {
            None
        };
        Ok(Some(Facts {
            name: typed.to_string(),
            size,
            blocks: blocks_of(stat.kind, size),
            io_block: if fstype == "proc" { 1024 } else { BLOCK },
            dev: device_of(mount.as_ref()),
            inode: inode_of(&stat.physical),
            links,
            rdev: rdev_of(&stat.physical),
            uid_name: self.user_name(stat.uid),
            gid_name: self.group_name(stat.gid),
            mount_point: mount.map_or_else(String::new, |mount| mount.point.to_string()),
            link,
            stat,
        }))
    }
}

// -------------------------------------------------------------------------------- format engine

/// One value of a format directive: text pads and truncates, a number zero-fills.
enum Val {
    Text(String),
    Num(String),
}

#[derive(Default)]
struct Spec {
    left: bool,
    zero: bool,
    width: usize,
    prec: Option<usize>,
}

fn pad(val: Val, spec: &Spec) -> String {
    let (text, numeric) = match val {
        Val::Text(text) => (text, false),
        Val::Num(text) => (text, true),
    };
    let text: String = match (spec.prec, numeric) {
        (Some(prec), false) => text.chars().take(prec).collect(),
        _ => text,
    };
    let fill = spec.width.saturating_sub(text.chars().count());
    if spec.left {
        format!("{text}{}", " ".repeat(fill))
    } else if spec.zero && numeric {
        format!("{}{text}", "0".repeat(fill))
    } else {
        format!("{}{text}", " ".repeat(fill))
    }
}

/// The character a backslash escape at `chars[at..]` stands for (`at` is past the backslash) and
/// the index after it.
fn escape(chars: &[char], at: usize) -> (String, usize) {
    let Some(&c) = chars.get(at) else {
        return ("\\".to_string(), at);
    };
    let next = at.saturating_add(1);
    let simple = |ch: char| (ch.to_string(), next);
    match c {
        'n' => simple('\n'),
        't' => simple('\t'),
        'r' => simple('\r'),
        'a' => simple('\x07'),
        'b' => simple('\x08'),
        'f' => simple('\x0c'),
        'v' => simple('\x0b'),
        '\\' => simple('\\'),
        '"' => simple('"'),
        '0'..='7' => {
            let digits: String = chars
                .iter()
                .skip(at)
                .take(3)
                .take_while(|ch| ('0'..='7').contains(ch))
                .collect();
            let value = u32::from_str_radix(&digits, 8).unwrap_or(0);
            let ch = char::from_u32(value & 0xff).unwrap_or('\0');
            (ch.to_string(), at.saturating_add(digits.len()))
        }
        'x' => {
            let digits: String = chars
                .iter()
                .skip(next)
                .take(2)
                .take_while(|ch| ch.is_ascii_hexdigit())
                .collect();
            if digits.is_empty() {
                return ("\\x".to_string(), next);
            }
            let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
            let ch = char::from_u32(value).unwrap_or('\0');
            (ch.to_string(), next.saturating_add(digits.len()))
        }
        other => (format!("\\{other}"), next),
    }
}

/// `fmt` with each `%` directive replaced by `value(directive)`: flags `-` and `0`, a width and a
/// precision are honored, `%%` is a percent sign and an unknown directive prints `?`. `printf`
/// also reads backslash escapes.
fn render(fmt: &str, printf: bool, value: &dyn Fn(char) -> Option<Val>) -> String {
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        i = i.saturating_add(1);
        if c == '\\' && printf {
            let (text, next) = escape(&chars, i);
            out.push_str(&text);
            i = next;
            continue;
        }
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = Spec::default();
        while let Some(&flag) = chars.get(i) {
            match flag {
                '-' => spec.left = true,
                '0' => spec.zero = true,
                '+' | ' ' | '#' | '\'' => {}
                _ => break,
            }
            i = i.saturating_add(1);
        }
        while let Some(digit) = chars.get(i).and_then(|ch| ch.to_digit(10)) {
            spec.width = spec
                .width
                .saturating_mul(10)
                .saturating_add(usize::try_from(digit).unwrap_or(0))
                .min(4096);
            i = i.saturating_add(1);
        }
        if chars.get(i) == Some(&'.') {
            i = i.saturating_add(1);
            let mut prec = 0usize;
            while let Some(digit) = chars.get(i).and_then(|ch| ch.to_digit(10)) {
                prec = prec
                    .saturating_mul(10)
                    .saturating_add(usize::try_from(digit).unwrap_or(0))
                    .min(4096);
                i = i.saturating_add(1);
            }
            spec.prec = Some(prec);
        }
        match chars.get(i) {
            None => out.push('%'),
            Some('%') => out.push('%'),
            Some(&directive) => match value(directive) {
                Some(val) => out.push_str(&pad(val, &spec)),
                None => out.push('?'),
            },
        }
        i = i.saturating_add(1);
    }
    out
}

fn text(s: impl Into<String>) -> Option<Val> {
    Some(Val::Text(s.into()))
}

fn num(n: impl ToString) -> Option<Val> {
    Some(Val::Num(n.to_string()))
}

/// The value of directive `c` for a file.
fn stat_value(f: &Facts, c: char, dialect: Dialect) -> Option<Val> {
    let mtime = f.stat.mtime;
    match c {
        'n' => text(f.name.as_str()),
        'N' => text(f.quoted_name()),
        's' => num(f.size),
        'b' => num(f.blocks),
        'B' => num(512),
        'o' => num(f.io_block),
        'f' => num(format!("{:x}", f.stat.mode)),
        'a' => num(format!("{:o}", f.stat.mode & 0o7777)),
        'A' => text(mode_string(f.stat.mode, f.stat.kind)),
        'u' => num(f.stat.uid),
        'U' => text(f.uid_name.as_str()),
        'g' => num(f.stat.gid),
        'G' => text(f.gid_name.as_str()),
        'h' => num(f.links),
        'i' => num(f.inode),
        'x' | 'y' | 'z' => text(stamp(mtime)),
        'w' if dialect == Dialect::Gnu => text(stamp(mtime)),
        'w' => text("-"),
        'X' | 'Y' | 'Z' => num(mtime),
        'W' if dialect == Dialect::Gnu => num(mtime),
        'W' => num(0),
        'F' => text(f.type_word()),
        't' => num(format!("{:x}", f.rdev.0)),
        'T' => num(format!("{:x}", f.rdev.1)),
        'd' => num(f.dev),
        'D' => num(format!("{:x}", f.dev)),
        'm' => text(f.mount_point.as_str()),
        _ => None,
    }
}

const STAT_TERSE: &str = "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o\n";

/// The default layout: coreutils', and toybox's without the birth time [unverified for toybox].
fn stat_default(f: &Facts, dialect: Dialect) -> String {
    let file = match (&f.link, dialect) {
        (Some(target), Dialect::Gnu) => format!("{} -> {target}", f.name),
        (None, Dialect::Gnu) => f.name.clone(),
        _ => f.quoted_name(),
    };
    let mut fmt = String::from("  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n");
    fmt.push_str(if f.stat.kind == FileKind::CharDevice {
        "Device: %Dh/%dd\tInode: %-10i  Links: %-5h Device type: %t,%T\n"
    } else {
        "Device: %Dh/%dd\tInode: %-10i  Links: %h\n"
    });
    fmt.push_str(
        "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\nAccess: %x\nModify: %y\nChange: %z\n",
    );
    if dialect == Dialect::Gnu {
        fmt.push_str(" Birth: %w\n");
    }
    format!(
        "  File: {file}\n{}",
        render(&fmt, false, &|c| stat_value(f, c, dialect))
    )
}

/// Everything `stat -f` prints about the filesystem under a path.
struct FsFacts {
    name: String,
    fsid: u64,
    magic: u64,
    type_name: String,
    blocks: u64,
    free: u64,
    avail: u64,
    inodes: u64,
    inodes_free: u64,
}

/// The filesystem type as `stat -f` names it, with its magic number [unverified: from memory].
fn fs_type(fstype: &str) -> (u64, String) {
    let known = match fstype {
        "ext4" => (0xef53, "ext2/ext3"),
        "tmpfs" | "devtmpfs" | "rootfs" => (0x0102_1994, "tmpfs"),
        "proc" => (0x9fa0, "proc"),
        "sysfs" => (0x6265_6572, "sysfs"),
        "devpts" => (0x1cd1, "devpts"),
        "securityfs" => (0x7363_7673, "securityfs"),
        "cgroup2" => (0x6367_7270, "cgroup2fs"),
        _ => (0, fstype),
    };
    (known.0, known.1.to_string())
}

fn fs_value(f: &FsFacts, c: char) -> Option<Val> {
    match c {
        'n' => text(f.name.as_str()),
        'i' => num(format!("{:016x}", f.fsid)),
        'l' => num(255),
        't' => num(format!("{:x}", f.magic)),
        'T' => text(f.type_name.as_str()),
        's' | 'S' => num(BLOCK),
        'b' => num(f.blocks),
        'f' => num(f.free),
        'a' => num(f.avail),
        'c' => num(f.inodes),
        'd' => num(f.inodes_free),
        _ => None,
    }
}

const FS_TERSE: &str = "%n %i %l %t %s %S %b %f %a %c %d\n";
const FS_DEFAULT: &str = "  File: \"%n\"\n    ID: %-8i Namelen: %-7l Type: %T\nBlock size: %-10s Fundamental block size: %S\nBlocks: Total: %-10b Free: %-10f Available: %a\nInodes: Total: %-10c Free: %d\n";

impl FakeShell {
    /// The filesystem under `typed`, from the mount model and `df`'s canned capacity.
    fn filesystem_facts(&mut self, typed: &str) -> Result<Option<FsFacts>, ()> {
        if typed.is_empty() {
            return Ok(None);
        }
        let logical = self.resolve_logical(typed);
        if !self.charge_work(1) {
            return Err(());
        }
        let Some(stat) = self.fs.stat(&logical, true) else {
            return Ok(None);
        };
        let Some(mount) = mount_covering(self.fs.mounts(), &stat.physical) else {
            return Ok(None);
        };
        let figures = disks(self.flavor)
            .iter()
            .find(|disk| disk.point == mount.point);
        let blocks = figures.map_or(0, |disk| disk.size / 4);
        let inodes = blocks / 4;
        let (magic, type_name) = fs_type(mount.fstype);
        Ok(Some(FsFacts {
            name: typed.to_string(),
            fsid: fnv(mount.point),
            magic,
            type_name,
            blocks,
            free: figures.map_or(0, |disk| disk.size.saturating_sub(disk.used) / 4),
            avail: figures.map_or(0, |disk| disk.avail / 4),
            inodes,
            inodes_free: figures.map_or(0, |disk| inodes.saturating_sub(disk.used / 16)),
        }))
    }
}

// ------------------------------------------------------------------------------------------ stat

const STAT_LONGS: &[(&str, bool)] = &[
    ("dereference", false),
    ("file-system", false),
    ("format", true),
    ("printf", true),
    ("terse", false),
    ("context", false),
    ("help", false),
    ("version", false),
];

impl FakeShell {
    /// `stat [-L] [-f] [-t] [-c FMT | --printf=FMT] FILE...`. A link is not followed unless `-L` or
    /// a trailing slash says so. `--help`, `--version` and `-Z` are not modeled: they print
    /// nothing and succeed.
    pub(super) fn cmd_stat(&mut self, parts: &[&str]) -> CommandResult {
        let dialect = self.dialect();
        let syn = Syntax {
            cmd: "stat",
            android: dialect == Dialect::Toybox,
            valued: "c",
            longs: if dialect == Dialect::Toybox {
                &[]
            } else {
                STAT_LONGS
            },
        };
        let toks = match scan(parts.get(1..).unwrap_or(&[]), &syn) {
            Ok(toks) => toks,
            Err(error) => return error,
        };
        let allowed = if dialect == Dialect::Gnu {
            "LftcZ"
        } else {
            "Lftc"
        };
        let (mut follow, mut file_system, mut terse) = (false, false, false);
        let mut format: Option<(&str, bool)> = None;
        let mut files: Vec<&str> = Vec::new();
        for tok in &toks {
            match tok {
                Tok::Operand(path) => files.push(*path),
                Tok::Short('L', _) | Tok::Long("dereference", _) => follow = true,
                Tok::Short('f', _) | Tok::Long("file-system", _) => file_system = true,
                Tok::Short('t', _) | Tok::Long("terse", _) => terse = true,
                Tok::Short('c', Some(fmt)) | Tok::Long("format", Some(fmt)) => {
                    format = Some((*fmt, false));
                }
                Tok::Long("printf", Some(fmt)) => format = Some((*fmt, true)),
                Tok::Short(flag, _) if !allowed.contains(*flag) => return syn.bad_short(*flag),
                Tok::Short(..) | Tok::Long(..) => return CommandResult::silent(0),
            }
        }
        if files.is_empty() {
            return CommandResult::stderr(
                1,
                format!(
                    "stat: missing operand\n{}",
                    super::hostinfo::try_help("stat")
                ),
            );
        }
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        for file in files {
            let rendered = if file_system {
                match self.filesystem_facts(file) {
                    Err(()) => return stopped(),
                    Ok(None) => Err(match dialect {
                        Dialect::Gnu => format!(
                            "stat: cannot read file system information for '{file}': No such file or directory\n"
                        ),
                        Dialect::Toybox => format!("stat: '{file}': No such file or directory\n"),
                        Dialect::Busybox => {
                            format!("stat: can't stat '{file}': No such file or directory\n")
                        }
                    }),
                    Ok(Some(facts)) => {
                        let value = |c| fs_value(&facts, c);
                        Ok(match (format, terse) {
                            (Some((fmt, printf)), _) => {
                                with_newline(render(fmt, printf, &value), printf)
                            }
                            (None, true) => render(FS_TERSE, false, &value),
                            (None, false) => render(FS_DEFAULT, false, &value),
                        })
                    }
                }
            } else {
                let follows = follow || file.ends_with('/');
                match self.node_facts(file, follows) {
                    Err(()) => return stopped(),
                    Ok(None) => Err(match dialect {
                        Dialect::Gnu => {
                            format!("stat: cannot statx '{file}': No such file or directory\n")
                        }
                        // [unverified] toybox's wording.
                        Dialect::Toybox => format!("stat: '{file}': No such file or directory\n"),
                        // [unverified] BusyBox's wording.
                        Dialect::Busybox => {
                            format!("stat: can't stat '{file}': No such file or directory\n")
                        }
                    }),
                    Ok(Some(facts)) => {
                        let value = |c| stat_value(&facts, c, dialect);
                        Ok(match (format, terse) {
                            (Some((fmt, printf)), _) => {
                                with_newline(render(fmt, printf, &value), printf)
                            }
                            (None, true) => render(STAT_TERSE, false, &value),
                            (None, false) => stat_default(&facts, dialect),
                        })
                    }
                }
            };
            match rendered {
                Ok(out) => acc.append(CommandResult::stdout(out)),
                Err(error) => {
                    failed = true;
                    acc.append(CommandResult::stderr(1, error));
                }
            }
        }
        acc.status = u8::from(failed);
        acc
    }

    /// `ls [-l] [-a|-A] [OPERAND...]`. An operand that is a file lists itself, one that is a
    /// directory its contents (sorted, dotfiles hidden without `-a`), with a `DIR:` heading once
    /// there is more than one operand; files come before directories, as GNU orders them. `-l` is
    /// the long listing, from the same node facts `stat` prints, so the two cannot disagree on a
    /// size or mode. A missing operand is GNU's `cannot access` complaint and status 2.
    ///
    /// The short listing joins names with two spaces whatever the output is, as it always has
    /// here; GNU prints one name per line to a pipe and columns to a terminal [unverified for the
    /// column widths]. Other options are accepted and ignored.
    pub(super) fn cmd_ls(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let show_hidden = args
            .iter()
            .any(|a| a.starts_with('-') && (a.contains('a') || a.contains('A')));
        let long = args
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('l'));
        let mut operands: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-') || *a == "-")
            .collect();
        let headed = operands.len() > 1;
        if operands.is_empty() {
            operands.push(".");
        }
        let mut errors = String::new();
        let mut files: Vec<&str> = Vec::new();
        let mut dirs: Vec<&str> = Vec::new();
        for operand in operands {
            let path = self.resolve_logical(operand);
            // A link named as an operand is listed as a link by `-l`, and followed otherwise.
            let Some(stat) = self.fs.stat(&path, !long) else {
                errors.push_str(&format!(
                    "ls: cannot access '{operand}': No such file or directory\n"
                ));
                continue;
            };
            if stat.kind == FileKind::Directory {
                dirs.push(operand);
            } else {
                files.push(operand);
            }
        }
        files.sort_unstable();
        dirs.sort_unstable();

        let mut out = String::new();
        if !files.is_empty() {
            let entries: Vec<(String, String)> = files
                .iter()
                .map(|file| ((*file).to_string(), (*file).to_string()))
                .collect();
            match self.ls_group(&entries, long, false) {
                Ok(text) => out.push_str(&text),
                Err(()) => return stopped(),
            }
        }
        for dir in dirs {
            let logical = self.resolve_logical(dir);
            let mut names = self.fs.list_dir(&logical).unwrap_or_default();
            if !show_hidden {
                names.retain(|name| !name.starts_with('.'));
            }
            names.sort();
            let entries: Vec<(String, String)> = names
                .into_iter()
                .map(|name| {
                    let typed = if logical == "/" {
                        format!("/{name}")
                    } else {
                        format!("{logical}/{name}")
                    };
                    (name, typed)
                })
                .collect();
            if !out.is_empty() {
                out.push('\n');
            }
            if headed {
                out.push_str(&format!("{dir}:\n"));
            }
            match self.ls_group(&entries, long, true) {
                Ok(text) => out.push_str(&text),
                Err(()) => return stopped(),
            }
        }

        let status = if errors.is_empty() { 0 } else { 2 };
        let mut result = CommandResult::silent(status);
        result.append(CommandResult::stderr(status, errors));
        result.append(CommandResult::one(
            super::OutputFd::Stdout,
            status,
            out.into_bytes(),
        ));
        result
    }

    /// One group of `ls` output: `entries` are (name shown, path), listed as they come. A long
    /// listing of a directory's contents starts with its `total` in 1 KiB blocks, as GNU's does.
    fn ls_group(
        &mut self,
        entries: &[(String, String)],
        long: bool,
        in_directory: bool,
    ) -> Result<String, ()> {
        if !long {
            if entries.is_empty() {
                return Ok(String::new());
            }
            let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
            return Ok(names.join("  ") + "\n");
        }
        let mut rows = Vec::with_capacity(entries.len());
        for (name, typed) in entries {
            if let Some(facts) = self.node_facts(typed, false)? {
                rows.push((name.as_str(), facts));
            }
        }
        let now = (self.clock)().timestamp();
        let size_of = |facts: &Facts| match facts.stat.kind {
            FileKind::CharDevice => format!("{}, {}", facts.rdev.0, facts.rdev.1),
            _ => facts.size.to_string(),
        };
        let width = |column: &dyn Fn(&Facts) -> usize| {
            rows.iter()
                .map(|(_, facts)| column(facts))
                .max()
                .unwrap_or(0)
        };
        let links_w = width(&|f| f.links.to_string().len());
        let user_w = width(&|f| f.uid_name.chars().count());
        let group_w = width(&|f| f.gid_name.chars().count());
        let size_w = width(&|f| size_of(f).len());
        let mut out = String::new();
        if in_directory {
            let blocks = rows
                .iter()
                .map(|(_, facts)| facts.blocks)
                .fold(0u64, u64::saturating_add);
            out.push_str(&format!("total {}\n", ceil_div(blocks, 2)));
        }
        for (name, facts) in &rows {
            let shown = match &facts.link {
                Some(target) => format!("{name} -> {target}"),
                None => (*name).to_string(),
            };
            out.push_str(&format!(
                "{} {:>links_w$} {:<user_w$} {:<group_w$} {:>size_w$} {} {shown}\n",
                mode_string(facts.stat.mode, facts.stat.kind),
                facts.links,
                facts.uid_name,
                facts.gid_name,
                size_of(facts),
                ls_time(facts.stat.mtime, now, self.dialect()),
            ));
        }
        Ok(out)
    }
}

/// The time column of `ls -l`. GNU shows the time of day for a file modified within the last six
/// months (and not in the future) and the year otherwise; toybox shows an ISO date
/// [unverified for toybox].
fn ls_time(mtime: i64, now: i64, dialect: Dialect) -> String {
    const SIX_MONTHS: i64 = 15_778_476;
    let Some(time) = DateTime::from_timestamp(mtime, 0) else {
        return "Jan  1  1970".to_string();
    };
    if dialect == Dialect::Toybox {
        return time.format("%Y-%m-%d %H:%M").to_string();
    }
    if mtime > now.saturating_sub(SIX_MONTHS) && mtime <= now {
        time.format("%b %e %H:%M").to_string()
    } else {
        time.format("%b %e  %Y").to_string()
    }
}

/// `-c` ends its output with a newline, `--printf` does not.
fn with_newline(mut out: String, printf: bool) -> String {
    if !printf {
        out.push('\n');
    }
    out
}

// ------------------------------------------------------------------------------------------ find

#[derive(Clone, Copy, PartialEq, Eq)]
enum Deref {
    /// `-P`: a link is a link.
    Never,
    /// `-H`: a link named on the command line is followed.
    Args,
    /// `-L`: every link is followed.
    All,
}

enum PermKind {
    Exact,
    All,
    Any,
}

enum Test {
    Name { pat: String, fold: bool },
    Path { pat: String, fold: bool },
    Type(Vec<char>),
    Perm(PermKind, u32),
    Size { cmp: Ordering, units: u64, per: u64 },
    Empty,
    True,
    False,
    Print,
    Print0,
    Prune,
}

enum Expr {
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Test(Test),
}

impl Expr {
    fn has_action(&self) -> bool {
        match self {
            Expr::Not(inner) => inner.has_action(),
            Expr::And(a, b) | Expr::Or(a, b) => a.has_action() || b.has_action(),
            Expr::Test(test) => matches!(test, Test::Print | Test::Print0),
        }
    }
}

struct FindPlan {
    expr: Expr,
    min_depth: u32,
    max_depth: u32,
    deref: Deref,
}

/// Why a command line did not become a plan.
enum Failure {
    /// The tool's own complaint, printed with status 1.
    Error(String),
    /// A predicate the tool has that this shell does not model.
    Unmodeled,
}

/// Predicates `find` has that act, or need data the model does not hold. `-exec` and its kin are
/// here so that nothing is ever run, and `-delete` so that nothing is ever removed.
const UNMODELED: &[&str] = &[
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-delete",
    "-ls",
    "-fls",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-printf",
    "-newer",
    "-anewer",
    "-cnewer",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-nouser",
    "-nogroup",
    "-links",
    "-inum",
    "-samefile",
    "-regex",
    "-iregex",
    "-mtime",
    "-atime",
    "-ctime",
    "-mmin",
    "-amin",
    "-cmin",
    "-used",
    "-xtype",
    "-readable",
    "-writable",
    "-executable",
    "-context",
    "-depth",
    "-d",
    "-xdev",
    "-mount",
    "-quit",
    "-follow",
    "-noleaf",
    "-daystart",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-nowarn",
    "-warn",
    "-newerXY",
    "-lname",
    "-ilname",
    "-files0-from",
];

struct Parser<'a, 'b> {
    args: &'b [&'a str],
    at: usize,
    min_depth: u32,
    max_depth: u32,
    /// The last non-global predicate parsed, for the warning about a global option after it.
    last_test: Option<&'a str>,
    warnings: String,
    gnu: bool,
}

type Parsed<T> = Result<T, Failure>;

impl<'a> Parser<'a, '_> {
    fn peek(&self) -> Option<&'a str> {
        self.args.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn operand(&mut self, predicate: &str) -> Parsed<&'a str> {
        let value = self
            .peek()
            .ok_or_else(|| Failure::Error(format!("find: missing argument to `{predicate}'\n")))?;
        self.bump();
        Ok(value)
    }

    fn or_expr(&mut self) -> Parsed<Expr> {
        let mut left = self.and_expr()?;
        while matches!(self.peek(), Some("-o" | "-or")) {
            self.bump();
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Parsed<Expr> {
        let mut left = self.unary()?;
        loop {
            match self.peek() {
                None | Some(")" | "-o" | "-or") => return Ok(left),
                Some("-a" | "-and") => self.bump(),
                Some(_) => {}
            }
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
    }

    fn unary(&mut self) -> Parsed<Expr> {
        let Some(token) = self.peek() else {
            let after = self
                .at
                .checked_sub(1)
                .and_then(|prev| self.args.get(prev))
                .copied()
                .unwrap_or("");
            return Err(Failure::Error(format!(
                "find: expected an expression after '{after}'\n"
            )));
        };
        match token {
            "!" | "-not" => {
                self.bump();
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            "(" => {
                self.bump();
                let inner = self.or_expr()?;
                if self.peek() != Some(")") {
                    return Err(Failure::Error(
                        "find: invalid expression; I was expecting to find a ')' somewhere but did not see one.\n"
                            .to_string(),
                    ));
                }
                self.bump();
                Ok(inner)
            }
            ")" => Err(Failure::Error(
                "find: invalid expression; you have too many ')'\n".to_string(),
            )),
            "-a" | "-and" | "-o" | "-or" => Err(Failure::Error(format!(
                "find: invalid expression; you have used a binary operator '{token}' with nothing before it.\n"
            ))),
            "," => Err(Failure::Unmodeled),
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Parsed<Expr> {
        let Some(token) = self.peek() else {
            return Err(Failure::Unmodeled);
        };
        self.bump();
        if !token.starts_with('-') {
            return Err(Failure::Error(format!(
                "find: paths must precede expression: `{token}'\n"
            )));
        }
        if matches!(token, "-maxdepth" | "-mindepth") {
            let value = self.operand(token)?;
            let depth = value.parse::<u32>().map_err(|_| {
                Failure::Error(format!(
                    "find: Expected a positive decimal integer argument to {token}, but got `{value}'\n"
                ))
            })?;
            if token == "-maxdepth" {
                self.max_depth = depth;
            } else {
                self.min_depth = depth;
            }
            if let (true, Some(prev)) = (self.gnu, self.last_test) {
                self.warnings.push_str(&format!(
                    "find: warning: you have specified the global option {token} after the argument {prev}, but global options are not positional, i.e., {token} affects tests specified before it as well as those specified after it.  Please specify global options before other arguments.\n"
                ));
            }
            return Ok(Expr::Test(Test::True));
        }
        if UNMODELED.contains(&token) {
            return Err(Failure::Unmodeled);
        }
        let test = match token {
            "-name" | "-iname" => Test::Name {
                pat: self.operand(token)?.to_string(),
                fold: token == "-iname",
            },
            "-path" | "-wholename" | "-ipath" | "-iwholename" => Test::Path {
                pat: self.operand(token)?.to_string(),
                fold: token.starts_with("-i"),
            },
            "-type" => {
                let value = self.operand(token)?;
                let mut kinds = Vec::new();
                for letter in value.split(',') {
                    match letter.chars().collect::<Vec<char>>().as_slice() {
                        [c @ ('f' | 'd' | 'l' | 'b' | 'c' | 'p' | 's')] => kinds.push(*c),
                        _ => {
                            return Err(Failure::Error(format!(
                                "find: Unknown argument to -type: {letter}\n"
                            )));
                        }
                    }
                }
                Test::Type(kinds)
            }
            "-perm" => {
                let value = self.operand(token)?;
                let (kind, digits) = if let Some(rest) = value.strip_prefix('-') {
                    (PermKind::All, rest)
                } else if let Some(rest) = value.strip_prefix('/') {
                    (PermKind::Any, rest)
                } else {
                    (PermKind::Exact, value)
                };
                // A symbolic mode (`u=rwx`) is not modeled.
                let bits = u32::from_str_radix(digits, 8)
                    .ok()
                    .filter(|bits| *bits <= 0o7777)
                    .ok_or(Failure::Unmodeled)?;
                Test::Perm(kind, bits)
            }
            "-size" => {
                let value = self.operand(token)?;
                let invalid =
                    || Failure::Error(format!("find: Invalid argument `{value}' to -size\n"));
                let (cmp, rest) = match value.chars().next() {
                    Some('+') => (Ordering::Greater, value.get(1..).unwrap_or("")),
                    Some('-') => (Ordering::Less, value.get(1..).unwrap_or("")),
                    _ => (Ordering::Equal, value),
                };
                let (digits, per) = match rest.chars().next_back() {
                    Some('c') => (rest.trim_end_matches('c'), 1),
                    Some('w') => (rest.trim_end_matches('w'), 2),
                    Some('b') => (rest.trim_end_matches('b'), 512),
                    Some('k') => (rest.trim_end_matches('k'), 1024),
                    Some('M') => (rest.trim_end_matches('M'), 1_048_576),
                    Some('G') => (rest.trim_end_matches('G'), 1_073_741_824),
                    _ => (rest, 512),
                };
                let units = digits.parse::<u64>().map_err(|_| invalid())?;
                Test::Size { cmp, units, per }
            }
            "-empty" => Test::Empty,
            "-true" => Test::True,
            "-false" => Test::False,
            "-print" => Test::Print,
            "-print0" => Test::Print0,
            "-prune" => Test::Prune,
            _ => {
                return Err(Failure::Error(format!(
                    "find: unknown predicate `{token}'\n"
                )));
            }
        };
        self.last_test = Some(token);
        Ok(Expr::Test(test))
    }
}

/// `pat` against `text` as `fnmatch` with no flags matches it: `*`, `?`, bracket classes with
/// ranges and `!`/`^` negation, and a backslash quoting the next character.
fn glob_match(pat: &str, text: &str, fold: bool) -> bool {
    let pat: Vec<char> = pat.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let same = |a: char, b: char| {
        if fold {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    // Where a bracket expression at `at` ends and whether `ch` is in it; `None` for a `[` with no
    // closing `]`, which is a literal.
    let class = |at: usize, ch: char| -> Option<(bool, usize)> {
        let mut i = at.saturating_add(1);
        let negate = matches!(pat.get(i), Some('!' | '^'));
        if negate {
            i = i.saturating_add(1);
        }
        let mut hit = false;
        let mut first = true;
        loop {
            let lo = *pat.get(i)?;
            if lo == ']' && !first {
                return Some((hit != negate, i.saturating_add(1)));
            }
            first = false;
            let dash = pat.get(i.saturating_add(1)) == Some(&'-');
            match pat.get(i.saturating_add(2)) {
                Some(&hi) if dash && hi != ']' => {
                    let (lo_c, hi_c, c) = if fold {
                        (
                            lo.to_ascii_lowercase(),
                            hi.to_ascii_lowercase(),
                            ch.to_ascii_lowercase(),
                        )
                    } else {
                        (lo, hi, ch)
                    };
                    hit |= (lo_c..=hi_c).contains(&c);
                    i = i.saturating_add(3);
                }
                _ => {
                    hit |= same(lo, ch);
                    i = i.saturating_add(1);
                }
            }
        }
    };
    // The pattern position after matching one character at `p`, or `None` when it does not.
    let step = |p: usize, ch: char| -> Option<usize> {
        match *pat.get(p)? {
            '?' => Some(p.saturating_add(1)),
            '[' => match class(p, ch) {
                Some((true, next)) => Some(next),
                Some((false, _)) => None,
                None => same('[', ch).then_some(p.saturating_add(1)),
            },
            '\\' => match pat.get(p.saturating_add(1)) {
                Some(&quoted) => same(quoted, ch).then_some(p.saturating_add(2)),
                None => same('\\', ch).then_some(p.saturating_add(1)),
            },
            literal => same(literal, ch).then_some(p.saturating_add(1)),
        }
    };
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&ch) = text.get(t) {
        if pat.get(p) == Some(&'*') {
            star = Some((p, t));
            p = p.saturating_add(1);
            continue;
        }
        if let Some(next) = step(p, ch) {
            p = next;
            t = t.saturating_add(1);
            continue;
        }
        let Some((star_p, star_t)) = star else {
            return false;
        };
        p = star_p.saturating_add(1);
        t = star_t.saturating_add(1);
        star = Some((star_p, t));
    }
    while pat.get(p) == Some(&'*') {
        p = p.saturating_add(1);
    }
    p >= pat.len()
}

/// The last component of a path as `find -name` sees it: `/` for the root, none of a trailing
/// slash.
fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return if path.is_empty() { "" } else { "/" };
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// What one run has done so far: the lines it built and whether a bound stopped it.
#[derive(Default)]
struct Walk {
    visited: u32,
    out: String,
    /// A cap on nodes, depth or output cut the walk short; what was reached was printed.
    capped: bool,
    /// The line's work allowance ran out.
    refused: bool,
}

/// The node being tested.
struct Here<'a> {
    shown: &'a str,
    logical: &'a str,
    stat: &'a Stat,
    prune: bool,
}

fn emit(walk: &mut Walk, shown: &str, end: char) {
    if walk.out.len() >= FIND_OUT_MAX {
        walk.capped = true;
        return;
    }
    walk.out.push_str(shown);
    walk.out.push(end);
}

impl FakeShell {
    fn eval(&mut self, expr: &Expr, here: &mut Here<'_>, walk: &mut Walk) -> bool {
        match expr {
            Expr::Not(inner) => !self.eval(inner, here, walk),
            Expr::And(a, b) => self.eval(a, here, walk) && self.eval(b, here, walk),
            Expr::Or(a, b) => self.eval(a, here, walk) || self.eval(b, here, walk),
            Expr::Test(test) => self.eval_test(test, here, walk),
        }
    }

    fn eval_test(&mut self, test: &Test, here: &mut Here<'_>, walk: &mut Walk) -> bool {
        match test {
            Test::Name { pat, fold } => glob_match(pat, base_name(here.shown), *fold),
            Test::Path { pat, fold } => glob_match(pat, here.shown, *fold),
            Test::Type(kinds) => {
                let letter = match here.stat.kind {
                    FileKind::Regular => 'f',
                    FileKind::Directory => 'd',
                    FileKind::Symlink => 'l',
                    FileKind::CharDevice => 'c',
                };
                kinds.contains(&letter)
            }
            Test::Perm(kind, bits) => {
                let mode = here.stat.mode & 0o7777;
                match kind {
                    PermKind::Exact => mode == *bits,
                    PermKind::All => mode & bits == *bits,
                    PermKind::Any => *bits == 0 || mode & bits != 0,
                }
            }
            Test::Size { cmp, units, per } => {
                let fstype = mount_covering(self.fs.mounts(), &here.stat.physical)
                    .map_or("", |mount| mount.fstype);
                ceil_div(shown_size(here.stat, fstype), *per).cmp(units) == *cmp
            }
            Test::Empty => match here.stat.kind {
                FileKind::Regular => here.stat.size == 0,
                FileKind::Directory => self
                    .fs
                    .list_dir(here.logical)
                    .is_none_or(|names| names.is_empty()),
                FileKind::Symlink | FileKind::CharDevice => false,
            },
            Test::True => true,
            Test::False => false,
            Test::Print => {
                emit(walk, here.shown, '\n');
                true
            }
            Test::Print0 => {
                emit(walk, here.shown, '\0');
                true
            }
            Test::Prune => {
                here.prune = true;
                true
            }
        }
    }

    /// Visit the node at `logical` (typed as `shown`), run the expression on it, and descend. The
    /// operand is depth 0. Bounded in depth, in nodes visited and in output, and each node costs
    /// the line one unit of work.
    fn find_node(
        &mut self,
        plan: &FindPlan,
        walk: &mut Walk,
        (logical, shown): (&str, &str),
        depth: u32,
        follow: bool,
    ) {
        if walk.capped || walk.refused {
            return;
        }
        if walk.visited >= FIND_VISIT_MAX {
            walk.capped = true;
            return;
        }
        if !self.charge_work(1) {
            walk.refused = true;
            return;
        }
        walk.visited = walk.visited.saturating_add(1);
        let stat = self.fs.stat(logical, follow).or_else(|| {
            // A dangling link is still a link when links are followed.
            follow.then(|| self.fs.stat(logical, false)).flatten()
        });
        let Some(stat) = stat else {
            return;
        };
        let mut pruned = false;
        if depth >= plan.min_depth {
            let mut here = Here {
                shown,
                logical,
                stat: &stat,
                prune: false,
            };
            self.eval(&plan.expr, &mut here, walk);
            pruned = here.prune;
        }
        if stat.kind != FileKind::Directory || pruned || depth >= plan.max_depth {
            return;
        }
        if depth >= FIND_DEPTH_MAX {
            walk.capped = true;
            return;
        }
        // The real tool prints in directory order, which is the disk's; names sorted keep a
        // replay of one session byte-identical, as the overlay's own order is not stable.
        let mut names = self.fs.list_dir(logical).unwrap_or_default();
        names.sort_unstable();
        for child in names {
            if walk.capped || walk.refused {
                break;
            }
            self.find_node(
                plan,
                walk,
                (&join(logical, &child), &join(shown, &child)),
                depth.saturating_add(1),
                plan.deref == Deref::All,
            );
        }
    }

    /// `find [-H|-L|-P] [PATH...] [EXPRESSION]` over the modeled tree, `.` for no path. Tests:
    /// `-name -iname -path -ipath -wholename -type -perm -size -empty -true -false`; operators
    /// `! -a -o ( )`; `-maxdepth`, `-mindepth`, `-prune`, `-print` and `-print0`, with `-print`
    /// implied when no action is given. `-exec` and the other predicates in [`UNMODELED`] print
    /// nothing and succeed: nothing is run or removed.
    pub(super) fn cmd_find(&mut self, parts: &[&str]) -> CommandResult {
        let dialect = self.dialect();
        let mut args = parts.get(1..).unwrap_or(&[]);
        let mut deref = Deref::Never;
        while let Some(&flag) = args.first() {
            match flag {
                "-P" => deref = Deref::Never,
                "-H" => deref = Deref::Args,
                "-L" => deref = Deref::All,
                _ => break,
            }
            args = args.get(1..).unwrap_or(&[]);
        }
        let split = args
            .iter()
            .position(|arg| arg.starts_with('-') || matches!(*arg, "(" | ")" | "!" | ","))
            .unwrap_or(args.len());
        let (starts, rest) = args.split_at(split);
        let mut parser = Parser {
            args: rest,
            at: 0,
            min_depth: 0,
            max_depth: u32::MAX,
            last_test: None,
            warnings: String::new(),
            gnu: dialect == Dialect::Gnu,
        };
        let parsed = if rest.is_empty() {
            Ok(Expr::Test(Test::True))
        } else {
            parser.or_expr().and_then(|expr| match parser.peek() {
                None => Ok(expr),
                Some(")") => Err(Failure::Error(
                    "find: invalid expression; you have too many ')'\n".to_string(),
                )),
                Some(_) => Err(Failure::Unmodeled),
            })
        };
        let mut expr = match parsed {
            Ok(expr) => expr,
            Err(Failure::Error(text)) => return CommandResult::stderr(1, text),
            Err(Failure::Unmodeled) => return CommandResult::silent(0),
        };
        if !expr.has_action() {
            expr = Expr::And(Box::new(expr), Box::new(Expr::Test(Test::Print)));
        }
        let plan = FindPlan {
            expr,
            min_depth: parser.min_depth,
            max_depth: parser.max_depth,
            deref,
        };
        let mut result = CommandResult::stderr(0, std::mem::take(&mut parser.warnings));
        let starts: Vec<&str> = if starts.is_empty() {
            vec!["."]
        } else {
            starts.to_vec()
        };
        let mut walk = Walk::default();
        let mut failed = false;
        for start in starts {
            let logical = self.resolve_logical(start);
            let follow = plan.deref != Deref::Never || start.ends_with('/');
            // A dangling link is a start point that exists, whatever is followed.
            let missing = start.is_empty()
                || (self.fs.stat(&logical, follow).is_none()
                    && self.fs.stat(&logical, false).is_none());
            if !missing {
                self.find_node(&plan, &mut walk, (&logical, start), 0, follow);
            }
            result.append(CommandResult::stdout(std::mem::take(&mut walk.out)));
            if missing {
                failed = true;
                result.append(CommandResult::stderr(
                    1,
                    match dialect {
                        Dialect::Gnu => {
                            format!("find: '{start}': No such file or directory\n")
                        }
                        // [unverified] toybox's and BusyBox's wording.
                        Dialect::Toybox | Dialect::Busybox => {
                            format!("find: {start}: No such file or directory\n")
                        }
                    },
                ));
            }
            if walk.refused {
                break;
            }
        }
        result.status = u8::from(failed);
        if walk.refused {
            result.append(stopped());
        }
        result
    }
}
