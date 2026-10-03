//! `stat`, `file` and `find`: the reads an enumeration script makes of the filesystem once `ls`
//! and `cat` have shown it what is there, answered from the modeled tree so none of them can
//! disagree with it.
//!
//! `stat` renders the metadata [`crate::fakefs::FakeFs::stat`] holds (mode, owner, size, mtime)
//! in GNU coreutils' layout and format directives. What the model has no field for is derived
//! from the node's physical path, so it is stable and equal for two names of one file: the inode,
//! the device number (from the mount table) and the link count of a directory (its subdirectories
//! plus two). The three timestamps are the node's modeled mtime, a constant of the persona, so a
//! replay prints the same bytes and nothing here calls the system clock. `file` identifies a
//! regular file from its modeled bytes: an ELF header (rendered from the node's recorded header,
//! so it agrees with the modeled binary and the persona architecture), `empty`, text, or `data`.
//! `find` walks the modeled tree in a walk bounded in depth, in nodes visited and in output, each
//! node charged to the line's work allowance, children sorted so a replay is byte-identical.
//!
//! `find` never runs anything: `-exec`, `-ok`, `-delete` and the other predicates that act or
//! need data the model lacks are not modeled, and a command line using one prints nothing and
//! succeeds (the `wc` and `grep` convention), never output this shell made up. Nothing here reads
//! the host or starts a process.
//!
//! `stat` and `find` exist on both personas (coreutils and findutils on Ubuntu, toybox on the
//! phone, BusyBox as an applet of either). `file` is Ubuntu only: toybox has no `file`.
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
use sha1::{Digest, Sha1};

use super::registry::Registry;
use super::sysres::{DU_DEPTH_MAX, DU_VISIT_MAX, Syntax, Tok, ceil_div, disks, scan};
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::binaries;
use crate::fakefs::{ELF_HEADER_LEN, ElfImage, FileKind, MountEntry, Stat};

pub(super) fn register(r: &mut Registry) {
    r.register("stat", HandlerId::Stat, FakeShell::cmd_stat);
    r.register("find", HandlerId::Find, FakeShell::cmd_find);
    // toybox has no `file`, and the phone answers "not found".
    r.register_if("file", ubuntu, HandlerId::File, FakeShell::cmd_file);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// Directories `find` descends below an operand, as `du` does.
pub(super) const FIND_DEPTH_MAX: u32 = DU_DEPTH_MAX;
/// Nodes one `find` run visits, across all its operands, as `du` does.
pub(super) const FIND_VISIT_MAX: u32 = DU_VISIT_MAX;
/// The most `find` output one run builds.
const FIND_OUT_MAX: usize = 65_536;
/// Children of one directory examined to count its subdirectories for `stat`'s link count.
const LINK_SCAN_MAX: usize = 4_096;
/// The most bytes of a file `file` examines.
pub(super) const FILE_PROBE: u64 = 65_536;
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
}

/// `-c` ends its output with a newline, `--printf` does not.
fn with_newline(mut out: String, printf: bool) -> String {
    if !printf {
        out.push('\n');
    }
    out
}

// ------------------------------------------------------------------------------------------ file

const FILE_SHORTS: &str = "bcdEhiklLnNprsSvzZ0efFmP";

const FILE_LONGS: &[(&str, bool)] = &[
    ("brief", false),
    ("mime", false),
    ("mime-type", false),
    ("mime-encoding", false),
    ("dereference", false),
    ("no-dereference", false),
    ("special-files", false),
    ("uncompress", false),
    ("uncompress-noreport", false),
    ("keep-going", false),
    ("raw", false),
    ("no-pad", false),
    ("preserve-date", false),
    ("no-buffer", false),
    ("no-sandbox", false),
    ("apple", false),
    ("extension", false),
    ("print0", false),
    ("debug", false),
    ("exclude", true),
    ("exclude-quiet", true),
    ("files-from", true),
    ("separator", true),
    ("magic-file", true),
    ("parameter", true),
    ("checking-printout", false),
    ("compile", false),
    ("list", false),
    ("help", false),
    ("version", false),
];

const FILE_USAGE: &str = "Usage: file [-bcdEhiklLNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n            [--mime-type] [-e testname] [-F separator] [-f namefile] [-m magicfiles] file ...\n        file -C [-m magicfile]\n        file [--help]\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum MimeMode {
    Off,
    Full,
    TypeOnly,
}

/// What `file` concluded about one operand.
struct Described {
    text: String,
    /// The MIME type and charset, `None` for an operand that could not be opened.
    mime: Option<(String, &'static str)>,
}

impl Described {
    fn of(text: impl Into<String>, mime: &str, charset: &'static str) -> Self {
        Self {
            text: text.into(),
            mime: Some((mime.to_string(), charset)),
        }
    }
}

fn elf_machine(machine: u16) -> String {
    match machine {
        0x3e => "x86-64".to_string(),
        0x03 => "Intel 80386".to_string(),
        0x28 => "ARM".to_string(),
        0xb7 => "ARM aarch64".to_string(),
        other => format!("*unknown arch 0x{other:x}*"),
    }
}

/// The dynamic loader a modeled image of this machine names.
fn elf_interpreter(machine: u16) -> &'static str {
    match machine {
        0x03 => "/lib/ld-linux.so.2",
        0x28 => "/lib/ld-linux-armhf.so.3",
        0xb7 => "/lib/ld-linux-aarch64.so.1",
        _ => "/lib64/ld-linux-x86-64.so.2",
    }
}

/// `file`'s ELF line from the first bytes of a file, or `None` when they are not an ELF header.
/// Class, byte order, type, machine, ABI and (for ARM) the EABI come from the header itself. A
/// modeled `image` (its length and whether it is the static busybox) adds what the 64 bytes
/// cannot say: linkage, interpreter and a build id derived from the image, not from a real build
/// [unverified: the layout, GNU/Linux 3.2.0 and `stripped` follow Ubuntu 22.04's `file` 5.41].
fn elf_description(header: &[u8], image: Option<(u64, bool)>) -> Option<Described> {
    if header.get(..4) != Some(&b"\x7fELF"[..]) || header.len() < 20 {
        return None;
    }
    let class = match header.get(4)? {
        1 => "32-bit",
        2 => "64-bit",
        _ => return None,
    };
    let big = match header.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let bytes: [u8; 2] = header.get(at..at.saturating_add(2))?.try_into().ok()?;
        Some(if big {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    };
    let machine = u16_at(18)?;
    let (kind, mime) = match u16_at(16)? {
        1 => ("relocatable", "application/x-object"),
        2 => ("executable", "application/x-executable"),
        3 => ("pie executable", "application/x-pie-executable"),
        4 => ("core file", "application/x-coredump"),
        _ => return None,
    };
    let abi = match header.get(7)? {
        0 => "SYSV".to_string(),
        3 => "GNU/Linux".to_string(),
        other => format!("OS/ABI {other}"),
    };
    let eabi = match (machine, header.get(36..40)) {
        (0x28, Some(flags)) => {
            let raw: [u8; 4] = flags.try_into().ok()?;
            let word = if big {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            };
            match word >> 24 {
                0 => String::new(),
                n => format!("EABI{n} "),
            }
        }
        _ => String::new(),
    };
    let mut line = format!(
        "ELF {class} {} {kind}, {}, {eabi}version {} ({abi})",
        if big { "MSB" } else { "LSB" },
        elf_machine(machine),
        header.get(6)?,
    );
    if let Some((len, is_static)) = image {
        let mut hasher = Sha1::new();
        hasher.update(header.get(..ELF_HEADER_LEN).unwrap_or(header));
        hasher.update(len.to_le_bytes());
        let build_id: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if is_static {
            line.push_str(", statically linked");
        } else {
            line.push_str(&format!(
                ", dynamically linked, interpreter {}",
                elf_interpreter(machine)
            ));
        }
        line.push_str(&format!(
            ", BuildID[sha1]={build_id}, for GNU/Linux 3.2.0, stripped"
        ));
    }
    Some(Described::of(line, mime, "binary"))
}

/// What a script's `#!` line names, as `file` describes it.
fn script_kind(first_line: &str) -> Option<&'static str> {
    let mut words = first_line.strip_prefix("#!")?.split_whitespace();
    let mut program = words.next()?.rsplit('/').next()?;
    if program == "env" {
        program = words.next()?.rsplit('/').next()?;
    }
    match program {
        "sh" | "dash" | "ash" => Some("POSIX shell script"),
        "bash" => Some("Bourne-Again shell script"),
        _ => None,
    }
}

/// Whether `bytes` are text as `file` counts it: ASCII printable and the common controls, or
/// UTF-8. `truncated` says the probe stopped before the file's end, so a character cut by it
/// is not an error.
fn text_charset(bytes: &[u8], truncated: bool) -> Option<&'static str> {
    let control_ok =
        |byte: u8| matches!(byte, 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x1b);
    let printable = |byte: u8| (byte >= 0x20 && byte != 0x7f) || control_ok(byte);
    if bytes.iter().all(|&byte| byte < 0x80 && printable(byte)) {
        return Some("us-ascii");
    }
    let valid = match std::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none() && truncated,
    };
    let clean = bytes.iter().all(|&byte| byte >= 0x80 || printable(byte));
    (valid && clean).then_some("utf-8")
}

/// `file`'s description of text: the line terminators and a very long line, after the charset.
/// [unverified: the very-long-line threshold and wording.]
fn text_description(bytes: &[u8], charset: &'static str) -> Described {
    let mut crlf = 0u64;
    let mut lf = 0u64;
    let mut cr = 0u64;
    let mut longest = 0usize;
    let mut run = 0usize;
    let mut i = 0usize;
    while let Some(&byte) = bytes.get(i) {
        let next = i.saturating_add(1);
        match byte {
            b'\r' if bytes.get(next) == Some(&b'\n') => {
                crlf = crlf.saturating_add(1);
                longest = longest.max(run);
                run = 0;
                i = i.saturating_add(2);
                continue;
            }
            b'\r' => {
                cr = cr.saturating_add(1);
                longest = longest.max(run);
                run = 0;
            }
            b'\n' => {
                lf = lf.saturating_add(1);
                longest = longest.max(run);
                run = 0;
            }
            _ => run = run.saturating_add(1),
        }
        i = next;
    }
    longest = longest.max(run);
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_end_matches('\r')
                .to_string()
        })
        .unwrap_or_default();
    let base = if charset == "utf-8" {
        "UTF-8 Unicode text"
    } else {
        "ASCII text"
    };
    let script = script_kind(&first_line);
    let mut text = match script {
        Some(kind) => format!("{kind}, {base} executable"),
        None => base.to_string(),
    };
    if longest > 300 {
        text.push_str(&format!(", with very long lines ({longest})"));
    }
    let kinds: Vec<&str> = [(crlf, "CRLF"), (cr, "CR"), (lf, "LF")]
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(_, name)| *name)
        .collect();
    match kinds.as_slice() {
        [] => text.push_str(", with no line terminators"),
        ["LF"] => {}
        many => text.push_str(&format!(", with {} line terminators", many.join(", "))),
    }
    let mime = if script.is_some() {
        "text/x-shellscript"
    } else {
        "text/plain"
    };
    Described::of(text, mime, charset)
}

/// What `file` says of a regular file's bytes. `len` is its whole length, `image` its recorded
/// image when it is one.
fn describe_bytes(bytes: &[u8], len: u64, image: Option<ElfImage>) -> Described {
    if len == 0 {
        return Described::of("empty", "inode/x-empty", "binary");
    }
    let header = image
        .as_ref()
        .map_or(bytes, |image| image.header.as_slice());
    let modeled = image.map(|image| (image.len, binaries::is_busybox(&image)));
    if let Some(elf) = elf_description(header, modeled) {
        return elf;
    }
    let truncated = len_u64(bytes.len()) < len;
    match text_charset(bytes, truncated) {
        Some(charset) => text_description(bytes, charset),
        None => Described::of("data", "application/octet-stream", "binary"),
    }
}

impl FakeShell {
    fn describe_operand(
        &mut self,
        parts: &[&str],
        name: &str,
        deref: bool,
    ) -> Result<Described, ()> {
        if name == "-" {
            let bytes = self.stdin.take(FILE_PROBE);
            if !self.charge_work(len_u64(bytes.len())) {
                return Err(());
            }
            return Ok(describe_bytes(&bytes, len_u64(bytes.len()), None));
        }
        let missing = || Described {
            text: format!("cannot open `{name}' (No such file or directory)"),
            mime: None,
        };
        if name.is_empty() {
            return Ok(missing());
        }
        let logical = self.resolve_logical(name);
        if !self.charge_work(1) {
            return Err(());
        }
        let Some(stat) = self.fs.stat(&logical, deref) else {
            // A dangling link is still a link to `file -L`.
            return Ok(match self.fs.stat(&logical, false) {
                Some(link) if link.kind == FileKind::Symlink => {
                    let target = self.fs.link_target(&logical).unwrap_or_default();
                    Described::of(
                        format!("broken symbolic link to {target}"),
                        "inode/symlink",
                        "binary",
                    )
                }
                _ => missing(),
            });
        };
        Ok(match stat.kind {
            FileKind::Directory => Described::of("directory", "inode/directory", "binary"),
            FileKind::Symlink => {
                let target = self.fs.link_target(&logical).unwrap_or_default();
                Described::of(
                    format!("symbolic link to {target}"),
                    "inode/symlink",
                    "binary",
                )
            }
            FileKind::CharDevice => {
                let (major, minor) = rdev_of(&stat.physical);
                Described::of(
                    format!("character special ({major}/{minor})"),
                    "inode/chardevice",
                    "binary",
                )
            }
            FileKind::Regular => {
                let probe = FILE_PROBE.min(self.read_cap());
                let Ok(bytes) = self.read_operand(parts, name, 0, probe) else {
                    return Ok(missing());
                };
                if !self.charge_work(len_u64(bytes.len())) {
                    return Err(());
                }
                let image = self
                    .fs
                    .content_and_mode(&logical)
                    .ok()
                    .and_then(|(blob, _)| blob.as_elf());
                describe_bytes(&bytes, stat.size, image)
            }
        })
    }

    /// `file [-b] [-i | --mime-type] [-L] [-s] [-z] FILE...`: each operand named, then described
    /// from its modeled bytes or kind. A symlink is reported, not followed, unless `-L`. Options
    /// outside these (`-f`, `-k`, `--apple`, ...) are not modeled: nothing is printed and the
    /// status is 0. Ubuntu only.
    pub(super) fn cmd_file(&mut self, parts: &[&str]) -> CommandResult {
        let syn = Syntax {
            cmd: "file",
            android: false,
            valued: "efFmP",
            longs: FILE_LONGS,
        };
        let toks = match scan(parts.get(1..).unwrap_or(&[]), &syn) {
            Ok(toks) => toks,
            Err(error) => return error,
        };
        let (mut brief, mut deref) = (false, false);
        let mut mime = MimeMode::Off;
        let mut files: Vec<&str> = Vec::new();
        for tok in &toks {
            match tok {
                Tok::Operand(path) => files.push(*path),
                Tok::Short('b', _) | Tok::Long("brief", _) => brief = true,
                Tok::Short('i', _) | Tok::Long("mime", _) => mime = MimeMode::Full,
                Tok::Long("mime-type", _) => mime = MimeMode::TypeOnly,
                Tok::Short('L', _) | Tok::Long("dereference", _) => deref = true,
                Tok::Short('h', _) | Tok::Long("no-dereference", _) => deref = false,
                // Block devices are not modeled, and nothing here is compressed.
                Tok::Short('s' | 'z', _) | Tok::Long("special-files" | "uncompress", _) => {}
                Tok::Short(flag, _) if !FILE_SHORTS.contains(*flag) => return syn.bad_short(*flag),
                Tok::Short(..) | Tok::Long(..) => return CommandResult::silent(0),
            }
        }
        if files.is_empty() {
            return CommandResult::stderr(1, FILE_USAGE);
        }
        let mut lines = Vec::new();
        for file in &files {
            match self.describe_operand(parts, file, deref) {
                Ok(described) => lines.push((*file, described)),
                Err(()) => return stopped(),
            }
        }
        let shown = |name: &str| {
            if name == "-" {
                "/dev/stdin".to_string()
            } else {
                name.to_string()
            }
        };
        let width = files
            .iter()
            .map(|name| shown(name).chars().count())
            .max()
            .unwrap_or(0);
        let mut out = String::new();
        for (name, described) in lines {
            let body = match (&described.mime, mime) {
                (Some((kind, charset)), MimeMode::Full) => format!("{kind}; charset={charset}"),
                (Some((kind, _)), MimeMode::TypeOnly) => kind.clone(),
                _ => described.text,
            };
            if brief {
                out.push_str(&body);
            } else {
                let name = shown(name);
                let fill = width.saturating_sub(name.chars().count());
                out.push_str(&format!("{name}:{} {body}", " ".repeat(fill)));
            }
            out.push('\n');
        }
        CommandResult::stdout(out)
    }
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
