//! In-memory fake filesystem backing the fake shell's `cat`/`ls` canned responses (Task 13). See
//! "Fake shell" in `internal/design/02-sensor-framework.md`. Every path here is static content
//! baked in at construction - there is no real filesystem underneath, so there is nothing for an
//! attacker's path argument to traverse into, and every session gets an identical, fresh
//! snapshot with no state leaking from one attacker to the next.
//!
//! Every file is internally consistent with one fictional host (hostname `server01`, Ubuntu
//! 22.04 "Jammy", kernel matching `/proc/version`): the detectability section of the design doc
//! calls out "not contradicting oneself" as the realistic bar this layer clears, so `/etc/hosts`,
//! `/etc/hostname`, and `/etc/os-release` all agree with each other rather than being independent
//! guesses. No content anywhere references a real public address: every IP is loopback or an
//! IPv6 multicast/link-local group, never a routable address of any kind - stricter than the
//! RFC 5737/RFC 1918 documentation-only ranges this project's *emitted events* use, since a
//! plain default `/etc/hosts` has no routable address in it at all.
//!
//! The model is one node type over two layers: an immutable persona [`Snapshot`] built at
//! construction, and a per-session overlay of created nodes and tombstones. Paths given to the
//! public methods are logical (symlinks unresolved); every content, directory and exec operation
//! resolves them to a physical path first, so `/bin/busybox` and `/usr/bin/busybox` are one file.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::binaries::{self, BinaryImage};
use crate::budget::{BudgetError, BudgetLimits, ConnectionBudget};
use crate::persona;

/// Unix seconds stamped on every baked node (2024-01-01T00:00:00Z). Persona data: invisible until
/// a `stat` is modeled, and kept a constant so this module never reads the clock.
pub const PERSONA_MTIME: i64 = 1_704_067_200;

/// Upper bound on the bytes one `read_all` returns. The connection's cumulative output is bounded
/// separately, by the egress budget each transport charges.
pub const READ_CAP: u64 = 1 << 20;

/// Symlinks followed while resolving one path before giving up with `ELOOP` (Linux's
/// `MAXSYMLINKS`).
const MAX_SYMLINK_HOPS: u32 = 40;

const MODE_FILE: u32 = 0o100_644;
const MODE_EXECUTABLE: u32 = 0o100_755;
const MODE_DIRECTORY: u32 = 0o040_755;
const MODE_SYMLINK: u32 = 0o120_777;
const MODE_DEVICE: u32 = 0o020_666;
const EXEC_BITS: u32 = 0o111;

/// Seeds for the two random devices, so `cat /dev/urandom` is deterministic per session.
const RANDOM_SEED: u64 = 0x5eed_0001;
const URANDOM_SEED: u64 = 0x5eed_0002;

/// One filesystem object. Size is always derived (a `Regular`'s blob length, a symlink's target
/// length, zero for the rest), never stored.
#[derive(Debug, Clone)]
pub struct Node {
    pub kind: NodeKind,
    pub meta: Metadata,
}

#[derive(Debug, Clone)]
pub enum NodeKind {
    Regular(Blob),
    Directory(DirListing),
    Symlink { target: String },
    Device(Device),
}

/// Static child names of a modeled directory. Overlay-created children are merged at list time,
/// never stored here, so a snapshot's listing is immutable.
#[derive(Debug, Clone)]
pub struct DirListing {
    entries: Vec<String>,
}

impl DirListing {
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    /// Reads EOF, discards writes.
    Null,
    /// Reads zeros, discards writes.
    Zero,
    /// Reads zeros, refuses writes with `ENOSPC`.
    Full,
    /// Reads a deterministic counter-mode stream, discards writes.
    Random,
    Urandom,
    /// Reads EOF, discards writes.
    Tty,
    /// `/dev/fd/N` behaviour, reserved for the fd table; nothing constructs it yet.
    FdLink(u8),
}

impl Device {
    fn read(self, off: u64, max_len: u64) -> Vec<u8> {
        let len = usize::try_from(max_len.min(READ_CAP)).unwrap_or(0);
        match self {
            Device::Null | Device::Tty | Device::FdLink(_) => Vec::new(),
            Device::Zero | Device::Full => vec![0; len],
            Device::Random | Device::Urandom => {
                let seed = if self == Device::Random {
                    RANDOM_SEED
                } else {
                    URANDOM_SEED
                };
                (0..len)
                    .map(|i| counter_byte(seed, off.saturating_add(i as u64)))
                    .collect()
            }
        }
    }

    fn write(self) -> Result<(), FsError> {
        match self {
            Device::Full => Err(FsError::NoSpace),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Full `st_mode`, type bits included (`0o100_644` file, `0o040_755` directory).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Unix seconds.
    pub mtime: i64,
}

/// The kind of a node as `stat` reports it. Every modeled device is a character device; the box
/// models no block device, FIFO or socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    CharDevice,
}

/// What [`FakeFs::stat`] reports: the node's metadata, its size, and the policy of the mount its
/// physical path sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub kind: FileKind,
    /// Full `st_mode`, type bits included.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    /// A regular file's length, a symlink's target length, zero for the rest.
    pub size: u64,
    /// The node's mount is `ro`: nothing under it can be written.
    pub read_only: bool,
    /// The node's mount is `noexec`: a file under it cannot be executed.
    pub no_exec: bool,
    /// Where the node lives once every link is followed. Two paths name one file exactly when
    /// this is equal.
    pub physical: String,
}

impl Metadata {
    fn root_owned(mode: u32) -> Self {
        Self {
            mode,
            uid: 0,
            gid: 0,
            mtime: PERSONA_MTIME,
        }
    }
}

impl Node {
    pub fn regular(blob: Blob, mode: u32) -> Self {
        Self {
            kind: NodeKind::Regular(blob),
            meta: Metadata::root_owned(mode),
        }
    }

    pub fn directory(entries: Vec<String>) -> Self {
        Self {
            kind: NodeKind::Directory(DirListing { entries }),
            meta: Metadata::root_owned(MODE_DIRECTORY),
        }
    }

    pub fn symlink(target: &str) -> Self {
        Self {
            kind: NodeKind::Symlink {
                target: target.to_string(),
            },
            meta: Metadata::root_owned(MODE_SYMLINK),
        }
    }

    pub fn device(device: Device) -> Self {
        Self {
            kind: NodeKind::Device(device),
            meta: Metadata::root_owned(MODE_DEVICE),
        }
    }
}

/// Bytes of the recorded header every synthetic executable starts with.
pub const ELF_HEADER_LEN: usize = 64;

/// A synthetic executable: a recorded header, then filler out to `len`. The whole file is this
/// description, so it costs the same to hold whatever its size, and any range of it costs only the
/// bytes asked for.
///
/// The filler byte at offset `i >= 64` is `0x80 | (i & 0x3f)`. The high bit is always set, so filler
/// is never a newline: the first newline a line-reading command meets is one the header carries or
/// the one planted at `newline_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfImage {
    pub header: [u8; ELF_HEADER_LEN],
    pub len: u64,
    /// An offset at or past the header that holds `0x0a` instead of filler.
    pub newline_at: Option<u64>,
}

impl ElfImage {
    /// Byte `index` of the file; meaningful for `index < len`.
    #[deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    pub fn byte_at(&self, index: u64) -> u8 {
        if let Some(byte) = usize::try_from(index)
            .ok()
            .and_then(|at| self.header.get(at))
        {
            return *byte;
        }
        if self.newline_at == Some(index) {
            return 0x0a;
        }
        0x80 | u8::try_from(index & 0x3f).unwrap_or(0)
    }
}

/// Bounded byte content of a regular file. Baked files are one small `Bytes` piece; `Fill`,
/// `Counter` and `Elf` are large synthetic bodies with O(1) storage.
#[derive(Debug, Clone)]
pub struct Blob {
    /// Invariant: `len` is the sum of the pieces' lengths; at most 64 pieces.
    pieces: Vec<Piece>,
    len: u64,
}

#[derive(Debug, Clone)]
enum Piece {
    Bytes(Arc<Vec<u8>>),
    Fill { byte: u8, len: u64 },
    Counter { seed: u64, len: u64 },
    Elf(ElfImage),
}

impl Piece {
    fn len(&self) -> u64 {
        match self {
            Piece::Bytes(bytes) => bytes.len() as u64,
            Piece::Fill { len, .. } | Piece::Counter { len, .. } => *len,
            Piece::Elf(image) => image.len,
        }
    }

    /// Append the bytes at piece-local offsets `[from, to)`; `to` is at most `self.len()`.
    #[deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn append_range(&self, from: u64, to: u64, out: &mut Vec<u8>) {
        match self {
            Piece::Bytes(bytes) => {
                let from = usize::try_from(from).unwrap_or(usize::MAX);
                let to = usize::try_from(to).unwrap_or(usize::MAX);
                if let Some(slice) = bytes.get(from..to) {
                    out.extend_from_slice(slice);
                }
            }
            Piece::Fill { byte, .. } => {
                let n = usize::try_from(to.saturating_sub(from)).unwrap_or(0);
                out.resize(out.len().saturating_add(n), *byte);
            }
            Piece::Counter { seed, .. } => {
                out.extend((from..to).map(|i| counter_byte(*seed, i)));
            }
            Piece::Elf(image) => {
                out.extend((from..to).map(|i| image.byte_at(i)));
            }
        }
    }
}

/// Byte `index` of the deterministic counter-mode stream for `seed` (splitmix64 over 8-byte
/// blocks).
#[deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn counter_byte(seed: u64, index: u64) -> u8 {
    let block = (index >> 3).wrapping_add(1);
    let mut z = seed.wrapping_add(block.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let lane = usize::try_from(index & 7).unwrap_or(0);
    z.to_le_bytes().get(lane).copied().unwrap_or(0)
}

impl Blob {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let len = bytes.len() as u64;
        Self {
            pieces: vec![Piece::Bytes(Arc::new(bytes))],
            len,
        }
    }

    /// `len` copies of `byte`, stored in O(1).
    pub fn fill(byte: u8, len: u64) -> Self {
        Self {
            pieces: vec![Piece::Fill { byte, len }],
            len,
        }
    }

    /// `len` bytes of the deterministic counter-mode stream for `seed`, stored in O(1).
    pub fn counter(seed: u64, len: u64) -> Self {
        Self {
            pieces: vec![Piece::Counter { seed, len }],
            len,
        }
    }

    /// A whole file that is `image`, stored in O(1).
    pub fn elf(image: ElfImage) -> Self {
        Self {
            len: image.len,
            pieces: vec![Piece::Elf(image)],
        }
    }

    /// The image this blob is, when it is exactly one and nothing has been added to it.
    pub fn as_elf(&self) -> Option<ElfImage> {
        match self.pieces.as_slice() {
            [Piece::Elf(image)] => Some(*image),
            _ => None,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Materialized bytes only; `Fill`, `Counter` and `Elf` pieces contribute nothing. The
    /// connection budget sums this over the overlay.
    pub fn owned_bytes(&self) -> u64 {
        self.pieces
            .iter()
            .map(|piece| match piece {
                Piece::Bytes(bytes) => bytes.len() as u64,
                Piece::Fill { .. } | Piece::Counter { .. } | Piece::Elf(_) => 0,
            })
            .sum()
    }

    /// The bytes in `[off, off + min(max_len, len - off))`, empty when `off >= len`. Allocates at
    /// most `max_len` bytes; an overflowing `off + max_len` saturates to the blob's end instead of
    /// wrapping.
    #[deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    pub fn read_range(&self, off: u64, max_len: u64) -> Vec<u8> {
        let end = off.saturating_add(max_len).min(self.len);
        if off >= end {
            return Vec::new();
        }
        let want = usize::try_from(end.saturating_sub(off)).unwrap_or(0);
        let mut out = Vec::with_capacity(want);
        let mut piece_start = 0u64;
        for piece in &self.pieces {
            let piece_end = piece_start.saturating_add(piece.len());
            if piece_end > off && piece_start < end {
                let from = off.max(piece_start).saturating_sub(piece_start);
                let to = end.min(piece_end).saturating_sub(piece_start);
                piece.append_range(from, to, &mut out);
            }
            piece_start = piece_end;
            if piece_start >= end {
                break;
            }
        }
        out
    }
}

/// One row of a mount table. `opts` is the comma-separated option string `/proc/mounts` shows.
#[derive(Debug, Clone, Copy)]
pub struct MountEntry {
    pub source: &'static str,
    pub point: &'static str,
    pub fstype: &'static str,
    pub opts: &'static str,
}

impl MountEntry {
    const fn new(
        source: &'static str,
        point: &'static str,
        fstype: &'static str,
        opts: &'static str,
    ) -> Self {
        Self {
            source,
            point,
            fstype,
            opts,
        }
    }

    fn opt(&self, name: &str) -> bool {
        self.opts.split(',').any(|opt| opt == name)
    }

    /// Whether `path` is the mount point or below it, on a component boundary (`/systemx` is not
    /// under `/system`).
    fn covers(&self, path: &str) -> bool {
        self.point == "/"
            || path == self.point
            || path
                .strip_prefix(self.point)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// The immutable persona filesystem.
struct Snapshot {
    nodes: HashMap<String, Node>,
    mounts: &'static [MountEntry],
}

impl Snapshot {
    /// The mount governing `physical_path`: the covering entry with the longest mount point.
    fn mount_for(&self, physical_path: &str) -> Option<&MountEntry> {
        self.mounts
            .iter()
            .filter(|mount| mount.covers(physical_path))
            .max_by_key(|mount| mount.point.len())
    }

    fn is_ro(&self, physical_path: &str) -> bool {
        self.mount_for(physical_path)
            .is_some_and(|mount| mount.opt("ro"))
    }

    fn is_noexec(&self, physical_path: &str) -> bool {
        self.mount_for(physical_path)
            .is_some_and(|mount| mount.opt("noexec"))
    }
}

/// What the session changed on top of the snapshot. Overlay nodes are keyed by physical path.
#[derive(Default)]
struct Overlay {
    nodes: HashMap<String, Node>,
    /// Physical paths removed this session, baked-in ones included: a file the shell said it
    /// deleted must stop being readable, or the next `cat` contradicts the `rm`.
    tombstones: HashSet<String>,
    /// `chattr` bits by physical path; an entry keeps its slot (and charge) once made.
    attrs: HashMap<String, u32>,
}

/// A snapshot of a plausible Linux filesystem, built fresh by `new()` for every session, plus what
/// the attacker changed. Files an attacker creates (a bare redirection, a download, a `cp`) live
/// only for the session: loaders probe for a writable directory that way before choosing where
/// to drop a payload, and the probe must succeed where a real box would let it. The hostname- and
/// OS-bearing files are sourced from [`crate::persona`] so they cannot contradict the shell's
/// `uname`, the sensor prompts, or the other sensors' banners.
pub struct FakeFs {
    snapshot: Arc<Snapshot>,
    overlay: Overlay,
    /// Charged by every write, so no writer can bypass it. Shared with the other filesystems and
    /// shells on the same connection.
    budget: Arc<ConnectionBudget>,
    /// Nodes the shell derives from state the snapshot cannot hold (the process table behind
    /// `/proc/<pid>`), keyed by physical path. Read after the snapshot and never charged: the
    /// owner replaces the whole set, bounded by [`GENERATED_MAX`], and a session's own writes
    /// and removals land in the overlay above it.
    generated: HashMap<String, Node>,
}

/// The most generated nodes one filesystem holds. The shell's process table is a handful of
/// processes with a few nodes each; the bound only keeps a caller's bug from growing the map.
pub const GENERATED_MAX: usize = 256;

impl Default for FakeFs {
    fn default() -> Self {
        Self::new()
    }
}

/// Assembles a snapshot's nodes. Everything starts root-owned; only the modeled binaries are
/// executable.
struct Builder {
    nodes: HashMap<String, Node>,
}

impl Builder {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    fn file(&mut self, path: &str, content: impl Into<Vec<u8>>) {
        self.nodes.insert(
            path.to_string(),
            Node::regular(Blob::from_bytes(content), MODE_FILE),
        );
    }

    fn binary(&mut self, path: &str, content: impl Into<Vec<u8>>) {
        self.nodes.insert(
            path.to_string(),
            Node::regular(Blob::from_bytes(content), MODE_EXECUTABLE),
        );
    }

    /// A modeled Ubuntu binary at its physical path, with its recorded mode.
    fn image(&mut self, binary: &BinaryImage) {
        self.nodes.insert(
            binary.path.to_string(),
            Node::regular(binary.blob(), binary.mode),
        );
    }

    fn dir(&mut self, path: &str, entries: &[&str]) {
        self.nodes.insert(
            path.to_string(),
            Node::directory(entries.iter().map(|e| e.to_string()).collect()),
        );
    }

    fn symlink(&mut self, path: &str, target: &str) {
        self.nodes.insert(path.to_string(), Node::symlink(target));
    }

    fn device(&mut self, path: &str, device: Device) {
        self.nodes.insert(path.to_string(), Node::device(device));
    }

    /// An empty directory node for every child the `/` listing advertises that has no node yet,
    /// except the names in `files`, which the listing shows but the box does not model as
    /// directories.
    fn advertise_root_children(&mut self, files: &[&str]) {
        let children: Vec<String> = match self.nodes.get("/").map(|n| &n.kind) {
            Some(NodeKind::Directory(listing)) => listing.entries.clone(),
            _ => Vec::new(),
        };
        for child in children {
            let path = format!("/{child}");
            if !files.contains(&child.as_str()) && !self.nodes.contains_key(&path) {
                self.nodes.insert(path, Node::directory(Vec::new()));
            }
        }
    }

    /// Give every node a directory for each missing ancestor (`/proc/self` exists because
    /// `/proc/self/mounts` does). Idempotent.
    fn ensure_ancestor_dirs(&mut self) {
        let paths: Vec<String> = self.nodes.keys().cloned().collect();
        for path in paths {
            let mut current = path;
            while let Some(parent) = parent_of(&current) {
                if parent == current {
                    break;
                }
                if !self.nodes.contains_key(&parent) {
                    self.nodes
                        .insert(parent.clone(), Node::directory(Vec::new()));
                }
                current = parent;
            }
        }
    }

    fn finish(mut self, mounts: &'static [MountEntry]) -> Snapshot {
        self.ensure_ancestor_dirs();
        Snapshot {
            nodes: self.nodes,
            mounts,
        }
    }
}

impl FakeFs {
    fn from_snapshot(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            overlay: Overlay::default(),
            budget: ConnectionBudget::new(BudgetLimits::default()),
            generated: HashMap::new(),
        }
    }

    /// Replace the generated nodes with `nodes` (physical path to node), keeping at most
    /// [`GENERATED_MAX`] of them in path order so the kept set does not depend on map order.
    /// The snapshot and the session's overlay are untouched, and a path the snapshot holds is
    /// still answered by the snapshot.
    pub fn set_generated(&mut self, nodes: HashMap<String, Node>) {
        let mut paths: Vec<String> = nodes.keys().cloned().collect();
        paths.sort_unstable();
        paths.truncate(GENERATED_MAX);
        let mut nodes = nodes;
        self.generated = paths
            .into_iter()
            .filter_map(|path| nodes.remove(&path).map(|node| (path, node)))
            .collect();
    }

    /// This filesystem charging `budget` instead of its own standard-limits one, so it shares a
    /// ceiling with the rest of its connection.
    pub fn with_budget(mut self, budget: Arc<ConnectionBudget>) -> Self {
        self.budget = budget;
        self
    }

    /// The mount table this persona presents, in mount order.
    pub fn mounts(&self) -> &'static [MountEntry] {
        self.snapshot.mounts
    }

    /// The mount `logical_abs` sits on once every link is followed, `None` when nothing is there.
    pub fn mount_of(&self, logical_abs: &str) -> Option<MountEntry> {
        let physical = self.resolve(logical_abs, true).ok()?;
        self.node_at(&physical)?;
        self.snapshot.mount_for(&physical).copied()
    }

    /// The budget this filesystem charges; a shell built on it charges the same one.
    pub fn budget(&self) -> &Arc<ConnectionBudget> {
        &self.budget
    }

    pub fn new() -> Self {
        let host = persona::hostname();
        let mut b = Builder::new();

        b.file("/etc/hostname", format!("{host}\n"));
        b.file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
             sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
             mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
             www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
             sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n\
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        );
        b.file(
            "/etc/hosts",
            format!(
                "127.0.0.1 localhost\n\
                 127.0.1.1 {host}\n\
                 \n\
                 ::1 localhost ip6-localhost ip6-loopback\n\
                 ff02::1 ip6-allnodes\n\
                 ff02::2 ip6-allrouters\n"
            ),
        );
        b.file(
            "/etc/os-release",
            format!(
                "NAME=\"{name}\"\n\
                 VERSION=\"{version}\"\n\
                 ID=ubuntu\n\
                 ID_LIKE=debian\n\
                 PRETTY_NAME=\"{pretty}\"\n\
                 VERSION_ID=\"{vid}\"\n",
                name = persona::OS_NAME,
                version = persona::OS_VERSION,
                pretty = persona::OS_PRETTY,
                vid = persona::OS_VERSION_ID,
            ),
        );
        b.file("/proc/version", format!("{}\n", persona::proc_version()));
        // One mount table behind every file that exposes it, so `cat /proc/mounts`,
        // `/proc/self/mounts`, `/etc/mtab` (a symlink to the second, as on Ubuntu), `mountinfo`
        // and the shell's `mount` cannot disagree. `cat /proc/mounts` used to say "No such
        // file", which no Linux box does.
        b.file("/proc/mounts", render_mounts(&MOUNT_TABLE));
        b.file("/proc/self/mounts", render_mounts(&MOUNT_TABLE));
        b.file("/proc/self/mountinfo", render_mountinfo(&MOUNT_TABLE));
        b.file(
            "/proc/cpuinfo",
            "processor\t: 0\n\
             vendor_id\t: GenuineIntel\n\
             model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n\
             cpu cores\t: 1\n",
        );
        b.file("/proc/meminfo", render_meminfo(&UBUNTU_MEMINFO));

        b.dir(
            "/",
            &[
                "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc",
                "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
            ],
        );
        // A freshly-booted honeypot has an empty /tmp and an empty (dotfiles-only, so invisible
        // to a plain `ls`) /root - both are present as *known, empty* directories rather than
        // absent, so `ls` on either returns a correct empty listing instead of misreporting a
        // brand-new box as not even having a /root or /tmp at all.
        b.dir("/tmp", &[]);
        b.dir("/root", &[]);
        b.dir(
            "/etc",
            &["hostname", "mtab", "passwd", "hosts", "os-release"],
        );
        b.dir("/home", &["ubuntu"]);
        // Every mount point in the table is a directory the box presents, so `cd` into one
        // that `cat /proc/mounts` lists never fails.
        b.dir("/boot", &["efi", "grub"]);
        b.dir("/boot/efi", &["EFI"]);
        b.dir(
            "/sys",
            &[
                "block",
                "bus",
                "class",
                "dev",
                "devices",
                "firmware",
                "fs",
                "hypervisor",
                "kernel",
                "module",
                "power",
            ],
        );
        b.dir("/sys/fs", &["bpf", "cgroup", "ext4", "fuse", "pstore"]);
        b.dir("/sys/fs/cgroup", &[]);
        b.dir("/sys/fs/bpf", &[]);
        b.dir("/sys/fs/pstore", &[]);
        b.dir("/sys/fs/fuse", &["connections"]);
        b.dir("/sys/fs/fuse/connections", &[]);
        b.dir(
            "/sys/kernel",
            &[
                "config",
                "debug",
                "mm",
                "security",
                "slab",
                "tracing",
                "uevent_seqnum",
            ],
        );
        b.dir("/sys/kernel/config", &[]);
        b.dir("/sys/kernel/debug", &[]);
        b.dir("/sys/kernel/security", &[]);
        b.dir("/sys/kernel/tracing", &[]);
        b.dir("/dev/pts", &["0", "ptmx"]);
        b.dir("/dev/hugepages", &[]);
        b.dir("/dev/mqueue", &[]);
        b.dir("/run/lock", &[]);
        b.dir("/run/user", &["0"]);
        b.dir("/run/user/0", &[]);
        // The directories a loader probes for somewhere writable (`>/var/run/.x && cd /var/run`,
        // then /mnt, /usr, /dev, /dev/shm, /tmp, /var). Every one exists on a real Ubuntu box,
        // so each probe must succeed here or the chain's `&& cd` never runs and the loader's
        // final marker, which it keys its next stage on, is never printed. Listings are the
        // stock contents, minus anything that would need a deeper model to be consistent.
        b.dir(
            "/var",
            &[
                "backups", "cache", "lib", "local", "lock", "log", "mail", "opt", "run", "spool",
                "tmp",
            ],
        );
        b.dir("/var/tmp", &[]);
        b.dir("/run", &["lock", "user"]);
        b.dir("/mnt", &[]);
        b.dir(
            "/usr",
            &[
                "bin", "games", "include", "lib", "lib64", "local", "sbin", "share", "src",
            ],
        );
        b.dir(
            "/dev",
            &[
                "hugepages",
                "mqueue",
                "null",
                "zero",
                "random",
                "urandom",
                "tty",
                "pts",
                "shm",
                "stdin",
                "stdout",
                "stderr",
            ],
        );
        b.dir("/dev/shm", &[]);
        b.advertise_root_children(&[]);

        // The binaries a loader chain touches: `cp /bin/busybox .` then running the copy is a
        // standard Mirai staging step, and probes read `/bin/echo` and `/bin/ls` for the ELF
        // header. Each is a synthetic image with the recorded header and size. They live at their
        // physical `/usr/bin` paths; `/bin` is the usrmerge symlink.
        for binary in binaries::BINARIES {
            b.image(binary);
        }
        for alias in binaries::ALIASES {
            b.symlink(alias.path, alias.target);
        }
        b.binary(binaries::WHICH_PATH, binaries::WHICH_SCRIPT);
        // The usrmerge layout: the top-level names are symlinks into /usr, with relative targets
        // as the real ones have, and their targets must be directories.
        for name in ["bin", "sbin", "lib", "lib64"] {
            b.symlink(&format!("/{name}"), &format!("usr/{name}"));
        }
        b.dir("/usr/sbin", &[]);
        b.dir("/usr/lib", &[]);
        b.dir("/usr/lib64", &[]);
        b.symlink("/var/run", "/run");
        b.symlink("/var/lock", "/run/lock");
        b.symlink("/etc/mtab", "/proc/self/mounts");

        b.device("/dev/null", Device::Null);
        b.device("/dev/zero", Device::Zero);
        b.device("/dev/random", Device::Random);
        b.device("/dev/urandom", Device::Urandom);
        b.device("/dev/tty", Device::Tty);
        // The fd links point into a /proc/self/fd this box does not model yet, so opening one
        // fails as a dangling link does.
        b.symlink("/dev/stdin", "/proc/self/fd/0");
        b.symlink("/dev/stdout", "/proc/self/fd/1");
        b.symlink("/dev/stderr", "/proc/self/fd/2");
        b.symlink("/dev/fd", "/proc/self/fd");

        Self::from_snapshot(b.finish(&MOUNT_TABLE))
    }

    /// The rooted Nexus 5 `sensor-adb` presents: the same snapshot machinery over an Android
    /// filesystem, so a bot that reaches ADB and looks around finds the phone the CNXN banner
    /// claimed. Its identity comes from [`crate::persona`]'s Android half, the same way the
    /// server's comes from the Ubuntu half.
    pub fn android() -> Self {
        let mut b = Builder::new();
        b.file(
            "/default.prop",
            "#\n# ADDITIONAL_DEFAULT_PROPERTIES\n#\n\
             ro.secure=0\n\
             ro.allow.mock.location=0\n\
             ro.debuggable=1\n\
             ro.adb.secure=0\n\
             persist.sys.usb.config=adb\n",
        );
        b.file("/system/build.prop", android_build_prop());
        b.file(
            "/proc/version",
            format!("{}\n", persona::android_proc_version()),
        );
        b.file(
            "/proc/cpuinfo",
            "Processor\t: ARMv7 Processor rev 0 (v7l)\n\
             processor\t: 0\n\
             BogoMIPS\t: 38.40\n\
             Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt \n\
             CPU implementer\t: 0x51\n\
             CPU architecture: 7\n\
             CPU variant\t: 0x2\n\
             CPU part\t: 0x06f\n\
             CPU revision\t: 0\n\
             \n\
             Hardware\t: Qualcomm MSM 8974 HAMMERHEAD (Flattened Device Tree)\n",
        );
        b.file(
            "/system/etc/hosts",
            "127.0.0.1       localhost\n::1             ip6-localhost\n",
        );
        b.file("/proc/meminfo", render_meminfo(&ANDROID_MEMINFO));
        b.file("/proc/mounts", render_mounts(&ANDROID_MOUNT_TABLE));
        b.file("/proc/self/mounts", render_mounts(&ANDROID_MOUNT_TABLE));
        b.file(
            "/proc/self/mountinfo",
            render_mountinfo(&ANDROID_MOUNT_TABLE),
        );

        b.dir(
            "/",
            &[
                "acct",
                "cache",
                "config",
                "d",
                "data",
                "default.prop",
                "dev",
                "etc",
                "init",
                "init.rc",
                "mnt",
                "oem",
                "persist",
                "proc",
                "root",
                "sbin",
                "sdcard",
                "storage",
                "sys",
                "system",
                "ueventd.rc",
                "vendor",
            ],
        );
        b.dir(
            "/system",
            &[
                "app",
                "bin",
                "build.prop",
                "etc",
                "fonts",
                "framework",
                "lib",
                "media",
                "priv-app",
                "tts",
                "usr",
                "vendor",
                "xbin",
            ],
        );
        b.dir(
            "/system/bin",
            &[
                "am",
                "app_process",
                "cat",
                "chmod",
                "dalvikvm",
                "date",
                "df",
                "du",
                "dumpsys",
                "env",
                "free",
                "getenforce",
                "getprop",
                "hostname",
                "ifconfig",
                "ip",
                "linker",
                "logcat",
                "ls",
                "mount",
                "netstat",
                "ping",
                "pm",
                "ps",
                "reboot",
                "route",
                "screencap",
                "setprop",
                "sh",
                "toolbox",
                "top",
                "toybox",
                "umount",
                "uptime",
                "wm",
            ],
        );
        b.dir("/system/xbin", &["busybox", "su"]);
        b.dir("/system/etc", &["hosts"]);
        b.dir(
            "/data",
            &[
                "anr",
                "app",
                "backup",
                "dalvik-cache",
                "data",
                "local",
                "media",
                "misc",
                "property",
                "system",
                "user",
            ],
        );
        b.dir("/data/local", &["tmp"]);
        // The two directories every ADB-borne dropper writes to.
        b.dir("/data/local/tmp", &[]);
        b.dir(
            "/sdcard",
            &[
                "Alarms",
                "Android",
                "DCIM",
                "Download",
                "Movies",
                "Music",
                "Notifications",
                "Pictures",
                "Podcasts",
                "Ringtones",
            ],
        );
        b.dir("/storage", &["emulated", "self"]);
        b.dir("/storage/emulated", &["0", "legacy"]);
        b.dir("/storage/emulated/0", &[]);
        b.dir("/cache", &["backup", "lost+found", "recovery"]);
        b.dir("/dev", &["block", "cpuctl", "null", "socket", "zero"]);
        b.dir("/mnt", &["asec", "obb", "runtime", "secure", "shell"]);
        b.dir("/sys", &["block", "class", "devices", "fs", "kernel"]);
        b.dir("/proc", &[]);
        b.dir("/root", &[]);
        b.dir("/sbin", &["adbd", "healthd", "ueventd", "watchdogd"]);
        b.dir("/vendor", &["firmware", "lib"]);
        // The root listing shows these three but the box models no content for them, so they are
        // not directories.
        b.advertise_root_children(&["default.prop", "init", "init.rc", "ueventd.rc"]);

        for binary in ANDROID_EXECUTABLE_BINARIES {
            b.binary(binary, "\u{7f}ELF\u{1}\u{1}\u{1}\0");
        }
        b.device("/dev/null", Device::Null);
        b.device("/dev/zero", Device::Zero);

        Self::from_snapshot(b.finish(&ANDROID_MOUNT_TABLE))
    }

    /// The live node at a physical path: an overlay node shadows the snapshot's, and a tombstone
    /// hides both.
    fn node_at(&self, physical: &str) -> Option<&Node> {
        if self.overlay.tombstones.contains(physical) {
            return None;
        }
        self.overlay
            .nodes
            .get(physical)
            .or_else(|| self.snapshot.nodes.get(physical))
            .or_else(|| self.generated.get(physical))
    }

    /// Resolve a logical absolute path to a physical one, following symlinks component by
    /// component. A relative link target joins against the link's parent, an absolute one
    /// restarts at `/`. `follow_final` false leaves a symlink in the last position alone (what
    /// `rm` acts on). The last component may be absent, so a creator can resolve the path it is
    /// about to make.
    fn resolve(&self, logical_abs: &str, follow_final: bool) -> Result<String, FsError> {
        self.resolve_with(logical_abs, follow_final, false)
    }

    /// [`Self::resolve`], with `allow_missing` letting a missing non-final component stand: the
    /// rest of the path is then kept as typed (`..` still climbing), as `realpath -m` does.
    fn resolve_with(
        &self,
        logical_abs: &str,
        follow_final: bool,
        allow_missing: bool,
    ) -> Result<String, FsError> {
        let mut pending: VecDeque<String> = logical_abs
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .map(str::to_string)
            .collect();
        let mut resolved: Vec<String> = Vec::new();
        let mut hops = 0u32;
        while let Some(component) = pending.pop_front() {
            if component == ".." {
                resolved.pop();
                continue;
            }
            let candidate = format!("/{}", join_with(&resolved, &component));
            let is_last = pending.is_empty();
            match self.node_at(&candidate).map(|node| &node.kind) {
                Some(NodeKind::Symlink { target }) if !is_last || follow_final => {
                    hops = hops.saturating_add(1);
                    if hops > MAX_SYMLINK_HOPS {
                        return Err(FsError::TooManyLinks);
                    }
                    if target.starts_with('/') {
                        resolved.clear();
                    }
                    for part in target.split('/').rev().filter(|c| !c.is_empty()) {
                        pending.push_front(part.to_string());
                    }
                }
                Some(NodeKind::Directory(_)) => resolved.push(component),
                Some(_) if !is_last => return Err(FsError::NotADirectory),
                None if !is_last && !allow_missing => {
                    return Err(FsError::NoSuchDirectory(candidate));
                }
                Some(_) | None => resolved.push(component),
            }
        }
        Ok(format!("/{}", resolved.join("/")))
    }

    /// What the symlink at `logical_abs` points to, exactly as stored (`usr/bin` for `/bin`), or
    /// `None` when the path is not a symlink or does not exist. Only the final component is left
    /// unfollowed; the directories leading to it resolve as they do for any path.
    pub fn link_target(&self, logical_abs: &str) -> Option<String> {
        let physical = self.resolve(logical_abs, false).ok()?;
        match self.node_at(&physical).map(|node| &node.kind) {
            Some(NodeKind::Symlink { target }) => Some(target.clone()),
            _ => None,
        }
    }

    /// The physical path `logical_abs` names once every symlink is followed, for the way `mode`
    /// asks for it. `None` when the mode's requirement fails or resolution does (a loop, a
    /// non-directory in the middle).
    pub fn canonicalize(&self, logical_abs: &str, mode: Canonical) -> Option<String> {
        let physical = self
            .resolve_with(logical_abs, true, mode == Canonical::AllowMissing)
            .ok()?;
        if mode == Canonical::Existing && self.node_at(&physical).is_none() {
            return None;
        }
        Some(physical)
    }

    /// The physical path and live node `path` names, following every symlink.
    fn lookup(&self, path: &str) -> Option<(String, &Node)> {
        let physical = self.resolve(path, true).ok()?;
        let node = self.node_at(&physical)?;
        Some((physical, node))
    }

    /// The attributes of the node `logical_abs` names, for `test` and the like. `follow` false
    /// leaves a symlink in the last position alone (`test -L`). `None` when nothing is there, a
    /// dangling link's target included.
    pub fn stat(&self, logical_abs: &str, follow: bool) -> Option<Stat> {
        let physical = self.resolve(logical_abs, follow).ok()?;
        let node = self.node_at(&physical)?;
        let (kind, size) = match &node.kind {
            NodeKind::Regular(blob) => (FileKind::Regular, blob.len()),
            NodeKind::Directory(_) => (FileKind::Directory, 0),
            NodeKind::Symlink { target } => (FileKind::Symlink, target.len() as u64),
            NodeKind::Device(_) => (FileKind::CharDevice, 0),
        };
        Some(Stat {
            kind,
            mode: node.meta.mode,
            uid: node.meta.uid,
            gid: node.meta.gid,
            mtime: node.meta.mtime,
            size,
            read_only: self.snapshot.is_ro(&physical),
            no_exec: self.snapshot.is_noexec(&physical),
            physical,
        })
    }

    /// Mark a file the attacker created this session executable (`chmod +x` / `chmod 777`).
    /// Returns false when `path` is not such a file; the baked-in files keep their modes.
    pub fn mark_executable(&mut self, path: &str) -> bool {
        let Ok(physical) = self.resolve(path, true) else {
            return false;
        };
        if self.overlay.tombstones.contains(&physical) {
            return false;
        }
        match self.overlay.nodes.get_mut(&physical) {
            Some(node) if matches!(node.kind, NodeKind::Regular(_)) => {
                node.meta.mode |= EXEC_BITS;
                true
            }
            _ => false,
        }
    }

    /// Whether running `path` as a command would start: a regular file with an execute bit, not
    /// on a `noexec` mount.
    pub fn is_executable(&self, path: &str) -> bool {
        self.lookup(path).is_some_and(|(physical, node)| {
            matches!(node.kind, NodeKind::Regular(_))
                && node.meta.mode & EXEC_BITS != 0
                && !self.snapshot.is_noexec(&physical)
        })
    }

    /// Up to `max_len` bytes of `path` from `off`. A directory is `IsADirectory`, an absent or
    /// removed path `NoSuchFile`; a device answers with its own stream.
    pub fn read_range(&self, path: &str, off: u64, max_len: u64) -> Result<Vec<u8>, FsError> {
        let physical = self.resolve(path, true).map_err(|error| match error {
            FsError::NoSuchDirectory(_) => FsError::NoSuchFile,
            other => other,
        })?;
        match self.node_at(&physical).map(|node| &node.kind) {
            Some(NodeKind::Regular(blob)) => Ok(blob.read_range(off, max_len)),
            Some(NodeKind::Device(device)) => Ok(device.read(off, max_len)),
            Some(NodeKind::Directory(_)) => Err(FsError::IsADirectory),
            Some(NodeKind::Symlink { .. }) | None => Err(FsError::NoSuchFile),
        }
    }

    /// The first `cap` bytes of `path`.
    pub fn read_all(&self, path: &str, cap: u64) -> Result<Vec<u8>, FsError> {
        self.read_range(path, 0, cap)
    }

    /// The content and mode of a regular file, for `cp`: cloning the blob shares its pieces.
    pub fn content_and_mode(&self, path: &str) -> Result<(Blob, u32), FsError> {
        match self.lookup(path).map(|(_, node)| node) {
            Some(Node {
                kind: NodeKind::Regular(blob),
                meta,
            }) => Ok((blob.clone(), meta.mode)),
            Some(Node {
                kind: NodeKind::Directory(_),
                ..
            }) => Err(FsError::IsADirectory),
            _ => Err(FsError::NoSuchFile),
        }
    }

    /// The names in directory `path`: the modeled ones plus what the session created, less what
    /// it removed. `None` for anything that is not a directory this box presents.
    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        let (physical, node) = self.lookup(path)?;
        let NodeKind::Directory(listing) = &node.kind else {
            return None;
        };
        let prefix = if physical == "/" {
            "/".to_string()
        } else {
            format!("{physical}/")
        };
        let mut entries = listing.entries.clone();
        // The generated children come in path order, so a listing never depends on map order.
        let mut generated: Vec<&str> = self
            .generated
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix))
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .collect();
        generated.sort_unstable();
        for name in generated {
            if !entries.iter().any(|entry| entry == name) {
                entries.push(name.to_string());
            }
        }
        for key in self.overlay.nodes.keys() {
            if let Some(name) = key
                .strip_prefix(&prefix)
                .filter(|name| !name.is_empty() && !name.contains('/'))
                && !entries.iter().any(|entry| entry == name)
            {
                entries.push(name.to_string());
            }
        }
        entries.retain(|name| !self.overlay.tombstones.contains(&format!("{prefix}{name}")));
        Some(entries)
    }

    /// Whether `path` names a file or device this box presents (a baked-in or created one).
    pub fn file_exists(&self, path: &str) -> bool {
        self.lookup(path).is_some_and(|(_, node)| {
            matches!(node.kind, NodeKind::Regular(_) | NodeKind::Device(_))
        })
    }

    /// Whether `path` is a directory this box presents, following symlinks. `cd` and the write
    /// probes consult this, so the shell never lets an attacker enter a directory that `ls /`
    /// did not show, and never refuses one it did.
    pub fn is_dir(&self, path: &str) -> bool {
        self.lookup(path)
            .is_some_and(|(_, node)| matches!(node.kind, NodeKind::Directory(_)))
    }

    /// Resolve a write target to its physical path, mapping a missing parent under a read-only
    /// mount to the refusal a real write there gets.
    fn resolve_for_write(&self, path: &str) -> Result<String, FsError> {
        self.resolve_for_write_with(path, true)
    }

    /// [`Self::resolve_for_write`] with `follow_final` false for a call that creates the name
    /// itself rather than writing through it (a symlink replaces nothing it points at).
    fn resolve_for_write_with(&self, path: &str, follow_final: bool) -> Result<String, FsError> {
        self.resolve(path, follow_final)
            .map_err(|error| match error {
                FsError::NoSuchDirectory(missing) if self.snapshot.is_ro(&missing) => {
                    FsError::ReadOnly
                }
                other => other,
            })
    }

    /// Write `bytes` to `path`, as a download saving its body or a redirection does.
    ///
    /// Bytes that are exactly a modeled binary (`cat /proc/self/exe > FILE`) are stored as that
    /// image, which is the same content held in O(1) instead of a couple of megabytes.
    pub fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let blob = binaries::image_blob_for(bytes).unwrap_or_else(|| Blob::from_bytes(bytes));
        self.write_blob(path, blob, MODE_FILE)
    }

    /// Write `blob` to `path` with `mode`. Fails the way a real write does, so a loader dropping
    /// into a directory this box denies, or onto a read-only mount, sees the refusal rather than
    /// a success it can never verify. A device target takes the write into its own semantics and
    /// stores nothing. Overwriting a file keeps its execute bits: a payload saved over a
    /// `chmod`ed name stays runnable, as it does when truncated in place.
    ///
    /// The name is checked first, then the connection budget is charged for the blob's
    /// materialized bytes (net of what the path already held) and, for a path with no overlay
    /// slot yet, one node. A refusal inserts nothing.
    pub fn write_blob(&mut self, path: &str, blob: Blob, mode: u32) -> Result<(), FsError> {
        self.budget.check_name(path)?;
        let physical = self.resolve_for_write(path)?;
        if self.snapshot.is_ro(&physical) {
            return Err(FsError::ReadOnly);
        }
        let mut mode = mode;
        match self.node_at(&physical).map(|node| (&node.kind, node.meta)) {
            Some((NodeKind::Directory(_), _)) => return Err(FsError::IsADirectory),
            Some((NodeKind::Device(device), _)) => return device.write(),
            Some((NodeKind::Regular(_), existing)) => mode |= existing.mode & EXEC_BITS,
            _ => {}
        }
        let new_bytes = blob.owned_bytes();
        let old_bytes = self.overlay_owned_bytes(&physical);
        // A path already holding an overlay node or a tombstone owns its slot; only a baked or
        // brand-new path needs one.
        let needs_slot = !self.overlay.nodes.contains_key(&physical)
            && !self.overlay.tombstones.contains(&physical);
        // A new slot also holds its path, charged with the content and kept charged for the life
        // of the slot: a tombstone keeps the path resident.
        let path_bytes = if needs_slot {
            u64::try_from(physical.len()).unwrap_or(u64::MAX)
        } else {
            0
        };
        let charged = new_bytes.saturating_add(path_bytes);
        self.budget.replace_bytes(old_bytes, charged)?;
        if needs_slot && let Err(error) = self.budget.charge_node() {
            // Undoing a swap that just fit cannot itself be refused.
            let _ = self.budget.replace_bytes(charged, old_bytes);
            return Err(error.into());
        }
        self.overlay.tombstones.remove(&physical);
        self.overlay
            .nodes
            .insert(physical, Node::regular(blob, mode));
        Ok(())
    }

    /// Bytes charged for the overlay node at `physical`: its blob's materialized bytes, zero for
    /// anything else.
    fn overlay_owned_bytes(&self, physical: &str) -> u64 {
        self.overlay.nodes.get(physical).map_or(0, node_owned_bytes)
    }

    /// Remove `path` (a symlink itself, never its target). `Ok(false)` when nothing was there:
    /// `rm` without `-f` reports that, and the caller decides. A removed file stops being
    /// readable, listed and executable.
    pub fn remove_path(&mut self, path: &str) -> Result<bool, FsError> {
        let physical = match self.resolve(path, false) {
            Ok(physical) => physical,
            Err(FsError::NoSuchDirectory(missing)) if self.snapshot.is_ro(&missing) => {
                return Err(FsError::ReadOnly);
            }
            Err(_) => return Ok(false),
        };
        if self.snapshot.is_ro(&physical) {
            return Err(FsError::ReadOnly);
        }
        let existing = self.node_at(&physical).map(|node| &node.kind);
        let existed = existing.is_some();
        let is_directory = matches!(existing, Some(NodeKind::Directory(_)));
        if is_directory {
            let below = format!("{physical}/");
            let doomed: Vec<String> = self
                .overlay
                .nodes
                .keys()
                .filter(|key| key.starts_with(&below))
                .cloned()
                .collect();
            for key in doomed {
                if let Some(node) = self.overlay.nodes.remove(&key) {
                    self.budget.refund_bytes(node_owned_bytes(&node));
                }
            }
        }
        // The bytes come back; the node slot does not. A created node's slot becomes the
        // tombstone's, and a baked path's tombstone takes a new one.
        let below = format!("{physical}/");
        for (key, bits) in &mut self.overlay.attrs {
            if *key == physical || key.starts_with(&below) {
                *bits = 0;
            }
        }
        let removed = self.overlay.nodes.remove(&physical);
        if let Some(node) = &removed {
            self.budget.refund_bytes(node_owned_bytes(node));
        }
        if existed {
            self.overlay.tombstones.insert(physical);
            if removed.is_none() {
                self.budget.charge_node_unchecked();
            }
        }
        Ok(existed)
    }

    /// `mkdir path`, with the failures a real `mkdir` distinguishes.
    pub fn make_dir(&mut self, path: &str) -> Result<(), FsError> {
        self.budget.check_name(path)?;
        let physical = self.resolve_for_write(path)?;
        if self.snapshot.is_ro(&physical) {
            return Err(FsError::ReadOnly);
        }
        if self.node_at(&physical).is_some() {
            return Err(FsError::Exists);
        }
        // No live node here, so a tombstone is the only thing that can already own the slot.
        if !self.overlay.tombstones.contains(&physical) {
            let path_bytes = u64::try_from(physical.len()).unwrap_or(u64::MAX);
            self.budget.charge_bytes(path_bytes)?;
            if let Err(error) = self.budget.charge_node() {
                self.budget.refund_bytes(path_bytes);
                return Err(error.into());
            }
        }
        self.overlay.tombstones.remove(&physical);
        self.overlay
            .nodes
            .insert(physical, Node::directory(Vec::new()));
        Ok(())
    }

    /// Model `> path` with no command: create an empty file if its directory exists, else fail
    /// the way the shell would.
    pub fn create_file(&mut self, path: &str) -> Result<(), FsError> {
        self.write_file(path, b"")
    }

    /// `symlink(target, path)`: a link node holding `target` exactly as typed. The target is
    /// never resolved here, so a dangling link is fine; the final component of `path` is the new
    /// name, never followed. The path and the target text are charged with the node, and stay
    /// charged for the life of the slot as a directory's do.
    pub fn create_symlink(&mut self, path: &str, target: &str) -> Result<(), FsError> {
        self.budget.check_name(path)?;
        let physical = self.resolve_for_write_with(path, false)?;
        if self.snapshot.is_ro(&physical) {
            return Err(FsError::ReadOnly);
        }
        if self.node_at(&physical).is_some() {
            return Err(FsError::Exists);
        }
        if !self.overlay.tombstones.contains(&physical) {
            let held = physical.len().saturating_add(target.len());
            let bytes = u64::try_from(held).unwrap_or(u64::MAX);
            self.budget.charge_bytes(bytes)?;
            if let Err(error) = self.budget.charge_node() {
                self.budget.refund_bytes(bytes);
                return Err(error.into());
            }
        }
        self.overlay.tombstones.remove(&physical);
        self.overlay.nodes.insert(physical, Node::symlink(target));
        Ok(())
    }

    /// The ext2 attribute bits (`chattr`) of the node `path` names, or `None` when nothing is
    /// there. Stored only: no write or removal consults them.
    pub fn attrs(&self, path: &str) -> Option<u32> {
        let physical = self.resolve(path, true).ok()?;
        self.node_at(&physical)?;
        Some(self.overlay.attrs.get(&physical).copied().unwrap_or(0))
    }

    /// Apply a `chattr` change to the node `path` names and return the bits it now holds. The
    /// bits live beside the overlay's nodes, keyed by physical path, so a modeled file needs no
    /// copy of itself to carry them; a path's first nonzero set is charged like a node slot and
    /// that slot stays charged. Removing a path zeroes its bits (a new file is a new inode).
    pub fn change_attrs(
        &mut self,
        path: &str,
        change: AttrChange,
        bits: u32,
    ) -> Result<u32, FsError> {
        let physical = self.resolve(path, true).map_err(|error| match error {
            FsError::NoSuchDirectory(_) => FsError::NoSuchFile,
            other => other,
        })?;
        if self.node_at(&physical).is_none() {
            return Err(FsError::NoSuchFile);
        }
        if self.snapshot.is_ro(&physical) {
            return Err(FsError::ReadOnly);
        }
        let held = self.overlay.attrs.get(&physical).copied();
        let current = held.unwrap_or(0);
        let next = match change {
            AttrChange::Add => current | bits,
            AttrChange::Remove => current & !bits,
            AttrChange::Replace => bits,
        };
        if held.is_none() {
            if next == 0 {
                return Ok(0);
            }
            let bytes = u64::try_from(physical.len()).unwrap_or(u64::MAX);
            self.budget.charge_bytes(bytes)?;
            if let Err(error) = self.budget.charge_node() {
                self.budget.refund_bytes(bytes);
                return Err(error.into());
            }
        }
        self.overlay.attrs.insert(physical, next);
        Ok(next)
    }
}

/// The ext2 attribute bits `chattr` stores, with the kernel's `FS_*_FL` values.
pub const ATTR_IMMUTABLE: u32 = 0x0000_0010;
pub const ATTR_APPEND_ONLY: u32 = 0x0000_0020;

/// How one `chattr` mode argument edits the stored bits: `+` adds, `-` clears, `=` replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrChange {
    Add,
    Remove,
    Replace,
}

/// The bytes a node was charged: a regular file's materialized blob bytes, nothing for the rest.
fn node_owned_bytes(node: &Node) -> u64 {
    match &node.kind {
        NodeKind::Regular(blob) => blob.owned_bytes(),
        _ => 0,
    }
}

/// `resolved` components followed by `component`, `/`-joined.
fn join_with(resolved: &[String], component: &str) -> String {
    let mut parts: Vec<&str> = resolved.iter().map(String::as_str).collect();
    parts.push(component);
    parts.join("/")
}

/// Which components of a path [`FakeFs::canonicalize`] requires to exist: `readlink -f`,
/// `-e` and `-m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonical {
    /// All but the last (`-f`).
    ParentsExist,
    /// All of them (`-e`).
    Existing,
    /// None (`-m`).
    AllowMissing,
}

/// Why an operation on the filesystem failed, so the shell can print what the real command prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// The parent directory does not exist; carries it for the message.
    NoSuchDirectory(String),
    /// The path is under a read-only mount (`/system` on the Android device).
    ReadOnly,
    /// `mkdir` on a path that is already there.
    Exists,
    /// A read or exec target that is absent or was removed.
    NoSuchFile,
    /// A read or copy target that is a directory.
    IsADirectory,
    /// A non-final path component that is not a directory.
    NotADirectory,
    /// Symlink resolution exceeded [`MAX_SYMLINK_HOPS`] (`ELOOP`).
    TooManyLinks,
    /// A write to `/dev/full`, or one the connection budget has no room for (`ENOSPC`).
    NoSpace,
    /// One write bigger than the connection's whole content budget (`EFBIG`).
    FileTooLarge,
    /// A path or path component over the name limits (`ENAMETOOLONG`).
    NameTooLong,
}

impl From<BudgetError> for FsError {
    fn from(error: BudgetError) -> Self {
        match error {
            BudgetError::NoSpace => Self::NoSpace,
            BudgetError::TooLarge => Self::FileTooLarge,
            BudgetError::NameTooLong => Self::NameTooLong,
        }
    }
}

/// The Android device's equivalents. `/system/xbin/busybox` is there because this device is
/// rooted (it hands out a root shell over ADB, which a stock one does not) and a rooted phone
/// almost always carries busybox; `su` for the same reason.
const ANDROID_EXECUTABLE_BINARIES: [&str; 23] = [
    "/system/bin/sh",
    "/system/bin/toybox",
    "/system/bin/toolbox",
    "/system/xbin/busybox",
    "/system/xbin/su",
    "/system/bin/app_process",
    "/system/bin/am",
    "/system/bin/dumpsys",
    "/system/bin/getenforce",
    "/system/bin/pm",
    "/system/bin/screencap",
    "/system/bin/wm",
    "/system/bin/logcat",
    "/system/bin/env",
    "/system/bin/ps",
    "/system/bin/top",
    "/system/bin/ifconfig",
    "/system/bin/ip",
    "/system/bin/netstat",
    "/system/bin/route",
    "/system/bin/df",
    "/system/bin/du",
    "/system/bin/free",
];

/// `/system/build.prop` on the impersonated device, resolved from [`crate::persona`] so it
/// cannot disagree with the ADB banner or `uname`.
fn android_build_prop() -> String {
    format!(
        "# begin build properties\n\
         # autogenerated by buildinfo.sh\n\
         ro.build.id={build_id}\n\
         ro.build.display.id={build_id} release-keys\n\
         ro.build.version.incremental=3565761\n\
         ro.build.version.sdk={sdk}\n\
         ro.build.version.release={release}\n\
         ro.build.type=user\n\
         ro.build.tags=release-keys\n\
         ro.product.model={model}\n\
         ro.product.brand=google\n\
         ro.product.name={device}\n\
         ro.product.device={device}\n\
         ro.product.board={device}\n\
         ro.product.cpu.abi=armeabi-v7a\n\
         ro.product.manufacturer=LGE\n\
         ro.board.platform=msm8974\n\
         ro.build.fingerprint={fingerprint}\n\
         # end build properties\n",
        build_id = persona::ANDROID_BUILD_ID,
        sdk = persona::ANDROID_SDK,
        release = persona::ANDROID_RELEASE,
        model = persona::ANDROID_MODEL,
        device = persona::ANDROID_DEVICE,
        fingerprint = persona::android_fingerprint(),
    )
}

/// The Android device's mount table: a read-only `/system`, a writable `/data`, and the FUSE
/// `/sdcard` a dropper reaches for. The read-only rootfs governs every path no submount claims
/// (`/vendor`, `/root`), which is why those refuse writes.
const ANDROID_MOUNT_TABLE: [MountEntry; 12] = [
    MountEntry::new("rootfs", "/", "rootfs", "ro,seclabel,relatime"),
    MountEntry::new(
        "tmpfs",
        "/dev",
        "tmpfs",
        "rw,seclabel,nosuid,relatime,mode=755",
    ),
    MountEntry::new(
        "devpts",
        "/dev/pts",
        "devpts",
        "rw,seclabel,relatime,mode=600",
    ),
    MountEntry::new("proc", "/proc", "proc", "rw,relatime"),
    MountEntry::new("sysfs", "/sys", "sysfs", "rw,seclabel,relatime"),
    MountEntry::new("selinuxfs", "/sys/fs/selinux", "selinuxfs", "rw,relatime"),
    MountEntry::new(
        "/dev/block/platform/msm_sdcc.1/by-name/system",
        "/system",
        "ext4",
        "ro,seclabel,relatime,data=ordered",
    ),
    MountEntry::new(
        "/dev/block/platform/msm_sdcc.1/by-name/userdata",
        "/data",
        "ext4",
        "rw,seclabel,nosuid,nodev,relatime,noauto_da_alloc,data=ordered",
    ),
    MountEntry::new(
        "/dev/block/platform/msm_sdcc.1/by-name/cache",
        "/cache",
        "ext4",
        "rw,seclabel,nosuid,nodev,relatime,data=ordered",
    ),
    MountEntry::new(
        "/dev/block/platform/msm_sdcc.1/by-name/persist",
        "/persist",
        "ext4",
        "rw,seclabel,nosuid,nodev,relatime,data=ordered",
    ),
    MountEntry::new(
        "/data/media",
        "/storage/emulated",
        "sdcardfs",
        "rw,nosuid,nodev,noexec,noatime",
    ),
    MountEntry::new(
        "/data/media",
        "/sdcard",
        "sdcardfs",
        "rw,nosuid,nodev,noexec,noatime",
    ),
];

/// The directory holding `path`, or `None` when `path` has no `/` at all.
fn parent_of(path: &str) -> Option<String> {
    match path.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(i) => Some(path[..i].to_string()),
        None => None,
    }
}

/// The mounted filesystems of a stock Ubuntu 22.04 cloud image on one virtual disk, in mount
/// order. Every mount point exists in the directory model above. Rendered into `/proc/mounts`,
/// `/proc/self/mountinfo` and the `mount` command, and consulted for each path's read-only and
/// `noexec` policy.
pub const MOUNT_TABLE: [MountEntry; 20] = [
    MountEntry::new("sysfs", "/sys", "sysfs", "rw,nosuid,nodev,noexec,relatime"),
    MountEntry::new("proc", "/proc", "proc", "rw,nosuid,nodev,noexec,relatime"),
    MountEntry::new(
        "udev",
        "/dev",
        "devtmpfs",
        "rw,nosuid,relatime,size=1968376k,nr_inodes=492094,mode=755,inode64",
    ),
    MountEntry::new(
        "devpts",
        "/dev/pts",
        "devpts",
        "rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000",
    ),
    MountEntry::new(
        "tmpfs",
        "/run",
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime,size=402244k,mode=755,inode64",
    ),
    MountEntry::new(
        "/dev/sda1",
        "/",
        "ext4",
        "rw,relatime,discard,errors=remount-ro",
    ),
    MountEntry::new(
        "securityfs",
        "/sys/kernel/security",
        "securityfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new("tmpfs", "/dev/shm", "tmpfs", "rw,nosuid,nodev,inode64"),
    MountEntry::new(
        "tmpfs",
        "/run/lock",
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime,size=5120k,inode64",
    ),
    MountEntry::new(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        "rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot",
    ),
    MountEntry::new(
        "pstore",
        "/sys/fs/pstore",
        "pstore",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "bpf",
        "/sys/fs/bpf",
        "bpf",
        "rw,nosuid,nodev,noexec,relatime,mode=700",
    ),
    MountEntry::new(
        "hugetlbfs",
        "/dev/hugepages",
        "hugetlbfs",
        "rw,relatime,pagesize=2M",
    ),
    MountEntry::new(
        "mqueue",
        "/dev/mqueue",
        "mqueue",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "debugfs",
        "/sys/kernel/debug",
        "debugfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "tracefs",
        "/sys/kernel/tracing",
        "tracefs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "fusectl",
        "/sys/fs/fuse/connections",
        "fusectl",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "configfs",
        "/sys/kernel/config",
        "configfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    MountEntry::new(
        "/dev/sda15",
        "/boot/efi",
        "vfat",
        "rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro",
    ),
    MountEntry::new(
        "tmpfs",
        "/run/user/0",
        "tmpfs",
        "rw,nosuid,nodev,relatime,size=402240k,nr_inodes=100560,mode=700,inode64",
    ),
];

/// One `/proc/meminfo` line: the field, its value, and whether the kernel writes ` kB` after it
/// (the huge-page counts are bare numbers).
type MemLine = (&'static str, u64, bool);

/// The Ubuntu host's memory [unverified: composed, not captured]. The totals are the ones `top`
/// already reports for this host (3923.7 MiB, which the `udev` and `/run` sizes in the mount table
/// also imply), and the rest is arranged so the kernel's own identities hold: the anon and file
/// LRU lists add up to `Active` and `Inactive`, `Slab` is its two halves, and the file lists equal
/// `Buffers` + `Cached` less `Shmem`.
const UBUNTU_MEMINFO: [MemLine; 50] = [
    ("MemTotal", 4_017_836, true),
    ("MemFree", 2_405_196, true),
    ("MemAvailable", 3_452_180, true),
    ("Buffers", 163_204, true),
    ("Cached", 1_039_408, true),
    ("SwapCached", 0, true),
    ("Active", 563_524, true),
    ("Inactive", 936_236, true),
    ("Active(anon)", 95_320, true),
    ("Inactive(anon)", 203_424, true),
    ("Active(file)", 468_204, true),
    ("Inactive(file)", 732_812, true),
    ("Unevictable", 18_432, true),
    ("Mlocked", 18_432, true),
    ("SwapTotal", 0, true),
    ("SwapFree", 0, true),
    ("Dirty", 156, true),
    ("Writeback", 0, true),
    ("AnonPages", 298_744, true),
    ("Mapped", 212_880, true),
    ("Shmem", 1_596, true),
    ("KReclaimable", 80_548, true),
    ("Slab", 142_148, true),
    ("SReclaimable", 79_816, true),
    ("SUnreclaim", 62_332, true),
    ("KernelStack", 3_232, true),
    ("PageTables", 5_716, true),
    ("Bounce", 0, true),
    ("WritebackTmp", 0, true),
    ("CommitLimit", 2_008_918, true),
    ("Committed_AS", 2_512_364, true),
    ("VmallocTotal", 34_359_738_367, true),
    ("VmallocUsed", 24_692, true),
    ("VmallocChunk", 0, true),
    ("Percpu", 1_216, true),
    ("HardwareCorrupted", 0, true),
    ("AnonHugePages", 0, true),
    ("ShmemHugePages", 0, true),
    ("ShmemPmdMapped", 0, true),
    ("FileHugePages", 0, true),
    ("FilePmdMapped", 0, true),
    ("HugePages_Total", 0, false),
    ("HugePages_Free", 0, false),
    ("HugePages_Rsvd", 0, false),
    ("HugePages_Surp", 0, false),
    ("Hugepagesize", 2_048, true),
    ("Hugetlb", 0, true),
    ("DirectMap4k", 235_520, true),
    ("DirectMap2M", 3_958_784, true),
    ("DirectMap1G", 0, true),
];

/// The Nexus 5's memory [unverified: composed, not captured]: 2 GiB less what the radio and the
/// graphics carve out, no swap, and the 3.4 kernel's fields (no `MemAvailable`, which arrived in
/// 3.14). The same identities hold as for the Ubuntu host, plus `HighTotal` + `LowTotal` =
/// `MemTotal` and likewise for the free halves.
const ANDROID_MEMINFO: [MemLine; 37] = [
    ("MemTotal", 1_875_408, true),
    ("MemFree", 112_432, true),
    ("Buffers", 4_724, true),
    ("Cached", 612_844, true),
    ("SwapCached", 0, true),
    ("Active", 502_316, true),
    ("Inactive", 804_460, true),
    ("Active(anon)", 312_000, true),
    ("Inactive(anon)", 377_208, true),
    ("Active(file)", 190_316, true),
    ("Inactive(file)", 427_252, true),
    ("Unevictable", 0, true),
    ("Mlocked", 0, true),
    ("HighTotal", 1_085_440, true),
    ("HighFree", 41_208, true),
    ("LowTotal", 789_968, true),
    ("LowFree", 71_224, true),
    ("SwapTotal", 0, true),
    ("SwapFree", 0, true),
    ("Dirty", 24, true),
    ("Writeback", 0, true),
    ("AnonPages", 689_208, true),
    ("Mapped", 301_120, true),
    ("Shmem", 12_340, true),
    ("Slab", 78_440, true),
    ("SReclaimable", 28_116, true),
    ("SUnreclaim", 50_324, true),
    ("KernelStack", 6_320, true),
    ("PageTables", 12_408, true),
    ("NFS_Unstable", 0, true),
    ("Bounce", 0, true),
    ("WritebackTmp", 0, true),
    ("CommitLimit", 937_704, true),
    ("Committed_AS", 1_432_604, true),
    ("VmallocTotal", 245_760, true),
    ("VmallocUsed", 169_356, true),
    ("VmallocChunk", 6_300, true),
];

/// `/proc/meminfo` as the kernel writes it: the name and colon padded to 16 columns, the value
/// right-aligned in 8, then ` kB` where the field has a unit (a name too long for that gets one
/// space and a five-column value).
fn render_meminfo(lines: &[MemLine]) -> String {
    let mut out = String::new();
    for &(name, value, kb) in lines {
        let label = format!("{name}:");
        let unit = if kb { " kB" } else { "" };
        if label.len() > 16 {
            // The kernel prints `HardwareCorrupted` with a format of its own, one space and a
            // five-column value.
            out.push_str(&format!("{label} {value:>5}{unit}\n"));
        } else {
            out.push_str(&format!("{label:<16}{value:>8}{unit}\n"));
        }
    }
    out
}

/// `/proc/mounts` format: `source mountpoint type options 0 0`.
fn render_mounts(table: &[MountEntry]) -> String {
    let mut out = String::new();
    for m in table {
        out.push_str(&format!(
            "{} {} {} {} 0 0\n",
            m.source, m.point, m.fstype, m.opts
        ));
    }
    out
}

/// `/proc/self/mountinfo` format: `id parent major:minor root mountpoint mount-opts - type
/// source super-opts`. Ids are sequential from the table; the per-mount options are the flags
/// (`rw,nosuid,...`) and the super options the rest, as the kernel splits them.
fn render_mountinfo(table: &[MountEntry]) -> String {
    let root_pos = table.iter().position(|m| m.point == "/").unwrap_or(0);
    let mut out = String::new();
    for (i, m) in table.iter().enumerate() {
        let id = 20 + i;
        let parent = if m.point == "/" { 1 } else { 20 + root_pos };
        let (mount_opts, super_opts): (Vec<&str>, Vec<&str>) = m.opts.split(',').partition(|o| {
            matches!(
                *o,
                "rw" | "ro" | "nosuid" | "nodev" | "noexec" | "relatime" | "noatime"
            )
        });
        let super_opts = if super_opts.is_empty() {
            "rw".to_string()
        } else {
            format!("rw,{}", super_opts.join(","))
        };
        out.push_str(&format!(
            "{id} {parent} 0:{} / {} {} - {} {} {super_opts}\n",
            i + 21,
            m.point,
            mount_opts.join(","),
            m.fstype,
            m.source
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_string(fs: &FakeFs, path: &str) -> String {
        String::from_utf8(fs.read_all(path, 8192).unwrap()).unwrap()
    }

    /// Every file that exposes the mount table agrees, and every mount point it names is a
    /// directory the shell will `cd` into: a table naming a path `ls` denies is the same
    /// contradiction as the missing file was.
    #[test]
    fn mount_table_is_exposed_consistently_and_every_mount_point_exists() {
        let fs = FakeFs::new();
        let mounts = read_string(&fs, "/proc/mounts");
        assert_eq!(read_string(&fs, "/proc/self/mounts"), mounts);
        assert_eq!(read_string(&fs, "/etc/mtab"), mounts);
        assert!(mounts.contains("/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0\n"));
        assert_eq!(mounts.lines().count(), MOUNT_TABLE.len());
        let info = read_string(&fs, "/proc/self/mountinfo");
        assert_eq!(info.lines().count(), MOUNT_TABLE.len());
        assert!(info.contains(" / / rw,relatime - ext4 /dev/sda1 rw,discard,errors=remount-ro\n"));
        for m in MOUNT_TABLE {
            assert!(
                fs.is_dir(m.point),
                "{} is mounted but not a directory",
                m.point
            );
        }
        assert!(fs.list_dir("/etc").unwrap().contains(&"mtab".to_string()));
    }

    /// A path's mount is the longest one covering where the path really is, so a link into `/usr`
    /// is on the root disk and a link into `/run` is on the `/run` tmpfs; a path that is not there
    /// has none.
    #[test]
    fn mount_of_follows_links_to_the_longest_covering_mount() {
        let fs = FakeFs::new();
        let point = |path: &str| fs.mount_of(path).map(|m| m.point);
        assert_eq!(point("/"), Some("/"));
        assert_eq!(point("/etc/passwd"), Some("/"));
        assert_eq!(point("/bin/busybox"), Some("/"));
        assert_eq!(point("/run/user"), Some("/run"));
        assert_eq!(point("/run/user/0"), Some("/run/user/0"));
        assert_eq!(point("/var/run/lock"), Some("/run/lock"));
        assert_eq!(point("/boot/efi"), Some("/boot/efi"));
        assert_eq!(point("/nonexistent"), None);
        assert_eq!(fs.mounts().len(), MOUNT_TABLE.len());
        let phone = FakeFs::android();
        assert_eq!(
            phone.mount_of("/sdcard").map(|m| m.fstype),
            Some("sdcardfs")
        );
        assert_eq!(phone.mount_of("/system").map(|m| m.point), Some("/system"));
        assert_eq!(phone.mounts().len(), 12);
    }

    /// The Android snapshot describes one device, and the same device the ADB banner announces.
    #[test]
    fn the_android_snapshot_is_one_coherent_device() {
        let mut fs = FakeFs::android();
        let build_prop = read_string(&fs, "/system/build.prop");
        for expected in [
            persona::ANDROID_MODEL,
            persona::ANDROID_DEVICE,
            persona::ANDROID_RELEASE,
            persona::ANDROID_SDK,
            persona::ANDROID_BUILD_ID,
        ] {
            assert!(build_prop.contains(expected), "build.prop lacks {expected}");
        }
        assert!(read_string(&fs, "/proc/version").contains(persona::ANDROID_KERNEL_RELEASE));
        // The directories an ADB dropper writes to, and the ones it lists first.
        for dir in ["/data/local/tmp", "/sdcard", "/system/bin", "/system/xbin"] {
            assert!(fs.is_dir(dir), "{dir} must exist");
        }
        assert!(fs.is_executable("/system/xbin/busybox"), "rooted device");
        assert!(fs.is_executable("/system/bin/sh"));
        // /system is mounted read-only, and the mount table says so, so a payload dropped there
        // is refused rather than silently accepted.
        let mounts = read_string(&fs, "/proc/mounts");
        assert!(mounts.contains(" /system ext4 ro,"), "{mounts}");
        assert!(mounts.contains(" /data ext4 rw,"), "{mounts}");
        assert_eq!(
            fs.write_file("/system/bin/payload", b"x"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.make_dir("/system/evil"), Err(FsError::ReadOnly));
        assert_eq!(
            fs.remove_path("/system/bin/sh"),
            Err(FsError::ReadOnly),
            "a read-only mount refuses deletions too"
        );
        assert!(fs.write_file("/data/local/tmp/payload", b"x").is_ok());
        assert!(fs.write_file("/sdcard/payload", b"x").is_ok());
        // Nothing from the Linux server leaks into the phone.
        assert!(fs.read_all("/etc/os-release", 8192).is_err());
        assert!(!fs.is_dir("/home"));
    }

    #[test]
    fn every_directory_the_loader_probes_exists_and_is_listable() {
        let fs = FakeFs::new();
        for dir in [
            "/var/run", "/mnt", "/usr", "/dev", "/dev/shm", "/tmp", "/var",
        ] {
            assert!(fs.is_dir(dir), "{dir} must exist");
            assert!(fs.list_dir(dir).is_some(), "{dir} must be listable");
        }
    }

    #[test]
    fn root_listing_entries_and_file_ancestors_are_directories_too() {
        let fs = FakeFs::new();
        assert!(fs.is_dir("/"));
        assert!(fs.is_dir("/bin"), "advertised by ls /");
        assert!(fs.is_dir("/proc"), "ancestor of /proc/cpuinfo");
        assert!(!fs.is_dir("/nonexistent"));
        assert!(!fs.is_dir("/etc/hostname"), "a file is not a directory");
    }

    #[test]
    fn create_file_needs_an_existing_directory_and_then_shows_in_the_listing() {
        let mut fs = FakeFs::new();
        assert_eq!(fs.create_file("/tmp/.x"), Ok(()));
        assert!(fs.list_dir("/tmp").unwrap().contains(&".x".to_string()));
        assert_eq!(fs.read_all("/tmp/.x", 8192), Ok(Vec::new()));
        assert_eq!(
            fs.create_file("/nonexistent/.x"),
            Err(FsError::NoSuchDirectory("/nonexistent".to_string()))
        );
        assert!(
            !fs.list_dir("/").unwrap().contains(&".x".to_string()),
            "a file created in /tmp must not appear at /"
        );
    }

    // The `is_dir` and `list_dir` goldens below were captured from the string-map FakeFs this
    // node model replaced, so they pin what the shell answered before the refactor. Paths the
    // old heuristics answered wrongly are left out and asserted separately where they change.

    const UBUNTU_DIRS: &[&str] = &[
        "/",
        "/bin",
        "/boot",
        "/boot/efi",
        "/dev",
        "/dev/hugepages",
        "/dev/mqueue",
        "/dev/pts",
        "/dev/shm",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/proc/self",
        "/root",
        "/run",
        "/run/lock",
        "/run/user",
        "/run/user/0",
        "/sbin",
        "/srv",
        "/sys",
        "/sys/fs",
        "/sys/fs/bpf",
        "/sys/fs/cgroup",
        "/sys/fs/fuse",
        "/sys/fs/fuse/connections",
        "/sys/fs/pstore",
        "/sys/kernel",
        "/sys/kernel/config",
        "/sys/kernel/debug",
        "/sys/kernel/security",
        "/sys/kernel/tracing",
        "/tmp",
        "/usr",
        "/usr/bin",
        "/var",
        "/var/run",
        "/var/tmp",
    ];

    const UBUNTU_NOT_DIRS: &[&str] = &[
        "/bin/bash",
        "/bin/busybox",
        "/bin/sh",
        "/etc/hostname",
        "/etc/hosts",
        "/etc/mtab",
        "/etc/os-release",
        "/etc/passwd",
        "/nonexistent",
        "/proc/cpuinfo",
        "/proc/mounts",
        "/proc/self/mountinfo",
        "/proc/self/mounts",
        "/proc/self/nothing",
        "/proc/version",
        "/tmp/x",
        "/usr/bin/wget",
        "/usr/share",
    ];

    const ANDROID_DIRS: &[&str] = &[
        "/",
        "/acct",
        "/cache",
        "/config",
        "/d",
        "/data",
        "/data/local",
        "/data/local/tmp",
        "/dev",
        "/etc",
        "/mnt",
        "/oem",
        "/persist",
        "/proc",
        "/proc/self",
        "/root",
        "/sbin",
        "/sdcard",
        "/storage",
        "/storage/emulated",
        "/storage/emulated/0",
        "/sys",
        "/system",
        "/system/bin",
        "/system/etc",
        "/system/xbin",
        "/vendor",
    ];

    const ANDROID_NOT_DIRS: &[&str] = &[
        "/dev/pts",
        "/etc/hostname",
        "/nonexistent",
        "/proc/cpuinfo",
        "/proc/mounts",
        "/proc/self/mountinfo",
        "/proc/self/mounts",
        "/proc/self/nothing",
        "/proc/version",
        "/sys/fs/selinux",
        "/system/bin/app_process",
        "/system/bin/env",
        "/system/bin/ps",
        "/system/bin/sh",
        "/system/bin/toolbox",
        "/system/bin/top",
        "/system/bin/toybox",
        "/system/build.prop",
        "/system/etc/hosts",
        "/system/xbin/busybox",
        "/system/xbin/su",
        "/tmp/x",
        "/usr/lib",
        "/usr/sbin",
        "/usr/share",
    ];

    const UBUNTU_LISTINGS: &str = "\
/: bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
/boot: efi grub
/boot/efi: EFI
/dev: hugepages mqueue null pts random shm stderr stdin stdout tty urandom zero
/dev/hugepages:
/dev/mqueue:
/dev/pts: 0 ptmx
/dev/shm:
/etc: hostname hosts mtab os-release passwd
/home: ubuntu
/mnt:
/root:
/run: lock user
/run/lock:
/run/user: 0
/run/user/0:
/sys: block bus class dev devices firmware fs hypervisor kernel module power
/sys/fs: bpf cgroup ext4 fuse pstore
/sys/fs/bpf:
/sys/fs/cgroup:
/sys/fs/fuse: connections
/sys/fs/fuse/connections:
/sys/fs/pstore:
/sys/kernel: config debug mm security slab tracing uevent_seqnum
/sys/kernel/config:
/sys/kernel/debug:
/sys/kernel/security:
/sys/kernel/tracing:
/tmp:
/usr: bin games include lib lib64 local sbin share src
/var: backups cache lib local lock log mail opt run spool tmp
/var/tmp:
";

    const ANDROID_LISTINGS: &str = "\
/: acct cache config d data default.prop dev etc init init.rc mnt oem persist proc root sbin sdcard storage sys system ueventd.rc vendor
/cache: backup lost+found recovery
/data: anr app backup dalvik-cache data local media misc property system user
/data/local: tmp
/data/local/tmp:
/dev: block cpuctl null socket zero
/mnt: asec obb runtime secure shell
/proc:
/root:
/sbin: adbd healthd ueventd watchdogd
/sdcard: Alarms Android DCIM Download Movies Music Notifications Pictures Podcasts Ringtones
/storage: emulated self
/storage/emulated: 0 legacy
/storage/emulated/0:
/sys: block class devices fs kernel
/system: app bin build.prop etc fonts framework lib media priv-app tts usr vendor xbin
/system/bin: am app_process cat chmod dalvikvm date df du dumpsys env free getenforce getprop hostname ifconfig ip linker logcat ls mount netstat ping pm ps reboot route screencap setprop sh toolbox top toybox umount uptime wm
/system/etc: hosts
/system/xbin: busybox su
/vendor: firmware lib
";

    const ANDROID_PROC_MOUNTS: &str = "\
rootfs / rootfs ro,seclabel,relatime 0 0
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0
proc /proc proc rw,relatime 0 0
sysfs /sys sysfs rw,seclabel,relatime 0 0
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
/dev/block/platform/msm_sdcc.1/by-name/system /system ext4 ro,seclabel,relatime,data=ordered 0 0
/dev/block/platform/msm_sdcc.1/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,relatime,noauto_da_alloc,data=ordered 0 0
/dev/block/platform/msm_sdcc.1/by-name/cache /cache ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/msm_sdcc.1/by-name/persist /persist ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/data/media /storage/emulated sdcardfs rw,nosuid,nodev,noexec,noatime 0 0
/data/media /sdcard sdcardfs rw,nosuid,nodev,noexec,noatime 0 0
";

    #[test]
    fn is_dir_answers_as_the_string_map_model_did() {
        for (name, fs, dirs, not_dirs) in [
            ("ubuntu", FakeFs::new(), UBUNTU_DIRS, UBUNTU_NOT_DIRS),
            ("android", FakeFs::android(), ANDROID_DIRS, ANDROID_NOT_DIRS),
        ] {
            for path in dirs {
                assert!(fs.is_dir(path), "{name}: {path} was a directory");
            }
            for path in not_dirs {
                assert!(!fs.is_dir(path), "{name}: {path} was not a directory");
            }
        }
        // The two names the usrmerge symlinks need as targets were not directories before; the
        // three root-listing entries below are files the listing shows but no content backs.
        let ubuntu = FakeFs::new();
        assert!(ubuntu.is_dir("/usr/sbin") && ubuntu.is_dir("/usr/lib"));
        let android = FakeFs::android();
        for file in ["/default.prop", "/init", "/init.rc", "/ueventd.rc"] {
            assert!(!android.is_dir(file), "{file} is listed, not a directory");
        }
    }

    #[test]
    fn list_dir_answers_as_the_string_map_model_did() {
        for (name, fs, listings) in [
            ("ubuntu", FakeFs::new(), UBUNTU_LISTINGS),
            ("android", FakeFs::android(), ANDROID_LISTINGS),
        ] {
            for line in listings.lines() {
                let (path, names) = line.split_once(':').unwrap();
                let mut listed = fs
                    .list_dir(path)
                    .unwrap_or_else(|| panic!("{name}: {path} was listable"));
                listed.sort();
                assert_eq!(listed.join(" "), names.trim(), "{name}: ls {path}");
            }
        }
        // /var/run was an empty directory and is /run now, as on a real box; /proc, /bin and the
        // other directories that were only implied used to refuse a listing and now list empty.
        let fs = FakeFs::new();
        assert_eq!(fs.list_dir("/var/run"), fs.list_dir("/run"));
        assert_eq!(fs.list_dir("/proc"), Some(Vec::new()));
    }

    #[test]
    fn android_proc_mounts_bytes_are_unchanged() {
        let fs = FakeFs::android();
        assert_eq!(read_string(&fs, "/proc/mounts"), ANDROID_PROC_MOUNTS);
        assert_eq!(read_string(&fs, "/proc/self/mounts"), ANDROID_PROC_MOUNTS);
    }

    /// A small deterministic generator, so the property test needs no new dependency and replays
    /// identically.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// A blob of random pieces and its full materialization, computed piece by piece rather than
    /// through `read_range`.
    fn random_blob(rng: &mut Rng) -> (Blob, Vec<u8>) {
        let mut pieces = Vec::new();
        let mut naive = Vec::new();
        for _ in 0..rng.below(7) {
            let len = rng.below(40);
            match rng.below(4) {
                3 => {
                    // Lengths straddle the 64-byte header, and the planted newline may land in it
                    // (where the header wins), at its edge, or in the filler.
                    let len = rng.below(200);
                    let mut header = [0u8; ELF_HEADER_LEN];
                    header.iter_mut().for_each(|byte| *byte = rng.next() as u8);
                    let newline_at = (rng.below(2) == 0).then(|| rng.below(220));
                    naive.extend((0..len).map(|i| {
                        if let Some(byte) = header.get(i as usize) {
                            *byte
                        } else if newline_at == Some(i) {
                            0x0a
                        } else {
                            0x80 | (i & 0x3f) as u8
                        }
                    }));
                    pieces.push(Piece::Elf(ElfImage {
                        header,
                        len,
                        newline_at,
                    }));
                }
                0 => {
                    let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                    naive.extend_from_slice(&bytes);
                    pieces.push(Piece::Bytes(Arc::new(bytes)));
                }
                1 => {
                    let byte = rng.next() as u8;
                    naive.extend(std::iter::repeat_n(byte, len as usize));
                    pieces.push(Piece::Fill { byte, len });
                }
                _ => {
                    let seed = rng.next();
                    naive.extend((0..len).map(|i| counter_byte(seed, i)));
                    pieces.push(Piece::Counter { seed, len });
                }
            }
        }
        let len = naive.len() as u64;
        (Blob { pieces, len }, naive)
    }

    #[test]
    fn read_range_equals_the_bounded_naive_slice_for_random_layouts() {
        let mut rng = Rng(7);
        for _ in 0..3000 {
            let (blob, naive) = random_blob(&mut rng);
            let total = naive.len() as u64;
            let (off, max_len) = match rng.below(6) {
                0 => (u64::MAX - rng.below(3), rng.below(20)),
                1 => (rng.below(total + 5), u64::MAX),
                _ => (rng.below(total + 5), rng.below(total + 5)),
            };
            let start = off.min(total);
            let end = start.saturating_add(max_len).min(total);
            let expected = &naive[start as usize..end as usize];
            let got = blob.read_range(off, max_len);
            assert_eq!(got, expected, "off={off} max_len={max_len} total={total}");
            assert!(got.len() as u64 <= max_len);
        }
    }

    #[test]
    fn read_range_saturates_instead_of_overflowing() {
        let blob = Blob::from_bytes(b"0123456789".to_vec());
        assert_eq!(blob.read_range(u64::MAX - 1, 10), Vec::<u8>::new());
        assert_eq!(blob.read_range(3, u64::MAX), b"3456789");
        assert_eq!(blob.read_range(10, 4), Vec::<u8>::new());
        assert_eq!(blob.read_range(2, 3), b"234");
        assert_eq!(blob.owned_bytes(), 10);
        let synthetic = Blob::fill(0xAA, 1 << 40);
        assert_eq!(synthetic.owned_bytes(), 0, "fill owns no bytes");
        assert_eq!(synthetic.read_range((1 << 40) - 2, 100), vec![0xAA, 0xAA]);
        assert_eq!(Blob::counter(9, 100).read_range(0, 100).len(), 100);
    }

    #[test]
    fn read_range_reads_files_and_refuses_directories_and_absences() {
        let fs = FakeFs::new();
        assert_eq!(
            fs.read_range("/etc/hostname", 0, 3).unwrap(),
            persona::hostname().as_bytes()[..3]
        );
        assert_eq!(
            fs.read_range("/etc/hostname", 1_000, 3),
            Ok(Vec::new()),
            "past the end is empty, not an error"
        );
        assert_eq!(fs.read_all("/etc", 16), Err(FsError::IsADirectory));
        assert_eq!(fs.read_all("/nonexistent", 16), Err(FsError::NoSuchFile));
        assert_eq!(
            fs.read_all("/nonexistent/deeper", 16),
            Err(FsError::NoSuchFile)
        );
        assert_eq!(
            fs.read_all("/etc/hostname/x", 16),
            Err(FsError::NotADirectory)
        );
    }

    #[test]
    fn the_usrmerge_symlinks_resolve_to_the_physical_paths() {
        let fs = FakeFs::new();
        assert_eq!(
            fs.resolve("/bin/busybox", true).unwrap(),
            "/usr/bin/busybox"
        );
        assert_eq!(fs.resolve("/var/run/.x", true).unwrap(), "/run/.x");
        assert_eq!(fs.resolve("/var/run/..", true).unwrap(), "/");
        assert_eq!(fs.resolve("/lib64", false).unwrap(), "/lib64");
        assert_eq!(fs.resolve("/lib64", true).unwrap(), "/usr/lib64");
        assert_eq!(
            fs.read_all("/bin/busybox", 64).unwrap(),
            fs.read_all("/usr/bin/busybox", 64).unwrap()
        );
        assert_eq!(
            fs.read_all("/etc/mtab", 8192).unwrap(),
            fs.read_all("/proc/self/mounts", 8192).unwrap()
        );
        assert!(fs.is_executable("/bin/busybox"));
        assert!(fs.is_dir("/var/run") && fs.is_dir("/bin") && fs.is_dir("/lib"));
        // The fd links point at a directory the box does not model.
        assert_eq!(fs.read_all("/dev/stdin", 1), Err(FsError::NoSuchFile));
        assert!(!fs.file_exists("/dev/stdin"));
    }

    /// Every modeled binary is a regular executable node at its recorded path, with its recorded
    /// size, mode and header, reachable through the usrmerge link; `sh` is a link to dash. The
    /// phone has none of them.
    #[test]
    fn every_modeled_binary_is_a_node_with_its_recorded_size_mode_and_header() {
        let fs = FakeFs::new();
        for binary in binaries::BINARIES {
            let (blob, mode) = fs.content_and_mode(binary.path).unwrap();
            assert_eq!(blob.len(), binary.size, "{}", binary.path);
            assert_eq!(blob.owned_bytes(), 0, "{} is O(1)", binary.path);
            assert_eq!(mode, binary.mode, "{}", binary.path);
            assert!(fs.is_executable(binary.path), "{}", binary.path);
            assert_eq!(
                fs.read_range(binary.path, 0, 64).unwrap(),
                binary.header(),
                "{}",
                binary.path
            );
            let merged = binary.path.strip_prefix("/usr").unwrap();
            assert_eq!(fs.resolve(merged, true).unwrap(), binary.path);
            let last = binary.size - 1;
            assert_eq!(fs.read_range(merged, last, 10).unwrap().len(), 1);
            assert_eq!(fs.read_range(merged, binary.size, 10), Ok(Vec::new()));
        }
        assert_eq!(fs.resolve("/bin/sh", true).unwrap(), "/usr/bin/dash");
        assert_eq!(fs.resolve("/usr/bin/sh", false).unwrap(), "/usr/bin/sh");
        assert_eq!(
            fs.read_all("/bin/sh", 64).unwrap(),
            fs.read_all("/bin/dash", 64).unwrap()
        );
        let android = FakeFs::android();
        assert!(android.read_all("/usr/bin/busybox", 8).is_err());
    }

    /// Saving bytes that are exactly a modeled image (what `cat /proc/self/exe > FILE` does) keeps
    /// them as the image, so a 2 MiB copy costs the connection its path and node, not its bytes.
    #[test]
    fn writing_the_bytes_of_an_image_stores_the_image() {
        let (mut fs, budget) = budgeted(1_000, 10);
        let busybox = binaries::find("busybox").unwrap();
        let bytes = busybox.blob().read_range(0, u64::MAX);
        assert_eq!(fs.write_file("/tmp/.bb", &bytes), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 8, "the path only");
        let (blob, mode) = fs.content_and_mode("/tmp/.bb").unwrap();
        assert_eq!(blob.as_elf(), Some(busybox.image()));
        assert_eq!(mode, MODE_FILE);
        assert_eq!(fs.read_all("/tmp/.bb", u64::MAX).unwrap(), bytes);
        // Anything else that large is content, and the budget refuses it.
        let mut other = bytes.clone();
        other[100] ^= 1;
        assert_eq!(
            fs.write_file("/tmp/.cc", &other),
            Err(FsError::FileTooLarge)
        );
    }

    #[test]
    fn a_symlink_cycle_gives_eloop_after_forty_hops() {
        let mut fs = FakeFs::new();
        fs.overlay.nodes.insert("/tmp/a".into(), Node::symlink("b"));
        fs.overlay.nodes.insert("/tmp/b".into(), Node::symlink("a"));
        assert_eq!(fs.resolve("/tmp/a", true), Err(FsError::TooManyLinks));
        assert_eq!(fs.read_all("/tmp/a", 1), Err(FsError::TooManyLinks));
        assert!(!fs.is_dir("/tmp/a") && !fs.file_exists("/tmp/a"));
        // A chain one link short of the cap still resolves; one over does not.
        for i in 0..40 {
            fs.overlay
                .nodes
                .insert(format!("/tmp/l{i}"), Node::symlink(&format!("l{}", i + 1)));
        }
        fs.overlay
            .nodes
            .insert("/tmp/l40".into(), Node::symlink("/etc/hostname"));
        assert_eq!(fs.resolve("/tmp/l1", true).unwrap(), "/etc/hostname");
        assert_eq!(fs.resolve("/tmp/l0", true), Err(FsError::TooManyLinks));
        // `rm` acts on the link itself, so it works on a cycle.
        assert_eq!(fs.remove_path("/tmp/a"), Ok(true));
        assert!(fs.overlay.tombstones.contains("/tmp/a"));
    }

    #[test]
    fn mount_policy_follows_the_longest_matching_mount_point() {
        let ubuntu = FakeFs::new();
        for path in ["/", "/tmp/x", "/run/x", "/dev/null", "/etc/passwd"] {
            assert!(!ubuntu.snapshot.is_ro(path), "{path} is on a rw mount");
        }
        assert!(ubuntu.snapshot.is_noexec("/run"));
        assert!(ubuntu.snapshot.is_noexec("/run/lock/x"));
        assert!(ubuntu.snapshot.is_noexec("/dev/pts/0"));
        assert!(ubuntu.snapshot.is_noexec("/proc/version"));
        assert!(
            !ubuntu.snapshot.is_noexec("/run/user/0/x"),
            "the nested mount is exec-permitted although /run is not"
        );
        assert!(!ubuntu.snapshot.is_noexec("/tmp/x"));
        assert!(!ubuntu.snapshot.is_noexec("/dev/shm/x"));
        assert!(
            !ubuntu.snapshot.is_noexec("/runx"),
            "/runx is not under /run"
        );

        let android = FakeFs::android();
        for path in ["/system/bin/x", "/system", "/vendor/x", "/root/x", "/x"] {
            assert!(android.snapshot.is_ro(path), "{path} is read-only");
        }
        for path in [
            "/data/local/tmp/x",
            "/cache/x",
            "/sdcard/x",
            "/dev/null",
            "/systemx",
        ] {
            assert!(
                android.snapshot.is_ro(path) == (path == "/systemx"),
                "{path}"
            );
        }
        assert!(android.snapshot.is_noexec("/sdcard/x"));
        assert!(android.snapshot.is_noexec("/storage/emulated/0/x"));
        assert!(!android.snapshot.is_noexec("/data/local/tmp/x"));
    }

    #[test]
    fn stat_reports_kind_size_and_mount_policy_and_follows_links_on_request() {
        let fs = FakeFs::new();
        let hostname = fs.stat("/etc/hostname", true).unwrap();
        assert_eq!(hostname.kind, FileKind::Regular);
        assert_eq!(
            hostname.size,
            fs.read_all("/etc/hostname", READ_CAP).unwrap().len() as u64
        );
        assert!(!hostname.read_only && !hostname.no_exec);
        assert_eq!(fs.stat("/etc", true).unwrap().kind, FileKind::Directory);
        assert_eq!(
            fs.stat("/dev/null", true).unwrap().kind,
            FileKind::CharDevice
        );

        // `/var/run` is a link to `/run`: unfollowed it is the link, followed the directory on
        // its own mount.
        let link = fs.stat("/var/run", false).unwrap();
        assert_eq!(link.kind, FileKind::Symlink);
        assert_eq!(link.size, "/run".len() as u64);
        let run = fs.stat("/var/run", true).unwrap();
        assert_eq!(
            (run.kind, run.physical.as_str()),
            (FileKind::Directory, "/run")
        );
        assert!(run.no_exec && !run.read_only);
        assert_eq!(fs.stat("/bin/ls", true).unwrap().physical, "/usr/bin/ls");

        assert!(fs.stat("/no/such/path", true).is_none());
        assert!(fs.stat("/etc/hostname/child", true).is_none());

        let android = FakeFs::android();
        assert!(android.stat("/system/bin", true).unwrap().read_only);
        assert!(!android.stat("/data/local/tmp", true).unwrap().read_only);
        assert!(android.stat("/sdcard", true).unwrap().no_exec);
    }

    #[test]
    fn stat_sees_what_the_session_created_and_removed() {
        let mut fs = FakeFs::new();
        fs.write_file("/tmp/made", b"abc").unwrap();
        let made = fs.stat("/tmp/made", true).unwrap();
        assert_eq!(
            (made.kind, made.size, made.mode),
            (FileKind::Regular, 3, MODE_FILE)
        );
        fs.remove_path("/tmp/made").unwrap();
        assert!(fs.stat("/tmp/made", true).is_none());
        fs.remove_path("/etc/hostname").unwrap();
        assert!(fs.stat("/etc/hostname", true).is_none());
    }

    #[test]
    fn a_write_into_a_readonly_mount_is_refused_even_through_a_missing_parent() {
        let mut fs = FakeFs::android();
        assert_eq!(
            fs.write_file("/system/nodir/x", b"x"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.write_file("/vendor/x", b"x"), Err(FsError::ReadOnly));
        assert_eq!(fs.write_file("/root/x", b"x"), Err(FsError::ReadOnly));
        assert_eq!(
            fs.write_file("/data/nodir/x", b"x"),
            Err(FsError::NoSuchDirectory("/data/nodir".into()))
        );
    }

    #[test]
    fn devices_read_and_write_by_their_own_rules() {
        let mut fs = FakeFs::new();
        assert_eq!(fs.write_file("/dev/null", b"x"), Ok(()));
        assert_eq!(fs.read_all("/dev/null", 16), Ok(Vec::new()));
        assert!(
            !fs.overlay.nodes.contains_key("/dev/null"),
            "a discarded write stores nothing"
        );
        assert_eq!(fs.read_all("/dev/zero", 4), Ok(vec![0, 0, 0, 0]));
        assert_eq!(fs.write_file("/dev/zero", b"x"), Ok(()));
        // No persona lists /dev/full, so the device is injected to exercise its rules.
        fs.overlay
            .nodes
            .insert("/dev/full".into(), Node::device(Device::Full));
        assert_eq!(fs.write_file("/dev/full", b"x"), Err(FsError::NoSpace));
        assert_eq!(fs.read_all("/dev/full", 2), Ok(vec![0, 0]));
        assert_eq!(fs.write_file("/dev/tty", b"x"), Ok(()));
        assert_eq!(fs.read_all("/dev/tty", 8), Ok(Vec::new()));
        let random = fs.read_all("/dev/urandom", 32).unwrap();
        assert_eq!(random.len(), 32);
        assert_ne!(random, vec![0; 32]);
        assert_eq!(fs.read_range("/dev/urandom", 8, 8).unwrap(), random[8..16]);
        assert_ne!(fs.read_all("/dev/random", 32).unwrap(), random);
        assert!(fs.file_exists("/dev/null") && !fs.is_dir("/dev/null"));
        assert_eq!(
            fs.read_all("/dev/zero", u64::MAX).unwrap().len() as u64,
            READ_CAP,
            "an unbounded read of an endless device is capped"
        );
        let mut android = FakeFs::android();
        assert_eq!(android.write_file("/dev/null", b"x"), Ok(()));
        assert_eq!(android.read_all("/dev/zero", 2), Ok(vec![0, 0]));
    }

    #[test]
    fn a_removed_baked_file_is_shadowed_by_its_tombstone_until_rewritten() {
        let mut fs = FakeFs::new();
        assert!(fs.file_exists("/etc/hostname"));
        assert_eq!(fs.remove_path("/etc/hostname"), Ok(true));
        assert!(!fs.file_exists("/etc/hostname"));
        assert_eq!(fs.read_all("/etc/hostname", 16), Err(FsError::NoSuchFile));
        assert!(
            !fs.list_dir("/etc")
                .unwrap()
                .contains(&"hostname".to_string())
        );
        assert_eq!(fs.remove_path("/etc/hostname"), Ok(false));
        assert_eq!(fs.write_file("/etc/hostname", b"new\n"), Ok(()));
        assert_eq!(fs.read_all("/etc/hostname", 16), Ok(b"new\n".to_vec()));
        assert_eq!(
            fs.list_dir("/etc")
                .unwrap()
                .iter()
                .filter(|name| *name == "hostname")
                .count(),
            1,
            "a rewritten baked name is listed once"
        );
        // A removed directory takes what was created under it along.
        assert_eq!(fs.make_dir("/tmp/a"), Ok(()));
        assert_eq!(fs.create_file("/tmp/a/f"), Ok(()));
        assert_eq!(fs.remove_path("/tmp/a"), Ok(true));
        assert_eq!(fs.make_dir("/tmp/a"), Ok(()));
        assert_eq!(fs.list_dir("/tmp/a"), Some(Vec::new()));
    }

    #[test]
    fn the_execute_bit_rides_the_node_mode() {
        let mut fs = FakeFs::new();
        assert!(
            !fs.mark_executable("/etc/hostname"),
            "baked files keep their modes"
        );
        assert!(fs.is_executable("/usr/bin/wget"));
        assert!(!fs.is_executable("/etc/hostname"));
        fs.create_file("/tmp/p").unwrap();
        assert!(!fs.is_executable("/tmp/p"));
        assert!(fs.mark_executable("/tmp/p"));
        assert!(fs.is_executable("/tmp/p"));
        // Truncating in place keeps the bit; a copy carries its source's mode.
        fs.write_file("/tmp/p", b"payload").unwrap();
        assert!(fs.is_executable("/tmp/p"));
        let (blob, mode) = fs.content_and_mode("/bin/busybox").unwrap();
        assert_eq!(mode, MODE_EXECUTABLE);
        fs.write_blob("/tmp/b", blob, mode).unwrap();
        assert!(fs.is_executable("/tmp/b"));
        let (blob, mode) = fs.content_and_mode("/etc/hostname").unwrap();
        fs.write_blob("/tmp/h", blob, mode).unwrap();
        assert!(!fs.is_executable("/tmp/h"));
        assert_eq!(
            fs.content_and_mode("/etc").err(),
            Some(FsError::IsADirectory)
        );
        assert_eq!(
            fs.content_and_mode("/nope").err(),
            Some(FsError::NoSuchFile)
        );
        // Nothing runs from a noexec mount, whatever its mode.
        fs.create_file("/run/x").unwrap();
        assert!(fs.mark_executable("/run/x"));
        assert!(!fs.is_executable("/run/x"));
        assert!(
            !fs.is_executable("/var/run/x"),
            "the same file through the link"
        );
        assert_eq!(fs.write_file("/tmp", b"x"), Err(FsError::IsADirectory));
    }

    fn budgeted(owned_bytes: u64, overlay_nodes: u64) -> (FakeFs, Arc<ConnectionBudget>) {
        let budget = ConnectionBudget::new(BudgetLimits {
            owned_bytes,
            overlay_nodes,
            ..BudgetLimits::standard()
        });
        (FakeFs::new().with_budget(budget.clone()), budget)
    }

    #[test]
    fn writes_charge_their_bytes_and_a_new_path_net_of_what_the_path_held() {
        let (mut fs, budget) = budgeted(100, 10);
        // The 6-byte path of a new node is charged with its content, once.
        assert_eq!(fs.write_file("/tmp/a", &[1; 60]), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 66);
        // Overwriting swaps 60 for 90, so it needs 30 more, not 90, and no second path.
        assert_eq!(fs.write_file("/tmp/a", &[2; 90]), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 96);
        assert_eq!(fs.write_file("/tmp/a", &[3; 10]), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 16);
        // 79 bytes and a 6-byte path would bring the total to 101.
        assert_eq!(fs.write_file("/tmp/b", &[4; 79]), Err(FsError::NoSpace));
        assert_eq!(fs.write_file("/tmp/b", &[4; 78]), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 100, "the cap itself fits");
        assert_eq!(fs.remove_path("/tmp/b"), Ok(true));
        assert_eq!(
            budget.owned_bytes_used(),
            22,
            "the tombstone keeps the path"
        );
        assert_eq!(fs.write_file("/tmp/c", &[4; 91]), Err(FsError::NoSpace));
        assert_eq!(
            fs.write_file("/tmp/c", &[4; 101]),
            Err(FsError::FileTooLarge)
        );
        assert!(!fs.file_exists("/tmp/c"), "a refused write inserts nothing");
        assert_eq!(budget.owned_bytes_used(), 22);
        assert_eq!(budget.overlay_nodes_used(), 2);
    }

    #[test]
    fn a_refused_node_gives_back_the_bytes_it_had_charged() {
        let (mut fs, budget) = budgeted(100, 1);
        assert_eq!(fs.write_file("/tmp/a", &[1; 10]), Ok(()));
        assert_eq!(fs.write_file("/tmp/b", &[1; 10]), Err(FsError::NoSpace));
        assert_eq!(
            budget.owned_bytes_used(),
            16,
            "the failed write left no charge behind (10 bytes and a 6-byte path)"
        );
        // Overwriting a file that already owns its slot never needs a second one.
        assert_eq!(fs.write_file("/tmp/a", &[1; 20]), Ok(()));
    }

    #[test]
    fn removing_returns_bytes_but_not_slots() {
        let (mut fs, budget) = budgeted(1_000, 10);
        fs.make_dir("/tmp/d").unwrap();
        fs.write_file("/tmp/d/a", &[1; 40]).unwrap();
        fs.write_file("/tmp/d/b", &[1; 40]).unwrap();
        fs.write_file("/tmp/c", &[1; 40]).unwrap();
        assert_eq!(
            (budget.owned_bytes_used(), budget.overlay_nodes_used()),
            (148, 4)
        );

        assert_eq!(fs.remove_path("/tmp/c"), Ok(true));
        assert_eq!(
            (budget.owned_bytes_used(), budget.overlay_nodes_used()),
            (108, 4)
        );
        // Removing a directory returns the content created under it; every node's path stays
        // charged with its slot.
        assert_eq!(fs.remove_path("/tmp/d"), Ok(true));
        assert_eq!(
            (budget.owned_bytes_used(), budget.overlay_nodes_used()),
            (28, 4)
        );
        // A removed path owns its slot, and its path charge, until something is created there
        // again.
        fs.make_dir("/tmp/d").unwrap();
        assert_eq!(
            (budget.owned_bytes_used(), budget.overlay_nodes_used()),
            (28, 4)
        );
        assert_eq!(fs.remove_path("/nonexistent"), Ok(false));
        assert_eq!(budget.overlay_nodes_used(), 4);
    }

    #[test]
    fn a_baked_path_needs_a_slot_to_be_overwritten_or_removed() {
        let (mut fs, budget) = budgeted(1_000, 10);
        fs.write_file("/etc/hostname", b"x\n").unwrap();
        assert_eq!(budget.overlay_nodes_used(), 1);
        fs.remove_path("/etc/passwd").unwrap();
        assert_eq!(budget.overlay_nodes_used(), 2);
    }

    #[test]
    fn names_over_the_limits_are_refused_by_every_writer() {
        let (mut fs, budget) = budgeted(1_000, 10);
        let long = format!("/tmp/{}", "a".repeat(256));
        assert_eq!(fs.write_file(&long, b"x"), Err(FsError::NameTooLong));
        assert_eq!(fs.create_file(&long), Err(FsError::NameTooLong));
        assert_eq!(fs.make_dir(&long), Err(FsError::NameTooLong));
        assert_eq!(
            fs.write_blob(&long, Blob::from_bytes(b"x".to_vec()), MODE_FILE),
            Err(FsError::NameTooLong)
        );
        assert_eq!(
            (budget.owned_bytes_used(), budget.overlay_nodes_used()),
            (0, 0)
        );
        assert_eq!(
            fs.write_file(&format!("/tmp/{}", "a".repeat(255)), b"x"),
            Ok(())
        );
    }

    #[test]
    fn synthetic_blobs_cost_no_content_but_do_cost_a_path_and_a_node() {
        let (mut fs, budget) = budgeted(10, 10);
        let huge = Blob::fill(0, 1 << 40);
        assert_eq!(fs.write_blob("/tmp/z", huge, MODE_FILE), Ok(()));
        assert_eq!(budget.owned_bytes_used(), 6, "the 6-byte path only");
        assert_eq!(budget.overlay_nodes_used(), 1);
        assert_eq!(fs.remove_path("/tmp/z"), Ok(true));
        assert_eq!(budget.owned_bytes_used(), 6);
    }

    #[test]
    fn two_filesystems_on_one_budget_draw_on_the_same_allowance() {
        let budget = ConnectionBudget::new(BudgetLimits {
            owned_bytes: 100,
            ..BudgetLimits::standard()
        });
        let mut a = FakeFs::new().with_budget(budget.clone());
        let mut b = FakeFs::android().with_budget(budget);
        assert_eq!(a.write_file("/tmp/a", &[1; 70]), Ok(()));
        // 76 used; the 17-byte path leaves room for 7 bytes of content.
        assert_eq!(
            b.write_file("/data/local/tmp/b", &[1; 8]),
            Err(FsError::NoSpace)
        );
        assert_eq!(b.write_file("/data/local/tmp/b", &[1; 7]), Ok(()));
    }
}
