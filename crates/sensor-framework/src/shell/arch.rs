//! Which CPU a file the session runs was built for, and the refusal a host gives for another one.
//!
//! Mirai-family loaders fetch one build per architecture and run each until one starts
//! (`for a in mips mpsl arm5 arm7 x86_64 x86; do wget .../$a -O .c; chmod +x .c && ./.c && break;
//! done`). Executing a binary built for another CPU fails on a real host, so the loop goes on to
//! the build that matters; a fake that ran the first one with status 0 ended the loop at `mips`
//! and never saw the x86_64 fetch.
//!
//! The decision is content first, then provenance:
//!
//! - A file whose bytes are an ELF is judged by its header (class, byte order, `e_machine`).
//! - Any other file the session fetched carries an [`Origin`], the URL and local name the fetch
//!   command used, and is judged by the architecture token in the URL's file name, else in the
//!   local name. The fake fetch applets write a canned HTML body, not a binary, so this is the
//!   only evidence there is. The origin follows `cp`, `mv` and `cat FILE > DEST`, and any other
//!   write to the destination drops it, so the busybox-copy trick (`cp /bin/busybox box; cat
//!   loader.mips > box; ./box`) is judged by what was cat'ed over the copy.
//! - A file with neither (a script the attacker typed, a file with no token) runs as before.
//!
//! The persona's CPU decides what is native: the Ubuntu persona is x86_64 (which also runs 32-bit
//! x86 binaries, as the distribution's kernel enables IA-32 emulation), the Android persona is
//! `armv7l` and runs 32-bit ARM builds of any generation.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::{CommandResult, FakeShell, ShellFlavor, ShellLevel};

/// Files whose provenance one shell keeps. A loader runs a handful; the bound stops a session
/// that fetches many files from growing the map.
const MAX_ORIGINS: usize = 64;

/// Bytes of the file read to judge an ELF header: the magic, class, byte order and `e_machine`.
const HEADER_LEN: u64 = 20;

/// Name suffixes of files that are not programs, so a token before them says nothing
/// (`mips.sh` is a script that fetches the mips build, not the build).
const NOT_PROGRAM: [&str; 18] = [
    "sh", "bash", "py", "pl", "php", "txt", "html", "htm", "cgi", "json", "log", "conf", "c", "gz",
    "tar", "zip", "jpg", "png",
];

/// An instruction set, as far as the exec decision tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Mipsel,
    PowerPc,
    Sh4,
    M68k,
    Sparc,
    /// An ELF machine this table does not name; it cannot be the persona's.
    Other,
}

/// A program's target: instruction set and word size (the `N-bit ELF file` mksh reports).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Image {
    pub(super) arch: Arch,
    pub(super) bits: u8,
}

impl Image {
    const fn new(arch: Arch, bits: u8) -> Self {
        Self { arch, bits }
    }
}

/// Where a file the session fetched came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Origin {
    /// The URL the fetch asked for, when its command line named one.
    url: Option<String>,
    /// The file name the fetch saved to, as typed.
    name: String,
}

/// The target an ELF header names; `None` when the bytes are not an ELF or too short to say.
pub(super) fn elf_image(head: &[u8]) -> Option<Image> {
    if !head.starts_with(b"\x7fELF") {
        return None;
    }
    let bits = match head.get(4)? {
        1 => 32,
        2 => 64,
        _ => return None,
    };
    let machine = [*head.get(18)?, *head.get(19)?];
    let little = match head.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let machine = if little {
        u16::from_le_bytes(machine)
    } else {
        u16::from_be_bytes(machine)
    };
    let arch = match machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        8 if little => Arch::Mipsel,
        8 => Arch::Mips,
        10 => Arch::Mipsel,
        20 | 21 => Arch::PowerPc,
        42 => Arch::Sh4,
        4 => Arch::M68k,
        2 | 43 => Arch::Sparc,
        _ => Arch::Other,
    };
    Some(Image::new(arch, bits))
}

/// The target a Mirai-family build name or URL path names, from the last name part that is an
/// architecture token. Parts split at every non-alphanumeric character (`x86_64` and `x86-64` are
/// kept whole), so `mirai.arm7` and `dlr_mpsl` name one and `alarm`, `armada` or `charm` do not.
pub(super) fn token_image(name: &str) -> Option<Image> {
    let lower = name
        .to_ascii_lowercase()
        .replace("x86_64", "x8664")
        .replace("x86-64", "x8664");
    let parts: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    let last = parts.iter().rev().find(|part| !part.is_empty())?;
    if NOT_PROGRAM.contains(last) {
        return None;
    }
    parts.iter().rev().find_map(|part| part_image(part))
}

fn part_image(part: &str) -> Option<Image> {
    let (arch, bits) = match part {
        "mips" | "mipseb" | "mipsbe" => (Arch::Mips, 32),
        "mpsl" | "mipsel" | "mipsle" => (Arch::Mipsel, 32),
        "aarch64" | "arm64" | "armv8" | "armv8a" | "aarch64be" => (Arch::Aarch64, 64),
        "arm" | "armhf" | "armel" | "armv8l" => (Arch::Arm, 32),
        "ppc" | "powerpc" | "ppc440" | "ppc440fp" => (Arch::PowerPc, 32),
        "ppc64" => (Arch::PowerPc, 64),
        "sh4" | "sh4a" | "superh" => (Arch::Sh4, 32),
        "m68k" | "m68000" => (Arch::M68k, 32),
        "sparc" | "spc" | "sparc32" => (Arch::Sparc, 32),
        "sparc64" => (Arch::Sparc, 64),
        "i386" | "i486" | "i586" | "i686" | "x86" | "ia32" => (Arch::X86, 32),
        "x8664" | "amd64" | "x64" => (Arch::X86_64, 64),
        other => return arm_generation(other),
    };
    Some(Image::new(arch, bits))
}

/// `arm4`..`arm7` and `armv4l`..`armv7l` with a short variant suffix (`arm5n`, `armv5tel`): 32-bit
/// ARM of one generation.
fn arm_generation(part: &str) -> Option<Image> {
    let rest = part
        .strip_prefix("armv")
        .or_else(|| part.strip_prefix("arm"))?;
    let mut chars = rest.chars();
    let generation = chars.next()?;
    let suffix = chars.as_str();
    let short = suffix.len() <= 3 && suffix.chars().all(|c| c.is_ascii_alphabetic());
    (('4'..='7').contains(&generation) && short).then(|| Image::new(Arch::Arm, 32))
}

/// The file-name part of a URL's path; `None` for a URL with no path (its host is not a name).
fn url_file(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (_, path) = rest.split_once('/')?;
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.rsplit('/').next().filter(|name| !name.is_empty())
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

impl Origin {
    pub(super) fn new(url: Option<String>, name: &str) -> Self {
        Self {
            url,
            name: file_name(name).to_string(),
        }
    }

    /// The target the build name implies: the URL's file name wins over the local one, because
    /// the local name is what the loader chose for the copy and the URL is what it asked for.
    fn image(&self) -> Option<Image> {
        self.url
            .as_deref()
            .and_then(url_file)
            .and_then(token_image)
            .or_else(|| token_image(&self.name))
    }
}

/// Whether the persona's CPU runs `image`.
fn runs_natively(flavor: ShellFlavor, image: Image) -> bool {
    match flavor {
        ShellFlavor::AndroidSh => image.arch == Arch::Arm && image.bits == 32,
        _ => matches!(
            (image.arch, image.bits),
            (Arch::X86_64, 64) | (Arch::X86, 32)
        ),
    }
}

impl FakeShell {
    /// The fetch applet saved `name` (a path as typed) from `url`.
    pub(super) fn note_origin(&mut self, path: &str, url: Option<String>, name: &str) {
        self.set_origin(path, Origin::new(url, name));
    }

    /// The file at `path` has new content or is gone, so what it was fetched as no longer
    /// describes it.
    pub(super) fn forget_origin(&mut self, path: &str) {
        self.origins.remove(path);
    }

    /// `dst` is a copy of `src`, which keeps where `src` came from.
    pub(super) fn copy_origin(&mut self, src: &str, dst: &str) {
        let Some(origin) = self.origins.get(src).cloned() else {
            return;
        };
        self.set_origin(dst, origin);
    }

    pub(super) fn origin_of(&self, path: &str) -> Option<Origin> {
        self.origins.get(path).cloned()
    }

    pub(super) fn set_origin(&mut self, path: &str, origin: Origin) {
        if self.origins.len() < MAX_ORIGINS {
            self.origins.insert(path.to_string(), origin);
        }
    }

    /// The target of the file at `path` when this host cannot run it: judged by its bytes when
    /// they are an ELF, else by the origin it was fetched with. `None` runs it as before.
    pub(super) fn foreign_image(&self, path: &str) -> Option<Image> {
        let head = self.fs.read_range(path, 0, HEADER_LEN).ok()?;
        let image = if head.starts_with(b"\x7fELF") {
            elf_image(&head)
        } else {
            self.origins.get(path).and_then(Origin::image)
        }?;
        (!runs_natively(self.flavor, image)).then_some(image)
    }

    /// What the active shell says when the kernel refuses a binary built for another CPU.
    ///
    /// Sources, checked on Ubuntu 22.04 (bash 5.1.16, dash 0.5.11) by running a foreign-machine
    /// ELF: bash `bash: ./x: cannot execute binary file: Exec format error`, dash
    /// `sh: 1: ./x: Exec format error`, both status 126. mksh R50, the Android 6 shell
    /// (AOSP `external/mksh` marshmallow-release `exec.c`, `scriptexec`): `errorf("%s: not
    /// executable: %d-bit ELF file")`, whose `errorf` sets status 1 [unverified on a device].
    pub(super) fn exec_format_refusal(&self, typed: &str, image: Image) -> CommandResult {
        match self.active_level() {
            ShellLevel::Bash { .. } => CommandResult::stderr(
                126,
                self.shell_error(format_args!(
                    "{typed}: cannot execute binary file: Exec format error"
                )),
            ),
            ShellLevel::Dash { .. } => CommandResult::stderr(
                126,
                self.shell_error(format_args!("{typed}: Exec format error")),
            ),
            ShellLevel::AndroidMksh => CommandResult::stderr(
                1,
                self.shell_error(format_args!(
                    "{typed}: not executable: {}-bit ELF file",
                    image.bits
                )),
            ),
        }
    }
}
