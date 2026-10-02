//! `sha256sum`, `sha1sum`, `md5sum` and `cksum`: the verify step of a fetch/verify/execute chain
//! runs `sha256sum FILE` before it runs the file.
//!
//! Each digests the modeled bytes of its operands (or standard input), read through the same
//! bounded reader as `cat`, and prints the coreutils line. Nothing is read from the host and
//! nothing is executed: the digest is a pure function of bytes the session already holds.
//!
//! What a tool is not asked to model it does not invent: `-c`/`--check`, `-b`, `--tag`, `-z`,
//! `--help`, `--version` and the other options of the real tools print nothing and succeed, never a
//! verification verdict or a digest line this shell made up. An option the tool does not have is
//! refused as the tool refuses it. Standard input at the terminal reads as empty, as it does for
//! `cat`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::read::errno_text;
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};

pub(super) fn register(r: &mut Registry) {
    // `md5sum`, `sha1sum` and `sha256sum` are applets of the captured BusyBox, so `busybox
    // sha256sum` reaches these handlers as `busybox wc` does; `cksum` is not an applet.
    r.register_if("md5sum", ubuntu, HandlerId::Md5sum, FakeShell::cmd_md5sum);
    r.register_if(
        "sha1sum",
        ubuntu,
        HandlerId::Sha1sum,
        FakeShell::cmd_sha1sum,
    );
    r.register_if(
        "sha256sum",
        ubuntu,
        HandlerId::Sha256sum,
        FakeShell::cmd_sha256sum,
    );
    r.register_if("cksum", ubuntu, HandlerId::Cksum, FakeShell::cmd_cksum);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

fn hex_digest<D: Digest>(data: &[u8]) -> String {
    D::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The POSIX `cksum` CRC: polynomial 0x04C11DB7 over the bytes, then the length as its octets
/// least significant first with no leading zero octets, complemented. (POSIX words this as the
/// length's octets "from the least significant", which is also what GNU does.)
fn posix_crc(data: &[u8]) -> u32 {
    fn feed(crc: u32, byte: u8) -> u32 {
        let mut crc = crc ^ (u32::from(byte) << 24);
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
        crc
    }
    let mut crc = data.iter().fold(0u32, |crc, &byte| feed(crc, byte));
    let mut length = len_u64(data.len());
    while length != 0 {
        crc = feed(crc, u8::try_from(length & 0xff).unwrap_or(0));
        length >>= 8;
    }
    !crc
}

/// What the command line of one of these tools asks for.
enum Parsed<'a> {
    Files(Vec<&'a str>),
    /// The tool's own complaint (status 1).
    Fail(String),
    /// An option the real tool has and this shell does not model.
    Unmodeled,
}

/// Options the real tools accept that this shell does not model, short and long.
const UNMODELED_SHORT: &str = "bctwz";
const UNMODELED_LONG: [&str; 13] = [
    "binary",
    "check",
    "tag",
    "text",
    "zero",
    "help",
    "version",
    "ignore-missing",
    "quiet",
    "status",
    "strict",
    "warn",
    "untagged",
];

fn parse<'a>(prog: &str, args: &[&'a str]) -> Parsed<'a> {
    let try_help = format!("Try '{prog} --help' for more information.\n");
    let mut files = Vec::new();
    let mut unmodeled = false;
    let mut options = true;
    for &arg in args {
        if !options || arg == "-" || !arg.starts_with('-') {
            files.push(arg);
        } else if arg == "--" {
            options = false;
        } else if let Some(long) = arg.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(name, _)| name);
            if UNMODELED_LONG.contains(&name) {
                unmodeled = true;
            } else {
                return Parsed::Fail(format!("{prog}: unrecognized option '{arg}'\n{try_help}"));
            }
        } else {
            for flag in arg.get(1..).unwrap_or("").chars() {
                if UNMODELED_SHORT.contains(flag) {
                    unmodeled = true;
                } else {
                    return Parsed::Fail(format!("{prog}: invalid option -- '{flag}'\n{try_help}"));
                }
            }
        }
    }
    if unmodeled {
        Parsed::Unmodeled
    } else {
        Parsed::Files(files)
    }
}

impl FakeShell {
    /// `md5sum [FILE]...`: `DIGEST  NAME` per operand, standard input named `-`.
    pub(super) fn cmd_md5sum(&mut self, parts: &[&str]) -> CommandResult {
        self.run_sum(parts, "md5sum", hex_digest::<Md5>)
    }

    /// `sha1sum [FILE]...`: as [`Self::cmd_md5sum`].
    pub(super) fn cmd_sha1sum(&mut self, parts: &[&str]) -> CommandResult {
        self.run_sum(parts, "sha1sum", hex_digest::<Sha1>)
    }

    /// `sha256sum [FILE]...`: as [`Self::cmd_md5sum`].
    pub(super) fn cmd_sha256sum(&mut self, parts: &[&str]) -> CommandResult {
        self.run_sum(parts, "sha256sum", hex_digest::<Sha256>)
    }

    /// `cksum [FILE]...`: `CRC SIZE NAME` per operand, and `CRC SIZE` for standard input.
    pub(super) fn cmd_cksum(&mut self, parts: &[&str]) -> CommandResult {
        self.run_sum(parts, "cksum", |data| {
            format!("{} {}", posix_crc(data), data.len())
        })
    }

    /// The shared loop. `line_of` renders a tool's answer for the bytes of one operand. A file is
    /// read up to the same cap as `cat`, and a longer one is digested up to that point.
    fn run_sum(
        &mut self,
        parts: &[&str],
        prog: &str,
        line_of: fn(&[u8]) -> String,
    ) -> CommandResult {
        let files = match parse(prog, parts.get(1..).unwrap_or(&[])) {
            Parsed::Files(files) => files,
            Parsed::Fail(text) => return CommandResult::stderr(1, text),
            Parsed::Unmodeled => return CommandResult::silent(0),
        };
        let names: Vec<Option<&str>> = if files.is_empty() {
            vec![None]
        } else {
            files.iter().copied().map(Some).collect()
        };
        let cksum = prog == "cksum";
        let cap = self.read_cap();
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        for name in names {
            let bytes = match self.read_source(parts, name, cap) {
                Ok(bytes) => bytes,
                Err(error) => {
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!("{prog}: {}: {}\n", name.unwrap_or("-"), errno_text(&error)),
                    ));
                    continue;
                }
            };
            // Digesting is work the line pays for, output or not.
            if !self.charge_work(len_u64(bytes.len())) {
                return stopped();
            }
            let head = line_of(&bytes);
            let row = match (name, cksum) {
                // `cksum` names no standard input; the `*sum` tools call it `-`.
                (None, true) => format!("{head}\n"),
                (None, false) => format!("{head}  -\n"),
                (Some(name), true) => format!("{head} {name}\n"),
                (Some(name), false) => format!("{head}  {name}\n"),
            };
            acc.append(CommandResult::stdout(row));
        }
        acc.status = u8::from(failed);
        acc
    }
}
