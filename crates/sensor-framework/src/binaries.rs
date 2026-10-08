//! The executables the Ubuntu persona presents, as synthetic ELF images. Each one is the first 64
//! bytes a real Ubuntu 22.04 binary starts with, then a body generated from that header out to the
//! size it really has ([`crate::elf_body`]), so `cat /bin/echo`, `cat /proc/self/exe` and a
//! byte-range read of `/bin/ls` show the header and the length a probe compares, and `readelf`,
//! `file` and `strings` find the program headers, sections, loader and imports a binary has.
//! Nothing here is read from the host: the header constants are data recorded once from the
//! reference system, the body is a pure function of the row and the byte offset, and no image is
//! ever handed to anything that runs it. Never-exec and no-fetch are untouched.
//!
//! The table is the one source of the binary set. `FakeFs::new` builds a regular node per entry, the
//! shell registry derives its node facts from it (so a lookup and the content behind it cannot
//! disagree), and `/proc/self/exe` resolves through it.
//!
//! Recorded from Ubuntu 22.04 (`ubuntu-2204-binaries`, 2026-09-29): name, path, size, mode and the
//! first 64 bytes. `tests/fixtures/ubuntu-2204-elf-headers.tsv` holds the same rows and the golden
//! test compares the two, so editing either alone fails.
//!
//! Rows after `su` were recorded on 2026-10-07 from a systemd-booted Ubuntu 22.04 reference with the
//! same method (`stat`, `head -c 64 | od`), for the commands the survey work models. `awk` is the
//! Debian alternatives chain `/usr/bin/awk -> /etc/alternatives/awk -> /usr/bin/mawk`, recorded link
//! by link the same day.
//!
//! Left out on purpose: two of the three scripts (`gunzip`, `service`), whose first bytes are text
//! and would need their real bodies. The third, `which`, is the one script the box models
//! ([`WHICH_SCRIPT`]), because the lookup commands must be able to find it.

use crate::fakefs::{Blob, ELF_HEADER_LEN, ElfImage};

/// Where the debianutils `which` script is found on the box.
pub const WHICH_PATH: &str = "/usr/bin/which";

/// The `which` script, debianutils 5.5-1ubuntu2. The first 64 bytes are the ones recorded from
/// Ubuntu 22.04 on 2026-09-29, which also gave its size, 946 bytes. The rest is written from the
/// script's logic (the search the shell's `which` performs), so its length is not the recorded one
/// [unverified body].
pub const WHICH_SCRIPT: &str = r#"#! /bin/sh
set -ef

if test -n "$KSH_VERSION"; then
	puts() {
		print -r -- "$*"
	}
else
	puts() {
		printf '%s\n' "$*"
	}
fi

ALLMATCHES=0

while getopts a whichopts
do
	case "$whichopts" in
		a) ALLMATCHES=1 ;;
		?) puts "Usage: $0 [-a] args"; exit 2 ;;
	esac
done
shift $(($OPTIND - 1))

if [ "$#" -eq 0 ]; then
	ALLRET=1
else
	ALLRET=0
fi
case $PATH in
	(*[!:]:) PATH="$PATH:" ;;
esac

for PROGRAM in "$@"; do
	RET=1
	IFS_SAVE="$IFS"
	IFS=:
	case $PROGRAM in
	*/*)
		if [ -f "$PROGRAM" ] && [ -x "$PROGRAM" ]; then
			puts "$PROGRAM"
			RET=0
		fi
		;;
	*)
		for ELEMENT in $PATH; do
			if [ -z "$ELEMENT" ]; then
				ELEMENT=.
			fi
			if [ -f "$ELEMENT/$PROGRAM" ] && [ -x "$ELEMENT/$PROGRAM" ]; then
				puts "$ELEMENT/$PROGRAM"
				RET=0
				[ "$ALLMATCHES" -eq 1 ] || break
			fi
		done
		;;
	esac
	IFS="$IFS_SAVE"
	if [ "$RET" -ne 0 ]; then
		ALLRET=1
	fi
done

exit "$ALLRET"
"#;

/// Offset of the first newline in `/usr/bin/ls`. The pty capture of `head -n 1 /bin/ls` returned 411
/// wire bytes, which is bytes 0 through this offset with the newline expanded to CR LF, so the
/// image must hold its first `0x0a` exactly here.
pub const LS_FIRST_NEWLINE: u64 = 409;

/// One modeled executable.
#[derive(Debug, Clone, Copy)]
pub struct BinaryImage {
    /// The command name it answers to.
    pub name: &'static str,
    /// The physical path of the file (merged-`/usr`; `/bin/NAME` reaches it by symlink).
    pub path: &'static str,
    pub size: u64,
    /// Full `st_mode`, type bits included.
    pub mode: u32,
    header: [u8; ELF_HEADER_LEN],
    newline_at: Option<u64>,
}

impl BinaryImage {
    /// `permissions` are the octal permission bits as `ls` shows them (`755`, `4755`).
    pub const fn new(
        name: &'static str,
        path: &'static str,
        size: u64,
        permissions: u32,
        header_hex: &str,
        newline_at: Option<u64>,
    ) -> Self {
        Self {
            name,
            path,
            size,
            mode: 0o100_000 | permissions,
            header: decode_header(header_hex),
            newline_at,
        }
    }

    /// The generator's description of this file.
    pub const fn image(&self) -> ElfImage {
        ElfImage {
            header: self.header,
            len: self.size,
            newline_at: self.newline_at,
            name: self.name,
        }
    }

    /// The file's content: O(1) to build, O(len) to read.
    pub fn blob(&self) -> Blob {
        Blob::elf(self.image())
    }

    /// The recorded first 64 bytes.
    pub fn header(&self) -> &[u8; ELF_HEADER_LEN] {
        &self.header
    }
}

/// A command name that is a symlink to another modeled binary (`/usr/bin/sh -> dash`).
#[derive(Debug, Clone, Copy)]
pub struct Alias {
    pub name: &'static str,
    /// Where the link lives.
    pub path: &'static str,
    /// The binary the name runs, by its table name. Without `via` it is also the link's text,
    /// relative to the link's directory, as on the reference system.
    pub target: &'static str,
    /// A Debian alternatives link between the two: the name's link reads this path, and this path
    /// links to the target's physical path.
    pub via: Option<&'static str>,
}

pub const ALIASES: [Alias; 2] = [
    Alias {
        name: "sh",
        path: "/usr/bin/sh",
        target: "dash",
        via: None,
    },
    Alias {
        name: "awk",
        path: "/usr/bin/awk",
        target: "mawk",
        via: Some("/etc/alternatives/awk"),
    },
];

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("header constants are lowercase hex"),
    }
}

/// Decode the 128 hex digits of a recorded header, at compile time so a malformed constant cannot
/// build.
const fn decode_header(hex: &str) -> [u8; ELF_HEADER_LEN] {
    let digits = hex.as_bytes();
    assert!(digits.len() == ELF_HEADER_LEN * 2, "a header is 64 bytes");
    let mut out = [0u8; ELF_HEADER_LEN];
    let mut i = 0;
    while i < ELF_HEADER_LEN {
        out[i] = (nibble(digits[i * 2]) << 4) | nibble(digits[i * 2 + 1]);
        i += 1;
    }
    out
}

/// The image `name` answers to, following an alias to its target.
pub fn find(name: &str) -> Option<&'static BinaryImage> {
    let name = ALIASES
        .iter()
        .find(|alias| alias.name == name)
        .map_or(name, |alias| alias.target);
    BINARIES.iter().find(|binary| binary.name == name)
}

/// Whether `image` is the modeled busybox, which a copy of it keeps being wherever it is saved.
pub fn is_busybox(image: &ElfImage) -> bool {
    find("busybox").is_some_and(|busybox| busybox.image() == *image)
}

/// The synthetic blob for `bytes` when they are, byte for byte, a modeled image: what
/// `cat /proc/self/exe > FILE` writes. Storing the description instead of two megabytes keeps such a
/// copy inside the connection's content allowance, as `cp` already does by sharing the blob. Anything
/// that is not exactly an image (the size and header are compared first) is stored as it came.
pub fn image_blob_for(bytes: &[u8]) -> Option<Blob> {
    const CHUNK: usize = 1 << 16;
    let head = bytes.get(..ELF_HEADER_LEN)?;
    let length = u64::try_from(bytes.len()).ok()?;
    BINARIES
        .iter()
        .filter(|binary| binary.size == length && binary.header[..] == *head)
        .find(|binary| {
            let body = binary.image().body();
            let mut generated = Vec::with_capacity(CHUNK);
            bytes
                .chunks(CHUNK)
                .zip((0u64..).step_by(CHUNK))
                .all(|(chunk, from)| {
                    generated.clear();
                    body.append_range(from, from + chunk.len() as u64, &mut generated);
                    generated == chunk
                })
        })
        .map(BinaryImage::blob)
}

/// Every binary the persona has, in the order they were recorded.
pub const BINARIES: &[BinaryImage] = &[
    BinaryImage::new(
        "busybox",
        "/usr/bin/busybox",
        2_193_272,
        0o755,
        "7f454c4602010103000000000000000002003e000100000000b34000000000004000000000000000387021000000000000000000400038000a0040001d001c00",
        None,
    ),
    BinaryImage::new(
        "cat",
        "/usr/bin/cat",
        35_288,
        0o755,
        "7f454c4602010100000000000000000003003e000100000060370000000000004000000000000000188200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "echo",
        "/usr/bin/echo",
        35_128,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000b02f0000000000004000000000000000b88100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "bash",
        "/usr/bin/bash",
        1_396_520,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f02e0300000000004000000000000000a84715000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "dash",
        "/usr/bin/dash",
        125_688,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f04e000000000000400000000000000078e301000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "readlink",
        "/usr/bin/readlink",
        39_336,
        0o755,
        "7f454c4602010100000000000000000003003e000100000080360000000000004000000000000000e89100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "dd",
        "/usr/bin/dd",
        68_120,
        0o755,
        "7f454c4602010100000000000000000003003e000100000070470000000000004000000000000000580201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "test",
        "/usr/bin/test",
        43_456,
        0o755,
        "7f454c4602010100000000000000000003003e00010000006027000000000000400000000000000040a200000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "[",
        "/usr/bin/[",
        51_648,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000102c000000000000400000000000000040c200000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "true",
        "/usr/bin/true",
        26_936,
        0o755,
        "7f454c4602010100000000000000000003003e000100000050190000000000004000000000000000b86100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "false",
        "/usr/bin/false",
        26_936,
        0o755,
        "7f454c4602010100000000000000000003003e000100000050190000000000004000000000000000b86100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "ls",
        "/usr/bin/ls",
        138_216,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000a06a0000000000004000000000000000281402000000000000000000400038000d0040001f001e00",
        Some(LS_FIRST_NEWLINE),
    ),
    BinaryImage::new(
        "cp",
        "/usr/bin/cp",
        141_832,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000705c0000000000004000000000000000482202000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "rm",
        "/usr/bin/rm",
        59_912,
        0o755,
        "7f454c4602010100000000000000000003003e00010000001043000000000000400000000000000048e200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "mkdir",
        "/usr/bin/mkdir",
        68_104,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f0360000000000004000000000000000480201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "chmod",
        "/usr/bin/chmod",
        55_816,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d041000000000000400000000000000048d200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "sleep",
        "/usr/bin/sleep",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000802b0000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "uname",
        "/usr/bin/uname",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000902a0000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "id",
        "/usr/bin/id",
        39_432,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000b0320000000000004000000000000000489200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "whoami",
        "/usr/bin/whoami",
        31_240,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000b0270000000000004000000000000000487200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "ping",
        "/usr/bin/ping",
        76_680,
        0o755,
        "7f454c4602010100000000000000000003003e000100000090670000000000004000000000000000482401000000000000000000400038000d0040001d001c00",
        None,
    ),
    BinaryImage::new(
        "wget",
        "/usr/bin/wget",
        470_032,
        0o755,
        "7f454c4602010100000000000000000003003e000100000070010100000000004000000000000000902407000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "curl",
        "/usr/bin/curl",
        260_328,
        0o755,
        "7f454c4602010100000000000000000003003e000100000030df000000000000400000000000000068f103000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "mount",
        "/usr/bin/mount",
        47_488,
        0o4755,
        "7f454c4602010100000000000000000003003e0001000000606e0000000000004000000000000000c0b100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "touch",
        "/usr/bin/touch",
        92_680,
        0o755,
        "7f454c4602010100000000000000000003003e000100000020480000000000004000000000000000486201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "mv",
        "/usr/bin/mv",
        137_752,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d04b0000000000004000000000000000581202000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "ln",
        "/usr/bin/ln",
        59_912,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000b034000000000000400000000000000048e200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "rmdir",
        "/usr/bin/rmdir",
        43_432,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000e02b0000000000004000000000000000e8a100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "printf",
        "/usr/bin/printf",
        51_648,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000502d000000000000400000000000000040c200000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "base64",
        "/usr/bin/base64",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e000100000020360000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "head",
        "/usr/bin/head",
        43_528,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f03a000000000000400000000000000048a200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "tail",
        "/usr/bin/tail",
        68_112,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000b05a0000000000004000000000000000500201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "wc",
        "/usr/bin/wc",
        43_440,
        0o755,
        "7f454c4602010100000000000000000003003e000100000000370000000000004000000000000000f0a100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "grep",
        "/usr/bin/grep",
        182_728,
        0o755,
        "7f454c4602010100000000000000000003003e00010000007071000000000000400000000000000048c202000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "basename",
        "/usr/bin/basename",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e000100000040280000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "dirname",
        "/usr/bin/dirname",
        31_112,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000e0270000000000004000000000000000c87100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "sha256sum",
        "/usr/bin/sha256sum",
        51_624,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000c03a0000000000004000000000000000e8c100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "md5sum",
        "/usr/bin/md5sum",
        43_432,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000103b0000000000004000000000000000e8a100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "sha1sum",
        "/usr/bin/sha1sum",
        43_432,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000c03a0000000000004000000000000000e8a100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "cksum",
        "/usr/bin/cksum",
        35_240,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000e0270000000000004000000000000000e88100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "realpath",
        "/usr/bin/realpath",
        39_336,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d02e0000000000004000000000000000e89100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "env",
        "/usr/bin/env",
        43_976,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000803d000000000000400000000000000008a400000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "ps",
        "/usr/bin/ps",
        141_776,
        0o755,
        "7f454c4602010100000000000000000003003e000100000020b90000000000004000000000000000502202000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "kill",
        "/usr/bin/kill",
        30_952,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0360000000000004000000000000000687100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "hostname",
        "/usr/bin/hostname",
        22_760,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000902a0000000000004000000000000000685100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "nproc",
        "/usr/bin/nproc",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000902d0000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "df",
        "/usr/bin/df",
        85_072,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000705f0000000000004000000000000000904401000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "free",
        "/usr/bin/free",
        26_864,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000702e0000000000004000000000000000706100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "uptime",
        "/usr/bin/uptime",
        14_568,
        0o755,
        "7f454c4602010100000000000000000003003e000100000040150000000000004000000000000000683100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "who",
        "/usr/bin/who",
        51_736,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000702c000000000000400000000000000058c200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "date",
        "/usr/bin/date",
        104_968,
        0o755,
        "7f454c4602010100000000000000000003003e000100000000420000000000004000000000000000489201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "stat",
        "/usr/bin/stat",
        80_400,
        0o755,
        "7f454c4602010100000000000000000003003e000100000080330000000000004000000000000000503201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "find",
        "/usr/bin/find",
        282_088,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0850000000000004000000000000000284604000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "tar",
        "/usr/bin/tar",
        522_048,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0ce0000000000004000000000000000c0ef07000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "gzip",
        "/usr/bin/gzip",
        93_424,
        0o755,
        "7f454c4602010100000000000000000003003e000100000010330000000000004000000000000000706501000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "sed",
        "/usr/bin/sed",
        113_224,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0490000000000004000000000000000c8b201000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "cut",
        "/usr/bin/cut",
        39_432,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0310000000000004000000000000000489200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "tr",
        "/usr/bin/tr",
        47_624,
        0o755,
        "7f454c4602010100000000000000000003003e00010000002035000000000000400000000000000048b200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "sort",
        "/usr/bin/sort",
        101_176,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000406f0000000000004000000000000000788301000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "uniq",
        "/usr/bin/uniq",
        43_528,
        0o755,
        "7f454c4602010100000000000000000003003e00010000001033000000000000400000000000000048a200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "xargs",
        "/usr/bin/xargs",
        63_912,
        0o755,
        "7f454c4602010100000000000000000003003e000100000040450000000000004000000000000000e8f100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "od",
        "/usr/bin/od",
        68_104,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000e03b0000000000004000000000000000480201000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "chattr",
        "/usr/bin/chattr",
        14_656,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000a0180000000000004000000000000000c03100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "lsattr",
        "/usr/bin/lsattr",
        14_656,
        0o755,
        "7f454c4602010100000000000000000003003e000100000080150000000000004000000000000000c03100000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "passwd",
        "/usr/bin/passwd",
        59_976,
        0o4755,
        "7f454c4602010100000000000000000003003e0001000000b0590000000000004000000000000000c8e200000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "useradd",
        "/usr/sbin/useradd",
        130_720,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000408e0000000000004000000000000000e0f601000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "nohup",
        "/usr/bin/nohup",
        35_240,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000202e0000000000004000000000000000e88100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "setsid",
        "/usr/bin/setsid",
        14_720,
        0o755,
        "7f454c4602010100000000000000000003003e000100000070180000000000004000000000000000c03100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "perl",
        "/usr/bin/perl",
        3_806_200,
        0o755,
        "7f454c4602010100000000000000000003003e000100000090a90400000000004000000000000000380c3a000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "apt",
        "/usr/bin/apt",
        18_824,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000d0240000000000004000000000000000c84100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "apt-get",
        "/usr/bin/apt-get",
        51_680,
        0o755,
        "7f454c4602010100000000000000000003003e000100000070500000000000004000000000000000e0c100000000000000000000400038000d00400020001f00",
        None,
    ),
    BinaryImage::new(
        "dpkg",
        "/usr/bin/dpkg",
        318_144,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000708c000000000000400000000000000040d304000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "su",
        "/usr/bin/su",
        55_680,
        0o4755,
        "7f454c4602010100000000000000000003003e0001000000203f0000000000004000000000000000c0d100000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "tee",
        "/usr/bin/tee",
        35_336,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000902f0000000000004000000000000000488200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "mawk",
        "/usr/bin/mawk",
        158_504,
        0o755,
        "7f454c4602010100000000000000000003003e000100000010620000000000004000000000000000a86302000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "ip",
        "/usr/bin/ip",
        718_896,
        0o755,
        "7f454c4602010100000000000000000003003e000100000000f1000000000000400000000000000070f00a000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "ss",
        "/usr/bin/ss",
        128_072,
        0o755,
        "7f454c4602010100000000000000000003003e00010000007063000000000000400000000000000088ec01000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "ssh",
        "/usr/bin/ssh",
        850_984,
        0o755,
        "7f454c4602010100000000000000000003003e00010000006037010000000000400000000000000068f40c000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "systemctl",
        "/usr/bin/systemctl",
        1_119_856,
        0o755,
        "7f454c4602010100000000000000000003003e000100000080370100000000004000000000000000b00d11000000000000000000400038000e00400023002200",
        None,
    ),
    BinaryImage::new(
        "crontab",
        "/usr/bin/crontab",
        39_568,
        0o2755,
        "7f454c4602010100000000000000000003003e000100000040350000000000004000000000000000d09200000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "lspci",
        "/usr/bin/lspci",
        94_288,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000e0320000000000004000000000000000906801000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "lshw",
        "/usr/bin/lshw",
        922_824,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f0c10100000000004000000000000000080d0e000000000000000000400038000d0040001f001e00",
        None,
    ),
    BinaryImage::new(
        "sshd",
        "/usr/sbin/sshd",
        921_288,
        0o755,
        "7f454c4602010100000000000000000003003e00010000008028010000000000400000000000000048070e000000000000000000400038000d0040001e001d00",
        None,
    ),
    BinaryImage::new(
        "w",
        "/usr/bin/w",
        22_760,
        0o755,
        "7f454c4602010100000000000000000003003e0001000000f0290000000000004000000000000000685100000000000000000000400038000d0040001e001d00",
        None,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakefs::FakeFs;
    use crate::persona;
    use sha2::{Digest, Sha256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The recorded rows, as the fixture file keeps them: name, path, size, permissions, header.
    fn recorded() -> Vec<[String; 5]> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ubuntu-2204-elf-headers.tsv");
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| {
                let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
                <[String; 5]>::try_from(fields).expect("five columns")
            })
            .collect()
    }

    /// The header constants in the code are the recorded ones, row for row and in both directions:
    /// a byte changed in either place, a row dropped or a row invented fails here.
    #[test]
    fn every_recorded_header_is_pinned_to_the_table() {
        let recorded = recorded();
        assert_eq!(recorded.len(), BINARIES.len());
        for (row, binary) in recorded.iter().zip(BINARIES) {
            let [name, path, size, permissions, header] = row;
            assert_eq!(name, binary.name);
            assert_eq!(path, binary.path, "{name}");
            assert_eq!(size.parse::<u64>().unwrap(), binary.size, "{name}");
            assert_eq!(
                u32::from_str_radix(permissions, 8).unwrap() | 0o100_000,
                binary.mode,
                "{name}"
            );
            assert_eq!(header, &hex(binary.header()), "{name}");
        }
    }

    /// The load-bearing rows, pinned by value so the golden file and the table cannot drift
    /// together: the header bytes every ELF-reading probe compares.
    #[test]
    fn the_probed_headers_are_the_recorded_bytes() {
        let expected = [
            (
                "busybox",
                "7f454c4602010103000000000000000002003e000100000000b34000000000004000000000000000387021000000000000000000400038000a0040001d001c00",
            ),
            (
                "ls",
                "7f454c4602010100000000000000000003003e0001000000a06a0000000000004000000000000000281402000000000000000000400038000d0040001f001e00",
            ),
            (
                "echo",
                "7f454c4602010100000000000000000003003e0001000000b02f0000000000004000000000000000b88100000000000000000000400038000d0040001e001d00",
            ),
            (
                "bash",
                "7f454c4602010100000000000000000003003e0001000000f02e0300000000004000000000000000a84715000000000000000000400038000d0040001e001d00",
            ),
        ];
        for (name, header) in expected {
            assert_eq!(hex(find(name).unwrap().header()), header, "{name}");
        }
        assert_eq!(find("busybox").unwrap().size, 2_193_272);
        assert_eq!(find("ls").unwrap().size, 138_216);
        assert_eq!(find("echo").unwrap().size, 35_128);
        assert_eq!(find("bash").unwrap().size, 1_396_520);
    }

    /// The 52 bytes an ELF probe of `/bin/ls` prints are the first 52 of the recorded header.
    #[test]
    fn ls_first_52_bytes_are_the_recorded_prefix() {
        let fs = FakeFs::new();
        assert_eq!(
            hex(&fs.read_range("/bin/ls", 0, 52).unwrap()),
            "7f454c4602010100000000000000000003003e0001000000a06a0000000000004000000000000000281402000000000000000000400038000d0040001f001e00"
                [..104]
        );
    }

    /// The pty capture of `head -n 1 /bin/ls` pins the first newline at offset 409, and nothing
    /// earlier may be one.
    #[test]
    fn ls_holds_its_first_newline_at_409_and_none_before() {
        let fs = FakeFs::new();
        let head = fs.read_range("/bin/ls", 0, 410).unwrap();
        assert_eq!(head.len(), 410);
        assert_eq!(head.get(409), Some(&0x0a));
        assert!(!head[..409].contains(&0x0a));
        // Past it the body has the newlines a binary's bytes do, out to the recorded size.
        let rest = fs.read_range("/bin/ls", 410, u64::MAX).unwrap();
        assert_eq!(rest.len() as u64, 138_216 - 410);
        assert!(rest.iter().filter(|b| **b == 0x0a).count() > 10);
    }

    /// Class, byte order and machine in every header say 64-bit little-endian x86-64, which is
    /// what `uname -m` and `/proc/cpuinfo` say.
    #[test]
    fn every_header_agrees_with_the_persona_architecture() {
        assert_eq!(persona::ARCH, "x86_64");
        for binary in BINARIES {
            let header = binary.header();
            assert_eq!(&header[..4], b"\x7fELF", "{}", binary.name);
            assert_eq!(header[4], 2, "{} is ELFCLASS64", binary.name);
            assert_eq!(header[5], 1, "{} is little-endian", binary.name);
            assert_eq!(header[18..20], [0x3e, 0x00], "{} is EM_X86_64", binary.name);
        }
    }

    /// The SHA-256 of each image as generated when the layout was written and checked with
    /// `file`, `readelf` and `objdump` (`elf_body_tests.rs`). A probe that hashes a binary on one
    /// visit and again on the next must get the same answer, so a change to any of these is a
    /// change to what every deployed sensor serves, and has to be deliberate.
    const GOLDEN_SHA256: [(&str, &str); 8] = [
        (
            "busybox",
            "07a69aaffb5f3e576a2160f81b78286a648007a0a6f0b521f79db2fa7c71ab75",
        ),
        (
            "ls",
            "531929008e9b5466ab17f4cac720029409d5b70bc4c90ca5649b6523669f44ce",
        ),
        (
            "cat",
            "f7d33ccf5072017d5cdea07d4a119267d7968a59baa1addbc000047493606ee6",
        ),
        (
            "echo",
            "53424cc3da4cca0c9d57d2cfd8881b3d468a3fea114e4c2debeb739c491cdb55",
        ),
        (
            "dash",
            "c904084ffcbfdf5593796ccbe24df9e34817b881fffb711f153a03d1ffc978dd",
        ),
        (
            "bash",
            "23bbe65be4cbaf09b258def0c8ad76616590c0228dda7744523f2a40dfd1f3ee",
        ),
        (
            "true",
            "b2de1b80d3da78d9c868e414ccba5e5b28ba748149909005e328843ddfa6cfad",
        ),
        (
            "false",
            "e5d20cf62e2bd4eb04258fd45d3c452211776745368a24a6e3fc18bad0577092",
        ),
    ];

    fn blob_digest(binary: &BinaryImage) -> Vec<u8> {
        let blob = binary.blob();
        let mut hasher = Sha256::new();
        let mut offset = 0;
        // An odd chunk size, so pieces and reads never line up by accident.
        while offset < binary.size {
            hasher.update(blob.read_range(offset, 6_007));
            offset += 6_007;
        }
        hasher.finalize().to_vec()
    }

    /// An image is a pure function of its table row: generated on separate threads it hashes the
    /// same, and it hashes what it hashed when it was checked. It has no input (cwd, environment,
    /// hostname, clock) to vary; a process-level variation test would need a spawned process,
    /// which this crate never has.
    #[test]
    fn an_image_is_the_same_on_every_thread_and_matches_its_recorded_digest() {
        for (name, golden) in GOLDEN_SHA256 {
            let digests: Vec<Vec<u8>> = (0..4)
                .map(|_| std::thread::spawn(move || blob_digest(find(name).unwrap())))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            for digest in digests {
                assert_eq!(hex(&digest), golden, "{name}");
            }
        }
    }

    #[test]
    fn a_saved_copy_of_an_image_is_recognized_and_nothing_else_is() {
        let busybox = find("busybox").unwrap();
        let bytes = busybox.blob().read_range(0, u64::MAX);
        assert_eq!(bytes.len() as u64, busybox.size);
        let blob = image_blob_for(&bytes).expect("an exact copy is an image");
        assert_eq!(blob.owned_bytes(), 0);
        assert!(is_busybox(&blob.as_elf().unwrap()));
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(image_blob_for(&altered).is_none(), "one byte off");
        assert!(
            image_blob_for(&bytes[..bytes.len() - 1]).is_none(),
            "one byte short"
        );
        assert!(image_blob_for(b"\x7fELF").is_none());
        assert!(image_blob_for(b"").is_none());
    }

    #[test]
    fn find_follows_the_sh_alias_to_dash() {
        assert_eq!(find("sh").unwrap().path, "/usr/bin/dash");
        assert_eq!(find("dash").unwrap().path, "/usr/bin/dash");
        assert!(find("nosuchbinary").is_none());
    }

    #[test]
    fn names_and_paths_are_unique_and_every_image_is_at_least_a_header() {
        for (i, binary) in BINARIES.iter().enumerate() {
            assert!(binary.size >= ELF_HEADER_LEN as u64, "{}", binary.name);
            assert!(binary.path.starts_with("/usr/"), "{}", binary.name);
            for other in &BINARIES[i + 1..] {
                assert_ne!(binary.name, other.name);
                assert_ne!(binary.path, other.path);
            }
        }
    }
}
