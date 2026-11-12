//! The bytes of a synthetic executable past its recorded 64-byte header.
//!
//! A real Ubuntu binary cannot ship in this public repository (the bodies are GPL code), and a
//! body of patterned filler gives itself away the moment anyone looks: no readable strings, no
//! zero runs, program headers that are noise, every binary the same. So the body is generated
//! from the recorded header instead, as the layout the GNU toolchain produces for that header's
//! counts and offsets: a program header table that agrees with the sections, `.interp` naming the
//! x86-64 loader, the three notes (one a per-binary build ID), `.dynsym` and `.dynstr` importing
//! libc functions under their glibc version names, version records, relocations, PLT stubs, a
//! `.text` of instruction-shaped bytes, a `.rodata` with the usage and error strings a binary of
//! that name prints, unwind tables, `.dynamic`, the GOT, and the section header table at the
//! header's `e_shoff` with `.shstrtab`. `busybox`, whose header says a static `ET_EXEC`, gets the
//! static glibc layout instead: no loader, no dynamic section.
//!
//! Every byte is a pure function of the image (header, length, name) and its offset, computed in
//! constant time and memory: nothing is stored but the layout, a few hundred bytes. Names of libc
//! symbols and versions are interface facts, the strings are short usage lines, and the code is
//! seeded noise shaped like x86-64 instructions: nothing here is copied code or runs.
//!
//! The header fields that drive the layout are `e_type`, `e_entry`, `e_phnum`, `e_shoff`,
//! `e_shnum` and `e_shstrndx`. A header the generator has no layout for (any image a test builds
//! from random bytes) keeps the old body: `0x80 | (offset & 0x3f)`.
//!
//! `newline_at` keeps its meaning: the first `0x0a` of the image. When an image names one, the
//! generator picks the import count whose layout puts the first newline exactly there (for
//! `/bin/ls`, offset 409, a byte of `PT_DYNAMIC`'s `p_offset`), and only if no count does is the
//! byte planted over the layout, every earlier `0x0a` in the body turned into `0x0b`.

use crate::fakefs::{ELF_HEADER_LEN, ElfImage};

const PAGE: u64 = 0x1000;
const EXEC_BASE: u64 = 0x40_0000;
const PHDR_SIZE: u64 = 56;
const SHDR_SIZE: u64 = 64;
const MAX_SECTIONS: usize = 40;
const MAX_PHDRS: usize = 16;
const INTERP: &[u8] = b"/lib64/ld-linux-x86-64.so.2\0";
const LIBC: &[u8] = b"libc.so.6\0";
const COMMENT: &[u8] = b"GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0\0";
const DYNAMIC_ENTRIES: u64 = 31;

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_GNU_HASH: u32 = 0x6fff_fff6;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_MERGE: u64 = 0x10;
const SHF_STRINGS: u64 = 0x20;
const SHF_INFO_LINK: u64 = 0x40;
const SHF_TLS: u64 = 0x400;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// The glibc version names the imports carry, in the order their `vna_other` indices are
/// assigned.
const VERSIONS: [&str; 12] = [
    "GLIBC_2.2.5",
    "GLIBC_2.3",
    "GLIBC_2.3.4",
    "GLIBC_2.4",
    "GLIBC_2.6",
    "GLIBC_2.7",
    "GLIBC_2.14",
    "GLIBC_2.17",
    "GLIBC_2.25",
    "GLIBC_2.26",
    "GLIBC_2.33",
    "GLIBC_2.34",
];

const V2_2_5: u8 = 0;
const V2_3: u8 = 1;
const V2_3_4: u8 = 2;
const V2_4: u8 = 3;
const V2_6: u8 = 4;
const V2_7: u8 = 5;
const V2_14: u8 = 6;
const V2_17: u8 = 7;
const V2_25: u8 = 8;
const V2_26: u8 = 9;
const V2_33: u8 = 10;
const V2_34: u8 = 11;
const UNVERSIONED: u8 = u8::MAX;

/// The imports every dynamic image has, as `.dynsym` entries 1 to 6: name, `st_info`, version.
const ALWAYS: [(&str, u8, u8); 6] = [
    ("__libc_start_main", 0x12, V2_34),
    ("__cxa_finalize", 0x22, V2_2_5),
    ("_ITM_deregisterTMCloneTable", 0x20, UNVERSIONED),
    ("__gmon_start__", 0x20, UNVERSIONED),
    ("_ITM_registerTMCloneTable", 0x20, UNVERSIONED),
    ("__stack_chk_fail", 0x12, V2_4),
];

/// libc functions with the version their x86-64 symbol is bound to. An image imports a window of
/// this list that starts at a per-binary offset.
const POOL: &[(&str, u8)] = &[
    ("__errno_location", V2_2_5),
    ("strlen", V2_2_5),
    ("__ctype_b_loc", V2_3),
    ("malloc", V2_2_5),
    ("fstat", V2_33),
    ("__fprintf_chk", V2_3_4),
    ("memcpy", V2_14),
    ("getenv", V2_2_5),
    ("openat", V2_4),
    ("clock_gettime", V2_17),
    ("free", V2_2_5),
    ("strcmp", V2_2_5),
    ("dcgettext", V2_2_5),
    ("error", V2_2_5),
    ("fclose", V2_2_5),
    ("__printf_chk", V2_3_4),
    ("getrandom", V2_25),
    ("reallocarray", V2_26),
    ("realloc", V2_2_5),
    ("setlocale", V2_2_5),
    ("bindtextdomain", V2_2_5),
    ("textdomain", V2_2_5),
    ("__cxa_atexit", V2_2_5),
    ("getopt_long", V2_2_5),
    ("__fpending", V2_2_5),
    ("fileno", V2_2_5),
    ("fflush", V2_2_5),
    ("lseek", V2_2_5),
    ("close", V2_2_5),
    ("read", V2_2_5),
    ("write", V2_2_5),
    ("abort", V2_2_5),
    ("exit", V2_2_5),
    ("_exit", V2_2_5),
    ("calloc", V2_2_5),
    ("memset", V2_2_5),
    ("memmove", V2_2_5),
    ("memchr", V2_2_5),
    ("memcmp", V2_2_5),
    ("strchr", V2_2_5),
    ("strrchr", V2_2_5),
    ("strncmp", V2_2_5),
    ("strdup", V2_2_5),
    ("strnlen", V2_2_5),
    ("strspn", V2_2_5),
    ("strcspn", V2_2_5),
    ("strstr", V2_2_5),
    ("strcoll", V2_2_5),
    ("strerror", V2_2_5),
    ("strtol", V2_2_5),
    ("strtoul", V2_2_5),
    ("strtoumax", V2_2_5),
    ("strtoimax", V2_2_5),
    ("__ctype_get_mb_cur_max", V2_2_5),
    ("__ctype_tolower_loc", V2_3),
    ("__ctype_toupper_loc", V2_3),
    ("mbrtowc", V2_2_5),
    ("mbsinit", V2_2_5),
    ("iswprint", V2_2_5),
    ("iswcntrl", V2_2_5),
    ("wcwidth", V2_2_5),
    ("nl_langinfo", V2_2_5),
    ("localeconv", V2_2_5),
    ("__freading", V2_2_5),
    ("fseeko", V2_2_5),
    ("fcntl", V2_2_5),
    ("__overflow", V2_2_5),
    ("__uflow", V2_2_5),
    ("fwrite", V2_2_5),
    ("fputs_unlocked", V2_2_5),
    ("fputc_unlocked", V2_2_5),
    ("fwrite_unlocked", V2_2_5),
    ("__snprintf_chk", V2_3_4),
    ("__sprintf_chk", V2_3_4),
    ("__vfprintf_chk", V2_3_4),
    ("__memcpy_chk", V2_3_4),
    ("__assert_fail", V2_2_5),
    ("isatty", V2_2_5),
    ("ioctl", V2_2_5),
    ("getpwuid", V2_2_5),
    ("getgrgid", V2_2_5),
    ("getpwnam", V2_2_5),
    ("getgrnam", V2_2_5),
    ("getuid", V2_2_5),
    ("geteuid", V2_2_5),
    ("getgid", V2_2_5),
    ("getegid", V2_2_5),
    ("getpid", V2_2_5),
    ("lstat", V2_33),
    ("stat", V2_33),
    ("fstatat", V2_33),
    ("opendir", V2_2_5),
    ("readdir", V2_2_5),
    ("closedir", V2_2_5),
    ("dirfd", V2_2_5),
    ("fdopendir", V2_4),
    ("readlink", V2_2_5),
    ("unlinkat", V2_4),
    ("unlink", V2_2_5),
    ("rename", V2_2_5),
    ("mkdir", V2_2_5),
    ("rmdir", V2_2_5),
    ("chmod", V2_2_5),
    ("fchmod", V2_2_5),
    ("fchown", V2_2_5),
    ("umask", V2_2_5),
    ("utimensat", V2_6),
    ("futimens", V2_6),
    ("__fread_chk", V2_7),
    ("__read_chk", V2_4),
    ("realpath", V2_3),
    ("getcwd", V2_2_5),
    ("localtime_r", V2_2_5),
    ("gmtime_r", V2_2_5),
    ("strftime", V2_2_5),
    ("mktime", V2_2_5),
    ("tzset", V2_2_5),
    ("time", V2_2_5),
    ("gettimeofday", V2_2_5),
    ("nanosleep", V2_2_5),
    ("sigaction", V2_2_5),
    ("sigemptyset", V2_2_5),
    ("sigaddset", V2_2_5),
    ("sigismember", V2_2_5),
    ("sigprocmask", V2_2_5),
    ("signal", V2_2_5),
    ("raise", V2_2_5),
    ("kill", V2_2_5),
    ("fork", V2_2_5),
    ("execvp", V2_2_5),
    ("waitpid", V2_2_5),
    ("pipe", V2_2_5),
    ("dup2", V2_2_5),
    ("posix_fadvise", V2_2_5),
    ("sysconf", V2_2_5),
    ("qsort", V2_2_5),
    ("bsearch", V2_2_5),
    ("fopen", V2_2_5),
    ("fdopen", V2_2_5),
    ("fread_unlocked", V2_2_5),
    ("getdelim", V2_2_5),
    ("ungetc", V2_2_5),
    ("setvbuf", V2_2_5),
    ("clearerr", V2_2_5),
    ("strverscmp", V2_2_5),
    ("mempcpy", V2_2_5),
    ("stpcpy", V2_2_5),
    ("rawmemchr", V2_2_5),
    ("memrchr", V2_2_5),
    ("secure_getenv", V2_17),
    ("explicit_bzero", V2_25),
    ("fnmatch", V2_2_5),
    ("regexec", V2_3_4),
    ("iconv_open", V2_2_5),
    ("socket", V2_2_5),
    ("connect", V2_2_5),
    ("getaddrinfo", V2_2_5),
    ("freeaddrinfo", V2_2_5),
    ("poll", V2_2_5),
];

/// The most symbols one image can have: the null entry, [`ALWAYS`] and the whole pool.
const MAX_SYMS: usize = 1 + ALWAYS.len() + POOL.len();

/// Strings `.rodata` holds for every GNU coreutils program.
const COREUTILS_STRINGS: [&str; 18] = [
    "Try '%s --help' for more information.\n",
    "      --help        display this help and exit\n",
    "      --version     output version information and exit\n",
    "GNU coreutils",
    "coreutils",
    "/usr/share/locale",
    "https://www.gnu.org/software/coreutils/",
    "Report any translation bugs to <https://translationproject.org/team/>\n",
    "Full documentation <%s%s>\n",
    "or available locally via: info '(coreutils) %s%s'\n",
    "%s (%s) %s\n",
    "Written by %s.\n",
    "write error",
    "%s: %s",
    "memory exhausted",
    "invalid argument %s for %s",
    "ambiguous argument %s for %s",
    "standard output",
];

/// Strings for a program outside coreutils: the formats any getopt-and-error program carries.
const OTHER_STRINGS: [&str; 8] = [
    "Try '%s --help' for more information.\n",
    "/usr/share/locale",
    "%s: %s\n",
    "%s: option requires an argument -- '%c'\n",
    "out of memory",
    "write error",
    "standard output",
    "standard input",
];

const BUSYBOX_STRINGS: [&str; 12] = [
    "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.",
    "Usage: busybox [function [arguments]...]",
    "   or: busybox --list[-full]",
    "   or: busybox --install [-s] [DIR]",
    "   or: function [arguments]...",
    "Currently defined functions:",
    "%s: applet not found",
    "/proc/self/exe",
    "/bin/sh",
    "can't execute '%s'",
    "out of memory",
    "write error",
];

const COREUTILS: [&str; 58] = [
    "cat",
    "echo",
    "readlink",
    "dd",
    "test",
    "[",
    "true",
    "false",
    "ls",
    "cp",
    "rm",
    "mkdir",
    "chmod",
    "sleep",
    "uname",
    "id",
    "whoami",
    "touch",
    "mv",
    "ln",
    "rmdir",
    "printf",
    "base64",
    "head",
    "tail",
    "wc",
    "basename",
    "dirname",
    "sha256sum",
    "md5sum",
    "sha1sum",
    "cksum",
    "realpath",
    "env",
    "nproc",
    "df",
    "who",
    "date",
    "stat",
    "cut",
    "tr",
    "sort",
    "uniq",
    "od",
    "nohup",
    "tee",
    "chown",
    "chgrp",
    "du",
    "pwd",
    "yes",
    "seq",
    "split",
    "tac",
    "nl",
    "expr",
    "mktemp",
    "sync",
];

/// The synopsis line of `name --help`, or `None` for a program with no line here.
fn usage_line(name: &str) -> Option<&'static str> {
    Some(match name {
        "ls" | "cat" | "rm" | "head" | "tail" | "wc" | "sha256sum" | "md5sum" | "sha1sum"
        | "cksum" | "df" | "od" | "tee" | "sort" => "Usage: %s [OPTION]... [FILE]...\n",
        "echo" => "Usage: %s [SHORT-OPTION]... [STRING]...\n  or:  %s LONG-OPTION\n",
        "true" | "false" => "Usage: %s [ignored command line arguments]\n  or:  %s OPTION\n",
        "test" | "[" => "Usage: test EXPRESSION\n  or:  test\n  or:  [ EXPRESSION ]\n",
        "cp" | "mv" => "Usage: %s [OPTION]... [-T] SOURCE DEST\n",
        "ln" => "Usage: %s [OPTION]... [-T] TARGET LINK_NAME\n",
        "mkdir" | "rmdir" => "Usage: %s [OPTION]... DIRECTORY...\n",
        "chmod" => "Usage: %s [OPTION]... MODE[,MODE]... FILE...\n",
        "sleep" => "Usage: %s NUMBER[SUFFIX]...\n  or:  %s OPTION\n",
        "uname" | "whoami" | "nproc" => "Usage: %s [OPTION]...\n",
        "id" => "Usage: %s [OPTION]... [USER]...\n",
        "touch" | "stat" | "realpath" | "readlink" => "Usage: %s [OPTION]... FILE...\n",
        "printf" => "Usage: %s FORMAT [ARGUMENT]...\n  or:  %s OPTION\n",
        "base64" => "Usage: %s [OPTION]... [FILE]\n",
        "uniq" => "Usage: %s [OPTION]... [INPUT [OUTPUT]]\n",
        "basename" => "Usage: %s NAME [SUFFIX]\n  or:  %s OPTION... NAME...\n",
        "dirname" => "Usage: %s [OPTION] NAME...\n",
        "env" => "Usage: %s [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]\n",
        "who" => "Usage: %s [OPTION]... [ FILE | ARG1 ARG2 ]\n",
        "date" => "Usage: %s [OPTION]... [+FORMAT]\n",
        "cut" => "Usage: %s OPTION... [FILE]...\n",
        "tr" => "Usage: %s [OPTION]... SET1 [SET2]\n",
        "nohup" => "Usage: %s COMMAND [ARG]...\n  or:  %s OPTION\n",
        "dd" => "Usage: %s [OPERAND]...\n  or:  %s OPTION\n",
        "grep" => "Usage: %s [OPTION]... PATTERNS [FILE]...\n",
        "sed" => "Usage: %s [OPTION]... {script-only-if-no-other-script} [input-file]...\n",
        "find" => "Usage: %s [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]\n",
        "xargs" => "Usage: %s [OPTION]... COMMAND [INITIAL-ARGS]...\n",
        "gzip" => "Usage: %s [OPTION]... [FILE]...\n",
        "tar" => "Usage: %s [OPTION...] [FILE]...\n",
        "wget" => "Usage: %s [OPTION]... [URL]...\n",
        "curl" => "Usage: curl [options...] <url>\n",
        "ps" => "Usage:\n ps [options]\n",
        "kill" => "Usage:\n kill [options] <pid> [...]\n",
        "free" => "Usage:\n free [options]\n",
        "uptime" => "Usage:\n uptime [options]\n",
        "w" => "Usage:\n w [options] [user]\n",
        "hostname" => "Usage: hostname [-b] {hostname|-F file}         set host name (from file)\n",
        "ssh" => "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n",
        "sshd" => "usage: sshd [-46DdeiqTt] [-C connection_spec] [-c host_cert_file]\n",
        "ip" => "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n",
        "ss" => "Usage: ss [ OPTIONS ]\n",
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Null,
    Interp,
    NoteProperty,
    NoteBuildId,
    NoteAbiTag,
    GnuHash,
    Dynsym,
    Dynstr,
    Versym,
    Verneed,
    RelaDyn,
    RelaPlt,
    IRelaPlt,
    Init,
    Fini,
    Plt,
    PltGot,
    PltSec,
    Code,
    Rodata,
    EhFrameHdr,
    EhFrame,
    InitArray,
    FiniArray,
    RelRo,
    Dynamic,
    Got,
    GotPlt,
    Data,
    NoBits,
    DebugLink,
    DebugAltLink,
    Comment,
    Shstrtab,
}

#[derive(Debug, Clone, Copy)]
struct Section {
    name: &'static str,
    kind: Kind,
    sh_type: u32,
    flags: u64,
    offset: u64,
    addr: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
    name_off: u32,
}

const NULL_SECTION: Section = Section {
    name: "",
    kind: Kind::Null,
    sh_type: 0,
    flags: 0,
    offset: 0,
    addr: 0,
    size: 0,
    link: 0,
    info: 0,
    align: 0,
    entsize: 0,
    name_off: 0,
};

impl Section {
    fn end(&self) -> u64 {
        self.offset + self.size
    }

    fn has_file_bytes(&self) -> bool {
        self.kind != Kind::Null && self.sh_type != SHT_NOBITS && self.size > 0
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Phdr {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// The fields of a recorded header the layout is built from.
#[derive(Debug, Clone, Copy)]
struct Header {
    exec: bool,
    entry: u64,
    shoff: u64,
    phnum: usize,
    shnum: usize,
}

fn le16(bytes: &[u8; ELF_HEADER_LEN], at: usize) -> u64 {
    u64::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn le64(bytes: &[u8; ELF_HEADER_LEN], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// The header as the generator needs it, when it is a 64-bit little-endian x86-64 executable
/// whose tables fit the file.
fn parse_header(header: &[u8; ELF_HEADER_LEN], len: u64) -> Option<Header> {
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return None;
    }
    let e_type = le16(header, 16);
    if le16(header, 18) != 0x3e || !(e_type == 2 || e_type == 3) {
        return None;
    }
    if le64(header, 32) != 64
        || le16(header, 52) != 64
        || le16(header, 54) != PHDR_SIZE
        || le16(header, 58) != SHDR_SIZE
    {
        return None;
    }
    let phnum = le16(header, 56);
    let shnum = le16(header, 60);
    let shstrndx = le16(header, 62);
    let shoff = le64(header, 40);
    if len > 1 << 36 || shnum == 0 || shstrndx != shnum - 1 || !shoff.is_multiple_of(8) {
        return None;
    }
    if shoff.checked_add(shnum * SHDR_SIZE)? > len {
        return None;
    }
    let exec = e_type == 2;
    let entry = le64(header, 24).checked_sub(if exec { EXEC_BASE } else { 0 })?;
    if entry >= shoff {
        return None;
    }
    Some(Header {
        exec,
        entry,
        shoff,
        phnum: usize::try_from(phnum).ok()?,
        shnum: usize::try_from(shnum).ok()?,
    })
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align) * align
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value / align * align
    }
}

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A deterministic 64-bit draw for `(seed, tag, index)`.
fn draw(seed: u64, tag: u64, index: u64) -> u64 {
    mix(seed ^ mix(tag.wrapping_mul(0xA24B_AED4_963E_E407) ^ index))
}

fn fnv_seed(bytes: impl Iterator<Item = u8>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    mix(hash)
}

/// One number per image: what makes two binaries differ in every generated byte.
fn image_seed(image: &ElfImage) -> u64 {
    fnv_seed(
        image
            .name
            .bytes()
            .chain(image.len.to_le_bytes())
            .chain(image.header.iter().copied()),
    )
}

/// The SysV ELF hash `vna_hash` carries.
fn elf_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in name.bytes() {
        hash = (hash << 4).wrapping_add(u32::from(byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

/// Byte `at` of a little-endian record given as `(value, width)` fields, widths 1 to 8.
fn record_byte(fields: &[(u64, u64)], mut at: u64) -> u8 {
    for &(value, width) in fields {
        if at < width {
            return value.to_le_bytes()[usize::try_from(at).unwrap_or(0)];
        }
        at -= width;
    }
    0
}

/// Byte `at` of `bytes`, zero past its end.
fn byte_of(bytes: &[u8], at: u64) -> u8 {
    usize::try_from(at)
        .ok()
        .and_then(|at| bytes.get(at))
        .copied()
        .unwrap_or(0)
}

/// Byte `at` of the strings in `parts` laid end to end, each followed by a NUL; `None` past them.
fn strings_byte<'a>(parts: impl IntoIterator<Item = &'a str>, mut at: u64) -> Option<u8> {
    for part in parts {
        let len = part.len() as u64 + 1;
        if at < len {
            return Some(byte_of(part.as_bytes(), at));
        }
        at -= len;
    }
    None
}

/// Program and section structure for one image, built once and read per byte.
#[derive(Debug, Clone)]
pub struct Layout {
    seed: u64,
    name: &'static str,
    exec: bool,
    entry: u64,
    phoff_end: u64,
    shoff: u64,
    sections: [Section; MAX_SECTIONS],
    nsec: usize,
    phdrs: [Phdr; MAX_PHDRS],
    nph: usize,
    cursor: u64,
    vdelta: u64,
    /// Window of [`POOL`] imported: its start and length.
    win_start: usize,
    nwin: usize,
    /// Bit `v` set when `VERSIONS[v]` is needed.
    versions: u16,
    sym_name_off: [u32; MAX_SYMS + 1],
    libc_off: u64,
    version_off: [u32; VERSIONS.len()],
    relro_ptrs: u64,
    /// `.data` is big enough for `__dso_handle`, which a RELATIVE relocation then names.
    dso_handle: bool,
    text: (u64, u64),
    rodata: (u64, u64),
    strings_len: u64,
    eh_count: u64,
    eh_step: u64,
    idx: Indices,
}

/// Where the sections other sections refer to ended up (0 when absent).
#[derive(Debug, Clone, Copy, Default)]
struct Indices {
    dynsym: usize,
    dynstr: usize,
    got: usize,
    gotplt: usize,
    plt: usize,
    init: usize,
    fini: usize,
    init_array: usize,
    fini_array: usize,
    relro: usize,
    dynamic: usize,
    data: usize,
    gnu_hash: usize,
    versym: usize,
    verneed: usize,
    rela_dyn: usize,
    rela_plt: usize,
    eh_frame: usize,
    eh_frame_hdr: usize,
    build_id: usize,
}

impl Layout {
    fn new(seed: u64, name: &'static str, header: &Header) -> Self {
        let mut layout = Self {
            seed,
            name,
            exec: header.exec,
            entry: header.entry,
            phoff_end: 64 + header.phnum as u64 * PHDR_SIZE,
            shoff: header.shoff,
            sections: [NULL_SECTION; MAX_SECTIONS],
            nsec: 1,
            phdrs: [Phdr::default(); MAX_PHDRS],
            nph: 0,
            cursor: 64 + header.phnum as u64 * PHDR_SIZE,
            vdelta: if header.exec { EXEC_BASE } else { 0 },
            win_start: 0,
            nwin: 0,
            versions: 0,
            sym_name_off: [0; MAX_SYMS + 1],
            libc_off: 0,
            version_off: [0; VERSIONS.len()],
            relro_ptrs: 0,
            dso_handle: false,
            text: (0, 0),
            rodata: (0, 0),
            strings_len: 0,
            eh_count: 0,
            eh_step: 16,
            idx: Indices::default(),
        };
        layout.strings_len = layout.rodata_strings().map(|s| s.len() as u64 + 1).sum();
        layout
    }

    fn base(&self) -> u64 {
        if self.exec { EXEC_BASE } else { 0 }
    }

    /// Append a section at the cursor, aligned, and move the cursor past it.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        name: &'static str,
        kind: Kind,
        sh_type: u32,
        flags: u64,
        align: u64,
        size: u64,
        entsize: u64,
    ) -> usize {
        let offset = align_up(self.cursor, align);
        self.place(name, kind, sh_type, flags, align, offset, size, entsize)
    }

    /// Append a section at `offset`.
    #[allow(clippy::too_many_arguments)]
    fn place(
        &mut self,
        name: &'static str,
        kind: Kind,
        sh_type: u32,
        flags: u64,
        align: u64,
        offset: u64,
        size: u64,
        entsize: u64,
    ) -> usize {
        let index = self.nsec;
        let addr = if flags & SHF_ALLOC != 0 {
            offset + self.vdelta
        } else {
            0
        };
        if let Some(slot) = self.sections.get_mut(index) {
            *slot = Section {
                name,
                kind,
                sh_type,
                flags,
                offset,
                addr,
                size,
                link: 0,
                info: 0,
                align,
                entsize,
                name_off: 0,
            };
            self.nsec += 1;
        }
        if sh_type != SHT_NOBITS {
            self.cursor = offset + size;
        }
        index
    }

    fn section(&self, index: usize) -> &Section {
        self.sections.get(index).unwrap_or(&NULL_SECTION)
    }

    fn vaddr(&self, index: usize) -> u64 {
        self.section(index).addr
    }

    fn phdr(
        &mut self,
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        size: (u64, u64),
        align: u64,
    ) {
        if let Some(slot) = self.phdrs.get_mut(self.nph) {
            *slot = Phdr {
                p_type,
                flags,
                offset,
                vaddr,
                filesz: size.0,
                memsz: size.1,
                align,
            };
            self.nph += 1;
        }
    }

    fn segment_of(&mut self, p_type: u32, flags: u32, first: usize, last: usize, align: u64) {
        let (start, end_file, end_mem) = {
            let first = self.section(first);
            let last = self.section(last);
            let end_file = if last.sh_type == SHT_NOBITS {
                last.offset
            } else {
                last.end()
            };
            (*first, end_file, last.addr + last.size)
        };
        self.phdr(
            p_type,
            flags,
            start.offset,
            start.addr,
            (end_file - start.offset, end_mem - start.addr),
            align,
        );
    }

    fn sym_count(&self) -> usize {
        ALWAYS.len() + self.nwin
    }

    /// Name and version of `.dynsym` entry `k` (1-based).
    fn symbol(&self, k: usize) -> (&'static str, u8, u8) {
        if let Some(&(name, info, version)) = k.checked_sub(1).and_then(|i| ALWAYS.get(i)) {
            return (name, info, version);
        }
        let i = (self.win_start + k - 1 - ALWAYS.len()) % POOL.len();
        let (name, version) = POOL[i];
        (name, 0x12, version)
    }

    /// Fill in the symbol tables' bookkeeping for a window of `nwin` imports.
    fn choose_symbols(&mut self, nwin: usize) {
        self.nwin = nwin.min(POOL.len());
        self.win_start = usize::try_from(self.seed % POOL.len() as u64).unwrap_or(0);
        self.versions = 0;
        let mut off: u64 = 1;
        for k in 1..=self.sym_count() {
            let (name, _, version) = self.symbol(k);
            self.sym_name_off[k] = u32::try_from(off).unwrap_or(0);
            off += name.len() as u64 + 1;
            if version != UNVERSIONED {
                self.versions |= 1 << version;
            }
        }
        self.libc_off = off;
        off += LIBC.len() as u64;
        for (v, name) in VERSIONS.iter().enumerate() {
            if self.versions & (1 << v) != 0 {
                self.version_off[v] = u32::try_from(off).unwrap_or(0);
                off += name.len() as u64 + 1;
            }
        }
        self.sym_name_off[0] = u32::try_from(off).unwrap_or(0);
    }

    fn dynstr_len(&self) -> u64 {
        u64::from(self.sym_name_off[0])
    }

    fn version_count(&self) -> u64 {
        u64::from(self.versions.count_ones())
    }

    /// `vna_other` of version `v`: 2 and up, in [`VERSIONS`] order among those needed.
    fn version_index(&self, v: u8) -> u64 {
        if v == UNVERSIONED {
            return 1;
        }
        2 + u64::from((self.versions & ((1u16 << v) - 1)).count_ones())
    }

    fn nplt(&self) -> u64 {
        1 + self.nwin as u64
    }

    /// RELATIVE relocations: `.init_array`, `.fini_array`, the `.data.rel.ro` pointers and,
    /// when `.data` holds it, `__dso_handle`.
    fn relative_count(&self) -> u64 {
        2 + self.relro_ptrs + u64::from(self.dso_handle)
    }

    fn rodata_strings(&self) -> impl Iterator<Item = &'static str> {
        let name = self.name;
        let (usage, group): (Option<&'static str>, &'static [&'static str]) = if name == "busybox" {
            (None, &BUSYBOX_STRINGS)
        } else if COREUTILS.contains(&name) {
            (usage_line(name), &COREUTILS_STRINGS)
        } else {
            (usage_line(name), &OTHER_STRINGS)
        };
        usage.into_iter().chain(group.iter().copied())
    }

    fn shstrtab_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.sections[1..self.nsec].iter().map(|s| s.name)
    }

    /// Name offsets for every section, and `.shstrtab`'s own size.
    fn finish_names(&mut self) -> u64 {
        let mut off: u64 = 1;
        for i in 1..self.nsec {
            self.sections[i].name_off = u32::try_from(off).unwrap_or(0);
            off += self.sections[i].name.len() as u64 + 1;
        }
        off
    }
}

/// The section names of a layout, in order, before it is placed: `.shstrtab` must be sized first
/// because it sits just below the section headers.
fn shstrtab_len(names: &[&str]) -> u64 {
    1 + names.iter().map(|n| n.len() as u64 + 1).sum::<u64>()
}

/// What the dynamic (PIE) layout includes beyond the 29 sections every one has.
#[derive(Debug, Clone, Copy)]
struct Extras {
    plt_got: bool,
    alt_link: bool,
    except: bool,
    comment: bool,
    tdata: bool,
    tbss: bool,
}

impl Extras {
    fn for_count(shnum: usize) -> Option<Self> {
        if !(29..=35).contains(&shnum) {
            return None;
        }
        let n = shnum - 29;
        Some(Self {
            plt_got: n >= 1,
            alt_link: n >= 2,
            except: n >= 3,
            comment: n >= 4,
            tdata: n >= 5,
            tbss: n >= 6,
        })
    }

    fn names(&self) -> Vec<&'static str> {
        let mut names = vec![
            ".interp",
            ".note.gnu.property",
            ".note.gnu.build-id",
            ".note.ABI-tag",
            ".gnu.hash",
            ".dynsym",
            ".dynstr",
            ".gnu.version",
            ".gnu.version_r",
            ".rela.dyn",
            ".rela.plt",
            ".init",
            ".plt",
        ];
        if self.plt_got {
            names.push(".plt.got");
        }
        names.extend([
            ".plt.sec",
            ".text",
            ".fini",
            ".rodata",
            ".eh_frame_hdr",
            ".eh_frame",
        ]);
        if self.except {
            names.push(".gcc_except_table");
        }
        if self.tdata {
            names.push(".tdata");
        }
        if self.tbss {
            names.push(".tbss");
        }
        names.extend([
            ".init_array",
            ".fini_array",
            ".data.rel.ro",
            ".dynamic",
            ".got",
            ".data",
            ".bss",
        ]);
        if self.comment {
            names.push(".comment");
        }
        if self.alt_link {
            names.push(".gnu_debugaltlink");
        }
        names.extend([".gnu_debuglink", ".shstrtab"]);
        names
    }
}

const DEBUGLINK_SIZE: u64 = 0x34;

/// How many words of `.data.rel.ro` are relocated pointers: more for a bigger program, few
/// enough that a small one's relocations stay inside its first page.
fn relro_pointers(relro_size: u64, len: u64) -> u64 {
    (relro_size / 8).min(8 + len / 4096).min(256)
}

fn alt_link_path(name: &str) -> &'static str {
    if COREUTILS.contains(&name) {
        "/usr/lib/debug/.dwz/x86_64-linux-gnu/coreutils.debug"
    } else {
        "/usr/lib/debug/.dwz/x86_64-linux-gnu/common.debug"
    }
}

fn alt_link_size(name: &str) -> u64 {
    align_up(alt_link_path(name).len() as u64 + 1, 4) + 20
}

/// The dynamic, position-independent layout every recorded binary but busybox has.
fn pie_layout(
    seed: u64,
    name: &'static str,
    header: &Header,
    len: u64,
    nwin: usize,
) -> Option<Layout> {
    if !(13..=14).contains(&header.phnum) {
        return None;
    }
    let extras = Extras::for_count(header.shnum)?;
    let mut l = Layout::new(seed, name, header);
    l.choose_symbols(nwin);
    let nsym = l.sym_count() as u64;
    let nplt = l.nplt();
    let relro_size = align_down((len / 64).clamp(0x20, 0x8000), 32);
    l.relro_ptrs = relro_pointers(relro_size, len);

    // From the section headers down: the non-allocated tail, then the writable segment, whose
    // read-only-after-relocation part ends on a page boundary as `-z relro` leaves it.
    let names = extras.names();
    let shstr_len = shstrtab_len(&names);
    let dbg_off = align_down(header.shoff.checked_sub(shstr_len + DEBUGLINK_SIZE)?, 4);
    let alt_off = if extras.alt_link {
        align_down(dbg_off.checked_sub(alt_link_size(name))?, 4)
    } else {
        dbg_off
    };
    let comment_off = if extras.comment {
        alt_off.checked_sub(COMMENT.len() as u64)?
    } else {
        alt_off
    };
    let data_end = comment_off;
    // `.data` starts on the boundary and runs to the tail: at least 4 bytes, so a small binary's
    // tail a few bytes past a page does not push the whole writable segment a page down. Only a
    // `.data` of 16 bytes or more holds `__dso_handle`, and with it the RELATIVE naming it.
    let boundary = align_down(data_end.checked_sub(4)?, PAGE);
    l.dso_handle = data_end - boundary >= 16;
    let nrelative = l.relative_count();

    // Read-only head: what the loader reads before any code.
    let interp = l.add(
        ".interp",
        Kind::Interp,
        SHT_PROGBITS,
        SHF_ALLOC,
        1,
        INTERP.len() as u64,
        0,
    );
    let prop = l.add(
        ".note.gnu.property",
        Kind::NoteProperty,
        SHT_NOTE,
        SHF_ALLOC,
        8,
        0x30,
        0,
    );
    l.idx.build_id = l.add(
        ".note.gnu.build-id",
        Kind::NoteBuildId,
        SHT_NOTE,
        SHF_ALLOC,
        4,
        0x24,
        0,
    );
    let abi = l.add(
        ".note.ABI-tag",
        Kind::NoteAbiTag,
        SHT_NOTE,
        SHF_ALLOC,
        4,
        0x20,
        0,
    );
    l.idx.gnu_hash = l.add(
        ".gnu.hash",
        Kind::GnuHash,
        SHT_GNU_HASH,
        SHF_ALLOC,
        8,
        0x1c,
        0,
    );
    l.idx.dynsym = l.add(
        ".dynsym",
        Kind::Dynsym,
        SHT_DYNSYM,
        SHF_ALLOC,
        8,
        24 * (nsym + 1),
        24,
    );
    let dynstr_len = l.dynstr_len();
    l.idx.dynstr = l.add(
        ".dynstr",
        Kind::Dynstr,
        SHT_STRTAB,
        SHF_ALLOC,
        1,
        dynstr_len,
        0,
    );
    l.idx.versym = l.add(
        ".gnu.version",
        Kind::Versym,
        SHT_GNU_VERSYM,
        SHF_ALLOC,
        2,
        2 * (nsym + 1),
        2,
    );
    let verneed_size = 16 + 16 * l.version_count();
    l.idx.verneed = l.add(
        ".gnu.version_r",
        Kind::Verneed,
        SHT_GNU_VERNEED,
        SHF_ALLOC,
        8,
        verneed_size,
        0,
    );
    l.idx.rela_dyn = l.add(
        ".rela.dyn",
        Kind::RelaDyn,
        SHT_RELA,
        SHF_ALLOC,
        8,
        24 * (nrelative + 5),
        24,
    );
    l.idx.rela_plt = l.add(
        ".rela.plt",
        Kind::RelaPlt,
        SHT_RELA,
        SHF_ALLOC | SHF_INFO_LINK,
        8,
        24 * nplt,
        24,
    );
    let head_end = l.cursor;

    // Code.
    l.cursor = align_up(head_end, PAGE);
    l.idx.init = l.add(
        ".init",
        Kind::Init,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        4,
        0x1b,
        0,
    );
    l.idx.plt = l.add(
        ".plt",
        Kind::Plt,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        16,
        16 * (nplt + 1),
        16,
    );
    if extras.plt_got {
        l.add(
            ".plt.got",
            Kind::PltGot,
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            16,
            16,
            16,
        );
    }
    l.add(
        ".plt.sec",
        Kind::PltSec,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        16,
        16 * nplt,
        16,
    );
    let text_start = align_up(l.cursor, 16);
    if text_start > header.entry {
        return None;
    }

    let got_size = 8 * (3 + nplt + 5);
    let got_off = boundary.checked_sub(got_size)?;
    let dyn_off = got_off.checked_sub(DYNAMIC_ENTRIES * 16)?;
    let relro_off = align_down(dyn_off.checked_sub(relro_size)?, 32);
    let fini_off = relro_off.checked_sub(8)?;
    let init_off = fini_off.checked_sub(8)?;
    let tdata_size = if extras.tdata { 0x10 } else { 0 };
    let w0 = align_down(init_off.checked_sub(tdata_size)?, 8);

    // Code and read-only data share what is left.
    let r_end = align_down(w0.checked_sub(0x10 + (seed >> 8) % 0x100)?, 8);
    let span = r_end.checked_sub(text_start)?;
    let mut text_end =
        align_up(text_start + span * 62 / 100, 16).max(align_up(header.entry + 0x40, 16));
    let min_rodata = 0x200 + l.strings_len;
    let r0_max = align_down(r_end.checked_sub(min_rodata)?, PAGE);
    if align_up(text_end + 0x20, PAGE) > r0_max {
        text_end = r0_max.checked_sub(0x20)?;
    }
    if text_end <= header.entry + 0x10 {
        return None;
    }
    l.place(
        ".text",
        Kind::Code,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        16,
        text_start,
        text_end - text_start,
        0,
    );
    l.idx.fini = l.add(
        ".fini",
        Kind::Fini,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        4,
        0xd,
        0,
    );
    l.text = (text_start, text_end);
    let rx_end = l.cursor;

    let r0 = align_up(rx_end, PAGE);
    let r_span = r_end.checked_sub(r0)?;
    let text_len = text_end - text_start;
    l.eh_count = (text_len / 0x200).clamp(2, (r_span / 3 / 40).max(2));
    l.eh_step = align_down(text_len / l.eh_count, 16).max(16);
    let eh_hdr_size = 12 + 8 * l.eh_count;
    let eh_size = 0x18 + 0x20 * l.eh_count + 4;
    let except_size = if extras.except {
        align_down((r_span / 40).clamp(0x10, 0x2000), 4)
    } else {
        0
    };
    let rodata_size = r_span.checked_sub(eh_hdr_size + eh_size + except_size + 32)?;
    if rodata_size < 0x40 {
        return None;
    }
    l.cursor = r0;
    let rodata = l.add(
        ".rodata",
        Kind::Rodata,
        SHT_PROGBITS,
        SHF_ALLOC,
        32,
        rodata_size,
        0,
    );
    l.rodata = (r0, r0 + rodata_size);
    l.idx.eh_frame_hdr = l.add(
        ".eh_frame_hdr",
        Kind::EhFrameHdr,
        SHT_PROGBITS,
        SHF_ALLOC,
        4,
        eh_hdr_size,
        0,
    );
    l.idx.eh_frame = l.add(
        ".eh_frame",
        Kind::EhFrame,
        SHT_PROGBITS,
        SHF_ALLOC,
        8,
        eh_size,
        0,
    );
    let mut r_last = l.idx.eh_frame;
    if extras.except {
        r_last = l.add(
            ".gcc_except_table",
            Kind::Data,
            SHT_PROGBITS,
            SHF_ALLOC,
            4,
            except_size,
            0,
        );
    }
    if l.cursor > r_end {
        return None;
    }

    // Writable segment, a page further on in memory.
    l.vdelta = PAGE;
    let mut tls = None;
    if extras.tdata {
        let tdata = l.place(
            ".tdata",
            Kind::Data,
            SHT_PROGBITS,
            SHF_WRITE | SHF_ALLOC | SHF_TLS,
            8,
            w0,
            tdata_size,
            0,
        );
        let tbss = if extras.tbss {
            l.place(
                ".tbss",
                Kind::NoBits,
                SHT_NOBITS,
                SHF_WRITE | SHF_ALLOC | SHF_TLS,
                8,
                w0 + tdata_size,
                8,
                0,
            )
        } else {
            tdata
        };
        tls = Some((tdata, tbss));
    }
    l.idx.init_array = l.place(
        ".init_array",
        Kind::InitArray,
        SHT_INIT_ARRAY,
        SHF_WRITE | SHF_ALLOC,
        8,
        init_off,
        8,
        8,
    );
    l.idx.fini_array = l.place(
        ".fini_array",
        Kind::FiniArray,
        SHT_FINI_ARRAY,
        SHF_WRITE | SHF_ALLOC,
        8,
        fini_off,
        8,
        8,
    );
    l.idx.relro = l.place(
        ".data.rel.ro",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        32,
        relro_off,
        dyn_off - relro_off,
        0,
    );
    l.idx.dynamic = l.place(
        ".dynamic",
        Kind::Dynamic,
        SHT_DYNAMIC,
        SHF_WRITE | SHF_ALLOC,
        8,
        dyn_off,
        DYNAMIC_ENTRIES * 16,
        16,
    );
    l.idx.got = l.place(
        ".got",
        Kind::Got,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        got_off,
        got_size,
        8,
    );
    l.idx.data = l.place(
        ".data",
        Kind::Data,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        boundary,
        data_end - boundary,
        0,
    );
    let bss_size = align_up((len / 50).clamp(0x8, 0x10000), 8);
    let bss_off = data_end;
    let bss = {
        let index = l.place(
            ".bss",
            Kind::NoBits,
            SHT_NOBITS,
            SHF_WRITE | SHF_ALLOC,
            32,
            bss_off,
            bss_size,
            0,
        );
        let addr = align_up(bss_off + PAGE, 32);
        l.sections[index].addr = addr;
        index
    };

    // Non-allocated tail.
    l.vdelta = 0;
    if extras.comment {
        l.place(
            ".comment",
            Kind::Comment,
            SHT_PROGBITS,
            SHF_MERGE | SHF_STRINGS,
            1,
            comment_off,
            COMMENT.len() as u64,
            1,
        );
    }
    if extras.alt_link {
        l.place(
            ".gnu_debugaltlink",
            Kind::DebugAltLink,
            SHT_PROGBITS,
            0,
            4,
            alt_off,
            alt_link_size(name),
            0,
        );
    }
    l.place(
        ".gnu_debuglink",
        Kind::DebugLink,
        SHT_PROGBITS,
        0,
        4,
        dbg_off,
        DEBUGLINK_SIZE,
        0,
    );
    l.place(
        ".shstrtab",
        Kind::Shstrtab,
        SHT_STRTAB,
        0,
        1,
        dbg_off + DEBUGLINK_SIZE,
        shstr_len,
        0,
    );
    if l.nsec != header.shnum || l.finish_names() != shstr_len || l.cursor > header.shoff {
        return None;
    }

    // Links between sections.
    let idx = l.idx;
    for (index, link, info) in [
        (idx.gnu_hash, idx.dynsym, 0),
        (idx.dynsym, idx.dynstr, 1),
        (idx.versym, idx.dynsym, 0),
        (idx.verneed, idx.dynstr, 1),
        (idx.rela_dyn, idx.dynsym, 0),
        (idx.rela_plt, idx.dynsym, idx.got),
        (idx.dynamic, idx.dynstr, 0),
    ] {
        l.sections[index].link = u32::try_from(link).unwrap_or(0);
        l.sections[index].info = u32::try_from(info).unwrap_or(0);
    }

    // Program headers, in the order `ld` writes them.
    let phdr_size = header.phnum as u64 * PHDR_SIZE;
    l.phdr(PT_PHDR, PF_R, 64, 64, (phdr_size, phdr_size), 8);
    let interp_off = l.section(interp).offset;
    l.phdr(
        PT_INTERP,
        PF_R,
        interp_off,
        interp_off,
        (INTERP.len() as u64, INTERP.len() as u64),
        1,
    );
    l.phdr(PT_LOAD, PF_R, 0, 0, (head_end, head_end), PAGE);
    l.segment_of(PT_LOAD, PF_R | PF_X, l.idx.init, l.idx.fini, PAGE);
    l.segment_of(PT_LOAD, PF_R, rodata, r_last, PAGE);
    let first_rw = tls.map_or(l.idx.init_array, |(tdata, _)| tdata);
    l.segment_of(PT_LOAD, PF_R | PF_W, first_rw, bss, PAGE);
    l.segment_of(PT_DYNAMIC, PF_R | PF_W, l.idx.dynamic, l.idx.dynamic, 8);
    l.segment_of(PT_NOTE, PF_R, prop, prop, 8);
    l.segment_of(PT_NOTE, PF_R, l.idx.build_id, abi, 4);
    if header.phnum == 14 {
        match tls {
            Some((tdata, tbss)) => l.segment_of(PT_TLS, PF_R, tdata, tbss, 8),
            None => l.phdr(PT_TLS, PF_R, w0, w0 + PAGE, (0, 0), 8),
        }
    }
    l.segment_of(PT_GNU_PROPERTY, PF_R, prop, prop, 8);
    l.segment_of(
        PT_GNU_EH_FRAME,
        PF_R,
        l.idx.eh_frame_hdr,
        l.idx.eh_frame_hdr,
        4,
    );
    l.phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, (0, 0), 16);
    let relro_len = boundary - w0;
    l.phdr(PT_GNU_RELRO, PF_R, w0, w0 + PAGE, (relro_len, relro_len), 1);
    (l.nph == header.phnum).then_some(l)
}

const STATIC_NAMES: [&str; 28] = [
    ".note.gnu.property",
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".rela.plt",
    ".init",
    ".plt",
    ".text",
    "__libc_freeres_fn",
    ".fini",
    ".rodata",
    ".stapsdt.base",
    ".eh_frame",
    ".gcc_except_table",
    ".tdata",
    ".tbss",
    ".init_array",
    ".fini_array",
    ".data.rel.ro",
    ".got",
    ".got.plt",
    ".data",
    "__libc_subfreeres",
    "__libc_IO_vtables",
    "__libc_atexit",
    ".bss",
    "__libc_freeres_ptrs",
    ".comment",
    ".shstrtab",
];

/// Indirect-function relocations a static glibc binary carries in `.rela.plt`.
const IRELATIVE_COUNT: u64 = 24;

/// The static `ET_EXEC` layout of a glibc program linked with `-static`.
fn static_layout(seed: u64, name: &'static str, header: &Header, len: u64) -> Option<Layout> {
    if header.phnum != 10 || header.shnum != STATIC_NAMES.len() + 1 {
        return None;
    }
    let mut l = Layout::new(seed, name, header);
    let k = IRELATIVE_COUNT;
    let relro_size = align_down((len / 64).clamp(0x20, 0x8000), 32);
    l.relro_ptrs = relro_pointers(relro_size, len);

    let prop = l.add(
        ".note.gnu.property",
        Kind::NoteProperty,
        SHT_NOTE,
        SHF_ALLOC,
        8,
        0x30,
        0,
    );
    l.idx.build_id = l.add(
        ".note.gnu.build-id",
        Kind::NoteBuildId,
        SHT_NOTE,
        SHF_ALLOC,
        4,
        0x24,
        0,
    );
    let abi = l.add(
        ".note.ABI-tag",
        Kind::NoteAbiTag,
        SHT_NOTE,
        SHF_ALLOC,
        4,
        0x20,
        0,
    );
    l.idx.rela_plt = l.add(
        ".rela.plt",
        Kind::IRelaPlt,
        SHT_RELA,
        SHF_ALLOC | SHF_INFO_LINK,
        8,
        24 * k,
        24,
    );
    let head_end = l.cursor;
    l.cursor = align_up(head_end, PAGE);
    l.idx.init = l.add(
        ".init",
        Kind::Init,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        4,
        0x1b,
        0,
    );
    l.idx.plt = l.add(
        ".plt",
        Kind::PltSec,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        16,
        16 * k,
        16,
    );
    let text_start = align_up(l.cursor, 64);
    if text_start > header.entry {
        return None;
    }

    let shstr_len = shstrtab_len(&STATIC_NAMES);
    let shstr_off = header.shoff.checked_sub(shstr_len)?;
    let comment_off = shstr_off.checked_sub(COMMENT.len() as u64)?;
    let data_end = comment_off;
    let atexit_off = align_down(data_end.checked_sub(8)?, 8);
    let vtables_off = align_down(atexit_off.checked_sub(0x768)?, 32);
    let subfree_off = align_down(vtables_off.checked_sub(0x48)?, 8);
    let gotplt_size = 0x18 + 8 * k;
    let boundary = align_down(subfree_off.checked_sub(gotplt_size + 0x40)?, PAGE);
    let data_off = align_up(boundary + gotplt_size, 32);
    let got_size = 0xe8;
    let got_off = boundary.checked_sub(got_size)?;
    let relro_off = align_down(got_off.checked_sub(relro_size)?, 32);
    let fini_off = relro_off.checked_sub(8)?;
    let init_off = fini_off.checked_sub(0x10)?;
    let tdata_size = 0x20;
    let w0 = align_down(init_off.checked_sub(tdata_size)?, 8);

    let r_end = align_down(w0.checked_sub(0x10 + (seed >> 8) % 0x100)?, 8);
    let freeres_size = align_down((len / 400).clamp(0x400, 0x2000), 16);
    let span = r_end.checked_sub(text_start)?;
    let mut text_end =
        align_up(text_start + span * 62 / 100, 64).max(align_up(header.entry + 0x40, 64));
    let r0_max = align_down(r_end.checked_sub(0x200 + l.strings_len)?, PAGE);
    if align_up(text_end + freeres_size + 0x40, PAGE) > r0_max {
        text_end = r0_max.checked_sub(freeres_size + 0x40)?;
    }
    if text_end <= header.entry + 0x10 {
        return None;
    }
    l.place(
        ".text",
        Kind::Code,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        64,
        text_start,
        text_end - text_start,
        0,
    );
    l.add(
        "__libc_freeres_fn",
        Kind::Code,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        16,
        freeres_size,
        0,
    );
    l.idx.fini = l.add(
        ".fini",
        Kind::Fini,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        4,
        0xd,
        0,
    );
    l.text = (text_start, text_end);

    let r0 = align_up(l.cursor, PAGE);
    let r_span = r_end.checked_sub(r0)?;
    let text_len = text_end - text_start;
    l.eh_count = (text_len / 0x200).clamp(2, (r_span / 3 / 40).max(2));
    l.eh_step = align_down(text_len / l.eh_count, 16).max(16);
    let eh_size = 0x18 + 0x20 * l.eh_count + 4;
    let except_size = align_down((r_span / 40).clamp(0x10, 0x2000), 4);
    let rodata_size = r_span.checked_sub(eh_size + except_size + 1 + 32)?;
    l.cursor = r0;
    let rodata = l.add(
        ".rodata",
        Kind::Rodata,
        SHT_PROGBITS,
        SHF_ALLOC,
        32,
        rodata_size,
        0,
    );
    l.rodata = (r0, r0 + rodata_size);
    l.add(
        ".stapsdt.base",
        Kind::Data,
        SHT_PROGBITS,
        SHF_ALLOC,
        1,
        1,
        0,
    );
    l.idx.eh_frame = l.add(
        ".eh_frame",
        Kind::EhFrame,
        SHT_PROGBITS,
        SHF_ALLOC,
        8,
        eh_size,
        0,
    );
    let except = l.add(
        ".gcc_except_table",
        Kind::Data,
        SHT_PROGBITS,
        SHF_ALLOC,
        4,
        except_size,
        0,
    );
    if l.cursor > r_end {
        return None;
    }

    l.vdelta = EXEC_BASE + PAGE;
    let tdata = l.place(
        ".tdata",
        Kind::Data,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC | SHF_TLS,
        8,
        w0,
        tdata_size,
        0,
    );
    let tbss = l.place(
        ".tbss",
        Kind::NoBits,
        SHT_NOBITS,
        SHF_WRITE | SHF_ALLOC | SHF_TLS,
        8,
        init_off,
        0x40,
        0,
    );
    l.sections[tbss].addr = w0 + tdata_size + l.vdelta;
    l.idx.init_array = l.place(
        ".init_array",
        Kind::InitArray,
        SHT_INIT_ARRAY,
        SHF_WRITE | SHF_ALLOC,
        8,
        init_off,
        0x10,
        8,
    );
    l.idx.fini_array = l.place(
        ".fini_array",
        Kind::FiniArray,
        SHT_FINI_ARRAY,
        SHF_WRITE | SHF_ALLOC,
        8,
        fini_off,
        8,
        8,
    );
    l.idx.relro = l.place(
        ".data.rel.ro",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        32,
        relro_off,
        got_off - relro_off,
        0,
    );
    l.idx.got = l.place(
        ".got",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        got_off,
        got_size,
        8,
    );
    l.idx.gotplt = l.place(
        ".got.plt",
        Kind::GotPlt,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        boundary,
        gotplt_size,
        8,
    );
    l.idx.data = l.place(
        ".data",
        Kind::Data,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        32,
        data_off,
        subfree_off.checked_sub(data_off)?,
        0,
    );
    l.place(
        "__libc_subfreeres",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        subfree_off,
        0x48,
        0,
    );
    l.place(
        "__libc_IO_vtables",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        32,
        vtables_off,
        0x768,
        0,
    );
    l.place(
        "__libc_atexit",
        Kind::RelRo,
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        atexit_off,
        8,
        0,
    );
    let bss_size = align_up((len / 50).clamp(0x8, 0x10000), 8);
    let bss_addr = align_up(atexit_off + 8 + l.vdelta, 32);
    let bss = l.place(
        ".bss",
        Kind::NoBits,
        SHT_NOBITS,
        SHF_WRITE | SHF_ALLOC,
        32,
        atexit_off + 8,
        bss_size,
        0,
    );
    l.sections[bss].addr = bss_addr;
    let ptrs = l.place(
        "__libc_freeres_ptrs",
        Kind::NoBits,
        SHT_NOBITS,
        SHF_WRITE | SHF_ALLOC,
        8,
        atexit_off + 8,
        0x20,
        0,
    );
    l.sections[ptrs].addr = bss_addr + bss_size;

    l.vdelta = 0;
    l.place(
        ".comment",
        Kind::Comment,
        SHT_PROGBITS,
        SHF_MERGE | SHF_STRINGS,
        1,
        comment_off,
        COMMENT.len() as u64,
        1,
    );
    l.place(
        ".shstrtab",
        Kind::Shstrtab,
        SHT_STRTAB,
        0,
        1,
        shstr_off,
        shstr_len,
        0,
    );
    if l.nsec != header.shnum || l.finish_names() != shstr_len || l.cursor > header.shoff {
        return None;
    }
    l.sections[l.idx.rela_plt].info = u32::try_from(l.idx.gotplt).unwrap_or(0);

    let base = EXEC_BASE;
    l.phdr(PT_LOAD, PF_R, 0, base, (head_end, head_end), PAGE);
    l.segment_of(PT_LOAD, PF_R | PF_X, l.idx.init, l.idx.fini, PAGE);
    l.segment_of(PT_LOAD, PF_R, rodata, except, PAGE);
    l.segment_of(PT_LOAD, PF_R | PF_W, tdata, ptrs, PAGE);
    l.segment_of(PT_NOTE, PF_R, prop, prop, 8);
    l.segment_of(PT_NOTE, PF_R, l.idx.build_id, abi, 4);
    l.segment_of(PT_TLS, PF_R, tdata, tbss, 8);
    l.segment_of(PT_GNU_PROPERTY, PF_R, prop, prop, 8);
    l.phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, (0, 0), 16);
    let relro_len = boundary - w0;
    let w0_addr = w0 + base + PAGE;
    l.phdr(PT_GNU_RELRO, PF_R, w0, w0_addr, (relro_len, relro_len), 1);
    (l.nph == header.phnum).then_some(l)
}

/// How many imports an image of `len` bytes asks for before the layout has to fit them.
fn wanted_imports(len: u64) -> usize {
    usize::try_from((len / 1500).clamp(20, 120)).unwrap_or(20)
}

/// What a body is: a layout, or the filler a header without one keeps.
#[derive(Debug, Clone)]
enum Shape {
    Filler,
    Elf(Box<Layout>),
}

/// The generated content of one [`ElfImage`], ready to read a byte at a time.
#[derive(Debug, Clone)]
pub struct ElfBody {
    header: [u8; ELF_HEADER_LEN],
    len: u64,
    newline_at: Option<u64>,
    /// The plant of last resort: a newline written over a layout that has none at `newline_at`.
    plant: Option<u64>,
    shape: Shape,
}

/// Per-scan state that lets sequential reads reuse an instruction bundle.
#[derive(Default)]
struct Cursor {
    bundle: Option<(u64, [u8; 16])>,
}

impl ElfBody {
    pub fn new(image: &ElfImage) -> Self {
        let mut body = Self {
            header: image.header,
            len: image.len,
            newline_at: image.newline_at,
            plant: None,
            shape: Shape::Filler,
        };
        let Some(header) = parse_header(&image.header, image.len) else {
            return body;
        };
        let seed = image_seed(image);
        if header.exec {
            if let Some(layout) = static_layout(seed, image.name, &header, image.len) {
                body.shape = Shape::Elf(Box::new(layout));
            }
            body.plant = body.newline_mismatch();
            return body;
        }
        let wanted = wanted_imports(image.len);
        let mut fallback = None;
        // Nearest counts first: wanted, wanted - 1, wanted + 1, ...
        for step in 0..=2 * POOL.len() {
            let delta = step.div_ceil(2);
            let nwin = if step % 2 == 1 {
                wanted.checked_sub(delta)
            } else {
                Some(wanted + delta)
            };
            let Some(nwin) = nwin.filter(|n| *n <= POOL.len()) else {
                continue;
            };
            let Some(layout) = pie_layout(seed, image.name, &header, image.len, nwin) else {
                continue;
            };
            body.shape = Shape::Elf(Box::new(layout));
            if body.newline_mismatch().is_none() {
                return body;
            }
            if fallback.is_none() {
                fallback = Some(body.shape.clone());
            }
            if body.newline_at.is_none() {
                return body;
            }
        }
        body.shape = fallback.unwrap_or(Shape::Filler);
        body.plant = body.newline_mismatch();
        body
    }

    /// `Some(newline_at)` when the unplanted layout does not put the image's first newline there.
    fn newline_mismatch(&self) -> Option<u64> {
        let at = self.newline_at?;
        if at < ELF_HEADER_LEN as u64 || at >= self.len {
            return None;
        }
        let mut cursor = Cursor::default();
        let clean = (0..at).all(|i| self.raw_byte(i, &mut cursor) != 0x0a);
        (!clean || self.raw_byte(at, &mut cursor) != 0x0a).then_some(at)
    }

    /// Whether the body is a generated layout rather than filler.
    pub fn is_structured(&self) -> bool {
        matches!(self.shape, Shape::Elf(_))
    }

    /// Whether a newline had to be planted over the layout.
    pub fn is_planted(&self) -> bool {
        self.plant.is_some()
    }

    /// Byte `index` of the file; meaningful for `index < len`.
    pub fn byte_at(&self, index: u64) -> u8 {
        self.byte(index, &mut Cursor::default())
    }

    /// Append the bytes at `[from, to)`.
    pub fn append_range(&self, from: u64, to: u64, out: &mut Vec<u8>) {
        let mut cursor = Cursor::default();
        out.extend((from..to).map(|i| self.byte(i, &mut cursor)));
    }

    fn byte(&self, index: u64, cursor: &mut Cursor) -> u8 {
        let raw = self.raw_byte(index, cursor);
        match self.plant {
            Some(at) if index == at => 0x0a,
            Some(at) if index < at && raw == 0x0a && index >= ELF_HEADER_LEN as u64 => 0x0b,
            _ => raw,
        }
    }

    fn raw_byte(&self, index: u64, cursor: &mut Cursor) -> u8 {
        if let Some(byte) = usize::try_from(index)
            .ok()
            .and_then(|at| self.header.get(at))
        {
            return *byte;
        }
        match &self.shape {
            Shape::Filler => {
                if self.newline_at == Some(index) {
                    0x0a
                } else {
                    0x80 | u8::try_from(index & 0x3f).unwrap_or(0)
                }
            }
            Shape::Elf(layout) => layout.byte(index, cursor),
        }
    }
}

impl Layout {
    fn byte(&self, index: u64, cursor: &mut Cursor) -> u8 {
        if index < self.phoff_end {
            let entry = (index - 64) / PHDR_SIZE;
            let at = (index - 64) % PHDR_SIZE;
            return self
                .phdrs
                .get(usize::try_from(entry).unwrap_or(usize::MAX))
                .filter(|_| (entry as usize) < self.nph)
                .map_or(0, |p| phdr_byte(p, at));
        }
        if index >= self.shoff {
            let entry = (index - self.shoff) / SHDR_SIZE;
            let at = (index - self.shoff) % SHDR_SIZE;
            let entry = usize::try_from(entry).unwrap_or(usize::MAX);
            if entry >= self.nsec {
                return 0;
            }
            return self.sections.get(entry).map_or(0, |s| shdr_byte(s, at));
        }
        let sections = &self.sections[..self.nsec];
        let upper = sections.partition_point(|s| s.offset <= index);
        for section in sections[..upper].iter().rev().take(4) {
            if section.has_file_bytes() && index < section.end() {
                return self.content(section, index - section.offset, index, cursor);
            }
        }
        0
    }

    fn got_slot(&self, slot: u64) -> u64 {
        self.vaddr(self.idx.got) + 8 * slot
    }

    /// A code address the pointer tables and relocations use.
    fn code_pointer(&self, tag: u64, i: u64) -> u64 {
        let (start, end) = self.text;
        let span = (end - start).max(16);
        self.base() + start + align_down(draw(self.seed, tag, i) % span, 16)
    }

    fn rodata_pointer(&self, tag: u64, i: u64) -> u64 {
        let (start, end) = self.rodata;
        let span = (end - start).max(8);
        self.base() + start + draw(self.seed, tag, i) % span
    }

    /// Word `slot` of a pointer-table section: `.data.rel.ro` opens with the pointers its
    /// RELATIVE relocations name; past them, and in the other such sections, plain data.
    fn relro_value(&self, section: &Section, slot: u64) -> u64 {
        let is_relro = self.idx.relro != 0 && section.offset == self.section(self.idx.relro).offset;
        if is_relro && slot < self.relro_ptrs {
            if slot % 3 == 2 {
                self.code_pointer(31, slot)
            } else {
                self.rodata_pointer(32, slot)
            }
        } else {
            data_word(self.seed, 33, section.offset / 8 + slot)
        }
    }

    fn content(&self, section: &Section, at: u64, absolute: u64, cursor: &mut Cursor) -> u8 {
        let seed = self.seed;
        match section.kind {
            Kind::Null | Kind::NoBits => 0,
            Kind::Interp => byte_of(INTERP, at),
            Kind::NoteProperty => record_byte(
                &[
                    (4, 4),
                    (0x20, 4),
                    (5, 4),
                    (u64::from(u32::from_le_bytes(*b"GNU\0")), 4),
                    (0xc000_0002, 4),
                    (4, 4),
                    (3, 4),
                    (0, 4),
                    (0xc000_8002, 4),
                    (4, 4),
                    (1, 4),
                    (0, 4),
                ],
                at,
            ),
            Kind::NoteBuildId => {
                if at < 16 {
                    record_byte(
                        &[
                            (4, 4),
                            (20, 4),
                            (3, 4),
                            (u64::from(u32::from_le_bytes(*b"GNU\0")), 4),
                        ],
                        at,
                    )
                } else {
                    self.build_id()[usize::try_from(at - 16).unwrap_or(0).min(19)]
                }
            }
            Kind::NoteAbiTag => record_byte(
                &[
                    (4, 4),
                    (16, 4),
                    (1, 4),
                    (u64::from(u32::from_le_bytes(*b"GNU\0")), 4),
                    (0, 4),
                    (3, 4),
                    (2, 4),
                    (0, 4),
                ],
                at,
            ),
            Kind::GnuHash => record_byte(
                &[
                    (1, 4),
                    (self.sym_count() as u64 + 1, 4),
                    (1, 4),
                    (6, 4),
                    (0, 8),
                    (0, 4),
                ],
                at,
            ),
            Kind::Dynsym => {
                let k = usize::try_from(at / 24).unwrap_or(0);
                if k == 0 {
                    return 0;
                }
                let (_, info, _) = self.symbol(k);
                record_byte(
                    &[
                        (u64::from(self.sym_name_off[k]), 4),
                        (u64::from(info), 1),
                        (0, 1),
                        (0, 2),
                        (0, 8),
                        (0, 8),
                    ],
                    at % 24,
                )
            }
            Kind::Dynstr => self.dynstr_byte(at),
            Kind::Versym => {
                let k = usize::try_from(at / 2).unwrap_or(0);
                if k == 0 {
                    return 0;
                }
                let (_, _, version) = self.symbol(k);
                record_byte(&[(self.version_index(version), 2)], at % 2)
            }
            Kind::Verneed => {
                let count = self.version_count();
                if at < 16 {
                    return record_byte(
                        &[(1, 2), (count, 2), (self.libc_off, 4), (16, 4), (0, 4)],
                        at,
                    );
                }
                let aux = (at - 16) / 16;
                let mut seen = 0;
                for (v, name) in VERSIONS.iter().enumerate() {
                    if self.versions & (1 << v) == 0 {
                        continue;
                    }
                    if seen == aux {
                        let next = if aux + 1 == count { 0 } else { 16 };
                        return record_byte(
                            &[
                                (u64::from(elf_hash(name)), 4),
                                (0, 2),
                                (2 + aux, 2),
                                (u64::from(self.version_off[v]), 4),
                                (next, 4),
                            ],
                            (at - 16) % 16,
                        );
                    }
                    seen += 1;
                }
                0
            }
            Kind::RelaDyn => {
                let r = at / 24;
                let nrelative = self.relative_count();
                let (offset, info, addend) = if r < nrelative {
                    let (slot_addr, value) = self.relative_slot(r);
                    (slot_addr, 8, value)
                } else {
                    let j = r - nrelative;
                    (self.got_slot(3 + self.nplt() + j), ((j + 1) << 32) | 6, 0)
                };
                record_byte(&[(offset, 8), (info, 8), (addend, 8)], at % 24)
            }
            Kind::RelaPlt => {
                let j = at / 24;
                let sym = ALWAYS.len() as u64 + j;
                record_byte(
                    &[(self.got_slot(3 + j), 8), ((sym << 32) | 7, 8), (0, 8)],
                    at % 24,
                )
            }
            Kind::IRelaPlt => {
                let j = at / 24;
                let slot = self.vaddr(self.idx.gotplt) + 0x18 + 8 * j;
                record_byte(
                    &[(slot, 8), (37, 8), (self.code_pointer(41, j), 8)],
                    at % 24,
                )
            }
            Kind::Init => {
                let addr = self.vaddr(self.idx.init);
                let gmon = self.got_slot(3 + self.nplt() + 3);
                let rel = rel32(gmon, addr + 15);
                let mut code = [0u8; 27];
                code[..11].copy_from_slice(&[
                    0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x83, 0xec, 0x08, 0x48, 0x8b, 0x05,
                ]);
                code[11..15].copy_from_slice(&rel.to_le_bytes());
                code[15..].copy_from_slice(&[
                    0x48, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x08, 0xc3,
                ]);
                if self.exec {
                    // No `__gmon_start__` slot in a static image: the test is against zero.
                    code[8..15].copy_from_slice(&[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00]);
                }
                byte_of(&code, at)
            }
            Kind::Fini => byte_of(
                &[
                    0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x83, 0xec, 0x08, 0x48, 0x83, 0xc4, 0x08, 0xc3,
                ],
                at,
            ),
            Kind::Plt => {
                let entry = at / 16;
                let addr = section.addr + entry * 16;
                let got = self.vaddr(self.idx.got);
                let stub = if entry == 0 {
                    let mut stub = [0u8; 16];
                    stub[..2].copy_from_slice(&[0xff, 0x35]);
                    stub[2..6].copy_from_slice(&rel32(got + 8, addr + 6).to_le_bytes());
                    stub[6..9].copy_from_slice(&[0xf2, 0xff, 0x25]);
                    stub[9..13].copy_from_slice(&rel32(got + 16, addr + 13).to_le_bytes());
                    stub[13..].copy_from_slice(&[0x0f, 0x1f, 0x00]);
                    stub
                } else {
                    let mut stub = [0u8; 16];
                    stub[..5].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0x68]);
                    stub[5..9]
                        .copy_from_slice(&u32::try_from(entry - 1).unwrap_or(0).to_le_bytes());
                    stub[9..11].copy_from_slice(&[0xf2, 0xe9]);
                    stub[11..15].copy_from_slice(&rel32(section.addr, addr + 15).to_le_bytes());
                    stub[15] = 0x90;
                    stub
                };
                stub[usize::try_from(at % 16).unwrap_or(0)]
            }
            Kind::PltGot => {
                let slot = self.got_slot(3 + self.nplt() + 1);
                jump_stub(slot, section.addr)[usize::try_from(at % 16).unwrap_or(0)]
            }
            Kind::PltSec => {
                let entry = at / 16;
                let addr = section.addr + entry * 16;
                let slot = if self.exec {
                    self.vaddr(self.idx.gotplt) + 0x18 + 8 * entry
                } else {
                    self.got_slot(3 + entry)
                };
                jump_stub(slot, addr)[usize::try_from(at % 16).unwrap_or(0)]
            }
            Kind::Code => {
                let bundle = absolute / 16;
                let bytes = match cursor.bundle {
                    Some((index, bytes)) if index == bundle => bytes,
                    _ => {
                        let bytes = code_bundle(seed, bundle, bundle * 16 == self.entry);
                        cursor.bundle = Some((bundle, bytes));
                        bytes
                    }
                };
                bytes[usize::try_from(absolute % 16).unwrap_or(0)]
            }
            Kind::Rodata => self.rodata_byte(at),
            Kind::EhFrameHdr => {
                let hdr = section.addr;
                let eh = self.vaddr(self.idx.eh_frame);
                if at < 12 {
                    return record_byte(
                        &[
                            (0x3b03_1b01, 4),
                            (u64::from(rel32(eh, hdr + 4)), 4),
                            (self.eh_count, 4),
                        ],
                        at,
                    );
                }
                let k = (at - 12) / 8;
                let fde = eh + 0x18 + 0x20 * k;
                let pc = self.base() + self.text.0 + self.eh_step * k;
                record_byte(
                    &[
                        (u64::from(rel32(pc, hdr)), 4),
                        (u64::from(rel32(fde, hdr)), 4),
                    ],
                    (at - 12) % 8,
                )
            }
            Kind::EhFrame => self.eh_frame_byte(section, at),
            Kind::InitArray => record_byte(&[(self.code_pointer(21, at / 8), 8)], at % 8),
            Kind::FiniArray => record_byte(&[(self.code_pointer(22, at / 8), 8)], at % 8),
            Kind::RelRo => record_byte(&[(self.relro_value(section, at / 8), 8)], at % 8),
            Kind::Dynamic => self.dynamic_byte(at),
            Kind::Got => {
                let slot = at / 8;
                let value = if slot == 0 {
                    self.vaddr(self.idx.dynamic)
                } else if slot < 3 || slot >= 3 + self.nplt() {
                    0
                } else {
                    self.vaddr(self.idx.plt) + 16 * (slot - 2)
                };
                record_byte(&[(value, 8)], at % 8)
            }
            Kind::GotPlt => {
                let slot = at / 8;
                let value = if slot < 3 {
                    0
                } else {
                    self.vaddr(self.idx.plt) + 16 * (slot - 3)
                };
                record_byte(&[(value, 8)], at % 8)
            }
            Kind::Data => {
                let slot = at / 8;
                let value = if section.addr == self.vaddr(self.idx.data) && slot < 2 {
                    if slot == 1 { section.addr + 8 } else { 0 }
                } else if draw(seed, 51, section.offset + slot).is_multiple_of(5) {
                    self.rodata_pointer(52, section.offset + slot)
                } else {
                    data_word(seed, 53, section.offset + slot)
                };
                record_byte(&[(value, 8)], at % 8)
            }
            Kind::DebugLink => {
                if at < 48 {
                    byte_of(self.debuglink_name().as_bytes(), at)
                } else {
                    let crc = draw(seed, 61, 0) & 0xffff_ffff;
                    record_byte(&[(crc, 4)], at - 48)
                }
            }
            Kind::DebugAltLink => {
                let path = alt_link_path(self.name);
                let path_len = align_up(path.len() as u64 + 1, 4);
                if at < path_len {
                    byte_of(path.as_bytes(), at)
                } else {
                    // One dwz file per package, so every binary of it names the same ID.
                    let id_seed = fnv_seed(path.bytes());
                    record_byte(
                        &[(draw(id_seed, 62, (at - path_len) / 8), 8)],
                        (at - path_len) % 8,
                    )
                }
            }
            Kind::Comment => byte_of(COMMENT, at),
            Kind::Shstrtab => {
                strings_byte(std::iter::once("").chain(self.shstrtab_names()), at).unwrap_or(0)
            }
        }
    }

    /// The RELATIVE slots: `.init_array`, `.fini_array`, the pointer words of `.data.rel.ro`,
    /// then `__dso_handle` in `.data`; each with the value written there.
    fn relative_slot(&self, r: u64) -> (u64, u64) {
        match r {
            0 => (self.vaddr(self.idx.init_array), self.code_pointer(21, 0)),
            1 => (self.vaddr(self.idx.fini_array), self.code_pointer(22, 0)),
            r if r < 2 + self.relro_ptrs => {
                let relro = self.section(self.idx.relro);
                let slot = r - 2;
                (relro.addr + 8 * slot, self.relro_value(relro, slot))
            }
            _ => {
                let data = self.vaddr(self.idx.data);
                (data + 8, data + 8)
            }
        }
    }

    fn build_id(&self) -> [u8; 20] {
        let mut id = [0u8; 20];
        for (i, byte) in id.iter_mut().enumerate() {
            let word = draw(self.seed, 1, i as u64 / 8).to_le_bytes();
            *byte = word[i % 8];
        }
        id
    }

    /// `<build-id less its first byte, in hex>.debug`: the name Debian's `dh_strip` links.
    fn debuglink_name(&self) -> String {
        let id = self.build_id();
        let mut name: String = id[1..].iter().map(|b| format!("{b:02x}")).collect();
        name.push_str(".debug");
        name
    }

    fn dynstr_byte(&self, at: u64) -> u8 {
        if at == 0 {
            return 0;
        }
        if at < self.libc_off {
            let count = self.sym_count();
            let offsets = &self.sym_name_off[1..=count];
            let k = offsets.partition_point(|off| u64::from(*off) <= at);
            if k == 0 {
                return 0;
            }
            let (name, _, _) = self.symbol(k);
            return byte_of(name.as_bytes(), at - u64::from(offsets[k - 1]));
        }
        if at < self.libc_off + LIBC.len() as u64 {
            return byte_of(LIBC, at - self.libc_off);
        }
        for (v, name) in VERSIONS.iter().enumerate() {
            if self.versions & (1 << v) == 0 {
                continue;
            }
            let off = u64::from(self.version_off[v]);
            if at >= off && at <= off + name.len() as u64 {
                return byte_of(name.as_bytes(), at - off);
            }
        }
        0
    }

    fn rodata_byte(&self, at: u64) -> u8 {
        // `_IO_stdin_used`, then the strings, then tables.
        if at < 8 {
            return byte_of(&[1, 0, 2, 0], at);
        }
        let at = at - 8;
        if at < self.strings_len {
            return strings_byte(self.rodata_strings(), at).unwrap_or(0);
        }
        let table_start = align_up(self.strings_len, 32);
        if at < table_start {
            return 0;
        }
        let at = at - table_start;
        let row = at / 16;
        let col = at % 16;
        match draw(self.seed, 71, row) % 6 {
            0 | 1 => {
                // A jump table: 32-bit offsets back from the table, as a switch compiles to.
                let value = draw(self.seed, 72, at / 4) % 0x4000;
                let rel = 0u32.wrapping_sub(u32::try_from(value + 0x100).unwrap_or(0x100));
                rel.to_le_bytes()[usize::try_from(col % 4).unwrap_or(0)]
            }
            2 => 0,
            3 => record_byte(&[(data_word(self.seed, 73, at / 8), 8)], col % 8),
            _ => {
                let value = draw(self.seed, 74, at / 4) % 0x200;
                u32::try_from(value).unwrap_or(0).to_le_bytes()
                    [usize::try_from(col % 4).unwrap_or(0)]
            }
        }
    }

    fn eh_frame_byte(&self, section: &Section, at: u64) -> u8 {
        const CIE: [u8; 0x18] = [
            0x14, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 0x10, 1, 0x1b, 0x0c, 0x07, 0x08,
            0x90, 0x01, 0, 0,
        ];
        if at < 0x18 {
            return byte_of(&CIE, at);
        }
        let k = (at - 0x18) / 0x20;
        if k >= self.eh_count {
            return 0;
        }
        let fde_at = (at - 0x18) % 0x20;
        let fde_addr = section.addr + 0x18 + 0x20 * k;
        let pc = self.base() + self.text.0 + self.eh_step * k;
        let instructions = [0x0e, 0x10, 0x86, 0x02, 0x0d, 0x06];
        if fde_at >= 17 {
            return byte_of(&instructions, fde_at - 17);
        }
        record_byte(
            &[
                (0x1c, 4),
                (fde_addr + 4 - section.addr, 4),
                (u64::from(rel32(pc, fde_addr + 8)), 4),
                (self.eh_step, 4),
                (0, 1),
            ],
            fde_at,
        )
    }

    fn dynamic_byte(&self, at: u64) -> u8 {
        let entry = at / 16;
        let addr = |index: usize| self.vaddr(index);
        let size = |index: usize| self.section(index).size;
        let (tag, value): (u64, u64) = match entry {
            0 => (1, self.libc_off),
            1 => (0xc, addr(self.idx.init)),
            2 => (0xd, addr(self.idx.fini)),
            3 => (0x19, addr(self.idx.init_array)),
            4 => (0x1b, 8),
            5 => (0x1a, addr(self.idx.fini_array)),
            6 => (0x1c, 8),
            7 => (0x6fff_fef5, addr(self.idx.gnu_hash)),
            8 => (5, addr(self.idx.dynstr)),
            9 => (6, addr(self.idx.dynsym)),
            10 => (0xa, size(self.idx.dynstr)),
            11 => (0xb, 24),
            12 => (0x15, 0),
            13 => (3, addr(self.idx.got)),
            14 => (2, size(self.idx.rela_plt)),
            15 => (0x14, 7),
            16 => (0x17, addr(self.idx.rela_plt)),
            17 => (7, addr(self.idx.rela_dyn)),
            18 => (8, size(self.idx.rela_dyn)),
            19 => (9, 24),
            20 => (0x1e, 8),
            21 => (0x6fff_fffb, 0x0800_0001),
            22 => (0x6fff_fffe, addr(self.idx.verneed)),
            23 => (0x6fff_ffff, 1),
            24 => (0x6fff_fff0, addr(self.idx.versym)),
            25 => (0x6fff_fff9, self.relative_count()),
            _ => (0, 0),
        };
        record_byte(&[(tag, 8), (value, 8)], at % 16)
    }
}

fn phdr_byte(p: &Phdr, at: u64) -> u8 {
    record_byte(
        &[
            (u64::from(p.p_type), 4),
            (u64::from(p.flags), 4),
            (p.offset, 8),
            (p.vaddr, 8),
            (p.vaddr, 8),
            (p.filesz, 8),
            (p.memsz, 8),
            (p.align, 8),
        ],
        at,
    )
}

fn shdr_byte(s: &Section, at: u64) -> u8 {
    if s.kind == Kind::Null {
        return 0;
    }
    record_byte(
        &[
            (u64::from(s.name_off), 4),
            (u64::from(s.sh_type), 4),
            (s.flags, 8),
            (s.addr, 8),
            (s.offset, 8),
            (s.size, 8),
            (u64::from(s.link), 4),
            (u64::from(s.info), 4),
            (s.align, 8),
            (s.entsize, 8),
        ],
        at,
    )
}

/// The 32-bit displacement from `from` to `to`.
fn rel32(to: u64, from: u64) -> u32 {
    (to.wrapping_sub(from) & 0xffff_ffff) as u32
}

/// `endbr64; bnd jmp *slot(%rip); nopl 0(%rax,%rax,1)`: a PLT stub through a GOT slot.
fn jump_stub(slot: u64, addr: u64) -> [u8; 16] {
    let mut stub = [0u8; 16];
    stub[..7].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25]);
    stub[7..11].copy_from_slice(&rel32(slot, addr + 11).to_le_bytes());
    stub[11..].copy_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]);
    stub
}

/// A data word: mostly zero, otherwise a small count, flag set or length.
fn data_word(seed: u64, tag: u64, i: u64) -> u64 {
    let r = draw(seed, tag, i);
    match r % 4 {
        0 | 1 => 0,
        2 => (r >> 8) % 0x100,
        _ => (r >> 8) % 0x10000,
    }
}

/// The nop of exactly `len` bytes (1 to 15) the assembler pads with.
fn nop(len: usize, out: &mut [u8]) {
    const NOPS: [&[u8]; 11] = [
        &[],
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    let long = NOPS[10];
    if len <= 10 {
        out[..len].copy_from_slice(NOPS[len]);
    } else {
        let prefixes = len - 10;
        out[..prefixes].fill(0x66);
        out[prefixes..len].copy_from_slice(long);
    }
}

/// Sixteen bytes of instruction-shaped noise for `bundle`: whole instructions drawn from the
/// forms compiled C is made of (moves, loads, calls, tests and branches, pushes and pops, stack
/// adjustment), a function boundary now and then as `ret` plus assembler padding, and the bundle
/// at the entry point opening as `_start` does. It decodes, and means nothing.
fn code_bundle(seed: u64, bundle: u64, at_entry: bool) -> [u8; 16] {
    let mut out = [0x90u8; 16];
    let mut state = draw(seed, 81, bundle);
    let mut next = || {
        state = mix(state);
        state
    };
    let mut at = 0usize;
    if at_entry {
        out[..6].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed]);
        at = 6;
    } else if next() % 6 == 0 {
        out[..4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
        at = 4;
    }
    while at < 16 {
        let room = 16 - at;
        let r = next();
        let small = (r >> 16) as u8;
        let rel = |r: u64| -> [u8; 4] {
            let span = (r >> 24) % 0x6000;
            let value = if (r >> 40) & 1 == 0 {
                span
            } else {
                0u64.wrapping_sub(span + 5)
            };
            ((value & 0xffff_ffff) as u32).to_le_bytes()
        };
        let reg = ((r >> 32) % 8) as u8;
        let form = r % 20;
        let mut emit = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        match form {
            0..=3 if room >= 3 => emit(&[0x48 | (small & 5), 0x89, 0xc0 | (small & 0x3f)]),
            4 | 5 if room >= 4 => emit(&[0x48, 0x8b, 0x45 | (reg << 3), small & 0xf8]),
            6 if room >= 5 => emit(&[0x48, 0x89, 0x44 | (reg << 3), 0x24, small & 0x78]),
            7 if room >= 7 => {
                let d = rel(r);
                emit(&[0x48, 0x8d, 0x05 | (reg << 3), d[0], d[1], d[2], d[3]]);
            }
            8 | 9 if room >= 5 => {
                let d = rel(r);
                emit(&[0xe8, d[0], d[1], d[2], d[3]]);
            }
            10 if room >= 2 => emit(&[0x85, 0xc0 | (small & 0x3f)]),
            11 if room >= 2 => emit(&[0x74 | (small & 1), small >> 1]),
            12 if room >= 6 => {
                let d = rel(r);
                emit(&[0x0f, 0x84 | (small & 1), d[0], d[1], d[2], d[3]]);
            }
            13 if room >= 2 => emit(&[0x31, 0xc0 | (reg << 3) | reg]),
            14 if room >= 5 => emit(&[0xb8 | reg, small, 0, 0, 0]),
            15 if room >= 1 => emit(&[0x50 | reg | (small & 8)]),
            16 if room >= 4 => emit(&[0x48, 0x83, 0xc4 | (small & 0x28), small & 0x78]),
            17 if room >= 3 => emit(&[0x48, 0x39, 0xc0 | (small & 0x3f)]),
            18 if room >= 3 => emit(&[0x0f, 0xb6, 0xc0 | (small & 0x3f)]),
            19 => {
                // End of a function: return, then pad to the next 16-byte boundary.
                emit(&[0xc3]);
                let rest = 16 - at;
                nop(rest, &mut out[at..]);
                at = 16;
            }
            _ => emit(&[0x5b | (small & 4)]),
        }
    }
    out
}

#[cfg(test)]
#[path = "elf_body_tests.rs"]
mod tests;
