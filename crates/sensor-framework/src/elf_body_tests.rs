//! The generated bodies, checked by a minimal ELF reader written here from the ELF-64 and x86-64
//! psABI layouts, sharing no code with the generator. What the real tools said about the images
//! (`file`, `readelf -lhSdV --dyn-syms --wide`, `strings`, `objdump -d`, run on images written by
//! `examples/elf_image.rs`) is pinned below as the facts those tools read.

use std::collections::HashSet;

use super::*;
use crate::binaries::{self, BINARIES, BinaryImage};

/// `len` bytes of `image` from `offset`, through the range reader the filesystem uses.
fn read(body: &ElfBody, offset: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    body.append_range(offset, offset + len, &mut out);
    out
}

fn u16_at(bytes: &[u8], at: usize) -> u64 {
    u64::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[derive(Debug, Clone, Copy)]
struct Ph {
    p_type: u64,
    flags: u64,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[derive(Debug, Clone)]
struct Sh {
    name: String,
    sh_type: u64,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u64,
    info: u64,
    align: u64,
    entsize: u64,
}

/// What the reader makes of one image.
struct Parsed {
    len: u64,
    e_type: u64,
    entry: u64,
    phoff: u64,
    shoff: u64,
    phdrs: Vec<Ph>,
    sections: Vec<Sh>,
}

impl Parsed {
    fn section(&self, name: &str) -> Option<&Sh> {
        self.sections.iter().find(|s| s.name == name)
    }

    fn segments(&self, p_type: u64) -> Vec<Ph> {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == p_type)
            .copied()
            .collect()
    }
}

fn parse(body: &ElfBody, len: u64) -> Parsed {
    let header = read(body, 0, 64);
    assert_eq!(&header[..4], b"\x7fELF");
    let phoff = u64_at(&header, 32);
    let shoff = u64_at(&header, 40);
    let phnum = u16_at(&header, 56);
    let shnum = u16_at(&header, 60);
    let shstrndx = u16_at(&header, 62);
    let table = read(body, phoff, phnum * 56);
    let phdrs = table
        .chunks(56)
        .map(|p| Ph {
            p_type: u32_at(p, 0),
            flags: u32_at(p, 4),
            offset: u64_at(p, 8),
            vaddr: u64_at(p, 16),
            paddr: u64_at(p, 24),
            filesz: u64_at(p, 32),
            memsz: u64_at(p, 40),
            align: u64_at(p, 48),
        })
        .collect();
    let table = read(body, shoff, shnum * 64);
    let raw: Vec<&[u8]> = table.chunks(64).collect();
    let strtab = raw[shstrndx as usize];
    let names = read(body, u64_at(strtab, 24), u64_at(strtab, 32));
    let sections = raw
        .iter()
        .map(|s| {
            let at = u32_at(s, 0) as usize;
            assert!(at < names.len(), "name offset {at} past .shstrtab");
            let end = names[at..]
                .iter()
                .position(|b| *b == 0)
                .expect("a name ends inside .shstrtab");
            Sh {
                name: String::from_utf8(names[at..at + end].to_vec()).unwrap(),
                sh_type: u32_at(s, 4),
                flags: u64_at(s, 8),
                addr: u64_at(s, 16),
                offset: u64_at(s, 24),
                size: u64_at(s, 32),
                link: u32_at(s, 40),
                info: u32_at(s, 44),
                align: u64_at(s, 48),
                entsize: u64_at(s, 56),
            }
        })
        .collect();
    Parsed {
        len,
        e_type: u16_at(&header, 16),
        entry: u64_at(&header, 24),
        phoff,
        shoff,
        phdrs,
        sections,
    }
}

fn body_of(binary: &BinaryImage) -> ElfBody {
    binary.image().body()
}

/// A NUL-terminated string at `offset` in the file.
fn c_string(body: &ElfBody, offset: u64) -> String {
    let bytes = read(body, offset, 256);
    let end = bytes.iter().position(|b| *b == 0).expect("terminated");
    String::from_utf8(bytes[..end].to_vec()).unwrap()
}

/// The file offset of virtual address `vaddr`, through the `PT_LOAD` that maps it.
fn file_offset(parsed: &Parsed, vaddr: u64) -> u64 {
    let load = parsed
        .segments(1)
        .into_iter()
        .find(|p| vaddr >= p.vaddr && vaddr < p.vaddr + p.filesz)
        .unwrap_or_else(|| panic!("{vaddr:#x} is in no loaded file range"));
    vaddr - load.vaddr + load.offset
}

const INTERP_PATH: &str = "/lib64/ld-linux-x86-64.so.2";

/// The checks `readelf -lhS --wide` makes before printing, and the ones its mapping table shows:
/// every table entry in bounds and aligned, segments congruent to their pages, sections inside
/// the segment that maps them, names resolving in `.shstrtab`.
fn assert_consistent(name: &str, parsed: &Parsed, body: &ElfBody) {
    let len = parsed.len;
    assert_eq!(parsed.phoff, 64, "{name}");
    assert_eq!(parsed.shoff % 8, 0, "{name}");
    assert!(
        parsed.shoff + 64 * parsed.sections.len() as u64 <= len,
        "{name}"
    );
    let phdr_bytes = 56 * parsed.phdrs.len() as u64;
    for p in &parsed.phdrs {
        assert!(p.offset + p.filesz <= len, "{name}: {p:?} past the file");
        assert!(p.filesz <= p.memsz, "{name}: {p:?}");
        assert_eq!(p.vaddr, p.paddr, "{name}: {p:?}");
        if p.align > 1 {
            assert!(p.align.is_power_of_two(), "{name}: {p:?}");
            assert_eq!(
                p.offset % p.align,
                p.vaddr % p.align,
                "{name}: {p:?} incongruent"
            );
        }
    }
    // PT_LOAD: ascending, disjoint, the first mapping the ELF header and the program headers.
    let loads = parsed.segments(1);
    assert!(loads.len() >= 4, "{name}");
    assert_eq!(loads[0].offset, 0, "{name}");
    assert!(loads[0].filesz >= 64 + phdr_bytes, "{name}");
    for pair in loads.windows(2) {
        assert!(
            pair[0].offset + pair[0].filesz <= pair[1].offset,
            "{name}: {pair:?}"
        );
        assert!(
            pair[0].vaddr + pair[0].memsz <= pair[1].vaddr,
            "{name}: {pair:?}"
        );
    }
    let exec_load = loads.iter().find(|p| p.flags == 5).expect("an R E segment");
    assert!(
        parsed.entry >= exec_load.vaddr && parsed.entry < exec_load.vaddr + exec_load.filesz,
        "{name}: entry {:#x} outside the code segment",
        parsed.entry
    );
    for stack in parsed.segments(0x6474_e551) {
        assert_eq!(
            (stack.filesz, stack.flags),
            (0, 6),
            "{name}: non-executable stack"
        );
    }
    // Sections: the null entry, then in file order, aligned, inside the file and below the
    // section header table, each allocated one inside the PT_LOAD that maps it.
    let first = &parsed.sections[0];
    assert_eq!(
        (first.sh_type, first.size, first.name.as_str()),
        (0, 0, ""),
        "{name}"
    );
    let mut names = HashSet::new();
    let mut end = 64 + phdr_bytes;
    for s in &parsed.sections[1..] {
        assert!(
            !s.name.is_empty() && names.insert(s.name.clone()),
            "{name}: {s:?}"
        );
        if s.align > 1 {
            assert!(s.align.is_power_of_two(), "{name}: {s:?}");
            assert_eq!(s.addr % s.align, 0, "{name}: {s:?} misaligned");
        }
        // NOBITS has an address and no file bytes: its offset is only where the file stops.
        if s.sh_type == 8 {
            continue;
        }
        if s.align > 1 {
            assert_eq!(s.offset % s.align, 0, "{name}: {s:?} misaligned");
        }
        if s.entsize > 0 {
            assert_eq!(s.size % s.entsize, 0, "{name}: {s:?}");
        }
        assert!(s.offset >= end, "{name}: {s:?} overlaps the section before");
        end = s.offset + s.size;
        assert!(
            end <= parsed.shoff,
            "{name}: {s:?} runs into the section headers"
        );
        assert!(s.link < parsed.sections.len() as u64, "{name}: {s:?}");
        if s.flags & 2 != 0 {
            let load = loads
                .iter()
                .find(|p| s.offset >= p.offset && s.offset + s.size <= p.offset + p.filesz)
                .unwrap_or_else(|| panic!("{name}: {s:?} in no PT_LOAD"));
            assert_eq!(s.addr - load.vaddr, s.offset - load.offset, "{name}: {s:?}");
        } else {
            assert_eq!(s.addr, 0, "{name}: {s:?}");
        }
    }
    let shstrtab = parsed.sections.last().unwrap();
    assert_eq!(
        (shstrtab.name.as_str(), shstrtab.sh_type),
        (".shstrtab", 3),
        "{name}"
    );
    // The build-ID note: "GNU", NT_GNU_BUILD_ID, 20 bytes.
    let note = parsed
        .section(".note.gnu.build-id")
        .expect("a build-id note");
    let bytes = read(body, note.offset, note.size);
    assert_eq!(
        &bytes[..16],
        b"\x04\0\0\0\x14\0\0\0\x03\0\0\0GNU\0",
        "{name}"
    );
    let abi = parsed.section(".note.ABI-tag").expect("an ABI tag");
    assert_eq!(
        read(body, abi.offset, abi.size),
        b"\x04\0\0\0\x10\0\0\0\x01\0\0\0GNU\0\0\0\0\0\x03\0\0\0\x02\0\0\0\0\0\0\0",
        "{name}: GNU/Linux 3.2.0"
    );
    if parsed.e_type == 3 {
        assert_dynamic(name, parsed, body);
    } else {
        assert!(
            parsed.segments(3).is_empty() && parsed.segments(2).is_empty(),
            "{name}"
        );
    }
}

/// What a dynamically linked PIE must hold for `file` to call it one and the loader to accept it:
/// PT_PHDR on the table, PT_INTERP naming the loader, PT_DYNAMIC on `.dynamic` with `DT_NEEDED`
/// libc and `DF_1_PIE`, symbol and version tables whose names resolve in `.dynstr`.
fn assert_dynamic(name: &str, parsed: &Parsed, body: &ElfBody) {
    let phdr = parsed.segments(6);
    assert_eq!(phdr.len(), 1, "{name}");
    assert_eq!(
        (phdr[0].offset, phdr[0].filesz),
        (64, 56 * parsed.phdrs.len() as u64),
        "{name}"
    );
    let interp = parsed.segments(3);
    assert_eq!(interp.len(), 1, "{name}");
    assert_eq!(interp[0].filesz, INTERP_PATH.len() as u64 + 1, "{name}");
    assert_eq!(c_string(body, interp[0].offset), INTERP_PATH, "{name}");
    let interp_section = parsed.section(".interp").unwrap();
    assert_eq!(interp_section.offset, interp[0].offset, "{name}");

    let dynamic = parsed.section(".dynamic").unwrap();
    let pt_dynamic = parsed.segments(2);
    assert_eq!(pt_dynamic.len(), 1, "{name}");
    assert_eq!(
        (pt_dynamic[0].offset, pt_dynamic[0].filesz),
        (dynamic.offset, dynamic.size),
        "{name}"
    );
    let entries = read(body, dynamic.offset, dynamic.size);
    let tags: Vec<(u64, u64)> = entries
        .chunks(16)
        .map(|e| (u64_at(e, 0), u64_at(e, 8)))
        .collect();
    let tag = |t: u64| tags.iter().find(|(k, _)| *k == t).map(|(_, v)| *v);
    let dynstr = parsed.section(".dynstr").unwrap();
    let dynsym = parsed.section(".dynsym").unwrap();
    assert_eq!(tag(5), Some(dynstr.addr), "{name}: DT_STRTAB");
    assert_eq!(tag(6), Some(dynsym.addr), "{name}: DT_SYMTAB");
    assert_eq!(tag(10), Some(dynstr.size), "{name}: DT_STRSZ");
    assert_eq!(
        tag(0x6fff_fffb),
        Some(0x0800_0001),
        "{name}: DF_1_NOW | DF_1_PIE"
    );
    let needed = tag(1).expect("DT_NEEDED");
    assert_eq!(
        c_string(body, dynstr.offset + needed),
        "libc.so.6",
        "{name}"
    );
    for (t, section) in [
        (0x6fff_fef5, ".gnu.hash"),
        (0x17, ".rela.plt"),
        (7, ".rela.dyn"),
        (0x6fff_fffe, ".gnu.version_r"),
        (0x6fff_fff0, ".gnu.version"),
        (0x19, ".init_array"),
        (0x1a, ".fini_array"),
        (0xc, ".init"),
        (0xd, ".fini"),
        (3, ".got"),
    ] {
        assert_eq!(
            tag(t),
            Some(parsed.section(section).unwrap().addr),
            "{name}: {section}"
        );
    }
    assert_eq!(
        dynsym.link,
        parsed
            .sections
            .iter()
            .position(|s| s.name == ".dynstr")
            .unwrap() as u64
    );

    // Every symbol name resolves to a libc import.
    let symbols = read(body, dynsym.offset, dynsym.size);
    let known: HashSet<&str> = ALWAYS
        .iter()
        .map(|a| a.0)
        .chain(POOL.iter().map(|p| p.0))
        .collect();
    assert_eq!(&symbols[..24], &[0u8; 24], "{name}");
    let mut seen = HashSet::new();
    for sym in symbols.chunks(24).skip(1) {
        let symbol = c_string(body, dynstr.offset + u32_at(sym, 0));
        assert!(known.contains(symbol.as_str()), "{name}: {symbol}");
        assert!(seen.insert(symbol), "{name}: a symbol imported twice");
        assert_eq!(u16_at(sym, 6), 0, "{name}: an import is undefined");
    }
    assert!(seen.contains("__libc_start_main"), "{name}");

    // One libc.so.6 need, its versions GLIBC_2.x, numbered from 2, each a versym target.
    let verneed = parsed.section(".gnu.version_r").unwrap();
    let need = read(body, verneed.offset, verneed.size);
    assert_eq!(u16_at(&need, 0), 1, "{name}");
    assert_eq!(
        c_string(body, dynstr.offset + u32_at(&need, 4)),
        "libc.so.6",
        "{name}"
    );
    let count = u16_at(&need, 2) as usize;
    let mut indices = HashSet::new();
    for aux in need[16..].chunks(16).take(count) {
        let version = c_string(body, dynstr.offset + u32_at(aux, 8));
        assert!(version.starts_with("GLIBC_2."), "{name}: {version}");
        assert_eq!(
            u32_at(aux, 0),
            u64::from(elf_hash_reference(&version)),
            "{name}: {version}"
        );
        indices.insert(u16_at(aux, 6));
    }
    let versym = parsed.section(".gnu.version").unwrap();
    for entry in read(body, versym.offset, versym.size).chunks(2).skip(1) {
        let v = u16_at(entry, 0);
        assert!(v == 1 || indices.contains(&v), "{name}: version index {v}");
    }

    // The relocations land inside writable sections, and PLT relocations in the GOT.
    let got = parsed.section(".got").unwrap();
    let rela_plt = parsed.section(".rela.plt").unwrap();
    let got_index = parsed
        .sections
        .iter()
        .position(|s| s.name == ".got")
        .unwrap() as u64;
    assert_eq!(
        (rela_plt.info, rela_plt.entsize, dynsym.entsize),
        (got_index, 24, 24),
        "{name}"
    );
    for rela in read(body, rela_plt.offset, rela_plt.size).chunks(24) {
        let at = u64_at(rela, 0);
        assert!(
            at >= got.addr && at + 8 <= got.addr + got.size,
            "{name}: {at:#x}"
        );
        assert_eq!(
            u64_at(rela, 8) & 0xffff_ffff,
            7,
            "{name}: R_X86_64_JUMP_SLOT"
        );
    }
    let rela_dyn = parsed.section(".rela.dyn").unwrap();
    for rela in read(body, rela_dyn.offset, rela_dyn.size).chunks(24) {
        let at = u64_at(rela, 0);
        let target = parsed
            .sections
            .iter()
            .find(|s| s.flags & 3 == 3 && at >= s.addr && at < s.addr + s.size.max(8))
            .unwrap_or_else(|| panic!("{name}: relocation at {at:#x} outside writable data"));
        let _ = file_offset(parsed, target.addr);
    }
}

/// The SysV hash written from the gABI pseudo-code.
fn elf_hash_reference(name: &str) -> u32 {
    let mut h: u32 = 0;
    for c in name.bytes() {
        h = (h << 4) + u32::from(c);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Printable runs of four or more, as `strings` finds them.
fn strings_of(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| !(0x20..=0x7e).contains(b) && *b != b'\t')
        .filter(|run| run.len() >= 4)
        .map(|run| String::from_utf8(run.to_vec()).unwrap())
        .collect()
}

#[test]
fn every_recorded_binary_gets_a_layout_and_none_needs_a_planted_newline() {
    for binary in BINARIES {
        let body = body_of(binary);
        assert!(body.is_structured(), "{}", binary.name);
        assert!(!body.is_planted(), "{}", binary.name);
    }
}

#[test]
fn program_and_section_headers_agree_with_each_other_and_the_file() {
    for binary in BINARIES {
        let body = body_of(binary);
        let parsed = parse(&body, binary.size);
        assert_eq!(
            parsed.phdrs.len() as u64,
            u16_at(binary.header(), 56),
            "{}",
            binary.name
        );
        assert_consistent(binary.name, &parsed, &body);
    }
}

/// `file`: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
/// interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped" for
/// every binary but busybox, which is "ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
/// statically linked, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped", as its recorded header
/// (`ET_EXEC`, ELFOSABI_GNU, ten program headers) says it was built.
#[test]
fn ls_is_a_dynamically_linked_pie_and_busybox_is_static() {
    let ls = binaries::find("ls").unwrap();
    let body = body_of(ls);
    let parsed = parse(&body, ls.size);
    let types: Vec<u64> = parsed.phdrs.iter().map(|p| p.p_type).collect();
    assert_eq!(
        types,
        [
            6,
            3,
            1,
            1,
            1,
            1,
            2,
            4,
            4,
            0x6474_e553,
            0x6474_e550,
            0x6474_e551,
            0x6474_e552
        ],
        "PHDR INTERP LOAD*4 DYNAMIC NOTE*2 GNU_PROPERTY GNU_EH_FRAME GNU_STACK GNU_RELRO"
    );
    let flags: Vec<u64> = parsed.segments(1).iter().map(|p| p.flags).collect();
    assert_eq!(flags, [4, 5, 4, 6], "R, R E, R, RW");
    assert!(parsed.section(".symtab").is_none(), "stripped");

    let busybox = binaries::find("busybox").unwrap();
    let body = body_of(busybox);
    let parsed = parse(&body, busybox.size);
    assert_eq!(parsed.e_type, 2);
    assert!(parsed.segments(3).is_empty(), "no interpreter");
    assert_eq!(parsed.segments(7).len(), 1, "PT_TLS");
    assert_eq!(parsed.segments(1)[0].vaddr, 0x40_0000);
}

/// `strings | head` of an image opens on the loader, the imported names and `libc.so.6` with its
/// `GLIBC_2.x` versions; its usage line and the coreutils boilerplate are further in.
#[test]
fn strings_shows_the_loader_the_imports_the_versions_and_the_usage_line() {
    let ls = binaries::find("ls").unwrap();
    let all = strings_of(&ls.blob().read_range(0, u64::MAX));
    assert_eq!(all[0], INTERP_PATH);
    assert_eq!(all[1], "__libc_start_main");
    let libc = all
        .iter()
        .position(|s| s == "libc.so.6")
        .expect("libc.so.6");
    assert!(libc < 200, "{libc}");
    assert!(all[libc + 1..].iter().take(12).any(|s| s == "GLIBC_2.34"));
    assert!(all[libc + 1..].iter().take(12).any(|s| s == "GLIBC_2.2.5"));
    for wanted in [
        "Usage: %s [OPTION]... [FILE]...",
        "GNU coreutils",
        "Try '%s --help' for more information.",
        ".shstrtab",
        ".gnu_debuglink",
    ] {
        assert!(all.iter().any(|s| s == wanted), "{wanted}");
    }
    let busybox = binaries::find("busybox").unwrap();
    let all = strings_of(&busybox.blob().read_range(0, u64::MAX));
    assert!(!all.iter().any(|s| s.contains("ld-linux")), "static");
    assert!(
        all.iter()
            .any(|s| s == "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.")
    );
}

/// `objdump -d --start-address=<entry>` decodes `endbr64; xor %ebp,%ebp` at the entry point, and
/// each `.plt.sec` stub is `endbr64; bnd jmp *GOT(%rip)` through the GOT slot its JUMP_SLOT
/// relocation names, which is how objdump names it `strerror@plt`.
#[test]
fn the_entry_point_and_the_plt_stubs_decode_as_the_toolchain_writes_them() {
    let ls = binaries::find("ls").unwrap();
    let body = body_of(ls);
    let parsed = parse(&body, ls.size);
    assert_eq!(
        read(&body, file_offset(&parsed, parsed.entry), 6),
        [0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed]
    );
    let plt_sec = parsed.section(".plt.sec").unwrap();
    let rela_plt = parsed.section(".rela.plt").unwrap();
    let relocs = read(&body, rela_plt.offset, rela_plt.size);
    let stubs = read(&body, plt_sec.offset, plt_sec.size);
    assert_eq!(stubs.len() / 16, relocs.len() / 24);
    for (j, stub) in stubs.chunks(16).enumerate() {
        assert_eq!(&stub[..7], &[0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25]);
        let next = plt_sec.addr + 16 * j as u64 + 11;
        let slot = next
            .wrapping_add(i64::from(i32::from_le_bytes(stub[7..11].try_into().unwrap())) as u64);
        assert_eq!(slot, u64_at(&relocs, 24 * j), "stub {j}");
    }
}

#[test]
fn a_body_is_the_same_every_time_it_is_generated() {
    for name in ["ls", "busybox", "true", "uptime"] {
        let binary = binaries::find(name).unwrap();
        let first = binary.blob().read_range(0, u64::MAX);
        assert_eq!(first, binary.blob().read_range(0, u64::MAX), "{name}");
        assert_eq!(first.len() as u64, binary.size, "{name}");
    }
}

/// `true` and `false` have the same recorded header and size; their bodies, build IDs and
/// strings still differ, as two programs' do. No two binaries share a build ID.
#[test]
fn binaries_with_one_header_still_differ_in_body_and_build_id() {
    let truth = binaries::find("true").unwrap();
    let falsity = binaries::find("false").unwrap();
    assert_eq!(truth.header(), falsity.header());
    assert_eq!(truth.size, falsity.size);
    let a = truth.blob().read_range(64, u64::MAX);
    let b = falsity.blob().read_range(64, u64::MAX);
    let differing = a.iter().zip(&b).filter(|(x, y)| x != y).count();
    assert!(differing > a.len() / 2, "{differing} of {}", a.len());

    let mut ids = HashSet::new();
    for binary in BINARIES {
        let body = body_of(binary);
        let parsed = parse(&body, binary.size);
        let note = parsed.section(".note.gnu.build-id").unwrap();
        assert!(
            ids.insert(read(&body, note.offset + 16, 20)),
            "{}",
            binary.name
        );
    }
}

/// A byte costs the same to compute wherever it is: reading the last bytes of the largest image
/// alone gives what a full read gives there, and the layout behind a body is a fixed few
/// kilobytes whatever the image's size.
#[test]
fn a_byte_anywhere_costs_constant_time_and_memory() {
    let perl = binaries::find("perl").unwrap();
    let body = body_of(perl);
    let full = perl.blob().read_range(0, u64::MAX);
    for offset in [0, 63, 64, 409, 4096, perl.size / 2, perl.size - 1] {
        assert_eq!(body.byte_at(offset), full[offset as usize], "{offset}");
        assert_eq!(
            perl.image().byte_at(offset),
            full[offset as usize],
            "{offset}"
        );
    }
    assert!(
        std::mem::size_of::<Layout>() < 8 * 1024,
        "{}",
        std::mem::size_of::<Layout>()
    );
    assert!(std::mem::size_of::<ElfBody>() < 256);
    assert!(std::mem::size_of::<ElfImage>() <= 112);
}

/// The first newline a line reader meets: `ls` at 409 (the recorded `head -n 1`), one its
/// recorded header carries (busybox's `e_phnum` is 10, ip's `e_shoff` has a `0x0a` byte), and for
/// the rest wherever their layout puts it, past the header.
#[test]
fn the_first_newline_is_where_each_image_says() {
    for binary in BINARIES {
        let bytes = binary.blob().read_range(0, 4096);
        let first = bytes.iter().position(|b| *b == 0x0a).map(|at| at as u64);
        let in_header = binary.header().iter().position(|b| *b == 0x0a);
        match (binary.name, in_header) {
            ("ls", _) => assert_eq!(first, Some(binaries::LS_FIRST_NEWLINE)),
            (_, Some(at)) => assert_eq!(first, Some(at as u64), "{}", binary.name),
            (name, None) => assert!(first.is_none_or(|at| at >= 64), "{name}: {first:?}"),
        }
    }
    assert_eq!(binaries::find("busybox").unwrap().header()[56], 0x0a);
    // ls carries it in PT_DYNAMIC's p_offset, not as a byte written over the layout.
    let ls = binaries::find("ls").unwrap();
    let body = body_of(ls);
    let parsed = parse(&body, ls.size);
    assert_eq!(parsed.phdrs[6].p_type, 2);
    assert_eq!((parsed.phdrs[6].offset >> 8) & 0xff, 0x0a);
}

/// A header the generator has no layout for keeps the filler body, newline plant included.
#[test]
fn a_header_without_a_layout_keeps_the_filler() {
    let mut header = *binaries::find("cat").unwrap().header();
    header[18] = 0x28; // EM_ARM
    let image = ElfImage {
        header,
        len: 500,
        newline_at: Some(200),
        name: "cat",
    };
    let body = image.body();
    assert!(!body.is_structured());
    for i in 64..500u64 {
        let want = if i == 200 {
            0x0a
        } else {
            0x80 | (i & 0x3f) as u8
        };
        assert_eq!(body.byte_at(i), want);
    }
}

/// When no import count puts the first newline where an image asks, the newline is planted and
/// every earlier one in the body is changed, so line readers still see the image's first line.
#[test]
fn a_newline_no_layout_can_place_is_planted() {
    let cat = binaries::find("cat").unwrap();
    let image = ElfImage {
        newline_at: Some(70),
        ..cat.image()
    };
    let body = image.body();
    assert!(body.is_structured() && body.is_planted());
    let bytes = read(&body, 0, 200);
    assert_eq!(bytes.iter().position(|b| *b == 0x0a), Some(70));
}

/// The modeled daemons behind `/proc/<pid>/exe` are laid out from the generic header too, with
/// the section headers moved to the end of each file.
#[test]
fn the_generic_daemon_header_lays_out_at_every_modeled_size() {
    let mut header = *binaries::find("ls").unwrap().header();
    for (name, len) in [
        ("cron", 56_048u64),
        ("systemd", 1_841_488),
        ("agetty", 64_840),
    ] {
        header[40..48].copy_from_slice(&((len - 31 * 64) / 8 * 8).to_le_bytes());
        header[24..32].copy_from_slice(&0x6b40u64.to_le_bytes());
        let image = ElfImage {
            header,
            len,
            newline_at: None,
            name,
        };
        let body = image.body();
        assert!(body.is_structured(), "{name}");
        assert_consistent(name, &parse(&body, len), &body);
    }
}
