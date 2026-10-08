//! Echo-loader reassembly: the file an attacker builds by redirecting `echo`/`printf` output into
//! it chunk by chunk, captured as one sample.
//!
//! A Mirai or Mozi telnet loader that finds no usable `wget` uploads a small downloader as some
//! forty `busybox echo -ne '\xNN...' >> .i` lines, makes it executable and runs it with the
//! stage-2 server's address as arguments. Each line is a command event; without this module the
//! file they build was never captured, and the loader, seeing its downloader fetch nothing,
//! retried the whole sequence every few minutes.
//!
//! The shell notes every file written by a command whose output carries typed bytes, with how
//! many writes built it and a digest of what the last one left. When such a file is made
//! executable or run, its bytes go to the session's [`StdinCaptures`] once the line has run, at
//! most once per distinct digest; a file still assembled when the session ends is taken then. The
//! digest, not the path, decides whether a file is an assembly, so the loader's own fallback
//! (`cp /bin/ls .j && cat .i>.j && rm .i && cp .j .i`) still finds `.i` to be the chunks it wrote.
//!
//! Running an assembled ELF with `<a> <b> <c> <d> <port>` as its arguments, when its bytes hold an
//! HTTP request line, also yields the URL it would have fetched, emitted as a
//! `honeypot_file_download` event marked `derived_from: echo_loader_args`. That event is data for
//! the review fetcher, which vets it like any other URL; nothing here, and nothing in the sensor,
//! opens a connection, and nothing runs the file.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use sensor_wire::{PROTO_TCP, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent, WIRE_VERSION};
use sha2::{Digest, Sha256};

use super::{FakeShell, MAX_URL_LEN, TraceEventKind, len_u64};
use crate::fakefs::READ_CAP;
use crate::held_input::{AssembledFile, StdinCaptures, TrackedFile};
use crate::sanitize_value;

/// `metadata.derived_from` of a download URL read off an assembled downloader's arguments.
pub const DERIVED_FROM_ECHO_LOADER_ARGS: &str = "echo_loader_args";

/// Assembled files one shell keeps. A loader builds one; the bound only keeps a session that
/// writes many small files from growing the map.
const MAX_ASSEMBLED: usize = 16;

/// The longest request path read out of a downloader.
const MAX_REQUEST_PATH: usize = 255;

/// A file built from typed bytes, as its last chunk left it.
#[derive(Clone, Debug)]
pub(super) struct Assembled {
    sha256: [u8; 32],
    len: u64,
    chunks: u32,
    /// The line that wrote the last chunk.
    command: String,
}

/// The bytes a `base64 -d` decoded from typed input, and how many typed writes built that input.
#[derive(Clone, Debug)]
pub(super) struct Decoded {
    sha256: [u8; 32],
    chunks: u32,
}

/// What one line found for the capture, acted on by [`FakeShell::flush_loader`] once the line
/// has run, so a line run only to learn whether it waits for input leaves nothing behind.
#[derive(Clone, Debug, Default)]
pub(super) struct LineLoader {
    files: Vec<AssembledFile>,
    /// Stage-2 URLs derived on the line, each with the digest of the downloader it came from.
    pub(super) urls: Vec<(String, [u8; 32])>,
    /// The assembled file this line wrote a chunk of, and that chunk's number.
    chunk: Option<(String, u32)>,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl FakeShell {
    /// The same shell capturing the files it sees assembled from typed bytes into `captures`,
    /// the session's stdin capture set, so one body is one sample however it arrived.
    pub fn with_captures(mut self, captures: StdinCaptures) -> Self {
        self.captures = Some(captures);
        self
    }

    /// Whether the file at `path` is one this shell is tracking as an assembly of typed bytes.
    #[cfg(test)]
    pub(super) fn is_assembled(&self, path: &str) -> bool {
        self.assembled.contains_key(path)
    }

    /// The running command wrote `out`, bytes the attacker typed, to its standard output.
    pub(super) fn note_typed_output(&mut self, out: &[u8]) {
        if !out.is_empty() {
            self.typed_output = true;
        }
    }

    /// `decoded` is what a `base64 -d` just made from `input`, which the attacker typed when it is
    /// piped from typed output or is a file an assembly of this session left. The decode is noted
    /// so the file it lands in counts as many chunks as its source did.
    pub(super) fn note_decoded(&mut self, input: &[u8], from_pipe: bool, decoded: &[u8]) {
        let chunks = if from_pipe && self.piped_typed {
            Some(1)
        } else {
            let sha256 = digest(input);
            self.assembled
                .values()
                .find(|known| known.sha256 == sha256)
                .map(|known| known.chunks)
        };
        if let Some(chunks) = chunks {
            self.note_typed_output(decoded);
            self.decoded = Some(Decoded {
                sha256: digest(decoded),
                chunks,
            });
        }
    }

    /// Pick up the assemblies other shells of this session left, so a loader that runs each
    /// command as its own `shell:<command>` stream (`adb shell CMD`) builds one file across them.
    /// A path this shell already knows keeps its own, newer, record.
    pub(super) fn import_assembled(&mut self) {
        let Some(captures) = &self.captures else {
            return;
        };
        for file in captures.tracked_assembled() {
            if self.assembled.len() >= MAX_ASSEMBLED {
                break;
            }
            self.assembled
                .entry(file.path.clone())
                .or_insert(Assembled {
                    sha256: file.sha256,
                    len: file.len,
                    chunks: file.chunk_count,
                    command: file.command,
                });
        }
    }

    /// Typed bytes reached the file `path`: it held `prior` before the write and `content` after.
    /// A write to an empty file starts an assembly (of as many chunks as the input of a decode
    /// that made `content` was); one appended to an assembly as its last chunk
    /// left it adds a chunk. Appending to anything else (a system file, an assembly something
    /// else has changed since) is not one: what the file holds is not all the attacker's.
    pub(super) fn note_typed_write(&mut self, path: &str, prior: &[u8], content: &[u8]) {
        let chunks = if prior.is_empty() {
            self.decoded
                .as_ref()
                .filter(|decoded| decoded.sha256 == digest(content))
                .map_or(1, |decoded| decoded.chunks)
        } else {
            match self.assembled.get(path) {
                Some(known)
                    if known.len == len_u64(prior.len()) && known.sha256 == digest(prior) =>
                {
                    known.chunks.saturating_add(1)
                }
                _ => {
                    self.assembled.remove(path);
                    return;
                }
            }
        };
        if !self.assembled.contains_key(path) && self.assembled.len() >= MAX_ASSEMBLED {
            return;
        }
        self.assembled.insert(
            path.to_string(),
            Assembled {
                sha256: digest(content),
                len: len_u64(content.len()),
                chunks,
                command: self.line_command.clone(),
            },
        );
        self.loader_line.chunk = Some((path.to_string(), chunks));
    }

    /// The bytes of the file at `path` and the assembly they are, when it holds exactly what an
    /// assembly of this session left in some file: its own, or the one a copy came from.
    fn assembled_content(&self, path: &str) -> Option<(Vec<u8>, Assembled)> {
        let size = self.fs.stat(path, true)?.size;
        // Only a file of an assembly's size is read and hashed, so running `/bin/ls` costs
        // nothing here.
        if size == 0 || !self.assembled.values().any(|known| known.len == size) {
            return None;
        }
        let bytes = self.fs.read_all(path, size.min(READ_CAP)).ok()?;
        let sha256 = digest(&bytes);
        let known = self
            .assembled
            .get(path)
            .filter(|known| known.sha256 == sha256)
            .or_else(|| self.assembled.values().find(|known| known.sha256 == sha256))?
            .clone();
        Some((bytes, known))
    }

    /// `path` was made executable or is being run. When it is an assembled file it is handed to
    /// the capture once the line has run, and its bytes come back.
    pub(super) fn loader_trigger(&mut self, path: &str) -> Option<Vec<u8>> {
        let (bytes, known) = self.assembled_content(path)?;
        let queued = self
            .loader_line
            .files
            .iter()
            .any(|file| digest(&file.bytes) == known.sha256);
        if !queued {
            self.loader_line.files.push(AssembledFile {
                path: path.to_string(),
                bytes: bytes.clone(),
                chunk_count: known.chunks,
                command: known.command,
            });
        }
        Some(bytes)
    }

    /// `parts` runs the executable at `path`. True when it is an assembled ELF downloader given a
    /// stage-2 address: its URL is noted for the line's events and the caller answers as the
    /// downloader does when its server cannot be reached, which is the only outcome this box can
    /// offer since nothing here connects anywhere. That is no output and status 1: the stage-1
    /// downloaders of this family exit nonzero on a failed connect without printing, and the
    /// loader's next command (`./Runn`) then finds no stage 2 [unverified: the exact status of
    /// this sample]. Anything else runs as `run_saved_executable` decides.
    pub(super) fn loader_exec(&mut self, parts: &[&str], path: &str) -> bool {
        let Some(bytes) = self.loader_trigger(path) else {
            return false;
        };
        if !bytes.starts_with(b"\x7fELF") {
            return false;
        }
        let Some(url) = stage2_url(parts.get(1..).unwrap_or_default(), &bytes) else {
            return false;
        };
        self.loader_line.urls.push((url, digest(&bytes)));
        true
    }

    /// Act on what the line found once it has run: mark its command event as a chunk of the
    /// file it wrote, emit the derived URLs, submit the files it made executable or ran, and
    /// report every assembly to the capture set for the session's end.
    pub(super) fn flush_loader(&mut self, events: &mut Vec<SensorEvent>) {
        let line = std::mem::take(&mut self.loader_line);
        if let Some((path, index)) = &line.chunk
            && self.trace.events.first() == Some(&TraceEventKind::CommandExec)
            && let Some(object) = events
                .first_mut()
                .and_then(|event| event.metadata.as_object_mut())
        {
            object.insert(
                "assembled_file".to_string(),
                serde_json::json!(sanitize_value(path, MAX_URL_LEN)),
            );
            object.insert("chunk_index".to_string(), serde_json::json!(index));
        }
        for (url, sha256) in line.urls {
            if !self.budget().download_allowed() {
                break;
            }
            self.trace.events.push(TraceEventKind::FileDownload);
            events.push(SensorEvent {
                v: WIRE_VERSION,
                source_ip: self.ctx.source_ip,
                wan_ip: self.ctx.wan_ip,
                sensor: self.ctx.protocol_label.clone(),
                signal_type: SIGNAL_HONEYPOT_FILE_DOWNLOAD.into(),
                protocol: PROTO_TCP.into(),
                authenticated: self.ctx.authenticated,
                observed_at: (self.clock)(),
                metadata: serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "url": sanitize_value(&url, MAX_URL_LEN),
                    "derived_from": DERIVED_FROM_ECHO_LOADER_ARGS,
                    "derived_sha256": hex(&sha256),
                }),
                sample: None,
                session_id: self.ctx.session_id,
                occurrence_id: None,
            });
        }
        let Some(captures) = &self.captures else {
            return;
        };
        for file in line.files {
            captures.record_assembled(file);
        }
        if !self.assembled.is_empty() {
            let tracked = self
                .assembled
                .iter()
                .map(|(path, known)| TrackedFile {
                    path: path.clone(),
                    sha256: known.sha256,
                    len: known.len,
                    chunk_count: known.chunks,
                    command: known.command.clone(),
                })
                .collect();
            captures.track_assembled(&self.fs, tracked);
        }
    }
}

/// The URL a downloader run as `PROG a b c d port` fetches, when `args` are four decimal octets
/// and a port and `image` holds an HTTP/1.x request line: `http://a.b.c.d:port/path`.
fn stage2_url(args: &[&str], image: &[u8]) -> Option<String> {
    let [a, b, c, d, port] = args else {
        return None;
    };
    let octet = |text: &str| -> Option<u8> {
        (!text.is_empty() && text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    };
    let (a, b, c, d) = (octet(a)?, octet(b)?, octet(c)?, octet(d)?);
    let port: u16 =
        (!port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()))
            .then(|| port.parse().ok())
            .flatten()
            .filter(|port| *port != 0)?;
    let path = request_path(image)?;
    Some(format!("http://{a}.{b}.{c}.{d}:{port}{path}"))
}

/// The path of the first `GET <path> HTTP/1.<digit>` request line in `image`: printable ASCII
/// starting with `/`, at most [`MAX_REQUEST_PATH`] bytes.
fn request_path(image: &[u8]) -> Option<String> {
    const VERB: &[u8] = b"GET ";
    const VERSION: &[u8] = b" HTTP/1.";
    let mut from = 0usize;
    while let Some(at) = image
        .get(from..)?
        .windows(VERB.len())
        .position(|window| window == VERB)
    {
        let start = from.saturating_add(at).saturating_add(VERB.len());
        from = start;
        let rest = image.get(start..)?;
        let Some(end) = rest.iter().position(|&byte| byte == b' ') else {
            continue;
        };
        let path = rest.get(..end)?;
        let tail = rest.get(end..)?;
        let versioned = tail.starts_with(VERSION)
            && tail
                .get(VERSION.len())
                .is_some_and(|byte| byte.is_ascii_digit());
        if versioned
            && path.first() == Some(&b'/')
            && path.len() <= MAX_REQUEST_PATH
            && path.iter().all(|&byte| (0x21..=0x7e).contains(&byte))
        {
            return String::from_utf8(path.to_vec()).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_and_an_address_make_the_stage2_url() {
        let image = b"\x7fELF..\0/proc/self/cmdline\0Runn\0GET /Mozi.6 HTTP/1.0\r\n\r\n\0";
        assert_eq!(
            stage2_url(&["198", "51", "100", "23", "3912"], image).as_deref(),
            Some("http://198.51.100.23:3912/Mozi.6")
        );
    }

    #[test]
    fn anything_short_of_four_octets_and_a_port_derives_nothing() {
        let image = b"GET /x HTTP/1.1\r\n";
        for args in [
            &["198", "51", "100", "3912"][..],
            &["198", "51", "100", "256", "3912"],
            &["198", "51", "100", "23", "0"],
            &["198", "51", "100", "23", "65536"],
            &["198", "51", "100", "+2", "80"],
            &["198", "51", "100", "23", "80", "extra"],
        ] {
            assert_eq!(stage2_url(args, image), None, "{args:?}");
        }
    }

    #[test]
    fn only_a_versioned_request_line_with_a_printable_path_counts() {
        for image in [
            &b"GET /x HTTP/2.0"[..],
            b"GET x HTTP/1.0",
            b"GET /a\x01b HTTP/1.0",
            b"GET /x HTTP/1.",
            b"POST /x HTTP/1.0",
        ] {
            assert_eq!(request_path(image), None, "{image:?}");
        }
        // The first well-formed line wins over an earlier malformed one.
        assert_eq!(
            request_path(b"GET broken GET /b.sh HTTP/1.1").as_deref(),
            Some("/b.sh")
        );
    }
}
