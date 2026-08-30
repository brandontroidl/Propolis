//! Event emission: the single path every sensor uses to append a `sensor-wire` record to its
//! local NDJSON log. See "Event emission" and "Transport" in
//! `internal/design/02-sensor-framework.md`: the sensor never talks to intake directly, so an
//! event exists once (and only once) it lands as a complete line in this file. The error-handling
//! rule this module enforces - "if an event cannot be serialized or appended, ... a sensor never
//! ... partially writes an event line" - is a framework guarantee, not left to each sensor to get
//! right independently.

use std::path::PathBuf;

use sensor_wire::SensorEvent;
use tokio::io::AsyncWriteExt;

pub struct EventEmitter {
    log_path: PathBuf,
}

impl EventEmitter {
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// Serialize `event` and append it as one NDJSON line.
    ///
    /// Every sensor connection appends through the same `EventEmitter` concurrently in
    /// production (it is held behind an `Arc` by the capture hand-off and by each per-connection
    /// handler), so this opens the log with `O_APPEND` (`OpenOptions::append`) and issues exactly
    /// one `write_all` of the whole line rather than seeking manually. Per `open(2)`: "the
    /// modification of the file offset and the write operation are performed as a single atomic
    /// step" for O_APPEND on a local filesystem, so concurrent appenders' lines are serialized,
    /// never interleaved or overwritten - this is not a size-dependent guarantee (it does not
    /// come from PIPE_BUF, which governs pipes, not regular files) and it does not extend to NFS,
    /// where the client kernel simulates O_APPEND and can race; the log directory must be local
    /// storage, consistent with the one-directional-channel model already assuming a local mount.
    ///
    /// `flush().await` is required, not decorative: `tokio::fs::File`'s `poll_write` hands the
    /// buffer to a background blocking-pool task and returns before that task has necessarily
    /// run, so a caller that skipped the flush could observe `append` return before the OS
    /// `write(2)` had actually executed.
    pub async fn append(&self, event: &SensorEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensor_wire::*;

    fn sample_event() -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
            metadata: serde_json::json!({"command": "uname -a"}),
            sample: None,
            session_id: None,
            occurrence_id: None,
        }
    }

    #[tokio::test]
    async fn append_produces_valid_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        emitter.append(&sample_event()).await.unwrap();
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed, sample_event());
    }

    #[tokio::test]
    async fn multiple_appends_produce_separate_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        for _ in 0..5 {
            emitter.append(&sample_event()).await.unwrap();
        }
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in &lines {
            let _: SensorEvent = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn emitted_line_has_no_embedded_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        emitter.append(&sample_event()).await.unwrap();
        let bytes = tokio::fs::read(&log_path).await.unwrap();
        // Exactly one newline, at the end.
        let newline_count = bytes.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(newline_count, 1);
        assert_eq!(*bytes.last().unwrap(), b'\n');
    }

    // Not in the brief's given suite. None of the three tests above call `append` from more than
    // one task, so none can distinguish this correct, stateless-`OpenOptions`-per-call
    // implementation from a plausible but broken alternative - e.g. one that caches a single open
    // file handle and tracks a "next offset" in memory to seek to before writing, which races
    // under concurrent callers and can interleave or clobber another task's bytes. Every sensor
    // connection is handled by its own spawned task and all of them append through one shared
    // `EventEmitter` (see the module doc and Task 6's hand-off), so concurrent calls are the real
    // production access pattern, not an edge case.
    #[tokio::test]
    async fn concurrent_appends_do_not_corrupt_or_lose_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = std::sync::Arc::new(EventEmitter::new(log_path.clone()));

        const TASKS: u64 = 20;
        const PER_TASK: u64 = 5;
        let mut handles = Vec::with_capacity(TASKS as usize);
        for task_id in 0..TASKS {
            let emitter = emitter.clone();
            handles.push(tokio::spawn(async move {
                for seq in 0..PER_TASK {
                    let mut event = sample_event();
                    event.metadata = serde_json::json!({ "task_id": task_id, "seq": seq });
                    emitter.append(&event).await.unwrap();
                }
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len() as u64,
            TASKS * PER_TASK,
            "line count must match appends issued: no line lost or merged under concurrency"
        );

        let mut seen = std::collections::HashSet::new();
        for line in &lines {
            let event: SensorEvent = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("corrupted or interleaved line ({e}): {line:?}"));
            let task_id = event.metadata["task_id"].as_u64().unwrap();
            let seq = event.metadata["seq"].as_u64().unwrap();
            assert!(
                seen.insert((task_id, seq)),
                "duplicate (task_id, seq) pair {task_id:?}/{seq:?}: a line was double-counted"
            );
        }
        assert_eq!(seen.len() as u64, TASKS * PER_TASK);
    }
}
