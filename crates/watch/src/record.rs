//! The output envelope. Every line the watcher writes is one JSON object whose `kind` is one of
//! `start`, `event`, `dropped`, `journal`, `heartbeat` or `error`, built only here, and every line
//! passes through [`bounded`] on its way out, so each is valid UTF-8 JSON on a single line and no
//! longer than [`MAX_OUTPUT_LINE_BYTES`].
//!
//! An event line that parses as a JSON object is embedded byte for byte rather than re-serialized:
//! a reader debugging a sensor sees exactly what the sensor wrote (key order, duplicate keys,
//! number formatting), which a parse-and-print round trip would hide. Attacker-controlled strings
//! inside it were sanitized by the sensor; JSON string escaping keeps any control byte that got
//! through visible as an escape rather than acted on by a terminal.

use std::net::IpAddr;
use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};

use crate::args::Options;
use crate::status::FileStatus;

/// Upper bound on one output line. A log line is at most `log_tailer::MAX_LINE_BYTES` (1 MiB);
/// JSON escaping can grow a non-JSON line up to six times (`\u001b` for one control byte), so a
/// line the tailer accepted always fits and the bound only ever catches a record that should not
/// exist.
pub const MAX_OUTPUT_LINE_BYTES: usize = 8 * 1024 * 1024;

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The filters from the arguments, applied to event and dropped records.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    sensors: Vec<String>,
    signal: Option<String>,
    source_ip: Option<IpAddr>,
}

impl Filter {
    pub fn from_options(options: &Options) -> Self {
        Self {
            sensors: options.sensors.clone(),
            signal: options.signal.clone(),
            source_ip: options.source_ip,
        }
    }

    pub fn keeps_label(&self, label: &str) -> bool {
        self.sensors.is_empty() || self.sensors.iter().any(|s| s == label)
    }

    /// `event` is `None` for a line that is not a JSON object; it can match no field filter.
    fn keeps_event(&self, event: Option<&Map<String, Value>>) -> bool {
        if let Some(signal) = &self.signal {
            let found = event
                .and_then(|e| e.get("signal_type"))
                .and_then(Value::as_str);
            if found != Some(signal.as_str()) {
                return false;
            }
        }
        if let Some(ip) = self.source_ip {
            let found = event
                .and_then(|e| e.get("source_ip"))
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<IpAddr>().ok())
                .map(|a| a.to_canonical());
            if found != Some(ip) {
                return false;
            }
        }
        true
    }
}

pub fn start(
    version: &str,
    sources: &[(String, &Path)],
    sources_from: &str,
    options: &Options,
) -> Value {
    json!({
        "kind": "start",
        "ts": now(),
        "version": version,
        "sources": sources
            .iter()
            .map(|(label, path)| json!({"label": label, "path": path_text(path)}))
            .collect::<Vec<_>>(),
        "sources_from": sources_from,
        "start_at": if options.since_start { "beginning" } else { "end" },
        "journal": options.journal,
        "filters": {
            "sensor": options.sensors,
            "signal": options.signal,
            "source_ip": options.source_ip.map(|ip| ip.to_string()),
        },
    })
}

pub struct FileReport<'a> {
    pub label: &'a str,
    pub path: &'a Path,
    pub status: FileStatus,
    pub size: Option<u64>,
    pub lines_seen: u64,
}

pub fn heartbeat(files: &[FileReport<'_>], sources_from: &str) -> Value {
    json!({
        "kind": "heartbeat",
        "ts": now(),
        "sources_from": sources_from,
        "files": files
            .iter()
            .map(|f| json!({
                "label": f.label,
                "path": path_text(f.path),
                "status": f.status.as_str(),
                "size": f.size,
                "lines_seen": f.lines_seen,
            }))
            .collect::<Vec<_>>(),
    })
}

pub fn error(source: &str, message: &str) -> Value {
    json!({"kind": "error", "ts": now(), "source": source, "message": message})
}

pub fn dropped_line(label: &str, path: &Path, bytes: u64) -> Value {
    json!({
        "kind": "dropped",
        "reason": "line_too_long",
        "label": label,
        "path": path_text(path),
        "bytes": bytes,
        "max_bytes": log_tailer::MAX_LINE_BYTES,
    })
}

/// One log line as an `event` record, or `None` when the filter drops it.
pub fn event_line(label: &str, path: &Path, line: &str, filter: &Filter) -> Option<String> {
    if !filter.keeps_label(label) {
        return None;
    }
    let parsed = serde_json::from_str::<Value>(line).ok();
    let object = parsed.as_ref().and_then(Value::as_object);
    if !filter.keeps_event(object) {
        return None;
    }
    Some(match object {
        // Both strings are valid JSON produced by serde_json, and `line` was just parsed as one
        // JSON object, so the concatenation is one valid JSON object. `line` holds no `\n`: the
        // tailer split on it.
        Some(_) => format!(
            r#"{{"kind":"event","label":{},"path":{},"event":{}}}"#,
            Value::from(label),
            Value::from(path_text(path)),
            line
        ),
        None => json!({
            "kind": "event",
            "label": label,
            "path": path_text(path),
            "raw": line,
        })
        .to_string(),
    })
}

/// One `journalctl -o json` entry as a `journal` record. journald sends `MESSAGE` as an array of
/// bytes when it is not valid UTF-8; that is decoded lossily rather than dropped.
pub fn journal_record(entry: &Value) -> Value {
    let text = |key: &str| entry.get(key).and_then(Value::as_str);
    let message = match entry.get("MESSAGE") {
        Some(Value::String(s)) => Value::from(s.as_str()),
        Some(Value::Array(bytes)) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|b| u8::try_from(b).ok())
                .collect();
            Value::from(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => Value::Null,
    };
    let ts = text("__REALTIME_TIMESTAMP")
        .and_then(|us| us.parse::<i64>().ok())
        .and_then(DateTime::from_timestamp_micros)
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Micros, true));
    json!({
        "kind": "journal",
        "unit": text("_SYSTEMD_UNIT"),
        "priority": text("PRIORITY").and_then(|p| p.parse::<u8>().ok()),
        "message": message,
        "ts": ts,
    })
}

/// `line` if it fits [`MAX_OUTPUT_LINE_BYTES`], otherwise a `dropped` record saying it did not.
pub fn bounded(line: String, label: Option<&str>) -> String {
    if line.len() <= MAX_OUTPUT_LINE_BYTES {
        return line;
    }
    json!({
        "kind": "dropped",
        "reason": "record_too_long",
        "label": label,
        "bytes": line.len(),
        "max_bytes": MAX_OUTPUT_LINE_BYTES,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(line: &str) -> Value {
        assert!(!line.contains('\n'), "one record per line: {line}");
        serde_json::from_str(line).unwrap()
    }

    fn filter(raw: &str) -> Filter {
        match crate::args::parse(crate::args::ssh_command_tokens(raw)).unwrap() {
            crate::args::Request::Watch(o) => Filter::from_options(&o),
            other => panic!("{other:?}"),
        }
    }

    const EVENT: &str = r#"{"v":1,"source_ip":"192.0.2.7","sensor":"ssh","signal_type":"honeypot_login_attempt","z":1,"a":2}"#;

    #[test]
    fn an_event_object_is_embedded_byte_for_byte() {
        let line = event_line("ssh", Path::new("/l/ssh.jsonl"), EVENT, &Filter::default()).unwrap();
        assert!(line.ends_with(&format!(r#""event":{EVENT}}}"#)), "{line}");
        let v = decode(&line);
        assert_eq!(v["kind"], "event");
        assert_eq!(v["label"], "ssh");
        assert_eq!(v["path"], "/l/ssh.jsonl");
        assert_eq!(v["event"]["signal_type"], "honeypot_login_attempt");
        assert!(v.get("raw").is_none());
    }

    #[test]
    fn a_line_that_is_not_a_json_object_is_carried_as_raw_text() {
        for raw in ["not json", "42", "[1,2]", "{\"broken\":", "\u{1b}[31mred"] {
            let v = decode(&event_line("ssh", Path::new("/l"), raw, &Filter::default()).unwrap());
            assert_eq!(v["kind"], "event");
            assert_eq!(v["raw"], raw);
            assert!(v.get("event").is_none());
        }
        let escaped = event_line("ssh", Path::new("/l"), "\u{1b}[31m", &Filter::default()).unwrap();
        assert!(
            escaped.contains("\\u001b"),
            "control bytes stay escaped: {escaped}"
        );
    }

    #[test]
    fn filters_narrow_events_and_a_raw_line_matches_no_field_filter() {
        let p = Path::new("/l");
        assert!(event_line("ssh", p, EVENT, &filter("--sensor ssh")).is_some());
        assert!(event_line("ftp", p, EVENT, &filter("--sensor ssh")).is_none());
        assert!(event_line("ssh", p, EVENT, &filter("--signal honeypot_login_attempt")).is_some());
        assert!(event_line("ssh", p, EVENT, &filter("--signal catchall_probe")).is_none());
        assert!(event_line("ssh", p, EVENT, &filter("--source-ip 192.0.2.7")).is_some());
        assert!(event_line("ssh", p, EVENT, &filter("--source-ip ::ffff:192.0.2.7")).is_some());
        assert!(event_line("ssh", p, EVENT, &filter("--source-ip 192.0.2.8")).is_none());
        assert!(event_line("ssh", p, "garbage", &filter("--signal x")).is_none());
        assert!(event_line("ssh", p, "garbage", &filter("--sensor ssh")).is_some());
    }

    #[test]
    fn every_record_kind_has_its_documented_shape() {
        let options = Options {
            sensors: vec!["ssh".into()],
            journal: true,
            ..Options::default()
        };
        let path = Path::new("/l/ssh.jsonl");
        let start = start("0.4.0", &[("ssh".to_string(), path)], "env", &options);
        assert_eq!(start["sources_from"], "env");
        assert_eq!(start["kind"], "start");
        assert_eq!(start["version"], "0.4.0");
        assert_eq!(start["sources"][0]["label"], "ssh");
        assert_eq!(start["start_at"], "end");
        assert_eq!(start["filters"]["sensor"][0], "ssh");

        let hb = heartbeat(
            &[FileReport {
                label: "ssh",
                path,
                status: FileStatus::Missing,
                size: None,
                lines_seen: 3,
            }],
            "/etc/propolis/watch.env",
        );
        assert_eq!(hb["sources_from"], "/etc/propolis/watch.env");
        assert_eq!(hb["kind"], "heartbeat");
        assert!(hb["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(
            hb["files"][0],
            json!({"label":"ssh","path":"/l/ssh.jsonl","status":"missing","size":null,"lines_seen":3})
        );

        let dropped = dropped_line("ssh", path, 2_000_000);
        assert_eq!(dropped["kind"], "dropped");
        assert_eq!(dropped["reason"], "line_too_long");
        assert_eq!(dropped["bytes"], 2_000_000);

        let err = error("journal", "journalctl not found");
        assert_eq!(err["kind"], "error");
        assert_eq!(err["source"], "journal");
    }

    #[test]
    fn a_journal_entry_maps_unit_priority_message_and_time() {
        let entry = json!({
            "_SYSTEMD_UNIT": "sensor-ssh.service",
            "PRIORITY": "4",
            "MESSAGE": "listener up",
            "__REALTIME_TIMESTAMP": "1700000000123456",
        });
        assert_eq!(
            journal_record(&entry),
            json!({
                "kind": "journal",
                "unit": "sensor-ssh.service",
                "priority": 4,
                "message": "listener up",
                "ts": "2023-11-14T22:13:20.123456Z",
            })
        );
        let bytes = json!({"MESSAGE": [104, 105, 255]});
        assert_eq!(journal_record(&bytes)["message"], "hi\u{fffd}");
        assert_eq!(journal_record(&json!({}))["unit"], Value::Null);
    }

    #[test]
    fn an_oversized_line_becomes_a_dropped_record() {
        let big = "x".repeat(MAX_OUTPUT_LINE_BYTES + 1);
        let v = decode(&bounded(big, Some("ssh")));
        assert_eq!(v["kind"], "dropped");
        assert_eq!(v["reason"], "record_too_long");
        assert_eq!(v["bytes"], MAX_OUTPUT_LINE_BYTES + 1);
        assert_eq!(bounded("{}".into(), None), "{}");
    }
}
