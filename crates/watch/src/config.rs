//! Where the sensor-log list comes from. `PROPOLIS_SENSOR_LOGS` in the environment wins, for a
//! local run that sets it; otherwise the watcher reads the copy `deploy/watch-env.sh` derives from
//! the daemon's env file into [`WATCH_ENV_PATH`]. That file is opened read-only and only the one
//! key is looked at: the watcher has no use for any other value, and the deploy script guarantees
//! there is none to find.

use std::io::Read;
use std::path::Path;

/// Written by `deploy/watch-env.sh`, root:propolis-watch 0640. Fixed, not configurable: the
/// forced command runs with no arguments the owner controls and no environment worth trusting.
pub const WATCH_ENV_PATH: &str = "/etc/propolis/watch.env";

pub const SENSOR_LOGS_KEY: &str = "PROPOLIS_SENSOR_LOGS";

/// The derived file is one line; anything near this size is not the file the script writes.
const MAX_WATCH_ENV_BYTES: u64 = 64 * 1024;

/// The raw list and a name for where it came from (`env`, or the file's path), which the start
/// record and every heartbeat repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorLogsSource {
    pub raw: String,
    pub from: String,
}

/// The value of the last uncommented `PROPOLIS_SENSOR_LOGS=` line in `path`, with one layer of
/// matching surrounding quotes removed, the same reading `deploy/fleet-listeners.sh` gives an env
/// file. Every other line is skipped unread.
pub fn sensor_logs_from_file(path: &Path) -> Result<SensorLogsSource, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_WATCH_ENV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_WATCH_ENV_BYTES {
        return Err(format!(
            "{} is larger than {MAX_WATCH_ENV_BYTES} bytes",
            path.display()
        ));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
    let prefix = format!("{SENSOR_LOGS_KEY}=");
    let value = text
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(prefix.as_str()))
        .next_back()
        .ok_or_else(|| format!("{} sets no {SENSOR_LOGS_KEY}", path.display()))?;
    Ok(SensorLogsSource {
        raw: unquote(value.trim_end()).to_string(),
        from: path.display().to_string(),
    })
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}
