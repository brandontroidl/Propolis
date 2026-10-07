//! `propolis-watch` entry point: parse the allowlisted arguments (argv, then the SSH client's
//! command), find `PROPOLIS_SENSOR_LOGS` (the environment, else `/etc/propolis/watch.env`), and
//! stream. Exit status: 0 when stdout closes (the reader went away), 1 when no valid list is
//! found, 2 on a usage error.

use std::collections::BTreeSet;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use std::path::Path;

use watch::args::{self, Request, USAGE, UsageError};
use watch::config::{self, SENSOR_LOGS_KEY, SensorLogsSource};
use watch::{record, watcher};

/// Set by sshd for a forced command to whatever the client asked to run.
const ENV_SSH_COMMAND: &str = "SSH_ORIGINAL_COMMAND";

fn main() -> ExitCode {
    let options = match arguments().and_then(args::parse) {
        Ok(Request::Watch(options)) => options,
        Ok(Request::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => return usage_error(&e.to_string()),
    };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let source = match std::env::var(SENSOR_LOGS_KEY) {
        Ok(raw) => Ok(SensorLogsSource {
            raw,
            from: "env".to_string(),
        }),
        Err(std::env::VarError::NotPresent) => {
            config::sensor_logs_from_file(Path::new(config::WATCH_ENV_PATH))
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{SENSOR_LOGS_KEY} in the environment is not valid UTF-8"
        )),
    };
    let logs = source.and_then(|source| {
        log_tailer::parse_sensor_logs(&source.raw)
            .map(|logs| (logs, source.from.clone()))
            .map_err(|e| format!("{SENSOR_LOGS_KEY} from {}: {e}", source.from))
    });
    let (logs, from) = match logs {
        Ok(found) => found,
        Err(reason) => {
            let message = format!(
                "{reason}; set {SENSOR_LOGS_KEY} or run deploy/watch-env.sh (see docs/operations/live-watch.md)"
            );
            eprintln!("propolis-watch: {message}");
            let _ = writeln!(out, "{}", record::error("config", &message));
            let _ = out.flush();
            return ExitCode::from(1);
        }
    };

    let configured: BTreeSet<&str> = logs.iter().map(|l| l.name.as_str()).collect();
    if let Some(unknown) = options
        .sensors
        .iter()
        .find(|s| !configured.contains(s.as_str()))
    {
        let labels: Vec<&str> = configured.into_iter().collect();
        return usage_error(&format!(
            "--sensor {unknown:?} is not a {SENSOR_LOGS_KEY} label (configured: {})",
            labels.join(", ")
        ));
    }

    // Returns only when stdout is gone, which is the normal way a remote session ends.
    let _closed = watcher::run(logs, &from, &options, env!("CARGO_PKG_VERSION"), &mut out);
    ExitCode::SUCCESS
}

/// argv after the program name, followed by the SSH client's command when there is one.
fn arguments() -> Result<Vec<String>, UsageError> {
    let mut tokens = Vec::new();
    for arg in std::env::args_os().skip(1) {
        tokens.push(
            arg.into_string()
                .map_err(|a| UsageError::UnknownArgument(a.to_string_lossy().into_owned()))?,
        );
    }
    match std::env::var(ENV_SSH_COMMAND) {
        Ok(raw) => tokens.extend(args::ssh_command_tokens(&raw)),
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => return Err(UsageError::NotUnicode),
    }
    Ok(tokens)
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("propolis-watch: {message}\n\n{USAGE}");
    ExitCode::from(2)
}
