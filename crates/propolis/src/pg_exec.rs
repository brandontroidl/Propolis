//! `propolis pg-exec <pg_dump|pg_restore|psql> [args...]`: runs one PostgreSQL client tool against
//! the daemon's own `DATABASE_URL` without that URL, or its password, ever appearing on a command
//! line, where `ps` would show it to every local user for as long as a dump runs.
//!
//! The URL is parsed with the same parser the daemon connects with (sqlx's `PgConnectOptions`), so
//! a backup reaches exactly the database the daemon uses, and handed to the tool through libpq's
//! own environment variables. sqlx does not expose the password, so that one field is read from
//! the URL here, percent-decoded. A URL setting this cannot hand on is refused rather than dropped:
//! a backup that quietly connects differently from the daemon (without its TLS root, say) is worse
//! than one that stops and says why.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgSslMode};

/// The tools this runs. Anything else is refused: this hands a database password to a process.
const TOOLS: [&str; 3] = ["pg_dump", "pg_restore", "psql"];

/// URL query settings sqlx reads and this module hands on through the options it parses.
const PARSED_KEYS: [&str; 8] = [
    "sslmode",
    "host",
    "hostaddr",
    "port",
    "dbname",
    "user",
    "password",
    "application_name",
];

/// URL query settings libpq reads from an environment variable of its own.
const PASSED_KEYS: [(&str, &str); 4] = [
    ("sslrootcert", "PGSSLROOTCERT"),
    ("sslcert", "PGSSLCERT"),
    ("sslkey", "PGSSLKEY"),
    ("options", "PGOPTIONS"),
];

/// Decode `%XX` escapes. Anything that is not valid hex after a `%`, or bytes that are not UTF-8,
/// is an error: a misread password fails authentication with a message that hides the real cause.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "a malformed %-escape in DATABASE_URL".to_string())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "DATABASE_URL decodes to bytes that are not UTF-8".into())
}

/// The URL's authority (between `scheme://` and the path or query) and its query string.
fn split_url(url: &str) -> Result<(&str, &str), String> {
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| "DATABASE_URL is not a postgres:// URL".to_string())?;
    let rest = rest.split('#').next().unwrap_or("");
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    Ok((authority, query))
}

/// The password in the URL's user information, decoded, if there is one.
fn url_password(url: &str) -> Result<Option<String>, String> {
    let (authority, _) = split_url(url)?;
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return Ok(None);
    };
    match userinfo.split_once(':') {
        Some((_, password)) => percent_decode(password).map(Some),
        None => Ok(None),
    }
}

/// The URL's query settings, decoded.
fn url_query(url: &str) -> Result<Vec<(String, String)>, String> {
    let (_, query) = split_url(url)?;
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(key)?, percent_decode(value)?))
        })
        .collect()
}

fn ssl_mode_name(mode: PgSslMode) -> &'static str {
    match mode {
        PgSslMode::Disable => "disable",
        PgSslMode::Allow => "allow",
        PgSslMode::Prefer => "prefer",
        PgSslMode::Require => "require",
        PgSslMode::VerifyCa => "verify-ca",
        PgSslMode::VerifyFull => "verify-full",
    }
}

/// The libpq environment that connects `tool` where `url` does.
fn connection_env(url: &str, tool: &str) -> Result<Vec<(String, String)>, String> {
    let options =
        PgConnectOptions::from_str(url).map_err(|e| format!("DATABASE_URL does not parse: {e}"))?;
    let mut env = Vec::new();
    let host = match options.get_socket() {
        Some(socket) => socket.display().to_string(),
        None => options.get_host().to_string(),
    };
    env.push(("PGHOST".to_string(), host));
    env.push(("PGPORT".to_string(), options.get_port().to_string()));
    env.push(("PGUSER".to_string(), options.get_username().to_string()));
    if let Some(database) = options.get_database() {
        env.push(("PGDATABASE".to_string(), database.to_string()));
    }
    env.push((
        "PGSSLMODE".to_string(),
        ssl_mode_name(options.get_ssl_mode()).to_string(),
    ));
    env.push(("PGAPPNAME".to_string(), format!("propolis-{tool}")));
    if let Some(password) = url_password(url)? {
        env.push(("PGPASSWORD".to_string(), password));
    }
    for (key, value) in url_query(url)? {
        if PARSED_KEYS.contains(&key.as_str()) {
            continue;
        }
        let Some((_, var)) = PASSED_KEYS.iter().find(|(k, _)| *k == key) else {
            return Err(format!(
                "DATABASE_URL setting `{key}` cannot be handed to {tool}; set it with the \
                 matching PG* variable for this command instead"
            ));
        };
        env.push((var.to_string(), value));
    }
    Ok(env)
}

/// Run `args[0]` (one of [`TOOLS`]) with the rest of `args`, connected by `DATABASE_URL` from this
/// process's environment. Replaces this process on success, so it only returns on failure, with
/// the exit code to use.
pub fn run(args: &[String]) -> i32 {
    let Some(tool) = args.first().map(String::as_str) else {
        eprintln!("usage: propolis pg-exec <{}> [args...]", TOOLS.join("|"));
        return 2;
    };
    if !TOOLS.contains(&tool) {
        eprintln!(
            "propolis pg-exec runs only {}, not {tool:?}",
            TOOLS.join(", ")
        );
        return 2;
    }
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("propolis pg-exec: DATABASE_URL is not set");
        return 1;
    };
    let env = match connection_env(&url, tool) {
        Ok(env) => env,
        Err(why) => {
            eprintln!("propolis pg-exec: {why}");
            return 1;
        }
    };
    let mut command = Command::new(tool);
    command.args(&args[1..]);
    // Inherited PG* variables would override nothing libpq is given here, but could add a setting
    // the daemon's URL does not have; start from the URL alone.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PG") {
            command.env_remove(&name);
        }
    }
    command.env_remove("DATABASE_URL");
    command.envs(env);
    let err = command.exec();
    eprintln!("propolis pg-exec: cannot run {tool}: {err}");
    127
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_tcp_url_becomes_the_libpq_environment_with_its_password_decoded() {
        let env = connection_env(
            "postgres://propolis:p%40ss%3Aw%2Fd@db.example:6543/propolis?sslmode=require",
            "pg_dump",
        )
        .unwrap();
        assert_eq!(value(&env, "PGHOST"), Some("db.example"));
        assert_eq!(value(&env, "PGPORT"), Some("6543"));
        assert_eq!(value(&env, "PGUSER"), Some("propolis"));
        assert_eq!(value(&env, "PGDATABASE"), Some("propolis"));
        assert_eq!(value(&env, "PGPASSWORD"), Some("p@ss:w/d"));
        assert_eq!(value(&env, "PGSSLMODE"), Some("require"));
        assert_eq!(value(&env, "PGAPPNAME"), Some("propolis-pg_dump"));
    }

    #[test]
    fn a_socket_url_points_pghost_at_the_socket_directory_and_has_no_password() {
        let env = connection_env(
            "postgres://propolis@localhost/propolis?host=/var/run/postgresql",
            "psql",
        )
        .unwrap();
        assert_eq!(value(&env, "PGHOST"), Some("/var/run/postgresql"));
        assert_eq!(value(&env, "PGPASSWORD"), None);
        assert_eq!(value(&env, "PGDATABASE"), Some("propolis"));
    }

    #[test]
    fn tls_file_settings_pass_through_and_an_unknown_setting_is_refused() {
        let env = connection_env(
            "postgres://u:p@h/d?sslmode=verify-full&sslrootcert=/etc/propolis/pg-ca.pem",
            "pg_dump",
        )
        .unwrap();
        assert_eq!(
            value(&env, "PGSSLROOTCERT"),
            Some("/etc/propolis/pg-ca.pem")
        );
        assert_eq!(value(&env, "PGSSLMODE"), Some("verify-full"));

        let err =
            connection_env("postgres://u:p@h/d?target_session_attrs=any", "pg_dump").unwrap_err();
        assert!(err.contains("target_session_attrs"), "{err}");
    }

    #[test]
    fn a_malformed_escape_is_an_error_not_a_wrong_password() {
        assert!(url_password("postgres://u:p%zz@h/d").is_err());
        assert!(url_password("postgres://u:p%4@h/d").is_err());
        assert_eq!(url_password("postgres://u@h/d").unwrap(), None);
        assert_eq!(url_password("postgres://h/d").unwrap(), None);
    }

    #[test]
    fn only_the_three_client_tools_run() {
        assert_eq!(run(&["sh".to_string(), "-c".to_string()]), 2);
        assert_eq!(run(&[]), 2);
    }
}
