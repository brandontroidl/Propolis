//! The operator CLI: clap subcommands wrapping [`ReviewQueue`]'s three
//! decisions (approve/reject/snooze), the pending listing, and the vendor
//! submission history for an IP. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("Operator
//! decisions"): "The CLI also supports listing the queue (pending entries,
//! with score and categories) and viewing the submission history for an IP."
//! This is the whole operator surface until the web console (sub-project 6)
//! lands.
//!
//! `daemon` is defined here as a [`Command`] variant (so `--help` documents it
//! alongside the operator subcommands, and both share one argument parser),
//! but [`execute`] never handles it: the daemon loop needs the constructed
//! vendor adapters and gatekeeper configs, not just a `pool`, so `main.rs`
//! intercepts `Command::Daemon` before ever calling [`execute`]. See that
//! function's own doc comment.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use sqlx::{PgPool, Row};

use crate::queue::{ReviewError, ReviewQueue};

/// Propolis review queue + vendor submission operator CLI.
#[derive(Parser, Debug)]
#[command(
    name = "review",
    about = "Propolis review queue and vendor submission operator CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// One invocation's subcommand. See the module doc comment for why `Daemon`
/// is defined here but not handled by [`execute`].
#[derive(Subcommand, Debug, PartialEq)]
pub enum Command {
    /// Run the submission daemon: populate/withdraw the review queue and
    /// submit approved entries to configured vendors, forever, on the
    /// configured poll intervals.
    Daemon,
    /// Approve an IP for vendor submission. The submission daemon picks up
    /// Approved entries on its next poll.
    Approve {
        ip: IpAddr,
        /// Optional note recording the reasoning behind this decision.
        #[arg(long)]
        notes: Option<String>,
    },
    /// Reject an IP: never reported, and not re-surfaced by a later
    /// population scan.
    Reject {
        ip: IpAddr,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Snooze an IP for later review.
    Snooze {
        ip: IpAddr,
        #[arg(long)]
        notes: Option<String>,
    },
    /// List every Pending review queue entry, oldest-surfaced first.
    List,
    /// Show vendor submission history for an IP, most recent first.
    History { ip: IpAddr },
}

/// Errors an operator command can fail with: either the review queue's own
/// errors (a decision on a nonexistent entry, a database error) or a bare
/// database error from the history query, which reads `vendor_submission`
/// directly (see [`submission_history`]) rather than through [`ReviewQueue`],
/// which owns only `review_queue`.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Review(#[from] ReviewError),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Run one operator subcommand to completion, printing its result to stdout.
///
/// # Panics
///
/// Panics if called with `Command::Daemon`. Running the daemon needs the
/// constructed vendor adapters and gatekeeper configs (`main.rs` builds those
/// from `FullVendorConfig` plus a shared `reqwest::Client`), not just a
/// `pool`, so `main.rs` must intercept that variant itself before ever
/// calling this function - see its own top-level dispatch, the only caller
/// of `execute`.
pub async fn execute(pool: &PgPool, command: Command) -> Result<(), CliError> {
    let queue = ReviewQueue::new();
    match command {
        Command::Daemon => {
            unreachable!("main.rs must handle Command::Daemon before calling cli::execute")
        }
        Command::Approve { ip, notes } => {
            queue.approve(pool, ip, notes.as_deref()).await?;
            println!("approved {ip}");
        }
        Command::Reject { ip, notes } => {
            queue.reject(pool, ip, notes.as_deref()).await?;
            println!("rejected {ip}");
        }
        Command::Snooze { ip, notes } => {
            queue.snooze(pool, ip, notes.as_deref()).await?;
            println!("snoozed {ip}");
        }
        Command::List => print_pending(pool, &queue).await?,
        Command::History { ip } => print_history(pool, ip).await?,
    }
    Ok(())
}

async fn print_pending(pool: &PgPool, queue: &ReviewQueue) -> Result<(), CliError> {
    let entries = queue.list_pending(pool).await?;
    if entries.is_empty() {
        println!("no pending review queue entries");
        return Ok(());
    }
    println!(
        "{:<16}{:>10}  {:<25}CATEGORIES",
        "SOURCE_IP", "SCORE", "SURFACED_AT"
    );
    for e in entries {
        println!(
            "{:<16}{:>10}  {:<25}{}",
            e.source_ip.to_string(),
            e.score_at_surface,
            e.surfaced_at.to_rfc3339(),
            e.categories_at_surface,
        );
    }
    Ok(())
}

/// One `vendor_submission` row for the `history` subcommand: everything
/// except `id`/`source_ip` (the caller already knows which IP it queried) and
/// `response_body` (a vendor error body can be long; the CLI's default
/// listing shows enough to triage without dumping raw HTTP responses to the
/// terminal).
#[derive(Debug, Clone, PartialEq)]
pub struct SubmissionHistoryEntry {
    pub vendor: String,
    pub categories: Vec<String>,
    pub submitted_at: DateTime<Utc>,
    pub response_status: Option<i32>,
    pub success: bool,
}

/// Every `vendor_submission` row for `ip`, most recent first: the operator's
/// audit trail of what has already been reported where. Reads
/// `vendor_submission` directly rather than through [`ReviewQueue`] (which
/// owns only `review_queue`) or `SubmissionRunner` (which writes but never
/// reads this table back) - see the design spec's "The CLI also supports ...
/// viewing the submission history for an IP."
pub async fn submission_history(
    pool: &PgPool,
    ip: IpAddr,
) -> Result<Vec<SubmissionHistoryEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT vendor, categories, submitted_at, response_status, success \
         FROM vendor_submission WHERE source_ip = $1::inet ORDER BY submitted_at DESC",
    )
    .bind(ip.to_string())
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(SubmissionHistoryEntry {
                vendor: row.try_get("vendor")?,
                categories: row.try_get("categories")?,
                submitted_at: row.try_get("submitted_at")?,
                response_status: row.try_get("response_status")?,
                success: row.try_get("success")?,
            })
        })
        .collect()
}

async fn print_history(pool: &PgPool, ip: IpAddr) -> Result<(), CliError> {
    let history = submission_history(pool, ip).await?;
    if history.is_empty() {
        println!("no submission history for {ip}");
        return Ok(());
    }
    println!(
        "{:<10}{:<25}{:<8}{:<8}CATEGORIES",
        "VENDOR", "SUBMITTED_AT", "STATUS", "SUCCESS"
    );
    for h in history {
        let status = h
            .response_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<10}{:<25}{:<8}{:<8}{:?}",
            h.vendor,
            h.submitted_at.to_rfc3339(),
            status,
            h.success,
            h.categories,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_approve_with_ip_and_notes() {
        let cli =
            Cli::try_parse_from(["review", "approve", "203.0.113.9", "--notes", "test"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Approve {
                ip: "203.0.113.9".parse().unwrap(),
                notes: Some("test".to_string()),
            }
        );
    }

    #[test]
    fn cli_parses_approve_without_notes() {
        let cli = Cli::try_parse_from(["review", "approve", "203.0.113.9"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Approve {
                ip: "203.0.113.9".parse().unwrap(),
                notes: None,
            }
        );
    }

    #[test]
    fn cli_parses_every_subcommand() {
        assert!(Cli::try_parse_from(["review", "daemon"]).is_ok());
        assert!(Cli::try_parse_from(["review", "list"]).is_ok());
        assert!(Cli::try_parse_from(["review", "reject", "203.0.113.9"]).is_ok());
        assert!(Cli::try_parse_from(["review", "snooze", "203.0.113.9"]).is_ok());
        assert!(Cli::try_parse_from(["review", "history", "203.0.113.9"]).is_ok());
    }

    #[test]
    fn cli_rejects_invalid_ip() {
        assert!(Cli::try_parse_from(["review", "approve", "not-an-ip"]).is_err());
    }

    #[test]
    fn cli_rejects_missing_subcommand() {
        assert!(Cli::try_parse_from(["review"]).is_err());
    }

    #[test]
    fn cli_command_debug_asserts_clean() {
        // clap's own self-check: catches derive-macro misconfigurations
        // (duplicate arg names, invalid conflicts) at test time rather than
        // only the first time the binary is actually invoked.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
