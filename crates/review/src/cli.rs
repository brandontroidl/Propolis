//! The operator CLI: clap subcommands wrapping [`ReviewQueue`]'s three
//! decisions (approve/reject/snooze), the way back out of a snooze
//! (`unsnooze`, and `snoozed` to find what is waiting), the pending listing,
//! and the vendor submission history for an IP. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("Operator
//! decisions"): "The CLI also supports listing the queue (pending entries,
//! with score and categories) and viewing the submission history for an IP."
//! This is the whole operator surface until the web console (sub-project 6)
//! lands.
//!
//! `volume` groups the same decisions for the other queue: the addresses
//! the connection-volume rule would list in the retention feeds
//! ([`crate::volume`]). They are separate subcommands, not a flag on
//! `approve`, because the two approvals do different things: `approve`
//! reports an address to vendors, `volume approve` publishes it and reports
//! nothing.
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
use crate::volume::{VolumeEntry, VolumeQueue};

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
    /// Return an IP to the pending queue. The way back out of a snooze (a
    /// population scan never re-surfaces a decided entry on its own), and the
    /// way to undo an approval or rejection made in error.
    Unsnooze { ip: IpAddr },
    /// List every Pending review queue entry, oldest-surfaced first.
    List,
    /// List every Snoozed entry, most-recently-snoozed first: what is waiting
    /// for the "later" a snooze promised. Nothing re-surfaces these
    /// automatically, so this listing is how they are found again.
    Snoozed,
    /// Show vendor submission history for an IP, most recent first.
    History { ip: IpAddr },
    /// Decide volume candidates: addresses with a thousand or more
    /// established TCP events, which are published in the retention feeds
    /// only once approved here. A volume approval is never reported to a
    /// vendor.
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },
}

/// The `volume` subcommands. `Reopen` is the way back from either decision,
/// and `Decided` is the listing it is used from.
#[derive(Subcommand, Debug, PartialEq)]
pub enum VolumeCommand {
    /// List every Pending volume candidate, oldest-surfaced first.
    List,
    /// List every Approved and Rejected volume candidate, most recently
    /// decided first.
    Decided,
    /// Approve a volume candidate: it is published in the retention feeds
    /// from the next feed build. It is not reported to abuse vendors. The
    /// approval stands until it is reopened, the address is delisted, or the
    /// address has gone unseen for the longest retention window.
    Approve {
        ip: IpAddr,
        /// Optional note recording the reasoning behind this decision.
        #[arg(long)]
        notes: Option<String>,
    },
    /// Reject a volume candidate: not published on volume, and not offered
    /// again by a later scan.
    Reject {
        ip: IpAddr,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Return a decided volume candidate to pending. Undoes an approval (the
    /// address leaves the retention feeds at the next build) or a rejection.
    Reopen { ip: IpAddr },
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
        Command::Unsnooze { ip } => {
            queue.unsnooze(pool, ip).await?;
            println!("{ip} returned to pending");
        }
        Command::List => print_pending(pool, &queue).await?,
        Command::Snoozed => print_snoozed(pool, &queue).await?,
        Command::History { ip } => print_history(pool, ip).await?,
        Command::Volume { command } => execute_volume(pool, command).await?,
    }
    Ok(())
}

async fn execute_volume(pool: &PgPool, command: VolumeCommand) -> Result<(), CliError> {
    let queue = VolumeQueue::new();
    match command {
        VolumeCommand::List => {
            let entries = queue.list_pending(pool).await?;
            if entries.is_empty() {
                println!("no pending volume candidates");
                return Ok(());
            }
            print_volume_entries(&entries);
            println!("\ndecide one with: review volume approve|reject <ip>");
        }
        VolumeCommand::Decided => {
            let mut entries = queue
                .list_by_state(pool, core_scoring::ReviewState::Approved, None)
                .await?;
            entries.extend(
                queue
                    .list_by_state(pool, core_scoring::ReviewState::Rejected, None)
                    .await?,
            );
            if entries.is_empty() {
                println!("no decided volume candidates");
                return Ok(());
            }
            entries.sort_by_key(|e| std::cmp::Reverse(e.decided_at));
            print_volume_entries(&entries);
            println!("\nundo one with: review volume reopen <ip>");
        }
        VolumeCommand::Approve { ip, notes } => {
            queue.approve(pool, ip, notes.as_deref()).await?;
            println!("approved {ip} for the retention feeds (not reported to vendors)");
        }
        VolumeCommand::Reject { ip, notes } => {
            queue.reject(pool, ip, notes.as_deref()).await?;
            println!("rejected {ip} as a volume candidate");
        }
        VolumeCommand::Reopen { ip } => {
            queue.reopen(pool, ip).await?;
            println!("{ip} returned to pending as a volume candidate");
        }
    }
    Ok(())
}

/// One line per volume candidate. `TCP_AT_SURFACE` is the established-event
/// count that listed it; the console's volume tab shows the current count
/// beside it.
fn print_volume_entries(entries: &[VolumeEntry]) {
    println!(
        "{:<16}{:<10}{:>15}  {:<25}{:<25}NOTES",
        "SOURCE_IP", "STATE", "TCP_AT_SURFACE", "SURFACED_AT", "DECIDED_AT"
    );
    for e in entries {
        println!(
            "{:<16}{:<10}{:>15}  {:<25}{:<25}{}",
            e.source_ip.to_string(),
            format!("{:?}", e.state).to_lowercase(),
            e.established_events_at_surface,
            e.surfaced_at.to_rfc3339(),
            e.decided_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "-".to_string()),
            e.notes.as_deref().unwrap_or_default(),
        );
    }
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

async fn print_snoozed(pool: &PgPool, queue: &ReviewQueue) -> Result<(), CliError> {
    let entries = queue
        .list_by_state(pool, core_scoring::ReviewState::Snoozed)
        .await?;
    if entries.is_empty() {
        println!("no snoozed review queue entries");
        return Ok(());
    }
    println!(
        "{:<16}{:>10}  {:<25}NOTES",
        "SOURCE_IP", "SCORE", "SNOOZED_AT"
    );
    for e in entries {
        println!(
            "{:<16}{:>10}  {:<25}{}",
            e.source_ip.to_string(),
            e.score_at_surface,
            e.decided_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "-".to_string()),
            e.notes.unwrap_or_default(),
        );
    }
    println!("\nact on one with: review approve|reject|unsnooze <ip>");
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
    fn cli_parses_the_volume_subcommands() {
        let parse = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        assert_eq!(
            parse(&["review", "volume", "list"]).unwrap(),
            Command::Volume {
                command: VolumeCommand::List
            }
        );
        assert_eq!(
            parse(&["review", "volume", "decided"]).unwrap(),
            Command::Volume {
                command: VolumeCommand::Decided
            }
        );
        assert_eq!(
            parse(&[
                "review",
                "volume",
                "approve",
                "203.0.113.9",
                "--notes",
                "flood"
            ])
            .unwrap(),
            Command::Volume {
                command: VolumeCommand::Approve {
                    ip: "203.0.113.9".parse().unwrap(),
                    notes: Some("flood".to_string()),
                }
            }
        );
        assert_eq!(
            parse(&["review", "volume", "reject", "203.0.113.9"]).unwrap(),
            Command::Volume {
                command: VolumeCommand::Reject {
                    ip: "203.0.113.9".parse().unwrap(),
                    notes: None,
                }
            }
        );
        assert_eq!(
            parse(&["review", "volume", "reopen", "203.0.113.9"]).unwrap(),
            Command::Volume {
                command: VolumeCommand::Reopen {
                    ip: "203.0.113.9".parse().unwrap(),
                }
            }
        );
        // A volume decision is never reachable as a flag or a bare `volume`: the operator has to
        // name the queue and the action.
        assert!(parse(&["review", "volume"]).is_err());
        assert!(parse(&["review", "volume", "approve", "not-an-ip"]).is_err());
        assert!(parse(&["review", "approve", "203.0.113.9", "--volume"]).is_err());
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
