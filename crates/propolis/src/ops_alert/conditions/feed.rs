//! Condition #4: the blocklist feed has not been re-published within several build cycles - the
//! feed loop is wedged or the build keeps failing, so downstream consumers are being served a stale
//! feed.
//!
//! Publish time is recorded as the mtime of a marker file the feed loop touches on each successful
//! publish. The marker is a SIBLING of the output directory (`<output_dir>.last_published`), never a
//! file inside it: the output directory is a public artifact synced to the public blocklist repo, so
//! an internal timing marker must not leak into it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// The publish-time marker path for `output_dir`: a sibling dotfile, so it never lands inside the
/// published feed directory. Both the feed loop (writer) and this condition (reader) derive it here.
pub fn marker_path(output_dir: &Path) -> PathBuf {
    let name = output_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "feed".to_string());
    let parent = match output_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    parent.join(format!(".{name}.last_published"))
}

/// Record a successful publish by writing the marker (its mtime is the publish time). Called by the
/// feed loop after a successful `Publisher::publish`.
pub fn touch_marker(output_dir: &Path) -> std::io::Result<()> {
    let path = marker_path(output_dir);
    // Content is irrelevant; the mtime carries the signal. Rewriting updates the mtime.
    std::fs::write(&path, b"propolis feed last-published marker\n")
}

/// The push-time marker path for `output_dir`: `<output_dir>.last_pushed`, the sibling dotfile
/// `deploy/blocklist-sync.sh` touches after a successful `git push`. Only the reader lives here;
/// the writer is the operator's cron script, which derives the same path from the feed directory
/// it publishes (`$(dirname "$SRC")/.$(basename "$SRC").last_pushed`).
pub fn push_marker_path(output_dir: &Path) -> PathBuf {
    let name = output_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "feed".to_string());
    let parent = match output_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    parent.join(format!(".{name}.last_pushed"))
}

/// Push-staleness test, split from I/O: has the local feed moved on from the last successful
/// push by more than `threshold`? Measured as publish-time minus push-time rather than push age,
/// so a wedged feed loop (already `feed-stale`) does not double-page here, and the cron's
/// structural one-build lag (it runs at the top of the hour and ships the previous build) never
/// counts as stale on its own. No push marker at all is grace, not stale: publishing to a public
/// repo is an optional operator step and a box that never syncs has nothing to supervise.
fn is_push_stale(
    last_published: Option<SystemTime>,
    last_pushed: Option<SystemTime>,
    threshold: Duration,
    unpushed_for: Option<Duration>,
) -> bool {
    match (last_published, last_pushed) {
        (Some(published), Some(pushed)) => published
            .duration_since(pushed)
            .map(|lag| lag > threshold)
            .unwrap_or(false),
        // A feed exists and nothing has ever pushed it. `unpushed_for` is how long this monitor
        // has watched that state with the operator having declared pushes expected
        // (`PROPOLIS_OPS_FEED_PUSH_EXPECTED`); `None` when they have not, which is grace forever
        // since the monitor cannot tell "syncing is optional" from "the cron never worked". Even
        // when expected, the same multi-build threshold applies, so a fresh deployment is not
        // paged before its first scheduled cron run.
        (Some(_), None) => unpushed_for.is_some_and(|watched| watched > threshold),
        (None, _) => false,
    }
}

/// `Some(mtime)` for an existing marker, `None` when it does not exist, `Err` for any other
/// stat/mtime failure (surfaced as `Unknown` by the caller rather than read as fresh).
fn marker_mtime(path: &Path) -> Result<Option<SystemTime>, String> {
    match std::fs::metadata(path) {
        Ok(md) => md
            .modified()
            .map(Some)
            .map_err(|e| format!("marker mtime {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("marker stat {}: {e}", path.display())),
    }
}

/// The public blocklist repo has fallen behind the local feed: the local publish marker has moved
/// on from the last successful push by more than `feed_stale_multiple` build cycles. The push is
/// an operator cron job outside the daemon, so without this the daemon's own feed health stays
/// green while downstream consumers of the public repo are served a stale feed.
pub struct FeedPushStale {
    /// When this monitor first saw a published feed with no push marker while pushes were
    /// expected; cleared as soon as a push marker appears. Fresh on every (re)start, so a
    /// restarted daemon grants a new deployment the full threshold before paging.
    unpushed_since: Mutex<Option<Instant>>,
}

impl FeedPushStale {
    pub fn new() -> Self {
        Self {
            unpushed_since: Mutex::new(None),
        }
    }
}

impl Default for FeedPushStale {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Condition for FeedPushStale {
    fn id(&self) -> &'static str {
        "feed-push-stale"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let threshold = ctx.feed_build_interval * ctx.cfg.feed_stale_multiple;
        let last_published = match marker_mtime(&ctx.feed_marker_path) {
            Ok(t) => t,
            Err(why) => return Outcome::Unknown { why },
        };
        let last_pushed = match marker_mtime(&ctx.feed_push_marker_path) {
            Ok(t) => t,
            Err(why) => return Outcome::Unknown { why },
        };
        let unpushed_for = {
            let mut since = self
                .unpushed_since
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match (last_published, last_pushed, ctx.cfg.feed_push_expected) {
                (Some(_), None, true) => Some(since.get_or_insert_with(Instant::now).elapsed()),
                _ => {
                    *since = None;
                    None
                }
            }
        };
        if is_push_stale(last_published, last_pushed, threshold, unpushed_for) {
            let detail = if last_pushed.is_none() {
                "public blocklist repo has never been pushed although PROPOLIS_OPS_FEED_PUSH_EXPECTED \
                 is set - deploy/blocklist-sync.sh has not succeeded once (cron, deploy key?)"
                    .to_string()
            } else {
                format!(
                    "public blocklist repo is over {}s (>= {} build cycles) behind the local \
                     feed - deploy/blocklist-sync.sh has not pushed since the local feed moved on",
                    threshold.as_secs(),
                    ctx.cfg.feed_stale_multiple
                )
            };
            Outcome::Firing {
                severity: Severity::Warning,
                detail,
            }
        } else {
            Outcome::Ok
        }
    }
}

/// Staleness test, split from I/O. `None` (no marker yet) is grace, not stale. A marker timestamped
/// in the future (clock skew) is treated as fresh rather than firing spuriously.
fn is_stale(last_published: Option<SystemTime>, now: SystemTime, threshold: Duration) -> bool {
    match last_published {
        None => false,
        Some(t) => now
            .duration_since(t)
            .map(|age| age > threshold)
            .unwrap_or(false),
    }
}

/// #4: feed publication is stale.
pub struct FeedStale;

#[async_trait]
impl Condition for FeedStale {
    fn id(&self) -> &'static str {
        "feed-stale"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // The threshold already spans multiple build cycles, so a stale reading is not a blip.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let threshold = ctx.feed_build_interval * ctx.cfg.feed_stale_multiple;
        let last_published = match marker_mtime(&ctx.feed_marker_path) {
            Ok(t) => t,
            Err(why) => return Outcome::Unknown { why },
        };
        if is_stale(last_published, SystemTime::now(), threshold) {
            Outcome::Firing {
                severity: Severity::Warning,
                detail: format!(
                    "blocklist feed not re-published in over {}s (>= {} build cycles)",
                    threshold.as_secs(),
                    ctx.cfg.feed_stale_multiple
                ),
            }
        } else {
            Outcome::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: Duration = Duration::from_secs(600);

    #[test]
    fn within_the_threshold_is_not_stale() {
        let now = SystemTime::now();
        let recent = now - Duration::from_secs(100);
        assert!(!is_stale(Some(recent), now, THRESHOLD));
    }

    #[test]
    fn past_the_threshold_is_stale() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(700);
        assert!(is_stale(Some(old), now, THRESHOLD));
    }

    #[test]
    fn no_marker_is_grace_not_stale() {
        assert!(!is_stale(None, SystemTime::now(), THRESHOLD));
    }

    #[test]
    fn a_future_marker_is_not_stale() {
        let now = SystemTime::now();
        let future = now + Duration::from_secs(100);
        assert!(!is_stale(Some(future), now, THRESHOLD));
    }

    #[test]
    fn push_lag_past_the_threshold_is_stale() {
        let now = SystemTime::now();
        let pushed = now - Duration::from_secs(700);
        assert!(is_push_stale(Some(now), Some(pushed), THRESHOLD, None));
    }

    #[test]
    fn push_one_build_behind_is_not_stale() {
        // The cron runs at the top of the hour and ships the PREVIOUS build, so a push that trails
        // the publish by less than the threshold is the normal steady state, not a failed push.
        let now = SystemTime::now();
        let pushed = now - Duration::from_secs(100);
        assert!(!is_push_stale(Some(now), Some(pushed), THRESHOLD, None));
    }

    #[test]
    fn push_newer_than_publish_is_not_stale() {
        // A push after the last publish (clock skew, or a by-hand run) is fresh, never negative.
        let now = SystemTime::now();
        let pushed = now + Duration::from_secs(50);
        assert!(!is_push_stale(Some(now), Some(pushed), THRESHOLD, None));
    }

    #[test]
    fn no_push_marker_is_grace_not_stale() {
        // Publishing to a public repo is optional; a box that never syncs has nothing to supervise.
        assert!(!is_push_stale(
            Some(SystemTime::now()),
            None,
            THRESHOLD,
            None
        ));
        assert!(!is_push_stale(None, None, THRESHOLD, None));
    }

    #[test]
    fn no_push_marker_is_stale_only_after_the_threshold_when_pushes_are_expected() {
        // With PROPOLIS_OPS_FEED_PUSH_EXPECTED set, "never pushed" is the failure itself, not
        // grace - otherwise a cron that never worked is indistinguishable from no cron at all.
        // But it gets the same multi-build threshold, so a fresh deployment is not paged before
        // its first scheduled cron run.
        let now = SystemTime::now();
        assert!(is_push_stale(
            Some(now),
            None,
            THRESHOLD,
            Some(THRESHOLD + Duration::from_secs(1))
        ));
        assert!(!is_push_stale(
            Some(now),
            None,
            THRESHOLD,
            Some(Duration::from_secs(100))
        ));
        // With no local feed published yet there is nothing to have pushed.
        assert!(!is_push_stale(None, None, THRESHOLD, Some(THRESHOLD * 10)));
        // And an actual push in the normal lag is still fine under the flag.
        assert!(!is_push_stale(
            Some(now),
            Some(now - Duration::from_secs(100)),
            THRESHOLD,
            Some(THRESHOLD * 10)
        ));
    }

    #[test]
    fn push_marker_path_is_a_sibling_dotfile_matching_the_sync_script() {
        // deploy/blocklist-sync.sh derives `$(dirname "$SRC")/.$(basename "$SRC").last_pushed`;
        // the two derivations must agree or the condition reads a marker nobody writes.
        let p = push_marker_path(Path::new("/var/lib/propolis/feed/current"));
        assert_eq!(p, Path::new("/var/lib/propolis/feed/.current.last_pushed"));
        assert!(!p.starts_with("/var/lib/propolis/feed/current"));
    }

    #[test]
    fn marker_mtime_distinguishes_missing_from_present() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        assert_eq!(marker_mtime(&missing).unwrap(), None);
        let present = tmp.path().join("yes");
        std::fs::write(&present, b"x").unwrap();
        assert!(marker_mtime(&present).unwrap().is_some());
    }

    #[test]
    fn marker_path_is_a_sibling_dotfile_not_inside_the_dir() {
        let p = marker_path(Path::new("/var/lib/propolis/feed"));
        assert_eq!(p, Path::new("/var/lib/propolis/.feed.last_published"));
        // Not inside the published directory.
        assert!(!p.starts_with("/var/lib/propolis/feed"));
    }

    #[test]
    fn touch_marker_creates_a_readable_marker_outside_the_output_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let output_dir = tmp.path().join("feed");
        std::fs::create_dir(&output_dir).unwrap();
        touch_marker(&output_dir).unwrap();
        let marker = marker_path(&output_dir);
        assert!(marker.exists(), "marker was created");
        assert!(
            !marker.starts_with(&output_dir),
            "marker is outside the feed dir"
        );
        // Its mtime is readable and recent, so the condition can compare against it.
        let mtime = std::fs::metadata(&marker).unwrap().modified().unwrap();
        assert!(SystemTime::now().duration_since(mtime).unwrap() < Duration::from_secs(60));
    }
}
