//! Condition #4: the blocklist feed has not been re-published within several build cycles - the
//! feed loop is wedged or the build keeps failing, so downstream consumers are being served a stale
//! feed.
//!
//! Publish time is recorded as the mtime of a marker file the feed loop touches on each successful
//! publish. The marker is a SIBLING of the output directory (`<output_dir>.last_published`), never a
//! file inside it: the output directory is a public artifact synced to the public blocklist repo, so
//! an internal timing marker must not leak into it.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

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
        let last_published = match std::fs::metadata(&ctx.feed_marker_path) {
            Ok(md) => match md.modified() {
                Ok(t) => Some(t),
                Err(e) => {
                    return Outcome::Unknown {
                        why: format!("feed marker mtime: {e}"),
                    };
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Outcome::Unknown {
                    why: format!("feed marker stat: {e}"),
                };
            }
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
