//! Volume-listed addresses through the real daemon: the compiled `propolis` binary, started from
//! environment variables against a real database, publishing real feed files.
//!
//! The pieces are tested where they live (the builder's statement in `feed`, the queue's scans in
//! `review`, the flag's parsing in this crate's config tests). What only the daemon can show is
//! that they are joined: that its queue scan offers a flooding address for approval, that the
//! feed it publishes leaves that address out until an operator approves it, and that
//! `PROPOLIS_FEED_VOLUME_AUTO_PUBLISH` is what reaches the builder as the opt-in. A daemon that
//! dropped any one of those links would still pass every other test.
//!
//! The flooding address is an arbitrary public-looking one, as in `feed`'s own tests: the daemon
//! uses the production reserved-range list, which refuses every documentation range.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use core_scoring::{EventInput, Protocol, SignalType, append_events};
use review::volume::VolumeQueue;
use sqlx::PgPool;

const FLOOD: &str = "45.10.30.77";

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// The connection string for the daemon: the caller's `DATABASE_URL` with the test's own
/// database in place of the one it names, so the credentials and host carry over.
fn database_url(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB tests");
    let base = base.split('?').next().unwrap();
    let (server, _) = base
        .rsplit_once('/')
        .expect("DATABASE_URL names a database");
    let database = pool.connect_options().get_database().unwrap().to_string();
    format!("{server}/{database}")
}

/// A thousand unauthenticated TCP connections from [`FLOOD`], the last a few minutes ago: listed
/// by the volume rule and nothing else.
async fn seed_flood(pool: &PgPool) {
    let last = chrono::Utc::now() - chrono::Duration::minutes(5);
    let connections: Vec<EventInput> = (0..1000)
        .map(|i| {
            EventInput::from_signal(
                FLOOD.parse().unwrap(),
                None,
                "ssh".into(),
                SignalType::HoneypotConnection,
                Protocol::Tcp,
                false,
                last - chrono::Duration::milliseconds(999 - i),
                serde_json::json!({}),
                None,
            )
        })
        .collect();
    assert!(append_events(pool, connections).await.failure.is_none());
}

/// The running daemon, killed when the test ends or fails.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts the daemon with every path under `root`, one retention window, and one-second queue
/// scans and feed builds. `auto_publish` is the value of `PROPOLIS_FEED_VOLUME_AUTO_PUBLISH`, or
/// `None` to leave it unset as a default install does.
fn start_daemon(pool: &PgPool, root: &Path, auto_publish: Option<&str>) -> Daemon {
    start_daemon_with(pool, root, auto_publish, &[])
}

/// [`start_daemon`] with more of the environment set, after everything it sets itself.
fn start_daemon_with(
    pool: &PgPool,
    root: &Path,
    auto_publish: Option<&str>,
    more: &[(&str, &str)],
) -> Daemon {
    let sensor_log = root.join("ssh.jsonl");
    std::fs::write(&sensor_log, "").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_propolis"));
    cmd.env_clear()
        .env("DATABASE_URL", database_url(pool))
        .env(
            "PROPOLIS_SENSOR_LOGS",
            format!("ssh:{}", sensor_log.display()),
        )
        .env("PROPOLIS_CONSOLE_PASSWORD", "volume-listing-test")
        .env(
            "PROPOLIS_CONSOLE_BIND",
            format!("127.0.0.1:{}", free_port()),
        )
        .env("PROPOLIS_CURSOR_DIR", root.join("cursors"))
        .env("PROPOLIS_QUARANTINE_DIR", root.join("quarantine"))
        .env("PROPOLIS_SPOOL_ROOT", root.join("spool"))
        .env("PROPOLIS_FEED_OUTPUT_DIR", feed_dir(root))
        .env("PROPOLIS_FEED_WINDOWS", "24h")
        .env("PROPOLIS_FEED_BUILD_INTERVAL_SECS", "1")
        .env("PROPOLIS_QUEUE_SCAN_INTERVAL_SECS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(value) = auto_publish {
        cmd.env("PROPOLIS_FEED_VOLUME_AUTO_PUBLISH", value);
    }
    cmd.envs(more.iter().copied());
    Daemon(cmd.spawn().expect("spawn propolis"))
}

fn feed_dir(root: &Path) -> PathBuf {
    root.join("feed").join("current")
}

/// Whether the published plain-text file `name` lists [`FLOOD`], from a build published after
/// `since`. `None` until such a build exists: an answer read from an older build says nothing
/// about the state the test has just set up.
fn listed_since(root: &Path, name: &str, since: SystemTime) -> Option<bool> {
    let path = feed_dir(root).join(name);
    let published = std::fs::metadata(&path).ok()?.modified().ok()?;
    if published <= since {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let flood: IpAddr = FLOOD.parse().unwrap();
    Some(
        text.lines()
            .any(|line| line.trim().parse::<IpAddr>() == Ok(flood)),
    )
}

/// Polls until a build published after `since` gives `want` for the retention file, or the
/// deadline passes. Returns whether it did.
async fn retention_file_settles(root: &Path, since: SystemTime, want: bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if listed_since(root, "all-24h.txt", since) == Some(want) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

async fn volume_state(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT state::text FROM volume_review WHERE source_ip = $1::inet")
        .bind(FLOOD)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn wait_for_volume_state(pool: &PgPool, want: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if volume_state(pool).await.as_deref() == Some(want) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// A build is published a moment after `SystemTime::now()` is read here, and file timestamps can
/// be coarser than the clock, so "after this point" starts a little late on purpose.
async fn after_this_point() -> SystemTime {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    SystemTime::now()
}

#[sqlx::test(migrations = false)]
async fn the_daemon_publishes_a_flooding_address_only_once_it_is_approved(pool: PgPool) {
    migrate(&pool).await;
    seed_flood(&pool).await;
    let root = tempfile::tempdir().unwrap();
    let _daemon = start_daemon(&pool, root.path(), None);

    // The daemon's own queue scan offers the address: nothing in this test created the row.
    assert!(
        wait_for_volume_state(&pool, "pending").await,
        "the daemon's queue scan must offer the flooding address as a pending volume candidate"
    );
    let offered = after_this_point().await;
    assert!(
        retention_file_settles(root.path(), offered, false).await,
        "a build published while the candidate is pending must leave it out of the retention feed"
    );

    let queue = VolumeQueue::new();
    queue
        .approve(&pool, FLOOD.parse().unwrap(), None)
        .await
        .unwrap();
    let approved = after_this_point().await;
    assert!(
        retention_file_settles(root.path(), approved, true).await,
        "once approved, the address is in the retention feed from the next build"
    );
    // Any published build will do for the tier files: no state of this address puts it in one.
    // Read with a retry, because a publish swaps the whole directory and a read can land
    // between its two renames.
    for tier_file in ["aggressive.txt", "standard.txt"] {
        let mut listed = None;
        for _ in 0..50 {
            listed = listed_since(root.path(), tier_file, SystemTime::UNIX_EPOCH);
            if listed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            listed,
            Some(false),
            "{tier_file}: a volume listing never reaches a tier file"
        );
    }

    queue.reopen(&pool, FLOOD.parse().unwrap()).await.unwrap();
    let reopened = after_this_point().await;
    assert!(
        retention_file_settles(root.path(), reopened, false).await,
        "taking the approval back takes the address out at the next build"
    );
}

#[sqlx::test(migrations = false)]
async fn the_daemon_publishes_without_approval_only_when_the_opt_in_is_set(pool: PgPool) {
    migrate(&pool).await;
    seed_flood(&pool).await;
    let root = tempfile::tempdir().unwrap();

    // A value that is not the word `true` is not the opt-in.
    {
        let _daemon = start_daemon(&pool, root.path(), Some("yes"));
        assert!(wait_for_volume_state(&pool, "pending").await);
        let offered = after_this_point().await;
        assert!(
            retention_file_settles(root.path(), offered, false).await,
            "PROPOLIS_FEED_VOLUME_AUTO_PUBLISH=yes must leave approval required"
        );
    }

    let restarted = after_this_point().await;
    let _daemon = start_daemon(&pool, root.path(), Some("true"));
    assert!(
        retention_file_settles(root.path(), restarted, true).await,
        "with PROPOLIS_FEED_VOLUME_AUTO_PUBLISH=true the address is published with no decision"
    );
    assert_eq!(
        volume_state(&pool).await.as_deref(),
        Some("pending"),
        "and no decision was made: the candidate is still pending"
    );
}

/// The scan that ends a lapsed volume approval runs with the review subsystem. A node with that
/// off and the feed on still publishes the approvals it already has, so something must still end
/// them: an approval that outlived its listing would put the address back in every window at its
/// next sighting, however long after. The feed build loop runs the scan there.
#[sqlx::test(migrations = false)]
async fn with_the_review_subsystem_off_the_feed_loop_still_ends_a_lapsed_approval(pool: PgPool) {
    migrate(&pool).await;
    seed_flood(&pool).await;
    // Offered and approved while the review subsystem was still on.
    let queue = VolumeQueue::new();
    assert_eq!(queue.populate(&pool).await.unwrap(), 1);
    queue
        .approve(&pool, FLOOD.parse().unwrap(), None)
        .await
        .unwrap();
    // Then the address went quiet for longer than any window, and longer than the ninety days
    // an approval is kept at the least.
    sqlx::query(
        "UPDATE ip_score SET established_last_seen = now() - interval '91 days' \
         WHERE source_ip = $1::inet",
    )
    .bind(FLOOD)
    .execute(&pool)
    .await
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    let _daemon = start_daemon_with(
        &pool,
        root.path(),
        None,
        &[("PROPOLIS_REVIEW_ENABLED", "false")],
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    while volume_state(&pool).await.is_some() {
        assert!(
            Instant::now() < deadline,
            "with the review subsystem off, the approval of an address out of every window was \
             never ended"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
