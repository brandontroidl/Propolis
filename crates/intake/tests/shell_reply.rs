//! A shell reply on the wire: what intake accepts, what it writes into the event the hash chain
//! covers, and what it stores.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_scoring::{ChainStatus, output_digest, verify_chain};
use intake::converter::{ConvertError, convert, convert_event};
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

fn reply(text: &str) -> ReplyRef {
    ReplyRef {
        sha256: output_digest(text),
        len: text.len() as u64 + 1,
        truncated: false,
        text: text.to_string(),
    }
}

fn event(n: i64, reply: Option<ReplyRef>) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: "192.0.2.10".parse().unwrap(),
        wan_ip: None,
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: "2026-09-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + chrono::Duration::seconds(n),
        metadata: serde_json::json!({ "protocol_label": "ssh", "command": "uname -a" }),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply,
    }
}

#[test]
fn the_digest_length_and_truncation_are_folded_into_the_metadata() {
    let mut r = reply("Linux box 5.15.0 x86_64");
    r.truncated = true;
    r.len = 9000;
    let converted = convert_event(event(0, Some(r.clone()))).unwrap();
    let md = &converted.input.metadata;
    assert_eq!(md["output_sha256"], r.sha256);
    assert_eq!(md["output_len"], 9000);
    assert_eq!(md["output_truncated"], true);
    assert_eq!(
        md["command"], "uname -a",
        "the sensor's own fields are kept"
    );
    assert_eq!(converted.reply, Some((r.sha256, r.text)));
}

#[test]
fn an_untruncated_reply_writes_no_truncated_key_and_convert_agrees() {
    let md = convert(event(0, Some(reply("x")))).unwrap().metadata;
    assert!(md.get("output_truncated").is_none());
    assert!(md.get("output_sha256").is_some(), "convert folds it too");
}

#[test]
fn an_event_without_a_reply_is_untouched() {
    let converted = convert_event(event(0, None)).unwrap();
    assert!(converted.reply.is_none());
    for key in ["output_sha256", "output_len", "output_truncated"] {
        assert!(converted.input.metadata.get(key).is_none());
    }
}

#[test]
fn a_digest_that_is_not_the_texts_refuses_the_line() {
    let mut r = reply("root");
    r.sha256 = output_digest("something else");
    assert!(matches!(
        convert_event(event(0, Some(r))),
        Err(ConvertError::BadReply(_))
    ));
}

#[test]
fn text_over_the_cap_refuses_the_line() {
    let at = reply(&"a".repeat(core_scoring::MAX_OUTPUT_BYTES));
    assert!(convert_event(event(0, Some(at))).is_ok());
    let over = reply(&"a".repeat(core_scoring::MAX_OUTPUT_BYTES + 1));
    assert!(matches!(
        convert_event(event(0, Some(over))),
        Err(ConvertError::BadReply(_))
    ));
}

#[test]
fn text_with_a_nul_refuses_the_line() {
    assert!(matches!(
        convert_event(event(0, Some(reply("a\0b")))),
        Err(ConvertError::BadReply(_))
    ));
}

#[test]
fn a_reply_on_metadata_that_is_not_an_object_refuses_the_line() {
    let mut e = event(0, Some(reply("x")));
    e.metadata = serde_json::json!("not an object");
    assert!(matches!(convert_event(e), Err(ConvertError::BadReply(_))));
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
}

fn runner(pool: &PgPool, dir: &std::path::Path) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        "ssh".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        Duration::from_secs(600),
    )
}

/// Three events, two sharing one reply: the ledger holds all three, each naming its reply by
/// digest in the metadata the chain covers; the text is stored once per distinct reply, and a
/// poisoned line (digest mismatch) is rejected without taking the others with it.
#[sqlx::test(migrations = false)]
async fn replies_are_stored_once_by_digest_and_named_in_the_ledger(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut bad = reply("forged");
    bad.sha256 = output_digest("not forged");
    let events = [
        event(0, Some(reply("uid=0(root)"))),
        event(1, Some(reply("uid=0(root)"))),
        event(2, Some(reply("Linux box"))),
        event(3, Some(bad)),
        event(4, None),
    ];
    let mut file = std::fs::File::create(dir.path().join("events.jsonl")).unwrap();
    for e in &events {
        writeln!(file, "{}", serde_json::to_string(e).unwrap()).unwrap();
    }

    let r = runner(&pool, dir.path()).run_batch().await;
    assert_eq!((r.ingested, r.rejected, r.errors), (4, 1, 0));

    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM shell_output")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 2, "two distinct replies, three events naming them");
    let text: String = sqlx::query_scalar("SELECT text FROM shell_output WHERE sha256 = $1")
        .bind(output_digest("uid=0(root)"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(text, "uid=0(root)");

    let named: Vec<Option<String>> =
        sqlx::query_scalar("SELECT metadata->>'output_sha256' FROM event ORDER BY observed_at")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        named,
        [
            Some(output_digest("uid=0(root)")),
            Some(output_digest("uid=0(root)")),
            Some(output_digest("Linux box")),
            None
        ]
    );
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);

    // The ledger rows never hold the text itself.
    let leaked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM event WHERE metadata::text LIKE '%uid=0(root)%'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(leaked, 0);
}

/// A reply already stored is left as it is when it arrives again.
#[sqlx::test(migrations = false)]
async fn storing_a_reply_again_keeps_the_first_row(pool: PgPool) {
    migrate(&pool).await;
    let pair = (output_digest("x"), "x".to_string());
    core_scoring::store_outputs(&pool, std::slice::from_ref(&pair))
        .await
        .unwrap();
    let first: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT first_seen FROM shell_output")
            .fetch_one(&pool)
            .await
            .unwrap();
    core_scoring::store_outputs(&pool, &[pair, (output_digest("y"), "y".to_string())])
        .await
        .unwrap();
    let again: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT first_seen FROM shell_output WHERE sha256 = $1")
            .bind(output_digest("x"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(first, again);
    let found = core_scoring::read_outputs(
        &pool,
        &[output_digest("x"), output_digest("y"), output_digest("z")],
    )
    .await
    .unwrap();
    assert_eq!(found.len(), 2, "a digest with no row is absent");
}

/// Two runners storing the same new replies in opposite orders must not deadlock: rows are
/// inserted in digest order whatever order they arrive in.
#[sqlx::test(migrations = false)]
async fn two_runners_storing_the_same_replies_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    migrate(&pool).await;
    for round in 0..15 {
        let forward: Vec<(String, String)> = (0..400)
            .map(|i| {
                let text = format!("reply {round} {i}");
                (output_digest(&text), text)
            })
            .collect();
        let mut backward = forward.clone();
        backward.reverse();
        let (a, b) = (pool.clone(), pool.clone());
        let one = tokio::spawn(async move { core_scoring::store_outputs(&a, &forward).await });
        let two = tokio::spawn(async move { core_scoring::store_outputs(&b, &backward).await });
        one.await.unwrap().expect("forward store");
        two.await.unwrap().expect("backward store");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM shell_output")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 15 * 400);
}

/// A reply the database always refuses (a trigger stands in for any permanent per-row refusal)
/// is accounted like a refused append of its line: the lines before it are ingested at once, the
/// poll reports the error, the refusal is reported as a wedge after `WEDGE_POLLS` polls, and then
/// the line is quarantined and the log behind it drains.
#[sqlx::test(migrations = false)]
async fn a_reply_the_database_refuses_wedges_then_quarantines_its_line(pool: PgPool) {
    migrate(&pool).await;
    sqlx::query(
        "CREATE FUNCTION refuse_poison() RETURNS trigger AS $$ BEGIN \
         IF NEW.text = 'poison' THEN RAISE EXCEPTION 'refused' USING ERRCODE = '23514'; END IF; \
         RETURN NEW; END $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER refuse_poison BEFORE INSERT ON shell_output \
         FOR EACH ROW EXECUTE FUNCTION refuse_poison()",
    )
    .execute(&pool)
    .await
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let texts = ["ok 0", "ok 1", "poison", "ok 3", "ok 4"];
    let mut file = std::fs::File::create(dir.path().join("events.jsonl")).unwrap();
    for (n, text) in texts.iter().enumerate() {
        writeln!(
            file,
            "{}",
            serde_json::to_string(&event(n as i64, Some(reply(text)))).unwrap()
        )
        .unwrap();
    }
    drop(file);
    let quarantine = dir.path().join("quarantine");
    let mut runner = runner(&pool, dir.path())
        .with_quarantine(intake::quarantine::Quarantine::new(quarantine.clone()));

    let first = runner.run_batch().await;
    assert_eq!(
        (first.ingested, first.errors, first.quarantined),
        (2, 1, 0),
        "the lines before the refused reply are ingested"
    );
    for _ in 2..intake::runner::WEDGE_POLLS {
        let again = runner.run_batch().await;
        assert_eq!((again.ingested, again.errors, again.quarantined), (0, 1, 0));
    }
    let third = runner.run_batch().await;
    assert_eq!((third.ingested, third.errors, third.quarantined), (0, 1, 1));
    assert!(runner.wedged().is_none());
    assert_eq!(
        runner.last_quarantine().and_then(|n| n.sqlstate.clone()),
        Some("23514".to_string()),
        "the notice carries the refusal's SQLSTATE"
    );
    let rest = runner.run_batch().await;
    assert_eq!((rest.ingested, rest.errors), (2, 0), "the log drains");
    let quarantined = std::fs::read_to_string(quarantine.join("ssh.jsonl")).unwrap();
    assert_eq!(quarantined.lines().count(), 1);
    assert!(quarantined.contains("23514"));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 4,
        "every line but the quarantined one is in the ledger"
    );
}
