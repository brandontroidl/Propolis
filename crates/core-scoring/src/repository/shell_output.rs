//! The text of what a fake shell answered, kept once per distinct reply (`shell_output`).
//!
//! Content-addressed: the key is the SHA-256 of the text, so storing the same reply again is a
//! no-op and the many sessions that ran one command share a row. An event refers to it by
//! `metadata.output_sha256`. Nothing here touches the event ledger or a projection.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// Most bytes of reply text a row holds; the same cap the sensor applies, and the table's CHECK.
pub const MAX_OUTPUT_BYTES: usize = 4096;

/// The digest a reply is stored under: lowercase hex SHA-256 of the text's bytes.
pub fn output_digest(text: &str) -> String {
    let mut hex = String::with_capacity(64);
    for b in Sha256::digest(text.as_bytes()) {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// The pairs in digest order, one per digest (the first text given for it).
fn sorted_unique(outputs: &[(String, String)]) -> Vec<(&str, &str)> {
    let mut by_sha: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for (sha, text) in outputs {
        by_sha.entry(sha.as_str()).or_insert(text.as_str());
    }
    by_sha.into_iter().collect()
}

/// Stores each `(sha256, text)` pair once; a digest already stored is left as it is. The caller
/// has checked each digest against its text ([`output_digest`]).
pub async fn store_outputs(pool: &PgPool, outputs: &[(String, String)]) -> Result<(), sqlx::Error> {
    if outputs.is_empty() {
        return Ok(());
    }
    let (shas, texts): (Vec<&str>, Vec<&str>) = sorted_unique(outputs).into_iter().unzip();
    // ORDER BY: two runners inserting the same new digests in opposite orders each hold one row's
    // lock and wait for the other's ("deadlock detected"); one fixed order makes them queue.
    sqlx::query(
        "INSERT INTO shell_output (sha256, text) \
         SELECT sha256, text FROM UNNEST($1::text[], $2::text[]) AS t(sha256, text) \
         ORDER BY sha256 \
         ON CONFLICT (sha256) DO UPDATE SET last_stored = now() \
             WHERE shell_output.last_stored < now() - interval '1 hour'",
    )
    .bind(&shas)
    .bind(&texts)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deletes the rows no event names (`metadata.output_sha256`) that intake has not stored for
/// `grace`, and returns how many. A row is orphaned when its batch's append failed or its line was
/// quarantined; the grace period keeps a row an in-flight batch is about to name (a re-store
/// refreshes `last_stored` at most hourly, so `grace` must exceed an hour). Uses
/// `event_output_sha256_idx`, so it never scans the ledger.
pub async fn prune_orphan_outputs(
    pool: &PgPool,
    grace: std::time::Duration,
) -> Result<u64, sqlx::Error> {
    let deleted = sqlx::query(
        "DELETE FROM shell_output o \
         WHERE o.last_stored < now() - make_interval(secs => $1) \
           AND NOT EXISTS (SELECT 1 FROM event e \
                           WHERE e.metadata ? 'output_sha256' \
                             AND e.metadata ->> 'output_sha256' = o.sha256)",
    )
    .bind(grace.as_secs_f64())
    .execute(pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

/// The stored text for each digest in `shas` that has a row; a digest with none is absent from the
/// map (an event recorded before the table, or whose text was not stored).
pub async fn read_outputs(
    pool: &PgPool,
    shas: &[String],
) -> Result<HashMap<String, String>, sqlx::Error> {
    if shas.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT sha256, text FROM shell_output WHERE sha256 = ANY($1)")
            .bind(shas)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(order: &[&str]) -> Vec<(String, String)> {
        order
            .iter()
            .map(|s| ((*s).to_string(), format!("text of {s}")))
            .collect()
    }

    #[test]
    fn the_order_the_pairs_arrive_in_does_not_change_the_order_they_are_inserted_in() {
        let forward = pairs(&["a1", "b2", "c3", "d4"]);
        let backward = pairs(&["d4", "c3", "b2", "a1"]);
        assert_eq!(sorted_unique(&forward), sorted_unique(&backward));
        assert_eq!(
            sorted_unique(&backward)
                .iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>(),
            ["a1", "b2", "c3", "d4"]
        );
    }

    #[test]
    fn a_digest_given_twice_is_inserted_once() {
        let twice = pairs(&["b2", "a1", "b2", "a1", "b2"]);
        assert_eq!(sorted_unique(&twice).len(), 2);
    }
}
