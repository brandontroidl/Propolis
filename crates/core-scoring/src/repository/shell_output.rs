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
         ON CONFLICT (sha256) DO NOTHING",
    )
    .bind(&shas)
    .bind(&texts)
    .execute(pool)
    .await?;
    Ok(())
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
