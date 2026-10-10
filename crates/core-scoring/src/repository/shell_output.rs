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

/// Stores each `(sha256, text)` pair once; a digest already stored is left as it is. The caller
/// has checked each digest against its text ([`output_digest`]).
pub async fn store_outputs(pool: &PgPool, outputs: &[(String, String)]) -> Result<(), sqlx::Error> {
    if outputs.is_empty() {
        return Ok(());
    }
    let (shas, texts): (Vec<&str>, Vec<&str>) = outputs
        .iter()
        .map(|(sha, text)| (sha.as_str(), text.as_str()))
        .unzip();
    sqlx::query(
        "INSERT INTO shell_output (sha256, text) \
         SELECT * FROM UNNEST($1::text[], $2::text[]) \
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
