//! VirusTotal file analysis integration. Scans captured malware samples by
//! SHA-256 lookup, optionally uploads unknown samples for analysis.
//! Verified live against the VT v3 API 2026-08-19.
//!
//! Rate limit: VT free tier allows 4 requests/minute, 500/day. The scanner
//! respects this with a configurable delay between requests.

use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct VtConfig {
    pub api_key: String,
    pub upload_unknown: bool,
    pub scan_interval_secs: u64,
    pub request_delay_ms: u64,
    pub daily_limit: u32,
}

/// A request budget that caps VirusTotal calls per UTC day.
///
/// The scanner re-invokes `scan_spool` every `scan_interval_secs` (minutes), so a counter local
/// to a single `scan_spool` call resets every cycle and never enforces a DAILY cap - the caller
/// must own one `DailyBudget` across all cycles and thread it in. The budget resets itself when
/// the UTC date rolls over.
#[derive(Debug)]
pub struct DailyBudget {
    limit: u32,
    used: u32,
    day: NaiveDate,
}

impl DailyBudget {
    pub fn new(limit: u32, today: NaiveDate) -> Self {
        Self {
            limit,
            used: 0,
            day: today,
        }
    }

    /// Reserve one request against today's budget, resetting first if the UTC day has changed.
    /// Returns `false` (consuming nothing) when the day's limit is already exhausted.
    pub fn try_consume(&mut self, now: DateTime<Utc>) -> bool {
        let today = now.date_naive();
        if today != self.day {
            self.day = today;
            self.used = 0;
        }
        if self.used >= self.limit {
            return false;
        }
        self.used += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ts: &str) -> DateTime<Utc> {
        ts.parse::<DateTime<Utc>>().unwrap()
    }

    #[test]
    fn budget_refuses_past_limit_then_resets_on_new_utc_day() {
        let day1 = at("2026-08-21T23:00:00Z");
        let mut budget = DailyBudget::new(2, day1.date_naive());

        assert!(budget.try_consume(day1), "1st request within limit");
        assert!(budget.try_consume(day1), "2nd request within limit");
        assert!(
            !budget.try_consume(day1),
            "3rd request the same day must be refused"
        );

        let day2 = at("2026-08-22T00:05:00Z");
        assert!(
            budget.try_consume(day2),
            "budget must reset on the new UTC day"
        );
    }
}

#[derive(Debug, Clone)]
pub struct VtResult {
    pub sha256: String,
    pub detected: i32,
    pub total: i32,
    pub link: String,
}

pub async fn scan_spool(
    pool: &PgPool,
    config: &VtConfig,
    spool_dirs: &[(&str, PathBuf)],
    budget: &mut DailyBudget,
) -> Vec<VtResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();
    let mut results = Vec::new();

    for (sensor, dir) in spool_dirs {
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }

            if already_analyzed(pool, &name).await {
                continue;
            }

            if !budget.try_consume(Utc::now()) {
                tracing::info!(
                    limit = config.daily_limit,
                    "vt: daily request limit reached, pausing until the UTC day rolls over"
                );
                return results;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(config.request_delay_ms)).await;

            match lookup_hash(&client, &config.api_key, &name).await {
                Ok(Some(result)) => {
                    if let Err(e) = store_result(pool, &result, sensor).await {
                        tracing::error!(sha256 = %name, error = %e, "vt: failed to store result");
                    }
                    tracing::info!(
                        sha256 = %result.sha256[..12], detected = result.detected,
                        total = result.total, "vt: sample analyzed"
                    );
                    results.push(result);
                }
                Ok(None) => {
                    if config.upload_unknown {
                        let path = dir.join(&name);
                        match upload_sample(&client, &config.api_key, &path, &name).await {
                            Ok(()) => {
                                tracing::info!(sha256 = %name[..12], "vt: sample uploaded for analysis");
                                let pending = VtResult {
                                    sha256: name.clone(),
                                    detected: -1,
                                    total: -1,
                                    link: format!("https://www.virustotal.com/gui/file/{name}"),
                                };
                                let _ = store_result(pool, &pending, sensor).await;
                                results.push(pending);
                            }
                            Err(e) => {
                                tracing::warn!(sha256 = %name[..12], error = %e, "vt: upload failed");
                            }
                        }
                    } else {
                        tracing::info!(sha256 = %name[..12], "vt: sample not in VT database");
                    }
                }
                Err(e) => {
                    tracing::warn!(sha256 = %name[..12], error = %e, "vt: lookup failed");
                }
            }
        }
    }

    results
}

async fn already_analyzed(pool: &PgPool, sha256: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sample_analysis WHERE sha256 = $1")
        .bind(sha256)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
        > 0
}

async fn lookup_hash(
    client: &reqwest::Client,
    api_key: &str,
    sha256: &str,
) -> Result<Option<VtResult>, String> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?;

    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "VT returned {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("json parse error: {e}"))?;

    let stats = &body["data"]["attributes"]["last_analysis_stats"];
    let detected =
        stats["malicious"].as_i64().unwrap_or(0) + stats["suspicious"].as_i64().unwrap_or(0);
    let total = stats["malicious"].as_i64().unwrap_or(0)
        + stats["suspicious"].as_i64().unwrap_or(0)
        + stats["undetected"].as_i64().unwrap_or(0)
        + stats["harmless"].as_i64().unwrap_or(0);

    Ok(Some(VtResult {
        sha256: sha256.to_string(),
        detected: detected as i32,
        total: total as i32,
        link: format!("https://www.virustotal.com/gui/file/{sha256}"),
    }))
}

async fn upload_sample(
    client: &reqwest::Client,
    api_key: &str,
    path: &Path,
    sha256: &str,
) -> Result<(), String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read error: {e}"))?;

    let boundary = format!("----propolis{}", chrono::Utc::now().timestamp_millis());
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{sha256}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let resp = client
        .post("https://www.virustotal.com/api/v3/files")
        .header("x-apikey", api_key)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .map_err(|e| format!("upload error: {e}"))?;

    let status = resp.status().as_u16();
    if status == 200 || status == 201 {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "VT upload returned {status}: {}",
            body.chars().take(200).collect::<String>()
        ))
    }
}

async fn store_result(pool: &PgPool, result: &VtResult, sensor: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sample_analysis (sha256, detected, total, vt_link, source_sensor, analyzed_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (sha256) DO UPDATE SET detected = $2, total = $3, vt_link = $4, analyzed_at = $6",
    )
    .bind(&result.sha256)
    .bind(result.detected)
    .bind(result.total)
    .bind(&result.link)
    .bind(sensor)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn cleanup_old_samples(spool_dirs: &[(&str, PathBuf)], max_age_days: u64) {
    let cutoff =
        std::time::SystemTime::now() - std::time::Duration::from_secs(max_age_days * 86400);
    let mut removed = 0u64;

    for (_sensor, dir) in spool_dirs {
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if let Ok(meta) = entry.metadata().await
                && let Ok(modified) = meta.modified()
                && modified < cutoff
                && tokio::fs::remove_file(entry.path()).await.is_ok()
            {
                removed += 1;
            }
        }
    }

    if removed > 0 {
        tracing::info!(removed, max_age_days, "spool: cleaned up old samples");
    }
}
