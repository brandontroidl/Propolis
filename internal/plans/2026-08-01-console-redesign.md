# Console Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the Propolis operator console from scaffold-grade UI into a dense, terminal-influenced operator tool focused on review workflow and threat picture.

**Architecture:** Server-rendered HTML (axum + minijinja + HTMX). All CSS inlined in base_head.html. No new crate dependencies. Changes are template CSS/HTML + new dashboard queries + uptime/version/pending-count in shared state.

**Tech Stack:** Rust, axum, minijinja, HTMX, sqlx (Postgres), chrono.

## Global Constraints

- Rust 2024 edition. `crates/console/`.
- No new crate dependencies. No JS frameworks or external stylesheets.
- Dark theme with amber accent palette. Monospace numbers, tabular-nums, tight padding.
- All CSS inlined in `base_head.html`.
- Commits: conventional, lowercase, no AI-attribution trailer.
- Canonical spec: `internal/design/09-console-redesign.md`.

---

### Task 1: Add startup_time and pending_count to AppState and base template context

**Files:**
- Modify: `crates/console/src/lib.rs` (add `startup_time: DateTime<Utc>` and `version: &'static str` to `AppState`)
- Modify: `crates/console/src/routes/mod.rs` (add middleware that injects `pending_count`, `uptime`, `version` into every template render)
- Modify: `crates/console/src/main.rs` (set `startup_time` and `version` at init)
- Modify: `crates/propolis/src/main.rs` (pass `startup_time` and `version` when constructing `AppState`)

**Produces:**
- `AppState.startup_time: DateTime<Utc>`
- `AppState.version: &'static str`
- Template context variables `pending_count: i64`, `uptime: String`, `version: String` available on every authenticated page

- [ ] Add `startup_time: chrono::DateTime<chrono::Utc>` and `version: &'static str` fields to `AppState` in `crates/console/src/lib.rs`.

- [ ] In `crates/console/src/main.rs`, set `startup_time: chrono::Utc::now()` and `version: env!("CARGO_PKG_VERSION")` when constructing `AppState`.

- [ ] In `crates/propolis/src/main.rs`'s `run_console` function, set the same two fields when constructing `AppState`.

- [ ] Create `crates/console/src/routes/context.rs`: a helper function `base_context` that queries pending count and computes uptime from `AppState`:

```rust
use chrono::Utc;
use sqlx::PgPool;

pub(crate) struct BaseContext {
    pub pending_count: i64,
    pub uptime: String,
    pub version: &'static str,
}

pub(crate) async fn base_context(db: &PgPool, startup_time: chrono::DateTime<Utc>, version: &'static str) -> BaseContext {
    let pending_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM review_queue WHERE state = 'pending'"
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let elapsed = Utc::now() - startup_time;
    let hours = elapsed.num_hours();
    let minutes = elapsed.num_minutes() % 60;
    let uptime = if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    };

    BaseContext { pending_count, uptime, version }
}
```

- [ ] Add `pub(crate) mod context;` to `crates/console/src/routes/mod.rs`.

- [ ] Update every route handler that renders a full page (dashboard, queue_page, detail, feed_status) to call `base_context` and merge its fields into the template context: `pending_count`, `uptime`, `version`.

- [ ] Verify the console compiles: `cargo check -p console`.

- [ ] Commit: `feat(console): add pending count, uptime, and version to shared template context`

---

### Task 2: Redesign base template shell (nav, footer, favicon, empty-state pattern, compact CSS)

**Files:**
- Modify: `crates/console/src/templates/base_head.html` (CSS overhaul + favicon)
- Modify: `crates/console/src/templates/base_tail.html` (nav badge, uptime/version, sign-out, footer)

**Consumes:** `pending_count`, `uptime`, `version` from Task 1's base context.

- [ ] In `base_tail.html`, update the nav to include:
  - Pending badge on review queue link: `Review queue{% if pending_count > 0 %} <span class="badge">{{ pending_count }}</span>{% endif %}`
  - Right-side group: `<span class="nav-meta mono dim">up {{ uptime }}</span> <span class="nav-meta mono dim">v{{ version }}</span> <a href="/logout">Sign out</a>`

- [ ] In `base_head.html`, add favicon as inline SVG data URI in a `<link>` tag (amber shield on transparent background).

- [ ] In `base_head.html`, update CSS - compact card sizing:
  - `.stat-card` padding: `0.7rem 0.9rem` (from `1rem 1.15rem`)
  - `.stat-card .value` font-size: `1.4rem` (from `1.9rem`)
  - `.stat-card .label` font-size: `0.62rem` (from `0.72rem`)
  - `.stat-row` grid: `grid-template-columns: repeat(auto-fit, minmax(140px, 1fr))` (from `180px`)

- [ ] Add CSS for compact table rows:
```css
.table-compact th, .table-compact td { padding: 0.4rem 0.7rem; font-size: 0.82rem; }
.table-compact .meter { width: 48px; height: 4px; }
```

- [ ] Add CSS for nav badge:
```css
.badge { background: var(--accent); color: #1a1006; font-size: 0.65rem; font-weight: 700; padding: 0.1rem 0.4rem; border-radius: 3px; margin-left: 0.3rem; font-family: var(--font-mono); }
.nav-meta { font-size: 0.72rem; }
.topnav .right { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
```

- [ ] Add CSS for the new empty-state pattern:
```css
.empty-line { color: var(--text-dim); font-family: var(--font-mono); font-size: 0.82rem; padding: 1.5rem 0; }
```

- [ ] Add CSS for footer status line:
```css
.status-line { text-align: center; color: var(--text-dim); font-family: var(--font-mono); font-size: 0.7rem; padding: 2rem 0 1rem; letter-spacing: 0.03em; }
```

- [ ] Add CSS for accent left-border on stat cards:
```css
.stat-card-accent { border-left: 3px solid var(--accent); }
```

- [ ] Add CSS for collapsed textarea:
```css
.actions textarea { min-height: 1.6rem; height: 1.6rem; transition: height 150ms ease; }
.actions textarea:focus { height: 3.5rem; }
```

- [ ] In `base_tail.html`, add footer before `</body>`:
```html
<div class="status-line">propolis v{{ version }} - up {{ uptime }}</div>
```

- [ ] Add a `/logout` route in `crates/console/src/routes/login.rs` that clears the session cookie and redirects to `/login`.

- [ ] Verify compile: `cargo check -p console`.

- [ ] Commit: `feat(console): redesign shell with nav badge, sign-out, footer, compact CSS`

---

### Task 3: Redesign dashboard with six-card stat strip, activity log, and protocol distribution

**Files:**
- Modify: `crates/console/src/routes/dashboard.rs` (add 4 new queries, restructure template context)
- Modify: `crates/console/src/templates/dashboard.html` (new layout)
- Modify: `crates/console/src/routes/format.rs` (add `format_relative_time` helper)

**Consumes:** `base_context` from Task 1.

- [ ] Add `format_relative_time` to `crates/console/src/routes/format.rs`:

```rust
pub(crate) fn format_relative_time(dt: DateTime<Utc>) -> String {
    let elapsed = Utc::now() - dt;
    if elapsed.num_seconds() < 60 {
        return format!("{}s ago", elapsed.num_seconds());
    }
    if elapsed.num_minutes() < 60 {
        return format!("{}m ago", elapsed.num_minutes());
    }
    if elapsed.num_hours() < 24 {
        return format!("{}h ago", elapsed.num_hours());
    }
    format!("{}d ago", elapsed.num_days())
}
```

- [ ] In `dashboard.rs`, add new queries and structs:

```rust
#[derive(Debug, Serialize)]
struct RecentEvent {
    relative_time: String,
    sensor: String,
    signal_type: String,
    source_ip: String,
}

#[derive(Debug, Serialize)]
struct ProtocolCount {
    sensor: String,
    count: i64,
}
```

- [ ] Add query for events last hour:
```rust
let events_last_hour: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM event WHERE observed_at >= now() - interval '1 hour'"
)
.fetch_one(&state.db)
.await
.unwrap_or(0);
```

- [ ] Add query for top attacker:
```rust
let top_attacker: Option<(String, String)> = sqlx::query_as::<_, (String, String)>(
    "SELECT host(source_ip), raw_score::text FROM ip_score ORDER BY raw_score DESC LIMIT 1"
)
.fetch_optional(&state.db)
.await
.unwrap_or(None);
let top_attacker_ip = top_attacker.as_ref().map(|t| t.0.as_str()).unwrap_or("--");
let top_attacker_score = top_attacker.as_ref().map(|t| t.1.as_str()).unwrap_or("");
```

- [ ] Add query for recent events (last 20):
```rust
let recent_event_rows = sqlx::query(
    "SELECT observed_at, sensor, signal_type::text, host(source_ip) AS source_ip \
     FROM event ORDER BY observed_at DESC LIMIT 20"
)
.fetch_all(&state.db)
.await
.unwrap_or_default();

let recent_events: Vec<RecentEvent> = recent_event_rows.iter().map(|row| {
    let observed_at: DateTime<Utc> = row.get("observed_at");
    RecentEvent {
        relative_time: format_relative_time(observed_at),
        sensor: row.get("sensor"),
        signal_type: row.get("signal_type"),
        source_ip: row.get("source_ip"),
    }
}).collect();
```

- [ ] Add query for protocol distribution (24h):
```rust
let protocol_rows = sqlx::query(
    "SELECT sensor, COUNT(*) AS cnt FROM event \
     WHERE observed_at >= now() - interval '24 hours' \
     GROUP BY sensor ORDER BY cnt DESC"
)
.fetch_all(&state.db)
.await
.unwrap_or_default();

let protocol_dist: Vec<ProtocolCount> = protocol_rows.iter().map(|row| {
    ProtocolCount { sensor: row.get("sensor"), count: row.get("cnt") }
}).collect();
```

- [ ] Add active feed entries count (read from manifest.json if feed_output_dir is set):
```rust
let feed_entries = state.feed_output_dir.as_ref()
    .and_then(|dir| std::fs::read_to_string(dir.join("manifest.json")).ok())
    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    .map(|m| {
        let agg = m.get("aggressive_count").and_then(|v| v.as_i64()).unwrap_or(0);
        let std = m.get("standard_count").and_then(|v| v.as_i64()).unwrap_or(0);
        agg + std
    })
    .unwrap_or(-1); // -1 signals "no data" -> display as "--"
```

- [ ] Update the template context render call to include all new variables.

- [ ] Rewrite `crates/console/src/templates/dashboard.html`:

```html
{% extends "base.html" %}
{% block title %}Dashboard - Propolis{% endblock %}
{% block content %}
<h1>Dashboard</h1>
<div class="stat-row">
  <div class="stat-card{% if pending_reviews > 0 %} stat-card-accent{% endif %}">
    <div class="label">Pending review</div>
    <div class="value"><a href="/queue">{{ pending_reviews }}</a></div>
  </div>
  <div class="stat-card">
    <div class="label">Total scored IPs</div>
    <div class="value">{{ total_scored_ips }}</div>
  </div>
  <div class="stat-card">
    <div class="label">Approved today</div>
    <div class="value">{{ approved_today }}</div>
  </div>
  <div class="stat-card">
    <div class="label">Events / hour</div>
    <div class="value">{% if events_last_hour >= 0 %}{{ events_last_hour }}{% else %}--{% endif %}</div>
  </div>
  <div class="stat-card">
    <div class="label">Feed entries</div>
    <div class="value">{% if feed_entries >= 0 %}{{ feed_entries }}{% else %}--{% endif %}</div>
  </div>
  <div class="stat-card">
    <div class="label">Top attacker</div>
    <div class="value" style="font-size:0.95rem">{% if top_attacker_ip != "--" %}<a href="/ip/{{ top_attacker_ip }}">{{ top_attacker_ip }}</a>{% else %}--{% endif %}</div>
  </div>
</div>

<h2 class="section-title">Recent activity</h2>
{% if recent_events %}
<div class="table-wrap">
<table class="table-compact">
  <thead><tr><th>When</th><th>Sensor</th><th>Signal</th><th>Source</th></tr></thead>
  <tbody>
    {% for e in recent_events %}
    <tr>
      <td class="seen mono">{{ e.relative_time }}</td>
      <td>{{ e.sensor }}</td>
      <td>{{ e.signal_type }}</td>
      <td class="ip"><a href="/ip/{{ e.source_ip }}">{{ e.source_ip }}</a></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>
{% else %}
<p class="empty-line">waiting for sensor events - start a sensor to begin collecting</p>
{% endif %}

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-top:2rem;">
  <div>
    <h2 class="section-title" style="margin-top:0">Protocol distribution (24h)</h2>
    {% if protocol_dist %}
    <div class="table-wrap">
    <table class="table-compact">
      <thead><tr><th>Sensor</th><th>Events</th></tr></thead>
      <tbody>
        {% for p in protocol_dist %}
        <tr><td>{{ p.sensor }}</td><td class="mono">{{ p.count }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    </div>
    {% else %}
    <p class="empty-line">waiting for sensor events</p>
    {% endif %}
  </div>
  <div>
    <h2 class="section-title" style="margin-top:0">Recent vendor submissions</h2>
    {% if recent_submissions %}
    <div class="table-wrap">
    <table class="table-compact">
      <thead><tr><th>IP</th><th>Vendor</th><th>Submitted</th><th>Result</th></tr></thead>
      <tbody>
        {% for s in recent_submissions %}
        <tr>
          <td class="ip"><a href="/ip/{{ s.source_ip }}">{{ s.source_ip }}</a></td>
          <td>{{ s.vendor }}</td>
          <td class="seen">{{ s.submitted_at }}</td>
          <td>{% if s.success %}<span class="state-pill state-approved">Sent</span>{% else %}<span class="state-pill state-rejected">Failed</span>{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    </div>
    {% else %}
    <p class="empty-line">no vendor submissions yet</p>
    {% endif %}
  </div>
</div>
{% endblock %}
```

- [ ] Run `cargo check -p console` to verify.

- [ ] Commit: `feat(console): dense dashboard with activity log, protocol dist, and six stat cards`

---

### Task 4: Polish queue, detail, feed, and login pages

**Files:**
- Modify: `crates/console/src/templates/queue.html` (compact treatment, new empty state)
- Modify: `crates/console/src/templates/queue_row.html` (tighter padding via table-compact class)
- Modify: `crates/console/src/templates/detail.html` (compact cards, relative timestamps, back link)
- Modify: `crates/console/src/templates/feed.html` (contextual empty states)
- Modify: `crates/console/src/templates/login.html` (remove nav, add version)
- Modify: `crates/console/src/routes/detail.rs` (add relative timestamps to evidence rows)

**Consumes:** `format_relative_time` from Task 3, `base_context` from Task 1.

- [ ] Update `queue.html`: add `table-compact` class to table, change empty state from `<p class="empty">Nothing pending review.</p>` to `<p class="empty-line">queue empty - no IPs have crossed the recommendation threshold yet</p>`.

- [ ] Update `queue_row.html`: the table-compact CSS from Task 2 handles row density. No template changes needed beyond inheriting the class.

- [ ] Update `detail.html`:
  - Add back-to-queue link at top: `<p><a href="/queue">&larr; back to queue</a></p>` before the h1.
  - Add `table-compact` class to all tables.
  - In the evidence timeline, add a `relative_time` column next to the absolute timestamp.

- [ ] Update `crates/console/src/routes/detail.rs` to include `relative_time` in each evidence row's template data using `format_relative_time`.

- [ ] Update `feed.html` empty states:
  - When no builds: replace `<p class="empty">No feed builds yet.</p>` with `<p class="empty-line">{% if feed_disabled %}feed builder is disabled on this node{% else %}feed enabled - awaiting first build{% endif %}</p>`
  - Add `feed_disabled` to the feed route's template context (true when `feed_output_dir` is None).

- [ ] Update `crates/console/src/routes/feed.rs` to pass `feed_disabled` boolean.

- [ ] Update `login.html`:
  - Change `{% block nav %}{% endblock %}` to also hide the topnav bar entirely. Add a block override: `{% block topnav %}{% endblock %}` and wrap the topnav div in `base_tail.html` with `{% block topnav %}...{% endblock %}`.
  - Add `<p class="dim" style="text-align:center;font-size:0.72rem;margin-top:1rem;">v{{ version }}</p>` below the form.

- [ ] Run `cargo check -p console` and `cargo test -p console`.

- [ ] Commit: `feat(console): polish queue, detail, feed, and login pages`

---

### Task 5: Visual verification and final cleanup

**Files:**
- All template files (read-only verification pass)
- Possibly minor CSS adjustments

- [ ] Start the propolis daemon (or the standalone console binary) against the test database.

- [ ] Open each page in Chrome via claude-in-chrome and take screenshots:
  - Login page
  - Dashboard (empty state)
  - Review queue (empty state)
  - Feed status (disabled state)

- [ ] Verify: no dashed-border empty boxes remain, nav badge renders, sign-out link works, footer shows version and uptime, favicon appears in browser tab.

- [ ] Fix any visual issues found (spacing, alignment, overflow on narrow viewports).

- [ ] Run the full console test suite: `cargo test -p console`.

- [ ] Commit any fixes: `fix(console): visual adjustments from browser verification`

- [ ] Push to origin.
