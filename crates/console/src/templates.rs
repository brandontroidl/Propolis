//! The console's minijinja template environment (`internal/design/06-console-observability.md`,
//! "Pages"). Every template is embedded into the binary via `include_str!` - there is no template
//! directory to ship or read at runtime - and minijinja auto-escapes any template whose registered
//! name ends in `.html` (verified against `vendor/minijinja/src/defaults.rs`'s
//! `default_auto_escape_callback`), which is this crate's XSS-prevention guarantee: every value
//! interpolated with `{{ }}` is HTML-escaped unless a template explicitly opts out with the `|safe`
//! filter (which nothing here does).
//!
//! `base.html`'s source is assembled at COMPILE TIME from five pieces: `base_head.html`, the
//! vendored `chart.min.js`, `chart_defaults.html`, the vendored `htmx.min.js`, and `base_tail.html`,
//! joined via `concat!(include_str!(..), ..)`, so neither the ~200KB minified Chart.js distribution
//! nor the ~50KB minified HTMX distribution ever has to be hand-transcribed into an HTML file or
//! spliced in at runtime; `concat!` accepts `include_str!` results because they expand to string
//! literals before `concat!` sees them. `htmx.min.js` is the unmodified, upstream `htmx.org@2.0.10`
//! distribution (cross-checked byte-for-byte against two independent CDNs mirroring the same
//! published npm package: unpkg and jsdelivr), no CDN dependency at runtime, per the task's global
//! constraint. `chart.min.js` is the unmodified, upstream `chart.js@4.5.1` UMD distribution (same
//! byte-for-byte cross-check against unpkg and jsdelivr) and sets `window.Chart` on load.
//!
//! `base_head.html` ends mid-tag, with `<body>` followed by an unclosed `<script>` - this opens the
//! Chart.js script tag; `chart_defaults.html` closes it, adds a second self-contained `<script>`
//! block applying the console's dark theme to `Chart.defaults`, then opens a third, unclosed
//! `<script>` tag for HTMX; `base_tail.html` closes that one and continues the page. Chart.js loads
//! before HTMX only because that ordering lets `base_head.html`'s existing trailing `<script>` be
//! reused as-is; the two libraries are independent (each only attaches its own global) and every
//! inline `<script>` in `base_tail.html` and the child page templates runs later still, inside
//! `<main>`, so load order between them is not otherwise significant.

use minijinja::Environment;

const BASE_HTML: &str = concat!(
    include_str!("templates/base_head.html"),
    include_str!("templates/chart.min.js"),
    include_str!("templates/chart_defaults.html"),
    include_str!("templates/htmx.min.js"),
    include_str!("templates/base_tail.html"),
);
const DASHBOARD_HTML: &str = include_str!("templates/dashboard.html");
const QUEUE_HTML: &str = include_str!("templates/queue.html");
const QUEUE_ROW_HTML: &str = include_str!("templates/queue_row.html");
const QUEUE_HISTORY_ROW_HTML: &str = include_str!("templates/queue_history_row.html");
const LOGIN_HTML: &str = include_str!("templates/login.html");
const DETAIL_HTML: &str = include_str!("templates/detail.html");
const DRAWER_SHELL_HTML: &str = include_str!("templates/drawer_shell.html");
const FEED_HTML: &str = include_str!("templates/feed.html");
const SESSION_CARDS_HTML: &str = include_str!("templates/session_cards.html");
const EVENTS_FRAGMENT_HTML: &str = include_str!("templates/events_fragment.html");
const DETAIL_CHART_FRAGMENT_HTML: &str = include_str!("templates/detail_chart_fragment.html");
const DASHBOARD_CHART_FRAGMENT_HTML: &str = include_str!("templates/dashboard_chart_fragment.html");
const SEARCH_HTML: &str = include_str!("templates/search.html");
const SEARCH_EVENTS_ROWS_HTML: &str = include_str!("templates/search_events_rows.html");
const SEARCH_EVENTS_FRAGMENT_HTML: &str = include_str!("templates/search_events_fragment.html");
const LOGS_HTML: &str = include_str!("templates/logs.html");
const FLEET_HTML: &str = include_str!("templates/fleet.html");
const FLEET_STATUS_FRAGMENT_HTML: &str = include_str!("templates/fleet_status_fragment.html");
const MACROS_HTML: &str = include_str!("templates/macros.html");

/// Builds the environment once at startup (`AppState::templates`); cheap to construct (five small
/// templates) but shared via `Arc` so the source is parsed exactly once per process rather than
/// once per request.
pub fn environment() -> Environment<'static> {
    let mut env = Environment::new();
    // Shared macros (the canonical IP evidence-link drawer trigger). Imported by every page that
    // renders an IP link so the drawer contract lives in exactly one place.
    env.add_template("macros.html", MACROS_HTML)
        .expect("macros.html must be a valid template");
    env.add_template("base.html", BASE_HTML)
        .expect("base.html must be a valid template");
    env.add_template("dashboard.html", DASHBOARD_HTML)
        .expect("dashboard.html must be a valid template");
    env.add_template("queue.html", QUEUE_HTML)
        .expect("queue.html must be a valid template");
    env.add_template("queue_row.html", QUEUE_ROW_HTML)
        .expect("queue_row.html must be a valid template");
    // The approved/rejected/snoozed history tabs (console-forensics task 6): decided_at/notes/
    // submissions instead of the pending tab's action buttons - see `routes::queue`'s doc comment.
    env.add_template("queue_history_row.html", QUEUE_HISTORY_ROW_HTML)
        .expect("queue_history_row.html must be a valid template");
    env.add_template("login.html", LOGIN_HTML)
        .expect("login.html must be a valid template");
    env.add_template("detail.html", DETAIL_HTML)
        .expect("detail.html must be a valid template");
    // Bare layout the evidence drawer reuses: detail.html extends this (instead of base.html) when
    // the detail handler answers the drawer's HTMX request, so the slide-over renders the real
    // /ip/{ip} dossier from one template - see `routes::detail`'s drawer handling.
    env.add_template("drawer_shell.html", DRAWER_SHELL_HTML)
        .expect("drawer_shell.html must be a valid template");
    env.add_template("feed.html", FEED_HTML)
        .expect("feed.html must be a valid template");
    // Fragments (console-forensics task 4): partial templates rendered standalone by an HTMX
    // endpoint's handler (no `base.html` wrapper) and also `{% include %}`-ed from the full page
    // template that shows the same content on first load, so the two never drift into two
    // different markups for the same data - `detail.rs`/`dashboard.rs`'s own doc comments explain
    // each one's endpoint.
    env.add_template("session_cards.html", SESSION_CARDS_HTML)
        .expect("session_cards.html must be a valid template");
    env.add_template("events_fragment.html", EVENTS_FRAGMENT_HTML)
        .expect("events_fragment.html must be a valid template");
    env.add_template("detail_chart_fragment.html", DETAIL_CHART_FRAGMENT_HTML)
        .expect("detail_chart_fragment.html must be a valid template");
    env.add_template(
        "dashboard_chart_fragment.html",
        DASHBOARD_CHART_FRAGMENT_HTML,
    )
    .expect("dashboard_chart_fragment.html must be a valid template");
    // Console-forensics task 5: event/IP search page plus its own load-more fragment pair, same
    // full-page/fragment split as `session_cards.html`/`events_fragment.html` above.
    env.add_template("search.html", SEARCH_HTML)
        .expect("search.html must be a valid template");
    env.add_template("search_events_rows.html", SEARCH_EVENTS_ROWS_HTML)
        .expect("search_events_rows.html must be a valid template");
    env.add_template("search_events_fragment.html", SEARCH_EVENTS_FRAGMENT_HTML)
        .expect("search_events_fragment.html must be a valid template");
    // Console-forensics task 7: live system log viewer (`routes::logs`).
    env.add_template("logs.html", LOGS_HTML)
        .expect("logs.html must be a valid template");
    // The fleet pane (`routes::fleet`), same full-page/fragment split as the pairs above: the
    // fragment is what `/fleet/status` renders on the 30-second refresh and what `fleet.html`
    // includes on first load.
    env.add_template("fleet.html", FLEET_HTML)
        .expect("fleet.html must be a valid template");
    env.add_template("fleet_status_fragment.html", FLEET_STATUS_FRAGMENT_HTML)
        .expect("fleet_status_fragment.html must be a valid template");
    env.add_template("ips.html", IPS_HTML)
        .expect("ips.html must be a valid template");
    env.add_template("integrity.html", INTEGRITY_HTML)
        .expect("integrity.html must be a valid template");
    env.add_template("samples.html", SAMPLES_HTML)
        .expect("samples.html must be a valid template");
    env
}

const IPS_HTML: &str = include_str!("templates/ips.html");
const INTEGRITY_HTML: &str = include_str!("templates/integrity.html");
const SAMPLES_HTML: &str = include_str!("templates/samples.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_registers_and_extends_cleanly() {
        // `add_template` above already asserts this at call time (via `.expect`), but this test
        // documents and re-verifies the invariant explicitly, and would fail loudly (not panic
        // during an unrelated test's setup) if a future template edit breaks parsing.
        let _ = environment();
    }

    #[test]
    fn interpolated_values_are_html_escaped() {
        // Behavioral proof of the doc comment's auto-escape claim: a value containing HTML
        // metacharacters must never reach the response unescaped. `login.html`'s `error` value is
        // operator-controlled data flowing straight from a POST body (via the wrong-password
        // message path an attacker cannot influence, but the template itself does not know that -
        // it must escape regardless), so it stands in for any future template that interpolates
        // less-trusted data.
        let env = environment();
        let tmpl = env.get_template("login.html").unwrap();
        let html = tmpl
            .render(minijinja::context! { error => "<script>alert(1)</script>" })
            .unwrap();
        assert!(
            !html.contains("<script>alert"),
            "raw markup leaked into rendered output unescaped: {html}"
        );
        // Verified against `vendor/minijinja/src/utils.rs`'s escape table: `<` -> `&lt;`,
        // `>` -> `&gt;`, and `/` -> `&#x2f;` (minijinja escapes `/` too, not just the HTML-special
        // five).
        assert!(html.contains("&lt;script&gt;alert(1)&lt;&#x2f;script&gt;"));
    }

    /// The fields `fleet_status_fragment.html` reads unconditionally, so a test can vary only the
    /// one thing it is about. Mirrors `routes::fleet`'s `render`; the panel-specific flags are
    /// merged over the top by each test.
    fn fleet_base_context() -> minijinja::Value {
        minijinja::context! {
            summary => minijinja::context! {
                total => 0, proven => 0, alarm => 0, unknown => 0,
                headline => "every listener proven", headline_level => "ok",
            },
            listeners => Vec::<()>::new(),
            captures => Vec::<()>::new(),
            captures_unavailable => false,
            ledger_unavailable => false,
            ledger => minijinja::context! {
                events => 0, newest_ingested_ago => (), dot => "dot dot--watch",
            },
            feed => minijinja::context! { disabled => true, dot => "dot dot--watch", note => "" },
            version_status => minijinja::context! {
                running_version => "0.0.0", running_sha => "abc1234", built_at => "now",
                installed_sha => (), binary_name => "propolis", verdict => "not recorded",
                verdict_sev => "sev sev--watch", note => "", stamp_head_sha => (),
                stamp_origin_main_sha => (), stamp_age => (),
            },
            last_event_ago => "never",
            last_event_level => "unknown",
            degraded_panels => Vec::<&str>::new(),
        }
    }

    /// Renders `fleet_status_fragment.html` with an empty capture list, which is what BOTH a quiet
    /// week and a failed capture query produce. The sentence has to differ: "no malware captures
    /// in the last 7 days" is a statement about the fleet, and printing it because a query errored
    /// is the console reporting a finding it never read.
    #[test]
    fn an_unreadable_capture_panel_does_not_claim_there_were_no_captures() {
        let env = environment();
        let tmpl = env.get_template("fleet_status_fragment.html").unwrap();

        let failed = tmpl
            .render(minijinja::context! {
                captures_unavailable => true,
                degraded_panels => vec!["capture completeness"],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(
            !failed.contains("no malware captures"),
            "a failed capture query must not render as an absence of captures: {failed}"
        );
        assert!(
            failed.contains("could not be read"),
            "the panel must say it could not be read: {failed}"
        );

        // The genuinely quiet week still reads the way it always did.
        let quiet = tmpl.render(fleet_base_context()).unwrap();
        assert!(quiet.contains("no malware captures in the last 7 days"));
        assert!(!quiet.contains("could not be read"));
    }

    /// Same distinction on the ledger: a count that failed is not a count of zero.
    #[test]
    fn an_unreadable_ledger_does_not_render_as_zero_events() {
        let env = environment();
        let tmpl = env.get_template("fleet_status_fragment.html").unwrap();
        let html = tmpl
            .render(minijinja::context! {
                ledger_unavailable => true,
                ledger => minijinja::context! {
                    events => (), newest_ingested_ago => (), dot => "dot dot--watch",
                },
                last_event_ago => "unavailable",
                degraded_panels => vec!["ledger head"],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(
            html.contains("the event count could not be read"),
            "the ledger cell must say the count is unreadable: {html}"
        );
        assert!(
            !html.contains("events recorded"),
            "a failed count must not be presented as a count of recorded events: {html}"
        );
        // Both surfaces that show the count - the band cell and the evidence-chain panel - plus
        // the "Newest ingest" line have to say so; a number in either is a fabricated reading.
        assert!(
            html.matches("unavailable").count() >= 3,
            "every ledger reading on the page must say unavailable: {html}"
        );
        assert!(
            !html.contains(">never<"),
            "an unread ledger must not claim nothing was ever ingested: {html}"
        );

        // The readable ledger still renders its real numbers.
        let readable = env
            .get_template("fleet_status_fragment.html")
            .unwrap()
            .render(minijinja::context! {
                ledger => minijinja::context! {
                    events => 4242, newest_ingested_ago => "3 minutes ago", dot => "dot dot--low",
                },
                ..fleet_base_context()
            })
            .unwrap();
        assert!(readable.contains("4242") && readable.contains("events recorded"));
    }

    /// The fleet page polls; a poll that starts failing leaves the last render on screen with
    /// server-computed ages that never move again. `data-live` is what opts the container into
    /// `base_tail.html`'s stale handling, so losing the attribute silently restores that bug.
    #[test]
    fn the_polled_fleet_container_is_marked_live_and_the_page_handles_a_failed_poll() {
        let env = environment();
        let page = env.get_template("fleet.html").unwrap();
        let html = page
            .render(minijinja::context! {
                pending_count => 0,
                uptime => "1m",
                version => "0.0.0",
                degraded => Vec::<&str>::new(),
                ..fleet_base_context()
            })
            .unwrap();
        assert!(
            html.contains(r#"id="fleet-status""#) && html.contains(r#"data-live="fleet reading""#),
            "the polled container must carry data-live so a failed refresh is announced"
        );
        // The handler that acts on it ships in the same document (base.html's tail).
        for event in ["htmx:responseError", "htmx:sendError", "htmx:timeout"] {
            assert!(
                html.contains(event),
                "the page must handle {event} on a polled panel"
            );
        }
        assert!(
            html.contains("has stopped "),
            "the stale banner's wording must be present in the page"
        );
    }
}
