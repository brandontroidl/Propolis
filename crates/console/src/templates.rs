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
const LOGIN_HTML: &str = include_str!("templates/login.html");
const DETAIL_HTML: &str = include_str!("templates/detail.html");
const FEED_HTML: &str = include_str!("templates/feed.html");
const SESSION_CARDS_HTML: &str = include_str!("templates/session_cards.html");
const EVENTS_FRAGMENT_HTML: &str = include_str!("templates/events_fragment.html");
const DETAIL_CHART_FRAGMENT_HTML: &str = include_str!("templates/detail_chart_fragment.html");
const DASHBOARD_CHART_FRAGMENT_HTML: &str = include_str!("templates/dashboard_chart_fragment.html");

/// Builds the environment once at startup (`AppState::templates`); cheap to construct (five small
/// templates) but shared via `Arc` so the source is parsed exactly once per process rather than
/// once per request.
pub fn environment() -> Environment<'static> {
    let mut env = Environment::new();
    env.add_template("base.html", BASE_HTML)
        .expect("base.html must be a valid template");
    env.add_template("dashboard.html", DASHBOARD_HTML)
        .expect("dashboard.html must be a valid template");
    env.add_template("queue.html", QUEUE_HTML)
        .expect("queue.html must be a valid template");
    env.add_template("queue_row.html", QUEUE_ROW_HTML)
        .expect("queue_row.html must be a valid template");
    env.add_template("login.html", LOGIN_HTML)
        .expect("login.html must be a valid template");
    env.add_template("detail.html", DETAIL_HTML)
        .expect("detail.html must be a valid template");
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
    env
}

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
}
