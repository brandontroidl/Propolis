//! The console's minijinja template environment (`internal/design/06-console-observability.md`,
//! "Pages"). Every template is embedded into the binary via `include_str!` - there is no template
//! directory to ship or read at runtime - and minijinja auto-escapes any template whose registered
//! name ends in `.html` (verified against `vendor/minijinja/src/defaults.rs`'s
//! `default_auto_escape_callback`), which is this crate's XSS-prevention guarantee: every value
//! interpolated with `{{ }}` is HTML-escaped unless a template explicitly opts out with the `|safe`
//! filter. Only the chart data elements do, and only for JSON built by [`script_json`], which
//! cannot end the element it sits in.
//!
//! `base.html` is `base_head.html` followed by `base_tail.html`. No page carries inline script,
//! inline style or an event-handler attribute: the Content-Security-Policy (`routes::mod`) allows
//! scripts and styles only from this origin, so every one is a static file under `src/assets/`,
//! served by `routes::assets` and referenced with `<script src>` / `<link rel="stylesheet">` in
//! the order the page needs them (see `base_head.html`). `htmx.min.js` is the unmodified,
//! upstream `htmx.org@2.0.10` distribution and `chart.min.js` the unmodified `chart.js@4.5.1` UMD
//! distribution (each cross-checked byte-for-byte against unpkg and jsdelivr); neither is fetched
//! from a CDN at runtime.

use minijinja::Environment;

const BASE_HTML: &str = concat!(
    include_str!("templates/base_head.html"),
    include_str!("templates/base_tail.html"),
);
const DASHBOARD_HTML: &str = include_str!("templates/dashboard.html");
const QUEUE_HTML: &str = include_str!("templates/queue.html");
const QUEUE_ROW_HTML: &str = include_str!("templates/queue_row.html");
const QUEUE_HISTORY_ROW_HTML: &str = include_str!("templates/queue_history_row.html");
const QUEUE_MOVED_ROW_HTML: &str = include_str!("templates/queue_moved_row.html");
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

/// `value` as JSON for a `<script type="application/json">` element, placed with `|safe`. The
/// browser reads such an element's content as raw text up to the first `</script`, and JSON leaves
/// `<` and `/` as they are, so a string holding `</script>` would end the element and put the rest
/// of it into the page as markup. A chart label can be a sensor name, which is whatever an event
/// carried, and in a split deployment whatever a collector shipped. `<`, `>` and `&` are written
/// as JSON unicode escapes instead, which `JSON.parse` reads back as the same characters. The chart
/// data is always a list, so a value that cannot be serialized becomes an empty one.
pub(crate) fn script_json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "[]".into());
    let backslash = char::from(92);
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' | '>' | '&' => out.push_str(&format!("{backslash}u{:04x}", u32::from(c))),
            other => out.push(other),
        }
    }
    out
}

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
    // The acknowledgement a history tab's row is swapped for once a decision moves it to another
    // tab - see the template's own comment for why it cannot just be re-rendered in place.
    env.add_template("queue_moved_row.html", QUEUE_MOVED_ROW_HTML)
        .expect("queue_moved_row.html must be a valid template");
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
    env.add_template("sample_detail.html", SAMPLE_DETAIL_HTML)
        .expect("sample_detail.html must be a valid template");
    env.add_template("campaigns.html", CAMPAIGNS_HTML)
        .expect("campaigns.html must be a valid template");
    env.add_template("campaign_detail.html", CAMPAIGN_DETAIL_HTML)
        .expect("campaign_detail.html must be a valid template");
    env.add_template("campaign_approve.html", CAMPAIGN_APPROVE_HTML)
        .expect("campaign_approve.html must be a valid template");
    env
}

const SAMPLE_DETAIL_HTML: &str = include_str!("templates/sample_detail.html");
const CAMPAIGNS_HTML: &str = include_str!("templates/campaigns.html");
const CAMPAIGN_DETAIL_HTML: &str = include_str!("templates/campaign_detail.html");
const CAMPAIGN_APPROVE_HTML: &str = include_str!("templates/campaign_approve.html");
const IPS_HTML: &str = include_str!("templates/ips.html");
const INTEGRITY_HTML: &str = include_str!("templates/integrity.html");
const SAMPLES_HTML: &str = include_str!("templates/samples.html");

#[cfg(test)]
mod tests {
    use super::*;

    /// The live-panel script every page loads (see `base_tail.html`).
    const LIVE_PANELS_JS: &str = include_str!("assets/live-panels.js");

    /// Every `.html` file in the templates directory, read from disk rather than from the constants
    /// above, so a template added without being listed here is still checked.
    fn template_sources() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/templates");
        let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "html"))
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read_to_string(&path).unwrap())
            })
            .collect();
        out.sort();
        assert!(
            out.len() >= 20,
            "found only {} templates in {dir:?}",
            out.len()
        );
        out
    }

    /// The Content-Security-Policy forbids inline script, inline style and event-handler
    /// attributes; a template that reintroduces any of them breaks silently in the browser (the
    /// policy blocks it, nothing errors server-side). This keeps them out at the source.
    #[test]
    fn no_template_carries_inline_script_style_or_handlers() {
        for (name, src) in template_sources() {
            // A backslash before an attribute quote is kept literally in HTML, so the attribute
            // value silently includes it: class=\"w-90\" names no class at all.
            assert!(
                !src.contains("=\\\""),
                "{name}: backslash-escaped attribute quote"
            );
            assert!(!src.contains("<style"), "{name}: inline <style> block");
            assert!(!src.contains(" style="), "{name}: inline style attribute");
            assert!(
                !src.to_ascii_lowercase().contains("javascript:"),
                "{name}: javascript: URL"
            );
            for (at, _) in src.match_indices("<script") {
                let tag = &src[at..src[at..].find('>').map_or(src.len(), |end| at + end)];
                assert!(
                    tag.contains(" src=\"/assets/") || tag.contains("type=\"application/json\""),
                    "{name}: inline executable script `{tag}>`"
                );
            }
            let bytes = src.as_bytes();
            for (at, _) in src.match_indices(" on") {
                let rest = &bytes[at + 3..];
                let letters = rest.iter().take_while(|b| b.is_ascii_lowercase()).count();
                assert!(
                    letters == 0 || rest.get(letters) != Some(&b'='),
                    "{name}: event-handler attribute near `{}`",
                    &src[at..(at + 20).min(src.len())]
                );
            }
        }
    }

    /// A confirmed action used to confirm through an inline onclick, active as soon as the button
    /// was parsed. Its replacement lives in console.js at the end of the page, so until that script
    /// runs a click would submit without asking. Every confirmed button therefore renders disabled,
    /// and console.js enables it once the confirmation handler exists.
    #[test]
    fn every_confirmed_action_renders_disabled_until_its_script_arms_it() {
        let mut confirmed = 0;
        for (name, src) in template_sources() {
            for (at, _) in src.match_indices("data-confirm=") {
                let tag_start = src[..at].rfind('<').unwrap();
                let tag = &src[tag_start..at];
                confirmed += 1;
                assert!(
                    tag.contains(" disabled"),
                    "{name}: a data-confirm element must render disabled: `{tag}`"
                );
            }
        }
        assert!(confirmed >= 3, "found only {confirmed} confirmed actions");
        let script = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/assets/console.js"),
        )
        .unwrap();
        assert!(
            script.contains("querySelectorAll('[data-confirm][disabled]')")
                && script.contains("disabled = false"),
            "console.js must enable the confirmed buttons it guards"
        );
        // Enabling before the confirmation listener exists would reopen the window this closes;
        // never enabling would leave the buttons dead. Content htmx swaps in later (the evidence
        // drawer) needs arming too.
        let listener = script
            .find("closest('[data-confirm]')")
            .expect("console.js registers its confirmation listener");
        let armed = script
            .find("armConfirmations(document)")
            .expect("console.js arms the page's confirmed buttons");
        assert!(
            listener < armed,
            "console.js must arm the buttons only after the confirmation listener exists"
        );
        assert!(
            script.contains("addEventListener('htmx:load'")
                && script.contains("armConfirmations(e.target)"),
            "console.js must arm confirmed buttons in content htmx swaps in"
        );
    }

    /// The policy applies to every response, including the few bodies Rust builds without a
    /// template (the 503 page and two not-found pages). Those escaped the template scan above and
    /// kept an inline style the policy then blocked. Scans the non-test, non-comment lines of
    /// every source file for the same three things.
    #[test]
    fn no_rust_built_page_carries_inline_script_style_or_handlers() {
        let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        let mut scanned = 0;
        while let Some(dir) = dirs.pop() {
            for path in std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()) {
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                scanned += 1;
                let source = std::fs::read_to_string(&path).unwrap();
                let lines: Vec<&str> = source.lines().collect();
                // Stop at the test module, not at the first `#[cfg(test)]`: a test-only helper
                // can carry that attribute in the middle of the production code.
                let end = (0..lines.len())
                    .find(|&i| {
                        lines[i].trim() == "#[cfg(test)]"
                            && lines[i + 1..]
                                .iter()
                                .find(|l| !l.trim().is_empty())
                                .is_some_and(|l| l.trim_start().starts_with("mod "))
                    })
                    .unwrap_or(lines.len());
                for (n, line) in lines[..end].iter().enumerate() {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    let at = format!("{}:{}", path.display(), n + 1);
                    let line = line.to_ascii_lowercase();
                    assert!(!line.contains("style="), "{at}: inline style attribute");
                    assert!(!line.contains("<style"), "{at}: inline <style> block");
                    assert!(
                        !line.contains("<script"),
                        "{at}: script element built in Rust"
                    );
                    let bytes = line.as_bytes();
                    for (i, _) in line.match_indices(" on") {
                        let rest = &bytes[i + 3..];
                        let letters = rest.iter().take_while(|b| b.is_ascii_lowercase()).count();
                        assert!(
                            letters == 0 || rest.get(letters) != Some(&b'='),
                            "{at}: event-handler attribute"
                        );
                    }
                }
            }
        }
        assert!(scanned >= 20, "scanned only {scanned} source files");
    }

    #[test]
    fn every_referenced_asset_is_served() {
        for (name, src) in template_sources() {
            for (at, _) in src.match_indices("\"/assets/") {
                let path = &src[at + 1..];
                let path = &path[..path.find('"').unwrap()];
                if path.starts_with("/assets/fonts/") {
                    continue;
                }
                let file = path.trim_start_matches("/assets/");
                assert!(
                    crate::routes::assets::is_static_asset(file),
                    "{name} references {path}, which routes::assets does not serve"
                );
            }
        }
    }

    #[test]
    fn a_rate_over_100_still_names_an_existing_meter_class() {
        let env = environment();
        assert_eq!(env.render_str("{{ [130, 100]|min }}", ()).unwrap(), "100");
        assert_eq!(env.render_str("{{ [42, 100]|min }}", ()).unwrap(), "42");
    }

    #[test]
    fn every_template_registers_and_extends_cleanly() {
        // `add_template` above already asserts this at call time (via `.expect`), but this test
        // documents and re-verifies the invariant explicitly, and would fail loudly (not panic
        // during an unrelated test's setup) if a future template edit breaks parsing.
        let _ = environment();
    }

    #[test]
    fn script_json_cannot_end_its_element_and_reads_back_unchanged() {
        let label = r#"</script><!-- a & b -->"#;
        let json = script_json(&[label]);
        assert!(!json.contains(['<', '>', '&']), "{json}");
        let back: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, [label]);
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

    /// A snoozed row's display data. `csrf_token` is what makes its controls usable at all - the
    /// history tabs used to render with an empty one.
    fn queue_row(state: &str) -> minijinja::Value {
        minijinja::context! {
            ip => "203.0.113.7", state => state, is_pending => false,
            score => "81.0", score_pct => 81, tier => "standard",
            categories => "auth", event_count => 12,
            first_seen => "-", last_seen => "-", decided_at => "2026-09-19T10:00:00Z",
            submissions => "-", notes => "check the ASN first",
            csrf_token => "tok-123",
        }
    }

    /// A snooze that cannot be acted on later is a rejection wearing a softer word. Nothing
    /// re-surfaces a snoozed entry, so this tab's controls are the only route back.
    #[test]
    fn the_snoozed_tab_can_actually_decide_the_entry_it_is_holding() {
        let env = environment();
        let tmpl = env.get_template("queue_history_row.html").unwrap();
        let html = tmpl
            .render(minijinja::context! { row => queue_row("snoozed") })
            .unwrap();

        for action in ["approve", "reject", "unsnooze"] {
            assert!(
                html.contains(&format!("/queue/203.0.113.7/{action}")),
                "the snoozed row must offer {action}: {html}"
            );
        }
        assert!(
            html.contains(r#"value="tok-123""#),
            "the controls need a real CSRF token or every one of them is rejected: {html}"
        );
        assert!(
            html.contains(r#"name="from_tab" value="snoozed""#),
            "the handler needs to know the row came from a history tab: {html}"
        );
    }

    /// Approved and rejected are terminal in the console's own model, and their tables have no
    /// Actions column - rendering controls there would add cells with no header over them.
    #[test]
    fn the_other_history_tabs_keep_their_existing_columns() {
        let env = environment();
        let tmpl = env.get_template("queue_history_row.html").unwrap();
        for state in ["approved", "rejected"] {
            let html = tmpl
                .render(minijinja::context! { row => queue_row(state) })
                .unwrap();
            assert!(
                !html.contains("/queue/203.0.113.7/unsnooze"),
                "the {state} tab has no Actions column: {html}"
            );
        }
    }

    /// The console tour says a delist holds "until you say otherwise". The page has to carry the
    /// control that says otherwise, and it has to be the one that matches the address's state.
    #[test]
    fn the_detail_page_offers_the_reverse_of_whichever_listing_state_applies() {
        let env = environment();
        let tmpl = env.get_template("detail.html").unwrap();
        let render = |delisted: bool| {
            tmpl.render(minijinja::context! {
                layout => "drawer_shell.html",
                is_drawer => true,
                csrf_token => "tok-123",
                ip => "203.0.113.7",
                delisted => delisted,
                ..detail_stub_context()
            })
            .unwrap()
        };

        let delisted = render(true);
        assert!(
            delisted.contains("/ip/203.0.113.7/relist") && delisted.contains(">Relist<"),
            "a delisted address must offer relisting: {delisted}"
        );
        assert!(
            !delisted.contains(">Delist<"),
            "offering to delist an already-delisted address says nothing true: {delisted}"
        );

        let listed = render(false);
        assert!(listed.contains("/ip/203.0.113.7/delist") && listed.contains(">Delist<"));
        assert!(
            !listed.contains("/ip/203.0.113.7/relist"),
            "an address that is not delisted has nothing to relist: {listed}"
        );
    }

    /// A certificate error is attacker-influenced text (names from the attacker's certificate); it
    /// reaches the page only as an escaped attribute, never as markup.
    #[test]
    fn a_fetched_sample_names_its_transport_and_escapes_the_certificate_error() {
        let html = environment()
            .get_template("samples.html")
            .unwrap()
            .render(minijinja::context! {
                active_nav => "samples", pending_count => 0, uptime => "1m", version => "0.0.0",
                degraded => Vec::<&str>::new(), total => 3, status_counts => Vec::<()>::new(),
                fetch_attempts_total => 0,
                samples => vec![
                    minijinja::context! {
                        sha256 => "a".repeat(64), sha256_short => "aaaaaaaaaaaa", size => "1 B",
                        sensor => "fetched", source_ips => Vec::<&str>::new(), more_source_ips => 0,
                        transport => vec![
                            minijinja::context! { label => "TLS unverified", sev => "watch",
                                detail => "invalid peer certificate: \"><script>x()</script>" },
                            minijinja::context! { label => "plaintext", sev => "low", detail => () },
                        ],
                    },
                    minijinja::context! {
                        sha256 => "b".repeat(64), sha256_short => "bbbbbbbbbbbb", size => "1 B",
                        sensor => "ssh", source_ips => Vec::<&str>::new(), more_source_ips => 0,
                        transport => Vec::<()>::new(), uploaded => true,
                    },
                    minijinja::context! {
                        sha256 => "c".repeat(64), sha256_short => "cccccccccccc", size => "1 B",
                        sensor => "fetched", source_ips => Vec::<&str>::new(),
                        more_source_ips => 0, transport => Vec::<()>::new(), uploaded => false,
                    },
                ],
            })
            .unwrap();
        assert!(html.contains(r#"<span class="sev sev--watch" title="invalid peer certificate: &quot;&gt;&lt;script&gt;x()&lt;&#x2f;script&gt;">TLS unverified</span>"#), "{html}");
        assert!(html.contains(r#"<span class="sev sev--low">plaintext</span>"#));
        assert!(
            html.contains("n/a, uploaded") && !html.contains("not fetched"),
            "a sensor upload is labelled as one, not as a fetch that did not happen"
        );
        assert!(
            html.contains("not recorded"),
            "a fetched body with no fetch record says the record is missing"
        );
        assert!(!html.contains("<script>x()"));
    }

    /// The remaining `detail.html` fields, so the two tests above can vary only `delisted`.
    fn detail_stub_context() -> minijinja::Value {
        minijinja::context! {
            active_nav => "detail", pending_count => 0, uptime => "1m", version => "0.0.0",
            degraded => Vec::<&str>::new(),
            raw_score => "0.0", raw_score_pct => 0,
            effective_score => "0.0", effective_score_pct => 0,
            tier => "-", eligible => false,
            recommended_for_vendor => false, recommended_for_blocklist => false,
            has_confirmed_real => false, event_count => 0, distinct_categories => 0,
            distinct_wan_count => 0, distinct_sensor_count => 0, active_days => 0,
            persistence_bonus => "0", max_confidence => "0.000",
            first_seen => "-", last_seen => "-",
            timeline_counts => minijinja::context! {
                events => 0, commands => 0, sessions => 0, ungrouped => 0,
            },
        }
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

    /// The capture panel's third state. The completeness query can succeed while the end-reason
    /// query fails, and the failure arrives as an empty map - exactly what a sensor with nothing
    /// incomplete also produces. A row showing incomplete captures must not then claim there is
    /// nothing incomplete; the two readings sit in the same row and cannot contradict each other.
    #[test]
    fn an_unreadable_end_reason_is_not_rendered_as_nothing_incomplete() {
        let env = environment();
        let tmpl = env.get_template("fleet_status_fragment.html").unwrap();

        let row = |unavailable: bool| {
            minijinja::context! {
                sensor => "ssh", sensor_label => "SSH",
                captures => 10, complete => 6, incomplete => 4, unlabelled => 0, truncated => 0,
                rate_pct => 60,
                top_end_reason => (), top_end_reason_count => 0,
                end_reason_unavailable => unavailable,
                end_reason_sev => "sev sev--watch",
                state_level => "warn", meter_class => "meter-fill meter-fill--warn",
            }
        };

        let failed = tmpl
            .render(minijinja::context! {
                captures => vec![row(true)],
                degraded_panels => vec!["capture end reasons"],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(
            !failed.contains("nothing incomplete"),
            "a row with 4 incomplete captures must not say nothing is incomplete: {failed}"
        );
        assert!(
            failed.contains("reason unavailable"),
            "the cell must say the reason could not be read: {failed}"
        );

        // The same row when the query DID run and this sensor simply has nothing to explain.
        let clean = tmpl
            .render(minijinja::context! {
                captures => vec![row(false)],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(clean.contains("nothing incomplete"));
        assert!(!clean.contains("reason unavailable"));

        // And a readable reason still renders as itself.
        let named = tmpl
            .render(minijinja::context! {
                captures => vec![minijinja::context! {
                    top_end_reason => "capture budget", top_end_reason_count => 4,
                    ..row(false)
                }],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(named.contains("capture budget") && !named.contains("nothing incomplete"));
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

    /// A listener row whose intake log is behind carries the badge as a word-bearing pill in the
    /// LAST EVENT cell; a row that is not behind carries nothing, not an empty pill.
    #[test]
    fn a_behind_listener_row_shows_its_backlog_and_a_current_one_shows_nothing() {
        let env = environment();
        let tmpl = env.get_template("fleet_status_fragment.html").unwrap();
        let row = |behind: Option<&str>| {
            minijinja::context! {
                collector => "local", sensor => "telnet", sensor_label => "Telnet",
                protocol => "tcp", port => "23", vantage => "", reach => "reachable",
                reach_level => "ok", reach_dot => "dot dot--low", reach_detail => (),
                probe_ago => "1 minute ago", confirmed_ago => (),
                last_event_ago => "11 days ago", last_event_dot => "dot dot--high",
                behind => behind, events_24h => 0, state_level => "warn", declared => true,
            }
        };

        let lagging = tmpl
            .render(minijinja::context! {
                listeners => vec![row(Some("behind: 6.6 GB / 11 d"))],
                ..fleet_base_context()
            })
            .unwrap();
        // Autoescaping writes the slash as `&#x2f;`; a browser shows "behind: 6.6 GB / 11 d".
        assert!(
            lagging.contains(r#"<span class="sev sev--high">behind: 6.6 GB &#x2f; 11 d</span>"#),
            "the behind row must carry its badge: {lagging}"
        );

        let current = tmpl
            .render(minijinja::context! {
                listeners => vec![row(None)],
                ..fleet_base_context()
            })
            .unwrap();
        assert!(
            !current.contains("behind:") && !current.contains("sev sev--high"),
            "a row that is not behind must show no badge: {current}"
        );
    }

    /// The fleet page polls; a poll that starts failing leaves the last render on screen with
    /// server-computed ages that never move again. `data-live` is what opts the container into
    /// the stale handling in `assets/live-panels.js`, so losing the attribute silently restores that bug.
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
        // The handler that acts on it ships with every page: base.html loads live-panels.js.
        assert!(
            html.contains(r#"<script src="/assets/live-panels.js"></script>"#),
            "the page must load the live-panel script"
        );
        for event in ["htmx:responseError", "htmx:sendError", "htmx:timeout"] {
            assert!(
                LIVE_PANELS_JS.contains(event),
                "the live-panel script must handle {event} on a polled panel"
            );
        }
        assert!(
            LIVE_PANELS_JS.contains("has stopped "),
            "the stale banner's wording must be present in the script"
        );
    }

    /// The evidence-chain panel must not offer a verdict it has no way to show.
    ///
    /// It used to read "The chain verdict is not stored yet. Run a verification to see it." Both
    /// halves misled: "yet" implied a verdict was on its way, and "to see it" pointed the reader
    /// at an action that cannot change this panel. `/integrity/verify` renders its result into
    /// that one response and nothing persists it, so an operator who followed the instruction came
    /// back to the identical sentence. Wording only - there is still no verdict to show.
    #[test]
    fn the_evidence_chain_panel_does_not_promise_a_verdict_it_cannot_show() {
        let env = environment();
        let html = env
            .get_template("fleet_status_fragment.html")
            .unwrap()
            .render(fleet_base_context())
            .unwrap();

        assert!(
            !html.contains("not stored yet"),
            "nothing is going to store a verdict, so the panel must not say \"yet\": {html}"
        );
        assert!(
            html.contains("No verdict is retained"),
            "the panel must say plainly that no verdict is kept: {html}"
        );
        assert!(
            html.contains(r#"href="/integrity""#),
            "the way to actually verify the chain must still be one click away: {html}"
        );
    }

    /// The half of stale detection that does not depend on an event arriving.
    ///
    /// A server that ACCEPTS the status poll and then never answers fires no htmx error and no
    /// htmx timeout, because htmx's own default request timeout is 0 (no limit). Measured in a
    /// browser against exactly that server, the fleet panel still read "Probed: just now" after
    /// 143 seconds, with `xhr.timeout === 0` and no stale marker. Two things shipped in the page
    /// close it, and both have to stay shipped: a bounded per-request timeout, and a watchdog
    /// that ages the last successful refresh on the clock rather than on an event.
    #[test]
    fn a_polled_panel_bounds_its_request_and_ages_itself_without_waiting_for_an_event() {
        let env = environment();
        let html = env
            .get_template("fleet.html")
            .unwrap()
            .render(minijinja::context! {
                pending_count => 0,
                uptime => "1m",
                version => "0.0.0",
                degraded => Vec::<&str>::new(),
                ..fleet_base_context()
            })
            .unwrap();

        assert!(
            LIVE_PANELS_JS.contains(r#"'{"timeout": ' + REQUEST_TIMEOUT_MS + '}'"#),
            "every polled panel must get a bounded request timeout; htmx's own default is 0              (no limit), which is what let a hung poll go unnoticed"
        );
        assert!(
            LIVE_PANELS_JS.contains("var REQUEST_TIMEOUT_MS = 15000;"),
            "the request timeout must be a real bound, not left unset"
        );
        assert!(
            LIVE_PANELS_JS.contains("setInterval(") && LIVE_PANELS_JS.contains("staleAfterMs(el)"),
            "the page must age a live panel on a timer, independently of any request completing"
        );
        assert!(
            LIVE_PANELS_JS.contains("no refresh has come back"),
            "the watchdog must be able to raise the stale banner on its own"
        );
        // The bound has to be shorter than the poll interval it guards, or a hung request is
        // still in flight when the next poll is due and nothing is ever abandoned.
        assert!(
            html.contains(r#"hx-trigger="every 30s""#),
            "the fleet panel's poll interval is what the 15s bound is sized against"
        );
    }
}
