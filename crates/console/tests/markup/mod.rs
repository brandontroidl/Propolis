//! Structural checks on rendered console pages, shared by the integration tests that fetch them.
//!
//! The console's panels follow one contract (`assets/console.css`, "Panels"): a panel holds a
//! head, then tables, `.panel-body` blocks, or an `.empty-line`, and nothing else, because only
//! those carry the padding that keeps content off the panel's border. Pages added after the
//! original design broke that contract one panel at a time, each individually reasonable, so it is
//! checked here on real rendered pages rather than trusted to review.
#![allow(dead_code)]

/// One element as the walker sees it: its tag name and its class tokens.
struct Element {
    name: String,
    classes: Vec<String>,
    id: Option<String>,
}

impl Element {
    fn has(&self, class: &str) -> bool {
        self.classes.iter().any(|c| c == class)
    }

    fn describe(&self) -> String {
        format!("<{} class=\"{}\">", self.name, self.classes.join(" "))
    }
}

const VOID: [&str; 10] = [
    "area", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
];

fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let at = tag.find(&needle)? + needle.len();
    let end = tag[at..].find('"')?;
    Some(tag[at..at + end].to_string())
}

/// Walks `html` and calls `visit(parent_chain, element)` for every element as it opens, and
/// `text(parent_chain, text)` for every run of non-blank text. The chain is outermost first.
fn walk(
    html: &str,
    mut visit: impl FnMut(&[Element], &Element),
    mut text: impl FnMut(&[Element], &str),
) {
    let mut stack: Vec<Element> = Vec::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        let before = &rest[..lt];
        if !before.trim().is_empty() {
            text(&stack, before.trim());
        }
        rest = &rest[lt..];
        if rest.starts_with("<!--") {
            rest = &rest[rest.find("-->").map_or(rest.len(), |e| e + 3)..];
            continue;
        }
        if rest.starts_with("<!") {
            rest = &rest[rest.find('>').map_or(rest.len(), |e| e + 1)..];
            continue;
        }
        let end = rest.find('>').expect("unterminated tag");
        let tag = &rest[..=end];
        rest = &rest[end + 1..];
        if let Some(close) = tag.strip_prefix("</") {
            let name = close.trim_end_matches('>').trim().to_ascii_lowercase();
            if let Some(at) = stack.iter().rposition(|e| e.name == name) {
                stack.truncate(at);
            }
            continue;
        }
        let name: String = tag[1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        let element = Element {
            classes: attr(tag, "class")
                .map(|c| c.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            id: attr(tag, "id"),
            name: name.clone(),
        };
        visit(&stack, &element);
        if name == "script" || name == "style" {
            let close = format!("</{name}>");
            rest = &rest[rest.find(&close).map_or(rest.len(), |e| e + close.len())..];
            continue;
        }
        if VOID.contains(&name.as_str()) || tag.ends_with("/>") {
            continue;
        }
        stack.push(element);
    }
}

fn is_panel(e: &Element) -> bool {
    e.name == "div" && e.has("panel")
}

/// What a panel may hold directly: its head, a table, a padded body, the one empty-state line,
/// the Load more row, and the log viewer's own bands (which carry their own padding).
fn allowed_in_panel(e: &Element) -> bool {
    (e.name == "div" && (e.has("panel-head") || e.has("panel-body") || e.has("log-viewer")))
        || e.name == "table"
        || (e.name == "p" && (e.has("empty-line") || e.has("log-hidden")))
        || e.id.as_deref() == Some("load-more-container")
}

/// Every way `html` breaks the panel contract: content placed directly in a `.panel` that is not
/// one of the padded parts, an `.empty-line` outside any panel (the panel stays when empty), and
/// the retired dashed `.empty` box and `.panel-note`.
pub fn panel_violations(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stray_text = Vec::new();
    walk(
        html,
        |chain, e| {
            if chain.last().is_some_and(is_panel) && !allowed_in_panel(e) {
                out.push(format!("flush in a panel: {}", e.describe()));
            }
            if e.has("empty-line") && !chain.iter().any(is_panel) {
                out.push(format!("empty state outside a panel: {}", e.describe()));
            }
            if e.has("empty") || e.has("panel-note") {
                out.push(format!(
                    "retired empty-state or note style: {}",
                    e.describe()
                ));
            }
        },
        |chain, t| {
            if chain.last().is_some_and(is_panel) {
                stray_text.push(format!("bare text in a panel: {t:?}"));
            }
        },
    );
    out.extend(stray_text);
    out
}

/// Every place `html` uses a chip outside its job. A review-state pill says approved, rejected
/// or snoozed and nothing else (it had spread over yes/no answers and VirusTotal verdicts,
/// painting benign negatives in alarm red); a tier is the `.tier` pill, never a bare `.tier-*`
/// colour; a score is never coloured by tier; and the chip and count styles later work invented
/// beside the system's own are gone.
pub fn vocabulary_violations(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (at, _) in html.match_indices("class=\"state-pill ") {
        let rest = &html[at..];
        let text = &rest[rest.find('>').unwrap() + 1..];
        let text = &text[..text.find('<').unwrap()];
        if !["approved", "rejected", "snoozed", "pending"].contains(&text) {
            out.push(format!("review-state pill used for {text:?}"));
        }
    }
    walk(
        html,
        |_, e| {
            let tier_colour = ["tier-aggressive", "tier-standard", "tier-none"];
            if tier_colour.iter().any(|c| e.has(c)) && !e.has("tier") {
                out.push(format!("tier colour without the pill: {}", e.describe()));
            }
            for retired in [
                "rule",
                "filter-toggle",
                "qg-count",
                "fold-count",
                "log-count",
                "chunk-count",
                "score--aggressive",
                "score--standard",
                "score--none",
                "spark",
                "qg-approve",
                "copy-btn",
            ] {
                if e.has(retired) {
                    out.push(format!("retired style .{retired}: {}", e.describe()));
                }
            }
        },
        |_, _| {},
    );
    out
}

/// Every table of addresses that would scroll sideways on a phone: a row whose address cell holds
/// an evidence link is a row about an attacker, and every such table stacks as cards (`.stack`)
/// so an address reads the same on Review, Attackers, Search and the dashboard. Four tables had
/// hand-built card layouts and the rest scrolled.
pub fn stack_violations(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk(
        html,
        |chain, e| {
            let in_ip_cell = chain.last().is_some_and(|p| p.name == "td" && p.has("ip"));
            if e.name == "a" && e.has("insp") && in_ip_cell {
                let table = chain.iter().rev().find(|p| p.name == "table");
                if !table.is_some_and(|t| t.has("stack")) {
                    out.push(format!(
                        "address table without .stack: {}",
                        table.map_or("<none>".into(), Element::describe)
                    ));
                }
            }
        },
        |_, _| {},
    );
    out.dedup();
    out
}

/// Asserts the page keeps the panel contract, naming every violation at once.
pub fn assert_panels(html: &str) {
    let found = panel_violations(html);
    assert!(
        found.is_empty(),
        "panel contract broken:\n{}\n\n{html}",
        found.join("\n")
    );
}
