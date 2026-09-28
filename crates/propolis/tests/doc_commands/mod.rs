//! Shell commands quoted in the operator docs, split into words the way a shell would. Shared by
//! the docs gate (`docs_agreement.rs`) and the restore rehearsal (`restore_rehearsal.rs`), so the
//! archive command the gate checks and the one the rehearsal runs are read by the same code.
//!
//! This is a reader for the shell a runbook actually contains, not a shell: quotes, `$(...)`,
//! backslash line continuations, comments and the `| && || ; &` separators. An option this reader
//! does not know is assumed to take no value, so an unusual flag can at worst make a value read
//! as an input path - which the gate then reports rather than passes.

/// The input paths of every archive-creating `tar` command inside `markdown`'s fenced code blocks,
/// one list per command, in document order.
pub fn tar_create_inputs(markdown: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for line in fenced_logical_lines(markdown) {
        let words = words(&line);
        for command in words.split(|w| matches!(w.as_str(), "|" | "||" | "&&" | ";" | "&")) {
            if let Some(inputs) = tar_create_operands(command) {
                commands.push(inputs);
            }
        }
    }
    commands
}

/// Lines inside ``` fences, with backslash-continued lines joined into one.
fn fenced_logical_lines(markdown: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_fence = false;
    let mut pending = String::new();
    for raw in markdown.lines() {
        if raw.trim_start().starts_with("```") {
            in_fence = !in_fence;
            if !pending.is_empty() {
                lines.push(std::mem::take(&mut pending));
            }
            continue;
        }
        if !in_fence {
            continue;
        }
        match raw.trim_end().strip_suffix('\\') {
            Some(head) => {
                pending.push_str(head);
                pending.push(' ');
            }
            None => {
                pending.push_str(raw);
                lines.push(std::mem::take(&mut pending));
            }
        }
    }
    lines
}

/// Splits one logical line into words. Quotes group and are removed; `$(...)` stays one word
/// (`propolis-state-$(date +%F).tgz` is one argument, not two); an unquoted `#` at the start of a
/// word ends the line.
fn words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let (mut single, mut double, mut substitution) = (false, false, 0usize);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !double => {
                single = !single;
                in_word = true;
            }
            '"' if !single => {
                double = !double;
                in_word = true;
            }
            '$' if !single && chars.peek() == Some(&'(') => {
                substitution += 1;
                word.push('$');
                word.push(chars.next().unwrap_or('('));
                in_word = true;
            }
            ')' if !single && substitution > 0 => {
                substitution -= 1;
                word.push(c);
            }
            '#' if !in_word && !single && !double && substitution == 0 => break,
            c if c.is_whitespace() && !single && !double && substitution == 0 => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// GNU tar short options that take a value: `-f FILE`, `-C DIR`, `-T FILE`, `-X FILE` and the
/// rarer block-size, format, label, date, script and compressor options.
const SHORT_WITH_VALUE: &[char] = &[
    'f', 'C', 'T', 'X', 'b', 'H', 'K', 'L', 'N', 'V', 'g', 'F', 'I',
];

/// GNU tar long options that take a value when it is written as the next word.
const LONG_WITH_VALUE: &[&str] = &[
    "file",
    "directory",
    "files-from",
    "exclude",
    "exclude-from",
    "format",
    "blocking-factor",
    "label",
    "newer",
    "after-date",
    "listed-incremental",
    "use-compress-program",
    "owner",
    "group",
    "mode",
    "mtime",
    "transform",
    "xform",
];

/// The operands of `command` if it is `tar` creating an archive, else `None`. A leading `sudo`
/// and `NAME=value` environment assignments are skipped to find the program.
fn tar_create_operands(command: &[String]) -> Option<Vec<String>> {
    let mut rest = command
        .iter()
        .skip_while(|w| *w == "sudo" || is_assignment(w));
    let program = rest.next()?;
    if program != "tar" && !program.ends_with("/tar") {
        return None;
    }
    let args: Vec<&str> = rest.map(String::as_str).collect();

    let mut create = false;
    let mut operands = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--" {
            operands.extend(args[i + 1..].iter().map(|a| a.to_string()));
            break;
        } else if let Some(long) = arg.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            create |= name == "create";
            if LONG_WITH_VALUE.contains(&name) && !long.contains('=') {
                i += 1;
            }
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
            // A value-taking letter ends the cluster: its value is the rest of the cluster, or
            // the next word when it is the last letter (`-czf archive.tgz`).
            for (at, letter) in cluster.char_indices() {
                create |= letter == 'c';
                if SHORT_WITH_VALUE.contains(&letter) {
                    if at + letter.len_utf8() == cluster.len() {
                        i += 1;
                    }
                    break;
                }
            }
        } else if i == 0 {
            // Old-style bundle (`tar czf archive.tgz ...`): every value-taking letter takes the
            // next word in turn.
            create |= arg.contains('c');
            i += arg.chars().filter(|l| SHORT_WITH_VALUE.contains(l)).count();
        } else {
            operands.push(arg.to_string());
        }
        i += 1;
    }
    create.then_some(operands)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}
