//! A reader for one shell line, just far enough to tell a command from a word that merely appears
//! on the line. `echo crontab` runs `echo`; `wget http://x/cron.sh` runs `wget`. It splits on the
//! operators that end a command, honours quotes and backslashes, collects the redirections, drops
//! leading `NAME=value` assignments and wrappers (`sudo`, `busybox`, ...), and reads the script of
//! `sh -c` and `eval` as lines of their own.
//!
//! Nothing is expanded or evaluated: a `$VAR` stays the word `$VAR`, a glob stays a glob. Command
//! substitution (`$(...)` and backticks) is read as if its content were a command of the line,
//! because that is when it runs. Heredoc bodies and here-strings are skipped. Every input is
//! attacker data, so the line, the words, the commands and the recursion are all bounded.

/// The longest line read, in bytes. Sensors cap a command at 1024 characters; this is slack.
const MAX_LINE_BYTES: usize = 4096;
/// The most words read from one line.
const MAX_WORDS: usize = 512;
/// The most commands one line yields, nested scripts included.
const MAX_SIMPLES: usize = 64;
/// How deep `sh -c` and `eval` scripts nest.
const MAX_DEPTH: usize = 3;

/// One command of a line: its words after assignments and wrappers, and its redirection targets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Simple {
    pub argv: Vec<String>,
    /// Targets of `>`, `>>`, `>|` and `&>`.
    pub out: Vec<String>,
    /// Targets of `<`.
    pub input: Vec<String>,
}

impl Simple {
    /// The command's name: the last path component of its first word.
    pub fn name(&self) -> &str {
        self.argv
            .first()
            .map(|w| w.rsplit('/').next().unwrap_or(w))
            .unwrap_or("")
    }

    /// Every word after the name.
    pub fn args(&self) -> &[String] {
        self.argv.get(1..).unwrap_or(&[])
    }

    /// The words after the name that do not start with `-`. An option's value counts as an operand
    /// here (`chmod -R 755 f` has `755` and `f`), so callers use the first or last operand only
    /// where that is unambiguous.
    pub fn operands(&self) -> Vec<&str> {
        self.args()
            .iter()
            .map(String::as_str)
            .filter(|a| !a.starts_with('-'))
            .collect()
    }
}

enum Tok {
    Word(String),
    Sep,
    RedirOut,
    RedirIn,
    /// A heredoc or here-string marker; the word after it is the delimiter or string.
    Skip,
}

/// The commands on `line`, in order, each nested script after the command that carries it.
pub fn parse(line: &str) -> Vec<Simple> {
    let mut out = Vec::new();
    parse_into(truncate(line, MAX_LINE_BYTES), 0, &mut out);
    out
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_into(line: &str, depth: usize, out: &mut Vec<Simple>) {
    let mut words: Vec<String> = Vec::new();
    let mut redirs = Simple::default();
    let mut pending: Option<bool> = None; // Some(true) = next word is an output target
    let mut skip_next = false;
    let mut count = 0;
    let mut toks = tokenize(line);
    toks.push(Tok::Sep);
    for tok in toks {
        match tok {
            Tok::Word(w) => {
                count += 1;
                if count > MAX_WORDS {
                    break;
                }
                if skip_next {
                    skip_next = false;
                } else if let Some(is_out) = pending.take() {
                    if is_out {
                        redirs.out.push(w);
                    } else {
                        redirs.input.push(w);
                    }
                } else {
                    words.push(w);
                }
            }
            Tok::RedirOut => pending = Some(true),
            Tok::RedirIn => pending = Some(false),
            Tok::Skip => skip_next = true,
            Tok::Sep => {
                pending = None;
                skip_next = false;
                let argv = normalize(std::mem::take(&mut words));
                let simple = Simple {
                    argv,
                    out: std::mem::take(&mut redirs.out),
                    input: std::mem::take(&mut redirs.input),
                };
                if simple.argv.is_empty() && simple.out.is_empty() && simple.input.is_empty() {
                    continue;
                }
                if out.len() >= MAX_SIMPLES {
                    return;
                }
                let script = nested_script(&simple);
                out.push(simple);
                if let Some(script) = script
                    && depth < MAX_DEPTH
                {
                    parse_into(&script, depth + 1, out);
                }
            }
        }
    }
}

const SHELLS: [&str; 9] = [
    "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "csh", "tcsh",
];

/// Whether `name` is a shell interpreter.
pub fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

/// The script an `sh -c SCRIPT` or `eval WORDS` command runs.
fn nested_script(s: &Simple) -> Option<String> {
    if s.name() == "eval" {
        let rest = s.args().join(" ");
        return (!rest.is_empty()).then_some(rest);
    }
    if !is_shell(s.name()) {
        return None;
    }
    let args = s.args();
    let flag = args
        .iter()
        .position(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c'))?;
    args.get(flag + 1).cloned()
}

/// Wrappers that run the command after them.
const WRAPPERS: [&str; 11] = [
    "sudo", "doas", "nohup", "exec", "command", "env", "time", "nice", "setsid", "busybox",
    "toybox",
];

fn is_assignment(w: &str) -> bool {
    match w.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// `words` without leading assignments and wrappers (and the options a wrapper takes).
fn normalize(mut words: Vec<String>) -> Vec<String> {
    loop {
        let mut start = 0;
        while words.get(start).is_some_and(|w| is_assignment(w)) {
            start += 1;
        }
        words.drain(..start);
        let Some(first) = words.first() else {
            return words;
        };
        let name = first.rsplit('/').next().unwrap_or(first).to_string();
        if !WRAPPERS.contains(&name.as_str()) {
            return words;
        }
        words.remove(0);
        // Options of the wrapper itself, up to the command; `-u root` style options take a value.
        let takes_value: &[&str] = match name.as_str() {
            "sudo" | "doas" => &["-u", "-g", "-C", "-p", "-r", "-t", "-h", "-U"],
            "nice" => &["-n"],
            _ => &[],
        };
        while let Some(w) = words.first() {
            if !w.starts_with('-') {
                break;
            }
            let consumes = takes_value.contains(&w.as_str());
            words.remove(0);
            if consumes && !words.is_empty() {
                words.remove(0);
            }
        }
    }
}

fn tokenize(line: &str) -> Vec<Tok> {
    let chars: Vec<char> = line.chars().collect();
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut i = 0;
    let flush = |toks: &mut Vec<Tok>, cur: &mut String, in_word: &mut bool| {
        if *in_word {
            toks.push(Tok::Word(std::mem::take(cur)));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            ' ' | '\t' | '\r' => {
                flush(&mut toks, &mut cur, &mut in_word);
                i += 1;
            }
            '\n' | ';' | '(' | ')' | '`' => {
                flush(&mut toks, &mut cur, &mut in_word);
                toks.push(Tok::Sep);
                i += 1;
            }
            '$' if next == Some('(') => {
                flush(&mut toks, &mut cur, &mut in_word);
                toks.push(Tok::Sep);
                i += 2;
            }
            '&' => {
                flush(&mut toks, &mut cur, &mut in_word);
                if next == Some('>') {
                    i += 2;
                    if chars.get(i) == Some(&'>') {
                        i += 1;
                    }
                    toks.push(Tok::RedirOut);
                } else {
                    toks.push(Tok::Sep);
                    i += if next == Some('&') { 2 } else { 1 };
                }
            }
            '|' => {
                flush(&mut toks, &mut cur, &mut in_word);
                toks.push(Tok::Sep);
                i += if next == Some('|') { 2 } else { 1 };
            }
            '>' | '<' => {
                // A file descriptor number right before the operator belongs to it (`2>`).
                if in_word && !cur.is_empty() && cur.chars().all(|d| d.is_ascii_digit()) {
                    cur.clear();
                    in_word = false;
                }
                flush(&mut toks, &mut cur, &mut in_word);
                if c == '>' {
                    i += 1;
                    if matches!(chars.get(i), Some('>') | Some('|')) {
                        i += 1;
                    }
                    if chars.get(i) == Some(&'&') {
                        // `2>&1` duplicates a descriptor; it names no file.
                        i += 1;
                        while chars
                            .get(i)
                            .is_some_and(|d| d.is_ascii_digit() || *d == '-')
                        {
                            i += 1;
                        }
                    } else {
                        toks.push(Tok::RedirOut);
                    }
                } else if next == Some('<') {
                    i += 2;
                    while matches!(chars.get(i), Some('-') | Some('<')) {
                        i += 1;
                    }
                    toks.push(Tok::Skip);
                } else {
                    i += 1;
                    toks.push(Tok::RedirIn);
                }
            }
            '#' if !in_word => break,
            '\'' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\'
                        && let Some(n) = chars.get(i + 1)
                        && matches!(n, '"' | '\\' | '$' | '`')
                    {
                        cur.push(*n);
                        i += 2;
                        continue;
                    }
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '\\' => {
                in_word = true;
                if let Some(n) = next
                    && n != '\n'
                {
                    cur.push(n);
                }
                i += 2;
            }
            _ => {
                in_word = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    flush(&mut toks, &mut cur, &mut in_word);
    toks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(line: &str) -> Vec<String> {
        parse(line).iter().map(|s| s.name().to_string()).collect()
    }

    #[test]
    fn a_word_is_a_command_only_in_command_position() {
        assert_eq!(names("echo crontab"), ["echo"]);
        assert_eq!(names("ls /etc/cron.d"), ["ls"]);
        assert_eq!(
            names("cd /tmp; wget http://x/a; chmod +x a"),
            ["cd", "wget", "chmod"]
        );
        assert_eq!(names("a && b || c | d & e"), ["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn quotes_hide_operators_and_assignments_and_wrappers_are_dropped() {
        let s = parse("echo 'a; rm -rf /' \"b | c\" > /tmp/o");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].argv, ["echo", "a; rm -rf /", "b | c"]);
        assert_eq!(s[0].out, ["/tmp/o"]);
        assert_eq!(
            parse("FOO=1 BAR=2 sudo -u root busybox wget x")[0].argv,
            ["wget", "x"]
        );
        assert_eq!(
            parse("/usr/bin/nohup /bin/ls -la")[0].argv,
            ["/bin/ls", "-la"]
        );
    }

    #[test]
    fn redirections_are_collected_and_descriptor_dups_are_not_files() {
        let s = &parse("cat <in >>out 2>&1 &>all 2>err")[0];
        assert_eq!(s.input, ["in"]);
        assert_eq!(s.out, ["out", "all", "err"]);
        assert_eq!(s.argv, ["cat"]);
        let attached = &parse("echo x>f")[0];
        assert_eq!(attached.out, ["f"]);
    }

    #[test]
    fn scripts_of_sh_c_and_eval_and_substitutions_are_commands_too() {
        assert_eq!(names("sh -c 'uname -a; ls'"), ["sh", "uname", "ls"]);
        assert_eq!(names("bash -lc \"ps\""), ["bash", "ps"]);
        assert_eq!(names("eval \"rm x\""), ["eval", "rm"]);
        assert_eq!(names("echo $(uname -m)"), ["echo", "uname"]);
        assert_eq!(names("echo `id`"), ["echo", "id"]);
        // `sh` without -c reads a script file: no nested command.
        assert_eq!(names("sh x.sh"), ["sh"]);
    }

    #[test]
    fn heredocs_comments_and_runaway_input_are_bounded() {
        assert_eq!(names("cat <<EOF\nrm -rf /\n"), ["cat", "rm"]);
        assert_eq!(names("cat <<EOF > f"), ["cat"]);
        assert_eq!(names("ls # rm -rf /"), ["ls"]);
        let deep = "sh -c \"sh -c 'sh -c \\\"sh -c ls\\\"'\"";
        assert!(parse(deep).len() <= MAX_DEPTH + 1);
        let long = "a;".repeat(10_000);
        assert!(parse(&long).len() <= MAX_SIMPLES);
        assert!(parse("echo \"unterminated").len() == 1);
    }
}
