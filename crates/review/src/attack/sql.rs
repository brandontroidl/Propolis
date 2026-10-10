//! A reader for the SQL a database sensor captured, just far enough to tell a keyword from text
//! that merely contains one. It is the counterpart of `super::parse` for the database sensors.
//!
//! The text is cut into tokens (words, quoted identifiers, string literals, numbers, punctuation)
//! and into statements at `;`. Comments are dropped and the content of a string literal or a
//! quoted identifier is never a word, so `SELECT 'DROP USER x'` and `-- GRANT ALL` contain no
//! keyword. A word is lowercased, so matching is case-insensitive, and a rule compares whole
//! tokens, never substrings.
//!
//! Dialects differ in the places that decide what is code: MySQL treats `"` as a string quote,
//! `\` as an escape inside a string and `#` as a comment, and runs the body of a `/*! ... */`
//! comment; PostgreSQL has `$tag$ ... $tag$` and `E'...'` strings; SQL Server has `[bracketed]`
//! identifiers. The reader takes the dialect from the sensor that captured the text.
//!
//! Nothing is evaluated. Every input is attacker data, so the text, the tokens and the statements
//! are bounded.

/// The longest text read, in bytes. Sensors cap a statement at 4096; this is slack.
const MAX_SQL_BYTES: usize = 8192;
/// The most tokens read from one text.
const MAX_TOKENS: usize = 2048;
/// The most statements one text yields.
const MAX_STATEMENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    MySql,
    MsSql,
}

impl Dialect {
    /// The dialect of the sensor that captured the text; an unknown sensor reads as PostgreSQL.
    pub fn of_sensor(sensor: &str) -> Self {
        match sensor {
            "mysql" => Dialect::MySql,
            "mssql" => Dialect::MsSql,
            _ => Dialect::Postgres,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// An unquoted word, lowercased: a keyword, a name or a `@@variable`.
    Word(String),
    /// A quoted identifier. Never a keyword, whatever it says.
    Quoted(String),
    /// A string literal's content. Secrets live here, so a rule never copies it into a token.
    Str(String),
    Num,
    Sym(char),
}

/// The statements of `sql`, each a list of tokens; empty statements are dropped.
pub fn parse(sql: &str, dialect: Dialect) -> Vec<Vec<Tok>> {
    let sql = truncate(sql, MAX_SQL_BYTES);
    let c: Vec<char> = sql.chars().collect();
    let mysql = dialect == Dialect::MySql;
    let mut out: Vec<Vec<Tok>> = Vec::new();
    let mut cur: Vec<Tok> = Vec::new();
    let mut total = 0usize;
    // Open `/*! ... */` bodies, which MySQL runs.
    let mut live_comments = 0usize;
    let mut i = 0;
    while i < c.len() && total < MAX_TOKENS {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        let tok = match ch {
            _ if ch.is_whitespace() => {
                i += 1;
                continue;
            }
            '-' if next == Some('-') => {
                i = skip_line(&c, i);
                continue;
            }
            '#' if mysql => {
                i = skip_line(&c, i);
                continue;
            }
            '/' if next == Some('*') => {
                if mysql && c.get(i + 2) == Some(&'!') {
                    i += 3;
                    while c.get(i).is_some_and(char::is_ascii_digit) {
                        i += 1;
                    }
                    live_comments += 1;
                } else {
                    i = skip_block(&c, i, !mysql);
                }
                continue;
            }
            '*' if live_comments > 0 && next == Some('/') => {
                live_comments -= 1;
                i += 2;
                continue;
            }
            '\'' => {
                let (s, n) = quoted(&c, i, '\'', mysql);
                i = n;
                Tok::Str(s)
            }
            '"' => {
                let (s, n) = quoted(&c, i, '"', mysql);
                i = n;
                if mysql { Tok::Str(s) } else { Tok::Quoted(s) }
            }
            '`' => {
                let (s, n) = quoted(&c, i, '`', false);
                i = n;
                Tok::Quoted(s)
            }
            '[' if dialect == Dialect::MsSql => {
                let (s, n) = quoted_until(&c, i);
                i = n;
                Tok::Quoted(s)
            }
            '$' if dialect == Dialect::Postgres && dollar_tag(&c, i).is_some() => {
                let (s, n) = dollar_quoted(&c, i);
                i = n;
                Tok::Str(s)
            }
            ';' => {
                i += 1;
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    if out.len() >= MAX_STATEMENTS {
                        return out;
                    }
                }
                continue;
            }
            d if d.is_ascii_digit() => {
                while c.get(i).is_some_and(|d| d.is_alphanumeric() || *d == '.') {
                    i += 1;
                }
                Tok::Num
            }
            a if a.is_alphabetic() || a == '_' || a == '@' => {
                let start = i;
                while c
                    .get(i)
                    .is_some_and(|d| d.is_alphanumeric() || matches!(d, '_' | '$' | '@' | '#'))
                {
                    i += 1;
                }
                let word: String = c[start..i].iter().collect::<String>().to_ascii_lowercase();
                if c.get(i) == Some(&'\'') {
                    // `N'...'` is a national string and `E'...'` an escape string; the prefix is
                    // not a word of its own.
                    if word == "n" {
                        continue;
                    }
                    if word == "e" && dialect == Dialect::Postgres {
                        let (s, n) = quoted(&c, i, '\'', true);
                        i = n;
                        cur.push(Tok::Str(s));
                        total += 1;
                        continue;
                    }
                }
                Tok::Word(word)
            }
            other => {
                i += 1;
                Tok::Sym(other)
            }
        };
        cur.push(tok);
        total += 1;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
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

fn skip_line(c: &[char], from: usize) -> usize {
    c[from..]
        .iter()
        .position(|d| *d == '\n')
        .map_or(c.len(), |p| from + p + 1)
}

/// Past the `*/` that closes the comment opened at `from`; PostgreSQL and SQL Server nest them.
fn skip_block(c: &[char], from: usize, nests: bool) -> usize {
    let mut depth = 1usize;
    let mut i = from + 2;
    while i < c.len() {
        match (c[i], c.get(i + 1)) {
            ('*', Some('/')) => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            ('/', Some('*')) if nests => {
                depth += 1;
                i += 2;
            }
            _ => i += 1,
        }
    }
    c.len()
}

/// The content of the literal opened by the quote at `from`, and the index past its closing
/// quote. A doubled quote is one quote; a backslash escapes the next character when `escapes`.
fn quoted(c: &[char], from: usize, q: char, escapes: bool) -> (String, usize) {
    let mut s = String::new();
    let mut i = from + 1;
    while i < c.len() {
        if c[i] == q {
            if c.get(i + 1) == Some(&q) {
                s.push(q);
                i += 2;
                continue;
            }
            return (s, i + 1);
        }
        if escapes && c[i] == '\\' && i + 1 < c.len() {
            s.push(c[i + 1]);
            i += 2;
            continue;
        }
        s.push(c[i]);
        i += 1;
    }
    (s, c.len())
}

/// A SQL Server `[identifier]`; `]]` is a closing bracket in the name.
fn quoted_until(c: &[char], from: usize) -> (String, usize) {
    let mut s = String::new();
    let mut i = from + 1;
    while i < c.len() {
        if c[i] == ']' {
            if c.get(i + 1) == Some(&']') {
                s.push(']');
                i += 2;
                continue;
            }
            return (s, i + 1);
        }
        s.push(c[i]);
        i += 1;
    }
    (s, c.len())
}

/// The end (inclusive) of the `$tag$` that opens at `from`, if one does.
fn dollar_tag(c: &[char], from: usize) -> Option<usize> {
    let mut j = from + 1;
    if c.get(j).is_some_and(|d| d.is_alphabetic() || *d == '_') {
        while c.get(j).is_some_and(|d| d.is_alphanumeric() || *d == '_') {
            j += 1;
        }
    }
    (c.get(j) == Some(&'$')).then_some(j)
}

fn dollar_quoted(c: &[char], from: usize) -> (String, usize) {
    let Some(end) = dollar_tag(c, from) else {
        return (String::new(), from + 1);
    };
    let delim = &c[from..=end];
    let body = end + 1;
    let mut i = body;
    while i + delim.len() <= c.len() {
        if &c[i..i + delim.len()] == delim {
            return (c[body..i].iter().collect(), i + delim.len());
        }
        i += 1;
    }
    (c[body..].iter().collect(), c.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(sql: &str, d: Dialect) -> Vec<String> {
        parse(sql, d)
            .into_iter()
            .flatten()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w),
                _ => None,
            })
            .collect()
    }

    const PG: Dialect = Dialect::Postgres;
    const MY: Dialect = Dialect::MySql;
    const MS: Dialect = Dialect::MsSql;

    #[test]
    fn keywords_are_case_insensitive_and_statements_split_at_semicolons() {
        assert_eq!(words("SeLeCt VeRsIoN();", PG), ["select", "version"]);
        assert_eq!(parse("select 1; select 2;;", PG).len(), 2);
    }

    #[test]
    fn literals_quoted_names_and_comments_hold_no_words() {
        assert_eq!(
            words("select 'drop user x', \"grant\" from t", PG),
            ["select", "from", "t"]
        );
        assert_eq!(words("select 1 -- grant all\n, 2", PG), ["select"]);
        assert_eq!(
            words("select /* grant /* nested */ still */ 1", PG),
            ["select"]
        );
        assert_eq!(words("select 'it''s a grant'", PG), ["select"]);
        assert_eq!(words("select `grant` from t", MY), ["select", "from", "t"]);
        assert_eq!(words("select [grant] from t", MS), ["select", "from", "t"]);
    }

    #[test]
    fn the_dialect_decides_what_is_code() {
        // MySQL: a backslash escapes the quote, so the string runs on; `#` starts a comment.
        assert_eq!(words("select 'a\\' grant x'", MY), ["select"]);
        assert_eq!(words("select 'a\\' grant x'", PG), ["select", "grant", "x"]);
        assert_eq!(words("select 1 # grant", MY), ["select"]);
        assert_eq!(words("select 1 # grant", PG), ["select", "grant"]);
        // MySQL double quotes are strings; elsewhere they quote an identifier. Neither is a word.
        assert_eq!(words("select \"grant\"", MY), ["select"]);
        // A MySQL `/*! */` comment runs; in the other dialects it is a comment.
        assert_eq!(
            words("select /*!50000 version*/()", MY),
            ["select", "version"]
        );
        assert_eq!(words("select /*!50000 version*/()", PG), ["select"]);
        // PostgreSQL dollar quoting and escape strings.
        assert_eq!(words("select $$grant$$, $a$ drop $a$", PG), ["select"]);
        assert_eq!(words("select e'a\\' grant'", PG), ["select"]);
    }

    #[test]
    fn variables_keep_their_at_signs_and_national_prefixes_vanish() {
        assert_eq!(
            words("select @@version, @x", MS),
            ["select", "@@version", "@x"]
        );
        assert_eq!(words("exec sp_x N'abc'", MS), ["exec", "sp_x"]);
    }

    #[test]
    fn runaway_input_is_bounded() {
        assert!(parse(&"a;".repeat(10_000), PG).len() <= MAX_STATEMENTS);
        let long = "select ".repeat(10_000);
        assert!(parse(&long, PG).iter().map(Vec::len).sum::<usize>() <= MAX_TOKENS);
        assert_eq!(words("select 'unterminated", PG), ["select"]);
        assert_eq!(words("select /* unterminated", PG), ["select"]);
        assert_eq!(words("select $a$ unterminated", PG), ["select"]);
    }
}
