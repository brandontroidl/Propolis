//! C `printf` conversions for numbers and strings, as glibc renders them: `%d %i %o %u %x %X %c
//! %s %e %E %f %F %g %G` with the `- + space # 0` flags, a width and a precision. `awk`'s
//! `printf`, `sprintf` and its number-to-string conversions (`CONVFMT`, `OFMT`) go through here.
//!
//! The floating forms are built from Rust's exact decimal rendering, which rounds a tie to even
//! the way glibc does (`%.1f` of 2.25 is `2.2`; recorded from mawk on Ubuntu 22.04).
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

/// The flags, width and precision of one conversion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Spec {
    pub left: bool,
    pub plus: bool,
    pub space: bool,
    pub alt: bool,
    pub zero: bool,
    pub width: Option<usize>,
    pub precision: Option<usize>,
}

/// The widest field and the most digits one conversion may ask for, so a format cannot grow a
/// reply without bound.
pub(super) const FIELD_MAX: usize = 4_096;

impl Spec {
    fn width(&self) -> usize {
        self.width.unwrap_or(0).min(FIELD_MAX)
    }

    fn precision(&self) -> Option<usize> {
        self.precision.map(|p| p.min(FIELD_MAX))
    }

    /// The sign glyph for a value, as the flags ask.
    fn sign(&self, negative: bool) -> &'static str {
        if negative {
            "-"
        } else if self.plus {
            "+"
        } else if self.space {
            " "
        } else {
            ""
        }
    }

    /// `sign` and `body` padded to the width: zeros between them when asked (and allowed),
    /// spaces on the left or right otherwise.
    fn pad(&self, sign: &str, body: &str, zero_ok: bool) -> String {
        let len = sign.len().saturating_add(body.len());
        let fill = self.width().saturating_sub(len);
        if self.left {
            format!("{sign}{body}{}", " ".repeat(fill))
        } else if self.zero && zero_ok {
            format!("{sign}{}{body}", "0".repeat(fill))
        } else {
            format!("{}{sign}{body}", " ".repeat(fill))
        }
    }
}

/// `%d` and `%i`.
pub(super) fn signed(spec: &Spec, value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let body = match spec.precision() {
        Some(0) if value == 0 => String::new(),
        Some(p) if p > digits.len() => {
            format!("{}{digits}", "0".repeat(p.saturating_sub(digits.len())))
        }
        _ => digits,
    };
    spec.pad(spec.sign(value < 0), &body, spec.precision.is_none())
}

/// `%o`, `%u`, `%x` and `%X`.
pub(super) fn unsigned(spec: &Spec, conv: char, value: u64) -> String {
    let mut digits = match conv {
        'o' => format!("{value:o}"),
        'x' => format!("{value:x}"),
        'X' => format!("{value:X}"),
        _ => value.to_string(),
    };
    if let Some(p) = spec.precision() {
        if p == 0 && value == 0 {
            digits.clear();
        } else if p > digits.len() {
            digits = format!("{}{digits}", "0".repeat(p.saturating_sub(digits.len())));
        }
    }
    let prefix = match conv {
        'o' if spec.alt && !digits.starts_with('0') => "0",
        'x' if spec.alt && value != 0 => "0x",
        'X' if spec.alt && value != 0 => "0X",
        _ => "",
    };
    spec.pad(prefix, &digits, spec.precision.is_none())
}

/// `%s`: the precision cuts the string to that many bytes.
pub(super) fn string(spec: &Spec, text: &[u8]) -> Vec<u8> {
    let cut = match spec.precision() {
        Some(p) => text.get(..p.min(text.len())).unwrap_or(text),
        None => text,
    };
    let fill = spec.width().saturating_sub(cut.len());
    let mut out = Vec::with_capacity(cut.len().saturating_add(fill));
    if !spec.left {
        out.resize(fill, b' ');
    }
    out.extend_from_slice(cut);
    if spec.left {
        out.resize(out.len().saturating_add(fill), b' ');
    }
    out
}

fn non_finite(spec: &Spec, conv: char, value: f64) -> String {
    let upper = conv.is_ascii_uppercase();
    let word = if value.is_nan() { "nan" } else { "inf" };
    let word = if upper {
        word.to_ascii_uppercase()
    } else {
        word.to_string()
    };
    spec.pad(spec.sign(value.is_sign_negative()), &word, false)
}

/// `d.ddde±XX` for a non-negative finite value with `precision` fraction digits.
fn exponent_form(value: f64, precision: usize, upper: bool, alt: bool) -> String {
    let rendered = format!("{value:.precision$e}");
    let (mantissa, exponent) = rendered.split_once('e').unwrap_or((&rendered, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let mut mantissa = mantissa.to_string();
    if alt && !mantissa.contains('.') {
        mantissa.push('.');
    }
    let sign = if exponent < 0 { '-' } else { '+' };
    let e = if upper { 'E' } else { 'e' };
    format!("{mantissa}{e}{sign}{:02}", exponent.unsigned_abs())
}

/// The decimal exponent `%e` would print for `value` at `precision` fraction digits.
fn exponent_of(value: f64, precision: usize) -> i32 {
    let rendered = format!("{value:.precision$e}");
    rendered
        .split_once('e')
        .and_then(|(_, e)| e.parse().ok())
        .unwrap_or(0)
}

fn strip_fraction_zeros(text: &str) -> String {
    if !text.contains('.') {
        return text.to_string();
    }
    let trimmed = text.trim_end_matches('0');
    trimmed.trim_end_matches('.').to_string()
}

/// `%e %E %f %F %g %G`.
pub(super) fn float(spec: &Spec, conv: char, value: f64) -> String {
    if !value.is_finite() {
        return non_finite(spec, conv, value);
    }
    let negative = value.is_sign_negative();
    let magnitude = value.abs();
    let upper = conv.is_ascii_uppercase();
    let body = match conv.to_ascii_lowercase() {
        'e' => exponent_form(magnitude, spec.precision().unwrap_or(6), upper, spec.alt),
        'f' => {
            let p = spec.precision().unwrap_or(6);
            let mut text = format!("{magnitude:.p$}");
            if spec.alt && p == 0 {
                text.push('.');
            }
            text
        }
        _ => {
            let p = match spec.precision().unwrap_or(6) {
                0 => 1,
                p => p,
            };
            let x = if magnitude == 0.0 {
                0
            } else {
                exponent_of(magnitude, p.saturating_sub(1))
            };
            let p_i = i32::try_from(p).unwrap_or(i32::MAX);
            if x < -4 || x >= p_i {
                let text = exponent_form(magnitude, p.saturating_sub(1), upper, spec.alt);
                if spec.alt {
                    text
                } else {
                    let (mantissa, exp) = text
                        .split_once(['e', 'E'])
                        .map_or((text.as_str(), ""), |(m, e)| (m, e));
                    let e = if upper { 'E' } else { 'e' };
                    format!("{}{e}{exp}", strip_fraction_zeros(mantissa))
                }
            } else {
                let decimals =
                    usize::try_from(p_i.saturating_sub(1).saturating_sub(x)).unwrap_or(0);
                let text = format!("{magnitude:.decimals$}");
                if spec.alt {
                    if text.contains('.') {
                        text
                    } else {
                        format!("{text}.")
                    }
                } else {
                    strip_fraction_zeros(&text)
                }
            }
        }
    };
    spec.pad(spec.sign(negative), &body, true)
}

/// Parse the flags, width and precision of a conversion starting just after its `%`, taking `*`
/// values from `star`. Returns the spec, the conversion character and how many bytes were read.
pub(super) fn parse_spec(text: &[u8], mut star: impl FnMut() -> i64) -> Option<(Spec, u8, usize)> {
    let mut spec = Spec::default();
    let mut at = 0usize;
    while let Some(&b) = text.get(at) {
        match b {
            b'-' => spec.left = true,
            b'+' => spec.plus = true,
            b' ' => spec.space = true,
            b'#' => spec.alt = true,
            b'0' => spec.zero = true,
            _ => break,
        }
        at = at.saturating_add(1);
    }
    let number = |at: &mut usize| -> Option<usize> {
        let start = *at;
        while text.get(*at).is_some_and(u8::is_ascii_digit) {
            *at = at.saturating_add(1);
        }
        std::str::from_utf8(text.get(start..*at)?)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
    };
    if text.get(at) == Some(&b'*') {
        at = at.saturating_add(1);
        let w = star();
        if w < 0 {
            spec.left = true;
        }
        spec.width = Some(usize::try_from(w.unsigned_abs()).unwrap_or(FIELD_MAX));
    } else {
        spec.width = number(&mut at);
    }
    if text.get(at) == Some(&b'.') {
        at = at.saturating_add(1);
        if text.get(at) == Some(&b'*') {
            at = at.saturating_add(1);
            let p = star();
            spec.precision = usize::try_from(p).ok();
        } else {
            spec.precision = Some(number(&mut at).unwrap_or(0));
        }
    }
    // Length modifiers mean nothing to a value that is already a double.
    while matches!(
        text.get(at),
        Some(b'h' | b'l' | b'L' | b'q' | b'j' | b'z' | b't')
    ) {
        at = at.saturating_add(1);
    }
    let conv = *text.get(at)?;
    Some((spec, conv, at.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(width: Option<usize>, precision: Option<usize>) -> Spec {
        Spec {
            width,
            precision,
            ..Spec::default()
        }
    }

    /// Each expectation is what mawk 1.3.4 (glibc) printed on Ubuntu 22.04, 2026-10-07.
    #[test]
    fn floats_render_as_glibc_does() {
        assert_eq!(float(&spec(None, Some(1)), 'f', 3.0 / 7.0 * 100.0), "42.9");
        assert_eq!(
            float(
                &Spec {
                    zero: true,
                    ..spec(Some(5), Some(1))
                },
                'f',
                2.25
            ),
            "002.2"
        );
        assert_eq!(float(&spec(Some(5), Some(2)), 'f', 1.23456), " 1.23");
        assert_eq!(float(&spec(None, None), 'e', 12345.678), "1.234568e+04");
        assert_eq!(float(&spec(None, Some(6)), 'g', 1.0 / 3.0), "0.333333");
        assert_eq!(float(&spec(None, Some(6)), 'g', 1e20), "1e+20");
        assert_eq!(
            float(&spec(None, Some(6)), 'g', 2_147_483_648.0),
            "2.14748e+09"
        );
        assert_eq!(
            float(&spec(None, Some(6)), 'g', 9_007_199_254_740_993.0),
            "9.0072e+15"
        );
        assert_eq!(float(&spec(None, Some(6)), 'g', 0.00001), "1e-05");
        assert_eq!(
            float(&spec(None, Some(6)), 'g', 123_456_789.5),
            "1.23457e+08"
        );
        assert_eq!(float(&spec(None, Some(6)), 'g', 100.0 / 3.0), "33.3333");
        assert_eq!(float(&spec(None, Some(6)), 'g', 0.1 + 0.2), "0.3");
        assert_eq!(float(&spec(None, None), 'g', f64::INFINITY), "inf");
        assert_eq!(float(&spec(None, None), 'g', f64::NEG_INFINITY), "-inf");
        assert_eq!(float(&spec(None, None), 'f', -0.0), "-0.000000");
    }

    #[test]
    fn integers_and_strings_pad_and_sign() {
        assert_eq!(signed(&spec(Some(5), None), 42), "   42");
        assert_eq!(
            signed(
                &Spec {
                    left: true,
                    ..spec(Some(4), None)
                },
                7
            ),
            "7   "
        );
        assert_eq!(
            signed(
                &Spec {
                    plus: true,
                    ..Spec::default()
                },
                3
            ),
            "+3"
        );
        assert_eq!(
            signed(
                &Spec {
                    space: true,
                    ..Spec::default()
                },
                4
            ),
            " 4"
        );
        assert_eq!(
            signed(
                &Spec {
                    zero: true,
                    ..spec(Some(3), None)
                },
                7
            ),
            "007"
        );
        assert_eq!(unsigned(&Spec::default(), 'x', 255), "ff");
        assert_eq!(unsigned(&Spec::default(), 'o', 8), "10");
        assert_eq!(string(&spec(Some(5), None), b"ab"), b"   ab");
        assert_eq!(string(&spec(None, Some(3)), b"abcdef"), b"abc");
    }

    #[test]
    fn a_spec_parses_flags_width_precision_and_stars() {
        let mut stars = [5i64, 2].into_iter();
        let (s, conv, used) = parse_spec(b"-*.*fX", || stars.next().unwrap_or(0)).expect("spec");
        assert!(s.left);
        assert_eq!(
            (s.width, s.precision, conv, used),
            (Some(5), Some(2), b'f', 5)
        );
    }
}
