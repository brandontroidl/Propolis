//! `$(( expr ))`: integer arithmetic over `i64` with 64-bit wrapping, as bash does. Operators, in
//! rising precedence: `,`, `?:`, `||`, `&&`, `|`, `^`, `&`, `== !=`, `< <= > >=`, `<< >>`, `+ -`,
//! `* / %`, `**`, and the unary `+ - ! ~`. A bare name is its variable's integer value, and an
//! unset or non-numeric one is 0.
//!
//! Every operation wraps or is checked (division and remainder by zero are the only errors that
//! come from a value), so no expression can panic. Recursion is bounded by the same depth cap as
//! everything else.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ArithError {
    /// `x / 0` or `x % 0`: the text from the divisor on, as bash reports it.
    DivByZero {
        token: String,
    },
    /// The expression is not well formed: the text from where it went wrong.
    Syntax {
        token: String,
    },
    TooDeep,
}

/// Evaluate `expr`, reading variables through `lookup`.
pub(super) fn eval(
    expr: &str,
    max_depth: u32,
    lookup: &mut dyn FnMut(&str) -> String,
) -> Result<i64, ArithError> {
    let mut parser = Arith {
        src: expr,
        pos: 0,
        depth: 0,
        max_depth,
        lookup,
    };
    let value = parser.comma(true)?;
    parser.skip_blanks();
    if parser.pos < parser.src.len() {
        return Err(parser.syntax());
    }
    Ok(value)
}

struct Arith<'a> {
    src: &'a str,
    pos: usize,
    depth: u32,
    max_depth: u32,
    lookup: &'a mut dyn FnMut(&str) -> String,
}

/// A variable's text as an integer: decimal, `0x` hex, leading-zero octal, else 0.
fn parse_integer(text: &str) -> i64 {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let value = number(digits).unwrap_or(0);
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

fn number(text: &str) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let (radix, digits) =
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, hex)
        } else if text.len() > 1 && text.starts_with('0') {
            (8, text.get(1..)?)
        } else {
            (10, text)
        };
    let mut value = 0i64;
    for c in digits.chars() {
        let digit = i64::from(c.to_digit(radix)?);
        value = value.wrapping_mul(i64::from(radix)).wrapping_add(digit);
    }
    Some(value)
}

impl Arith<'_> {
    fn rest(&self) -> &str {
        self.src.get(self.pos..).unwrap_or("")
    }

    fn syntax(&self) -> ArithError {
        ArithError::Syntax {
            token: self.rest().to_string(),
        }
    }

    fn skip_blanks(&mut self) {
        while self.rest().starts_with([' ', '\t', '\n']) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// Consume `op` if it comes next, and is not the start of a longer operator in `longer`.
    fn eat(&mut self, op: &str, longer: &[&str]) -> bool {
        self.skip_blanks();
        let rest = self.rest();
        if rest.starts_with(op) && !longer.iter().any(|l| rest.starts_with(l)) {
            self.pos = self.pos.saturating_add(op.len());
            true
        } else {
            false
        }
    }

    fn enter(&mut self) -> Result<(), ArithError> {
        if self.depth >= self.max_depth {
            return Err(ArithError::TooDeep);
        }
        self.depth = self.depth.saturating_add(1);
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// `live` is false in a branch that is not taken, where a division by zero is not an error.
    fn comma(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut value = self.ternary(live)?;
        while self.eat(",", &[]) {
            value = self.ternary(live)?;
        }
        Ok(value)
    }

    fn ternary(&mut self, live: bool) -> Result<i64, ArithError> {
        let cond = self.logical_or(live)?;
        if !self.eat("?", &[]) {
            return Ok(cond);
        }
        self.enter()?;
        let then = self.comma(live && cond != 0);
        self.leave();
        let then = then?;
        if !self.eat(":", &[]) {
            return Err(self.syntax());
        }
        let otherwise = self.ternary(live && cond == 0)?;
        Ok(if cond != 0 { then } else { otherwise })
    }

    fn logical_or(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.logical_and(live)?;
        while self.eat("||", &[]) {
            let right = self.logical_and(live && left == 0)?;
            left = i64::from(left != 0 || right != 0);
        }
        Ok(left)
    }

    fn logical_and(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.bit_or(live)?;
        while self.eat("&&", &[]) {
            let right = self.bit_or(live && left != 0)?;
            left = i64::from(left != 0 && right != 0);
        }
        Ok(left)
    }

    fn bit_or(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.bit_xor(live)?;
        while self.eat("|", &["||"]) {
            left |= self.bit_xor(live)?;
        }
        Ok(left)
    }

    fn bit_xor(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.bit_and(live)?;
        while self.eat("^", &[]) {
            left ^= self.bit_and(live)?;
        }
        Ok(left)
    }

    fn bit_and(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.equality(live)?;
        while self.eat("&", &["&&"]) {
            left &= self.equality(live)?;
        }
        Ok(left)
    }

    fn equality(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.relational(live)?;
        loop {
            if self.eat("==", &[]) {
                left = i64::from(left == self.relational(live)?);
            } else if self.eat("!=", &[]) {
                left = i64::from(left != self.relational(live)?);
            } else {
                return Ok(left);
            }
        }
    }

    fn relational(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.shift(live)?;
        loop {
            if self.eat("<=", &[]) {
                left = i64::from(left <= self.shift(live)?);
            } else if self.eat(">=", &[]) {
                left = i64::from(left >= self.shift(live)?);
            } else if self.eat("<", &["<<"]) {
                left = i64::from(left < self.shift(live)?);
            } else if self.eat(">", &[">>"]) {
                left = i64::from(left > self.shift(live)?);
            } else {
                return Ok(left);
            }
        }
    }

    fn shift(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.additive(live)?;
        loop {
            if self.eat("<<", &[]) {
                let by = self.additive(live)?;
                left = left.wrapping_shl(shift_count(by));
            } else if self.eat(">>", &[]) {
                let by = self.additive(live)?;
                left = left.wrapping_shr(shift_count(by));
            } else {
                return Ok(left);
            }
        }
    }

    fn additive(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.multiplicative(live)?;
        loop {
            if self.eat("+", &[]) {
                left = left.wrapping_add(self.multiplicative(live)?);
            } else if self.eat("-", &[]) {
                left = left.wrapping_sub(self.multiplicative(live)?);
            } else {
                return Ok(left);
            }
        }
    }

    fn multiplicative(&mut self, live: bool) -> Result<i64, ArithError> {
        let mut left = self.power(live)?;
        loop {
            if self.eat("*", &["**"]) {
                left = left.wrapping_mul(self.power(live)?);
            } else if self.eat("/", &[]) {
                self.skip_blanks();
                let token = self.rest().to_string();
                let right = self.power(live)?;
                if right == 0 {
                    if live {
                        return Err(ArithError::DivByZero { token });
                    }
                    left = 0;
                } else {
                    // `MIN / -1` overflows; the wrapped result is `MIN`.
                    left = left.checked_div(right).unwrap_or(i64::MIN);
                }
            } else if self.eat("%", &[]) {
                self.skip_blanks();
                let token = self.rest().to_string();
                let right = self.power(live)?;
                if right == 0 {
                    if live {
                        return Err(ArithError::DivByZero { token });
                    }
                    left = 0;
                } else {
                    left = left.checked_rem(right).unwrap_or(0);
                }
            } else {
                return Ok(left);
            }
        }
    }

    fn power(&mut self, live: bool) -> Result<i64, ArithError> {
        let base = self.unary(live)?;
        if self.eat("**", &[]) {
            self.enter()?;
            let exponent = self.power(live);
            self.leave();
            let exponent = exponent?;
            if exponent < 0 {
                return if live { Err(self.syntax()) } else { Ok(0) };
            }
            let exponent = u32::try_from(exponent).unwrap_or(u32::MAX);
            return Ok(base.wrapping_pow(exponent));
        }
        Ok(base)
    }

    fn unary(&mut self, live: bool) -> Result<i64, ArithError> {
        self.skip_blanks();
        self.enter()?;
        let result = self.unary_inner(live);
        self.leave();
        result
    }

    fn unary_inner(&mut self, live: bool) -> Result<i64, ArithError> {
        if self.eat("+", &[]) {
            return self.unary(live);
        }
        if self.eat("-", &[]) {
            return Ok(self.unary(live)?.wrapping_neg());
        }
        if self.eat("!", &["!="]) {
            return Ok(i64::from(self.unary(live)? == 0));
        }
        if self.eat("~", &[]) {
            return Ok(!self.unary(live)?);
        }
        if self.eat("(", &[]) {
            let value = self.comma(live)?;
            if !self.eat(")", &[]) {
                return Err(self.syntax());
            }
            return Ok(value);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<i64, ArithError> {
        self.skip_blanks();
        let rest = self.rest();
        let len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .map(char::len_utf8)
            .fold(0usize, usize::saturating_add);
        if len == 0 {
            return Err(self.syntax());
        }
        let word = rest.get(..len).unwrap_or("").to_string();
        self.pos = self.pos.saturating_add(len);
        if word.starts_with(|c: char| c.is_ascii_digit()) {
            return number(&word).ok_or_else(|| ArithError::Syntax {
                token: format!("{word}{}", self.rest()),
            });
        }
        let text = (self.lookup)(&word);
        Ok(parse_integer(&text))
    }
}

/// A shift count taken modulo the word size, as the hardware does.
fn shift_count(by: i64) -> u32 {
    u32::try_from(by & 63).unwrap_or(0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn run(expr: &str) -> Result<i64, ArithError> {
        eval(expr, 16, &mut |name| match name {
            "n" => "7".to_string(),
            "hex" => "0x10".to_string(),
            "junk" => "abc".to_string(),
            _ => String::new(),
        })
    }

    #[test]
    fn precedence_and_grouping_follow_c() {
        assert_eq!(run("1+2*3"), Ok(7));
        assert_eq!(run("(1+2)*3"), Ok(9));
        assert_eq!(run("2**3**2"), Ok(512));
        assert_eq!(run("-2**2"), Ok(4), "unary binds tighter than **");
        assert_eq!(run("10-4-3"), Ok(3));
        assert_eq!(run("7%4"), Ok(3));
        assert_eq!(run("1<<4|1"), Ok(17));
        assert_eq!(run("6&3^1|8"), Ok(11));
        assert_eq!(run("1<2==1"), Ok(1));
        assert_eq!(run("3>2>1"), Ok(0));
        assert_eq!(run("!0+~0"), Ok(0));
        assert_eq!(run("1?2:3"), Ok(2));
        assert_eq!(run("0?2:1?4:5"), Ok(4));
        assert_eq!(run("1,2,3"), Ok(3));
        assert_eq!(run("0||5"), Ok(1));
        assert_eq!(run("2&&0"), Ok(0));
    }

    #[test]
    fn numbers_read_decimal_hex_and_octal() {
        assert_eq!(run("0x1F"), Ok(31));
        assert_eq!(run("010"), Ok(8));
        assert!(matches!(run("09"), Err(ArithError::Syntax { .. })));
    }

    #[test]
    fn variables_are_integers_and_unset_or_junk_is_zero() {
        assert_eq!(run("n*2"), Ok(14));
        assert_eq!(run("hex+1"), Ok(17));
        assert_eq!(run("junk+1"), Ok(1));
        assert_eq!(run("unset_q"), Ok(0));
    }

    #[test]
    fn arithmetic_wraps_at_64_bits() {
        assert_eq!(run("9223372036854775807+1"), Ok(i64::MIN));
        assert_eq!(run("-9223372036854775807-2"), Ok(i64::MAX));
        assert_eq!(run("9223372036854775807*2"), Ok(-2));
        assert_eq!(run("2**64"), Ok(0));
        assert_eq!(run("1<<63"), Ok(i64::MIN));
        assert_eq!(run("1<<64"), Ok(1), "the count is taken modulo 64");
        assert_eq!(run("-9223372036854775808/-1"), Ok(i64::MIN));
    }

    #[test]
    fn division_and_remainder_by_zero_report_the_divisor_text() {
        assert_eq!(
            run("1/0"),
            Err(ArithError::DivByZero {
                token: "0".to_string()
            })
        );
        assert_eq!(
            run("5 % 0 + 1"),
            Err(ArithError::DivByZero {
                token: "0 + 1".to_string()
            })
        );
        // A branch that is not taken never divides.
        assert_eq!(run("0 && 1/0"), Ok(0));
        assert_eq!(run("1 ? 3 : 1/0"), Ok(3));
    }

    #[test]
    fn malformed_expressions_are_syntax_errors_not_panics() {
        for expr in ["", "1+", "(1", "1)", "1 2", "*3", "1 ? 2", "$"] {
            assert!(
                matches!(run(expr), Err(ArithError::Syntax { .. })),
                "{expr:?}"
            );
        }
    }

    #[test]
    fn nesting_past_the_cap_is_refused() {
        let deep = format!("{}1{}", "(".repeat(40), ")".repeat(40));
        assert_eq!(run(&deep), Err(ArithError::TooDeep));
        let unary = format!("{}1", "-".repeat(40));
        assert_eq!(run(&unary), Err(ArithError::TooDeep));
    }
}
