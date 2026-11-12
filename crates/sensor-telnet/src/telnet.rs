//! Telnet IAC (Interpret As Command) negotiation helpers (RFC 854): pure, I/O-free parsing of
//! the escape-byte protocol embedded in the Telnet byte stream, mirroring sensor-ssh's
//! `auth`/`channel` modules' own "no I/O of its own" convention so this logic is deterministic
//! and testable without a live socket. `handler.rs` is the only place that touches an actual
//! `TcpStream`.
//!
//! Telnet's wire format interleaves two kinds of bytes on the same stream: ordinary data (the
//! username, password, and command lines this sensor actually cares about) and IAC-prefixed
//! protocol bytes (`0xFF` followed by a command byte, optionally followed by an option byte or a
//! whole subnegotiation block). [`IacFilter`] splits an arbitrary, possibly protocol-boundary-
//! splitting-across-reads byte slice into the two: plain data bytes to feed the line buffer, and
//! any IAC bytes this sensor must write back immediately to keep the client's own negotiation
//! state machine from stalling.
//!
//! **Negotiation policy.** This sensor claims `WILL ECHO` and `WILL SGA` unconditionally at
//! connect (see [`negotiation_preamble`]) and refuses everything else the client proposes: a
//! client `WILL <opt>` is answered `DONT <opt>`, a client `DO <opt>` is answered `WONT <opt>`.
//! Per RFC 854, `WONT`/`DONT` from the client are never themselves answered - replying to an
//! already-refused option risks an infinite negotiation loop.

/// Interpret As Command: escapes the next byte(s) as a Telnet protocol sequence rather than data.
const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;

/// Telnet Suppress Go Ahead option (RFC 858) - the only option this sensor offers.
const OPT_SGA: u8 = 3;
const OPT_ECHO: u8 = 1;

/// The bytes to send immediately after accepting a connection: `IAC WILL ECHO`, `IAC WILL SGA`.
///
/// A real telnetd offers server-side echo, so the sensor does too - and, unlike the earlier
/// behaviour, actually echoes (see the handler's `LineReader`). A line-mode client that agrees
/// (`DO ECHO`) then stops local-echoing, so a bare Enter's CR is no longer shown by the client as a
/// literal `^M` and the login/shell renders like a real host. `WILL SGA` is also offered (character
/// mode). Offering echo without echoing would be the contradiction the previous code avoided by not
/// claiming it; the fix is to claim it AND honour it.
pub fn negotiation_preamble() -> Vec<u8> {
    vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]
}

/// Which negotiation verb [`IacFilter`] is midway through parsing the option byte for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Will,
    Do,
    WontOrDont,
}

/// [`IacFilter`]'s parse position within the byte stream. Persists across calls to `process` so a
/// negotiation or subnegotiation sequence split across two separate socket reads (a slow or
/// deliberately adversarial client can write one byte at a time) is still parsed correctly rather
/// than corrupting the line buffer with a stray protocol byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Ordinary data.
    Data,
    /// Just saw a lone `IAC`.
    Iac,
    /// Saw `IAC <verb>`; the next byte is the option code this verb applies to.
    Negotiate(Verb),
    /// Inside a subnegotiation block (`IAC SB ...`); every byte is discarded until `IAC SE`
    /// closes it. This sensor never participates in subnegotiation content (see the module doc's
    /// negotiation policy: everything but the two options it unilaterally claims is refused), so
    /// the block's contents are never inspected, only skipped.
    Subneg,
    /// Inside a subnegotiation block, just saw an `IAC`: the next byte is either `SE` (closing
    /// the block) or anything else (an escaped literal 0xFF, or a nested command), which resumes
    /// discarding subnegotiation bytes rather than ending the block.
    SubnegIac,
}

/// Stateful IAC stripper. One instance per connection, fed every raw byte read off the socket, in
/// order, via [`process`](Self::process).
pub struct IacFilter {
    state: State,
}

impl Default for IacFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IacFilter {
    pub fn new() -> Self {
        Self { state: State::Data }
    }

    /// Consume `input` (raw bytes just read off the socket), appending plain data bytes to
    /// `data_out` and any negotiation reply bytes this sensor must write back to `response_out`.
    /// Never panics on any input, including a truncated or malformed IAC sequence split across
    /// the boundary of this call (see the module doc): worst case, a dangling `Iac`/`Negotiate`/
    /// `SubnegIac` state simply carries over to the next `process` call.
    pub fn process(&mut self, input: &[u8], data_out: &mut Vec<u8>, response_out: &mut Vec<u8>) {
        for &byte in input {
            self.state = match self.state {
                State::Data => {
                    if byte == IAC {
                        State::Iac
                    } else {
                        data_out.push(byte);
                        State::Data
                    }
                }
                State::Iac => match byte {
                    // A doubled IAC is the escape for one literal 0xFF data byte (RFC 854).
                    IAC => {
                        data_out.push(IAC);
                        State::Data
                    }
                    WILL => State::Negotiate(Verb::Will),
                    DO => State::Negotiate(Verb::Do),
                    WONT | DONT => State::Negotiate(Verb::WontOrDont),
                    SB => State::Subneg,
                    // NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, and anything else this sensor does
                    // not recognize: all are exactly `IAC <byte>` with no further argument, so
                    // the command is simply consumed and ignored.
                    _ => State::Data,
                },
                State::Negotiate(verb) => {
                    match verb {
                        // The client proposed enabling an option, or asked us to: refuse both,
                        // per the module doc's negotiation policy.
                        Verb::Will => response_out.extend_from_slice(&[IAC, DONT, byte]),
                        // We offered WILL ECHO and WILL SGA, so a client DO ECHO / DO SGA is the
                        // agreement - reply nothing (RFC 854 loop avoidance). A DO for any option we
                        // did not offer is refused with WONT.
                        Verb::Do => {
                            if byte != OPT_SGA && byte != OPT_ECHO {
                                response_out.extend_from_slice(&[IAC, WONT, byte]);
                            }
                        }
                        // WONT/DONT are already-refused notices; never reply to one (RFC 854's
                        // loop-avoidance rule).
                        Verb::WontOrDont => {}
                    }
                    State::Data
                }
                State::Subneg => {
                    if byte == IAC {
                        State::SubnegIac
                    } else {
                        State::Subneg
                    }
                }
                State::SubnegIac => {
                    if byte == SE {
                        State::Data
                    } else {
                        State::Subneg
                    }
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_preamble_offers_echo_and_sga() {
        // A real telnetd offers server-side echo; the sensor now does too (and actually echoes), so
        // a line-mode client stops local-echoing and the CR of a bare Enter no longer renders as ^M.
        const OPT_ECHO: u8 = 1;
        assert_eq!(
            negotiation_preamble(),
            vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]
        );
    }

    #[test]
    fn client_do_sga_gets_no_reply_because_we_offered_it() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[IAC, DO, OPT_SGA], &mut data, &mut resp);
        assert!(
            resp.is_empty(),
            "DO for our own offered SGA is agreement, not something to refuse"
        );
    }

    #[test]
    fn client_do_echo_gets_no_reply_because_we_offered_it() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        const OPT_ECHO: u8 = 1; // RFC 857; the sensor now offers WILL ECHO
        // DO ECHO is the client agreeing to our offer - reply nothing (RFC 854 loop avoidance).
        filter.process(&[IAC, DO, OPT_ECHO], &mut data, &mut resp);
        assert!(resp.is_empty());
    }

    #[test]
    fn plain_data_passes_through_unchanged() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(b"hello world\r\n", &mut data, &mut resp);
        assert_eq!(data, b"hello world\r\n");
        assert!(resp.is_empty());
    }

    #[test]
    fn client_will_is_answered_dont() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        // Client claims it will handle option 24 (terminal type).
        filter.process(&[IAC, WILL, 24], &mut data, &mut resp);
        assert_eq!(resp, vec![IAC, DONT, 24]);
        assert!(data.is_empty());
    }

    #[test]
    fn client_do_is_answered_wont() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[IAC, DO, 31], &mut data, &mut resp); // NAWS
        assert_eq!(resp, vec![IAC, WONT, 31]);
    }

    #[test]
    fn client_wont_and_dont_get_no_reply() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[IAC, WONT, 1, IAC, DONT, 3], &mut data, &mut resp);
        assert!(
            resp.is_empty(),
            "must never reply to WONT/DONT (RFC 854 loop avoidance)"
        );
    }

    #[test]
    fn doubled_iac_is_one_literal_data_byte() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[b'a', IAC, IAC, b'b'], &mut data, &mut resp);
        assert_eq!(data, vec![b'a', 0xFF, b'b']);
        assert!(resp.is_empty());
    }

    #[test]
    fn subnegotiation_is_consumed_without_leaking_into_data() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        // IAC SB <opt 24> 0 "xterm" IAC SE, surrounded by real data.
        let mut input = vec![b'A'];
        input.extend_from_slice(&[IAC, SB, 24, 0]);
        input.extend_from_slice(b"xterm");
        input.extend_from_slice(&[IAC, SE]);
        input.push(b'B');
        filter.process(&input, &mut data, &mut resp);
        assert_eq!(data, vec![b'A', b'B']);
        assert!(resp.is_empty());
    }

    #[test]
    fn negotiation_sequence_split_across_two_calls_still_answered() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[IAC, WILL], &mut data, &mut resp);
        assert!(resp.is_empty(), "must wait for the option byte");
        filter.process(&[24], &mut data, &mut resp);
        assert_eq!(resp, vec![IAC, DONT, 24]);
    }

    #[test]
    fn subnegotiation_split_across_two_calls_does_not_leak() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[b'A', IAC, SB, 24], &mut data, &mut resp);
        filter.process(b"xterm", &mut data, &mut resp);
        filter.process(&[IAC, SE, b'B'], &mut data, &mut resp);
        assert_eq!(data, vec![b'A', b'B']);
        assert!(resp.is_empty());
    }

    #[test]
    fn two_byte_commands_are_consumed_with_no_reply() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        // AYT (Are You There) - a bare 2-byte command, no option byte, no reply defined here.
        filter.process(&[IAC, 246], &mut data, &mut resp);
        assert!(data.is_empty());
        assert!(resp.is_empty());
    }

    #[test]
    fn malformed_truncated_iac_at_end_of_input_does_not_panic() {
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        filter.process(&[b'x', IAC], &mut data, &mut resp);
        assert_eq!(data, vec![b'x']);
    }

    #[test]
    fn iac_embedded_mid_line_is_stripped_not_left_in_data() {
        // "Don't let IAC bytes corrupt the line buffer" - the task brief's own phrasing.
        let mut filter = IacFilter::new();
        let mut data = Vec::new();
        let mut resp = Vec::new();
        let mut input = b"ro".to_vec();
        input.extend_from_slice(&[IAC, WILL, 24]);
        input.extend_from_slice(b"ot\r\n");
        filter.process(&input, &mut data, &mut resp);
        assert_eq!(data, b"root\r\n");
        assert_eq!(resp, vec![IAC, DONT, 24]);
    }

    proptest::proptest! {
        /// Fuzz-lite guard mirroring sensor-ssh's `channel`/`auth` modules' own
        /// `never_panics_on_arbitrary_bytes` convention: `IacFilter` parses fully
        /// attacker-controlled, pre-authentication bytes, so arbitrary (including malformed or
        /// truncated) input must never panic, whatever state it lands the filter in.
        #[test]
        fn process_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=1024)
        ) {
            let mut filter = IacFilter::new();
            let mut data = Vec::new();
            let mut resp = Vec::new();
            filter.process(&bytes, &mut data, &mut resp);
        }

        /// Splitting the same input across two arbitrary-length calls must never panic either,
        /// and must not depend on internal buffering beyond `state` (this crate's read loop
        /// genuinely delivers input across many separate socket reads).
        #[test]
        fn process_never_panics_when_split_across_calls(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=512),
            split in 0usize..=512
        ) {
            let mut filter = IacFilter::new();
            let mut data = Vec::new();
            let mut resp = Vec::new();
            let split = split.min(bytes.len());
            filter.process(&bytes[..split], &mut data, &mut resp);
            filter.process(&bytes[split..], &mut data, &mut resp);
        }
    }
}
