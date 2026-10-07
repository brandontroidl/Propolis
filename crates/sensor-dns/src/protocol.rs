//! DNS message parsing (RFC 1035 4.1) as far as this sensor needs it, and the one reply shape it
//! builds. Parsing is total over arbitrary bytes: every input yields `Ok(Query)` or
//! `Err(Rejected)`, never a panic. No compression pointer is ever followed: one in the question is
//! a rejection, and one in an additional record's owner name only ends that name.

use std::borrow::Cow;
use std::ops::Range;

pub const HEADER_LEN: usize = 12;
/// RFC 1035 2.3.4: length bytes plus label bytes plus the terminal zero.
pub const MAX_NAME_WIRE_LEN: usize = 255;
/// Additional records examined for an OPT record.
pub const MAX_ADDITIONAL_WALK: usize = 8;
/// EDNS option codes recorded per OPT record.
pub const MAX_EDNS_OPTIONS: usize = 16;
pub const RCODE_REFUSED: u16 = 5;

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const FLAG_Z: u16 = 0x0040;
pub const FLAG_AD: u16 = 0x0020;
pub const FLAG_CD: u16 = 0x0010;

pub const TYPE_TXT: u16 = 16;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_IXFR: u16 = 251;
pub const TYPE_AXFR: u16 = 252;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;

/// Bound on the owner-name walk inside an additional record, so a name of many tiny labels
/// cannot turn the scan into a long loop.
const MAX_NAME_SKIP_STEPS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn qr(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xF) as u8
    }

    pub fn rd(&self) -> bool {
        self.flags & FLAG_RD != 0
    }

    pub fn ad(&self) -> bool {
        self.flags & FLAG_AD != 0
    }

    pub fn cd(&self) -> bool {
        self.flags & FLAG_CD != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Presentation format (see [`presentation`]); not sanitized here.
    pub qname: String,
    /// Labels excluding the root.
    pub label_count: usize,
    /// Length bytes plus label bytes plus the terminal zero (1..=255).
    pub name_wire_len: usize,
    /// At least one ASCII uppercase and one ASCII lowercase letter in the labels.
    pub mixed_case: bool,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset one past QCLASS.
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    pub version: u8,
    pub udp_payload_size: u16,
    pub dnssec_ok: bool,
    pub extended_rcode: u8,
    pub option_codes: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdnsScan {
    Absent,
    Present(Edns),
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub header: Header,
    pub question: Question,
    pub edns: EdnsScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    ShortHeader,
    /// Produced only by the TCP framing (a length prefix over the message cap), never by
    /// [`parse_query`].
    Oversize,
    ResponseInbound,
    Opcode,
    Qdcount,
    CompressionPointer,
    BadLabel,
    NameTooLong,
    TruncatedQuestion,
    AnswerOrAuthorityPresent,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::ShortHeader => "short_header",
            RejectReason::Oversize => "oversize",
            RejectReason::ResponseInbound => "response_inbound",
            RejectReason::Opcode => "opcode",
            RejectReason::Qdcount => "qdcount",
            RejectReason::CompressionPointer => "compression_pointer",
            RejectReason::BadLabel => "bad_label",
            RejectReason::NameTooLong => "name_too_long",
            RejectReason::TruncatedQuestion => "truncated_question",
            RejectReason::AnswerOrAuthorityPresent => "answer_or_authority_present",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub reason: RejectReason,
    pub header: Option<Header>,
    pub question: Option<Question>,
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    let bytes = msg.get(pos..pos.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn u32_at(msg: &[u8], pos: usize) -> Option<u32> {
    let bytes = msg.get(pos..pos.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// `None` when the message is shorter than a header.
pub fn parse_header(msg: &[u8]) -> Option<Header> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    Some(Header {
        id: u16_at(msg, 0)?,
        flags: u16_at(msg, 2)?,
        qdcount: u16_at(msg, 4)?,
        ancount: u16_at(msg, 6)?,
        nscount: u16_at(msg, 8)?,
        arcount: u16_at(msg, 10)?,
    })
}

/// Parse one query. The checks run in a fixed order and the first failure wins: header length,
/// QR, opcode, QDCOUNT, the question, then the section counts. The EDNS scan never rejects.
pub fn parse_query(msg: &[u8], transport: Transport) -> Result<Query, Rejected> {
    let reject = |reason, header, question| Rejected {
        reason,
        header,
        question,
    };
    let Some(header) = parse_header(msg) else {
        return Err(reject(RejectReason::ShortHeader, None, None));
    };
    if header.qr() {
        return Err(reject(RejectReason::ResponseInbound, Some(header), None));
    }
    if header.opcode() != 0 {
        return Err(reject(RejectReason::Opcode, Some(header), None));
    }
    if header.qdcount != 1 {
        return Err(reject(RejectReason::Qdcount, Some(header), None));
    }
    let question = parse_question(msg).map_err(|reason| reject(reason, Some(header), None))?;
    if header.ancount > 0 {
        return Err(reject(
            RejectReason::AnswerOrAuthorityPresent,
            Some(header),
            Some(question),
        ));
    }
    // RFC 1995: an IXFR request carries the client's SOA in the authority section.
    let ixfr_soa =
        transport == Transport::Tcp && header.nscount == 1 && question.qtype == TYPE_IXFR;
    if header.nscount > 0 && !ixfr_soa {
        return Err(reject(
            RejectReason::AnswerOrAuthorityPresent,
            Some(header),
            Some(question),
        ));
    }
    let edns = scan_edns(msg, &header, question.end);
    Ok(Query {
        header,
        question,
        edns,
    })
}

fn parse_question(msg: &[u8]) -> Result<Question, RejectReason> {
    let mut pos = HEADER_LEN;
    let mut wire = 0usize;
    let mut labels: Vec<&[u8]> = Vec::new();
    loop {
        let len = *msg.get(pos).ok_or(RejectReason::TruncatedQuestion)?;
        match len & 0xC0 {
            0xC0 => return Err(RejectReason::CompressionPointer),
            0x40 | 0x80 => return Err(RejectReason::BadLabel),
            _ => {}
        }
        let len = usize::from(len);
        wire += 1 + len;
        if wire > MAX_NAME_WIRE_LEN {
            return Err(RejectReason::NameTooLong);
        }
        pos += 1;
        if len == 0 {
            break;
        }
        let label = msg
            .get(pos..pos + len)
            .ok_or(RejectReason::TruncatedQuestion)?;
        labels.push(label);
        pos += len;
    }
    let qtype = u16_at(msg, pos).ok_or(RejectReason::TruncatedQuestion)?;
    let qclass = u16_at(msg, pos + 2).ok_or(RejectReason::TruncatedQuestion)?;
    let has_upper = labels.iter().any(|l| l.iter().any(u8::is_ascii_uppercase));
    let has_lower = labels.iter().any(|l| l.iter().any(u8::is_ascii_lowercase));
    Ok(Question {
        qname: presentation(&labels),
        label_count: labels.len(),
        name_wire_len: wire,
        mixed_case: has_upper && has_lower,
        qtype,
        qclass,
        end: pos + 4,
    })
}

/// RFC 1035 5.1 master-file escaping, so every byte value survives as printable ASCII. The root
/// name is `.`.
fn presentation(labels: &[&[u8]]) -> String {
    if labels.is_empty() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in labels {
        for &b in *label {
            match b {
                b'.' => out.push_str("\\."),
                b'\\' => out.push_str("\\\\"),
                0x21..=0x7E => out.push(char::from(b)),
                _ => out.push_str(&format!("\\{b:03}")),
            }
        }
        out.push('.');
    }
    out
}

struct Rr {
    name_is_root: bool,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: Range<usize>,
    next: usize,
}

/// Skip one resource record starting at `pos`. Owner-name pointers end the name but are never
/// followed.
fn read_rr(msg: &[u8], pos: usize) -> Option<Rr> {
    let start = pos;
    let mut pos = pos;
    let mut wire = 0usize;
    let mut name_end = None;
    for _ in 0..MAX_NAME_SKIP_STEPS {
        let b = *msg.get(pos)?;
        match b & 0xC0 {
            0xC0 => {
                if pos + 1 >= msg.len() {
                    return None;
                }
                name_end = Some(pos + 2);
                break;
            }
            0x40 | 0x80 => return None,
            _ => {}
        }
        if b == 0 {
            name_end = Some(pos + 1);
            break;
        }
        wire += 1 + usize::from(b);
        if wire > MAX_NAME_WIRE_LEN {
            return None;
        }
        pos += 1 + usize::from(b);
    }
    let pos = name_end?;
    let name_is_root = pos == start + 1 && msg[start] == 0;
    let rtype = u16_at(msg, pos)?;
    let rclass = u16_at(msg, pos + 2)?;
    let ttl = u32_at(msg, pos + 4)?;
    let rdlength = usize::from(u16_at(msg, pos + 8)?);
    let rdata_start = pos + 10;
    let rdata_end = rdata_start + rdlength;
    if rdata_end > msg.len() {
        return None;
    }
    Some(Rr {
        name_is_root,
        rtype,
        rclass,
        ttl,
        rdata: rdata_start..rdata_end,
        next: rdata_end,
    })
}

fn parse_opt(msg: &[u8], rr: &Rr) -> Option<Edns> {
    let mut option_codes = Vec::new();
    let mut pos = rr.rdata.start;
    while pos < rr.rdata.end {
        if pos + 4 > rr.rdata.end {
            return None;
        }
        let code = u16_at(msg, pos)?;
        let len = usize::from(u16_at(msg, pos + 2)?);
        let next = pos + 4 + len;
        if next > rr.rdata.end {
            return None;
        }
        // Option data is never stored: ECS carries a third party's subnet, COOKIE is opaque.
        if option_codes.len() < MAX_EDNS_OPTIONS {
            option_codes.push(code);
        }
        pos = next;
    }
    Some(Edns {
        version: (rr.ttl >> 16) as u8,
        udp_payload_size: rr.rclass,
        dnssec_ok: rr.ttl & 0x8000 != 0,
        extended_rcode: (rr.ttl >> 24) as u8,
        option_codes,
    })
}

/// Look for the OPT record among the first [`MAX_ADDITIONAL_WALK`] additional records, after
/// skipping the authority records `parse_query` admitted (none, or an IXFR request's SOA).
fn scan_edns(msg: &[u8], header: &Header, question_end: usize) -> EdnsScan {
    let mut pos = question_end;
    for _ in 0..header.nscount {
        match read_rr(msg, pos) {
            Some(rr) => pos = rr.next,
            None => return EdnsScan::Malformed,
        }
    }
    let mut found = None;
    for _ in 0..usize::from(header.arcount).min(MAX_ADDITIONAL_WALK) {
        let Some(rr) = read_rr(msg, pos) else {
            return EdnsScan::Malformed;
        };
        if rr.rtype == TYPE_OPT {
            // Two OPT records, or one not owned by the root, is RFC 6891's FORMERR case.
            if found.is_some() || !rr.name_is_root {
                return EdnsScan::Malformed;
            }
            match parse_opt(msg, &rr) {
                Some(edns) => found = Some(edns),
                None => return EdnsScan::Malformed,
            }
        }
        pos = rr.next;
    }
    found.map(EdnsScan::Present).unwrap_or(EdnsScan::Absent)
}

pub fn qtype_name(t: u16) -> Cow<'static, str> {
    let name = match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        52 => "TLSA",
        59 => "CDS",
        60 => "CDNSKEY",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        // RFC 3597 form for everything else.
        _ => return Cow::Owned(format!("TYPE{t}")),
    };
    Cow::Borrowed(name)
}

pub fn qclass_name(c: u16) -> Cow<'static, str> {
    let name = match c {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "ANY",
        _ => return Cow::Owned(format!("CLASS{c}")),
    };
    Cow::Borrowed(name)
}

pub fn opcode_name(o: u8) -> Cow<'static, str> {
    let name = match o {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        6 => "DSO",
        _ => return Cow::Owned(format!("OPCODE{o}")),
    };
    Cow::Borrowed(name)
}

/// The one reply this sensor sends: the query's header rewritten in place and its first question
/// copied verbatim, nothing appended. Its length is `question.end`, which is never more than
/// `msg.len()`, so a reply can never exceed the query it answers.
pub fn refused_reply(msg: &[u8], query: &Query) -> Vec<u8> {
    let end = query.question.end;
    let mut out = msg[..end].to_vec();
    let flags = FLAG_QR | (query.header.flags & (FLAG_RD | FLAG_CD)) | RCODE_REFUSED;
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out[6..12].fill(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, flags: u16, labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(id.to_be_bytes());
        m.extend(flags.to_be_bytes());
        m.extend(1u16.to_be_bytes());
        m.extend([0u8; 6]);
        for l in labels {
            m.push(l.len() as u8);
            m.extend_from_slice(l);
        }
        m.push(0);
        m.extend(qtype.to_be_bytes());
        m.extend(qclass.to_be_bytes());
        m
    }

    fn set_count(msg: &mut [u8], offset: usize, value: u16) {
        msg[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn bump_arcount(msg: &mut [u8]) {
        let n = u16::from_be_bytes([msg[10], msg[11]]) + 1;
        set_count(msg, 10, n);
    }

    /// An OPT RR with the given options (code, data) appended, ARCOUNT bumped.
    fn with_opt(
        mut msg: Vec<u8>,
        udp_size: u16,
        do_bit: bool,
        options: &[(u16, &[u8])],
    ) -> Vec<u8> {
        with_opt_ttl(&mut msg, udp_size, if do_bit { 0x8000 } else { 0 }, options);
        msg
    }

    fn with_opt_ttl(msg: &mut Vec<u8>, udp_size: u16, ttl: u32, options: &[(u16, &[u8])]) {
        let mut rdata = Vec::new();
        for (code, data) in options {
            rdata.extend(code.to_be_bytes());
            rdata.extend((data.len() as u16).to_be_bytes());
            rdata.extend_from_slice(data);
        }
        msg.push(0);
        msg.extend(TYPE_OPT.to_be_bytes());
        msg.extend(udp_size.to_be_bytes());
        msg.extend(ttl.to_be_bytes());
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
        bump_arcount(msg);
    }

    /// A root-owned A record with 4 bytes of RDATA, ARCOUNT bumped.
    fn with_dummy_a(msg: &mut Vec<u8>) {
        msg.push(0);
        msg.extend(1u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend(0u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([192, 0, 2, 1]);
        bump_arcount(msg);
    }

    fn reason(msg: &[u8], t: Transport) -> Rejected {
        parse_query(msg, t).expect_err("must reject")
    }

    fn example() -> Vec<u8> {
        query(0x1234, FLAG_RD, &[b"example", b"com"], 1, CLASS_IN)
    }

    #[test]
    fn parses_a_minimal_a_query() {
        let msg = example();
        let q = parse_query(&msg, Transport::Udp).unwrap();
        assert_eq!(
            q.header,
            Header {
                id: 0x1234,
                flags: FLAG_RD,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0
            }
        );
        assert_eq!(
            q.question,
            Question {
                qname: "example.com.".into(),
                label_count: 2,
                name_wire_len: 13,
                mixed_case: false,
                qtype: 1,
                qclass: CLASS_IN,
                end: msg.len(),
            }
        );
        assert_eq!(q.edns, EdnsScan::Absent);
    }

    #[test]
    fn header_bits_decode() {
        let h = |flags| Header {
            id: 0,
            flags,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert!(h(0x8000).qr() && !h(0x0000).qr());
        assert_eq!(h(0x2800).opcode(), 5);
        assert_eq!(h(0x7800).opcode(), 15);
        assert!(h(FLAG_RD).rd() && !h(FLAG_RD).ad() && !h(FLAG_RD).cd());
        assert!(h(FLAG_AD).ad() && !h(FLAG_AD).rd());
        assert!(h(FLAG_CD).cd() && !h(FLAG_CD).ad());
    }

    #[test]
    fn presentation_escapes_every_byte_class() {
        let label: &[u8] = b".\\ \x00\xff\x7fA";
        assert_eq!(presentation(&[label]), "\\.\\\\\\032\\000\\255\\127A.");
        assert_eq!(presentation(&[b"a", b"b"]), "a.b.");
        assert_eq!(presentation(&[]), ".");
        let root = query(1, 0, &[], 2, CLASS_IN);
        assert_eq!(
            parse_query(&root, Transport::Udp).unwrap().question.qname,
            "."
        );
    }

    #[test]
    fn mixed_case_detected_only_with_both_cases() {
        let mixed = |labels: &[&[u8]]| {
            parse_query(&query(1, 0, labels, 1, 1), Transport::Udp)
                .unwrap()
                .question
                .mixed_case
        };
        assert!(mixed(&[b"ExAmPlE", b"com"]));
        assert!(mixed(&[b"EXAMPLE", b"com"]));
        assert!(!mixed(&[b"example", b"com"]));
        assert!(!mixed(&[b"EXAMPLE", b"COM"]));
        assert!(!mixed(&[b"123", b"-_"]));
    }

    #[test]
    fn short_header() {
        let r = reason(&example()[..11], Transport::Udp);
        assert_eq!(r.reason, RejectReason::ShortHeader);
        assert!(r.header.is_none() && r.question.is_none());
    }

    #[test]
    fn response_inbound() {
        let r = reason(&query(1, FLAG_QR, &[b"a"], 1, 1), Transport::Udp);
        assert_eq!(r.reason, RejectReason::ResponseInbound);
        assert!(r.header.is_some() && r.question.is_none());
    }

    #[test]
    fn opcode() {
        for op in [4u16, 5] {
            let r = reason(&query(1, op << 11, &[b"a"], 6, 1), Transport::Tcp);
            assert_eq!(r.reason, RejectReason::Opcode, "opcode {op}");
            assert!(r.header.is_some() && r.question.is_none());
        }
    }

    #[test]
    fn qdcount() {
        for n in [0u16, 2] {
            let mut msg = example();
            set_count(&mut msg, 4, n);
            let r = reason(&msg, Transport::Udp);
            assert_eq!(r.reason, RejectReason::Qdcount, "qdcount {n}");
            assert!(r.header.is_some() && r.question.is_none());
        }
    }

    #[test]
    fn compression_pointer() {
        let mut msg = example();
        msg[12] = 0xC0;
        msg[13] = 0x0C;
        let r = reason(&msg, Transport::Udp);
        assert_eq!(r.reason, RejectReason::CompressionPointer);
        assert!(r.header.is_some() && r.question.is_none());
    }

    #[test]
    fn bad_label() {
        for b in [0x40u8, 0x80] {
            let mut msg = example();
            msg[12] = b | 0x07;
            let r = reason(&msg, Transport::Udp);
            assert_eq!(r.reason, RejectReason::BadLabel, "{b:#x}");
            assert!(r.header.is_some() && r.question.is_none());
        }
    }

    #[test]
    fn name_too_long() {
        let l = [b'a'; 63];
        let last = [b'b'; 62];
        // 64 * 3 + 63 + 1 = 256 wire bytes.
        let msg = query(1, 0, &[&l, &l, &l, &last], 1, 1);
        let r = reason(&msg, Transport::Udp);
        assert_eq!(r.reason, RejectReason::NameTooLong);
        assert!(r.header.is_some() && r.question.is_none());
    }

    #[test]
    fn name_of_exactly_255_is_accepted() {
        let l = [b'a'; 63];
        let last = [b'b'; 61];
        let msg = query(1, 0, &[&l, &l, &l, &last], 1, 1);
        let q = parse_query(&msg, Transport::Udp).unwrap();
        assert_eq!(q.question.name_wire_len, 255);
        assert_eq!(q.question.label_count, 4);
    }

    #[test]
    fn truncated_question() {
        let msg = example();
        // The name runs past the end; qtype has one byte; qclass has one byte.
        for cut in [16, msg.len() - 3, msg.len() - 1] {
            let r = reason(&msg[..cut], Transport::Udp);
            assert_eq!(r.reason, RejectReason::TruncatedQuestion, "cut {cut}");
            assert!(r.header.is_some() && r.question.is_none());
        }
    }

    #[test]
    fn answer_or_authority_present() {
        let mut an = example();
        set_count(&mut an, 6, 1);
        let mut ns = example();
        set_count(&mut ns, 8, 1);
        for msg in [an, ns] {
            let r = reason(&msg, Transport::Udp);
            assert_eq!(r.reason, RejectReason::AnswerOrAuthorityPresent);
            assert!(r.header.is_some() && r.question.is_some());
        }
    }

    fn with_soa_authority(mut msg: Vec<u8>) -> Vec<u8> {
        // Root-owned SOA with a 22-byte RDATA: two root names and five u32s.
        msg.push(0);
        msg.extend(6u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend(0u32.to_be_bytes());
        msg.extend(22u16.to_be_bytes());
        msg.extend([0, 0]);
        msg.extend([0u8; 20]);
        set_count(&mut msg, 8, 1);
        msg
    }

    #[test]
    fn ixfr_with_one_authority_rr_is_accepted_on_tcp_only() {
        let msg = with_opt(
            with_soa_authority(query(7, 0, &[b"example", b"com"], TYPE_IXFR, 1)),
            1232,
            false,
            &[],
        );
        let q = parse_query(&msg, Transport::Tcp).unwrap();
        assert_eq!(q.question.qtype, TYPE_IXFR);
        assert!(matches!(q.edns, EdnsScan::Present(ref e) if e.udp_payload_size == 1232));
        assert_eq!(
            reason(&msg, Transport::Udp).reason,
            RejectReason::AnswerOrAuthorityPresent
        );
    }

    #[test]
    fn axfr_with_authority_is_rejected_on_tcp() {
        let msg = with_soa_authority(query(7, 0, &[b"example", b"com"], TYPE_AXFR, 1));
        assert_eq!(
            reason(&msg, Transport::Tcp).reason,
            RejectReason::AnswerOrAuthorityPresent
        );
    }

    #[test]
    fn opt_fields_are_decoded() {
        let mut msg = example();
        // ext-rcode 1, version 0, DO set.
        with_opt_ttl(
            &mut msg,
            4096,
            0x0100_8000,
            &[(10, &[1; 8]), (8, &[0, 1, 24, 0, 192, 0, 2])],
        );
        let q = parse_query(&msg, Transport::Udp).unwrap();
        assert_eq!(
            q.edns,
            EdnsScan::Present(Edns {
                version: 0,
                udp_payload_size: 4096,
                dnssec_ok: true,
                extended_rcode: 1,
                option_codes: vec![10, 8],
            })
        );
        let mut v1 = example();
        with_opt_ttl(&mut v1, 512, 0x0001_0000, &[]);
        assert!(matches!(
            parse_query(&v1, Transport::Udp).unwrap().edns,
            EdnsScan::Present(Edns {
                version: 1,
                dnssec_ok: false,
                extended_rcode: 0,
                ..
            })
        ));
    }

    #[test]
    fn opt_with_non_root_name_is_malformed() {
        let mut msg = with_opt(example(), 4096, false, &[]);
        let at = example().len();
        msg[at] = 0xC0;
        msg.insert(at + 1, 0x0C);
        assert_eq!(
            parse_query(&msg, Transport::Udp).unwrap().edns,
            EdnsScan::Malformed
        );
    }

    #[test]
    fn two_opts_are_malformed() {
        let msg = with_opt(with_opt(example(), 4096, false, &[]), 512, false, &[]);
        assert_eq!(
            parse_query(&msg, Transport::Udp).unwrap().edns,
            EdnsScan::Malformed
        );
    }

    #[test]
    fn option_running_past_rdata_is_malformed() {
        let mut msg = with_opt(example(), 4096, false, &[(10, &[1, 2, 3, 4])]);
        // Declare the option 5 bytes long while RDATA holds 4.
        let len_at = msg.len() - 6;
        msg[len_at..len_at + 2].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(
            parse_query(&msg, Transport::Udp).unwrap().edns,
            EdnsScan::Malformed
        );
    }

    #[test]
    fn opt_beyond_the_eighth_additional_rr_is_not_seen() {
        let mut msg = example();
        for _ in 0..9 {
            with_dummy_a(&mut msg);
        }
        let msg = with_opt(msg, 4096, false, &[]);
        assert_eq!(
            parse_query(&msg, Transport::Udp).unwrap().edns,
            EdnsScan::Absent
        );
        let mut seen = example();
        for _ in 0..7 {
            with_dummy_a(&mut seen);
        }
        let seen = with_opt(seen, 4096, false, &[]);
        assert!(matches!(
            parse_query(&seen, Transport::Udp).unwrap().edns,
            EdnsScan::Present(_)
        ));
    }

    #[test]
    fn pointer_in_an_additional_name_is_skipped_not_followed() {
        let mut msg = example();
        // An A record owned by a pointer to offset 0 (the header): following it would misparse.
        msg.extend([0xC0, 0x00]);
        msg.extend(1u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend(0u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([192, 0, 2, 1]);
        bump_arcount(&mut msg);
        let msg = with_opt(msg, 1400, true, &[]);
        assert!(matches!(
            parse_query(&msg, Transport::Udp).unwrap().edns,
            EdnsScan::Present(Edns {
                udp_payload_size: 1400,
                dnssec_ok: true,
                ..
            })
        ));
    }

    #[test]
    fn option_codes_capped_at_16() {
        let options: Vec<(u16, &[u8])> = (0..20u16).map(|c| (c, &[][..])).collect();
        let msg = with_opt(example(), 4096, false, &options);
        match parse_query(&msg, Transport::Udp).unwrap().edns {
            EdnsScan::Present(e) => assert_eq!(e.option_codes, (0..16).collect::<Vec<u16>>()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn name_tables_cover_the_named_and_unknown_values() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(TYPE_AXFR), "AXFR");
        assert_eq!(qtype_name(TYPE_IXFR), "IXFR");
        assert_eq!(qtype_name(TYPE_ANY), "ANY");
        assert_eq!(qtype_name(TYPE_OPT), "OPT");
        assert_eq!(qtype_name(65280), "TYPE65280");
        assert_eq!(qclass_name(CLASS_IN), "IN");
        assert_eq!(qclass_name(CLASS_CH), "CH");
        assert_eq!(qclass_name(9), "CLASS9");
        assert_eq!(opcode_name(0), "QUERY");
        assert_eq!(opcode_name(4), "NOTIFY");
        assert_eq!(opcode_name(15), "OPCODE15");
    }

    #[test]
    fn refused_reply_is_header_rewrite_plus_question() {
        for (flags, want) in [
            (FLAG_RD, 0x8105u16),
            (FLAG_RD | FLAG_CD, 0x8115),
            (0, 0x8005),
        ] {
            let base = query(0xBEEF, flags | FLAG_AD, &[b"example", b"com"], 1, CLASS_IN);
            let end = base.len();
            let mut msg = with_opt(base, 4096, true, &[(10, &[9; 8])]);
            msg.extend_from_slice(b"trailing junk");
            let q = parse_query(&msg, Transport::Udp).unwrap();
            let reply = refused_reply(&msg, &q);
            assert_eq!(&reply[0..2], &0xBEEFu16.to_be_bytes());
            assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), want);
            assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(&reply[12..], &msg[12..end]);
            assert!(reply.len() < msg.len());
        }
    }

    /// The xorshift generator `sensor-tftp`'s `malformed_frame_fuzz_never_panics` uses.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    const TABLE_TYPES: [u16; 33] = [
        1, 2, 5, 6, 10, 11, 12, 13, 15, 16, 28, 33, 35, 41, 43, 46, 47, 48, 50, 52, 59, 60, 63, 64,
        65, 99, 251, 252, 253, 254, 255, 256, 257,
    ];

    /// A valid query: 1-6 labels of 1-20 random bytes (name <= 255 wire bytes), a qtype half from
    /// the name table and half uniform, a random class, random RD/CD/AD, an optional OPT with
    /// 0-3 options, then 0-32 bytes of trailing junk. Returns the message and its label count.
    fn generated_query(rng: &mut Rng) -> (Vec<u8>, usize) {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut wire = 1;
        for _ in 0..1 + rng.below(6) {
            let len = 1 + rng.below(20) as usize;
            if wire + 1 + len > MAX_NAME_WIRE_LEN {
                break;
            }
            wire += 1 + len;
            labels.push((0..len).map(|_| rng.next() as u8).collect());
        }
        let qtype = if rng.below(2) == 0 {
            TABLE_TYPES[rng.below(TABLE_TYPES.len() as u64) as usize]
        } else {
            rng.next() as u16
        };
        let flag_bits = [FLAG_RD, FLAG_CD, FLAG_AD];
        let flags = flag_bits
            .iter()
            .filter(|_| rng.below(2) == 0)
            .fold(0, |f, b| f | b);
        let refs: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();
        let mut msg = query(rng.next() as u16, flags, &refs, qtype, rng.next() as u16);
        if rng.below(2) == 0 {
            let data: Vec<Vec<u8>> = (0..rng.below(4))
                .map(|_| (0..rng.below(12)).map(|_| rng.next() as u8).collect())
                .collect();
            let options: Vec<(u16, &[u8])> = data
                .iter()
                .map(|d| (rng.next() as u16, d.as_slice()))
                .collect();
            let size = rng.next() as u16;
            let do_bit = rng.below(2) == 0;
            msg = with_opt(msg, size, do_bit, &options);
        }
        for _ in 0..rng.below(33) {
            msg.push(rng.next() as u8);
        }
        (msg, refs.len())
    }

    #[test]
    fn reply_never_exceeds_query_property() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..400 {
            let (msg, labels) = generated_query(&mut rng);
            let q = parse_query(&msg, Transport::Udp).expect("generated query must parse");
            let reply = refused_reply(&msg, &q);
            let end = q.question.end;
            assert_eq!(reply.len(), end);
            assert!(reply.len() <= msg.len());
            assert_eq!(&reply[12..], &msg[12..end]);
            let want = FLAG_QR | (q.header.flags & (FLAG_RD | FLAG_CD)) | RCODE_REFUSED;
            assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), want);
            assert_eq!(q.question.label_count, labels);
        }
    }

    #[test]
    fn malformed_message_fuzz_never_panics() {
        let version_bind = query(3, 0, &[b"version", b"bind"], TYPE_TXT, CLASS_CH);
        let mut junk = example();
        junk.extend_from_slice(&[0xC0, 0xFF, 0x3F, 0x00, 0x29]);
        let seeds = vec![
            example(),
            with_opt(example(), 4096, true, &[(10, &[1; 8])]),
            with_soa_authority(query(7, 0, &[b"example", b"com"], TYPE_IXFR, 1)),
            version_bind,
            query(9, 0, &[b"example", b"com"], TYPE_AXFR, 1),
            junk,
        ];
        let mut checked = 0usize;
        let mut check = |msg: &[u8]| {
            for t in [Transport::Udp, Transport::Tcp] {
                if let Ok(q) = parse_query(msg, t) {
                    assert!(refused_reply(msg, &q).len() <= msg.len());
                }
            }
            checked += 1;
        };
        for seed in &seeds {
            for end in 0..=seed.len() {
                check(&seed[..end]);
            }
        }
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for i in 0..400 {
            let len = rng.below(601) as usize;
            let mut msg: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if i % 2 == 0 && msg.len() >= HEADER_LEN {
                msg[2..6].copy_from_slice(&[0, 0, 0, 1]);
            }
            check(&msg);
        }
        assert!(checked > 400, "{checked}");
    }
}
