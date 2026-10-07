//! Event records for the DNS sensor: one per query (UDP, TCP or DoT), one per TCP/DoT connection.
//!
//! UDP query events are `honeypot_connection` over `udp`: a UDP source is forgeable, so the
//! lower-weight signal is used, as `sensor-tftp` does. TCP and DoT query events are
//! `honeypot_command_exec` over `tcp` with a `command` field: the handshake proves the source and
//! each query is a protocol command. Derived probe classifications are metadata
//! (`probe_signals`), never a `signal_type`. Nothing here performs I/O.

use std::net::IpAddr;

use chrono::Utc;
use sensor_framework::{Uuid, sanitize_value};
use sensor_wire::{
    PROTO_TCP, PROTO_UDP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent,
    WIRE_VERSION,
};
use serde_json::{Map, Value, json};

use crate::guarded::SuppressReason;
use crate::protocol::{
    CLASS_CH, CLASS_IN, EdnsScan, Header, Question, RejectReason, TYPE_ANY, TYPE_AXFR, TYPE_DNSKEY,
    TYPE_IXFR, TYPE_RRSIG, TYPE_TXT, Transport, opcode_name, qclass_name, qtype_name,
};

pub const PROTOCOL_LABEL: &str = "dns";
/// 255 wire bytes escape to at most four characters each.
pub const MAX_QNAME_TEXT_LEN: usize = 1024;

const SENSOR: &str = "dns";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStatus {
    /// The reply was handed to the socket.
    Answered,
    Rejected(RejectReason),
    /// UDP only: the reply gate refused to send.
    Suppressed(SuppressReason),
}

/// Everything one query event records.
#[derive(Debug, Clone, Copy)]
pub struct QueryRecord<'a> {
    pub transport: Transport,
    pub tls: bool,
    pub status: QueryStatus,
    /// TCP: the message bytes, excluding the length prefix; 0 when the body was not read.
    pub query_len: usize,
    /// TCP `short_header` / `oversize` only.
    pub declared_len: Option<usize>,
    /// TCP/DoT only, 0-based within the connection.
    pub msg_index: Option<usize>,
    pub header: Option<&'a Header>,
    pub question: Option<&'a Question>,
    pub edns: Option<&'a EdnsScan>,
    /// `Answered` only.
    pub reply_len: Option<usize>,
}

/// Probe classifications derived from the parsed query, in a fixed order, each at most once.
pub fn probe_signals(
    header: &Header,
    q: &Question,
    edns: Option<&EdnsScan>,
    transport: Transport,
) -> Vec<&'static str> {
    let large_edns = matches!(edns, Some(EdnsScan::Present(e)) if e.udp_payload_size > 512);
    let transfer = q.qtype == TYPE_AXFR || q.qtype == TYPE_IXFR;
    let mut out = Vec::new();
    if transport == Transport::Udp
        && (q.qtype == TYPE_ANY
            || ([TYPE_TXT, TYPE_DNSKEY, TYPE_RRSIG].contains(&q.qtype) && large_edns))
    {
        out.push("amplification_probe");
    }
    if header.rd() && q.qclass == CLASS_IN && !transfer {
        out.push("open_resolver_probe");
    }
    if transfer {
        out.push("zone_transfer_probe");
    }
    if q.qclass == CLASS_CH {
        out.push("chaos_fingerprint_probe");
    }
    out
}

fn sanitized_qname(q: &Question) -> String {
    sanitize_value(&q.qname, MAX_QNAME_TEXT_LEN)
}

pub fn query_metadata(r: &QueryRecord) -> Value {
    let mut m = Map::new();
    m.insert("protocol_label".into(), json!(PROTOCOL_LABEL));
    m.insert("transport".into(), json!(r.transport.label()));
    let status = match r.status {
        QueryStatus::Answered => "answered",
        QueryStatus::Rejected(reason) => {
            m.insert("reject_reason".into(), json!(reason.as_str()));
            "rejected"
        }
        QueryStatus::Suppressed(reason) => {
            m.insert("suppress_reason".into(), json!(reason.as_str()));
            "suppressed"
        }
    };
    m.insert("query_status".into(), json!(status));
    m.insert("query_len".into(), json!(r.query_len as u64));
    if let Some(len) = r.declared_len {
        m.insert("declared_len".into(), json!(len as u64));
    }
    if let Some(index) = r.msg_index {
        m.insert("msg_index".into(), json!(index as u64));
    }
    if let Some(h) = r.header {
        m.insert("dns_id".into(), json!(h.id));
        m.insert("flags_raw".into(), json!(h.flags));
        m.insert("qdcount".into(), json!(h.qdcount));
        m.insert("ancount".into(), json!(h.ancount));
        m.insert("nscount".into(), json!(h.nscount));
        m.insert("arcount".into(), json!(h.arcount));
        m.insert("opcode".into(), json!(h.opcode()));
        m.insert("opcode_name".into(), json!(opcode_name(h.opcode())));
        m.insert("rd".into(), json!(h.rd()));
        m.insert("ad".into(), json!(h.ad()));
        m.insert("cd".into(), json!(h.cd()));
    }
    if let Some(q) = r.question {
        m.insert("qname".into(), json!(sanitized_qname(q)));
        m.insert("qname_mixed_case".into(), json!(q.mixed_case));
        m.insert("qname_labels".into(), json!(q.label_count as u64));
        m.insert("qname_wire_len".into(), json!(q.name_wire_len as u64));
        m.insert("qtype".into(), json!(q.qtype));
        m.insert("qtype_name".into(), json!(qtype_name(q.qtype)));
        m.insert("qclass".into(), json!(q.qclass));
        m.insert("qclass_name".into(), json!(qclass_name(q.qclass)));
        if let Some(h) = r.header {
            m.insert(
                "probe_signals".into(),
                json!(probe_signals(h, q, r.edns, r.transport)),
            );
        }
    }
    match r.edns {
        Some(EdnsScan::Present(e)) => {
            m.insert(
                "edns".into(),
                json!({
                    "version": e.version,
                    "udp_payload_size": e.udp_payload_size,
                    "do": e.dnssec_ok,
                    "extended_rcode": e.extended_rcode,
                    "option_codes": e.option_codes,
                }),
            );
        }
        Some(EdnsScan::Malformed) => {
            m.insert("edns_malformed".into(), json!(true));
        }
        Some(EdnsScan::Absent) | None => {}
    }
    if r.status == QueryStatus::Answered {
        m.insert("rcode".into(), json!("REFUSED"));
        if let Some(len) = r.reply_len {
            m.insert("reply_len".into(), json!(len as u64));
        }
    }
    let mut metadata = Value::Object(m);
    stamp_tls(&mut metadata, r.tls);
    metadata
}

fn event(
    signal_type: &str,
    protocol: &str,
    metadata: Value,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: SENSOR.into(),
        signal_type: signal_type.into(),
        protocol: protocol.into(),
        authenticated: false,
        observed_at: Utc::now(),
        metadata,
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

pub fn udp_query_event(
    r: &QueryRecord,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
) -> SensorEvent {
    event(
        SIGNAL_HONEYPOT_CONNECTION,
        PROTO_UDP,
        query_metadata(r),
        source_ip,
        wan_ip,
        session_id,
    )
}

pub fn stream_query_event(
    r: &QueryRecord,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
) -> SensorEvent {
    let mut metadata = query_metadata(r);
    let command = match r.question {
        Some(q) => format!("{} {}", qtype_name(q.qtype), sanitized_qname(q)),
        None => "malformed".to_string(),
    };
    metadata["command"] = json!(command);
    event(
        SIGNAL_HONEYPOT_COMMAND_EXEC,
        PROTO_TCP,
        metadata,
        source_ip,
        wan_ip,
        session_id,
    )
}

pub fn connection_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    tls: bool,
) -> SensorEvent {
    let mut metadata = json!({
        "protocol_label": PROTOCOL_LABEL,
        "transport": Transport::Tcp.label(),
    });
    stamp_tls(&mut metadata, tls);
    event(
        SIGNAL_HONEYPOT_CONNECTION,
        PROTO_TCP,
        metadata,
        source_ip,
        wan_ip,
        session_id,
    )
}

/// Sets `"tls": true` only for a DoT event; a plaintext event carries no `tls` key at all.
pub fn stamp_tls(metadata: &mut Value, tls: bool) {
    if tls {
        metadata["tls"] = json!(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Edns, FLAG_RD, Query, parse_query};

    fn query(flags: u16, labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend(flags.to_be_bytes());
        m.extend([0, 1, 0, 0, 0, 0, 0, 0]);
        for l in labels {
            m.push(l.len() as u8);
            m.extend_from_slice(l);
        }
        m.push(0);
        m.extend(qtype.to_be_bytes());
        m.extend(qclass.to_be_bytes());
        m
    }

    fn parsed(flags: u16, labels: &[&[u8]], qtype: u16, qclass: u16) -> Query {
        parse_query(&query(flags, labels, qtype, qclass), Transport::Tcp).unwrap()
    }

    fn edns(size: u16) -> EdnsScan {
        EdnsScan::Present(Edns {
            version: 0,
            udp_payload_size: size,
            dnssec_ok: false,
            extended_rcode: 0,
            option_codes: vec![],
        })
    }

    fn signals(q: &Query, edns: Option<&EdnsScan>, t: Transport) -> Vec<&'static str> {
        probe_signals(&q.header, &q.question, edns, t)
    }

    #[test]
    fn probe_signals_cover_each_rule_and_its_negative() {
        let any = parsed(0, &[b"example", b"com"], TYPE_ANY, CLASS_IN);
        assert_eq!(
            signals(&any, None, Transport::Udp),
            vec!["amplification_probe"]
        );
        assert!(signals(&any, None, Transport::Tcp).is_empty());

        let txt = parsed(0, &[b"example", b"com"], TYPE_TXT, CLASS_IN);
        assert_eq!(
            signals(&txt, Some(&edns(4096)), Transport::Udp),
            vec!["amplification_probe"]
        );
        assert!(signals(&txt, Some(&edns(512)), Transport::Udp).is_empty());
        assert!(signals(&txt, None, Transport::Udp).is_empty());

        let rd_a = parsed(FLAG_RD, &[b"example", b"com"], 1, CLASS_IN);
        assert_eq!(
            signals(&rd_a, None, Transport::Udp),
            vec!["open_resolver_probe"]
        );
        let a = parsed(0, &[b"example", b"com"], 1, CLASS_IN);
        assert!(signals(&a, None, Transport::Udp).is_empty());

        let rd_axfr = parsed(FLAG_RD, &[b"example", b"com"], TYPE_AXFR, CLASS_IN);
        assert_eq!(
            signals(&rd_axfr, None, Transport::Tcp),
            vec!["zone_transfer_probe"]
        );
        let ixfr = parsed(0, &[b"example", b"com"], TYPE_IXFR, CLASS_IN);
        assert_eq!(
            signals(&ixfr, None, Transport::Tcp),
            vec!["zone_transfer_probe"]
        );

        let chaos = parsed(FLAG_RD, &[b"version", b"bind"], TYPE_TXT, CLASS_CH);
        assert_eq!(
            signals(&chaos, None, Transport::Udp),
            vec!["chaos_fingerprint_probe"]
        );

        // Fixed order when several rules fire.
        let rd_any = parsed(FLAG_RD, &[b"example", b"com"], TYPE_ANY, CLASS_IN);
        assert_eq!(
            signals(&rd_any, None, Transport::Udp),
            vec!["amplification_probe", "open_resolver_probe"]
        );
        let ch_any = parsed(0, &[b"x"], TYPE_ANY, CLASS_CH);
        assert_eq!(
            signals(&ch_any, None, Transport::Udp),
            vec!["amplification_probe", "chaos_fingerprint_probe"]
        );
    }

    fn answered<'a>(q: &'a Query, transport: Transport, tls: bool) -> QueryRecord<'a> {
        QueryRecord {
            transport,
            tls,
            status: QueryStatus::Answered,
            query_len: 29,
            declared_len: None,
            msg_index: (transport == Transport::Tcp).then_some(2),
            header: Some(&q.header),
            question: Some(&q.question),
            edns: Some(&q.edns),
            reply_len: Some(q.question.end),
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[test]
    fn udp_query_event_shape() {
        let q = parsed(FLAG_RD, &[b"example", b"com"], 1, CLASS_IN);
        let e = udp_query_event(
            &answered(&q, Transport::Udp, false),
            ip(),
            None,
            Uuid::now_v7(),
        );
        assert_eq!(e.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(e.protocol, PROTO_UDP);
        assert_eq!(e.sensor, "dns");
        assert!(!e.authenticated);
        assert!(e.session_id.is_some() && e.sample.is_none());
        let md = e.metadata.as_object().unwrap();
        let mut keys: Vec<&str> = md.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "protocol_label",
            "transport",
            "query_status",
            "query_len",
            "dns_id",
            "flags_raw",
            "qdcount",
            "ancount",
            "nscount",
            "arcount",
            "opcode",
            "opcode_name",
            "rd",
            "ad",
            "cd",
            "qname",
            "qname_mixed_case",
            "qname_labels",
            "qname_wire_len",
            "qtype",
            "qtype_name",
            "qclass",
            "qclass_name",
            "probe_signals",
            "rcode",
            "reply_len",
        ];
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(md["transport"], "udp");
        assert_eq!(md["query_status"], "answered");
        assert_eq!(md["qname"], "example.com.");
        assert_eq!(md["qtype_name"], "A");
        assert_eq!(md["opcode_name"], "QUERY");
        assert_eq!(md["rcode"], "REFUSED");
        assert_eq!(md["reply_len"], q.question.end as u64);
        assert_eq!(md["dns_id"], 0x1234);
        assert_eq!(md["probe_signals"], json!(["open_resolver_probe"]));
    }

    #[test]
    fn stream_query_event_shape() {
        let q = parsed(0, &[b"example", b"com"], TYPE_AXFR, CLASS_IN);
        let e = stream_query_event(
            &answered(&q, Transport::Tcp, false),
            ip(),
            None,
            Uuid::now_v7(),
        );
        assert_eq!(e.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(e.protocol, PROTO_TCP);
        assert_eq!(e.metadata["command"], "AXFR example.com.");
        assert_eq!(e.metadata["msg_index"], 2);
        assert_eq!(e.metadata["transport"], "tcp");
        assert_eq!(e.metadata["probe_signals"], json!(["zone_transfer_probe"]));
    }

    #[test]
    fn rejected_event_without_question_has_no_question_keys_and_command_malformed() {
        let r = QueryRecord {
            transport: Transport::Tcp,
            tls: false,
            status: QueryStatus::Rejected(RejectReason::Oversize),
            query_len: 0,
            declared_len: Some(4097),
            msg_index: Some(0),
            header: None,
            question: None,
            edns: None,
            reply_len: None,
        };
        let e = stream_query_event(&r, ip(), None, Uuid::now_v7());
        let md = e.metadata.as_object().unwrap();
        assert_eq!(md["query_status"], "rejected");
        assert_eq!(md["reject_reason"], "oversize");
        assert_eq!(md["declared_len"], 4097);
        assert_eq!(md["command"], "malformed");
        for absent in [
            "qname",
            "qtype",
            "qclass",
            "probe_signals",
            "dns_id",
            "rcode",
            "reply_len",
            "edns",
        ] {
            assert!(!md.contains_key(absent), "{absent} present: {md:?}");
        }
    }

    #[test]
    fn tls_is_stamped_only_when_tls() {
        let q = parsed(0, &[b"example", b"com"], 1, CLASS_IN);
        let plain = stream_query_event(
            &answered(&q, Transport::Tcp, false),
            ip(),
            None,
            Uuid::now_v7(),
        );
        let dot = stream_query_event(
            &answered(&q, Transport::Tcp, true),
            ip(),
            None,
            Uuid::now_v7(),
        );
        assert!(plain.metadata.get("tls").is_none());
        assert_eq!(dot.metadata["tls"], true);
        let c_plain = connection_event(ip(), None, Uuid::now_v7(), false);
        let c_dot = connection_event(ip(), None, Uuid::now_v7(), true);
        assert!(c_plain.metadata.get("tls").is_none());
        assert_eq!(c_dot.metadata["tls"], true);
        assert_eq!(c_plain.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(c_plain.protocol, PROTO_TCP);
    }

    #[test]
    fn qname_is_sanitized_and_bounded() {
        let l = [0xFFu8; 63];
        let last = [0xFFu8; 61];
        let q = parsed(0, &[&l, &l, &l, &last], 1, CLASS_IN);
        assert_eq!(q.question.name_wire_len, 255);
        let e = udp_query_event(
            &answered(&q, Transport::Udp, false),
            ip(),
            None,
            Uuid::now_v7(),
        );
        let qname = e.metadata["qname"].as_str().unwrap();
        assert!(qname.len() <= MAX_QNAME_TEXT_LEN, "{}", qname.len());
        assert!(qname.starts_with("\\255\\255"));
        assert!(qname.chars().all(|c| c.is_ascii_graphic()));
    }
}
