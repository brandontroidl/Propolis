use chrono::{DateTime, Utc};

use crate::FeedEntry;

use super::format_timestamp;

pub fn export_ipset(tier_name: &str, entries: &[FeedEntry]) -> String {
    let set_name = format!("propolis_{tier_name}");
    let mut out = format!(
        "create {set_name} hash:ip family inet hashsize 4096 maxelem {}\n",
        entries.len().max(1024)
    );
    for entry in entries {
        out.push_str(&format!("add {set_name} {}\n", entry.source_ip));
    }
    out
}

pub fn export_nftables(tier_name: &str, entries: &[FeedEntry]) -> String {
    let set_name = format!("propolis_{tier_name}");
    let mut out = format!(
        "define {set_name} = {{\n"
    );
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!("    {}", entry.source_ip));
    }
    out.push_str("\n}\n");
    out
}

pub fn export_pf(tier_name: &str, generated: DateTime<Utc>, entries: &[FeedEntry]) -> String {
    let mut out = format!(
        "# Propolis blocklist - {} tier\n# Generated: {}\n",
        tier_name,
        format_timestamp(generated),
    );
    for entry in entries {
        out.push_str(&entry.source_ip.to_string());
        out.push('\n');
    }
    out
}

pub fn export_pfsense_alias(_tier_name: &str, entries: &[FeedEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&entry.source_ip.to_string());
        out.push('\n');
    }
    out
}

pub fn export_hosts(entries: &[FeedEntry]) -> String {
    let mut out = String::from("# Propolis blocklist - reverse DNS sinkhole\n");
    for entry in entries {
        let ip = entry.source_ip;
        let reversed = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
            }
            std::net::IpAddr::V6(_) => continue,
        };
        out.push_str(&format!("0.0.0.0 {reversed}\n"));
    }
    out
}

pub fn export_rpz(tier_name: &str, generated: DateTime<Utc>, entries: &[FeedEntry]) -> String {
    let mut out = format!(
        "; Propolis RPZ - {} tier\n; Generated: {}\n$TTL 300\n",
        tier_name,
        format_timestamp(generated),
    );
    for entry in entries {
        let ip = entry.source_ip;
        let reversed = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
            }
            std::net::IpAddr::V6(_) => continue,
        };
        out.push_str(&format!("{reversed}.rpz-ip CNAME .\n"));
    }
    out
}
