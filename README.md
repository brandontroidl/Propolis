# Propolis

Self-hosted honeypot and threat-intelligence platform. Native sensors score attackers across your WAN IPs, so an IP that hits more of them weighs more. Only on operator approval are confirmed-real sources reported to abuse vendors and published as a firewall blocklist.

## What it does

- Runs your own honeypot sensors and scores every source IP that touches them.
- Aggregates an attacker's activity across every WAN IP it hits. A source that sweeps many of your addresses weighs more than one that pokes a single address.
- Holds every candidate behind an operator review queue. Nothing reaches a vendor or the feed without explicit approval.
- Reports only confirmed-real sources. An IP becomes reportable only after a completed TCP handshake proves the source address is genuine, never on spoofable UDP or a lone SYN.
- Publishes a conservative firewall blocklist that avoids blocking an attacker's uninvolved neighbors.
- Drops passwords and payloads at capture, and keeps your own WAN addresses off every external surface.

## Design

- Rust, PostgreSQL, event-sourced. Evidence is an append-only, hash-chained ledger, and every score is reproducible by replaying it.
- Passive only. Sensors observe and record; they never respond to or probe an attacker.
- Runs as a single node, or as a cluster of collectors that feed one shared score.

## Status

In active development. Not yet released. Interfaces, schema, and behavior are unstable and will change.

## License

Source-available under the PolyForm Noncommercial License 1.0.0: free for personal, home-lab, research, educational, and nonprofit or government use. Commercial use requires a separate license. See [LICENSE.md](LICENSE.md).
