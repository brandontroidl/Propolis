# Security, Privacy, and Compliance Posture

This document states the security, privacy, and legal posture of Propolis-new: a single-operator defensive honeypot and threat-intelligence platform. It describes the controls the platform implements and the design constraints that produce them. It also names, explicitly, the points where an operator needs legal sign-off for their own jurisdiction. It does not assert legal compliance. It describes controls and where sign-off is required.

Propolis-new is a clean-room Rust rebuild. It is event-sourced over a single canonical PostgreSQL store. The behavior described here is a set of decisions for the new system, justified on the new system's goals. It is not a port of the old system's posture.

## 1. Passive-only sensors

Sensors observe and record. They never respond to an attacker, never probe back, and never engage a source in any way. There is no active response and no hack-back path anywhere in the platform. A sensor accepts a connection or a packet, captures a bounded record of what arrived, and appends it to the local log. It emits nothing back to the source beyond what the transport itself requires to establish the connection.

The reason is legal exposure, not only good manners. Active response against a remote host - scanning it, connecting back to it, attempting to disrupt it - can constitute unauthorized access under anti-hacking law regardless of the fact that the host attacked first. Passive observation of traffic that arrives at the operator's own infrastructure sits on far firmer legal ground. The platform stays entirely on the passive side of that line by construction: there is no code path that originates outbound traffic to an attacker, and the only outbound actions the platform takes at all are operator-approved abuse reports to reputation vendors and the published blocklist feed, both of which are covered separately below.

UDP sensors never answer. A UDP listener that replies can be abused as a reflection and amplification vector against a spoofed victim. Propolis-new UDP sensors log the arriving datagram and send nothing, so a sensor can never be turned into an amplifier.

## 2. Sensor isolation

Sensors are the platform's internet-facing attack surface, so they hold the least authority of any component. Each sensor:

- Runs unprivileged, under its own dedicated OS user, never root.
- Holds no database handle. A sensor cannot read or write the canonical store. It appends to a local append-only log, and a separate privileged component ingests that log one-directionally.
- Holds no secrets. No vendor API keys, no database credentials, no push tokens, no session secrets reach a sensor process.
- Holds minimal kernel capabilities. A sensor that must bind privileged ports carries only the single capability required for that (bind-service), granted through the service manager, never through root. It carries nothing else.

The log flow is strictly one-directional: sensors have write access to the shared sensor-log location; the ingest component has read-only access to it. This is enforced by filesystem permissions and service-manager mount controls, not by convention.

The consequence is the threat model this design buys: compromise of an internet-facing sensor process yields no credentials, no database access, and no ability to write the canonical store or influence scoring directly. The blast radius of a sensor compromise is the sensor host's log directory and the sensor's own minimal privileges, nothing more.

Native sensors are attack surface in their own right and must be safe by construction. A native honeypot must never execute attacker-supplied commands for real, must run unprivileged, and must carry the same no-database, no-secrets, minimal-capability isolation as every other sensor. Sensor service definitions must carry full service-manager hardening (no-new-privileges, a read-only system view, a single minimal capability). A weakly-hardened or unhardened sensor unit is a defect.

## 3. PII discipline

The platform drops the most sensitive attacker-supplied content at the earliest possible point and keeps operator infrastructure identifiers off every external surface.

Passwords and payloads are dropped at the sensor, at capture time. A sensor never persists a captured password and never persists a full payload body. Where a credential must be read to parse a record, it is read and discarded in the same step and never written to the log. This means the sensitive content never enters the event ledger, never reaches the datastore, and therefore cannot leak from any later stage, because it does not exist past capture.

The WAN IP that a hit arrived on is surfaced to the operator only. Per-hit WAN attribution - which of the operator's WAN IPs an attacker touched - is internal signal. It drives cross-sensor breadth scoring and is shown in the operator console. It is never sent to a reputation vendor and never written to the published feed. The operator's own infrastructure addresses are not disclosed to third parties by this platform.

The distinction to hold: the attacker's source IP is the reportable subject and does travel outward on operator approval. The operator's destination WAN IPs are collateral infrastructure identifiers and stay on the platform.

## 4. Data protection

Attacker source IP addresses are personal data. An IP address that can be linked to a person, including with the aid of a third party such as an ISP, is personal data under prevailing data-protection interpretation. Propolis-new treats every source IP it processes as personal data and applies data-protection controls accordingly. The operator is the data controller for this processing.

**Lawful basis.** The processing basis is legitimate interest: operating and defending a network against attack. Network and information security is a recognized legitimate-interest purpose. The operator must record this basis and the balancing assessment that supports it before relying on it.

**Required artifacts.** Legitimate-interest processing of this kind requires the operator to prepare and maintain:

- A Data Protection Impact Assessment (DPIA) covering the honeypot collection, the scoring, the vendor reporting, and the public feed. The DPIA must resolve whether publishing a blocklist of attacker IPs constitutes processing of criminal-offence or alleged-offence data, which carries stricter conditions. This question is open and must be answered for the operator's jurisdiction before publishing.
- A Record of Processing Activities (RoPA) describing the categories of data, the purposes, the recipients (reputation vendors, the public feed), retention, and safeguards.
- A documented legitimate-interest balancing assessment.

These are the operator's artifacts to author and ratify. The platform provides the technical controls (minimization, retention, erasure) that the artifacts rely on. It does not author or ratify them.

**Data minimization.** The platform stores the minimum needed to score and corroborate an attacker. It does not store passwords or payloads (dropped at the sensor). It does not export attack content. Firewall-format feeds carry IP or CIDR only. Machine-readable feeds add only derived metadata (score, first-seen and last-seen, event count, tier, expiry) and never attack content, never geolocation, never WHOIS or ASN enrichment. Operator destination addresses never leave the host.

**Storage limitation.** Data is retained only as long as it serves the security purpose, then purged on a retention clock (see Section 6). Retention windows are operator-set and must be justified in the DPIA and RoPA; the values in this platform are recommended defaults and are tunable, not legal minimums.

**Delist and erasure path.** The platform provides operator-driven data-subject-rights mechanisms:

- Export of everything held about one IP (supports a subject access request).
- Suppression / delist of an IP, which is idempotent and reaches the feed on the next scheduled rebuild.
- Erasure of an IP, which deletes its events, score, review, feed, and dedup rows and inserts a fresh suppression record so the address is not re-listed. The immutable audit record of platform actions is deliberately retained as the lawful record of what was done and when; erasure removes the subject's data, not the platform's account of its own decisions.

Delist and erasure write the datastore only. Suppression reaches the published feed on the next scheduled build or a manual publish. There is no per-entry live revocation of an already-published feed file; the revocation latency is bounded by the feed rebuild interval, which is an operator-set and tunable value.

**Publishing the feed is publishing personal data.** A public blocklist is a public disclosure of personal data (attacker IPs). Under the transparency rules, a data subject would normally be notified that their data is being processed. Direct notification of every scanned attacker is impossible and disproportionate. The operator therefore relies on the disproportionate-effort exception, which requires a documented substitute measure: a public processing notice. The feed's published policy document serves as that notice and must state the controller, the purpose, the lawful basis, the retention, and the delist process. A working delist process is a condition of relying on this exception, not an optional add-on.

## 5. Interception posture

Capturing connections and packets that arrive at the operator's own sensors is generally lawful: the operator is a party to, or the intended recipient of, traffic directed at their own infrastructure, and honeypot addresses exist to receive it. This is materially different from intercepting third-party communications in transit, which is not what the platform does.

Even so, the platform minimizes content capture:

- Keep metadata and attempted credentials, not full transcripts. The platform records that a login was attempted and the username offered as an attack indicator; it does not retain the password and does not retain a full session transcript.
- Payload capture is bounded. Where a sensor captures any payload bytes at all, it captures a bounded, truncated sample sufficient to classify the probe, not the full body, and never a password field.
- Prefer metadata over content everywhere the detection goal allows it.

Interception law varies significantly by jurisdiction, and the "party to the communication" and "own-infrastructure" positions are not uniform across legal systems. The specific rules that apply to capturing honeypot traffic, and the content-capture minimization that keeps the operator inside them, need legal sign-off for the operator's locale. This document states the platform's minimization posture; it does not determine that the posture is lawful in any given jurisdiction.

## 6. Evidence integrity

Every scoring decision must be reconstructible and tamper-evident.

**Append-only hash-chained event ledger.** Evidence is an append-only ledger of events, hash-chained so that each event commits to its predecessor. Altering or removing a past event breaks the chain and is detectable. Events are never mutated in place. The event-sourced design means the ledger is the source of truth and derived state (an IP's score, tier, and decision) is a projection of it.

**Reproducible scoring.** Each IP's score and each reportability and tier decision are reproducible by replaying that IP's events through the same scoring rules. There is no hidden mutable state that a decision depends on outside the ledger, so an operator (or a reviewer of a disputed report) can re-derive exactly why an IP reached the score and recommendation it did.

**Audit trail.** Operator actions - approvals, rejections, delists, erasures, reports filed - are recorded in an audit trail. As noted in Section 4, the audit trail is retained through subject erasure as the lawful record of platform actions.

**Retention clock.** All retained data runs on a retention clock and is purged when its window elapses, enforcing storage limitation. Recommended default windows, all tunable and all subject to justification in the DPIA and RoPA: attacker events on the order of months, derived scores somewhat longer than events so a score never outlives the events that justify it, audit records on a comparable multi-month horizon, and feed entries on shorter per-tier expiries anchored on last-seen. These are recommended starting values, not fixed constants and not legal thresholds; the operative constraint the platform enforces is that a score's retention is at least as long as its events' retention, so no score is left standing on purged evidence.

**Optional evidence hold for law-enforcement referral.** The platform may provide an optional, access-controlled evidence hold: an operator can place a specific IP's evidence under a hold that exempts it from the normal retention purge so that a completed, corroborated case can be preserved for a law-enforcement referral. A hold is access-controlled and is itself an audited action. Whether and how such evidence may be retained and handed to law enforcement, and what chain-of-custody obligations attach, is jurisdiction-specific and needs legal sign-off for the operator's locale before the hold feature is used for a real referral.

## 7. Report integrity

The platform files abuse reports with reputation vendors and publishes a public blocklist. A false or spoofable report damages the operator's vendor reporter accounts and pollutes shared reputation data. Three layered controls protect against that.

**Human-approval gate (mandatory).** Nothing is reported to a vendor and nothing is published to the feed without explicit operator approval. The automated pipeline scores, corroborates, and queues; it never files a report or publishes a feed entry on its own. A recommended IP is surfaced and queued for the operator, who approves or rejects each one. This gate is architectural, not a configurable convenience.

**The confirmed-real requirement (eligibility).** An IP may be reported at all only after at least one confirmed-real event: a completed TCP handshake or an authenticated honeypot event, which proves the source address is real and not spoofed. Eligibility additionally requires variety: at least two events across at least two distinct signal categories. A completed TCP handshake cannot be forged by a spoofed source, so this requirement is what keeps the platform from reporting spoofable UDP traffic or a lone unacknowledged SYN, the exact traffic classes that get vendor reporter accounts penalized.

**Corroboration and breadth (weight and recommendation).** An eligible IP accumulates a decayed, capped signal weight. Breadth - the same attacker observed across multiple sensors and multiple WAN IPs - multiplies that weight up and raises the recommendation, so a widely-seen attacker is surfaced sooner. An eligible IP whose weight crosses the recommendation threshold is actively surfaced and queued for operator approval.

**The load-bearing invariant.** Breadth raises weight and raises the recommendation. Breadth can never make an ineligible IP eligible. Only a confirmed-real event confers eligibility. This is what keeps the anti-spoof guarantee intact: a spoofable sweep seen across many WAN IPs gains breadth weight but stays unreportable until a real, handshake-confirmed event proves the source exists. Breadth feeds the weight and recommendation axis; it does not touch the eligibility gate.

Together these mean a vendor report requires: a real, handshake-proven source; corroboration across events and categories; sufficient decayed weight; and a human's explicit approval. The cost of this is a non-real-time feed. That latency is an accepted trade: a false report's reputational cost is judged worse than the delay.

## 8. Jurisdiction and legal sign-off

Several controls above rest on legal positions that are not uniform across jurisdictions. The following need legal sign-off for the operator's specific locale before the platform is operated in production:

- The interception and content-capture posture in Section 5 (whether capturing honeypot traffic, and the content minimization applied, are lawful locally).
- The data-protection lawful basis, the DPIA (including the criminal-offence-data question for the published feed), the RoPA, and the retention windows in Sections 4 and 6.
- The disproportionate-effort notice and delist process supporting feed publication in Section 4.
- Any retention and handover of evidence to law enforcement under the evidence hold in Section 6, including chain-of-custody obligations.

This document describes the platform's controls and the design constraints behind them. It does not constitute legal advice and does not assert that the platform is compliant in any jurisdiction. The operator, as data controller, is responsible for obtaining that sign-off.
