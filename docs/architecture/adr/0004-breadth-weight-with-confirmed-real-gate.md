# ADR 0004: Breadth raises weight behind a confirmed-real eligibility gate

Status: Accepted 2026-07-16

## Context

Cross-WAN breadth is the reason for the cluster: an attacker seen on several WAN
IPs should score higher and be surfaced sooner. The risk is that a lot of that
WAN traffic is spoofable. UDP packets and lone SYN segments carry a source
address the sender can forge, so breadth across WAN IPs can be manufactured by an
attacker spoofing a victim's address. If breadth alone could make an IP
reportable, the platform would file abuse reports against forged sources, and
reputation vendors penalize reporter accounts that submit spoofable or
single-sourced traffic.

## Decision

Separate eligibility from weight, and let breadth move only weight.

- ELIGIBLE: an IP may be reported at all only after at least one confirmed-real
  event, meaning a completed TCP handshake or an authenticated honeypot event,
  plus variety of at least 2 events across at least 2 distinct signal
  categories. A completed handshake proves the source IP is real because a
  spoofed source cannot complete it.
- WEIGHT: the decayed, accumulated signal score, capped at 100, then multiplied
  up by breadth across WAN IPs.
- RECOMMENDED: an eligible IP whose weight crosses the recommendation threshold
  is actively surfaced and queued for operator approval.

Invariant: breadth raises weight and the recommendation, but it can never make
an ineligible IP eligible. Only a confirmed-real event does that.

## Alternatives considered

- Breadth alone can trigger a report. Rejected: it lets a spoofable UDP or
  lone-SYN sweep across WAN IPs manufacture a report against a forged source and
  risks vendor account penalties, defeating the corroboration guarantee.

## Consequences

The anti-spoof floor is fixed and independent of breadth. Breadth changes how
fast a genuinely real attacker is surfaced, never whether an unproven source can
be surfaced at all. The recommendation threshold is a recommended, tunable
value; the eligibility floor is not tunable downward.
