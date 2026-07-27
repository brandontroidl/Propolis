# ADR-0010: Sensor-to-intake integrity model - channel isolation, not sensor-side signing

Status: accepted (2026-07-20)

## Context

`architecture/frozen-contracts.md` deferred the sensor-to-intake wire format as the highest-risk
interface, to be settled at sub-project 2 design time before sub-projects 2 and 3 fork. The scope
stub (`design/02-sensor-framework.md`) described sensors emitting "signed events." Settling the wire
format forced the question of what "signed" means when the security posture
(`security/posture.md` §2) states that no secrets - no keys of any kind - reach a sensor process.

A cryptographic signature requires a signing key. A signing key is a secret. Placing one on an
internet-facing sensor both violates the no-secrets posture and defends against nothing: the primary
sensor threat is compromise of the sensor process itself, and a compromised process holding its own
signing key hands that key to the attacker, who can then sign forged lines indistinguishably. Sensor-
side signing is therefore impossible under the posture and pointless against the threat it would
nominally address.

## Decision

The sensor-to-intake integrity model has two parts, and the wire format is amended from "signed
events" to "structured, channel-isolated events with a sample side channel; integrity via the OS
one-directional channel and the ledger hash chain at intake."

1. **Trust boundary: the OS-enforced one-directional channel.** A sensor's OS user has write-only
   access to its own log and quarantine spool; intake has read-only access. This is enforced by
   filesystem permissions and service-manager mounts (kernel-enforced), not by convention. A sensor
   compromise can spoil that sensor's own event lines and reach nothing else - exactly the blast
   radius `security/posture.md` §2 already accepts. Intake treats sensor input as untrusted data and
   validates every record (parseable source IP, known signal type, in-range fields) before it enters
   the ledger.

2. **Tamper-evidence: the ledger hash chain (sub-project 1).** Durable evidence integrity lives in
   the append-only hash-chained `event` ledger, applied by intake as it appends each event. Altering
   ingested evidence breaks the chain and is detectable. There is no sensor-held signature to verify.

3. **Authenticity at capture: the sanitization chokepoint** (added 2026-07-27, see Consequences).
   Parts 1 and 2 answer a *compromised* sensor and *later alteration* of stored evidence. Neither
   answers an uncompromised sensor being talked into emitting an event the attacker authored, which
   in a newline-delimited transport requires nothing more than a newline inside a captured command,
   filename, or banner. Such a line is written by the legitimate sensor through the legitimate
   channel and is chained by intake as genuine evidence, so no part of the model above can detect
   it. The control is therefore at capture, not in transit or at rest: every attacker-controlled
   value passes one shared sanitizer that neutralizes line terminators before any other processing,
   and byte-derived fields are carried as hexadecimal, whose alphabet cannot express a terminator at
   all. This is specified in `design/02-sensor-framework.md` § Capture sanitization contract and is
   a frozen precondition of the wire format, not an implementation detail.

## Consequences

- Sensors hold no keys and no secrets, consistent with the posture; the framework crate has no
  secret-bearing dependency, so a sensor cannot hold one by construction.
- The integrity guarantee for the durable record is the ledger chain, with the limitations already
  recorded in ADR-0009 (an unsigned chain does not detect tail truncation). The channel isolation,
  not a signature, is what bounds a sensor compromise.
- `architecture/frozen-contracts.md` is amended to move this item from Deferred to Frozen, pointing at
  `design/02-sensor-framework.md` as the canonical wire-contract definition.
- Part 3 was added on 2026-07-27 while checking the sub-project 2 spec against the prior-art sensor
  specification written for the predecessor system, which treated capture-time neutralization as a
  named chokepoint. The original two-part decision is unchanged and not superseded; the gap was that
  it was stated as *the* integrity model while covering only two of the three ways a record can be
  wrong. Choosing a newline-delimited transport is what makes the third one cheap, so the control
  belongs in this decision rather than being left to the implementation.

## Rejected alternatives

- **Per-sensor HMAC / signature on each event line** - rejected: needs a key on the sensor (violates
  the no-secrets posture) and does not defend against sensor compromise, the primary threat, since the
  compromised process holds the key. It would defend only against a distinct local writer to the log
  directory, which filesystem permissions already prevent.
- **Sign at a privileged local agent between sensor and intake** - rejected for this layer: it adds a
  secret-bearing component alongside every sensor for a guarantee the OS channel boundary and the
  ledger chain already provide; premature and higher-surface.
