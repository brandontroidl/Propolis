# 08 - Remaining native sensors

Status: design pending (not yet brainstormed)

## Scope

The remaining first-party honeypots built on the sub-project-2 harness: Redis, ADB, malware-capture, and credential. Added incrementally, one sensor at a time, each inheriting the harness contract (unprivileged, no database handle, no secrets, passive-only, structured signed events, passwords and payloads dropped at capture time).

## Goals

Broaden the sensor surface so more attacker behavior produces evidence, without weakening the safe-by-construction posture. Each sensor earns its place on the current goals and ships only when its full loop is wired and verified, not as a batch. Emulation depth is chosen to gather signal, never to run real attacker code.

## Dependencies

Sub-project 2 (sensor framework): the harness, the signed-event contract, and the isolation model every sensor here reuses.

## Key open questions

- Per-protocol emulation depth for Redis, ADB, and credential: how much of each protocol to emulate to earn useful signal without real execution.
- Malware-capture safety and storage: how captured samples are handled, isolated, and retained without turning the sensor into an execution or exfiltration surface.
