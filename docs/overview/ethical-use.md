<!--
title: Ethical use
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Ethical use

Propolis is defensive tooling. Its legitimate use rests on the boundaries below.

## Defensive and authorized use only

Deploy Propolis only on infrastructure you **own or are explicitly authorized to
monitor**. The platform captures hostile traffic delivered to decoy services you
deliberately expose; it is not for use against systems, networks, or IP addresses
you do not control.

## Capture hostile traffic on your own infrastructure

Sensors are passive: they observe and record traffic that reaches them, and never
execute captured content or initiate connections to the sources they observe. The
intelligence Propolis produces comes from attackers choosing to engage your decoys -
not from any outbound probing on your part.

## Malware custody responsibility

Sensors capture uploaded samples (SSH/SCP/SFTP, FTP STOR, ADB push, and the fetcher
spool). **Captured malware is live, hostile code.** You are responsible for storing,
handling, and disposing of it safely, and for any onward transmission (for example,
enabling VirusTotal scanning uploads samples to a third party). Read
[`../security/malware-custody.md`](../security/malware-custody.md) and
[`../security/sample-and-credential-privacy.md`](../security/sample-and-credential-privacy.md)
before capturing samples, and never execute captured content.

## Not for offensive use

Propolis must not be used to attack, scan, exploit, or otherwise act against third
parties. It has no offensive capability by design (see [Non-goals](non-goals.md)),
and repurposing its captured data or credentials for offensive ends is outside both
its intent and its license.

## Outbound actions are operator-gated

No vendor abuse report is filed and no IP enters the score-based tier files without
a per-case operator decision. The retention feeds additionally list sources that
completed a thousand or more TCP connections in the last day, without review; such a
source is never reported to a vendor on volume alone. Enabling any enrichment or
reporting egress path
(VirusTotal, AbuseIPDB/DShield/OTX, ntfy alerts, reverse DNS) is an operator
decision with associated exposure - see
[`../security/outbound-controls.md`](../security/outbound-controls.md). When you file
an abuse report, ensure it is accurate and made in good faith.

## License reminder

Propolis is **source-available, not open source**. Noncommercial use is free under
the PolyForm Noncommercial License 1.0.0 - personal use, home labs, research,
teaching, and nonprofit, public-safety, or government organizations. Commercial use
requires a separate license. See [`LICENSE.md`](../../LICENSE.md) and
[`../governance/licensing.md`](../governance/licensing.md).
