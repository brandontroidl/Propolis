<!--
title: Captured content handling
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Captured content handling

A honeypot that accepts arbitrary uploads can be handed illegal material. The realistic worst
case is child sexual abuse material (CSAM) arriving as an image, a video, or an archive in an
SSH/SCP transfer, an FTP or TFTP upload, an ADB push, a telnet stdin capture, an MQTT payload,
or a file the fetcher downloads from a URL an attacker named. This page is the operator
procedure for that case: what the software already does to limit exposure, the rules an
operator follows, how to isolate one sample with the tools that exist, and what to do on
suspicion.

> **Not legal advice.** The legal parts below describe public processes and cite primary
> sources. Whether a duty applies to you, and what you may lawfully do with a file, is a
> question for counsel in your jurisdiction. Get that answer before you need it.

Custody, hashing, budgets and the never-execute invariant are owned by
[malware custody](../security/malware-custody.md) and [never execute](../security/never-execute.md);
spool paths by [filesystem paths](../reference/filesystem-paths.md); the 30-day cleanup by
[retention](retention.md#captured-sample-cleanup-30-days). This page does not restate them.

## What the system already does to limit exposure

- **Bodies are stored by SHA-256, never by the attacker's filename**, mode `0640`, written
  through a bounded off-response-path queue (`crates/sensor-framework/src/spool.rs#store`,
  `crates/sensor-framework/src/spool.rs#write_and_seal`,
  `crates/sensor-framework/src/handoff.rs#submit`). The operator identifies a sample by its
  digest alone.
- **The console never renders content.** `/samples` and `/samples/{sha256}` show digest, size,
  sensor, source addresses, campaign, VirusTotal counts and transport label; the templates
  contain no image, video, iframe, embed, object or text-preview element
  (`crates/console/src/templates/samples.html`, `crates/console/src/templates/sample_detail.html`).
  Nothing in the console reads a body except the download route.
- **The one route that returns bytes forces a download.**
  `crates/console/src/routes/samples.rs#serve_sample` answers with
  `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="<sha256>"`,
  `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`, after
  re-hashing the file and refusing symlinks, non-regular files and mismatched content
  (`crates/review/src/spool.rs#read_sample`). The browser will not display it inline. It does
  put a copy on the workstation of whoever clicks Download.
- **There is no content classification of any kind.** No MIME sniffing, thumbnailing, decoding
  or image parsing runs on a captured body anywhere in the console or the review crate; a body
  is bytes plus a digest.
- **Vendor abuse submissions carry no file and no payload.** AbuseIPDB, DShield and OTX reports
  are built from the source IP, category codes, an event count, a score and a time window
  (`crates/review/src/submit.rs#build_report`, `crates/review/src/vendor/mod.rs#VendorReport`),
  and only for review-queue entries a human approved (see
  [malware custody](../security/malware-custody.md#human-gated-forward)).
- **The blocklist feed carries addresses only** (see [scoring and feed](../reference/scoring-and-feed.md)).
- **Sensors make no outbound connection and never execute a body**
  ([never execute](../security/never-execute.md)).

### What the system does that works against you

Know these before an incident, because each one is the opposite of what you need.

1. **VirusTotal upload sends the file to a third party, automatically.** With
   `PROPOLIS_VT_ENABLED` and a key, every spooled body is looked up by hash. With
   `PROPOLIS_VT_UPLOAD=true` (default `false`), a body VirusTotal does not know is uploaded
   in full, with no file-type filter and no per-sample approval
   (`crates/review/src/virustotal.rs#scan_spool`, `crates/review/src/virustotal.rs#upload_sample`).
   If a CSAM image arrives while upload is on, the node can distribute it to a third party
   within one scan cycle (default 300 s). **Leave `PROPOLIS_VT_UPLOAD` off.** Hash lookup alone
   sends only the digest.
2. **Samples are deleted automatically after 30 days**, by age, with no hold mechanism
   (`crates/review/src/virustotal.rs#cleanup_old_samples`). Where a preservation duty may
   apply, an automatic delete is the wrong default; see "Quarantine one sample" for how to
   take a file out of the cleanup's reach.
3. **The recommended spool mounts are `tmpfs`** (printed by `deploy/install.sh`), so a body
   does not survive a reboot unless you moved it to persistent disk first.
4. **The fetcher downloads what attacker commands point at** when `PROPOLIS_FETCH_ENABLED=true`
   (default `false`), into the `fetched` spool, with no content-type filter. That makes your
   node the party that retrieved the file.
5. **The MQTT sensor writes a 256-byte payload preview into the event record**, as sanitized
   text when it decodes as text and as hex otherwise
   (`crates/sensor-mqtt/src/handler.rs#payload_preview`). The event ledger is append-only and
   hash-chained, so that text cannot be removed without breaking the chain
   ([retention](retention.md#event-and-score-retention)). Other sensors store commands and
   paths as text; this page did not audit every event field for payload text.

## Operator rules

1. **Never open, render, preview, decode, extract or "just check" an unknown capture.** No
   `file`, `strings`, `xxd` into a viewer, image viewer, file manager with previews, archive
   manager, `unzip`, `tar -x`, browser, or antivirus GUI. A digest is the identity of the
   sample; the digest is all you need.
2. **Image, video, audio, document and archive types are handled by hash only.** Everything you
   do with them (note them, link them to a campaign, look up reputation) uses the SHA-256.
   Do not unpack an archive to see what is inside.
3. **Do not use the Download button for a sample you have any reason to suspect.** Download
   exists for malware analysis on an isolated analysis host. It copies the bytes to your
   workstation, which is possession on a second machine.
4. **Do not forward, attach, upload, paste, email or chat a suspect file or its bytes**, to a
   colleague, a vendor, a scanner, an AI service or a ticket. Share the SHA-256, the sensor,
   the UTC time and the source address instead.
5. **Keep the sample out of every outward path** while it is held:
   - set `PROPOLIS_VT_UPLOAD` to `false` (or unset) and restart, or take the file out of the
     spool first (below). Check whether the digest was already sent:
     `SELECT sha256, detected, analyzed_at FROM sample_analysis WHERE sha256 = '<digest>';`
     (`detected = -1` is "uploaded, no verdict yet", see
     `crates/review/src/virustotal.rs#AnalysisState`). A row that exists means VirusTotal has
     been asked about it; whether it was uploaded is in the service journal (`vt: sample uploaded
     for analysis`).
   - do not Approve the source address in the review queue on the strength of that sample if
     you do not want the vendor report to mention it; vendor reports never include the file
     either way.
   - the feed and the Samples page contain no bytes, so they need no change.
6. **Do not delete first.** Preservation duties may apply (below). Isolate, then ask.
7. **Record, do not copy.** Keep a private note (not in the repository, not in a ticket system
   shared with others): digest, sensor, spool bucket, UTC time of capture, source address, who
   did what and when.

## Quarantine one sample

There is no per-sample quarantine or hold command. The review CLI (`approve`,
`reject`, `snooze`, `unsnooze`, `history`) acts on source addresses, not files
(`crates/review/src/cli.rs#Command`). Isolate a file with the operating system, from the
sample's digest, without ever reading it:

1. Find it without opening it. The Samples page shows the digest and the sensor; the path is
   `<spool dir>/<digest>` for that sensor's directory
   ([filesystem paths](../reference/filesystem-paths.md)).
2. Stop the paths that would touch it, if upload is on: set `PROPOLIS_VT_UPLOAD=false` and
   restart `propolis.service` ([service lifecycle](service-lifecycle.md)).
3. Create a holding directory on **persistent** storage that is not under any spool root and
   not `tmpfs`, mode `0700`, owned by root, ideally on an encrypted volume
   (for example `sudo install -d -m 0700 -o root -g root /srv/propolis-hold`; the path is yours
   to choose).
4. Move the file there by name: `sudo mv -- /var/spool/propolis/<sensor>/<digest> /srv/propolis-hold/`.
   A move takes it outside `cleanup_old_samples`, which only walks the spool directories
   (`crates/review/src/spool.rs#all_body_dirs`), and outside the Samples page, the VirusTotal
   scan and the download route. Confirm with `sudo ls -l /srv/propolis-hold/` (metadata only) and
   that the Samples detail page now reads "Not in any spool".
5. Leave the database rows alone. `event`, `fetch_attempt` and `sample_analysis` rows are the
   record of how the file arrived; the event ledger is hash-chained and deleting from it breaks
   the chain.
6. If the capture came from the fetcher, also stop `PROPOLIS_FETCH_ENABLED` until you have
   counsel's answer, so the node does not fetch more from the same source.
7. Include the holding directory in whatever you tell counsel; exclude it from your normal
   backups unless counsel says otherwise (a backup is another copy
   ([backup and restore](backup-and-restore.md))).

If the file must be preserved for law enforcement, do not decrypt, rename, compress or "tidy"
it. Digest-named and unmodified is the best chain-of-custody state you can offer.

## On suspicion

This is a description of the public process, not advice.

1. **Stop.** Do not view it to confirm. Apply the rules above and quarantine the file.
2. **Do not distribute it** to anyone, including for "a second opinion".
3. **Do not delete it yet.** Federal law in the United States treats a provider's completed
   CyberTipline report as a request to preserve the reported contents for one year, and law
   enforcement may ask for more. Knowing possession of such material is itself an offence
   under 18 U.S.C. 2252A(a)(5), which also contains a narrow affirmative defence for a person
   who promptly and in good faith destroys it or reports to law enforcement and gives them
   access, subject to its conditions. Those two statements pull in different directions, and
   which one governs your facts is exactly the question for counsel.
4. **Talk to counsel before or immediately after reporting**, and say you operate a honeypot
   that accepts uploads unattended.
5. **Report through the proper hotline.**

### United States

- Providers' duty: 18 U.S.C. 2258A(a)(1) requires a *provider* that obtains actual knowledge
  of an apparent violation involving child sexual abuse material to report it as soon as
  reasonably possible to NCMEC's CyberTipline. Section 2258E defines "provider" as an
  "electronic communication service provider or remote computing service" (as defined in
  sections 2510 and 2711). The statute does not oblige a provider to monitor users or scan
  for such material (2258A(f)).
- **Whether 2258A applies to an individual running a honeypot is a question for counsel.**
  This page does not answer it either way. Voluntary reporting is open to anyone: NCMEC
  states that "the public and electronic service providers can make reports"
  ([report.cybertip.org](https://report.cybertip.org/), 1-800-843-5678).
- Section 2258B's limited-liability protection is written for providers, NCMEC contractors and
  depicted minors; it should not be assumed to cover an ordinary reporter. Another reason to
  ask counsel first.
- Preservation: a completed provider report is treated as a request to preserve the reported
  contents for one year after submission (2258A(h)(1), as amended by the 2024 REPORT Act).

### Outside the United States

Use your own jurisdiction's hotline and your own counsel; do not assume the US process
applies. INHOPE lists member hotlines in 53 countries and routes a report to the national
one (the UK's is the Internet Watch Foundation). Contact the hotline first where possible, and
let it say whether you should send, keep or avoid the file. Your national law on possession,
reporting and preservation differs and is not described here.

## Sources

Checked live on 2026-10-08 through a page-fetch tool that returns a summary of the page, not
the raw text. Treat the statutory quotations as accurate to the summary and confirm the exact
wording against the statute or counsel before relying on them.

- 18 U.S.C. 2258A, reporting requirements of providers: <https://www.law.cornell.edu/uscode/text/18/2258A>
  (duty, preservation 2258A(h), privacy 2258A(f), penalties 2258A(e)). Verified in summary.
- 18 U.S.C. 2258B, limited liability: <https://www.law.cornell.edu/uscode/text/18/2258B>.
  Verified in summary.
- 18 U.S.C. 2258E, definitions: <https://www.law.cornell.edu/uscode/text/18/2258E>. Verified in summary.
- 18 U.S.C. 2252A, possession and the (d) affirmative defence: <https://www.law.cornell.edu/uscode/text/18/2252A>.
  Verified in summary.
- NCMEC CyberTipline: <https://www.missingkids.org/gethelpnow/cybertipline>,
  <https://report.cybertip.org/>. The statement that the public can report and the phone
  number were read live.
- INHOPE hotline directory: <https://inhope.org/EN/articles/report-illegal-content>. Read live.

Not verified: the current penalty amounts in 2258A(e) (not used above); whether any 2025-2026
amendment changed the text after the REPORT Act (the LII page showed none); whether the
"provider" definitions in 18 U.S.C. 2510 and 2711 cover an individual operating a honeypot
[unverified, and counsel's question]; any non-US law or hotline procedure
[unverified].
