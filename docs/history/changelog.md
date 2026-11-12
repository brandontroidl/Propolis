<!--
title: Changelog (canonical view)
audience: all
status: historical
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Changelog

The authoritative changelog is the root [`CHANGELOG.md`](../../CHANGELOG.md). This
page describes its shape and current state so a reader knows how to interpret it; it
does not replace it.

## State of the changelog

The root changelog is a **single, undated `## Unreleased` section** in
Keep-a-Changelog style, with one `### Added` subsection. It is **not
version-partitioned**: there are no dated or versioned release headings (no
`## [0.1.0]`, no `## [0.2.0]`, no dates). Every entry is filed under `Unreleased`,
so entries cannot be mapped to a specific release from the changelog alone.

This matters when reading it against the tag history: the crate tree is at version
`0.3.0` while the only release tag is `v0.1.0`, and the changelog files both the
original SP1-SP8 build and the later post-tag features together under `Unreleased`.
For the version/tag relationship, see
[overview/maturity-and-status](../overview/maturity-and-status.md).

## Not yet in the changelog

The **V12 operator-console interface** (theme system, evidence drawer, self-hosted
fonts) merged post-tag at commit `dbf8c053` but is **not mentioned in the
changelog** as of this writing. The changelog's `Added` list does not reflect it.

## What the `Added` section covers

Grouped as the root file lists them (see
[`CHANGELOG.md`](../../CHANGELOG.md) for exact wording):

- **Recent post-tag features** (top of the list): forward-confirmed reverse DNS
  (`PROPOLIS_CONSOLE_RDNS_ENABLED`, default off); trusted-org ASN suppression
  (`PROPOLIS_FEED_ASN_ALLOWLIST`, opt-in); IP-detail network-profile panel with
  optional offline MaxMind GeoLite2 enrichment (`PROPOLIS_GEOIP_DIR`, local file
  reads); telnet single-byte-XOR de-obfuscation; operational self-alerting over
  ntfy (`PROPOLIS_OPS_ENABLED`, opt-in). All five of these enrichment/reporting
  paths are **operator-gated and default off**.
- **The original build**, SP1 through SP8 (bottom of the list): core scoring, the
  sensor framework + SSH, event intake, the review queue and reporting, the
  blocklist feed, the web console, the unified daemon, and the seven additional
  sensor crates.

The completed build items are summarized, with their current status, in
[completed-and-superseded](completed-and-superseded.md).

## A note on counts

Test-count figures in the `v0.1.0` tag message ("770+ tests") and the SP-era
subtotals in the changelog (e.g. "60 tests", "251 tests") predate later work and
are **stale**; they should not be read as the current total. See
[overview/maturity-and-status](../overview/maturity-and-status.md) for the current
test-corpus figure and the caveat that it is a declared-attribute count, not a
verified passing run.
