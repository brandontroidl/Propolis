<!--
title: Evaluation deployment
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Evaluation deployment

The commands for a loopback evaluation are in the [quickstart](../manuals/quickstart.md).
This page is what that setup leaves out, so you know what you are and are not testing.

## What the evaluation skips

- **Process sandboxing.** The daemon and sensor run as your user from the build
  directory. A production install runs each as its own system user under a hardened
  systemd unit with a read-only filesystem view, no new privileges, and a syscall
  filter.
- **Secret handling.** The database URL and console password sit in your shell
  environment. In production each service reads its own `/etc/propolis/*.env` file,
  mode 0600.
- **TLS.** The console is plain HTTP on loopback in both cases; production puts a
  reverse proxy in front if the console must be reachable from elsewhere.
- **The spool mount.** Captured samples land in a plain temp directory. Production
  mounts the spool `noexec,nosuid,nodev`.
- **Backups, log rotation, monitoring.** None of it. The evaluation is disposable.

## What the evaluation does exercise

The real pipeline end to end: a sensor writing events, the daemon tailing them into the
hash-chained ledger, scoring, the review queue, the feed builder writing its files, and
the console. Nothing is stubbed.

## Outbound traffic during an evaluation

With nothing beyond the required variables set, the daemon connects to PostgreSQL and
nowhere else. VirusTotal, vendor reporting, the dropper fetcher, reverse DNS and push
alerts are all off until you set their variables, and the sensors never make outbound
connections. See [outbound controls](../security/outbound-controls.md).

## Next

[Your first capture](first-capture.md) walks through what an event looks like as it
moves through the system. When you are done, [tear it down](safe-teardown.md). When
you want the real thing, start from [installation](../operations/installation.md).
