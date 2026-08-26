<!--
title: Never-execute invariant
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Never-execute invariant

The honeypot captures what an attacker sends; it never runs it. No Propolis
code spawns a subprocess or execs. This is a property held **by construction**
(the code contains no process-spawning call) and reinforced by static-check
regression tests, deployment-layer W^X, and no-execute spool permissions.

## The invariant

No source file under `crates/*/src/**` (test trees excluded) invokes any
process-spawning facility. A whole-workspace grep for `Command::new`,
`process::Command`, `libc::exec`, `nix::unistd::exec`, and `.spawn()` returns
zero matches. The only `std::process` uses in non-test source are three
`std::process::exit(1)` calls for clean shutdown in `crates/review/src/main.rs`
(lines 414, 422, 432) - process termination, not process creation.

No crate enables Tokio's `process` feature: a grep for `"process"` across every
`crates/*/Cargo.toml` returns nothing. `sensor-cred` asserts this directly - its
integration test checks that the `tokio = ` line in its own `Cargo.toml` does
not contain `"process"` (`crates/sensor-cred/tests/integration.rs:485-486`).

Because the capability is simply absent from the dependency tree and the source,
there is no exec path to reach - not a runtime guard that could be misconfigured
off.

## Static-check regression tests (8)

Eight per-sensor tests walk their crate's `src/` tree and fail if any `.rs` file
contains `std::process::Command`, `process::Command`, or `Command::new` (the SSH
test also bans `libc::exec` and `nix::unistd::exec`). They are regression guards:
they exist so a future edit that introduces a spawn call fails the gate rather
than shipping.

| Test | Location |
|------|----------|
| `never_exec_static_check` (SSH) | `crates/sensor-ssh/tests/shell_test.rs:121` |
| (cred) | `crates/sensor-cred/tests/integration.rs:488` |
| (adb) | `crates/sensor-adb/tests/integration.rs:356` |
| (ftp) | `crates/sensor-ftp/tests/integration.rs:255` |
| (http) | `crates/sensor-http/tests/integration.rs:198` |
| (redis) | `crates/sensor-redis/tests/integration.rs:270` |
| (smtp) | `crates/sensor-smtp/tests/integration.rs:358` |
| (telnet) | `crates/sensor-telnet/tests/integration.rs:181` |

The SSH test is broader than its own crate: it walks **both** `sensor-ssh/src`
and `sensor-framework/src` (lines 145-160). The `FakeFs`/`FakeShell`
implementations - the highest-priority surfaces for this guarantee - moved into
`sensor-framework`, so the check follows the code wherever it lives rather than
guarding a fixed crate.

### Coverage gap

`sensor-catchall` has an `integration.rs` but no `never_exec_static_check`, so
seven sensor tests plus the SSH test's framework coverage make eight. The
whole-workspace grep above still shows `sensor-catchall`'s source is clean; only
the per-crate regression guard is absent for it. [inferred] Adding the guard to
`sensor-catchall` would close the asymmetry. See
[residual-risks.md](residual-risks.md).

## Reinforcing controls

The invariant is defence-in-depth, not source discipline alone:

- **Deployment-layer W^X.** Every systemd unit sets `MemoryDenyWriteExecute=yes`
  (`deploy/sensor-ssh.service:104-112`), so a page cannot be both writable and
  executable even if an exec primitive were somehow reached. A test asserts the
  directive is present and correctly spelled -
  `crates/sensor-framework/tests/deploy_test.rs:100-102` - because the `-ion`
  misspelling silently installs no rule. Owned by
  [filesystem-and-db-protections.md](filesystem-and-db-protections.md).
- **No-execute spool.** Captured sample bodies are written mode `0640`
  (`crates/sensor-framework/src/spool.rs:271-279`) and the spool directory is
  required to be a `noexec,nosuid,nodev` mount. A captured file is therefore not
  marked executable and lives on a mount that would refuse execution. The mount
  option is an operator deployment step, not enforced by the units - see
  [malware-custody.md](malware-custody.md).

## What this does not claim

The never-execute invariant covers the honeypot's own process behaviour. It is
distinct from the outbound-network posture (the platform has opt-in egress paths
- see [outbound-controls.md](outbound-controls.md)) and from whether the
`noexec` spool mount is actually mounted on a given box, which install.sh only
prints guidance for and cannot enforce (see [residual-risks.md](residual-risks.md)).
