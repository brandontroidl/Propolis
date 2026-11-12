<!--
title: Sanitizer results
audience: security
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-28
-->

# Sanitizer results

Dated records of runtime sanitizer runs against the workspace, and how each report
was attributed. A record describes the tree at the commit it names; it is not
re-run on every change.

## sensor-adb under AddressSanitizer and LeakSanitizer (2026-09-28)

**Question.** The 2026-09-28 audit (finding P-15, informational, low confidence)
saw LeakSanitizer report 495 bytes in 33 allocations at exit of the sensor-adb test
process, with no invalid memory access. Is that a product leak?

**Answer.** No. All 33 allocations are the path buffers of `tempfile::TempDir`
values that a test-only helper deliberately forgets. No production code path in
`sensor-adb` or `sensor-framework` leaked.

### Setup

| Item | Value |
|---|---|
| Tree | commit `c7302ee0` |
| Toolchain | `rustc 1.101.0-nightly (d080e7dff 2026-09-27)`, LLVM 23.1.1; `cargo 1.101.0-nightly (3d7cf6e93 2026-09-25)` |
| Target | `x86_64-unknown-linux-gnu`, debug test profile |
| Sanitizer | `RUSTFLAGS=-Zsanitizer=address`; the standard library was not rebuilt (no `-Zbuild-std`) |
| Symbolizer | GNU `addr2line` 2.46 (no `llvm-symbolizer` was available); frames inside the sanitizer runtime print as `??:?` |

Without `-Zbuild-std`, AddressSanitizer checks memory accesses only in code built
with the flag (the workspace crates and the vendored dependencies). Leak detection
still covers every heap allocation, the standard library's included, because the
sanitizer runtime intercepts `malloc`/`realloc`/`free`, which Rust's default
allocator calls.

Build, from the repository root, with `$NIGHTLY` the nightly toolchain directory:

```sh
RUSTFLAGS=-Zsanitizer=address RUSTC=$NIGHTLY/bin/rustc CARGO_TARGET_DIR=target/asan \
  $NIGHTLY/bin/cargo test -p sensor-adb --lib --bins --tests --locked \
  --target x86_64-unknown-linux-gnu --no-run
```

Run each test binary (the paths the build prints) from `crates/sensor-adb`, which is
the working directory `cargo test` would use:

```sh
ASAN_OPTIONS=detect_leaks=1:symbolize=1:allow_addr2line=1:fast_unwind_on_malloc=0:malloc_context_size=64 \
ASAN_SYMBOLIZER_PATH=/usr/bin/addr2line LSAN_OPTIONS=report_objects=1 \
  <test-binary> [--test-threads=1] [--exact <test-name>]
```

### Results

| Test binary | Tests | LeakSanitizer |
|---|---|---|
| `sensor-adb` lib unit tests (`src/lib.rs`) | 42 passed | 495 bytes in 33 allocations, 14 records, one allocation site |
| `sensor-adb` bin unit tests (`src/main.rs`) | 11 passed | none |
| `sensor-adb` integration (`tests/integration.rs`) | 20 passed | none |
| `sensor-framework`, 5 binaries, `--test-threads=1` | 201 passed | none |

The lib result is identical with the default thread count and with
`--test-threads=1`. For the two clean `sensor-adb` binaries, a run with
`verbosity=1` printed `LeakSanitizer: checking for leaks`, so the exit-time check
ran and found nothing rather than being off. No AddressSanitizer access error was
reported by any binary.

### Minimized reproduction

Each of the 42 lib tests was run alone (`--exact`, one thread). Exactly the 11
tests that call the `test_handoff` helper leak, 15 bytes per call:

| Test in `handler::tests` | `test_handoff` calls | Leak when run alone |
|---|---|---|
| `sync_feed_never_panics_on_arbitrary_bytes` | 20 (a loop) | 300 bytes, 20 allocations |
| `sync_abandoned_mid_send_yields_an_incomplete_capture` | 3 | 45 bytes, 3 |
| `sync_submits_the_unfinished_send_when_cancelled_or_reset` | 2 | 30 bytes, 2 |
| the other 8 `sync_*` tests | 1 each | 15 bytes, 1 each |
| **Total** | **33** | **495 bytes, 33** |

The 30 `adb_proto` tests (property tests included) and
`connection_event_is_unauthenticated_with_adb_label` report nothing. The smallest
reproducing set is any one of the 11, for example:

```sh
<lib-test-binary> --test-threads=1 --exact handler::tests::sync_send_data_done_produces_capture_job
# SUMMARY: AddressSanitizer: 15 byte(s) leaked in 1 allocation(s).
```

The audit noted that individual ordinary tests did not reproduce the report. Here
every one of the 11 does when run alone; which tests the original run selected is
[unverified].

### Attribution

All 14 records share one allocation stack (innermost first, library frames
abridged):

```
realloc                                  (sanitizer runtime)
Vec<u8>::into_boxed_slice / PathBuf::into_boxed_path
tempfile::dir::imp::unix::create         vendor/tempfile/src/dir/imp/unix.rs:23
tempfile::dir::tempdir                   vendor/tempfile/src/dir/mod.rs:65
sensor_adb::handler::tests::test_handoff crates/sensor-adb/src/handler.rs:927
sensor_adb::handler::tests::test_sync_state (handler.rs:949), or the test itself
test::run_test_in_process                (libtest worker thread)
```

The source that makes this a leak, at `c7302ee0`:

- `crates/sensor-adb/src/handler.rs:927` creates the directory
  (`tempfile::tempdir()`), and `handler.rs:934` calls `std::mem::forget(dir)`,
  inside `test_handoff`, in the `#[cfg(test)] mod tests` block that starts at
  `handler.rs:901`. The helper is not compiled into the sensor binary.
- `TempDir` owns its path as `path: Box<Path>` (`vendor/tempfile/src/dir/mod.rs:182`),
  allocated at `vendor/tempfile/src/dir/imp/unix.rs:23`. Dropping a `TempDir`
  frees that box, and its `Drop` impl (`vendor/tempfile/src/dir/mod.rs:498`)
  removes the directory. `mem::forget` skips both, so the box is never freed and
  nothing points to it, which LeakSanitizer reports as a direct leak.
- The size matches: `/tmp/` plus the `.tmp` prefix (`vendor/tempfile/src/lib.rs:231`)
  plus 6 random characters (`vendor/tempfile/src/lib.rs:195`) is 15 bytes.

Separate check: the same single test run with `TMPDIR` set to a 105-byte
directory leaked 116 bytes, which is the length of `<TMPDIR>/.tmpXXXXXX`, and the
forgotten directory, with its `spool/` subdirectory, was still on disk after the
process exited. The leaked size follows the temp-directory path, which a product
allocation would not.

Classification: **test-harness artifact.** It is neither a product leak nor
runtime or library process-lifetime state. No tokio, thread-local or global frame
appears at the allocation site. A search of `crates/sensor-adb` and
`crates/sensor-framework/src` for `mem::forget`, `Box::leak`, `.leak()`,
`ManuallyDrop`, `into_raw`, `static mut`, `OnceLock`, `LazyLock`, `lazy_static`
and `thread_local` finds only `handler.rs:934`. The production composition (`start_test_server` in
`crates/sensor-adb/src/lib.rs`, which `main.rs` also uses) is what the 20
integration tests drive over real TCP connections: shell sessions, `sync` pushes,
cancellation at `max_duration`, the OPEN flood cap and malformed input. That run
reported no leaks. Its fixture keeps its `TempDir` alive in
`TestServer::_dir` (`crates/sensor-adb/tests/integration.rs:34`).

### Limits

- LeakSanitizer reports memory that is unreachable at exit. Memory that grows but
  stays referenced, such as an unbounded map, is not reported. Per-connection
  bounds are covered by their own tests (for example the OPEN flood cap), not by
  this run.
- One nightly toolchain, one host, debug profile.

### Follow-up (done)

`test_handoff` also left one directory per call on disk
(`$TMPDIR/.tmpXXXXXX/spool`), 33 for each run of the lib tests. The helper now
returns the `TempDir` alongside the hand-off, and every test holds it until the
test ends, as the integration fixture does. Re-run the same way after that change
(2026-09-28): the lib unit tests pass (42), `verbosity=1` shows
`LeakSanitizer: checking for leaks`, no leak is reported, and a fresh `TMPDIR` is
empty after the run.

The raw symbolized report and the per-test table are kept with the audit
evidence, outside the repository.

## Related

- [Supply chain](./supply-chain.md), for the memory-safety posture
- [Residual risks](./residual-risks.md)
