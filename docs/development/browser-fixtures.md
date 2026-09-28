<!--
title: Browser fixtures
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; no tags in this repository)
last-verified: 2026-09-21
-->

# Browser fixtures

Almost everything the console does is checked by the Rust suite. One thing is not, because it
cannot be: how a real browser behaves when a polled panel's request is accepted and then never
answered. That case is reproduced by a fixture you run by hand.

This page covers `crates/console/tests/fixtures/poll-fixture.py` - what it proves, how to run it,
what a passing run looks like, and how to read a failing one.

## What it guards

The fleet page refreshes itself (`fleet.html`, `hx-trigger="every 30s"`). HTMX leaves the last
successful render on screen when a refresh fails, and every relative age on that render ("4 minutes
ago", "never") was computed by the **server** at render time - so a panel that has stopped
refreshing keeps reading as current while the real gap grows. `base_tail.html`'s live-panel script
exists to stop that, and it decides staleness two independent ways:

| Mechanism | Covers | Fails silently if |
|---|---|---|
| HTMX's `htmx:responseError` / `htmx:sendError` / `htmx:timeout` | a refused connection, a 500, a request that exceeds its bound | the request has no bound, so nothing ever fires |
| An age watchdog on a 5s timer | everything else, including a request that hangs forever | the timer is removed in favour of "HTMX will tell us" |

The second row is not hypothetical. HTMX's own default request timeout is `0` - unlimited - so
before both mechanisms shipped, a server that accepted the status poll and held it open left the
page reading `Listeners proven: 1 / 1` and `Probed: just now` **143 seconds later**, with
`xhr.timeout === 0`, no error event, and no stale marker.

`templates.rs`'s `a_polled_panel_bounds_its_request_and_ages_itself_without_waiting_for_an_event`
asserts that both mechanisms still **ship** in the rendered page. It cannot assert that they
**work** - that needs a real XHR against a real hung socket, which is this fixture.

## What it serves

One page, assembled from the repository's own files:

- the unmodified vendored `htmx.min.js`, and
- the live-panel IIFE lifted verbatim out of `base_tail.html`, located by its opening comment.

Nothing about the behaviour under test is restated in the fixture, so it cannot drift into passing
against code the console does not ship. Change the live-panel script and the fixture picks the
change up on its next run; delete it and the fixture fails.

The page reports its own observable state (`data-stale`, the banner text, the HTMX events seen, the
live `xhr.timeout`) back to the fixture once a second, and the fixture prints a line whenever any
of that changes.

## Running it

```
python3 crates/console/tests/fixtures/poll-fixture.py --launch-chrome
python3 crates/console/tests/fixtures/poll-fixture.py --launch-chrome --unbounded
```

Both modes take about two minutes each. `--launch-chrome` starts headless Chrome against a
throwaway profile and cleans it up on exit; without the flag the fixture just prints its URL and
waits, which is worth doing at least once - the banner is written to be read by an operator, so
read it.

Driving the browser yourself:

```
python3 crates/console/tests/fixtures/poll-fixture.py
google-chrome --headless=new --disable-background-timer-throttling \
    --user-data-dir=$(mktemp -d) http://127.0.0.1:8733/
```

> **`--disable-background-timer-throttling` is load-bearing.** A headless window is never
> foregrounded, and Chrome throttles `setInterval` in a backgrounded page to roughly once a minute.
> Without the flag both HTMX's polling and the watchdog stall and the timeline is meaningless - the
> first run of this fixture reported nothing at all for that reason.

`--port`, `--run-seconds` and `--recover-after-seconds` are there for when you need a second run
alongside the first or a longer window; the defaults are sized for the 30s poll interval the fleet
page actually uses.

## A passing run

**Default mode** - the per-request bound turns the hang into a timeout, and a later good answer
clears the banner:

```
[   1.2s] {"stale": null, "hxRequest": "{\"timeout\": 15000}", "xhrTimeout": null, ...}
[  30.2s] /fleet/status accepted and HELD open
[  31.2s] {"stale": null, ..., "xhrTimeout": 15000, "events": "", ...}
[  46.2s] {"stale": "true", ..., "events": "htmx:timeout",
           "banner": "This fleet reading has stopped refreshing (the server did not answer in
                      time). What is shown below was measured 45 seconds ago; ..."}
[  90.2s] /fleet/status answered normally
[  91.2s] {"stale": null, ..., "events": "htmx:timeout,htmx:timeout,htmx:afterSwap", "banner": null}
```

What matters, in order: `xhrTimeout` is **15000, not 0**; `stale` becomes `"true"` roughly one
timeout after the poll starts (~46s, not ~143s or never); the banner names how long ago the reading
was actually measured; and a successful refresh clears both the flag and the banner.

**`--unbounded`** - the bound is neutralised in the page, so the watchdog is the only thing left
that can notice:

```
[   1.2s] {"stale": null, "hxRequest": "{\"timeout\": 600000}", ...}
[  30.2s] /fleet/status accepted and HELD open
[  80.2s] {"stale": "true", ..., "events": "",
           "banner": "This fleet reading has stopped refreshing (no refresh has come back). What is
                      shown below was measured 80 seconds ago; ..."}
```

The empty `events` string is the whole point: no HTMX event fired, and the panel went stale anyway,
at `2 × poll interval + request timeout + watchdog tick` (80s for a 30s poll).

This mode shows no recovery line, and should not. The single hung request never completes, HTMX
does not start a second one over the top of it, so there is nothing to recover from until that
request resolves. Recovery is what the default mode demonstrates.

## Reading a failure

| Symptom | Almost certainly |
|---|---|
| No lines at all after the first | Chrome is throttling the page's timers - the flag above is missing |
| `xhrTimeout` is `0` | the live-panel script no longer sets `hx-request` on `[data-live]` elements |
| Default mode never goes stale | the request bound is gone AND the watchdog is gone; `--unbounded` will fail too |
| `--unbounded` never goes stale, default mode is fine | the watchdog was removed and the page is relying on HTMX events alone - this is the regression the fixture exists for |
| Stale is reached but never cleared | `htmx:afterSwap` is no longer reaching `markFresh` |
| `no console templates under ...` | run it from a checkout, or pass `--repo-root` |

## Why this is not in CI

It would run on `ubuntu-latest`, which has Chrome preinstalled, so wiring it up is possible. It is
deliberately not wired up: it costs ~4 minutes of wall clock for two modes, and a wall-clock timing
assertion on a shared runner is a flake source in a gate whose whole design
([build-and-test](build-and-test.md)) is independent jobs that each fail for exactly one reason. The
committed template guard catches the likely regression - someone deleting the code - in the normal
suite. Run this fixture by hand when you touch the live-panel script in `base_tail.html`, the poll
markup in `fleet.html`, or the vendored `htmx.min.js`, and paste the timeline into the change.
