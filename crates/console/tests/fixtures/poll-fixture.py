#!/usr/bin/env python3
"""Behavioural acceptance fixture for the console's stale-poll handling.

WHY THIS IS NOT A `#[test]`. The bug it guards is a browser behaviour, not a Rust one: a status
poll that the server ACCEPTS and then never answers fires no htmx error and no htmx timeout, so a
panel goes on presenting a reading it took minutes ago as the current one. Reproducing that needs a
real XHR in a real browser against a real hung socket. `templates.rs`'s
`a_polled_panel_bounds_its_request_and_ages_itself_without_waiting_for_an_event` checks that the
guarding code still SHIPS in the page; this checks that it still WORKS. Run it by hand whenever the
live-panel script in `base_tail.html`, the poll markup in `fleet.html`, or the vendored
`htmx.min.js` changes.

WHAT IT SERVES. One page, built from this repo's own unmodified `htmx.min.js` and the live-panel
IIFE lifted verbatim out of `base_tail.html` - nothing about the behaviour under test is restated
here, so the fixture cannot drift into passing against code the console does not ship. The page
polls `/fleet/status`, which is held open (headers sent, body never finished) until
`recover-after-seconds`, and answers normally after that. The page reports its own observable state
back once a second and this prints the timeline whenever it changes.

TWO MODES, because there are two independent mechanisms to check:

* Default: the per-request timeout the live-panel script sets bounds the hang, so the panel goes
  stale one timeout after the poll starts.
* `?unbounded=1`: that bound is neutralised in the page, leaving the age watchdog as the only thing
  that can notice. This is the mode that fails if the watchdog is ever removed in favour of relying
  on htmx's events alone.

RUNNING IT.

    python3 crates/console/tests/fixtures/poll-fixture.py --launch-chrome
    python3 crates/console/tests/fixtures/poll-fixture.py --launch-chrome --unbounded

Or drive the browser yourself, which is worth doing at least once - the banner is meant to be read
by an operator, so read it:

    python3 crates/console/tests/fixtures/poll-fixture.py
    google-chrome --headless=new --disable-background-timer-throttling \\
        --user-data-dir=$(mktemp -d) http://127.0.0.1:8733/

`--disable-background-timer-throttling` matters: a headless window is never foregrounded, and
Chrome throttles `setInterval` in a backgrounded page to roughly once a minute, which stalls both
htmx's polling and the watchdog and makes the timeline meaningless.

See `docs/development/browser-fixtures.md` for the expected output and how to read a failure.
"""

import argparse
import http.server
import json
import pathlib
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

# .../crates/console/tests/fixtures/poll-fixture.py -> repository root
REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--repo-root", type=pathlib.Path, default=REPO_ROOT, help="defaults to this file's repository")
parser.add_argument("--port", type=int, default=8733)
parser.add_argument("--run-seconds", type=int, default=130, help="how long to serve before exiting")
parser.add_argument(
    "--recover-after-seconds",
    type=int,
    default=80,
    help="when /fleet/status stops hanging and starts answering, so the run also shows recovery",
)
parser.add_argument(
    "--unbounded",
    action="store_true",
    help="neutralise the per-request timeout in the page, leaving the watchdog as the only detector",
)
parser.add_argument("--launch-chrome", action="store_true", help="start headless Chrome against the fixture")
args = parser.parse_args()

TEMPLATES = args.repo_root / "crates/console/src/templates"
if not (TEMPLATES / "base_tail.html").is_file():
    sys.exit(f"no console templates under {TEMPLATES} - pass --repo-root")

# The behaviour under test, taken from the shipped page rather than restated here.
tail = (TEMPLATES / "base_tail.html").read_text()
start = tail.index("// A polled panel")
LIVE_SCRIPT = tail[start : tail.index("</script>", start)]
HTMX = (TEMPLATES / "htmx.min.js").read_text()

STARTED = time.monotonic()

PAGE_TMPL = """<!doctype html><html><head><meta charset="utf-8"><title>poll fixture</title></head><body>
<main>
<div id="fleet-status" data-live="fleet reading" hx-get="/fleet/status" hx-trigger="every 30s" hx-swap="innerHTML">
  <p>Listeners proven: 1 / 1</p>
  <p>Probed: just now</p>
</div>
</main>
<script>__HTMX__</script>
<script>__LIVE__</script>
<script>
window.__events = [];
window.__xhrTimeout = null;
['htmx:timeout','htmx:sendError','htmx:responseError','htmx:afterSwap'].forEach(function (n) {
  document.body.addEventListener(n, function () { window.__events.push(n); });
});
document.body.addEventListener('htmx:beforeSend', function (e) {
  window.__xhrTimeout = e.detail.xhr.timeout;
});
// `?unbounded=1` neutralises the per-request bound, leaving the watchdog as the ONLY thing that
// can notice the hang - the half of the fix this mode exists to exercise.
if (location.search.indexOf('unbounded=1') >= 0) {
  document.getElementById('fleet-status').setAttribute('hx-request', '{"timeout": 600000}');
}
setInterval(function () {
  var el = document.getElementById('fleet-status');
  var b = document.getElementById('stale-banner-fleet-status');
  fetch('/observe?d=' + encodeURIComponent(JSON.stringify({
    stale: el.getAttribute('data-stale') || null,
    hxRequest: el.getAttribute('hx-request'),
    xhrTimeout: window.__xhrTimeout,
    events: window.__events.join(','),
    banner: b ? b.textContent.slice(0, 140) : null,
    body: el.textContent.replace(/\\s+/g, ' ').trim().slice(0, 60)
  })));
}, 1000);
</script>
</body></html>"""

PAGE = PAGE_TMPL.replace("__HTMX__", HTMX).replace("__LIVE__", LIVE_SCRIPT).encode()

last = None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body, ctype="text/html; charset=utf-8"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global last
        t = time.monotonic() - STARTED
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/fleet/status":
            if t < args.recover_after_seconds:
                # Accepted, then held: headers sent, the promised body never written. This is the
                # case that produces no htmx event of any kind when the request is unbounded.
                print("[%6.1fs] /fleet/status accepted and HELD open" % t, flush=True)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                while time.monotonic() - STARTED < args.run_seconds + 5:
                    time.sleep(0.5)
                return
            print("[%6.1fs] /fleet/status answered normally" % t, flush=True)
            return self._send(b"<p>Listeners proven: 1 / 1</p><p>Probed: just now</p>")

        if parsed.path == "/observe":
            d = json.loads(urllib.parse.parse_qs(parsed.query)["d"][0])
            # Only transitions are printed; a second-by-second dump buries them.
            key = (d["stale"], d["events"], d["hxRequest"], d["xhrTimeout"])
            if key != last:
                last = key
                print("[%6.1fs] %s" % (t, json.dumps(d)), flush=True)
            return self._send(b"ok", "text/plain")

        return self._send(PAGE)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def launch_chrome(url):
    exe = next((p for p in ("google-chrome", "chromium", "chromium-browser") if shutil.which(p)), None)
    if not exe:
        sys.exit("no chrome/chromium on PATH - start a browser against the URL above by hand")
    profile = tempfile.mkdtemp(prefix="poll-fixture-chrome-")
    print("launching %s (throwaway profile %s)" % (exe, profile), flush=True)
    return subprocess.Popen(
        [
            exe,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            # Without these, Chrome throttles the never-foregrounded page's timers and neither the
            # poll nor the watchdog runs on the schedule the timeline is read against.
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--window-size=1280,900",
            "--user-data-dir=" + profile,
            url,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ), profile


url = "http://127.0.0.1:%d/%s" % (args.port, "?unbounded=1" if args.unbounded else "")
chrome = profile = None

with Server(("127.0.0.1", args.port), Handler) as httpd:
    print(
        "fixture on %s  (%s; holds the poll for %ds, then answers; exits after %ds)"
        % (
            url,
            "watchdog only - per-request bound neutralised" if args.unbounded else "per-request bound active",
            args.recover_after_seconds,
            args.run_seconds,
        ),
        flush=True,
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        if args.launch_chrome:
            chrome, profile = launch_chrome(url)
        time.sleep(args.run_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        if chrome:
            chrome.terminate()
            # Wait for it to actually exit: Chrome keeps writing to its profile until it does, and
            # removing the directory underneath a live process leaves most of it behind.
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
                chrome.wait(timeout=15)
            shutil.rmtree(profile, ignore_errors=True)
    print("done", flush=True)
