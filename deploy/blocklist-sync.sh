#!/usr/bin/env bash
#
# blocklist-sync.sh - publish the built feed into the public blocklist repo, split into
#   tiers/       aggressive.* standard.*      (block-this-now)
#   retention/   all-<window>.*               (active-in-the-last-N)
# with manifest.json and this directory's blocklist-README.md at the repo root, then commit and push.
#
# Runs on the honeypot node from cron, after the feed publisher's atomic swap. The split lives HERE,
# at the push - the publisher's flat output, the manifest contract, and the console are unchanged by
# design.
#
# Idempotent: a run with no new build makes no commit. Fail-closed: a missing, malformed or tampered
# feed output aborts before the repo is touched, so nothing but a complete build is ever pushed.
#
#   blocklist-sync.sh --check [FEED_DIR]
# runs every check on the build and stops there: nothing is committed or pushed and no checkout is
# needed. Exit 0 means the build would be published as it stands.
#
# Privilege boundary. The feed directory is written by the daemon, the process that parses every
# attacker byte, and this script reads it from a cron job. So everything in that directory is
# treated as chosen by an attacker who controls the daemon: a symlink or hard link under a feed
# name would have this script copy a file the daemon cannot read (a host key, the deploy key) into
# a public repo, a FIFO would hang it, and a link planted where it writes would have it overwrite
# any file. Run it as the dedicated propolis-blocklist account deploy/provision.sh creates, which
# can read the feed and nothing of root's (docs/operations/routine-procedures.md); and whichever
# account runs it, it copies only single-link regular files with the publisher's own names, opens
# each without following a link or blocking, checks it again after reading, and writes nothing in
# the daemon's tree.
#
# The same boundary covers what is IN the files. Consumers apply these files with `nft -f` and
# `ipset restore`, as root, on a timer: a file that held anything but the feed's own lines would be
# commands run on every consumer's firewall, and any file could carry data out of the node into a
# public repository. So every copy is read back and must be, line for line, what the publisher
# writes for that format and nothing else (check_content below): its fixed header, and addresses.
#
# Paths (override via environment; both feed and repo are auto-detected when unset):
#   PROPOLIS_FEED_OUTPUT_DIR      the publisher's flat output holding manifest.json
#   PROPOLIS_BLOCKLIST_REPO       the git checkout that is pushed        (default below)
#   PROPOLIS_BLOCKLIST_SSH_KEY    passphraseless deploy key used for the push (see below)
#   PROPOLIS_BLOCKLIST_STATUS_DIR where the last-pushed marker is written (default below)
set -euo pipefail
# stat's %F type names are translated under other locales.
export LC_ALL=C

# Where this script lives, so it can publish its sibling README alongside the feed.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The publisher's formats, one file per feed each (crates/feed/src/publisher.rs, write_tier); a
# test holds this list to the publisher's.
FORMATS=(txt json csv cidr ipset nft pf alias rpz)

# --check [FEED_DIR]: validate the build and stop. See the header.
CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then
  CHECK_ONLY=1
  if [ -n "${2:-}" ]; then PROPOLIS_FEED_OUTPUT_DIR="$2"; fi
elif [ "$#" -gt 0 ]; then
  echo "usage: blocklist-sync.sh [--check [FEED_DIR]]" >&2
  exit 2
fi
# The largest live file is about 1 MB (a 90-day JSON) and the whole build about 8 MB. 32 MiB a file
# stays under GitHub's 50 MB warning and 100 MB refusal; 256 MiB a build bounds what one run copies.
MAX_FILE_BYTES=$((32 * 1024 * 1024))
MAX_BUILD_BYTES=$((256 * 1024 * 1024))
# Retention windows are operator-configured (PROPOLIS_FEED_WINDOWS, five by default); this bounds
# how many file sets a tampered directory can make one run copy.
MAX_WINDOWS=16

# --- Push authentication ------------------------------------------------------------------------
# Cron has no ssh-agent, so a passphrase-protected key cannot be used non-interactively: the push
# hangs or fails while the same command run by hand succeeds against the operator's loaded agent.
# The historical fix was `git config core.sshCommand` inside the repo checkout, which is box-local
# state living outside version control - it has silently reverted more than once, each time turning
# the hourly publish back into a silent failure that only surfaced as a stale feed.
#
# So the key is named HERE, from the environment, and the script fails closed rather than letting
# ssh fall back to whatever identity happens to be available: a fallback that works interactively
# and fails under cron is the exact trap this is meant to remove.
KEY="${PROPOLIS_BLOCKLIST_SSH_KEY:-}"
if [ "$CHECK_ONLY" = 1 ]; then
  : # nothing is pushed, so no key is needed
elif [ -n "$KEY" ]; then
  if [ ! -r "$KEY" ]; then
    echo "blocklist-sync: PROPOLIS_BLOCKLIST_SSH_KEY=$KEY is not readable - refusing to push with" \
         "an unintended identity (interactive runs would silently succeed via an agent that cron" \
         "does not have)" >&2
    exit 1
  fi
  export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes"
elif [ -z "${SSH_AUTH_SOCK:-}" ] && [ ! -t 0 ]; then
  # Non-interactive, no agent, no explicit key: the classic cron configuration in which the push is
  # about to fail. Say so up front so the cause is in the log next to the failure, not inferred.
  echo "blocklist-sync: WARNING no PROPOLIS_BLOCKLIST_SSH_KEY set and no ssh-agent in this" \
       "environment; the push will fail if the remote needs a passphrase-protected key" >&2
fi

# One header per run. The log is append-only and shared by cron and by-hand runs, and without
# this a failure could not be attributed to either: which identity pushed, and whether a terminal
# was attached (cron never has one), is exactly what a stale-feed investigation needs first.
if [ -t 0 ]; then tty_state="tty"; else tty_state="no-tty"; fi
if [ "$CHECK_ONLY" = 0 ]; then
  echo "blocklist-sync: run $(date -Is) ${tty_state} identity=${KEY:-agent-or-default} uid=$(id -u)"
fi

# Root can still run it (a crontab from before the dedicated account), and the checks below hold
# for root too; but as root, any gap in them reaches every file on the host.
if [ "$CHECK_ONLY" = 0 ] && [ "$(id -u)" -eq 0 ]; then
  echo "blocklist-sync: WARNING running as root; run it as propolis-blocklist so the feed it" \
       "copies can never reach a file only root can read (docs/operations/routine-procedures.md)" >&2
fi

refuse() {
  echo "blocklist-sync: $* - refusing to push" >&2
  exit 1
}

# --- Resolve the feed source ------------------------------------------------------------------
# Prefer an explicit override; otherwise take whichever standard location actually holds a build.
# This tolerates both the documented `.../feed/current` and the older flat `.../feed` layout without
# guessing which this host uses.
SRC="${PROPOLIS_FEED_OUTPUT_DIR:-}"
if [ -z "$SRC" ]; then
  for cand in /var/lib/propolis/feed/current /var/lib/propolis/feed; do
    if [ -f "$cand/manifest.json" ]; then SRC="$cand"; break; fi
  done
fi
REPO="${PROPOLIS_BLOCKLIST_REPO:-/var/lib/propolis/blocklist-repo}"
STATUS_DIR="${PROPOLIS_BLOCKLIST_STATUS_DIR:-/var/lib/propolis/blocklist-status}"

# --- Validate (fail closed) -------------------------------------------------------------------
if [ -z "$SRC" ] || [ ! -f "$SRC/manifest.json" ]; then
  echo "blocklist-sync: no manifest.json under ${SRC:-<feed dir>} - feed not built, refusing to push" >&2
  exit 1
fi
if [ "$CHECK_ONLY" = 0 ] && [ ! -d "$REPO/.git" ]; then
  echo "blocklist-sync: $REPO is not a git checkout" >&2
  exit 1
fi
# Absolute, since the work below runs from inside the feed directory.
absolute() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
SRC="$(absolute "$SRC")"
REPO="$(absolute "$REPO")"
STATUS_DIR="$(absolute "$STATUS_DIR")"
# stat resolves a trailing slash through a final symlink, which would blind the identity check below.
while [ "${#SRC}" -gt 1 ] && [ "${SRC%/}" != "$SRC" ]; do SRC="${SRC%/}"; done

# Enter the feed directory once and work only on names relative to it, so the daemon swapping the
# path for a link afterwards changes nothing. The directory entered must be the one the path names
# itself: a path that is a symlink, or was swapped while being entered, compares unequal.
cd -- "$SRC" || refuse "cannot enter $SRC"
[ "$(stat -c %d:%i .)" = "$(stat -c %d:%i -- "$SRC")" ] \
  || refuse "$SRC is a symbolic link or was replaced while being entered"

# --- Check every name against the publisher's output ------------------------------------------
# The directory is exactly one publisher build (it is swapped in whole), so any other name means
# something else wrote here: the build is refused rather than published without it.
shopt -s nullglob dotglob
entries=( * )
shopt -u nullglob dotglob

format_pattern="$(IFS='|'; printf '%s' "${FORMATS[*]}")"
name_pattern="^(aggressive|standard|all-[1-9][0-9]{0,4}[hd])\\.(${format_pattern})\$"
declare -A present=() feeds=([aggressive]=1 [standard]=1)
for name in "${entries[@]}"; do
  if [ "$name" = manifest.json ]; then
    present[$name]=1
  elif [[ "$name" =~ $name_pattern ]]; then
    present[$name]=1
    feeds[${BASH_REMATCH[1]}]=1
  else
    refuse "unexpected entry $(printf '%q' "$name") in $SRC"
  fi
done

# Two tiers plus the retention windows.
if [ $(( ${#feeds[@]} - 2 )) -gt "$MAX_WINDOWS" ]; then
  refuse "$(( ${#feeds[@]} - 2 )) retention windows in $SRC, more than the $MAX_WINDOWS allowed"
fi
# Every feed present carries every format, as the publisher writes them; manifest.json is required.
for feed in "${!feeds[@]}"; do
  for f in "${FORMATS[@]}"; do
    [ -n "${present[$feed.$f]:-}" ] || refuse "$feed.$f missing from $SRC - malformed feed output"
  done
done
[ -n "${present[manifest.json]:-}" ] || refuse "manifest.json missing from $SRC"

# --- Copy each file safely --------------------------------------------------------------------
# Copies one feed file to `dest`. The type and link count are checked on the name before opening
# it, so a FIFO or device is not opened in the ordinary case. The read is then bound to the file
# that was checked: perl (perl-base, Essential on Debian) opens the name ONCE with O_NOFOLLOW (a
# symlink swapped in is never opened, so nothing at its target sees an open) and O_NONBLOCK (a FIFO
# swapped in cannot hold the open), takes the device and inode of that same handle with fstat,
# refuses unless they equal the pre-open stat (perl's st_dev is the raw dev_t, the number GNU stat
# prints as %d) and the handle is a regular file, and only then copies at most `max` bytes from it.
# A hard link swapped in around the open is a different inode and is refused even if the name is
# restored before the next look. The timeout covers only a filesystem that stalls an open. After
# the read the name must still match its check, and the copy must be the size checked.
copy_feed_file() {
  local name="$1" dest="$2" max="$3" checked after type links size id
  checked="$(stat -c '%F|%h|%s|%d:%i' -- "$name")" || return 1
  IFS='|' read -r type links size id <<<"$checked"
  case "$type" in
    "regular file"|"regular empty file") ;;
    *) echo "blocklist-sync: $name is a $type, not a regular file" >&2; return 1 ;;
  esac
  if [ "$links" != 1 ]; then
    echo "blocklist-sync: $name has $links hard links; a feed file has exactly one" >&2
    return 1
  fi
  if [ "$size" -gt "$max" ]; then
    echo "blocklist-sync: $name is $size bytes, over the $max-byte limit" >&2
    return 1
  fi
  # shellcheck disable=SC2016 # perl, not the shell, expands $ARGV and the other $ names here
  timeout 10 perl -e '
    use Fcntl;
    my ($name, $id, $dest, $max) = @ARGV;
    sysopen(my $in, $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or exit 1;
    my @st = stat($in);
    exit 3 unless @st && "$st[0]:$st[1]" eq $id && -f $in;
    sysopen(my $out, $dest, O_WRONLY | O_CREAT | O_EXCL, 0644) or exit 1;
    my ($left, $buf) = ($max, "");
    while ($left > 0) {
      my $n = sysread($in, $buf, $left < 1048576 ? $left : 1048576);
      exit 1 unless defined $n;
      last if $n == 0;
      for (my $off = 0; $off < $n; ) {
        my $w = syswrite($out, $buf, $n - $off, $off);
        exit 1 unless defined $w;
        $off += $w;
      }
      $left -= $n;
    }
    close($out) or exit 1;
  ' "$name" "$id" "$dest" "$max"
  local rc=$?
  case "$rc" in
    0) ;;
    3) echo "blocklist-sync: $name could not be opened as the file that was checked" >&2; return 1 ;;
    124) echo "blocklist-sync: opening $name did not finish within 10 s; refused" >&2; return 1 ;;
    127) echo "blocklist-sync: perl is not installed; it is required to copy feed files safely" >&2; return 1 ;;
    *) echo "blocklist-sync: $name could not be opened or copied (a link, a FIFO or an I/O error)" >&2; return 1 ;;
  esac
  after="$(stat -c '%F|%h|%s|%d:%i' -- "$name")" || return 1
  if [ "$after" != "$checked" ]; then
    echo "blocklist-sync: $name changed between its check and its copy" >&2
    return 1
  fi
  if [ "$(stat -c %s -- "$dest")" != "$size" ]; then
    echo "blocklist-sync: $name changed size while being copied" >&2
    return 1
  fi
}

# --- Check what each file holds ---------------------------------------------------------------
# One copy, already made and bound to the file that was checked, is read whole and held to its
# format: `check_content FILE FEED EXT`. FEED is the name the file's own text must carry (set and
# table names, headers). Exit 0 and nothing printed when the file is exactly what the publisher
# writes for that format (crates/feed/src/export/); otherwise one line on stderr naming the file,
# the line and what was expected, and exit 1. For manifest.json it prints `build_time <TS>` and one
# `window <label>` per retention window on stdout.
#
# The grammars are the exporters', restated: a test publishes real builds and runs them through
# `--check`, so a change to an exporter that this does not follow fails that test
# (crates/feed/tests/sync_check_test.rs). An address is one inet_pton accepts AND that is spelt
# the one way the publisher spells it (v6text below); a number has no leading zero; a timestamp
# is an hour boundary, which is all the feed ever states. Text that only means the same as what
# the publisher writes is refused too: "count":01 is not JSON, a resolver ignores an RPZ trigger
# that is not in canonical form, and either would break every consumer for as long as it stood.
#
# Only core perl: Socket is in perl-base, a JSON module is not, so the one-line JSON is walked
# with anchored matches.
# shellcheck disable=SC2016 # perl, not the shell, expands the $ names in this program
CHECK_CONTENT_PL='
use strict; use warnings;
use Socket qw(inet_pton AF_INET AF_INET6);
my ($path, $name, $ext) = @ARGV;
my $what = $ext eq "manifest" ? "manifest.json" : "$name.$ext";
sub bad { print STDERR "blocklist-sync: $what: $_[0]\n"; exit 1 }
open(my $fh, "<", $path) or bad("cannot be read back");
binmode($fh);
my $data = do { local $/; <$fh> };
close($fh);
$data = "" unless defined $data;
# Printable ASCII and newlines only (a tab too, which only nftables uses). No NUL, no CR, no
# escape sequence, nothing a terminal or a parser could read as something else.
if ($ext eq "nft") { bad("holds a byte that is not plain text") if $data =~ /[^\x09\x0a\x20-\x7e]/ }
else { bad("holds a byte that is not plain text") if $data =~ /[^\x0a\x20-\x7e]/ }

my $TS = qr/[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):00:00Z/;
my $OCTET = qr/(?:0|[1-9][0-9]{0,2})/;
# A count (at most nine digits) and a 32-bit counter (at most ten), as a number is printed.
my $N = qr/(?:0|[1-9][0-9]{0,8})/;
my $N32 = qr/(?:0|[1-9][0-9]{0,9})/;
sub v4 { my $s = shift; $s =~ /\A$OCTET(?:\.$OCTET){3}\z/ && defined inet_pton(AF_INET, $s) }
# The eight 16-bit groups of an IPv6 address, or nothing if the text is not one.
sub groups {
  my $s = shift;
  return unless $s =~ /\A[0-9a-f:.]{2,45}\z/ && $s =~ /:/;
  my $packed = inet_pton(AF_INET6, $s);
  return unless defined $packed;
  return unpack("n8", $packed);
}
# The run of zero groups that is written short: the longest of two or more, the first of equals.
sub zero_run {
  my ($at, $len, $start, $n) = (0, 0, 0, 0);
  for my $k (0 .. 7) {
    if ($_[$k] == 0) { $start = $k if $n == 0; $n++; ($at, $len) = ($start, $n) if $n > $len }
    else { $n = 0 }
  }
  return $len >= 2 ? ($at, $len) : ();
}
sub mapped { !grep({ $_ != 0 } @_[0 .. 4]) && $_[5] == 0xffff }
# An IPv6 address as the publisher prints it: RFC 5952, and an IPv4-mapped one with its last 32
# bits as a dotted quad.
sub v6text {
  return sprintf("::ffff:%d.%d.%d.%d", $_[6] >> 8, $_[6] & 255, $_[7] >> 8, $_[7] & 255) if mapped(@_);
  my @h = map { sprintf("%x", $_) } @_;
  my ($at, $len) = zero_run(@_);
  return join(":", @h) unless defined $at;
  return join(":", @h[0 .. $at - 1]) . "::" . join(":", @h[$at + $len .. 7]);
}
sub v6 { my @g = groups($_[0]); @g == 8 && v6text(@g) eq $_[0] }
sub ip { v4($_[0]) || v6($_[0]) }
# An address in a list or a set a firewall loads. The publisher writes an IPv4-mapped address
# there as the IPv4 address it maps, so the mapped form is never one of its lines.
sub v6_listed { my @g = groups($_[0]); @g == 8 && !mapped(@g) && v6text(@g) eq $_[0] }
sub listed { v4($_[0]) || v6_listed($_[0]) }
# The RPZ trigger owner the publisher writes for an IPv6 address: its groups in reverse, the
# zero run as the one label zz. A resolver ignores any other spelling of the same address.
sub rpz6 {
  my @h = map { sprintf("%x", $_) } @_;
  my ($at, $len) = zero_run(@_);
  splice(@h, $at, $len, "zz") if defined $at;
  return "128." . join(".", reverse @h);
}
sub rpz6_owner {
  my $owner = shift;
  $owner =~ /\A128((?:\.(?:[0-9a-f]{1,4}|zz)){1,8})\z/ or return 0;
  my @labels = reverse grep { length } split(/\./, $1);
  my $short = grep { $_ eq "zz" } @labels;
  return 0 if $short > 1 || (!$short && @labels != 8);
  my @g = map { $_ eq "zz" ? ((0) x (9 - @labels)) : hex($_) } @labels;
  return @g == 8 && !mapped(@g) && rpz6(@g) eq $owner;
}

if ($ext eq "json") {
  my $sig = qr/"[a-z0-9_]+"/;
  $data =~ /\A\{"meta":\{"generator":"propolis","tier":"\Q$name\E","generated":"$TS","valid_until":"$TS","count":($N)\},"entries":\[/gc
    or bad("does not start with the feed\x27s own meta block");
  my ($count, $seen) = ($1, 0);
  unless ($data =~ /\G\]\}\z/gc) {
    while (1) {
      $data =~ /\G\{"ip":"([0-9a-f:.]{2,45})","first_seen":"$TS","last_seen":"$TS","categories":$N32,"events":$N32,"signals":\[(?:$sig(?:,$sig)*)?\]\}/gc
        or bad("entry " . ($seen + 1) . " is not an entry the publisher writes");
      ip($1) or bad("entry " . ($seen + 1) . " does not name an address");
      $seen++;
      last if $data =~ /\G\]\}\z/gc;
      $data =~ /\G,/gc or bad("text after entry $seen that is not another entry");
    }
  }
  $seen == $count or bad("meta says $count entries and the file holds $seen");
  exit 0;
}
if ($ext eq "manifest") {
  my $H = qr/[0-9a-f]{64}/;
  my $T = qr/\{"count":$N,"sha256":"$H","valid_until":"$TS"\}/;
  my $W = qr/\{"label":"[1-9][0-9]{0,4}[hd]","count":$N,"sha256":"$H","valid_until":"$TS"\}/;
  $data =~ /\A\{"build_time":"($TS)","tiers":\{"aggressive":$T,"standard":$T\},"windows":\[((?:$W(?:,$W)*)?)\],"exclusions":\{"allowlist_count":$N,"delist_count":$N,"asn_allowlist_count":$N,"asn_db_loaded":(?:true|false)\}\}\z/
    or bad("is not a manifest the publisher writes");
  my ($build_time, $windows) = ($1, $2);
  print "build_time $build_time\n";
  print "window $1\n" while $windows =~ /"label":"([^"]+)"/g;
  exit 0;
}

# Every other format is lines, each ended by a newline.
bad("does not end with a newline") unless $data eq "" || substr($data, -1) eq "\n";
my @l = split(/\n/, $data, -1);
pop @l;
my $i = 0;
sub want { my ($text, $role) = @_; my $got = $l[$i]; (defined $got && $got eq $text) or bad("line " . ($i + 1) . " is not the $role"); $i++ }
sub want_re { my ($re, $role) = @_; my $got = $l[$i]; (defined $got && $got =~ $re) or bad("line " . ($i + 1) . " is not the $role"); $i++ }
sub rest_are { my ($ok, $role) = @_; for (; $i < @l; $i++) { $ok->($l[$i]) or bad("line " . ($i + 1) . " is not $role") } }

if ($ext eq "txt") {
  want("# Propolis blocklist - " . ucfirst($name) . " tier", "title line");
  want_re(qr/\A# Generated: $TS\z/, "Generated line");
  want_re(qr/\A# Valid until: $TS\z/, "Valid until line");
  ($l[$i] // "") =~ /\A# Entries: ($N)\z/ or bad("line 4 is not the Entries line");
  my $n = $1; $i++;
  @l - $i == $n or bad("says $n entries and lists " . (@l - $i));
  rest_are(\&listed, "an address as the publisher lists it");
} elsif ($ext eq "csv") {
  want("ip,first_seen,last_seen,categories,events,signals", "header row");
  rest_are(sub { $_[0] =~ /\A([0-9a-f:.]{2,45}),$TS,$TS,$N32,$N32,(?:[a-z0-9_]+(?:;[a-z0-9_]+)*)?\z/ && ip($1) }, "a row the publisher writes");
} elsif ($ext eq "cidr") {
  rest_are(sub { ($_[0] =~ /\A(.+)\/32\z/ && v4($1)) || ($_[0] =~ /\A(.+)\/128\z/ && v6_listed($1)) }, "a host route as the publisher lists it");
} elsif ($ext eq "alias") {
  rest_are(\&listed, "an address as the publisher lists it");
} elsif ($ext eq "pf") {
  want("# Propolis blocklist - $name tier", "title line");
  want_re(qr/\A# Generated: $TS\z/, "Generated line");
  rest_are(\&listed, "an address as the publisher lists it");
} elsif ($ext eq "ipset") {
  for my $f (["v4", "inet", \&v4], ["v6", "inet6", \&v6_listed]) {
    my ($suffix, $family, $ok) = @$f;
    my $live = "propolis_${name}_$suffix";
    my $params = "hash:ip family $family hashsize 4096 maxelem 1048576";
    want("create $live $params", "create of $live");
    want("create $live-new $params", "create of $live-new");
    want("flush $live-new", "flush of $live-new");
    while (defined $l[$i] && $l[$i] =~ /\Aadd \Q$live\E-new (\S+)\z/) {
      $ok->($1) or bad("line " . ($i + 1) . " adds something that is not an $family address");
      $i++;
    }
    want("swap $live-new $live", "swap into $live");
    want("destroy $live-new", "destroy of $live-new");
  }
  $i == @l or bad("line " . ($i + 1) . " is past the end of what the publisher writes");
} elsif ($ext eq "nft") {
  my ($s4, $s6) = ("propolis_${name}_v4", "propolis_${name}_v6");
  want($_, "set declaration") for (
    "table inet propolis {", "\tset $s4 {", "\t\ttype ipv4_addr", "\t}",
    "\tset $s6 {", "\t\ttype ipv6_addr", "\t}", "}",
    "flush set inet propolis $s4", "flush set inet propolis $s6");
  for my $f ([$s4, \&v4], [$s6, \&v6_listed]) {
    my ($set, $ok) = @$f;
    next unless defined $l[$i] && $l[$i] eq "add element inet propolis $set {";
    $i++;
    my $n = 0;
    while (defined $l[$i] && $l[$i] ne "}") {
      my $last = !defined $l[$i + 1] || $l[$i + 1] eq "}";
      my $re = $last ? qr/\A\t(\S+)\z/ : qr/\A\t(\S+),\z/;
      ($l[$i] =~ $re && $ok->($1)) or bad("line " . ($i + 1) . " is not an element of $set");
      $i++; $n++;
    }
    $n > 0 or bad("an add element for $set with no elements");
    want("}", "end of the elements of $set");
  }
  $i == @l or bad("line " . ($i + 1) . " is past the end of what the publisher writes");
} elsif ($ext eq "rpz") {
  want("; Propolis RPZ - $name tier", "title line");
  # The serial is the build hour the Generated line states, as YYYYMMDDHH. Any ten digits would
  # admit a serial no resolver loads (it has to fit 32 bits).
  my $serial = ($l[$i] // "") =~ /\A; Generated: ([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):/ ? "$1$2$3$4" : "";
  want_re(qr/\A; Generated: $TS\z/, "Generated line");
  want("\$TTL 300", "TTL line");
  want("\@ IN SOA localhost. hostmaster.localhost. $serial 3600 600 86400 300", "SOA record with the build hour as its serial");
  want("\@ IN NS localhost.", "NS record");
  rest_are(sub {
    my $t = $_[0];
    return 1 if $t =~ /\A32\.($OCTET)\.($OCTET)\.($OCTET)\.($OCTET)\.rpz-ip CNAME \.\z/ && $1 < 256 && $2 < 256 && $3 < 256 && $4 < 256;
    return $t =~ /\A(128\.[0-9a-fz.]+)\.rpz-ip CNAME \.\z/ && rpz6_owner($1);
  }, "an address trigger as the publisher writes it");
} else {
  bad("has no content rule; add one before publishing a new format");
}
exit 0;
'
check_content() {
  perl -e "$CHECK_CONTENT_PL" "$1" "$2" "$3"
  local rc=$?
  case "$rc" in
    0) return 0 ;;
    127) echo "blocklist-sync: perl is not installed; it is required to check feed files" >&2; return 1 ;;
    *) return 1 ;;
  esac
}

# Copies land in a private directory inside the checkout's .git (same filesystem, never committed)
# and move into the work tree only once all of them passed, so a refusal leaves the repo untouched.
# A --check run has no checkout and stages under the temporary directory instead.
if [ "$CHECK_ONLY" = 1 ]; then
  stage="$(mktemp -d "${TMPDIR:-/tmp}/blocklist-check.XXXXXX")"
else
  stage="$(mktemp -d "$REPO/.git/blocklist-sync.XXXXXX")"
fi
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/tiers" "$stage/retention"
total=0
for name in "${!present[@]}"; do
  case "$name" in
    manifest.json) dest="$stage/manifest.json" ;;
    all-*) dest="$stage/retention/$name" ;;
    *) dest="$stage/tiers/$name" ;;
  esac
  copy_feed_file "$name" "$dest" "$MAX_FILE_BYTES" || refuse "$name in $SRC failed its checks"
  total=$(( total + $(stat -c %s -- "$dest") ))
  [ "$total" -le "$MAX_BUILD_BYTES" ] || refuse "the build in $SRC is over $MAX_BUILD_BYTES bytes"
done

# Every copy is now the bytes that will be pushed. Hold each to its format (see check_content).
# The manifest names the build hour and the retention windows this build carries, which must be
# exactly the all-* feeds present: a window file the manifest does not vouch for is not published.
manifest_facts="$(check_content "$stage/manifest.json" "" manifest)" \
  || refuse "manifest.json in $SRC is not what the publisher writes"
build_time=""
declare -A manifest_windows=()
while read -r key value; do
  case "$key" in
    build_time) build_time="$value" ;;
    window) manifest_windows["all-$value"]=1 ;;
  esac
done <<<"$manifest_facts"
[ -n "$build_time" ] || refuse "manifest.json in $SRC names no build time"
for feed in "${!feeds[@]}"; do
  case "$feed" in
    all-*) [ -n "${manifest_windows[$feed]:-}" ] \
             || refuse "$feed is in $SRC but manifest.json does not list that window" ;;
  esac
done
for feed in "${!manifest_windows[@]}"; do
  [ -n "${feeds[$feed]:-}" ] || refuse "manifest.json lists window $feed and $SRC has no such feed"
done
for name in "${!present[@]}"; do
  case "$name" in
    manifest.json) continue ;;
    all-*) staged="$stage/retention/$name" ;;
    *) staged="$stage/tiers/$name" ;;
  esac
  check_content "$staged" "${name%.*}" "${name##*.}" \
    || refuse "$name in $SRC is not what the publisher writes for that format"
done

if [ "$CHECK_ONLY" = 1 ]; then
  echo "blocklist-sync: $SRC holds a complete build ($build_time, ${#feeds[@]} feeds) that passes every check"
  exit 0
fi

# --- Arrange the repo layout ------------------------------------------------------------------
# tiers/ and retention/ are this script's own and are replaced whole, so the published tree is
# exactly this build. Moving the new files over the old ones left behind every file the build no
# longer has: a retention window the operator removed, a format the publisher dropped, each one
# frozen at its last contents and still fetched by consumers who never learn it stopped changing.
# Everything else in the checkout (README, LICENSE, whatever the operator keeps there) is left
# alone. With no retention window the empty directory simply drops out of the commit.
cd -- "$REPO"
rm -rf -- tiers retention
mv -- "$stage/tiers" tiers
mv -- "$stage/retention" retention
mv -f -- "$stage/manifest.json" manifest.json

# Keep the repo's public README in sync with the packaged one, so the layout docs and raw-URL
# examples never drift from what this script actually publishes.
if [ -f "$SCRIPT_DIR/blocklist-README.md" ]; then
    cp -f "$SCRIPT_DIR/blocklist-README.md" README.md
fi

# Drop any stale FLAT feed files the pre-folder layout left at the repo root, so the repo converges
# on tiers/ + retention/ instead of carrying both copies. Matches only feed filenames; manifest.json,
# README, and LICENSE are untouched.
find . -maxdepth 1 -type f \( -name 'aggressive.*' -o -name 'standard.*' -o -name 'all-*.*' \) -delete

# --- Commit & push ----------------------------------------------------------------------------
# The commit is public, so it says nothing the feed does not already say. Left to itself git signs
# a commit with a name and address it makes up from the account and the machine's host name, and
# dates it to the second in the node's own time zone: the host name of a honeypot, where it is,
# and when its cron job runs. Instead:
#   - the author is the identity set in this checkout (`git config user.name` / `user.email`
#     there) if the operator set one, and otherwise a fixed neutral one. Nothing is guessed, and
#     an identity in the environment or the account's global config is not used;
#   - the date is the build hour from the manifest, in UTC: the same hour every feed file states.
# `build_time` was checked above to be exactly an hour boundary, so it is safe in the message.
git add -A
if git diff --cached --quiet; then
  echo "blocklist-sync: no new build to commit"
else
  commit_name="$(git config --local --get user.name || true)"
  commit_email="$(git config --local --get user.email || true)"
  GIT_AUTHOR_NAME="${commit_name:-propolis-blocklist}" \
  GIT_AUTHOR_EMAIL="${commit_email:-propolis-blocklist@users.noreply.invalid}" \
  GIT_COMMITTER_NAME="${commit_name:-propolis-blocklist}" \
  GIT_COMMITTER_EMAIL="${commit_email:-propolis-blocklist@users.noreply.invalid}" \
  GIT_AUTHOR_DATE="$build_time" GIT_COMMITTER_DATE="$build_time" TZ=UTC \
    git commit -q -m "feed: $build_time"
fi

# Records the push time for the daemon's `feed-push-stale` condition, which pages when the local
# feed has moved on from the last successful push - the one failure the daemon's own feed health
# cannot see, since this script runs outside it. The path is the one the condition reads
# (crates/propolis/src/ops_alert/conditions/feed.rs, PUSH_MARKER_PATH), in a directory only this
# account writes: never the daemon's tree, where a link it planted would redirect the write. A
# directory others can write is refused for the same reason. Written to a fresh temporary name and
# renamed over the marker, which replaces whatever entry is there rather than following it.
write_marker_files() {
  local dir="$1" tmp
  tmp="$(mktemp "$dir/.last-pushed.XXXXXX")" || return 1
  if printf 'blocklist-sync last-pushed marker\n' >"$tmp" && chmod 0644 -- "$tmp" \
     && mv -f -T -- "$tmp" "$dir/last-pushed"; then
    return 0
  fi
  rm -f -- "$tmp"
  return 1
}
export -f write_marker_files

# A root run (a crontab from before the dedicated account) cannot write the marker as itself: the
# directory belongs to propolis-blocklist and must stay that way, and root writing in a directory
# another account controls is the redirect this layout exists to prevent. So root drops to the
# directory's owner for the write, which then reaches nothing the owner could not already write.
write_push_marker() {
  local owner group mode me
  me="$(id -u)"
  [ -d "$STATUS_DIR" ] && [ ! -L "$STATUS_DIR" ] || return 1
  read -r owner group mode < <(stat -c '%u %g %a' -- "$STATUS_DIR") || return 1
  if (( 8#$mode & 8#022 )); then return 1; fi
  if [ "$owner" = "$me" ]; then
    write_marker_files "$STATUS_DIR"
  elif [ "$me" = 0 ]; then
    command -v setpriv >/dev/null 2>&1 || return 1
    # shellcheck disable=SC2016 # expanded by the child bash, which receives the directory as "$1"
    setpriv --reuid="$owner" --regid="$group" --clear-groups --no-new-privs -- \
      bash -c 'write_marker_files "$1"' write_marker_files "$STATUS_DIR"
  else
    return 1
  fi
}

# Always attempt the push, even when nothing new was committed: an earlier run may have committed
# locally but FAILED to push (the classic cause is cron having no SSH agent for the git remote), and
# a "no new changes -> skip push" flow would strand that commit forever. `git push` is a clean no-op
# when the branch is already up to date, and ships any stranded commit otherwise.
if git push -q origin HEAD; then
  echo "blocklist-sync: pushed (HEAD $(git rev-parse --short HEAD))"
  # A marker failure must not fail a successful push.
  if ! write_push_marker; then
    echo "blocklist-sync: WARNING could not update push marker $STATUS_DIR/last-pushed (the" \
         "directory must exist, be owned by this account (or by the account root can drop to, with" \
         "setpriv installed) and be writable by no one else);" \
         "the daemon's feed-push-stale condition will read this push as not having happened" >&2
  fi
else
  echo "blocklist-sync: git push FAILED - the local commit is not on the remote. Under cron this is" \
       "almost always missing SSH auth (no agent / passphrase key). See the deploy README." >&2
  exit 1
fi
