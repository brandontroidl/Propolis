#!/usr/bin/env bash
# shellcheck disable=SC2034 # the PA_* variables are this library's output, read by its callers
#
# The shared library of the shell alerting code, to be sourced by the failure hook's record step,
# the witness, the status command and config-check, and installed as
# /usr/local/sbin/propolis-alert-lib. Sourced, never executed. It sets no shell options and no
# trap (a trap set here would replace the caller's), and defines functions and PA_* variables
# only. Every function returns a status and works under the caller's `set -u` and `set -e`
# without relying on either.
#
# WHY ONE LIBRARY. Four programs read the same env files, state files, lock and ids. Four copies
# of the env reader or of the state-file format would drift, and a drift here is silent: one
# program would page about a state another reads as healthy. So each rule is written once.
#
# WHAT IT HOLDS. The env reader that trims the way systemd's EnvironmentFile= does (pa_env_get) and
# the alert target settings; the host role; salted opaque ids and the fallback host alias, so no
# push can name a unit, a log or a host; the checkers every state field and push line pass; time
# stamps that survive a clock step (WALL/BOOT/UP: within a boot, ages come from uptime); a read
# as the account that owns a file, for paths another account can write; the trust check for a
# program root is about to run; atomic 0600 writes; the one state lock; state files that fall
# back to /run when the disk refuses a write; the PROPOLIS_SENSOR_LOGS grammar.
#
# TEMPORARY FILES. A function that makes one appends its path to PA_CLEANUP. Each caller's single
# EXIT handler runs pa_cleanup, which removes them.
#
# PATHS AND SEAMS. pa_init ROOT puts every path under ROOT (empty in production); each caller
# will pass the test root its own tests give it. Tests only:
# PA_TEST_WALL, PA_TEST_BOOT and PA_TEST_UP, all three together, replace the clock and the boot;
# PA_TEST_READ_AS_SELF=1 makes pa_read_as and pa_stat_as read as the caller, which they also do
# whenever the uid is not 0, since setpriv cannot change uid without root; PA_TEST_UID stands for
# that uid, honoured only under a non-empty ROOT (no unit passes one), so the drop's command line
# is tested whether the tests run as root or not.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then echo "alert-lib.sh is sourced, not run" >&2; exit 64; fi

# Raised by every change that adds a function or a field. Functions are only ever added and never
# change meaning, so a newer library serves an older consumer. Nothing reads the number yet: the
# rollback script will compare it with what each consumer needs before it restores an older
# library.
PA_LIB_VERSION=1
# The optional env file of the shell senders; the deploy tests will derive the sensors' denied set
# from this name.
PA_ALERT_ENV_NAME=alert.env

# Writers trim incidents to 192 KiB; readers accept up to 1 MiB, so a file a writer produced is
# never thrown away as too large.
PA_INCIDENTS_MAX=196608
PA_STATE_MAX=1048576
# The state files pa_state_read and pa_state_write handle, all at major version 1.
PA_STATE_NAMES="incidents send-ledger readcheck meta observe testpage"

# Internal state never comes from the environment: an inherited PA_LOCK_FD would make pa_lock
# skip the lock, and an inherited PA_CLEANUP would make pa_cleanup delete a path someone else
# chose. A value this shell set itself, before sourcing again, is kept. Bash cannot export an
# array, so an inherited PA_CLEANUP is always a scalar.
for _PA_V in PA_LOCK_FD _PA_UNREADABLE_LOGGED; do
    if [[ $(declare -p "$_PA_V" 2> /dev/null) =~ ^declare\ -[a-zA-Z]*x ]]; then unset "$_PA_V"; fi
done
unset _PA_V
PA_LOCK_FD="${PA_LOCK_FD:-}"
_PA_UNREADABLE_LOGGED="${_PA_UNREADABLE_LOGGED:-}"
if [[ $(declare -p PA_CLEANUP 2> /dev/null) != 'declare -a'* ]]; then
    unset PA_CLEANUP
    PA_CLEANUP=()
fi

# ---- loading ---------------------------------------------------------------------------------

# pa_init ROOT: every path under ROOT, and umask 077 so nothing the library creates is readable by
# another account. Reads and writes nothing.
pa_init() {
    PA_ROOT="${1:-}"
    PA_STATE="$PA_ROOT/var/lib/propolis/witness"
    PA_RUN="$PA_ROOT/run/propolis-witness"
    PA_ENV_DIR="$PA_ROOT/etc/propolis"
    PA_MOTD="$PA_ROOT/run/motd.d"
    PA_WHERE=""
    PA_STAMP=""
    PA_STATE_UNREADABLE=""
    umask 077
}

# pa_cleanup: removes every file listed in PA_CLEANUP. Never fails, so an EXIT handler keeps the
# caller's status.
pa_cleanup() {
    local f
    for f in "${PA_CLEANUP[@]}"; do
        [ -z "$f" ] || rm -f -- "$f" 2> /dev/null || true
    done
    PA_CLEANUP=()
    return 0
}

# ---- checkers ----------------------------------------------------------------------------------
#
# Glob patterns under LC_ALL=C, not regular expressions: a range then means bytes in every locale
# and whatever the caller's globasciiranges, so a multibyte character (a bidi override among them)
# never passes as ASCII.

# pa_ok_field S: what a state-file field may hold.
pa_ok_field() {
    local LC_ALL=C
    [ "${#1}" -ge 1 ] && [ "${#1}" -le 128 ] && [[ $1 != *[!A-Za-z0-9._:@#/+=,%-]* ]]
}

# pa_ok_line S: what a rendered push line may hold, printable ASCII and at most 200 bytes.
pa_ok_line() {
    local LC_ALL=C
    [ "${#1}" -le 200 ] && [[ $1 != *[!\ -~]* ]]
}

# pa_plain_id S: a name found where another account writes, printable only if it passes.
pa_plain_id() {
    local LC_ALL=C
    [ "${#1}" -ge 1 ] && [ "${#1}" -le 64 ] && [[ $1 != *[!A-Za-z0-9._-]* ]]
}

# pa_clean_untrusted MAX LINES: stdin made safe to show a person. Every byte outside printable
# ASCII becomes `?`, which also removes Unicode format characters without a table of them; each
# line is cut to MAX bytes, at most LINES lines are kept, and each is marked. sed reads to the end
# of its input, so a long input never ends the pipeline on SIGPIPE.
pa_clean_untrusted() {
    [[ ${1:-} =~ ^[1-9][0-9]{0,5}$ && ${2:-} =~ ^[1-9][0-9]{0,5}$ ]] || return 2
    LC_ALL=C tr -c '\040-\176\n' '?' | LC_ALL=C cut -b "1-$1" | LC_ALL=C sed -n "1,$2s/^/[untrusted] /p"
}

# _pa_ascii S: printable ASCII only (an empty string passes).
_pa_ascii() {
    local LC_ALL=C
    [[ $1 != *[!\ -~]* ]]
}

# ---- the env reader and the settings -----------------------------------------------------------

# pa_env_get KEY FILE...: the value systemd's EnvironmentFile= gives KEY when the files load in
# the order given (the last assignment in the last file that has one). Blank lines and lines whose
# first non-blank character is # or ; are skipped; `KEY = value` is read too (config-check's old
# env_file_value missed it). Spaces, tabs and CR around the value are stripped and one pair of
# matching quotes removed. A backslash, or a quote that is not that one surrounding pair, means
# systemd may read the line differently than this does, so the raw value is printed and
# PA_ENV_COMPLEX=1 tells the caller to report it. So does a chosen line that systemd does not read
# on its own: one the line before it runs into (that line ends in an escaping backslash, or leaves
# a quote open, see _pa_env_scan), one after a comment line ending in a backslash (systemd before
# v254 joined the two), and one cut out of a longer line by a CR, which systemd takes as the end
# of a line. An unreadable file counts as absent and sets PA_ENV_UNREADABLE to its name.
#
# Prints the value, and also sets PA_ENV_VALUE and PA_ENV_SRC (the file that assigned it): the
# flags only reach a caller that calls this directly, not one that reads its output through $().
pa_env_get() {
    local key="$1" f phys line t k v raw="" src="" found="" q inner joined=0 st sw own bs
    local -a pieces
    local ws=$' \t\r'
    shift
    PA_ENV_VALUE="" PA_ENV_SRC="" PA_ENV_COMPLEX=0 PA_ENV_UNREADABLE=""
    for f in "$@"; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        if [ ! -f "$f" ] || [ ! -r "$f" ]; then
            [ -n "$PA_ENV_UNREADABLE" ] || PA_ENV_UNREADABLE="$f"
            continue
        fi
        # st: what the line before left behind. k: nothing, this line stands on its own. v: an
        # unquoted value this line continues. s, d: a single or double quote still open. c: a
        # comment that ended in a backslash.
        st=k
        while IFS= read -r phys || [ -n "$phys" ]; do
            pieces=("$phys")
            case "$phys" in *$'\r'*) IFS=$'\r' read -r -a pieces <<< "$phys" ;; esac
            [ "${#pieces[@]}" -gt 0 ] || pieces=("")
            for line in "${pieces[@]}"; do
                # sw: systemd does not read this line on its own. own: it starts a new entry.
                sw=0 own=1
                [ "${#pieces[@]}" -eq 1 ] || sw=1
                case "$st" in
                    k) ;;
                    c) sw=1 st=k ;;
                    *)
                        sw=1 own=0
                        _pa_env_scan "$st" "$line"
                        st="$_PA_ENV_NEXT"
                        ;;
                esac
                t="${line#"${line%%[!"$ws"]*}"}"
                case "$t" in
                    '#'* | ';'*)
                        if [ "$own" = 1 ]; then
                            bs="${t##*[!\\]}"
                            [ $((${#bs} % 2)) -eq 0 ] || st=c
                        fi
                        continue
                        ;;
                    *=*) ;;
                    *) continue ;;
                esac
                v="${t#*=}"
                if [ "$own" = 1 ]; then
                    _pa_env_scan p "$v"
                    st="$_PA_ENV_NEXT"
                fi
                k="${t%%=*}"
                k="${k%"${k##*[!"$ws"]}"}"
                [ "$k" = "$key" ] || continue
                v="${v#"${v%%[!"$ws"]*}"}"
                v="${v%"${v##*[!"$ws"]}"}"
                raw="$v" src="$f" found=1 joined="$sw"
            done
        done < "$f"
    done
    [ -n "$found" ] || return 0
    v="$raw"
    [ "$joined" = 0 ] || PA_ENV_COMPLEX=1
    case "$v" in
        *\\*) PA_ENV_COMPLEX=1 ;;
        \"*\" | \'*\')
            q="${v:0:1}"
            inner="${v:1:${#v}-2}"
            case "$inner" in
                *"$q"*) PA_ENV_COMPLEX=1 ;;
                *) v="$inner" ;;
            esac
            ;;
        *[\"\']*) PA_ENV_COMPLEX=1 ;;
    esac
    [ "$PA_ENV_COMPLEX" = 0 ] || v="$raw"
    PA_ENV_VALUE="$v" PA_ENV_SRC="$src"
    printf '%s' "$v"
}

# _pa_env_scan MODE TEXT: what one line leaves behind for the next, in _PA_ENV_NEXT (k, v, s or d
# as in pa_env_get), by the value states of systemd's env-file.c. MODE is where TEXT starts: p
# before a value, v inside an unquoted one, s or d inside single or double quotes. In an unquoted
# value and inside double quotes a backslash takes the next character, the newline included, so a
# line ending in one runs into the next. Inside single quotes only the closing quote is special.
# A value may close one quote and open another, and once an unquoted value has begun a quote is
# an ordinary character.
_pa_env_scan() {
    local m="$1" t="$2" i c bs
    if [ "$m" = v ] || { [ "$m" = p ] && [[ $t != *[\"\']* ]]; }; then
        bs="${t##*[!\\]}"
        _PA_ENV_NEXT=k
        [ $((${#bs} % 2)) -eq 0 ] || _PA_ENV_NEXT=v
        return 0
    fi
    # e and f: the character after a backslash, in an unquoted value and inside double quotes.
    for ((i = 0; i < ${#t}; i++)); do
        c="${t:i:1}"
        case "$m" in
            p)
                case "$c" in
                    \') m=s ;;
                    \") m=d ;;
                    \\) m=e ;;
                    ' ' | $'\t') ;;
                    *) m=v ;;
                esac
                ;;
            v) [ "$c" != \\ ] || m=e ;;
            e) m=v ;;
            s) [ "$c" != \' ] || m=p ;;
            d)
                case "$c" in
                    \") m=p ;;
                    \\) m=f ;;
                esac
                ;;
            f) m=d ;;
        esac
    done
    case "$m" in
        p | v) _PA_ENV_NEXT=k ;;
        e) _PA_ENV_NEXT=v ;;
        s) _PA_ENV_NEXT=s ;;
        *) _PA_ENV_NEXT=d ;;
    esac
}

_pa_valid_url() {
    local re='^https?://[^[:space:]/]+(/[^[:space:]]*)?$'
    _pa_ascii "$1" && [[ $1 =~ $re ]]
}

_pa_valid_topic() {
    local LC_ALL=C
    [ "${#1}" -ge 1 ] && [ "${#1}" -le 64 ] && [[ $1 != *[!A-Za-z0-9_-]* ]]
}

_pa_valid_token() {
    local LC_ALL=C
    [ "${#1}" -ge 1 ] && [ "${#1}" -le 256 ] && [[ $1 != *[!!-~]* ]]
}

# _pa_setting VAR KEY CHECK FILE...: VAR from KEY when CHECK passes, else empty with KEY added to
# PA_INVALID. A line systemd may read differently is invalid too: the value used here could
# differ from the one the daemon gets. Sets _PA_SETTING_SRC to the file that assigned it.
_pa_setting() {
    local var="$1" key="$2" check="$3"
    shift 3
    printf -v "$var" '%s' ""
    _PA_SETTING_SRC=""
    pa_env_get "$key" "$@" > /dev/null
    [ -n "$PA_ENV_VALUE" ] || return 0
    if [ "$PA_ENV_COMPLEX" = 0 ] && "$check" "$PA_ENV_VALUE"; then
        printf -v "$var" '%s' "$PA_ENV_VALUE"
        _PA_SETTING_SRC="$PA_ENV_SRC"
    else
        PA_INVALID="${PA_INVALID:+$PA_INVALID }$key"
    fi
}

# pa_settings_load: the shell senders' ntfy target. Only propolis.env is read until the senders
# that honour alert.env exist, so the target is the daemon's (PA_D_*) as well. The target exists
# (PA_TARGET=1) only when URL and topic are both valid and come from the same file; PA_INVALID
# names every key that was set to an invalid value and ignored.
pa_settings_load() {
    local env="$PA_ENV_DIR/propolis.env" url_src topic_src
    PA_INVALID="" PA_TARGET=0 PA_TARGET_SRC=""
    _pa_setting PA_URL PROPOLIS_OPS_NTFY_URL _pa_valid_url "$env"
    url_src="$_PA_SETTING_SRC"
    PA_URL="${PA_URL%/}"
    _pa_setting PA_TOPIC PROPOLIS_OPS_NTFY_TOPIC _pa_valid_topic "$env"
    topic_src="$_PA_SETTING_SRC"
    _pa_setting PA_TOKEN PROPOLIS_OPS_NTFY_TOKEN _pa_valid_token "$env"
    if [ -n "$PA_URL" ] && [ -n "$PA_TOPIC" ] && [ "$url_src" = "$topic_src" ]; then
        PA_TARGET=1
        PA_TARGET_SRC="${url_src##*/}"
    fi
    PA_D_URL="$PA_URL" PA_D_TOPIC="$PA_TOPIC" PA_D_TARGET="$PA_TARGET"
    return 0
}

# ---- role --------------------------------------------------------------------------------------

# pa_role: collector, control, single, gateway or unknown, from which units are enabled.
pa_role() {
    local p=0 g=0
    if systemctl is-enabled --quiet propolis.service 2> /dev/null; then p=1; fi
    if systemctl is-enabled --quiet gateway.service 2> /dev/null; then g=1; fi
    if [ -e "$PA_ENV_DIR/shipper.env" ] && [ "$p" = 0 ]; then
        printf 'collector'
    elif [ "$p" = 1 ] && [ "$g" = 1 ]; then
        printf 'control'
    elif [ "$p" = 1 ]; then
        printf 'single'
    elif [ "$g" = 1 ]; then
        printf 'gateway'
    else
        printf 'unknown'
    fi
}

# ---- salt, ids and the alias -------------------------------------------------------------------
#
# Ids are keyed on a secret salt: the shipped log labels are a short list, so an unsalted hash of
# them could be reversed by anyone reading the topic.

# _pa_sha256 PART...: the hex sha256 of the parts joined by NUL bytes.
_pa_sha256() {
    local h
    h="$({
        printf '%s' "$1"
        shift
        for p in "$@"; do printf '\0%s' "$p"; done
    } | sha256sum)" || return 1
    printf '%s' "${h%% *}"
}

# _pa_salt: prints the salt, or fails when it is absent or damaged.
_pa_salt() {
    local s=""
    [ -f "$PA_STATE/id-salt" ] || return 1
    { IFS= read -r s < "$PA_STATE/id-salt"; } 2> /dev/null || [ -n "$s" ] || return 1
    [[ $s =~ ^[0-9a-f]{32}$ ]] || return 1
    printf '%s' "$s"
}

# pa_salt_ensure: creates the salt once, from /dev/urandom. The caller holds the lock. A valid salt
# is never replaced: that would rename every id.
pa_salt_ensure() {
    local s
    _pa_salt > /dev/null && return 0
    s="$(od -An -N16 -tx1 /dev/urandom 2> /dev/null | tr -d ' \n')" || return 1
    [[ $s =~ ^[0-9a-f]{32}$ ]] || return 1
    pa_write "$PA_STATE/id-salt" < <(printf '%s\n' "$s")
}

_pa_id_prefix() {
    case "$1" in
        unit) printf u ;;
        source) printf s ;;
        collector) printf c ;;
        vendor) printf v ;;
        mount) printf m ;;
        finding) printf f ;;
        *) return 1 ;;
    esac
}

# pa_id KIND NAME: <prefix><5 hex> of sha256(salt NUL KIND NUL NAME); `-` and status 1 without a
# salt, status 2 for an unknown kind. Senders take ids from pa_id_table, which widens collisions.
pa_id() {
    local prefix salt h
    prefix="$(_pa_id_prefix "$1")" || return 2
    if ! salt="$(_pa_salt)"; then
        printf -- '-'
        return 1
    fi
    h="$(_pa_sha256 "$salt" "$1" "$2")" || return 1
    printf '%s%s' "$prefix" "${h:0:5}"
}

# pa_id_table: reads `kind<TAB>name` lines (the configured instances the caller found) and prints
# `id<TAB>kind<TAB>name` for each, once, in input order. Two names of one kind whose 5-hex ids
# collide both get 8 hex digits, so no id ever stands for two instances. Unknown kinds are skipped.
pa_id_table() {
    local salt kind name prefix h key i w
    local -a kinds=() names=() hashes=()
    local -A seen=() count=()
    salt="$(_pa_salt)" || return 1
    while IFS=$'\t' read -r kind name _ || [ -n "$kind" ]; do
        _pa_id_prefix "$kind" > /dev/null || continue
        [ -n "$name" ] || continue
        key="$kind/$name"
        [ -z "${seen[$key]+set}" ] || continue
        seen[$key]=1
        h="$(_pa_sha256 "$salt" "$kind" "$name")" || return 1
        kinds+=("$kind")
        names+=("$name")
        hashes+=("$h")
        key="$kind/${h:0:5}"
        count[$key]=$((${count[$key]:-0} + 1))
    done
    for i in "${!kinds[@]}"; do
        h="${hashes[$i]}"
        key="${kinds[$i]}/${h:0:5}"
        w=5
        [ "${count[$key]}" -lt 2 ] || w=8
        prefix="$(_pa_id_prefix "${kinds[$i]}")"
        printf '%s%s\t%s\t%s\n' "$prefix" "${h:0:$w}" "${kinds[$i]}" "${names[$i]}"
    done
}

# _pa_alias_ok A: the shape, and neither the host's names nor a word that says what it runs.
_pa_alias_ok() {
    local a="$1" h hs
    local LC_ALL=C
    [[ ${#a} -ge 3 && ${#a} -le 32 && $a == [a-z]* && $a != *[!a-z0-9-]* ]] || return 1
    case "$a" in *propolis* | *honey*) return 1 ;; esac
    h="$(hostname 2> /dev/null)" || h=""
    hs="$(hostname -s 2> /dev/null)" || hs=""
    [ "$a" != "${h,,}" ] && [ "$a" != "${hs,,}" ]
}

# pa_alias: the host's name on the channel. PA_ALIAS_SET (read from PROPOLIS_OPS_HOST_ALIAS by the
# settings once the daily message exists) when it passes _pa_alias_ok; otherwise host- and 4 hex
# of sha256(salt NUL "alias"), which never involves the hostname. Sets PA_ALIAS, and
# PA_ALIAS_REJECTED=1 when a set alias was refused. Status 1 without a salt.
pa_alias() {
    local salt h
    PA_ALIAS="" PA_ALIAS_REJECTED=0
    if [ -n "${PA_ALIAS_SET:-}" ]; then
        if _pa_alias_ok "$PA_ALIAS_SET"; then
            PA_ALIAS="$PA_ALIAS_SET"
            printf '%s' "$PA_ALIAS"
            return 0
        fi
        PA_ALIAS_REJECTED=1
    fi
    if ! salt="$(_pa_salt)"; then
        PA_ALIAS="-"
        printf -- '-'
        return 1
    fi
    h="$(_pa_sha256 "$salt" alias)" || return 1
    PA_ALIAS="host-${h:0:4}"
    printf '%s' "$PA_ALIAS"
}

# pa_ref: a random 6-hex pointer reference, tied to nothing.
pa_ref() {
    local r
    r="$(od -An -N3 -tx1 /dev/urandom 2> /dev/null | tr -d ' \n')" || return 1
    [[ $r =~ ^[0-9a-f]{6}$ ]] || return 1
    printf '%s' "$r"
}

# ---- time --------------------------------------------------------------------------------------
#
# A stamp is WALL/BOOT/UP: epoch seconds, the first 8 hex of the boot id, whole seconds of uptime.
# Within one boot an age comes from uptime, which a clock step cannot move; across boots only the
# wall clock is left. An unreadable boot id is `-`, which never matches, so such ages use the wall
# clock too.

# pa_now: sets PA_WALL, PA_BOOT, PA_UP and PA_STAMP.
pa_now() {
    local b="" u=""
    if [ -n "${PA_TEST_WALL:-}" ] && [ -n "${PA_TEST_BOOT:-}" ] && [ -n "${PA_TEST_UP:-}" ]; then
        PA_WALL="$PA_TEST_WALL" PA_BOOT="$PA_TEST_BOOT" PA_UP="$PA_TEST_UP"
    else
        PA_WALL="$(date +%s)"
        b="$(tr -d - 2> /dev/null < /proc/sys/kernel/random/boot_id)" || b=""
        read -r u _ 2> /dev/null < /proc/uptime || u=""
        u="${u%%.*}"
        PA_BOOT="${b:0:8}" PA_UP="$u"
        [[ $PA_BOOT =~ ^[0-9a-f]{8}$ && $PA_UP =~ ^[0-9]{1,10}$ ]] || PA_BOOT="-" PA_UP=0
    fi
    PA_STAMP="$PA_WALL/$PA_BOOT/$PA_UP"
}

# _pa_stamp_split STAMP: sets _PA_W, _PA_B and _PA_U, or fails on a malformed stamp.
_pa_stamp_split() {
    [[ $1 =~ ^([0-9]{1,12})/([0-9a-f]{8}|-)/([0-9]{1,10})$ ]] || return 1
    _PA_W="${BASH_REMATCH[1]}" _PA_B="${BASH_REMATCH[2]}" _PA_U="${BASH_REMATCH[3]}"
}

# pa_age STAMP: seconds since STAMP; -1 when it is malformed or in the future. A budget window
# treats -1 as expired and a reminder as not yet due, so a clock fault can only allow a send.
pa_age() {
    local a
    [ -n "${PA_STAMP:-}" ] || pa_now
    if ! _pa_stamp_split "${1:-}"; then
        printf -- '-1'
        return 0
    fi
    if [ "$_PA_B" != - ] && [ "$_PA_B" = "$PA_BOOT" ]; then
        a=$((10#$PA_UP - 10#$_PA_U))
    else
        a=$((10#$PA_WALL - 10#$_PA_W))
    fi
    [ "$a" -ge 0 ] || a=-1
    printf '%s' "$a"
}

# pa_clock_check: compares the time now with meta's `clock`. Within one boot, wall time and uptime
# that moved more than 120 s apart mean the clock was stepped; that is recorded as `clock_step`
# (<stamp>/<signed seconds>). Then `clock` is stored. The caller holds the lock.
pa_clock_check() {
    local prev step sign=""
    [ -n "${PA_STAMP:-}" ] || pa_now
    prev="$(_pa_meta_get clock)"
    if _pa_stamp_split "$prev" && [ "$_PA_B" != - ] && [ "$_PA_B" = "$PA_BOOT" ]; then
        step=$(((10#$PA_WALL - 10#$_PA_W) - (10#$PA_UP - 10#$_PA_U)))
        if [ "$step" -gt 120 ] || [ "$step" -lt -120 ]; then
            [ "$step" -lt 0 ] || sign=+
            _pa_meta_set clock_step "$PA_STAMP/$sign$step" clock "$PA_STAMP"
            return
        fi
    fi
    _pa_meta_set clock "$PA_STAMP"
}

# pa_hms WALL: HH:MM:SS in UTC, `?` for anything but epoch seconds.
pa_hms() {
    if [[ ${1:-} =~ ^[0-9]{1,12}$ ]] && date -u -d "@$1" +%H:%M:%S 2> /dev/null; then
        return 0
    fi
    printf '?'
}

# pa_dur SECONDS: `44 min`, `2 h 31 min` or `3 d`; `?` for anything but a whole number.
pa_dur() {
    local s="${1:-}" h m
    if ! [[ $s =~ ^[0-9]{1,12}$ ]]; then
        printf '?'
        return 0
    fi
    s=$((10#$s))
    if [ "$s" -lt 3600 ]; then
        printf '%s min' "$((s / 60))"
    elif [ "$s" -lt 86400 ]; then
        h=$((s / 3600)) m=$((s % 3600 / 60))
        if [ "$m" = 0 ]; then printf '%s h' "$h"; else printf '%s h %s min' "$h" "$m"; fi
    else
        printf '%s d' "$((s / 86400))"
    fi
}

# ---- reading as another account ----------------------------------------------------------------

# _pa_as USER CMD...: CMD under `timeout 5`, as USER with exactly USER's own groups (the readers
# reach sensor logs only through supplementary groups), and without the state-lock descriptor,
# so a process running as another account never holds root's lock.
_pa_as() {
    local user="$1" uid gid me="$UID"
    shift
    [ -z "${PA_ROOT:-}" ] || me="${PA_TEST_UID:-$UID}"
    if [ "$me" != 0 ] || [ "${PA_TEST_READ_AS_SELF:-}" = 1 ]; then
        set -- timeout 5 "$@"
    else
        uid="$(id -u -- "$user" 2> /dev/null)" || return 1
        gid="$(id -g -- "$user" 2> /dev/null)" || return 1
        set -- timeout 5 setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- "$@"
    fi
    if [[ $PA_LOCK_FD =~ ^[0-9]+$ ]]; then
        _pa_without_fds "$@" {PA_LOCK_FD}>&-
    else
        _pa_without_fds "$@"
    fi
}

# _pa_without_fds CMD...: CMD with stdin and stderr on /dev/null and every descriptor above 2
# closed.
# Once setpriv makes the real uid the target's, the child can be traced by any process of that
# account, which could then take whatever root left open in it: the operator's terminal during
# an interactive walk, or a file the caller opened.
_pa_without_fds() {
    (
        for fd in /proc/self/fd/*; do
            fd="${fd##*/}"
            if [[ $fd =~ ^[0-9]+$ ]] && [ "$fd" -gt 2 ]; then eval "exec $fd>&-"; fi
        done 2> /dev/null
        exec "$@"
    ) < /dev/null 2> /dev/null
}

# pa_read_as USER FILE MAX: prints at most MAX bytes of FILE, read as USER, for a path another
# account can write. 0 read; 3 not a regular file, or a link; 4 larger than MAX; 5 timeout (a FIFO
# swapped in after the check blocks the open until then); 1 otherwise. With MAX=0 it is the
# readability test: nothing printed, 0 when USER can open and read a byte, 6 when it cannot.
#
# The type check runs in the caller (root in production), without following a link. Run as USER
# it would fail on a regular file USER cannot reach, and a reader that lost the group of a 0750
# log directory would be reported as a planted link (3) instead of unreadable (6). The child
# checks again for a swap after this check.
pa_read_as() {
    local rc
    [[ ${3:-} =~ ^[0-9]{1,12}$ ]] || return 1
    [ -f "$2" ] && [ ! -L "$2" ] || return 3
    # shellcheck disable=SC2016 # the child bash expands these, with the file as $1 and the cap as $2
    local prog='[ -L "$1" ] && exit 3
[ -f "$1" ] || { [ "$2" -eq 0 ] && exit 6; exit 1; }
if [ "$2" -eq 0 ]; then [ -r "$1" ] && head -c 1 -- "$1" > /dev/null 2>&1 && exit 0; exit 6; fi
s=$(stat -c %s -- "$1") || exit 1
[ "$s" -le "$2" ] || exit 4
exec head -c "$2" -- "$1"'
    _pa_as "$1" bash -c "$prog" _ "$2" "$3"
    rc=$?
    case "$rc" in
        0 | 3 | 4 | 6) return "$rc" ;;
        124) return 5 ;;
        *) return 1 ;;
    esac
}

# pa_stat_as USER FMT PATH: `stat -c FMT` without -L, as USER. 5 on timeout.
pa_stat_as() {
    local rc
    _pa_as "$1" stat -c "$2" -- "$3"
    rc=$?
    [ "$rc" -ne 124 ] || return 5
    return "$rc"
}

# _pa_trust_one PATH UID: PATH owned by UID and not writable by group or other.
_pa_trust_one() {
    local u a o g
    if ! read -r u a o g < <(stat -c '%u %a %U %G' -- "$1" 2> /dev/null); then
        PA_UNTRUSTED="$1: cannot be checked"
        return 1
    fi
    if [ "$u" != "$2" ]; then
        PA_UNTRUSTED="$1: not owned by root ($o:$g $a)"
    elif ((8#$a & 8#020)); then
        PA_UNTRUSTED="$1: group-writable ($o:$g $a)"
    elif ((8#$a & 8#002)); then
        PA_UNTRUSTED="$1: world-writable ($o:$g $a)"
    else
        return 0
    fi
    return 1
}

# pa_trusted_exec PATH: true when PATH is a regular file, not a link, and it and every directory
# passed through to reach it are owned by root and writable by nobody else: otherwise anyone who
# can write one of them can replace what a root timer runs. PATH is resolved one component at a
# time, the way the kernel resolves it, and each directory is checked as it is entered. A symbolic
# link among the directories is followed and its target resolved the same way, links inside that
# target included, so the directory holding every link on the way is checked: whoever can write it
# can point the link elsewhere after the check. On failure PA_UNTRUSTED names the first path that
# failed and why, for the caller to print. Under a test root (pa_init given one) that root's owner
# stands for root and the directories above the root are not checked.
pa_trusted_exec() {
    local path="$1" top="" owner=0 cur=/ base rest comp entry target hops=0
    PA_UNTRUSTED=""
    if [ -n "${PA_ROOT:-}" ]; then
        if ! top="$(cd -P -- "$PA_ROOT" 2> /dev/null && pwd -P)"; then
            PA_UNTRUSTED="$PA_ROOT: missing"
            return 1
        fi
        owner="$(stat -c %u -- "$top" 2> /dev/null)" || owner=0
    fi
    if [ -L "$path" ]; then
        PA_UNTRUSTED="$path: a symbolic link"
        return 1
    fi
    if [ ! -f "$path" ]; then
        PA_UNTRUSTED="$path: not a regular file"
        return 1
    fi
    case "$path" in
        /*) ;;
        *) path="$(pwd -P)/$path" ;;
    esac
    rest="${path#/}"
    if [ -n "$top" ]; then
        base="${PA_ROOT%/}"
        case "$path" in
            "$base"/*) cur="$top" rest="${path#"$base"/}" ;;
        esac
    fi
    # cur: the directory reached so far, with no link in it. rest: what is still to be resolved.
    _pa_trust_dir "$cur" "$owner" "$top" || return 1
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        case "$rest" in
            */*) rest="${rest#*/}" ;;
            *) rest="" ;;
        esac
        case "$comp" in
            '' | .) continue ;;
            ..) cur="$(dirname -- "$cur")" ;;
            *)
                entry="${cur%/}/$comp"
                if [ -L "$entry" ]; then
                    if [ -z "$rest" ]; then
                        PA_UNTRUSTED="$entry: a symbolic link"
                        return 1
                    fi
                    hops=$((hops + 1))
                    if [ "$hops" -gt 40 ] || ! target="$(readlink -- "$entry")"; then
                        PA_UNTRUSTED="$entry: too many levels of symbolic links"
                        return 1
                    fi
                    case "$target" in /*) cur=/ ;; esac
                    rest="${target#/}/$rest"
                elif [ -d "$entry" ]; then
                    cur="$entry"
                elif [ -z "$rest" ] && [ -f "$entry" ]; then
                    _pa_trust_one "$entry" "$owner"
                    return
                else
                    PA_UNTRUSTED="$entry: not a regular file"
                    return 1
                fi
                ;;
        esac
        _pa_trust_dir "$cur" "$owner" "$top" || return 1
    done
    PA_UNTRUSTED="$path: not a regular file"
    return 1
}

# _pa_trust_dir DIR OWNER TOP: DIR passes _pa_trust_one. Under a test root (TOP) the directories
# above that root are the test's surroundings and pass unchecked.
_pa_trust_dir() {
    # The prefix goes through a variable: bash 5.2 does not match "${1%/}"/* when $1 is /.
    local above="${1%/}"
    if [ -n "$3" ]; then
        case "$3" in "$above"/*) return 0 ;; esac
    fi
    _pa_trust_one "$1" "$2"
}

# ---- writes, the lock and the state files ------------------------------------------------------

# _pa_trim_incidents FILE: trims FILE to PA_INCIDENTS_MAX bytes, dropping withheld (W) lines
# oldest first, then resolved records oldest first by their resolve time. Open, acked and pending
# records are never dropped, so a file of those alone is left over the size.
_pa_trim_incidents() {
    local f="$1" size drop
    size="$(stat -c %s -- "$f" 2> /dev/null)" || return 1
    [ "$size" -gt "$PA_INCIDENTS_MAX" ] || return 0
    drop="$(
        LC_ALL=C awk -F '\t' '
            function wall(s,  p) { split(s, p, "/"); return (p[1] ~ /^[0-9]+$/) ? p[1] + 0 : 0 }
            $1 == "W" { print 0, wall($2), NR, length($0) + 1 }
            $1 == "I" && $8 == "resolved" { print 1, wall($22), NR, length($0) + 1 }
        ' "$f" | sort -k1,1n -k2,2n -k3,3n \
            | awk -v over=$((size - PA_INCIDENTS_MAX)) 'got < over { print $3; got += $4 }'
    )" || return 1
    PA_CLEANUP+=("$f.trim")
    LC_ALL=C awk 'NR == FNR { d[$1]; next } !(FNR in d)' <(printf '%s\n' "$drop") "$f" > "$f.trim" \
        && chmod 0600 -- "$f.trim" && mv -f -T -- "$f.trim" "$f"
}

# _pa_fits FILE: FILE is no larger than readers accept.
_pa_fits() {
    local s
    s="$(stat -c %s -- "$1" 2> /dev/null)" && [ "$s" -le "$PA_STATE_MAX" ]
}

# pa_write PATH: writes stdin to PATH as PATH.tmp.<pid>, mode 0600 whatever the umask, then
# renames it over PATH, so a reader sees the old file or the new one, never half of one. A file
# named `incidents` is trimmed first. Returns 1 and removes the temporary file when any step fails
# (ENOSPC, EROFS), and when the file is larger than readers accept (open records alone can
# outgrow the trim): a write a reader would throw away keeps the old file instead. The caller
# holds the lock.
#
# The temporary file is flushed (`sync FILE` fsyncs it, coreutils 8.24 and later) before the
# rename publishes it. XFS, and ext4 mounted noauto_da_alloc, do not flush on rename, so without
# it a power cut soon after could leave an empty state file or id-salt, and a new salt renames
# every id. The directory is flushed after the rename so the rename itself lasts.
pa_write() {
    local path="$1" tmp
    tmp="$path.tmp.$$"
    PA_CLEANUP+=("$tmp")
    if { cat > "$tmp"; } 2> /dev/null && chmod 0600 -- "$tmp" 2> /dev/null \
        && { [ "${path##*/}" != incidents ] || _pa_trim_incidents "$tmp" 2> /dev/null; } \
        && _pa_fits "$tmp" && sync -- "$tmp" 2> /dev/null \
        && mv -f -T -- "$tmp" "$path" 2> /dev/null; then
        sync -- "${path%/*}" 2> /dev/null || true
        return 0
    fi
    rm -f -- "$tmp" "$tmp.trim" 2> /dev/null
    return 1
}

# pa_lock WAIT: takes the state lock on PA_LOCK_FD, waiting at most WAIT seconds. The persistent
# lock file is opened read-only (enough for flock, so it works on a full disk); when it cannot be
# opened, /run's, created 0600 if needed. Both are root:root 0600 so no other account can hold the
# lock and wedge every root writer. 1 on timeout, 2 when no lock file can be opened, 3 when this
# shell already holds it: pa_unlock is not counted, so a nested lock and unlock would release the
# lock the outer caller still relies on. Only the outermost owner locks and unlocks.
pa_lock() {
    local wait="${1:-10}"
    [[ $wait =~ ^[0-9]{1,4}$ ]] || wait=10
    [[ ! $PA_LOCK_FD =~ ^[0-9]+$ ]] || return 3
    if ! { exec {PA_LOCK_FD}< "$PA_STATE/state.lock"; } 2> /dev/null; then
        if [ ! -e "$PA_RUN/state.lock" ]; then
            { (umask 077 && : >> "$PA_RUN/state.lock") && chmod 0600 -- "$PA_RUN/state.lock"; } 2> /dev/null
        fi
        if ! { exec {PA_LOCK_FD}< "$PA_RUN/state.lock"; } 2> /dev/null; then
            PA_LOCK_FD=""
            return 2
        fi
    fi
    if flock -w "$wait" "$PA_LOCK_FD" 2> /dev/null; then
        return 0
    fi
    pa_unlock
    return 1
}

# pa_unlock: closes the lock descriptor, which releases the lock.
pa_unlock() {
    if [[ $PA_LOCK_FD =~ ^[0-9]+$ ]]; then
        exec {PA_LOCK_FD}>&-
    fi
    PA_LOCK_FD=""
    return 0
}

_pa_state_name() {
    case " $PA_STATE_NAMES " in *" $1 "*) return 0 ;; esac
    return 1
}

# _pa_state_unreadable FILE NAME WHY: the reader starts empty and NAME is added to
# PA_STATE_UNREADABLE. A reader that holds the lock also keeps the file as FILE.unreadable.<wall>
# (only the newest such copy) and logs one line. A lockless reader (the walk) writes nothing: its
# rename could also move aside a good file a locked writer had just put in its place. When the
# rename fails (a read-only disk), that is logged once per process, so every later read does not
# repeat it.
_pa_state_unreadable() {
    local f="$1" dest old
    case " ${PA_STATE_UNREADABLE:-} " in
        *" $2 "*) ;;
        *) PA_STATE_UNREADABLE="${PA_STATE_UNREADABLE:+$PA_STATE_UNREADABLE }$2" ;;
    esac
    [[ ${PA_LOCK_FD:-} =~ ^[0-9]+$ ]] || return 0
    [ -n "${PA_STAMP:-}" ] || pa_now
    dest="$f.unreadable.$PA_WALL"
    if mv -f -T -- "$f" "$dest" 2> /dev/null; then
        for old in "$f".unreadable.*; do
            [ "$old" = "$dest" ] || [ ! -e "$old" ] || rm -f -- "$old" 2> /dev/null
        done
        logger -p daemon.notice -t propolis-witness \
            "state file $2 is unreadable ($3); kept as ${dest##*/}, starting empty" 2> /dev/null || true
        return 0
    fi
    case " $_PA_UNREADABLE_LOGGED " in *" $f "*) return 0 ;; esac
    _PA_UNREADABLE_LOGGED="${_PA_UNREADABLE_LOGGED:+$_PA_UNREADABLE_LOGGED }$f"
    logger -p daemon.notice -t propolis-witness \
        "state file $2 is unreadable ($3) and could not be set aside; starting empty" 2> /dev/null || true
}

# _pa_state_load FILE NAME: sets _PA_G to the file's generation (-1 when absent or unreadable)
# and _PA_BODY to its lines after the header.
_pa_state_load() {
    local f="$1" name="$2" size content head why=""
    local re="^#$name v([0-9]+) g=([0-9]{1,18})\$"
    _PA_G=-1 _PA_BODY=""
    [ -e "$f" ] || [ -L "$f" ] || return 0
    if [ -L "$f" ] || [ ! -f "$f" ]; then
        why="not a regular file"
    elif ! size="$(stat -c %s -- "$f" 2> /dev/null)" || [ ! -r "$f" ]; then
        why="cannot be read"
    elif [ "$size" -gt "$PA_STATE_MAX" ]; then
        why="larger than 1 MiB"
    elif ! content="$(cat -- "$f" 2> /dev/null)"; then
        why="cannot be read"
    else
        head="${content%%$'\n'*}"
        if [[ ! $head =~ $re ]]; then
            why="no header"
        elif [ "${BASH_REMATCH[1]}" != 1 ]; then
            why="unknown major version ${BASH_REMATCH[1]}"
        else
            _PA_G=$((10#${BASH_REMATCH[2]}))
            if [ "$head" != "$content" ]; then
                _PA_BODY="${content#*$'\n'}"
            fi
            return 0
        fi
    fi
    _pa_state_unreadable "$f" "$name" "$why"
}

# pa_state_read NAME: prints the lines after the header of state file NAME, from the persistent
# copy or the /run fallback, whichever has the higher generation. A missing file reads as empty,
# and so does an unreadable one (see _pa_state_unreadable). Readers take fields with
# `IFS=$'\t' read -r type f1 ... _`, so fields a newer minor revision appends land in `_` and are
# ignored.
pa_state_read() {
    local name="$1" ga body
    _pa_state_name "$name" || return 2
    _pa_state_load "$PA_STATE/$name" "$name"
    ga="$_PA_G" body="$_PA_BODY"
    _pa_state_load "$PA_RUN/fallback/$name" "$name"
    [ "$_PA_G" -le "$ga" ] || body="$_PA_BODY"
    [ -z "$body" ] || printf '%s\n' "$body"
}

# pa_state_write NAME: writes stdin as the body of state file NAME, with the header's generation
# one above both copies'. It tries the persistent directory first and, when that refuses
# (a full or read-only disk), /run's fallback, setting PA_WHERE to persistent, run or none. A
# persistent write removes the fallback copy, whose content the caller read through
# pa_state_read. The caller holds the lock.
pa_state_write() {
    local name="$1" body ga content
    _pa_state_name "$name" || return 2
    body="$(cat)"
    _pa_state_load "$PA_STATE/$name" "$name"
    ga="$_PA_G"
    _pa_state_load "$PA_RUN/fallback/$name" "$name"
    [ "$_PA_G" -le "$ga" ] || ga="$_PA_G"
    [ "$ga" -ge 0 ] || ga=0
    content="#$name v1 g=$((ga + 1))"$'\n'
    [ -z "$body" ] || content+="$body"$'\n'
    if pa_write "$PA_STATE/$name" < <(printf '%s' "$content"); then
        PA_WHERE=persistent
        rm -f -- "$PA_RUN/fallback/$name" 2> /dev/null
        return 0
    fi
    if { [ -d "$PA_RUN/fallback" ] || mkdir -m 0700 -- "$PA_RUN/fallback"; } 2> /dev/null \
        && pa_write "$PA_RUN/fallback/$name" < <(printf '%s' "$content"); then
        PA_WHERE=run
        return 0
    fi
    PA_WHERE=none
    return 1
}

# _pa_meta_get KEY: the value of `M<TAB>KEY<TAB>value` in meta (the last one), or nothing.
_pa_meta_get() {
    local t k v out=""
    while IFS=$'\t' read -r t k v _; do
        if [ "$t" = M ] && [ "$k" = "$1" ]; then out="$v"; fi
    done < <(pa_state_read meta)
    printf '%s' "$out"
}

# _pa_meta_set KEY VALUE [KEY VALUE...]: sets the keys in one write. Other lines are kept as they
# are, record types this version does not know included. A value that fails pa_ok_field is
# stored as `?`. The caller holds the lock.
_pa_meta_set() {
    local line out="" k skip i
    local -a keys=() values=()
    while [ "$#" -ge 2 ]; do
        keys+=("$1")
        if pa_ok_field "$2"; then values+=("$2"); else values+=("?"); fi
        shift 2
    done
    while IFS= read -r line; do
        skip=""
        for k in "${keys[@]}"; do
            case "$line" in "M"$'\t'"$k"$'\t'*) skip=1 ;; esac
        done
        [ -n "$skip" ] || out+="$line"$'\n'
    done < <(pa_state_read meta)
    for i in "${!keys[@]}"; do
        out+="M"$'\t'"${keys[$i]}"$'\t'"${values[$i]}"$'\n'
    done
    pa_state_write meta < <(printf '%s' "$out")
}

# ---- sensor logs -------------------------------------------------------------------------------

# _pa_trim_ws S: sets _PA_T to S without the characters Rust's str::trim removes at either end,
# which are Unicode White_Space: the ASCII ones and 19 others, matched here as their UTF-8 bytes.
# A label trimmed any other way would hash to an id the daemon's label does not have.
_pa_trim_ws() {
    local s="$1" w more=1
    local LC_ALL=C
    local ws=$' \t\n\v\f\r'
    local -a u=($'\xc2\x85' $'\xc2\xa0' $'\xe1\x9a\x80' $'\xe2\x80\x80' $'\xe2\x80\x81'
        $'\xe2\x80\x82' $'\xe2\x80\x83' $'\xe2\x80\x84' $'\xe2\x80\x85' $'\xe2\x80\x86'
        $'\xe2\x80\x87' $'\xe2\x80\x88' $'\xe2\x80\x89' $'\xe2\x80\x8a' $'\xe2\x80\xa8'
        $'\xe2\x80\xa9' $'\xe2\x80\xaf' $'\xe2\x81\x9f' $'\xe3\x80\x80')
    while [ "$more" = 1 ]; do
        more=0
        s="${s#"${s%%[!"$ws"]*}"}"
        s="${s%"${s##*[!"$ws"]}"}"
        for w in "${u[@]}"; do
            if [[ $s == "$w"* ]]; then s="${s#"$w"}" more=1; fi
            if [[ $s == *"$w" ]]; then s="${s%"$w"}" more=1; fi
        done
    done
    _PA_T="$s"
}

# pa_sensor_logs VALUE: the daemon's PROPOLIS_SENSOR_LOGS grammar
# (crates/log-tailer/src/sensor_logs.rs parse_sensor_logs): comma separated, each entry trimmed,
# blank entries skipped, split on the first colon, both halves non-empty. Sets PA_LOG_LABEL and
# PA_LOG_PATH for the good entries, PA_LOG_BAD and PA_LOG_BAD_WHY for the others; one bad entry
# makes the daemon refuse to start.
pa_sensor_logs() {
    local entry name path why
    local -a parts=()
    PA_LOG_LABEL=() PA_LOG_PATH=() PA_LOG_BAD=() PA_LOG_BAD_WHY=()
    IFS=',' read -r -a parts <<< "${1:-}" || true
    for entry in "${parts[@]}"; do
        _pa_trim_ws "$entry"
        entry="$_PA_T"
        [ -n "$entry" ] || continue
        why=""
        case "$entry" in
            *:*)
                name="${entry%%:*}"
                path="${entry#*:}"
                if [ -z "$name" ]; then
                    why="empty label"
                elif [ -z "$path" ]; then
                    why="label with no path"
                fi
                ;;
            *) why="no ':' separator" ;;
        esac
        if [ -n "$why" ]; then
            PA_LOG_BAD+=("$entry")
            PA_LOG_BAD_WHY+=("$why")
        else
            PA_LOG_LABEL+=("$name")
            PA_LOG_PATH+=("$path")
        fi
    done
}
