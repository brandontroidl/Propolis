#!/usr/bin/env bash
# shellcheck disable=SC2034 # the PA_* variables are this library's output, read by its callers
#
# The shared library of the shell alerting code, to be sourced by the failure hook's record step,
# the witness, the status command and config-check. deploy/install.sh and deploy/upgrade.sh
# install it as /usr/local/sbin/propolis-alert-lib, 0644. Sourced, never executed. It sets no
# shell options and no trap (a trap set here would replace the caller's), and defines functions
# and PA_* variables only. Every function returns a status and works under the caller's `set -u`
# and `set -e` without relying on either.
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
# back to /run when the disk refuses a write; the PROPOLIS_SENSOR_LOGS grammar; the cause codes
# of a failed run and the unit map; the maintenance marker; the witness's heartbeat URL request
# (pa_heartbeat_get) and the fixed journal lines it looks for (PA_JOURNAL_CLASSES); the database
# probe through pg-exec (pa_pg) and the public-feed push scheduler check (pa_push_scheduler), so
# the status command and the witness judge both by one rule; the volume projection and triggers
# (pa_vol_project, pa_vol_judge), for the same reason; the incident record; and the failure
# hook's record step (pa_hook_record), which the hook runs in a child process of its own.
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
# change meaning, so a newer library serves an older consumer. deploy/rollback.sh compares it with
# the `# needs-alert-lib: <n>` line of each consumer before it restores an older library.
PA_LIB_VERSION=11
# The optional env file of the shell senders; the deploy tests derive the sensors' denied set from
# this name.
PA_ALERT_ENV_NAME=alert.env

# Writers trim incidents to 192 KiB; readers accept up to 1 MiB, so a file a writer produced is
# never thrown away as too large.
PA_INCIDENTS_MAX=196608
PA_STATE_MAX=1048576
# The state files pa_state_read and pa_state_write handle, all at major version 1.
PA_STATE_NAMES="incidents send-ledger readcheck meta observe testpage"

# Internal state never comes from the environment: an inherited PA_LOCK_FD would make pa_lock
# skip the lock, an inherited PA_PG_GUARD_KNOWN would make pa_pg run, as root, a binary whose
# pg-exec guard nobody read, and an inherited PA_CLEANUP would make pa_cleanup delete a path
# someone else chose. A value this shell set itself, before sourcing again, is kept. Bash cannot export an
# array, so an inherited PA_CLEANUP is always a scalar.
for _PA_V in PA_LOCK_FD _PA_UNREADABLE_LOGGED PA_PG_GUARD_KNOWN; do
    if [[ $(declare -p "$_PA_V" 2> /dev/null) =~ ^declare\ -[a-zA-Z]*x ]]; then unset "$_PA_V"; fi
done
unset _PA_V
PA_LOCK_FD="${PA_LOCK_FD:-}"
_PA_UNREADABLE_LOGGED="${_PA_UNREADABLE_LOGGED:-}"
PA_PG_GUARD_KNOWN="${PA_PG_GUARD_KNOWN:-}"
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

# pa_unit_name_ok S: a unit name as systemd itself gives one, within the characters the failure
# hook accepts: at most 200 bytes, a unit type after the last dot, a prefix that starts with
# neither a dot nor `@`, and an instance after the first `@` when there is one. systemctl turns
# any other word into a name of its own making (`x` into `x.service`) or refuses the question, so
# nothing is recorded under one and none is put to systemd.
pa_unit_name_ok() {
    local LC_ALL=C s="${1:-}" prefix
    [ "${#s}" -ge 1 ] && [ "${#s}" -le 200 ] && [[ $s != *[!A-Za-z0-9@._:-]* ]] || return 1
    case "${s##*.}" in
        service | socket | target | device | mount | automount | swap | timer | path | slice | scope) ;;
        *) return 1 ;;
    esac
    prefix="${s%.*}"
    [ -n "$prefix" ] && [ "$prefix" != "$s" ] || return 1
    case "$prefix" in
        .* | @*) return 1 ;;
        *@*) [ -n "${prefix#*@}" ] || return 1 ;;
    esac
    return 0
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
# PA_INVALID and `KEY=<file name>` to PA_INVALID_IN. A line systemd may read differently is
# invalid too: the value used here could differ from the one the daemon gets. Sets
# _PA_SETTING_SRC to the file that assigned a valid value.
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
        PA_INVALID_IN="${PA_INVALID_IN:+$PA_INVALID_IN }$key=${PA_ENV_SRC##*/}"
    fi
}

# _pa_shell_files KEY: the file a shell sender reads KEY from, in _PA_FILES: alert.env when that
# file gives KEY a value, else propolis.env. An empty value in alert.env counts as unset, so a
# template copied with its lines left empty does not blank what propolis.env sets.
_pa_shell_files() {
    pa_env_get "$1" "$PA_ENV_DIR/$PA_ALERT_ENV_NAME" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        _PA_FILES=("$PA_ENV_DIR/$PA_ALERT_ENV_NAME")
    else
        _PA_FILES=("$PA_ENV_DIR/propolis.env")
    fi
}

# pa_settings_load: the shell senders' settings, each from alert.env when that file assigns it
# a value and otherwise from propolis.env, and the daemon's ntfy target, which is propolis.env's
# alone.
#
# The shell senders' target (PA_URL, PA_TOPIC, PA_TOKEN) exists (PA_TARGET=1, PA_TARGET_SRC the
# file's name) only when URL and topic are both valid and come from the same file: half a target
# from each file would post to a server with a topic meant for another. Then PA_TARGET_SPLIT=1,
# and PA_URL_SRC and PA_TOPIC_SRC name the two files. The token is read from the target's file
# only, so a token written for one server never goes to the other; PA_TOKEN_IGNORED=1 when
# alert.env sets a token and no target of its own, so that token is not used. PA_INVALID names every key of
# the shell target that was set to an invalid value and ignored, PA_INVALID_IN each as
# `KEY=<file>`.
#
# PA_D_URL, PA_D_TOPIC, PA_D_TOKEN and PA_D_TARGET are the target the daemon and today's failure
# hook post to, from propolis.env alone (the hook reads alert.env only to send a test page), with PA_D_INVALID for
# its invalid keys. Without alert.env both targets are the same.
#
# Also the witness's heartbeat URL, PROPOLIS_WITNESS_HEARTBEAT_URL (alert.env over propolis.env):
# PA_HB_URL holds it only when it is a valid https:// URL, and PA_HB_STATE says set, unset,
# insecure (any other scheme: whoever can read or answer plain HTTP on the path could silence the
# dead-man check, so it is never requested) or invalid. The URL is a secret: it is held in this
# variable, given to curl only through a 0600 config file (pa_heartbeat_get), and never printed.
# PA_OPS_ENABLED is 1 when propolis.env turns the daemon's monitor on, read as the daemon reads it.
#
# The alias and the daily message's time come from alert.env over propolis.env too, with
# PA_ALIAS_SRC and PA_DAILY_SRC naming the file. PA_ALIAS_SET holds
# PROPOLIS_OPS_HOST_ALIAS as written, for pa_alias to judge, and PA_ALIAS_STATE says unset, set or
# invalid (a line systemd may read otherwise; pa_alias then takes the fallback). PA_DAILY_AT is
# PROPOLIS_OPS_DAILY_AT when it is HH:MM, `off` when the value starts with a word that means off
# (_pa_daily_off), else 08:41, with PA_DAILY_STATE default, set or invalid: a value of neither
# form keeps the default time rather than turning the message off, because the message goes only
# to a topic proven to refuse anonymous reads, so one more message reveals nothing, while a daily
# message that silently stopped is the absence the operator reads as the host being down.
#
# PROPOLIS_ALERT_PROFILE (alert.env over propolis.env) is read and checked: PA_PROFILE_STATE is
# unset, legacy, v2 or invalid (anything else, read as legacy), PA_PROFILE_SRC its file. This
# release sends as legacy whatever the file says, so PA_PROFILE is legacy: the v2 senders are
# not in force yet, and a profile that could be switched on before they are would page in a
# format nothing has proven. Only the test seam PA_TEST_PROFILE (legacy or v2) sets it, and only
# under a non-empty root, which no unit and no script passes.
pa_settings_load() {
    local env="$PA_ENV_DIR/propolis.env" url_src topic_src
    local -a tfiles
    PA_INVALID="" PA_INVALID_IN="" PA_TARGET=0 PA_TARGET_SRC="" PA_TARGET_SPLIT=0
    _pa_setting PA_D_URL PROPOLIS_OPS_NTFY_URL _pa_valid_url "$env"
    PA_D_URL="${PA_D_URL%/}"
    _pa_setting PA_D_TOPIC PROPOLIS_OPS_NTFY_TOPIC _pa_valid_topic "$env"
    _pa_setting PA_D_TOKEN PROPOLIS_OPS_NTFY_TOKEN _pa_valid_token "$env"
    PA_D_TARGET=0
    if [ -n "$PA_D_URL" ] && [ -n "$PA_D_TOPIC" ]; then PA_D_TARGET=1; fi
    PA_D_INVALID="$PA_INVALID"
    PA_INVALID="" PA_INVALID_IN=""
    _pa_shell_files PROPOLIS_OPS_NTFY_URL
    _pa_setting PA_URL PROPOLIS_OPS_NTFY_URL _pa_valid_url "${_PA_FILES[@]}"
    url_src="$_PA_SETTING_SRC"
    PA_URL="${PA_URL%/}"
    _pa_shell_files PROPOLIS_OPS_NTFY_TOPIC
    _pa_setting PA_TOPIC PROPOLIS_OPS_NTFY_TOPIC _pa_valid_topic "${_PA_FILES[@]}"
    topic_src="$_PA_SETTING_SRC"
    PA_URL_SRC="${url_src##*/}" PA_TOPIC_SRC="${topic_src##*/}"
    _pa_shell_files PROPOLIS_OPS_NTFY_TOKEN
    tfiles=("${_PA_FILES[@]}")
    if [ -n "$PA_URL" ] && [ -n "$PA_TOPIC" ]; then
        if [ "$url_src" = "$topic_src" ]; then
            PA_TARGET=1
            PA_TARGET_SRC="${url_src##*/}"
            tfiles=("$url_src")
        else
            PA_TARGET_SPLIT=1
        fi
    fi
    _pa_setting PA_TOKEN PROPOLIS_OPS_NTFY_TOKEN _pa_valid_token "${tfiles[@]}"
    # A token alert.env sets beside no target of its own goes nowhere: say so, or the operator
    # takes it for the one in use.
    PA_TOKEN_IGNORED=0
    if [ "$PA_TARGET_SRC" != "$PA_ALERT_ENV_NAME" ] && [ "$PA_TARGET_SPLIT" = 0 ]; then
        pa_env_get PROPOLIS_OPS_NTFY_TOKEN "$PA_ENV_DIR/$PA_ALERT_ENV_NAME" > /dev/null
        [ -z "$PA_ENV_VALUE" ] || PA_TOKEN_IGNORED=1
    fi
    PA_HB_URL="" PA_HB_STATE=unset
    _pa_shell_files PROPOLIS_WITNESS_HEARTBEAT_URL
    pa_env_get PROPOLIS_WITNESS_HEARTBEAT_URL "${_PA_FILES[@]}" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        if [ "$PA_ENV_COMPLEX" != 0 ] || ! _pa_valid_url "$PA_ENV_VALUE"; then
            PA_HB_STATE=invalid
        elif [[ $PA_ENV_VALUE != https://* ]]; then
            PA_HB_STATE=insecure
        else
            PA_HB_URL="$PA_ENV_VALUE" PA_HB_STATE=set
        fi
    fi
    PA_OPS_ENABLED=0
    pa_env_get PROPOLIS_OPS_ENABLED "$env" > /dev/null
    case "${PA_ENV_VALUE,,}" in true | 1 | yes | on) PA_OPS_ENABLED=1 ;; esac
    # Neither goes into PA_INVALID: that list is of the push settings today's failure hook and
    # the daemon read too, and these two are the shell senders' alone.
    PA_ALIAS_SET="" PA_ALIAS_STATE=unset PA_ALIAS_SRC=""
    _pa_shell_files PROPOLIS_OPS_HOST_ALIAS
    pa_env_get PROPOLIS_OPS_HOST_ALIAS "${_PA_FILES[@]}" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        PA_ALIAS_SRC="${PA_ENV_SRC##*/}"
        if [ "$PA_ENV_COMPLEX" = 0 ]; then PA_ALIAS_SET="$PA_ENV_VALUE" PA_ALIAS_STATE=set; else PA_ALIAS_STATE=invalid; fi
    fi
    PA_DAILY_AT=08:41 PA_DAILY_STATE=default PA_DAILY_SRC=""
    _pa_shell_files PROPOLIS_OPS_DAILY_AT
    pa_env_get PROPOLIS_OPS_DAILY_AT "${_PA_FILES[@]}" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        PA_DAILY_SRC="${PA_ENV_SRC##*/}"
        if _pa_daily_off "$PA_ENV_VALUE"; then
            PA_DAILY_AT=off PA_DAILY_STATE=set
        elif [ "$PA_ENV_COMPLEX" = 0 ] && _pa_valid_daily "$PA_ENV_VALUE"; then
            PA_DAILY_AT="$PA_ENV_VALUE" PA_DAILY_STATE=set
        else
            PA_DAILY_STATE=invalid
        fi
    fi
    PA_PROFILE=legacy PA_PROFILE_STATE=unset PA_PROFILE_SRC=""
    _pa_shell_files PROPOLIS_ALERT_PROFILE
    pa_env_get PROPOLIS_ALERT_PROFILE "${_PA_FILES[@]}" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        PA_PROFILE_SRC="${PA_ENV_SRC##*/}" PA_PROFILE_STATE=invalid
        if [ "$PA_ENV_COMPLEX" = 0 ]; then
            case "$PA_ENV_VALUE" in legacy | v2) PA_PROFILE_STATE="$PA_ENV_VALUE" ;; esac
        fi
    fi
    if [ -n "${PA_ROOT:-}" ]; then
        case "${PA_TEST_PROFILE:-}" in legacy | v2) PA_PROFILE="$PA_TEST_PROFILE" ;; esac
    fi
    return 0
}

# _pa_valid_daily V: `off`, or a time of day as HH:MM on the 24-hour clock.
_pa_valid_daily() {
    [ "${1:-}" = off ] || [[ ${1:-} =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]
}

# _pa_daily_off V: V starts with a word an operator writes to turn the message off (off, false,
# no, n, 0, none, never, stop, disable, disabled), in any letter case, alone or with a blank or a
# punctuation mark after it: a comment, a quote, a line systemd would read otherwise. A letter, a
# digit, `:`, `_` or `-` straight after the word makes it another word (offline, noon, 08:41).
# Read this loosely on purpose. Only this library reads the setting, and the other way to misread
# it is a message a day that the operator tried to stop.
_pa_daily_off() {
    local v="${1:-}" re="^[\"'[:blank:]]*(off|false|no|n|0|none|never|stop|disabled?)([^a-z0-9:_-]|\$)"
    [[ ${v,,} =~ $re ]]
}

# pa_hook_env_value KEY [FILE]: KEY as today's failure hook reads it (deploy/alert.sh env_value)
# from FILE, propolis.env by default: the last line that starts with `KEY=`, with one quote taken
# off each end. An indented line, `KEY = value` and a trailing comment are read differently here
# than by pa_env_get, which is why the two readings are compared before a test page counts for
# the hook. KEY is a fixed setting name, never data.
pa_hook_env_value() {
    local f="${2:-$PA_ENV_DIR/propolis.env}" v
    [ -r "$f" ] || return 0
    v="$(sed -n "s/^$1=//p" -- "$f" 2> /dev/null | tail -n 1)" || v=""
    v="${v%\"}"
    v="${v#\"}"
    v="${v%\'}"
    v="${v#\'}"
    printf '%s' "$v"
}

# pa_hook_differs: the push settings today's failure hook reads (pa_hook_env_value) are not the
# library's reading of the same file, propolis.env (PA_D_*, from pa_settings_load, which the
# caller has run), whatever alert.env says: the hook reads alert.env only to send a test page. Sets PA_HOOK_DIFF to
# the names of the settings that differ or that the library ignores as invalid, and PA_HOOK_URL
# to the hook's URL; status 1 when they agree. No value is put anywhere but the variables.
pa_hook_differs() {
    local key url topic token
    PA_HOOK_DIFF=""
    url="$(pa_hook_env_value PROPOLIS_OPS_NTFY_URL)"
    topic="$(pa_hook_env_value PROPOLIS_OPS_NTFY_TOPIC)"
    token="$(pa_hook_env_value PROPOLIS_OPS_NTFY_TOKEN)"
    PA_HOOK_URL="${url%/}" PA_HOOK_TOPIC_SET=0
    [ -z "$topic" ] || PA_HOOK_TOPIC_SET=1
    [ "${url%/}" = "${PA_D_URL:-}" ] || PA_HOOK_DIFF+=" PROPOLIS_OPS_NTFY_URL"
    [ "$topic" = "${PA_D_TOPIC:-}" ] || PA_HOOK_DIFF+=" PROPOLIS_OPS_NTFY_TOPIC"
    [ "$token" = "${PA_D_TOKEN:-}" ] || PA_HOOK_DIFF+=" PROPOLIS_OPS_NTFY_TOKEN"
    for key in PROPOLIS_OPS_NTFY_URL PROPOLIS_OPS_NTFY_TOPIC PROPOLIS_OPS_NTFY_TOKEN; do
        case " ${PA_D_INVALID:-} " in
            *" $key "*) [[ " $PA_HOOK_DIFF " == *" $key "* ]] || PA_HOOK_DIFF+=" $key" ;;
        esac
    done
    PA_HOOK_DIFF="${PA_HOOK_DIFF# }"
    [ -n "$PA_HOOK_DIFF" ]
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
    local a="$1" h hs k
    local LC_ALL=C
    [[ ${#a} -ge 3 && ${#a} -le 32 && $a == [a-z]* && $a != *[!a-z0-9-]* ]] || return 1
    case "$a" in *propolis* | *honey*) return 1 ;; esac
    h="$(hostname 2> /dev/null)" || h=""
    hs="$(hostname -s 2> /dev/null)" || hs=""
    # Where `hostname` cannot answer (not installed on every distribution), the kernel's name is
    # read instead, and without any name the alias is refused: an empty name would let the host's
    # own name through. PA_TEST_KERNEL_HOSTNAME replaces the kernel's file under a test root only.
    if [ -z "$h" ] && [ -z "$hs" ]; then
        k=/proc/sys/kernel/hostname
        [ -z "${PA_ROOT:-}" ] || k="${PA_TEST_KERNEL_HOSTNAME:-$k}"
        h="$(head -c 256 -- "$k" 2> /dev/null | tr -d '\n')" || h=""
        hs="${h%%.*}"
        [ -n "$h" ] || return 1
    fi
    [ "$a" != "${h,,}" ] && [ "$a" != "${hs,,}" ]
}

# pa_alias: the host's name on the channel. PA_ALIAS_SET (read from PROPOLIS_OPS_HOST_ALIAS by
# pa_settings_load) when it passes _pa_alias_ok; otherwise host- and 4 hex
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
    _pa_as_t 5 "$@"
}

# _pa_as_t SECONDS USER CMD...: _pa_as under `timeout SECONDS` (1 to 99), for a command that may
# wait on a slow mount for longer than 5 s.
_pa_as_t() {
    local t="$1" user="$2" uid gid me="$UID"
    shift 2
    [[ $t =~ ^[1-9][0-9]?$ ]] || t=5
    [ -z "${PA_ROOT:-}" ] || me="${PA_TEST_UID:-$UID}"
    if [ "$me" != 0 ] || [ "${PA_TEST_READ_AS_SELF:-}" = 1 ]; then
        set -- timeout "$t" "$@"
    else
        uid="$(id -u -- "$user" 2> /dev/null)" || return 1
        gid="$(id -g -- "$user" 2> /dev/null)" || return 1
        set -- timeout "$t" setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- "$@"
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

# ---- causes, the unit map and the maintenance marker -------------------------------------------

# _pa_signal S: sets _PA_SIGNUM and _PA_SIGNAME from a signal number (systemctl's ExecMainStatus)
# or a name with or without SIG (systemd's MONITOR_EXIT_STATUS), or fails. The names and numbers
# are bash's own `kill -l`, so SYS is whatever number this architecture gives it.
_pa_signal() {
    local s="${1#SIG}" out
    _PA_SIGNUM="" _PA_SIGNAME=""
    if [[ ${1:-} =~ ^[0-9]{1,2}$ ]] && [ "$((10#$1))" -ge 1 ]; then
        out="$(kill -l "$((10#$1))" 2> /dev/null)" || return 1
        [[ $out =~ ^[A-Z][A-Z0-9+-]{0,15}$ ]] || return 1
        _PA_SIGNUM="$((10#$1))" _PA_SIGNAME="$out"
    elif [[ $s =~ ^[A-Z][A-Z0-9+-]{0,15}$ ]]; then
        out="$(kill -l "$s" 2> /dev/null)" || return 1
        [[ $out =~ ^[0-9]{1,2}$ ]] || return 1
        _PA_SIGNUM="$((10#$out))" _PA_SIGNAME="$s"
    else
        return 1
    fi
}

# pa_cause RESULT STATUS PANICS: the cause code of a failed run, from systemd's result (the
# unit's SERVICE_RESULT, or Result= from systemctl show), its exit status or signal, and how many
# `panicked at` lines the run logged. Prints the code and sets PA_CAUSE. A state field holds no
# blank, so a code that carries a number joins it with a colon (`proc.exit:3`); the class is the
# part before the dot, and every code here is class proc, so a run that changes how it crashes is
# still the same class. A sandbox exit (200 to 243, systemd's own setup) means the program never
# ran, so a panic line cannot be its cause. Anything not recognised is `unknown`.
pa_cause() {
    local result="${1:-}" status="${2:-}" panics="${3:-0}" n
    PA_CAUSE=unknown
    [[ $panics =~ ^[0-9]{1,9}$ ]] || panics=0
    case "$result" in
        exit-code)
            if [[ $status =~ ^[0-9]{1,3}$ ]] && [ "$((10#$status))" -le 255 ]; then
                n=$((10#$status))
                if [ "$n" -ge 200 ] && [ "$n" -le 243 ]; then
                    PA_CAUSE="proc.sandbox:$n"
                elif [ "$panics" -gt 0 ]; then
                    PA_CAUSE=proc.panic
                else
                    PA_CAUSE="proc.exit:$n"
                fi
            fi
            ;;
        signal | core-dump)
            if _pa_signal "$status"; then
                if [ "$_PA_SIGNAME" = SYS ]; then
                    PA_CAUSE=proc.sigsys
                elif [ "$panics" -gt 0 ]; then
                    PA_CAUSE=proc.panic
                else
                    PA_CAUSE="proc.signal:$_PA_SIGNUM"
                fi
            fi
            ;;
        oom-kill) PA_CAUSE=proc.oom ;;
        timeout) PA_CAUSE=proc.timeout ;;
        watchdog) PA_CAUSE=proc.watchdog ;;
        start-limit-hit) PA_CAUSE=proc.start_limit ;;
        resources) PA_CAUSE=proc.resources ;;
    esac
    printf '%s' "$PA_CAUSE"
}

# pa_unit_map UNIT: where a unit's failure shows and how loud it is. Sets PA_UNIT_STAGE (a stage
# or rail word), PA_UNIT_TIER, PA_UNIT_LISTENER (yes for a listener) and PA_UNIT_RESERVE (the
# reserve kind, or -). Any unit not named here is a host matter.
pa_unit_map() {
    PA_UNIT_STAGE=host PA_UNIT_TIER=ACT PA_UNIT_LISTENER=no PA_UNIT_RESERVE=-
    case "${1:-}" in
        sensor-*.service) PA_UNIT_STAGE=listen PA_UNIT_TIER=PAGE PA_UNIT_LISTENER=yes ;;
        propolis.service) PA_UNIT_STAGE=intake PA_UNIT_TIER=PAGE PA_UNIT_RESERVE=daemon-down ;;
        shipper.service) PA_UNIT_STAGE=ship ;;
        gateway.service) PA_UNIT_STAGE=gateway ;;
        propolis-logrotate.service) PA_UNIT_STAGE=source ;;
        propolis-backup.service) PA_UNIT_STAGE=backup ;;
        propolis-witness@*.service) PA_UNIT_STAGE=witness ;;
    esac
    return 0
}

# pa_maint_active: true while the maintenance marker in PA_RUN holds: written in this boot (a
# marker cannot outlive a reboot, and /run is emptied by one anyway), ending in the future but no
# more than 7200 s ahead, so a forgotten or forged far-off end cannot hide a fault for longer than
# an upgrade could. Sets PA_MAINT_REASON (upgrade, rollback or manual) and PA_MAINT_UNTIL. A
# marker that is not a regular file, or not in the two-line form, holds nothing.
pa_maint_active() {
    local f="$PA_RUN/maintenance" head="" t="" until="" boot="" reason="" ahead
    PA_MAINT_REASON="" PA_MAINT_UNTIL=""
    [ -f "$f" ] && [ ! -L "$f" ] || return 1
    [ -n "${PA_STAMP:-}" ] || pa_now
    [ "$PA_BOOT" != - ] || return 1
    {
        IFS= read -r head
        IFS=$'\t' read -r t until boot reason _
    } < "$f" 2> /dev/null
    [[ $head =~ ^#maintenance\ v1\ g=[0-9]{1,18}$ ]] || return 1
    [ "$t" = X ] && [[ $until =~ ^[0-9]{1,12}$ ]] && [ "$boot" = "$PA_BOOT" ] || return 1
    case "$reason" in
        upgrade | rollback | manual) ;;
        *) return 1 ;;
    esac
    ahead=$((10#$until - 10#$PA_WALL))
    [ "$ahead" -gt 0 ] && [ "$ahead" -le 7200 ] || return 1
    PA_MAINT_REASON="$reason" PA_MAINT_UNTIL="$((10#$until))"
}

# pa_maint_write REASON MINUTES: writes the maintenance marker in PA_RUN for MINUTES from now (1 to
# 120, pa_maint_active's own ceiling, so a forgotten marker hides nothing longer than an upgrade
# could) with this boot's id and REASON (upgrade, rollback or manual); 0 removes the marker
# whoever wrote it. Status 2 for a value outside those, 1 when the file cannot be written or
# removed, or when the boot id is unknown (a marker without it would never hold). Sets
# PA_MAINT_UNTIL. It takes no lock: the marker is not a state file, and the verb that writes it
# must work while the lock is wedged.
pa_maint_write() {
    local reason="${1:-}" min="${2:-}" until f="$PA_RUN/maintenance"
    case "$reason" in upgrade | rollback | manual) ;; *) return 2 ;; esac
    [[ $min =~ ^[0-9]{1,3}$ ]] && [ "$((10#$min))" -le 120 ] || return 2
    if [ "$((10#$min))" -eq 0 ]; then
        { [ -e "$f" ] || [ -L "$f" ]; } || return 0
        rm -f -- "$f" 2> /dev/null && return 0
        return 1
    fi
    [ -n "${PA_STAMP:-}" ] || pa_now
    [ "$PA_BOOT" != - ] || return 1
    until=$((10#$PA_WALL + 10#$min * 60))
    PA_MAINT_UNTIL="$until"
    pa_write "$f" < <(printf '#maintenance v1 g=1\nX\t%s\t%s\t%s\n' "$until" "$PA_BOOT" "$reason")
}

# ---- the login banner --------------------------------------------------------------------------

# _pa_undelivered_count: alerts that did not go out: the legacy hook's undelivered files (one per
# unit, root-written under /run/propolis-alert) and the daemon's queue, counted in the file the
# daemon writes, read as the daemon's account. Prints the total, `?` when either cannot be read.
_pa_undelivered_count() {
    local dir="$PA_ROOT/run/propolis-alert/undelivered" n=0 name text rc=0 cdir q
    if [ -d "$dir" ] && [ ! -L "$dir" ]; then
        while IFS= read -r -d '' name; do
            [[ $name =~ ^[A-Za-z0-9@._:-]{1,200}$ ]] && n=$((n + 1))
        done < <(timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' 2> /dev/null)
    fi
    pa_env_get PROPOLIS_CURSOR_DIR "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    cdir="${PA_ENV_VALUE:-$PA_ROOT/var/lib/propolis/cursors}"
    if [ -e "$cdir/ops-alert-undelivered.json" ] || [ -L "$cdir/ops-alert-undelivered.json" ]; then
        text="$(pa_read_as propolis "$cdir/ops-alert-undelivered.json" 262144)" || rc=$?
        if [ "$rc" != 0 ]; then
            printf '?'
            return 0
        fi
        q="$(printf '%s' "$text" | grep -o '"first_failed_unix":' | wc -l)"
        [[ $q =~ ^[0-9]{1,9}$ ]] && n=$((n + 10#$q))
    fi
    printf '%s' "$n"
}

# pa_banner: the login banner, four lines of at most 78 bytes, from state files only (no network,
# no database, no config-check, no journal): what is open, where alerts stand, what keeps the
# state from being trusted, and how to read the time. Closed words and numbers only: no host
# name, unit, label or raw text, so the file says nothing an attacker on the host could use
# beyond whether alerting works. A value that cannot be read prints `?`. PA_ROLE, when the caller
# set it, tells a collector, which has no push target by design.
pa_banner() {
    local hm t f st open=0 page=0 act=0 unjudged=0 part maint="" alert state="" lw=0 c u light=""
    local where=""
    local -a lines=() f_arr=()
    [ -n "${PA_STAMP:-}" ] || pa_now
    hm="$(date -u -d "@$PA_WALL" +%H:%M 2> /dev/null)" || hm="??:??"
    [[ $hm =~ ^[0-9]{2}:[0-9]{2}$ ]] || hm="??:??"
    # Read once in this shell too: only a read here leaves an unreadable file's name in
    # PA_STATE_UNREADABLE, and the loops below read in subshells.
    pa_state_read meta > /dev/null
    pa_state_read incidents > /dev/null
    while IFS=$'\t' read -r t f st _; do
        if [ "$t" = M ] && [ "$f" = light_last ]; then light="$st"; fi
        if [ "$t" = M ] && [ "$f" = where ]; then where="$st"; fi
    done < <(pa_state_read meta)
    # A writer that has just written knows better than meta, which may be what it could not write.
    where="${PA_WHERE:-$where}"
    while IFS= read -r t; do
        [[ $t == I$'\t'* ]] || continue
        IFS=$'\t' read -r -a f_arr <<< "$t"
        case "${f_arr[7]:-}" in
            open | acked)
                open=$((open + 1)) unjudged=$((unjudged + 1))
                case "${f_arr[6]:-}" in PAGE) page=$((page + 1)) ;; ACT) act=$((act + 1)) ;; esac
                ;;
            pending) unjudged=$((unjudged + 1)) ;;
        esac
    done < <(pa_state_read incidents)
    if pa_maint_active; then
        maint="maint ($PA_MAINT_REASON) until $(date -u -d "@$PA_MAINT_UNTIL" +%H:%M 2> /dev/null)"
    fi
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
        part="? open"
    elif [ -z "$light" ]; then
        part="$unjudged recent failures, not judged"
    elif [ "$open" -eq 0 ]; then
        part="nothing open"
        [ -z "$maint" ] || part=""
    else
        part="$open open (PAGE $page, ACT $act)"
    fi
    part="${part:+$part${maint:+; }}$maint; profile legacy"
    # The fixed prefix is 21 bytes. A long count and a maintenance marker together would pass 78:
    # the tier counts go first, then the longer words.
    if [ "$((21 + ${#part}))" -gt 78 ]; then
        if [ -z "$light" ]; then part="$unjudged unjudged"; else part="$open open"; fi
        part+="${maint:+; $maint}; profile legacy"
    fi
    lines+=("$part")
    pa_settings_load
    if [ "${PA_TARGET:-0}" != 1 ]; then
        # The daemon and today's failure hook post to propolis.env's target whatever the shell
        # senders lack, so what is known of that topic comes first.
        if ! alert="$(_pa_banner_daemon)"; then
            pa_hook_differs || true
            if [ -n "${PA_HOOK_URL:-}" ] && [ "${PA_HOOK_TOPIC_SET:-0}" = 1 ]; then
                alert="no shell target; failure hook still posts"
            elif [ "${PA_ROLE:-}" = collector ]; then
                alert="no push path here (collector)"
            else
                alert="NO PUSH TARGET (journal only)"
            fi
        fi
    else
        alert="$(_pa_banner_alert)"
    fi
    lines+=("alerts: $alert")
    if [ -f "$PA_RUN/lockwait" ] && [ ! -L "$PA_RUN/lockwait" ]; then
        while read -r t c _; do
            [[ $t =~ ^[a-z]{1,16}$ && $c =~ ^[0-9]{1,9}$ ]] || continue
            [ "$((10#$c))" -le "$lw" ] || lw=$((10#$c))
        done < <(timeout 5 head -c 4096 -- "$PA_RUN/lockwait" 2> /dev/null)
    fi
    u="$(_pa_undelivered_count)"
    state=""
    if [ "$lw" -gt 0 ]; then
        state="state LOCK BUSY - "
    elif [[ " ${PA_STATE_UNREADABLE:-} " == *" meta "* ]]; then
        state="state ? - "
    elif [ "$where" = run ] || [ "$where" = none ]; then
        state="state NOT PERSISTED - "
    elif [ "$u" = "?" ]; then
        state="? alerts UNDELIVERED - "
    elif [ "$u" -gt 0 ]; then
        state="$u alerts UNDELIVERED - "
    fi
    lines+=("${state}run: sudo propolis-status")
    lines+=("rewritten every 5 min; older means the witness stopped")
    for t in "${lines[@]}"; do
        t="[propolis $hm UTC] $t"
        if [ "${#t}" -gt 78 ] || ! pa_ok_line "$t"; then t="[propolis $hm UTC] (line withheld)"; fi
        printf '%s\n' "$t"
    done
}

# pa_banner_write: writes pa_banner to PA_MOTD/propolis by way of a temporary file made 0600
# before the rename (the mode is set, never left to the umask: the banner says whether alerting
# works, which a sensor that can read /run must not learn). Status 1 when the directory is
# missing or refuses the write; the directory is never created here (tmpfiles makes it).
pa_banner_write() {
    local tmp="$PA_MOTD/.propolis.tmp.$$"
    [ -d "$PA_MOTD" ] && [ ! -L "$PA_MOTD" ] || return 1
    PA_CLEANUP+=("$tmp")
    if pa_banner > "$tmp" 2> /dev/null && chmod 0600 -- "$tmp" 2> /dev/null \
        && mv -f -T -- "$tmp" "$PA_MOTD/propolis" 2> /dev/null; then
        return 0
    fi
    rm -f -- "$tmp" 2> /dev/null
    return 1
}

# _pa_banner_class CLASS: the banner's words for a definite read-check class that is not a
# refusal: READABLE only for readable, since a redirect, a 404 or an answer from some other
# server shows only that the topic is not proven private. Closed words, so nothing the server
# said reaches the banner. Status 1 (nothing printed) for refused or no class.
_pa_banner_class() {
    case "${1:-}" in
        - | refused | "") return 1 ;;
        readable) printf 'topic READABLE by anyone' ;;
        redirect) printf 'topic not proven private (redirect)' ;;
        not_found) printf 'topic not proven private (not found)' ;;
        not_ntfy) printf 'topic not proven private (not a push server)' ;;
        *) printf 'topic not proven private (unexpected)' ;;
    esac
}

# _pa_banner_daemon: the banner's word (_pa_banner_class) on the daemon's target, propolis.env's,
# when its stored read check, bound to that target now, found anything but a refusal. Status 1,
# nothing printed, otherwise.
_pa_banner_daemon() {
    local b
    [ "${PA_D_TARGET:-0}" = 1 ] || return 1
    b="$(pa_readcheck_binding "$PA_D_URL" "$PA_D_TOPIC")" || return 1
    _pa_rc_line daemon && [ "$PA_RCL_BIND" = "$b" ] && _pa_banner_class "$PA_RCL_DCLASS"
}

# _pa_banner_alert: the banner's word on a target that exists: READABLE when the stored read check
# of the shell target or of the daemon's (propolis.env) target, bound to the target in use now,
# found the topic readable, and not proven private for any other definite class but refused
# (_pa_banner_class); once pa_gate holds the shell target's refusal proven,
# whether a test page got through (pa_verified), with `daemon not verified` where the daemon is
# enabled, since nothing tests the daemon's own sender; that the refusal is not proof over plain
# http, or that the check is stale, when that is why the gate does not; else not checked yet.
_pa_banner_alert() {
    local b
    b="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || b=""
    if _pa_rc_line shell && [ "$PA_RCL_BIND" = "$b" ] && _pa_banner_class "$PA_RCL_DCLASS"; then
        return 0
    fi
    if _pa_banner_daemon; then return 0; fi
    # A refusal is claimed only where the gate holds it proven: decided within a day, an attempt
    # within three hours, over https. A token that can read is the gate's own reason to hold full
    # detail back, not a sign the anonymous refusal is unproven, and so is the detail setting,
    # which is why the gate is asked with it at auto.
    # A check that ran and proves nothing is not `not checked yet`: over plain HTTP no refusal
    # can prove the topic private, and a stale one means the checker stopped or its answer aged.
    # Once the refusal is proven, what is left to say is whether a test page got through. The
    # gate names a reading token before it looks at the scheme, so plain http is asked here too.
    b="$(PA_DETAIL=auto pa_gate)"
    if [ "$b" = pointer:token-reads ] && [[ ${PA_URL:-} != https://* ]]; then b=pointer:insecure; fi
    case "$b" in
        full | pointer:token-reads | pointer:token-unknown)
            if pa_verified > /dev/null; then
                printf 'VERIFIED %s (shell)' "$(pa_dur "$(pa_age "$PA_TP_ACKED")")"
            else
                printf 'NOT VERIFIED (%s)' "$PA_VERIFIED_WORD"
            fi
            if _pa_daemon_enabled; then printf '; daemon not verified'; fi
            ;;
        pointer:insecure) printf 'topic not proven private (plain http)' ;;
        pointer:stale) printf 'topic check is stale' ;;
        *) printf 'topic not checked yet' ;;
    esac
}

# ---- the anonymous-read check and the gate -----------------------------------------------------
#
# Whether anyone who knows the topic's name can read what is pushed to it. Three GETs without
# credentials (json, raw and sse, so a proxy guarding one or two read paths cannot pass), and
# with a token one more json GET carrying it. The topic and the token are secrets: they reach curl
# only through files made 0600 here (a curl config file for the URL, a header file for the
# token), listed in PA_CLEANUP and removed before the function returns, never through a command
# line or a child's environment, and no message names them. The answer is untrusted: its body is
# capped, never printed, and judged only by the status code, the content type up to its first
# `;`, and whether every line of a json body starts with ntfy's own `{"id":"`. Anything that
# cannot be classified is not refused, so the gate falls to pointer mode. The readcheck state file
# holds one line per target role (shell, daemon, or both when they are the same):
# R binding attempt-stamp attempt-class definite-stamp definite-class token json raw role sse
# [credential], the last only when a credential was carried (pa_cred_fp).

PA_RC_CLASSES="refused readable not_ntfy redirect not_found transient unexpected"

# pa_readcheck_binding URL TOPIC: the first 16 hex of sha256(URL LF TOPIC LF). A stored result is
# used only for the target whose binding it carries, so a changed URL or topic voids it at once.
pa_readcheck_binding() {
    local h
    h="$(printf '%s\n%s\n' "${1:-}" "${2:-}" | sha256sum 2> /dev/null)" || return 1
    h="${h%% *}"
    [[ $h =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s' "${h:0:16}"
}

# pa_readcheck_class ENDPOINT CODE CTYPE BODY: the class of one answer (json, raw or sse) from its
# HTTP status, its content type and, for json, its body file. A 200 is readable only with the
# endpoint's own content type and, for json, an empty body or one whose every line is an ntfy
# message; any other 200 is a login page or a portal (not_ntfy). 000 (no answer), 429 and 5xx are
# transient; a status that is not three digits, or one not named here, is unexpected.
pa_readcheck_class() {
    local ep="${1:-}" code="${2:-}" ct="${3:-}" body="${4:-}" s bad
    if ! [[ $code =~ ^[0-9]{3}$ ]]; then
        printf unexpected
        return 0
    fi
    case "$code" in
        401 | 403) printf refused ;;
        200)
            ct="${ct%%;*}"
            ct="${ct//[[:space:]]/}"
            ct="${ct,,}"
            case "$ep:$ct" in
                json:application/x-ndjson | json:application/json)
                    s="$(stat -c %s -- "$body" 2> /dev/null)" || s=x
                    if ! [[ $s =~ ^[0-9]{1,12}$ ]] || [ "$((10#$s))" -gt 65536 ]; then
                        printf not_ntfy
                        return 0
                    fi
                    bad="$(head -c 65536 -- "$body" 2> /dev/null | LC_ALL=C grep -c -a -v -e '^{"id":"' -e '^$')" || true
                    if [[ $bad =~ ^[0-9]{1,9}$ ]] && [ "$((10#$bad))" -eq 0 ]; then printf readable; else printf not_ntfy; fi
                    ;;
                raw:text/plain | sse:text/event-stream) printf readable ;;
                *) printf not_ntfy ;;
            esac
            ;;
        301 | 302 | 303 | 307 | 308) printf redirect ;;
        404) printf not_found ;;
        000 | 429 | 5[0-9][0-9]) printf transient ;;
        *) printf unexpected ;;
    esac
}

# _pa_rc_get CONFIG HEADER BODY: one GET of the URL in the curl config file CONFIG (with the
# headers in HEADER when it is not empty), the body into BODY. Prints `<code><TAB><content type>`,
# code 000 when curl gave nothing usable. -q first, so no .curlrc of root's can add to the
# request; no -L, so a redirect is an answer, not a second request; a file size limit with
# SIGXFSZ ignored, so a body larger than any ntfy answer ends the transfer with a write error.
_pa_rc_get() {
    local out code
    out="$(
        trap '' XFSZ
        ulimit -f 1024 2> /dev/null
        if [ -n "$2" ]; then
            timeout 15 curl -q -K "$1" -H "@$2" -sS -o "$3" -w '%{http_code}\t%{content_type}' \
                --connect-timeout 5 --max-time 10 --max-filesize 65536 --proto '=https,http' 2> /dev/null
        else
            timeout 15 curl -q -K "$1" -sS -o "$3" -w '%{http_code}\t%{content_type}' \
                --connect-timeout 5 --max-time 10 --max-filesize 65536 --proto '=https,http' 2> /dev/null
        fi
    )" || true
    out="${out:0:512}"
    code="${out%%$'\t'*}"
    if [ "$code" = "$out" ] || ! [[ $code =~ ^[0-9]{3}$ ]]; then
        # Nothing parseable: no answer at all is 000; a reply curl printed but not in the form
        # asked for is something this check cannot classify.
        if [ -z "$out" ]; then printf '000\t'; else printf 'xxx\t'; fi
        return 0
    fi
    printf '%s\t%s' "$code" "${out#*$'\t'}"
}

# _pa_rc_conf FILE URL: writes FILE as a curl config file naming URL, quoted the way curl's config
# parser reads a quoted value. globoff, because curl otherwise expands braces and brackets in a URL
# into several requests, and a path may hold either: the request goes to the URL as written, once.
_pa_rc_conf() {
    local u="$2"
    u="${u//\\/\\\\}"
    u="${u//\"/\\\"}"
    { printf 'url = "%s"\ngloboff\n' "$u" > "$1"; } 2> /dev/null && chmod 0600 -- "$1" 2> /dev/null
}

# pa_readcheck_run URL TOPIC TOKEN: the read check of one target (TOKEN may be empty). Sets
# PA_RC_CLASS (the attempt's class: transient when any answer was, refused when all three were,
# else the class of the first answer that was not refused), PA_RC_JSON, PA_RC_RAW and PA_RC_SSE
# (each status code) with PA_RC_JSON_CT, PA_RC_RAW_CT and PA_RC_SSE_CT (each content type's word,
# `-` when there was none in a type's form), PA_RC_TOKEN (whether the credential a post carries
# can read the topic: reads, noread, unknown, or `-` when there is none), PA_RC_TOKEN_DEF (1 when
# that GET got a definite answer, 0 when none came or none was asked), PA_RC_CRED (which
# credential that was: token, url for a user and password written into the URL, or `-`),
# PA_RC_CRED_ASKED (0 when there is a credential and it was not asked, over plain http, its class
# then being unknown; else 1) and PA_RC_CAUSE (`-`, or tool.exec when curl or a private temporary
# file was not to be had, the class then being transient). Status 0, or 1 with that cause.
pa_readcheck_run() {
    local url="${1:-}" topic="${2:-}" token="${3:-}" conf hdr body ep r code ct cls first="" any_t=0 all_r=1
    local rest auth url_set="${1:-}" url_cred=0
    PA_RC_CLASS=transient PA_RC_JSON=000 PA_RC_RAW=000 PA_RC_SSE=000 PA_RC_TOKEN=- PA_RC_CAUSE=-
    PA_RC_JSON_CT=- PA_RC_RAW_CT=- PA_RC_SSE_CT=- PA_RC_CRED=- PA_RC_CRED_ASKED=1 PA_RC_TOKEN_DEF=0
    # The check is of anonymous reads: a user and password written into the URL would go out as
    # Basic credentials, and a 401 for those would pass for a refusal of anyone. They are taken
    # off the anonymous requests here; the binding is the caller's, of the URL as set.
    if [[ $url == *://* ]]; then
        rest="${url#*://}"
        # The authority ends at the first /, ? or #, as curl and pa_url_shown end it: an @ after
        # that is no user.
        auth="${rest%%[/?#]*}"
        if [[ $auth == *@* ]]; then
            url="${url%%://*}://${auth##*@}${rest:${#auth}}"
            url_cred=1
        fi
    fi
    if ! command -v curl > /dev/null 2>&1; then
        PA_RC_CAUSE=tool.exec
        return 1
    fi
    conf="$(umask 077 && mktemp 2> /dev/null)" || conf=""
    hdr="$(umask 077 && mktemp 2> /dev/null)" || hdr=""
    body="$(umask 077 && mktemp 2> /dev/null)" || body=""
    PA_CLEANUP+=("$conf" "$hdr" "$body")
    if [ -z "$conf" ] || [ -z "$hdr" ] || [ -z "$body" ]; then
        rm -f -- "$conf" "$hdr" "$body" 2> /dev/null
        PA_RC_CAUSE=tool.exec
        return 1
    fi
    for ep in json raw sse; do
        : > "$body" 2> /dev/null
        if ! _pa_rc_conf "$conf" "$url/$topic/$ep?poll=1&since=1s"; then
            rm -f -- "$conf" "$hdr" "$body" 2> /dev/null
            PA_RC_CAUSE=tool.exec
            return 1
        fi
        r="$(_pa_rc_get "$conf" "" "$body")"
        code="${r%%$'\t'*}" ct="${r#*$'\t'}"
        cls="$(pa_readcheck_class "$ep" "$code" "$ct" "$body")"
        [[ $code =~ ^[0-9]{3}$ ]] || code=-
        # The content type is the server's text, shown to the operator by the status command:
        # only its type word is kept, and only in a type's own characters.
        ct="${ct%%;*}"
        ct="${ct//[[:space:]]/}"
        if [[ ${ct,,} =~ ^[a-z0-9.+-]{1,40}/[a-z0-9.+-]{1,40}$ ]]; then ct="${ct,,}"; else ct=-; fi
        case "$ep" in
            json) PA_RC_JSON="$code" PA_RC_JSON_CT="$ct" ;;
            raw) PA_RC_RAW="$code" PA_RC_RAW_CT="$ct" ;;
            sse) PA_RC_SSE="$code" PA_RC_SSE_CT="$ct" ;;
        esac
        [ "$cls" != transient ] || any_t=1
        if [ "$cls" != refused ]; then
            all_r=0
            [ -n "$first" ] || first="$cls"
        fi
    done
    if [ "$any_t" = 1 ]; then
        PA_RC_CLASS=transient
    elif [ "$all_r" = 1 ]; then
        PA_RC_CLASS=refused
    else
        PA_RC_CLASS="$first"
    fi
    # What a post from this host carries is asked too, since on a collector a credential that can
    # read the topic holds the gate at pointer: the token when one is set (its header replaces
    # any user in the URL), else the user and password written into the URL, sent as they are.
    # Not over plain http: the gate never gives full there whatever the answer, so the request
    # would change no decision and would carry the credential in clear.
    if { [ -n "$token" ] || [ "$url_cred" = 1 ]; } && [[ $url != https://* ]]; then
        PA_RC_TOKEN=unknown PA_RC_CRED=url PA_RC_CRED_ASKED=0
        [ -z "$token" ] || PA_RC_CRED=token
    elif [ -n "$token" ]; then
        PA_RC_TOKEN=unknown PA_RC_CRED=token
        : > "$body" 2> /dev/null
        if _pa_rc_conf "$conf" "$url/$topic/json?poll=1&since=1s" \
            && { printf 'Authorization: Bearer %s\n' "$token" > "$hdr"; } 2> /dev/null; then
            r="$(_pa_rc_get "$conf" "$hdr" "$body")"
            code="${r%%$'\t'*}" ct="${r#*$'\t'}"
            _pa_rc_token_answer "$(pa_readcheck_class json "$code" "$ct" "$body")"
        fi
    elif [ "$url_cred" = 1 ]; then
        PA_RC_TOKEN=unknown PA_RC_CRED=url
        : > "$body" 2> /dev/null
        if _pa_rc_conf "$conf" "$url_set/$topic/json?poll=1&since=1s"; then
            r="$(_pa_rc_get "$conf" "" "$body")"
            code="${r%%$'\t'*}" ct="${r#*$'\t'}"
            _pa_rc_token_answer "$(pa_readcheck_class json "$code" "$ct" "$body")"
        fi
    fi
    rm -f -- "$conf" "$hdr" "$body" 2> /dev/null
    return 0
}

# _pa_rc_token_answer CLASS: the credential's class from its GET's answer: reads for readable,
# noread for refused, unknown for anything else. PA_RC_TOKEN_DEF is 1 when the server gave a
# definite answer (anything but no answer, 429 or a 5xx): only an answer that never came lets a
# stored class about the same credential stand.
_pa_rc_token_answer() {
    case "$1" in
        readable) PA_RC_TOKEN=reads PA_RC_TOKEN_DEF=1 ;;
        refused) PA_RC_TOKEN=noread PA_RC_TOKEN_DEF=1 ;;
        transient) PA_RC_TOKEN=unknown PA_RC_TOKEN_DEF=0 ;;
        *) PA_RC_TOKEN=unknown PA_RC_TOKEN_DEF=1 ;;
    esac
}

# _pa_rc_line ROLE: the stored readcheck line for ROLE (shell or daemon; a `both` line serves
# either). Sets PA_RCL_BIND, PA_RCL_ASTAMP, PA_RCL_ACLASS, PA_RCL_DSTAMP, PA_RCL_DCLASS,
# PA_RCL_TOKEN, PA_RCL_JSON, PA_RCL_RAW, PA_RCL_ROLE, PA_RCL_SSE and PA_RCL_CRED (the credential
# the token class is about, as pa_cred_fp names it; empty when the line does not say, which is
# how an older release wrote it), every field checked against its form (a class outside the
# closed list reads unexpected, a stamp that cannot be read `-`). Status 1 when there is none.
_pa_rc_line() {
    local want="${1:-}" t b as ac ds dc tk j r role s c found=""
    PA_RCL_BIND="" PA_RCL_ASTAMP=- PA_RCL_ACLASS=- PA_RCL_DSTAMP=- PA_RCL_DCLASS=- PA_RCL_TOKEN=-
    PA_RCL_JSON=- PA_RCL_RAW=- PA_RCL_ROLE="" PA_RCL_SSE=- PA_RCL_CRED=""
    while IFS=$'\t' read -r t b as ac ds dc tk j r role s c _; do
        [ "$t" = R ] && [[ ${b:-} =~ ^[0-9a-f]{16}$ ]] || continue
        case "${role:-}" in shell | daemon | both) ;; *) continue ;; esac
        if [ "$role" = "$want" ]; then
            found=1
        elif [ "$role" = both ] && [ -z "$found" ]; then
            found=both
        else
            continue
        fi
        PA_RCL_BIND="$b" PA_RCL_ROLE="$role"
        PA_RCL_ASTAMP=- PA_RCL_DSTAMP=-
        if _pa_stamp_split "${as:-}"; then PA_RCL_ASTAMP="$as"; fi
        if _pa_stamp_split "${ds:-}"; then PA_RCL_DSTAMP="$ds"; fi
        PA_RCL_ACLASS="$(_pa_rc_word "${ac:-}")" PA_RCL_DCLASS="$(_pa_rc_word "${dc:-}")"
        case "${tk:-}" in reads | noread | unknown) PA_RCL_TOKEN="$tk" ;; *) PA_RCL_TOKEN=- ;; esac
        if [[ ${j:-} =~ ^[0-9]{3}$ ]]; then PA_RCL_JSON="$j"; else PA_RCL_JSON=-; fi
        if [[ ${r:-} =~ ^[0-9]{3}$ ]]; then PA_RCL_RAW="$r"; else PA_RCL_RAW=-; fi
        if [[ ${s:-} =~ ^[0-9]{3}$ ]]; then PA_RCL_SSE="$s"; else PA_RCL_SSE=-; fi
        if [[ ${c:-} =~ ^(-|(token|url):[0-9a-f]{8})$ ]]; then PA_RCL_CRED="$c"; else PA_RCL_CRED=""; fi
        [ "$found" != 1 ] || break
    done < <(pa_state_read readcheck)
    [ -n "$found" ]
}

# _pa_rc_word W: W when it is a read-check class, `-` for `-`, else unexpected.
_pa_rc_word() {
    if [ "${1:-}" = - ] || [ -z "${1:-}" ]; then
        printf -- -
    elif [[ " $PA_RC_CLASSES " == *" $1 "* ]]; then
        printf '%s' "$1"
    else
        printf unexpected
    fi
}

# pa_cred_fp URL TOKEN: the credential a post to URL with TOKEN carries, named without being
# kept: token:<pa_token8 of the token> when a token is set (its header replaces any user in the
# URL), url:<pa_token8 of the user and password> when they are written into the URL, `-` for
# none. A stored answer about a credential is used only while this names the same one. `?` and
# status 1 without a salt, which matches no stored value.
pa_cred_fp() {
    local url="${1:-}" token="${2:-}" rest auth h kind=token
    if [ -z "$token" ] && [[ $url == *://* ]]; then
        rest="${url#*://}"
        auth="${rest%%[/?#]*}"
        if [[ $auth == *@* ]]; then
            token="${auth%@*}" kind=url
        fi
    fi
    if [ -z "$token" ]; then
        printf -- -
        return 0
    fi
    if ! h="$(pa_token8 "$token")"; then
        printf '?'
        return 1
    fi
    printf '%s:%s' "$kind" "$h"
}

# pa_gate: full, pointer:<reason> or none:notarget for the shell target, from the stored read
# check and the settings; no network. full only when: there is a target; the detail setting is
# auto (PA_DETAIL, read from a later release; auto until then); the stored line is bound to this
# target; its definite class is refused, decided within 24 h; an attempt was made within 3 h (the
# checker is alive); the URL is https (over plain HTTP anyone on the path can answer 403 to the
# check and then read every push); and on a collector the credential a post carries is proven
# unable to read the topic, or there is none (the role is PA_ROLE, or pa_role's answer when the
# caller set none, and a role that cannot be told counts as a collector's). What a credential
# reads is known only from a stored answer about that same credential (pa_cred_fp), so a token
# changed since the check, a line that does not say, and an answer of unknown all hold pointer:
# token-reads for one proven to read, token-unknown otherwise. A stamp that cannot be read or lies
# in the future fails its rule. Sets PA_GATE, and PA_GATE_CHECKED to the stored attempt stamp
# (`-` without one).
pa_gate() {
    local b a role cred ck held=0
    PA_GATE="" PA_GATE_CHECKED=-
    if [ "${PA_TARGET:-0}" != 1 ]; then
        PA_GATE=none:notarget
    elif [ "${PA_DETAIL:-auto}" != auto ]; then
        PA_GATE=pointer:detail-pointer
    elif ! _pa_rc_line shell; then
        PA_GATE=pointer:never
    else
        PA_GATE_CHECKED="$PA_RCL_ASTAMP"
        b="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || b=""
        if [ "$PA_RCL_BIND" != "$b" ]; then
            PA_GATE=pointer:unbound PA_GATE_CHECKED=-
        elif [ "$PA_RCL_DCLASS" = - ]; then
            PA_GATE=pointer:never
        elif [ "$PA_RCL_DCLASS" != refused ]; then
            PA_GATE="pointer:$PA_RCL_DCLASS"
        else
            a="$(pa_age "$PA_RCL_DSTAMP")"
            if [ "$a" -lt 0 ] || [ "$a" -gt 86400 ]; then
                PA_GATE=pointer:stale
            else
                a="$(pa_age "$PA_RCL_ASTAMP")"
                ck=unknown
                cred="$(pa_cred_fp "${PA_URL:-}" "${PA_TOKEN:-}")" || cred=""
                if [ "$cred" = - ]; then
                    ck=none
                elif [ -n "$cred" ] && [ "$PA_RCL_CRED" = "$cred" ]; then
                    case "$PA_RCL_TOKEN" in reads | noread) ck="$PA_RCL_TOKEN" ;; esac
                fi
                # The role is asked for here when the caller has not set it, and only when it
                # decides anything: a collector must never pass for another host because nobody
                # said what it is, and a host whose role cannot be told is held to its rule.
                role="${PA_ROLE:-}"
                if { [ "$ck" = reads ] || [ "$ck" = unknown ]; } && [ -z "$role" ]; then role="$(pa_role)"; fi
                case "$role" in collector | unknown) held=1 ;; esac
                if [ "$a" -lt 0 ] || [ "$a" -gt 10800 ]; then
                    PA_GATE=pointer:stale
                elif [ "$held" = 1 ] && [ "$ck" = reads ]; then
                    PA_GATE=pointer:token-reads
                elif [[ ${PA_URL:-} != https://* ]]; then
                    PA_GATE=pointer:insecure
                elif [ "$held" = 1 ] && [ "$ck" = unknown ]; then
                    PA_GATE=pointer:token-unknown
                else
                    PA_GATE=full
                fi
            fi
        fi
    fi
    printf '%s' "$PA_GATE"
}

# pa_readcheck_merge ROLE BINDING HAVE [CRED]: the readcheck line for ROLE after an attempt whose
# results are in PA_RC_* (pa_readcheck_run), merged with the stored line the caller read under
# the lock with _pa_rc_line (HAVE 1, its fields in PA_RCL_*) or without one (HAVE 0). CRED is
# pa_cred_fp of the credential the attempt asked about; anything not of its form means it could
# not be named. A new binding replaces the line; an attempt with the same binding that was
# transient changes only the attempt fields, so a 429, a 5xx or a timeout never undoes an
# earlier definite answer, except that a definite answer about the credential (reads or noread)
# is new knowledge and is kept whatever the anonymous GETs got. An unknown answer keeps a stored
# definite one only when that one is about the same credential and the credential's GET got no
# answer at all (PA_RC_TOKEN_DEF 0), so a timed-out GET cannot lift a collector out of pointer
# mode, a redirect or a 404 for the credential is not taken for its earlier refusal, and an
# answer about an old token never stands for a new one: over a line about another credential, or
# about none, the attempt's credential is stored with the class unknown. The
# credential is appended as the last field only when there is one: with none the line is the one
# an older release wrote, and a reader that does not know the field ignores it. Prints the line.
pa_readcheck_merge() {
    local role="${1:-}" b="${2:-}" have="${3:-0}" fp="${4:-}" ds dc tk j r s same=0 tab=$'\t'
    [[ $fp =~ ^(-|(token|url):[0-9a-f]{8})$ ]] || fp=""
    ds="$PA_STAMP" dc="$PA_RC_CLASS" tk="$PA_RC_TOKEN" j="$PA_RC_JSON" r="$PA_RC_RAW" s="$PA_RC_SSE"
    if [ "$have" = 1 ] && [ "$PA_RCL_BIND" = "$b" ]; then same=1; fi
    if [ "$PA_RC_CLASS" = transient ]; then
        ds=- dc=-
        if [ "$same" = 1 ]; then
            ds="$PA_RCL_DSTAMP" dc="$PA_RCL_DCLASS" j="$PA_RCL_JSON" r="$PA_RCL_RAW" s="$PA_RCL_SSE"
            # The stored class stands only for the credential it is about: an older line names
            # none, and keeping its fingerprint would make every light pass ask again.
            case "$PA_RC_TOKEN" in
                reads | noread) ;;
                *)
                    if [ -n "$fp" ] && [ "$PA_RCL_CRED" = "$fp" ] && [ "${PA_RC_TOKEN_DEF:-0}" = 0 ]; then
                        tk="$PA_RCL_TOKEN"
                    elif [ "$fp" = - ]; then
                        tk=-
                    elif [ -n "$fp" ]; then
                        tk=unknown
                    else
                        tk="$PA_RCL_TOKEN" fp="$PA_RCL_CRED"
                    fi
                    ;;
            esac
        fi
    elif [ "$PA_RC_TOKEN" = unknown ] && [ "${PA_RC_TOKEN_DEF:-0}" = 0 ] && [ "$same" = 1 ] && [ -n "$fp" ] \
        && [ "$PA_RCL_CRED" = "$fp" ] && { [ "$PA_RCL_TOKEN" = reads ] || [ "$PA_RCL_TOKEN" = noread ]; }; then
        tk="$PA_RCL_TOKEN"
    fi
    [ "$fp" != - ] || fp=""
    printf 'R\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s%s\n' "$b" "$PA_STAMP" "$PA_RC_CLASS" "$ds" "$dc" \
        "${tk:--}" "${j:--}" "${r:--}" "$role" "${s:--}" "${fp:+$tab$fp}"
}

# ---- the heartbeat URL -------------------------------------------------------------------------

# pa_heartbeat_get: one GET of PA_HB_URL (pa_settings_load), the witness's ping to an external
# dead-man check. Whoever holds the URL can keep that check quiet, so it reaches curl only through
# a curl config file made 0600 here and removed before return, never a command line or a child's
# environment; -q first, so no .curlrc of root's adds to the request; https only and no
# redirects, so the request never leaves for another host or for plain HTTP. Nothing of the answer
# is kept but its status code. Sets PA_HB_RESULT to ok (any 2xx) or a cause code: http.auth,
# http.not_found, http.rate, http.client (any other 4xx, and a redirect), http.server,
# net.timeout, net.connect (no answer), nocurl, tool.exec (no private file), config.invalid (no
# https URL to ask). Status 0 for ok, else 1.
pa_heartbeat_get() {
    local conf out rc
    PA_HB_RESULT=config.invalid
    [ -n "${PA_HB_URL:-}" ] && [[ $PA_HB_URL == https://* ]] && _pa_valid_url "$PA_HB_URL" || return 1
    if ! command -v curl > /dev/null 2>&1; then
        PA_HB_RESULT=nocurl
        return 1
    fi
    PA_HB_RESULT=tool.exec
    conf="$(umask 077 && mktemp 2> /dev/null)" || return 1
    PA_CLEANUP+=("$conf")
    if ! _pa_rc_conf "$conf" "$PA_HB_URL"; then
        rm -f -- "$conf" 2> /dev/null
        return 1
    fi
    out="$(timeout 15 curl -q -K "$conf" -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 \
        --max-time 10 --max-redirs 0 --proto '=https' 2> /dev/null)"
    rc=$?
    rm -f -- "$conf" 2> /dev/null
    out="${out:0:3}"
    [[ $out =~ ^[0-9]{3}$ ]] || out=000
    case "$out" in
        2[0-9][0-9]) PA_HB_RESULT=ok ;;
        401 | 403) PA_HB_RESULT=http.auth ;;
        404) PA_HB_RESULT=http.not_found ;;
        429) PA_HB_RESULT=http.rate ;;
        # A redirect is the server's answer and is never followed: the URL is not the check's.
        [134][0-9][0-9]) PA_HB_RESULT=http.client ;;
        5[0-9][0-9]) PA_HB_RESULT=http.server ;;
        *)
            case "$rc" in
                28 | 124) PA_HB_RESULT=net.timeout ;;
                126 | 127) PA_HB_RESULT=nocurl ;;
                *) PA_HB_RESULT=net.connect ;;
            esac
            ;;
    esac
    [ "$PA_HB_RESULT" = ok ]
}

# ---- the journal classes -----------------------------------------------------------------------
#
# PA_JOURNAL_CLASSES: the fixed lines the witness's light pass looks for in the journal, one per
# line as `class|writer|text`, the writer being the source file that prints the text (systemd for
# journald's own message). The journal is written by other accounts and by whoever can reach a
# sensor, so a class is first narrowed by fields journald sets itself (the unit from the cgroup,
# the uid from the socket credentials, the invocation id), and only then matched against these
# texts as fixed strings; no line is ever kept, printed or sent, only counted. A test holds each
# text to its writer, so a reworded message fails the build instead of leaving its class blind.
# The daemon class's order matters: its first text is the connect failure that ties the daemon's
# failure to the database, its second the start line that says the last run connected after all.
# So does the shipper class's: its first seven texts are lines it logs at ERROR when nothing is
# being shipped (a failed connection; then a failed cycle, a batch it cannot record in its state
# directory and a gateway that keeps answering Retry; then a rejected batch, a chain that
# diverged, matched by a part of its text with no quote in it, and the line before every exit on a
# permanent stop), the other three those it logs at WARN, which show only with RUST_LOG set.
PA_JOURNAL_CLASSES='
hook|deploy/alert.sh|; alert follows
hook|deploy/alert.sh|still undelivered since
hook|deploy/alert.sh| entered the failed state on
guard|deploy/logrotate-guard.sh|propolis-logrotate-guard: refusing to rotate
guard|deploy/logrotate-guard.sh|propolis-logrotate-guard: skipping rotation of
daemon|crates/propolis/src/main.rs|propolis: failed to connect to PostgreSQL
daemon|crates/propolis/src/main.rs|propolis: starting unified daemon
journald|systemd|Suppressed
gateway|crates/gateway/src/verify.rs|gateway: batch reuses the last accepted seq with different content
shipper|crates/shipper/src/main.rs|shipper: failed to connect to gateway
shipper|crates/shipper/src/main.rs|shipper: ship cycle IO error
shipper|crates/shipper/src/client.rs|shipper: cannot record the batch about to be sent in the state directory
shipper|crates/shipper/src/client.rs|gateway kept returning Retry past the consecutive-retry bound;
shipper|crates/shipper/src/main.rs|shipper: gateway rejected a batch
shipper|crates/shipper/src/main.rs|chain has diverged from the gateway
shipper|crates/shipper/src/main.rs|shipper: ship loop terminated on a permanent stop condition
shipper|crates/shipper/src/batcher.rs|shipper: dropping a line the origin policy refuses for this log
shipper|crates/shipper/src/main.rs|shipper: this cycle dropped lines the origin policy refuses for this log
shipper|crates/shipper/src/batcher.rs|shipper: dropping an over-length record that cannot fit a frame
pull|deploy/backup-serve.sh|served
'

# pa_journal_patterns CLASS: the texts of CLASS, one per line, in the order listed. Status 1 for a
# class with none.
pa_journal_patterns() {
    local c w p found=1
    while IFS='|' read -r c w p; do
        [ -n "$c" ] && [ "$c" = "${1:-}" ] || continue
        printf '%s\n' "$p"
        found=0
    done <<< "$PA_JOURNAL_CLASSES"
    return "$found"
}

# pa_jcursor_ok TEXT: TEXT has the form of a journal cursor (`s=...;i=...;b=...`, hex fields), and
# so may be handed back to journalctl, which is all a stored cursor is ever used for.
pa_jcursor_ok() {
    local LC_ALL=C re='^[a-z]=[0-9a-f]{1,64}(;[a-z]=[0-9a-f]{1,64}){1,15}$'
    [ "${#1}" -le 512 ] && [[ ${1:-} =~ $re ]]
}

# ---- volumes -----------------------------------------------------------------------------------
#
# The witness's hourly pass keeps one sample of every filesystem a store lives on (observe `Z`
# lines) and judges each with these two functions; the status walk shows the same projection from
# the same lines, so the two can never disagree on when a volume fills. Sizes are bytes and can
# pass 2^53, while bash counts in 64-bit signed integers: every size is held to 18 digits and
# taken down to KiB before any product is formed, and no division is made by a number not first
# shown to be above zero.

# _pa_kib V: V (bytes, at most 18 digits) in whole KiB, or failure for anything else.
_pa_kib() {
    [[ ${1:-} =~ ^[0-9]{1,18}$ ]] || return 1
    printf '%s' "$((10#$1 / 1024))"
}

# pa_vol_project NOW_STAMP NOW_AVAIL: reads earlier samples of one filesystem on stdin, one
# `stamp<TAB>avail` line each (avail in bytes, any order), and sets PA_VOL_SPAN (seconds from the
# oldest usable sample to NOW_STAMP), PA_VOL_RATE (the KiB an hour by which the free space
# shrinks, or `-`) and PA_VOL_HOURS (whole hours until the free space falls to 1 GiB at that
# rate, or `-`). Time between samples is measured from their stamps (uptime within a boot, the
# wall clock across boots), so a host that was off for a day does not make the same fall look
# faster. A projection needs samples spanning 72 hours and a free space that shrank over that
# span (the seven-day rate): a nightly backup or a one-off copy is a step, and only a fall that
# lasts is a trend. The rate is then the larger of the seven-day rate and the rate since the
# oldest sample of the last 24 hours, the latter only over at least 12 hours. A sample that
# cannot be read, lies ahead of NOW_STAMP or is over seven days old is not used. Status 2 for
# arguments out of form.
pa_vol_project() {
    local now="${1:-}" nowk st av span k old=-1 oldk=0 b24=-1 b24k=0 rate=-1 r
    PA_VOL_SPAN=0 PA_VOL_RATE=- PA_VOL_HOURS=-
    _pa_stamp_split "$now" || return 2
    nowk="$(_pa_kib "${2:-}")" || return 2
    while IFS=$'\t' read -r st av _ || [ -n "$st" ]; do
        k="$(_pa_kib "$av")" || continue
        span="$(_pa_stamp_span "$st" "$now")" || continue
        [ "$span" -gt 0 ] && [ "$span" -le 604800 ] || continue
        if [ "$span" -gt "$old" ]; then old="$span" oldk="$k"; fi
        if [ "$span" -le 86400 ] && [ "$span" -gt "$b24" ]; then b24="$span" b24k="$k"; fi
    done
    [ "$old" -gt 0 ] || return 0
    PA_VOL_SPAN="$old"
    [ "$old" -ge 259200 ] || return 0
    # KiB times 3600 stays under 2^63 for any size of 18 digits (under 1e15 KiB).
    rate=$(((oldk - nowk) * 3600 / old))
    [ "$rate" -gt 0 ] || return 0
    if [ "$b24" -ge 43200 ]; then
        r=$(((b24k - nowk) * 3600 / b24))
        [ "$r" -le "$rate" ] || rate="$r"
    fi
    PA_VOL_RATE="$rate"
    if [ "$nowk" -le 1048576 ]; then
        PA_VOL_HOURS=0
    else
        PA_VOL_HOURS=$(((nowk - 1048576) / rate))
    fi
    return 0
}

# pa_vol_judge SIZE AVAIL ITOTAL IAVAIL PCT HOURS: the triggers of one sample, from its sizes (bytes)
# and inode counts, the share of free space below which a volume is filling (PCT, the daemon's
# PROPOLIS_OPS_CAPACITY_FREE_PCT) and the projection's HOURS (`-` for none). Sets PA_VOL_A (free
# space under PCT of the size), PA_VOL_B (free inodes under 10%; never on a filesystem that
# reports no inodes, as btrfs does), PA_VOL_C (full within 72 hours at the current rate),
# PA_VOL_SOON (full within 12 hours, under 1 GiB and the rotation guard's 512 MiB reserve free on
# a filesystem that is also under half free, or free inodes under 2%), each 0 or 1, and
# PA_VOL_CAUSE (vol.low, vol.inodes or vol.projected for the first that holds, or `-`). Status 2
# for numbers out of form: unknown is never a trigger.
pa_vol_judge() {
    local size="${1:-}" avail="${2:-}" it="${3:-}" ia="${4:-}" pct="${5:-}" hours="${6:--}"
    local low=0 ilow=0
    PA_VOL_A=0 PA_VOL_B=0 PA_VOL_C=0 PA_VOL_SOON=0 PA_VOL_CAUSE=-
    [[ $size =~ ^[0-9]{1,18}$ && $avail =~ ^[0-9]{1,18}$ && $it =~ ^[0-9]{1,18}$ && $ia =~ ^[0-9]{1,18}$ ]] || return 2
    [[ $pct =~ ^[0-9]{1,3}$ ]] && [ "$((10#$pct))" -le 100 ] || return 2
    [[ $hours == - || $hours =~ ^[0-9]{1,18}$ ]] || return 2
    size=$((10#$size)) avail=$((10#$avail)) it=$((10#$it)) ia=$((10#$ia)) pct=$((10#$pct))
    # A filesystem that reports no size has no share of it free to judge, and one that reports no
    # inodes has no inode count to run out of.
    # shellcheck disable=SC2017 # dividing first keeps the product under 2^63 for a size of 18 digits
    if [ "$size" -gt 0 ] && [ "$avail" -lt "$((size / 100 * pct))" ]; then PA_VOL_A=1; fi
    # The floor is a size, so a filesystem smaller than about that is under it even when empty:
    # it counts only when the filesystem is under half free as well.
    if [ "$size" -gt 0 ] && [ "$avail" -lt 1610612736 ] && [ "$avail" -lt "$((size / 2))" ]; then low=1; fi
    if [ "$it" -gt 0 ] && [ "$ia" -lt "$((it / 10))" ]; then PA_VOL_B=1; fi
    if [ "$it" -gt 0 ] && [ "$ia" -lt "$((it / 50))" ]; then ilow=1; fi
    if [ "$hours" != - ] && [ "$((10#$hours))" -lt 72 ]; then PA_VOL_C=1; fi
    if [ "$low" = 1 ] || [ "$ilow" = 1 ] || { [ "$hours" != - ] && [ "$((10#$hours))" -lt 12 ]; }; then
        PA_VOL_SOON=1
    fi
    if [ "$PA_VOL_A" = 1 ] || [ "$low" = 1 ]; then
        PA_VOL_CAUSE=vol.low
    elif [ "$PA_VOL_B" = 1 ] || [ "$ilow" = 1 ]; then
        PA_VOL_CAUSE=vol.inodes
    elif [ "$PA_VOL_C" = 1 ]; then
        PA_VOL_CAUSE=vol.projected
    fi
    return 0
}

# _pa_path_ok PATH: an absolute path of the closed character set a path read from a file or a
# unit's properties must keep to before it reaches a command line: no blank, quote or glob
# character, and no `..` component.
_pa_path_ok() {
    local LC_ALL=C
    [[ ${1:-} =~ ^/[A-Za-z0-9._/-]{1,200}$ ]] && [[ /$1/ != */../* ]]
}

# pa_vol_stores BACKUP_ENV DATADIR: the stores whose filesystems the witness's hourly pass samples,
# which the walk's host view maps back to mount points; one list for both, so the walk can name
# every filesystem the witness keeps samples of. They are /var/lib/propolis, /var/log/propolis,
# /var/spool/propolis, the gateway's spool (PROPOLIS_GATEWAY_SPOOL_DIR in gateway.env, its
# default when unset or out of form), the journal, the backups (the last PROPOLIS_BACKUP_DIR in
# BACKUP_ENV, the backup unit's Environment property as systemctl prints it, the default when
# none is set or it is out of form), the local data directory DATADIR (empty: none) and the
# directory of each configured sensor log (PA_LOG_PATH, from pa_sensor_logs). A path is taken from
# a file or a property only in _pa_path_ok's form. BACKUP_ENV `?` is a property that could not be
# read.
#
# Sets PA_VOL_STORE (each path once), PA_VOL_STORE_AS (the account that reaches it: postgres for
# the data directory and propolis for a configured log directory, since that account could put a
# link on the path; empty for root's own), PA_VOL_STORE_LOG (1 for a store of sensor logs) and
# PA_VOL_STORE_KNOWN (0 when a path could not be learnt and its default stands in for it: a
# filesystem missing from the stores then proves nothing).
pa_vol_stores() {
    local benv="${1:-}" data="${2:-}" gw=/var/spool/propolis/gateway bk=/var/backups/propolis w bd="" p
    local -a words=()
    local -A at=()
    PA_VOL_STORE=() PA_VOL_STORE_AS=() PA_VOL_STORE_LOG=() PA_VOL_STORE_KNOWN=1
    pa_env_get PROPOLIS_GATEWAY_SPOOL_DIR "$PA_ENV_DIR/gateway.env" > /dev/null
    [ -z "$PA_ENV_UNREADABLE" ] || PA_VOL_STORE_KNOWN=0
    if [ "$PA_ENV_COMPLEX" = 0 ] && _pa_path_ok "$PA_ENV_VALUE"; then gw="$PA_ENV_VALUE"; fi
    PA_ENV_VALUE=""
    if [ "$benv" = "?" ]; then
        PA_VOL_STORE_KNOWN=0
    else
        # systemd uses the last assignment; one it had to quote holds a character no store path has.
        read -r -a words <<< "$benv" || true
        for w in "${words[@]}"; do
            case "$w" in PROPOLIS_BACKUP_DIR=*) bd="${w#PROPOLIS_BACKUP_DIR=}" ;; esac
        done
        ! _pa_path_ok "$bd" || bk="$bd"
    fi
    _pa_vol_store /var/lib/propolis "" 0
    _pa_vol_store /var/log/propolis "" 1
    _pa_vol_store /var/spool/propolis "" 0
    _pa_vol_store "$gw" "" 0
    _pa_vol_store /var/log/journal "" 0
    _pa_vol_store "$bk" "" 0
    ! _pa_path_ok "$data" || _pa_vol_store "$data" postgres 0
    for p in "${PA_LOG_PATH[@]}"; do
        p="${p%/*}"
        ! _pa_path_ok "$p" || _pa_vol_store "$p" propolis 1
    done
}

# _pa_vol_store PATH AS LOG: adds one store to pa_vol_stores' lists; a path already there keeps
# the account it was added with, and is a store of logs when either says so.
_pa_vol_store() {
    local k
    if [ -n "${at[$1]:-}" ]; then
        k=$((at[$1] - 1))
        [ "$3" != 1 ] || PA_VOL_STORE_LOG[k]=1
        return 0
    fi
    PA_VOL_STORE+=("$1") PA_VOL_STORE_AS+=("$2") PA_VOL_STORE_LOG+=("$3")
    at[$1]="${#PA_VOL_STORE[@]}"
}

# ---- the database probe and the push scheduler -------------------------------------------------

# _pa_pg_where URL: local when the URL names no host, a loopback host or a socket directory (a
# path, %2F-encoded in the host position or given as a host= query), else remote. Which one
# decides whether an outage is this host's own database or one several nodes may share.
_pa_pg_where() {
    local rest="${1#*://}" query="" host
    case "$rest" in *\?*) query="${rest#*\?}" rest="${rest%%\?*}" ;; esac
    rest="${rest%%/*}"
    host="${rest##*@}"
    case "$host" in
        \[*\]*) host="${host%%]*}" host="${host#[}" ;;
        *) host="${host%%:*}" ;;
    esac
    case "&$query" in
        *'&host=/'* | *'&host=%2F'* | *'&host=%2f'*)
            printf local
            return 0
            ;;
    esac
    case "$host" in
        '' | localhost | 127.0.0.1 | ::1 | /* | %2F* | %2f*) printf local ;;
        *) printf remote ;;
    esac
}

# pa_pg TIMEOUT SQL...: one psql session through `propolis pg-exec`, with the daemon's DATABASE_URL
# (fleet-listeners.env then propolis.env, systemd's order for propolis.service) given in that one
# process's environment and never on a command line. pg-exec drops every inherited PG* variable and
# sets its own from the URL, so the bounds go in psql's conninfo, which libpq merges with those:
# a 5 s connect timeout, a 5 s statement timeout and a read-only transaction, all inside an outer
# `timeout TIMEOUT`. PA_PG_APP names the session (default propolis-witness). Each SQL is one -c.
# psql never asks for a password (-w): it would ask on the terminal, past the closed stdin, and
# stop there until the timeout, so a server that wants one the URL lacks reads as db.auth.
#
# Before the binary is run as root it must pass pa_trusted_exec and carry pg-exec's guard string
# (the check deploy/backup.sh makes): an older binary would start the daemon as root instead.
# Reading 50 MB for the string every five minutes is waste, so a caller that keeps the answer may
# set PA_PG_GUARD_KNOWN to the inode/size/mtime (PA_PG_BIN_ID) of a binary that carried it: the
# same file is then not read again. PA_PG_GUARD says 1 (carries it), 0 (does not) or `-` (not
# looked at). The variable is never taken from the environment (see the top of this file).
#
# Prints psql's output and also sets PA_PG_OUT, because a caller reading it through $() would lose
# the rest: PA_PG_CAUSE (`-` on success, else a cause code of the closed list), PA_PG_WHY (why the
# binary was not run), PA_PG_ERR (psql's stderr, raw text another party wrote: a caller shows it
# only cleaned, and never stores or sends it) and PA_PG_WHERE (local or remote). 0 on success, 1
# otherwise, 2 for bad arguments.
pa_pg() {
    local t="${1:-}" url bin="$PA_ROOT/usr/local/bin/propolis" app="${PA_PG_APP:-propolis-witness}"
    local both line rc="" sql err
    local -a args=()
    PA_PG_OUT="" PA_PG_ERR="" PA_PG_CAUSE=unknown PA_PG_WHY="" PA_PG_WHERE="" PA_PG_GUARD=- PA_PG_BIN_ID=""
    [[ $t =~ ^[1-9][0-9]{0,2}$ ]] || return 2
    shift
    [ "$#" -ge 1 ] || return 2
    [[ $app =~ ^[a-z][a-z0-9-]{0,40}$ ]] || app=propolis-witness
    pa_env_get DATABASE_URL "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    url="$PA_ENV_VALUE"
    if [ -z "$url" ]; then
        PA_PG_CAUSE=config.invalid PA_PG_WHY="DATABASE_URL is not set"
        [ -z "$PA_ENV_UNREADABLE" ] || PA_PG_WHY="${PA_ENV_UNREADABLE##*/} cannot be read"
        return 1
    fi
    PA_PG_WHERE="$(_pa_pg_where "$url")"
    if ! pa_trusted_exec "$bin"; then
        PA_PG_CAUSE=tool.exec PA_PG_WHY="not trusted: $PA_UNTRUSTED"
        return 1
    fi
    PA_PG_BIN_ID="$(timeout 5 stat -c '%i/%s/%Y' -- "$bin" 2> /dev/null)" || PA_PG_BIN_ID=""
    [[ $PA_PG_BIN_ID =~ ^[0-9]{1,20}/[0-9]{1,20}/[0-9]{1,12}$ ]] || PA_PG_BIN_ID=""
    if [ -n "$PA_PG_BIN_ID" ] && [ "$PA_PG_GUARD_KNOWN" = "$PA_PG_BIN_ID" ]; then
        PA_PG_GUARD=1
    elif timeout 30 grep -q -a -F 'propolis pg-exec: DATABASE_URL is not set' -- "$bin" 2> /dev/null; then
        PA_PG_GUARD=1
    else
        PA_PG_GUARD=0 PA_PG_CAUSE=tool.exec PA_PG_WHY="daemon binary predates pg-exec"
        return 1
    fi
    for sql in "$@"; do args+=(-c "$sql"); done
    # Both streams come back through one capture, each line tagged by its stream, because a value
    # with no NUL cannot carry them apart otherwise and the walk may write no temporary file. The
    # NUL bytes a server message could hold are dropped before bash would warn about them.
    both="$(
        {
            o="$(DATABASE_URL="$url" timeout -k 2 "$t" "$bin" pg-exec psql -X -A -t -q -w -v ON_ERROR_STOP=1 \
                -d "connect_timeout=5 application_name=$app options='-c statement_timeout=5000 -c default_transaction_read_only=on'" \
                "${args[@]}" < /dev/null 2> >(LC_ALL=C tr -d '\000' | LC_ALL=C sed 's/^/E/' >&4) \
                | LC_ALL=C tr -d '\000'
            exit "${PIPESTATUS[0]}")"
            printf 'R%s\n' "$?"
            [ -z "$o" ] || printf '%s\n' "$o" | LC_ALL=C sed 's/^/O/'
        } 4>&1
    )"
    while IFS= read -r line; do
        case "$line" in
            R*) rc="${line#R}" ;;
            O*) PA_PG_OUT+="${line#O}"$'\n' ;;
            E*) PA_PG_ERR+="${line#E}"$'\n' ;;
        esac
    done <<< "$both"
    PA_PG_OUT="${PA_PG_OUT%$'\n'}" PA_PG_ERR="${PA_PG_ERR%$'\n'}"
    if [ "$rc" = 0 ]; then
        PA_PG_CAUSE=-
        printf '%s' "$PA_PG_OUT"
        return 0
    fi
    err="$PA_PG_ERR"
    if [ "$rc" = 124 ] || [ "$rc" = 137 ] || [[ $err == *'timeout expired'* ]]; then
        PA_PG_CAUSE=db.timeout
    elif [ "$rc" = 126 ] || [ "$rc" = 127 ] || [[ $err == 'propolis pg-exec: cannot run psql'* ]] \
        || [[ ${err%%$'\n'*} == *'Permission denied'* ]]; then
        PA_PG_CAUSE=tool.exec
    elif [[ $err == *'password authentication failed'* || $err == *'Peer authentication failed'* \
        || $err == *'Ident authentication failed'* || $err == *'no pg_hba.conf entry'* \
        || $err == *'no password supplied'* \
        || ($err == *'role "'* && $err == *'does not exist'*) ]]; then
        PA_PG_CAUSE=db.auth
    elif [[ $err == *'could not connect'* || $err == *'Connection refused'* \
        || $err == *'could not translate host name'* || $err == *'No route to host'* ]]; then
        PA_PG_CAUSE=db.unreachable
    elif [[ $err == *'propolis pg-exec: '* ]]; then
        PA_PG_CAUSE=config.invalid
    elif [ "$rc" = 2 ]; then
        PA_PG_CAUSE=db.unreachable
    fi
    return 1
}

# _pa_sched_text FILE: sets _PA_SCHED_TEXT to FILE's content, read as root only when it is a
# regular file and not a link, at most 64 KiB, under `timeout 5`. Fails otherwise.
_pa_sched_text() {
    local s
    _PA_SCHED_TEXT=""
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    s="$(timeout 5 stat -c %s -- "$1" 2> /dev/null)" || return 1
    [[ $s =~ ^[0-9]{1,12}$ ]] && [ "$s" -le 65536 ] || return 1
    _PA_SCHED_TEXT="$(timeout 5 head -c 65536 -- "$1" 2> /dev/null | LC_ALL=C tr -d '\000')" || return 1
}

# pa_push_scheduler: whether anything runs the public-feed push (deploy/blocklist-sync.sh). A
# crontab line that is not a comment and names blocklist-sync, in /etc/crontab, /etc/cron.d/*,
# /var/spool/cron/crontabs/* (Debian) or /var/spool/cron/* (RHEL), counts as cron; a unit in
# /etc/systemd/system whose ExecStart= names it counts as timer when the timer of the same name is
# enabled. The spool files are read directly, never through the setgid crontab binary; their
# directories are not writable by the accounts they belong to, so no account can plant a link or a
# FIFO there, and every file is still read only when regular and small (_pa_sched_text). Prints
# `<cron|timer|none> <count>` and sets PA_SCHED and PA_SCHED_N. Status 1 when a file could not be
# read, so a caller that found nothing shows unknown, never none.
pa_push_scheduler() {
    local f name bad=0 cron=0 timer=0
    for f in "$PA_ROOT/etc/crontab" "$PA_ROOT"/etc/cron.d/* "$PA_ROOT"/var/spool/cron/crontabs/* \
        "$PA_ROOT"/var/spool/cron/*; do
        { [ -e "$f" ] || [ -L "$f" ]; } && [ ! -L "$f" ] && [ ! -d "$f" ] || continue
        if ! _pa_sched_text "$f"; then
            bad=1
            continue
        fi
        # grep -c reads to the end: a grep -q stopping at the first match would kill the writers
        # before it, and under the caller's pipefail the match would read as a failure.
        if [ "$(printf '%s\n' "$_PA_SCHED_TEXT" | grep -v '^[[:space:]]*#' | grep -c -F blocklist-sync)" -gt 0 ]; then
            cron=$((cron + 1))
        fi
    done
    for f in "$PA_ROOT"/etc/systemd/system/*.service; do
        [ -e "$f" ] && [ ! -L "$f" ] || continue
        if ! _pa_sched_text "$f"; then
            bad=1
            continue
        fi
        [ "$(printf '%s\n' "$_PA_SCHED_TEXT" | grep -c '^[[:space:]]*ExecStart=.*blocklist-sync')" -gt 0 ] || continue
        name="${f##*/}"
        name="${name%.service}"
        if timeout 10 systemctl is-enabled --quiet "$name.timer" 2> /dev/null; then
            timer=$((timer + 1))
        fi
    done
    PA_SCHED=none PA_SCHED_N=$((cron + timer))
    if [ "$cron" -gt 0 ]; then
        PA_SCHED=cron
    elif [ "$timer" -gt 0 ]; then
        PA_SCHED=timer
    fi
    printf '%s %s' "$PA_SCHED" "$PA_SCHED_N"
    [ "$bad" = 0 ]
}

# ---- the incident record -----------------------------------------------------------------------
#
# incidents holds an `N<TAB><next number>` line, one `I` line of 34 fields per incident (the
# fields are numbered from 1: 1 id, 2 key, 3 kind, 4 stage, 5 inst, 6 tier, 7 state, 8 first_seen,
# 9 opened, 10 onset, 11 cause, 12 cause_since, 13 parent, 14 sends, 15 last_sent, 16 last_tx,
# 17 delivered_open, 18 reminders, 19 next_due, 20 acked, 21 resolved, 22 proof, 23 reopens,
# 24 reopen_first, 25 hold_until, 26 pending_tx, 27 pending_since, 28 ref, 29 would_push, 30 flags,
# 31 occ, 32 nr_seen, 33 legacy_out, 34 count) and `W` lines of withheld transitions. One key, one
# record. The caller holds the lock from pa_incident_load to pa_incident_put.
#
# The whole lifecycle runs in record mode: a first sighting (pending) the witness's light pass
# opens or drops, an open, a repeat that only counts, a change, a reminder, a resolve with its
# proof and a reopen of the same id. Nothing is sent: in the legacy profile each transition v2
# would push adds one to would_push. A NOTICE never would, and neither would a child folded under
# a parent, whose parent speaks for it.

# _pa_num V: V when it is a plain count, else 0.
_pa_num() {
    if [[ ${1:-} =~ ^[0-9]{1,9}$ ]]; then printf '%s' "$((10#$1))"; else printf 0; fi
}

# pa_incident_load: reads incidents into memory (the persistent copy or /run's, whichever is
# newer). Lines of other types, and fields after the 34th, are kept as they are for the version
# that knows them. The next number is never below one past the highest id already used, so a
# damaged N line cannot hand out an id twice.
pa_incident_load() {
    local line n top=0
    _PA_INC_N=1 _PA_INC_I=() _PA_INC_REST=() PA_INC=() PA_INC_AT=-1 PA_INC_EXTRA=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            N$'\t'*)
                n="${line#N$'\t'}"
                n="${n%%$'\t'*}"
                if [[ $n =~ ^[0-9]{1,9}$ ]]; then _PA_INC_N=$((10#$n)); fi
                ;;
            I$'\t'*)
                _PA_INC_I+=("$line")
                n="${line#I$'\t'w#}"
                n="${n%%$'\t'*}"
                if [[ $n =~ ^[0-9]{1,9}$ ]] && [ "$((10#$n))" -ge "$top" ]; then top=$((10#$n + 1)); fi
                ;;
            *) _PA_INC_REST+=("$line") ;;
        esac
    done < <(pa_state_read incidents)
    [ "$_PA_INC_N" -ge "$top" ] || _PA_INC_N="$top"
    [ "$_PA_INC_N" -ge 1 ] || _PA_INC_N=1
    return 0
}

# pa_incident_get KEY: finds KEY's record. Sets PA_INC to its fields (PA_INC[1] the id to
# PA_INC[34] the count; a field an older writer did not have reads `-`), PA_INC_AT to its place
# and PA_INC_EXTRA to the fields after the 34th. Status 1, with PA_INC empty and PA_INC_AT -1,
# when there is none.
pa_incident_get() {
    local i
    local -a f
    PA_INC=() PA_INC_AT=-1 PA_INC_EXTRA=""
    for i in "${!_PA_INC_I[@]}"; do
        IFS=$'\t' read -r -a f <<< "${_PA_INC_I[$i]}"
        [ "${f[2]:-}" = "${1:-}" ] || continue
        PA_INC=("${f[@]:0:35}")
        while [ "${#PA_INC[@]}" -lt 35 ]; do PA_INC+=(-); done
        if [ "${#f[@]}" -gt 35 ]; then
            PA_INC_EXTRA="$(
                IFS=$'\t'
                printf '%s' "${f[*]:35}"
            )"
        fi
        PA_INC_AT="$i"
        return 0
    done
    return 1
}

# pa_finding_inst RULE ID K12 SCOPE: the instance a config-check finding is about, printed as
# `<kind><TAB><name>` for pa_id_table, or nothing when it cannot be recovered (the finding then
# reads `a listener` or `a source`). config-check's TSV carries only a hash of the finding's key
# and its scope, which is text, so the instance is found by matching, never taken from the line:
# RULE unit hashes `<id>:<unit>` for each configured sensor unit in PA_FI_UNITS (names without
# .service); scope finds the listener row (PA_FI_SCOPE, PA_FI_UNIT, from the run's R lines) whose
# scope is SCOPE; logpath hashes `<id>:<path>` for each path of PROPOLIS_SENSOR_LOGS
# (PA_LOG_LABEL and PA_LOG_PATH, from pa_sensor_logs) and gives that log's label. A unit found is
# printed only when its name passes pa_unit_name_ok.
pa_finding_inst() {
    local rule="${1:-}" id="${2:-}" k12="${3:-}" scope="${4:-}" i h u
    [[ $k12 =~ ^[0-9a-f]{12}$ ]] || [ "$rule" = scope ] || return 0
    case "$rule" in
        unit)
            for u in "${PA_FI_UNITS[@]}"; do
                h="$(printf '%s' "$id:$u" | sha256sum 2> /dev/null)" || continue
                if [ "${h:0:12}" = "$k12" ] && pa_unit_name_ok "$u.service"; then
                    printf 'unit\t%s.service' "$u"
                    return 0
                fi
            done
            ;;
        scope)
            for i in "${!PA_FI_SCOPE[@]}"; do
                [ "${PA_FI_SCOPE[$i]}" = "$scope" ] || continue
                u="${PA_FI_UNIT[$i]:-}.service"
                if pa_unit_name_ok "$u"; then printf 'unit\t%s' "$u"; fi
                return 0
            done
            ;;
        logpath)
            for i in "${!PA_LOG_PATH[@]}"; do
                h="$(printf '%s' "$id:${PA_LOG_PATH[$i]}" | sha256sum 2> /dev/null)" || continue
                if [ "${h:0:12}" = "$k12" ] && pa_plain_id "${PA_LOG_LABEL[$i]}"; then
                    printf 'source\t%s' "${PA_LOG_LABEL[$i]}"
                    return 0
                fi
            done
            ;;
    esac
    return 0
}

# _pa_tier_rank T: 3 for PAGE, 2 for ACT, 1 for NOTICE, 0 for anything else, so a record whose
# tier field is damaged takes the next firing's.
_pa_tier_rank() {
    case "${1:-}" in
        PAGE) printf 3 ;;
        ACT) printf 2 ;;
        NOTICE) printf 1 ;;
        *) printf 0 ;;
    esac
}

# _pa_flag_add F: adds flag F to the current record's flag list (field 30), once.
_pa_flag_add() {
    local flags="${PA_INC[30]:--}"
    [ -n "${1:-}" ] || return 0
    case ",$flags," in *",$1,"*) return 0 ;; esac
    if [ "$flags" = - ]; then PA_INC[30]="$1"; else PA_INC[30]="$flags,$1"; fi
}

# _pa_flag_drop NAME: NAME taken out of the current record's flags, `-` when none is left.
_pa_flag_drop() {
    local flags=",${PA_INC[30]:--},"
    flags="${flags//,$1,/,}"
    flags="${flags#,}"
    flags="${flags%,}"
    PA_INC[30]="${flags:--}"
}

# _pa_counts: the current record is one whose transitions v2 would push: not a NOTICE, not folded
# under a parent, and not a standing duplicate of a condition the daemon already reports.
_pa_counts() {
    [ "${PA_INC[6]:-}" != NOTICE ] && [ "${PA_INC[13]:--}" = - ] && [[ ,${PA_INC[30]:--}, != *,dup,* ]]
}

# _pa_stamp_add STAMP SECONDS: STAMP moved SECONDS later, on the wall clock and in uptime alike, so
# its age keeps counting from uptime within the boot. Fails on a malformed stamp.
_pa_stamp_add() {
    _pa_stamp_split "${1:-}" || return 1
    [[ ${2:-} =~ ^[0-9]{1,9}$ ]] || return 1
    printf '%s/%s/%s' "$((10#$_PA_W + 10#$2))" "$_PA_B" "$((10#$_PA_U + 10#$2))"
}

# _pa_stamp_span FROM TO: seconds from stamp FROM to stamp TO, by uptime within one boot and by
# the wall clock across boots; fails on a malformed stamp.
_pa_stamp_span() {
    local w b u
    _pa_stamp_split "${1:-}" || return 1
    w="$_PA_W" b="$_PA_B" u="$_PA_U"
    _pa_stamp_split "${2:-}" || return 1
    if [ "$b" != - ] && [ "$b" = "$_PA_B" ]; then
        printf '%s' "$((10#$_PA_U - 10#$u))"
    else
        printf '%s' "$((10#$_PA_W - 10#$w))"
    fi
}

# _pa_due STAMP: STAMP is a time that has come. One that is malformed or in the future (pa_age -1)
# has not: a reminder or a hold is never brought forward by a clock fault.
_pa_due() {
    local a
    a="$(pa_age "${1:-}")"
    [ "$a" -ge 0 ]
}

# _pa_reminder_offsets TIER: the reminder times after an open, in seconds: 1 h, 4 h and 12 h for
# a PAGE, 4 h and 12 h for an ACT, none for a NOTICE.
_pa_reminder_offsets() {
    case "${1:-}" in
        PAGE) printf '3600 14400 43200' ;;
        ACT) printf '14400 43200' ;;
    esac
}

# _pa_schedule: sets next_due of the current record from its tier, when it was opened (or last
# reopened) and how many reminders it has had: `-` when there are no more, for a kind that is
# never reminded (unit-nobind), and for a record that does not count (_pa_counts).
_pa_schedule() {
    local -a offs=()
    local n
    PA_INC[19]=-
    _pa_counts || return 0
    [ "${PA_INC[3]:-}" != unit-nobind ] || return 0
    read -r -a offs <<< "$(_pa_reminder_offsets "${PA_INC[6]:-}")"
    n="$(_pa_num "${PA_INC[18]:-}")"
    [ "$n" -lt "${#offs[@]}" ] || return 0
    PA_INC[19]="$(_pa_stamp_add "${PA_INC[9]:-}" "${offs[$n]}")" || PA_INC[19]=-
}

# _pa_reopen_window: the current record is resolved, and its resolve is recent enough for the
# same fault to count as back: within max(2 x (resolved - opened), 30 min). A resolve or open time
# that cannot be read, or a resolve dated after now, means no: a new incident always gets its
# own id and its first message.
_pa_reopen_window() {
    local span age window
    [ "${PA_INC[7]:-}" = resolved ] || return 1
    span="$(_pa_stamp_span "${PA_INC[9]:-}" "${PA_INC[21]:-}")" || return 1
    age="$(pa_age "${PA_INC[21]:-}")"
    [ "$age" -ge 0 ] || return 1
    window=$((2 * span))
    [ "$window" -ge 1800 ] || window=1800
    [ "$age" -le "$window" ]
}

# _pa_opened: the current record opens now: from a first sighting, or as a reopen when it still
# holds the resolve of an earlier open (a pending record kept inside its reopen window). A reopen
# keeps the id, clears the acknowledgement and counts reopens within 24 h of the first; the third
# holds the next resolve until its proof has held an hour (hold_until).
_pa_opened() {
    local first
    PA_INC[9]="$PA_STAMP" PA_INC[18]=0
    if [ "${PA_INC[21]:--}" != - ]; then
        first="${PA_INC[24]:--}"
        if [ "$first" = - ] || [ "$(pa_age "$first")" -lt 0 ] || [ "$(pa_age "$first")" -gt 86400 ]; then
            PA_INC[24]="$PA_STAMP" PA_INC[23]=1
        else
            PA_INC[23]=$(($(_pa_num "${PA_INC[23]:-}") + 1))
        fi
        [ "${PA_INC[23]}" -lt 3 ] || PA_INC[25]="$PA_STAMP"
        PA_INC[7]=open PA_INC[10]="$PA_STAMP" PA_INC[20]=- PA_INC[21]=- PA_INC[22]=- PA_INC[16]=reopen
        PA_TX=reopen PA_TX_DONE=open
    else
        PA_INC[7]=open PA_INC[16]=open
        PA_TX=open PA_TX_DONE=open
    fi
    if _pa_counts; then
        PA_INC[29]=$(($(_pa_num "${PA_INC[29]}") + 1))
    else
        PA_TX=-
    fi
    _pa_schedule
}

# _pa_class CAUSE: the class of a stored cause, the part before the dot (`proc` of proc.exit:3).
_pa_class() {
    printf '%s' "${1%%.*}"
}

# pa_incident_transition KEY TX: applies a transition to KEY's record in memory. pa_incident_put
# (or pa_incident_set, then pa_incident_write) writes the result. The attributes of a firing come
# from PA_REC_KIND, PA_REC_STAGE, PA_REC_INST, PA_REC_TIER, PA_REC_CAUSE, PA_REC_NR (NRestarts at
# the sighting), PA_REC_OUT (what today's hook did) and PA_REC_FLAG (one flag to add, or empty).
# Sets PA_TX_DONE to what was done (pending, open, occ, drop, change, remind or resolve) and PA_TX
# to what v2 would send (open, reopen, change, remind, resolve) or `-`; in record mode each of
# those adds one to would_push instead.
#
# TX pending (a first sighting, which the witness's light pass later opens or drops) or open, a
# firing: for a record already pending, open or acked it raises occ, takes the latest outcome and
# adds its flag. It takes the firing's kind, stage, tier and cause too, unless its tier ranks below
# the record's (PAGE over ACT over NOTICE): one key can carry firings of two tiers (a refused
# rotation at ACT, then a routine skip at NOTICE), and an unresolved fault must stay recorded at
# the tier it has, because a tier may rise while an incident is open but never fall. An inst the
# record lacks (`-`) is filled from the firing; one it has is kept. A pending record opens when TX
# is open. A resolved record inside its reopen window keeps its id: TX open reopens it, and TX
# pending makes it pending again with its resolve kept, so that opening it reopens it and dropping
# it resolves it again as it was; either way it takes this firing's NRestarts (nr_seen), and a
# pending one this firing's time as its onset, which the light pass judges it by. Any other resolved record is replaced by a new incident with the
# next id.
#
# The witness's transitions, each on an existing record (status 1 when there is none, 3 when the
# record is not in a state the transition applies to): drop removes a pending first sighting that
# healed (or puts a kept resolve back); change applies the attributes of a fresh reading to an
# open or acked record and counts when the cause changes class (an unknown cause on either side
# is learnt, not changed) or the tier rises; remind sends the reminder that is due on an open
# record (3 when none is due); resolve closes an open or acked record with the proof in
# PA_REC_PROOF (2 for a proof outside the closed list, 4 while a flapping record's hold_until is
# less than an hour old).
pa_incident_transition() {
    local key="${1:-}" tx="${2:-}" flags
    PA_TX=- PA_TX_DONE=-
    case "$tx" in
        pending | open) ;;
        drop | change | remind | resolve)
            [ -n "${PA_STAMP:-}" ] || pa_now
            pa_incident_get "$key" || return 1
            "_pa_tx_$tx"
            return
            ;;
        *) return 2 ;;
    esac
    [ -n "${PA_STAMP:-}" ] || pa_now
    if pa_incident_get "$key" && _pa_reopen_window; then
        PA_INC[31]=$(($(_pa_num "${PA_INC[31]}") + 1))
        [ "${PA_INC[31]}" -le 999999999 ] || PA_INC[31]=999999999
        PA_INC[33]="${PA_REC_OUT:--}"
        # The maint flag describes the sighting the record is judged on: one left by an earlier
        # episode would hold this one as planned work when no marker is involved.
        _pa_flag_drop maint
        _pa_flag_add "${PA_REC_FLAG:-}"
        [ -z "${PA_REC_KIND:-}" ] || PA_INC[3]="$PA_REC_KIND"
        [ -z "${PA_REC_STAGE:-}" ] || PA_INC[4]="$PA_REC_STAGE"
        [ -z "${PA_REC_TIER:-}" ] || PA_INC[6]="$PA_REC_TIER"
        if [ -n "${PA_REC_CAUSE:-}" ] && [ "$PA_REC_CAUSE" != "${PA_INC[11]}" ]; then
            PA_INC[11]="$PA_REC_CAUSE" PA_INC[12]="$PA_STAMP"
        fi
        # The light pass judges a first sighting on what was read this time: the count of the
        # first open would make one healed restart look like a unit that kept failing.
        PA_INC[32]="${PA_REC_NR:--}"
        if [ "$tx" = open ]; then
            _pa_opened
        else
            PA_INC[7]=pending PA_INC[10]="$PA_STAMP" PA_TX_DONE=pending
        fi
        return 0
    fi
    if [ "$PA_INC_AT" -ge 0 ] && [ "${PA_INC[7]}" != resolved ]; then
        if [ -z "${PA_REC_TIER:-}" ] \
            || [ "$(_pa_tier_rank "$PA_REC_TIER")" -ge "$(_pa_tier_rank "${PA_INC[6]}")" ]; then
            [ -z "${PA_REC_KIND:-}" ] || PA_INC[3]="$PA_REC_KIND"
            [ -z "${PA_REC_STAGE:-}" ] || PA_INC[4]="$PA_REC_STAGE"
            [ -z "${PA_REC_TIER:-}" ] || PA_INC[6]="$PA_REC_TIER"
            if [ -n "${PA_REC_CAUSE:-}" ] && [ "$PA_REC_CAUSE" != "${PA_INC[11]}" ]; then
                PA_INC[11]="$PA_REC_CAUSE" PA_INC[12]="$PA_STAMP"
            fi
        fi
        if [ "${PA_INC[5]}" = - ] && [ "${PA_REC_INST:--}" != - ]; then
            PA_INC[5]="$PA_REC_INST"
        fi
        PA_INC[31]=$(($(_pa_num "${PA_INC[31]}") + 1))
        [ "${PA_INC[31]}" -le 999999999 ] || PA_INC[31]=999999999
        PA_INC[33]="${PA_REC_OUT:--}"
        _pa_flag_add "${PA_REC_FLAG:-}"
        PA_TX_DONE=occ
        if [ "${PA_INC[7]}" = pending ] && [ "$tx" = open ]; then
            _pa_opened
        fi
        return 0
    fi
    # A new incident, in place of a resolved record of the same key when there is one.
    flags="${PA_REC_FLAG:-}"
    PA_INC=(I "w#$_PA_INC_N" "$key" "${PA_REC_KIND:--}" "${PA_REC_STAGE:--}" "${PA_REC_INST:--}"
        "${PA_REC_TIER:--}" "$tx" "$PA_STAMP" - "$PA_STAMP" "${PA_REC_CAUSE:-unknown}" "$PA_STAMP"
        - 0 - - 0 0 - - - - 0 - - - - - 0 "${flags:--}" 1 "${PA_REC_NR:--}" "${PA_REC_OUT:--}" -)
    PA_INC_EXTRA=""
    _PA_INC_N=$((_PA_INC_N + 1))
    PA_TX_DONE="$tx"
    [ "$tx" != open ] || _pa_opened
    return 0
}

# _pa_tx_drop: a pending first sighting whose unit healed leaves no record; one kept inside its
# reopen window is resolved again as it was.
_pa_tx_drop() {
    [ "${PA_INC[7]}" = pending ] || return 3
    if [ "${PA_INC[21]:--}" != - ]; then
        PA_INC[7]=resolved
    else
        unset '_PA_INC_I[PA_INC_AT]'
        _PA_INC_I=("${_PA_INC_I[@]}")
        PA_INC=() PA_INC_AT=-1 PA_INC_EXTRA=""
    fi
    PA_TX_DONE=drop
}

# _pa_tx_change: a fresh reading of an open or acked record. It counts as a change when the cause
# changes class or the tier rises; otherwise, like a repeat, it only records the new cause.
_pa_tx_change() {
    local old="${PA_INC[11]:-unknown}" new="${PA_REC_CAUSE:-}" moved=0
    case "${PA_INC[7]}" in open | acked) ;; *) return 3 ;; esac
    if [ -n "${PA_REC_TIER:-}" ] && [ "$(_pa_tier_rank "$PA_REC_TIER")" -gt "$(_pa_tier_rank "${PA_INC[6]}")" ]; then
        PA_INC[6]="$PA_REC_TIER" moved=1
    fi
    if [ -n "$new" ] && [ "$new" != "$old" ]; then
        if [ "$old" != unknown ] && [ "$new" != unknown ] && [ "$(_pa_class "$old")" != "$(_pa_class "$new")" ]; then
            moved=1
        fi
        PA_INC[11]="$new" PA_INC[12]="$PA_STAMP"
    fi
    [ -z "${PA_REC_KIND:-}" ] || PA_INC[3]="$PA_REC_KIND"
    PA_INC[31]=$(($(_pa_num "${PA_INC[31]}") + 1))
    [ "${PA_INC[31]}" -le 999999999 ] || PA_INC[31]=999999999
    PA_TX_DONE=occ
    [ "$moved" = 1 ] && _pa_counts || return 0
    PA_INC[16]=change PA_INC[29]=$(($(_pa_num "${PA_INC[29]}") + 1))
    PA_TX=change PA_TX_DONE=change
}

# _pa_tx_remind: the reminder that is due on an open record (an acked one is not reminded), and
# the next one scheduled. Offsets that went by while no pass ran (a stopped timer, or a schedule
# given to a record opened before the witness) are skipped: one late reminder says the same as
# several, and they would otherwise come due on consecutive passes. The count of reminders stays
# the count recorded (the status walk shows it), so the next one is found by its time alone.
_pa_tx_remind() {
    local -a offs=()
    local o next
    [ "${PA_INC[7]}" = open ] && [ "${PA_INC[19]:--}" != - ] && _pa_due "${PA_INC[19]}" || return 3
    PA_INC[18]=$(($(_pa_num "${PA_INC[18]}") + 1)) PA_INC[16]=remind
    PA_INC[29]=$(($(_pa_num "${PA_INC[29]}") + 1))
    PA_TX=remind PA_TX_DONE=remind
    _pa_schedule
    [ "${PA_INC[19]}" != - ] && _pa_due "${PA_INC[19]}" || return 0
    PA_INC[19]=-
    read -r -a offs <<< "$(_pa_reminder_offsets "${PA_INC[6]:-}")"
    for o in "${offs[@]}"; do
        next="$(_pa_stamp_add "${PA_INC[9]:-}" "$o")" || break
        if ! _pa_due "$next"; then
            PA_INC[19]="$next"
            break
        fi
    done
    return 0
}

# _pa_tx_resolve: closes an open or acked record with its proof. It counts only where v2 would
# have sent the open: a RESOLVED follows only an open that went out.
_pa_tx_resolve() {
    case "${PA_REC_PROOF:-}" in
        active10 | nextrun | disabled | quiet30 | ready2 | db2 | sent2xx | clean2 | pushed | persist2 \
            | spool2 | quiet24 | ended | pulled | room2 | fresh2 | restart) ;;
        *) return 2 ;;
    esac
    case "${PA_INC[7]}" in open | acked) ;; *) return 3 ;; esac
    if [ "${PA_INC[25]:--}" != - ]; then
        [ "$(pa_age "${PA_INC[25]}")" -ge 3600 ] || return 4
    fi
    PA_INC[7]=resolved PA_INC[21]="$PA_STAMP" PA_INC[22]="$PA_REC_PROOF" PA_INC[16]=resolve
    PA_INC[19]=- PA_INC[25]=-
    PA_TX_DONE=resolve
    if _pa_counts && [ "$(_pa_num "${PA_INC[29]}")" -gt 0 ]; then
        PA_INC[29]=$(($(_pa_num "${PA_INC[29]}") + 1))
        PA_TX=resolve
    fi
}

# pa_incident_fold KEY PARENT_ID: the late-parent rule. A child already open (or pending) when a
# fixed-format line ties its cause to another open incident takes that incident as its parent:
# from then on it is not reminded and nothing it does counts, and its resolve folds into the
# parent's, whose lines carry the folded count. Nothing is sent when it happens. Status 1 when
# either record is missing, not open, or the same one.
pa_incident_fold() {
    local key="${1:-}" parent="${2:-}" i
    local -a f
    [[ $parent =~ ^w#[0-9]{1,9}$ ]] || return 1
    for i in "${!_PA_INC_I[@]}"; do
        IFS=$'\t' read -r -a f <<< "${_PA_INC_I[$i]}"
        [ "${f[1]:-}" = "$parent" ] || continue
        [ "${f[2]:-}" != "$key" ] || return 1
        case "${f[7]:-}" in open | acked) ;; *) return 1 ;; esac
        pa_incident_get "$key" || return 1
        case "${PA_INC[7]}" in open | acked | pending) ;; *) return 1 ;; esac
        PA_INC[13]="$parent" PA_INC[19]=-
        _pa_flag_add folded
        return 0
    done
    return 1
}

# pa_first_sighting NR_SEEN NRESTARTS UP PREV: how the light pass judges a first sighting the hook
# left pending for a unit that restarts itself. NR_SEEN is the NRestarts the hook read (`-` when
# unknown), NRESTARTS the count now (empty when unknown), UP how long the unit has been active on
# this sample in seconds (`-` when it is not active) and PREV the same on the previous light pass
# (`?` when there is none). Prints open, wait or drop. systemd raises NRestarts when it enqueues
# the restart, after the hook read it, so one restart that healed shows as NR_SEEN + 1: a count
# above that means it failed again. A unit not active is still failing. A unit up for under 60 s
# opens when it was also up for under 60 s, or down, on the previous pass, and otherwise waits
# one pass, since the sample may have landed just after the one restart. Anything else healed.
pa_first_sighting() {
    local sighted="${1:-}" now_n="${2:-}" up="${3:-}" prev="${4:-}"
    if ! [[ $up =~ ^[0-9]{1,12}$ ]]; then
        printf open
    elif [[ $sighted =~ ^[0-9]{1,9}$ && $now_n =~ ^[0-9]{1,9}$ ]] && [ "$((10#$now_n))" -gt "$((10#$sighted + 1))" ]; then
        printf open
    elif [ "$((10#$up))" -lt 60 ]; then
        if [ "$prev" = - ] || { [[ $prev =~ ^[0-9]{1,12}$ ]] && [ "$((10#$prev))" -lt 60 ]; }; then
            printf open
        else
            printf wait
        fi
    else
        printf drop
    fi
}

# _pa_incident_make_room: drops the first resolved record, for a new one past the 512-record
# bound. Fails when every record is open, acked or pending: those are never dropped.
_pa_incident_make_room() {
    local i
    local -a f
    for i in "${!_PA_INC_I[@]}"; do
        IFS=$'\t' read -r -a f <<< "${_PA_INC_I[$i]}"
        if [ "${f[7]:-}" = resolved ]; then
            unset '_PA_INC_I[i]'
            _PA_INC_I=("${_PA_INC_I[@]}")
            return 0
        fi
    done
    return 1
}

# pa_incident_put: puts the current record (PA_INC) back in its place, or appends it, and writes
# incidents with pa_state_write, which sets PA_WHERE. A field that is empty is written `-` and one
# that fails pa_ok_field `?`. Status 2 when the key itself fails pa_ok_field (a `?` key would merge
# unrelated incidents), 3 when 512 records are open or pending and none can make room, and
# pa_state_write's status otherwise.
pa_incident_put() {
    [ "${#PA_INC[@]}" -ge 35 ] || return 2
    pa_incident_set || return
    pa_incident_write
}

# pa_incident_set: pa_incident_put without the write, for a caller that changes several records
# and writes them once with pa_incident_write. After a drop (PA_INC empty) there is nothing to put
# back and it returns 0. Status 2 and 3 as pa_incident_put.
pa_incident_set() {
    local i v line
    [ "${#PA_INC[@]}" -gt 0 ] || return 0
    [ "${#PA_INC[@]}" -ge 35 ] || return 2
    pa_ok_field "${PA_INC[2]}" || return 2
    line=I
    for ((i = 1; i <= 34; i++)); do
        v="${PA_INC[$i]}"
        if [ -z "$v" ]; then
            v=-
        elif ! pa_ok_field "$v"; then
            v='?'
        fi
        line+=$'\t'"$v"
    done
    [ -z "$PA_INC_EXTRA" ] || line+=$'\t'"$PA_INC_EXTRA"
    if [ "$PA_INC_AT" -ge 0 ]; then
        _PA_INC_I[PA_INC_AT]="$line"
    else
        if [ "${#_PA_INC_I[@]}" -ge 512 ] && ! _pa_incident_make_room; then
            return 3
        fi
        _PA_INC_I+=("$line")
        PA_INC_AT=$((${#_PA_INC_I[@]} - 1))
    fi
    return 0
}

# pa_incident_write: writes the records in memory as incidents with pa_state_write, which sets
# PA_WHERE, and returns its status.
pa_incident_write() {
    local line out
    out="N"$'\t'"$_PA_INC_N"$'\n'
    for line in "${_PA_INC_I[@]}" "${_PA_INC_REST[@]}"; do
        out+="$line"$'\n'
    done
    pa_state_write incidents < <(printf '%s' "$out")
}

# pa_incident_prune: the bounds of the incidents file, in memory: a resolved record goes seven
# days after its resolve and a withheld (W) line after 48 hours. A time that cannot be read keeps
# the line, and open, acked and pending records always stay.
pa_incident_prune() {
    local i a
    local -a f keep=() rest=()
    for i in "${!_PA_INC_I[@]}"; do
        IFS=$'\t' read -r -a f <<< "${_PA_INC_I[$i]}"
        if [ "${f[7]:-}" = resolved ]; then
            a="$(pa_age "${f[21]:-}")"
            [ "$a" -le 604800 ] || continue
        fi
        keep+=("${_PA_INC_I[$i]}")
    done
    for i in "${!_PA_INC_REST[@]}"; do
        if [[ ${_PA_INC_REST[$i]} == W$'\t'* ]]; then
            IFS=$'\t' read -r -a f <<< "${_PA_INC_REST[$i]}"
            a="$(pa_age "${f[1]:-}")"
            [ "$a" -le 172800 ] || continue
        fi
        rest+=("${_PA_INC_REST[$i]}")
    done
    _PA_INC_I=("${keep[@]}") _PA_INC_REST=("${rest[@]}")
    PA_INC=() PA_INC_AT=-1 PA_INC_EXTRA=""
}

# ---- the failure hook's record step ------------------------------------------------------------
#
# deploy/alert.sh runs pa_hook_record after it has sent (or not sent) today's alert, in a child
# bash of its own under `timeout`, so nothing here can change what the hook sends, logs as
# propolis-alert or returns. Its input is the environment: PA_HOOK_UNIT (the unit, already checked
# by the hook), PA_HOOK_OUT (what today's hook did: delivered, undelivered, cooldown or journal),
# PA_HOOK_T0 (the hook's SECONDS when it started this step) and systemd's MONITOR_* variables.
# Every value from them is checked against a closed form before it is written or reaches a
# command line, and nothing a unit logged is ever copied: journal lines are only counted or
# matched against fixed prefixes.

# _pa_hook_unrecorded UNIT WHY: the one journal line that says a firing was not recorded.
_pa_hook_unrecorded() {
    logger -p daemon.notice -t propolis-witness "incident not recorded for $1: $2" 2> /dev/null || true
}

# _pa_hook_facts UNIT ASK: what systemd says about the failed run. Sets _PA_HK_RESULT,
# _PA_HK_CODE (exited, killed or dumped), _PA_HK_STATUS, _PA_HK_INV (the invocation id),
# _PA_HK_RESTART and _PA_HK_NR (NRestarts), each empty when unknown. The MONITOR_* variables
# (systemd 251 and later) describe the run that failed and win; systemctl show is asked when ASK
# is 1, for Restart and NRestarts always and for the run's own values when the MONITOR_* ones are
# absent. Both answers stay within one source, so a result and a status never come from two runs.
_pa_hook_facts() {
    local unit="$1" ask="$2" k v s_result="" s_code="" s_status="" s_inv=""
    _PA_HK_RESULT="" _PA_HK_CODE="" _PA_HK_STATUS="" _PA_HK_INV="" _PA_HK_RESTART="" _PA_HK_NR=""
    if [ "$ask" = 1 ]; then
        while IFS='=' read -r k v; do
            case "$k" in
                Result) if [[ $v =~ ^[a-z-]{1,32}$ ]]; then s_result="$v"; fi ;;
                ExecMainCode)
                    case "$v" in
                        1) s_code=exited ;;
                        2) s_code=killed ;;
                        3) s_code=dumped ;;
                    esac
                    ;;
                ExecMainStatus) if [[ $v =~ ^[0-9]{1,3}$ ]]; then s_status="$v"; fi ;;
                InvocationID) if [[ $v =~ ^[0-9a-f]{32}$ ]]; then s_inv="$v"; fi ;;
                Restart) if [[ $v =~ ^[a-z-]{1,24}$ ]]; then _PA_HK_RESTART="$v"; fi ;;
                NRestarts) if [[ $v =~ ^[0-9]{1,9}$ ]]; then _PA_HK_NR="$((10#$v))"; fi ;;
            esac
        done < <(timeout 3 systemctl show -p Result,ExecMainCode,ExecMainStatus,InvocationID,Restart,Type,NRestarts -- "$unit" 2> /dev/null)
    fi
    if [ -n "${MONITOR_SERVICE_RESULT:-}" ]; then
        if [[ $MONITOR_SERVICE_RESULT =~ ^[a-z-]{1,32}$ ]]; then _PA_HK_RESULT="$MONITOR_SERVICE_RESULT"; fi
        case "${MONITOR_EXIT_CODE:-}" in
            exited | killed | dumped) _PA_HK_CODE="$MONITOR_EXIT_CODE" ;;
        esac
        if [[ ${MONITOR_EXIT_STATUS:-} =~ ^([0-9]{1,3}|[A-Z][A-Z0-9+-]{0,15})$ ]]; then
            _PA_HK_STATUS="$MONITOR_EXIT_STATUS"
        fi
        if [[ ${MONITOR_INVOCATION_ID:-} =~ ^[0-9a-f]{32}$ ]]; then _PA_HK_INV="$MONITOR_INVOCATION_ID"; fi
    else
        _PA_HK_RESULT="$s_result" _PA_HK_CODE="$s_code" _PA_HK_STATUS="$s_status" _PA_HK_INV="$s_inv"
    fi
}

# _pa_hook_guard: for propolis-logrotate.service, what the rotation guard said in the failed run.
# The run's journal is read by trusted fields only (the unit, uid 0 and the invocation id, which
# journald sets and no `logger -t` can forge), and its lines are matched against the guard's two
# fixed prefixes and logrotate's companion line for a failed prerotate script. A refusal for want
# of space is a failure with its own cause. A run is the routine skip of a reader that is behind,
# a NOTICE, only when every line it logged is a skip or a companion, at least one is a skip, and
# there are no more companions than skips: any other line (a guard that broke on another log, a
# note that it rotated blind, an error from logrotate) or a companion with no skip of its own
# means something besides the skip failed. A value that cannot be read is never a pass, so a read
# that failed, timed out or was cut at 10000 lines leaves the failure as it is. Without an
# invocation id the run cannot be told from another, so it stays an ordinary failure too.
_pa_hook_guard() {
    local out st line n=0 skip=0 companion=0 refuse=0 other=0
    [ -n "$_PA_HK_INV" ] || return 0
    out="$(
        timeout 3 journalctl -q -o cat _SYSTEMD_UNIT=propolis-logrotate.service _UID=0 \
            "_SYSTEMD_INVOCATION_ID=$_PA_HK_INV" 2> /dev/null | head -n 10001
        exit "${PIPESTATUS[0]}"
    )"
    st=$?
    while IFS= read -r line; do
        n=$((n + 1))
        case "$line" in
            'propolis-logrotate-guard: refusing to rotate'*) refuse=1 ;;
            'propolis-logrotate-guard: skipping rotation of'*) skip=$((skip + 1)) ;;
            'error: error running non-shared prerotate script for'*) companion=$((companion + 1)) ;;
            *) other=1 ;;
        esac
    done <<< "$out"
    if [ "$refuse" = 1 ]; then
        PA_REC_CAUSE=guard.no_space
    elif [ "$st" = 0 ] && [ "$n" -le 10000 ] && [ "$other" = 0 ] && [ "$skip" -ge 1 ] \
        && [ "$companion" -le "$skip" ]; then
        PA_REC_KIND=rotation-skipped PA_REC_TIER=NOTICE PA_REC_CAUSE=guard.behind
    fi
}

# _pa_hook_field V: V for a spool field: `-` when empty, `?` when it fails pa_ok_field.
_pa_hook_field() {
    if [ -z "${1:-}" ]; then
        printf -- '-'
    elif pa_ok_field "$1"; then
        printf '%s' "$1"
    else
        printf '?'
    fi
}

# _pa_hook_spool UNIT OUT: the firing written to the hook spool, for when the lock cannot be had
# or the hook's time is nearly spent: PA_STATE/hook/UNIT, else PA_RUN/fallback/hook-UNIT. One file
# per unit, overwritten each time with the first time kept and the count raised, so a crash loop
# cannot grow it. Written without the lock, which is the point. propolis-status lists the file
# (deploy/propolis-status.sh#load_hook_spool reads this format), and nothing removes it yet: the
# witness's light pass will take it in under the lock and delete it. The cause is PA_CAUSE.
_pa_hook_spool() {
    local unit="$1" out="$2" dir f head="" t="" a="" b="" c="" g first count
    for dir in "$PA_STATE/hook" "$PA_RUN/fallback"; do
        { [ -d "$dir" ] || mkdir -m 0700 -- "$dir"; } 2> /dev/null || continue
        if [ "$dir" = "$PA_RUN/fallback" ]; then f="$dir/hook-$unit"; else f="$dir/$unit"; fi
        g=0 first="$PA_STAMP" count=0
        if [ -f "$f" ] && [ ! -L "$f" ]; then
            {
                IFS= read -r head
                IFS=$'\t' read -r t a b c _
            } < "$f" 2> /dev/null
            if [[ $head =~ ^#hook\ v1\ g=([0-9]{1,18})$ ]] && [ "$t" = H ]; then
                g=$((10#${BASH_REMATCH[1]}))
                if _pa_stamp_split "$a"; then first="$a"; fi
                count="$(_pa_num "$c")"
            fi
        fi
        count=$((count + 1))
        [ "$count" -le 999999999 ] || count=999999999
        if pa_write "$f" < <(printf '#hook v1 g=%s\nH\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$((g + 1))" "$first" "$PA_STAMP" "$count" "$(_pa_hook_field "$_PA_HK_RESULT")" \
            "$(_pa_hook_field "$_PA_HK_CODE")" "$(_pa_hook_field "$_PA_HK_STATUS")" \
            "$(_pa_hook_field "$PA_CAUSE")" "$(_pa_hook_field "$_PA_HK_NR")" "$out"); then
            return 0
        fi
    done
    _pa_hook_unrecorded "$unit" "neither the state directory nor /run took the hook spool"
    return 1
}

# pa_hook_record: records one firing of the failure hook (see the section comment). Within the
# hook's time it asks systemd and the journal (3 s each) and takes the lock for at most 5 s; when
# the lock cannot be had, or the hook started this step 70 s or more into its 90 s, the firing goes
# to the hook spool with the cause from the MONITOR_* variables alone. A unit that restarts itself
# (or whose Restart= cannot be read) is a first sighting, left pending for the witness to judge;
# one that does not opens at once, and under an active maintenance marker it too stays pending,
# flagged maint. It logs one line under propolis-witness only when nothing could be written, and
# returns 0 then too: that line is the whole account of the failure.
pa_hook_record() {
    local unit="${PA_HOOK_UNIT:-}" out="${PA_HOOK_OUT:-}" t0="${PA_HOOK_T0:-0}" panics=0 tx rc k12
    case "$out" in
        delivered | undelivered | cooldown | journal) ;;
        *) out=- ;;
    esac
    [[ $t0 =~ ^[0-9]{1,9}$ ]] || t0=0
    # The hook is started by hand too (propolis-alert@sensor-ssh.service passes `sensor-ssh`): a
    # record under a word systemd answers for by another name could never be judged.
    if ! pa_unit_name_ok "$unit"; then
        _pa_hook_unrecorded - "the unit name is not one systemd gives"
        return 0
    fi
    pa_now
    if [ "$((10#$t0))" -ge 70 ]; then
        _pa_hook_facts "$unit" 0
        pa_cause "$_PA_HK_RESULT" "$_PA_HK_STATUS" 0 > /dev/null
        _pa_hook_spool "$unit" "$out" || true
        return 0
    fi
    _pa_hook_facts "$unit" 1
    if [ -n "$_PA_HK_INV" ]; then
        panics="$(timeout 3 journalctl -q -o cat "_SYSTEMD_UNIT=$unit" "_SYSTEMD_INVOCATION_ID=$_PA_HK_INV" \
            2> /dev/null | grep -c -F 'panicked at')" || true
        panics="$(_pa_num "$panics")"
    fi
    pa_cause "$_PA_HK_RESULT" "$_PA_HK_STATUS" "$panics" > /dev/null
    pa_unit_map "$unit"
    PA_REC_KIND=unit-failed PA_REC_STAGE="$PA_UNIT_STAGE" PA_REC_TIER="$PA_UNIT_TIER"
    PA_REC_CAUSE="$PA_CAUSE" PA_REC_NR="$_PA_HK_NR" PA_REC_OUT="$out" PA_REC_FLAG="" PA_REC_INST=-
    case "$unit" in
        propolis.service) PA_REC_KIND=daemon-down ;;
        propolis-logrotate.service) _pa_hook_guard ;;
    esac
    tx=pending
    [ "$_PA_HK_RESTART" != no ] || tx=open
    if pa_maint_active; then
        tx=pending PA_REC_FLAG=maint
    fi
    rc=0
    pa_lock 5 || rc=$?
    if [ "$rc" != 0 ]; then
        _pa_hook_spool "$unit" "$out" || true
        return 0
    fi
    # The opaque id stays `-` (PA_REC_INST above). pa_id_table widens two colliding names only
    # among the instances it is given, and the hook knows one unit, so an id it took could differ
    # from the one the walk and the witness show for the same unit; the witness, which builds the
    # table from every configured unit, fills it. The salt is still made here, as the first root
    # writer makes it, so ids exist from the first record on.
    pa_salt_ensure || true
    pa_incident_load
    # A sensor with no bind configured, as an open config-check finding says, restarts on
    # nothing to bind: its own kind, which is not reminded.
    case "$unit" in
        sensor-*.service)
            k12="$(_pa_sha256 "noconfig:${unit%.service}")" || k12=""
            if [ -n "$k12" ] && pa_incident_get "finding:noconfig:${k12:0:12}"; then
                case "${PA_INC[7]}" in
                    pending | open | acked) PA_REC_KIND=unit-nobind PA_REC_TIER=ACT PA_REC_STAGE=listen ;;
                esac
            fi
            ;;
    esac
    pa_incident_transition "unit:$unit" "$tx"
    rc=0
    pa_incident_put || rc=$?
    # Where the record landed, for the walk's state row: a host whose records go to /run must
    # show it before the witness ever runs.
    if [ "$rc" = 0 ]; then
        _pa_meta_set where "$PA_WHERE" > /dev/null 2>&1 || true
    fi
    pa_unlock
    case "$rc" in
        0) ;;
        2) _pa_hook_unrecorded "$unit" "the unit name is too long for a record" ;;
        3) _pa_hook_unrecorded "$unit" "512 incidents are open or pending (notpersisted)" ;;
        *) _pa_hook_unrecorded "$unit" "neither the state directory nor /run took the write" ;;
    esac
    return 0
}

# ---- the messages: the send ledger, the budget, the sender and VERIFIED ------------------------
#
# The shell code of this release sends two messages: the witness's daily message (see "the daily
# message" below) and the test page the operator asks for with `propolis-status --test-page`.
# For the test page the status command counts it in the send ledger and writes the
# testpage record under the lock, then starts propolis-alert@propolis-test-page-<CODE>.service;
# the failure hook sends it through pa_send from the same unit a real failure alert runs in, so a
# test page that arrives proves that unit, the network and the target as this library reads it.
# Today's failure hook reads propolis.env with a rule of its own, so pa_verified also requires the
# hook to read the same target and token (pa_hook_differs). The operator types the code back with
# `--ack-test CODE`, and pa_verified then says whether that proof still stands.
#
# The topic is as secret as the token: on a public server knowing it is all it takes to read the
# channel. Neither, nor a URL that holds the topic, is ever put on a command line (where the
# process list shows it), in a child's environment, in a journal line, in anything printed or in
# a state file. curl gets them in a config file made 0600 here and removed straight after the
# call; the stored binding and token8 are hashes.
#
# testpage (one T line): T code sent binding token8 result acked uid. result is pending, sending
# (the hook claimed it just before the send and has not written its result yet), ok,
# perm:<code>, transient:<code>, nomatch (the hook was started for a code it could not send),
# lockbusy (the hook found the state lock busy and sent nothing), noclaim (the hook could not
# write its claim on the send ledger and sent nothing), or the sender's own word when
# nothing was sent (norender, nocurl, notarget).
# send-ledger: L stamp class keyhash8 tx mode result sender, one line per admitted message,
# written before the send, pending (a test page, which the hook claims as sending) or sending (a
# daily message, claimed by the witness as it writes it); lines over 48 h old go on every write.

# pa_url_shown URL: the scheme and host (with a port) of URL, or `the target` when it is not a
# plain http or https URL. A user name and password before the host, a path (a topic written into
# the URL) and a query (ntfy takes a token there) are never copied out into a report.
pa_url_shown() {
    if [[ ${1:-} =~ ^(https?://)([^/@?#]*@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?([/?#].*)?$ ]]; then
        printf '%s%s%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
    else
        printf 'the target'
    fi
}

# pa_token8 TOKEN: the first 8 hex of sha256(salt NUL TOKEN), `-` for no token, so a changed token
# can be told without the token being stored. `?` and status 1 without a salt: that matches no
# stored value.
pa_token8() {
    local salt h
    if [ -z "${1:-}" ]; then
        printf -- -
        return 0
    fi
    if ! salt="$(_pa_salt)" || ! h="$(_pa_sha256 "$salt" "$1")"; then
        printf '?'
        return 1
    fi
    printf '%s' "${h:0:8}"
}

# _pa_conf_value V: V as a double-quoted value of a curl config file, with each backslash and
# double quote escaped the way curl's config parser reads them, so neither can end the string or
# start an escape of its own. Status 1, nothing printed, for anything but printable ASCII: a
# control character could end the line and start a directive of its own.
_pa_conf_value() {
    local v="${1-}"
    _pa_ascii "$v" || return 1
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    printf '"%s"' "$v"
}

# pa_send TITLE PRIORITY: posts stdin (cut to 1024 bytes) to the shell target (pa_settings_load)
# with that title and priority. Sets PA_SEND_RESULT: ok, perm:<code> (a 4xx other than 408 and
# 429: retrying will not help), transient:<code> (408, 429, 5xx, or 000 for no answer), notarget,
# norender (a title or body line pa_ok_line refuses, a priority outside 1 to 5, or a value that
# cannot be written into the config file safely; nothing sent) or nocurl. Everything curl is told,
# the URL with the topic and the token's header included, is in a 0600 config file listed in
# PA_CLEANUP and removed before return; the command line is `curl -q -K <file>` and nothing else,
# -q first so no .curlrc adds to the request. No redirect is followed. Under 40 s in all.
pa_send() {
    local title="${1-}" prio="${2-}" body line conf v out code
    local -a lines=()
    PA_SEND_RESULT=norender PA_SEND_CODE=-
    body="$(head -c 1024)"
    if [ "${PA_TARGET:-0}" != 1 ]; then
        PA_SEND_RESULT=notarget
        return 1
    fi
    pa_ok_line "$title" && [ -n "$title" ] && [[ $prio =~ ^[1-5]$ ]] || return 1
    while IFS= read -r line; do
        pa_ok_line "$line" || return 1
    done <<< "$body"
    if ! command -v curl > /dev/null 2>&1; then
        PA_SEND_RESULT=nocurl
        return 1
    fi
    v="$(_pa_conf_value "$PA_URL/$PA_TOPIC")" || return 1
    lines+=("url = $v")
    v="$(_pa_conf_value "Title: $title")" || return 1
    lines+=("header = $v")
    v="$(_pa_conf_value "Priority: $prio")" || return 1
    lines+=("header = $v")
    if [ -n "${PA_TOKEN:-}" ]; then
        v="$(_pa_conf_value "Authorization: Bearer $PA_TOKEN")" || return 1
        lines+=("header = $v")
    fi
    # globoff: a brace or a bracket in the URL is sent as written, never expanded into more posts.
    lines+=(globoff silent show-error 'output = "/dev/null"' 'write-out = "%{http_code}"'
        'connect-timeout = 5' 'max-time = 15' 'retry = 1' 'retry-max-time = 20'
        'proto = "=https,http"' 'data-binary = "@-"')
    conf="$(umask 077 && mktemp 2> /dev/null)" || conf=""
    if [ -z "$conf" ]; then
        PA_SEND_RESULT=transient:000
        return 1
    fi
    PA_CLEANUP+=("$conf")
    if ! { printf '%s\n' "${lines[@]}" > "$conf"; } 2> /dev/null || ! chmod 0600 -- "$conf" 2> /dev/null; then
        rm -f -- "$conf" 2> /dev/null
        PA_SEND_RESULT=transient:000
        return 1
    fi
    out="$(printf '%s' "$body" | timeout 40 curl -q -K "$conf" 2> /dev/null)" || true
    rm -f -- "$conf" 2> /dev/null
    code="${out:0:3}"
    [[ $code =~ ^[0-9]{3}$ ]] && [ "${#out}" = 3 ] || code=000
    PA_SEND_CODE="$code"
    case "$code" in
        2[0-9][0-9]) PA_SEND_RESULT=ok ;;
        408 | 429 | 5[0-9][0-9] | 000) PA_SEND_RESULT="transient:$code" ;;
        4[0-9][0-9]) PA_SEND_RESULT="perm:$code" ;;
        *) PA_SEND_RESULT="transient:$code" ;;
    esac
    [ "$PA_SEND_RESULT" = ok ]
}

# pa_render MODE TX ID: the message for transition TX, in PA_TITLE, PA_PRIO and PA_BODY. This
# release renders two. The test page (TX test, ID its code) is the same in full and pointer
# mode: it carries the host's alias and the code and nothing else, no tier, host name or unit.
# The daily message (TX daily, MODE full only: it goes only where the gate is full) is
# _pa_render_daily's. Status 1, with nothing set, for any other message, a code not of 6 hex, a
# line pa_ok_line refuses, or no alias yet.
pa_render() {
    local mode="${1:-}" tx="${2:-}" id="${3:-}" line
    PA_TITLE="" PA_PRIO="" PA_BODY=""
    case "$tx" in
        test) [[ $id =~ ^[0-9a-f]{6}$ ]] || return 1 ;;
        daily) [ "$mode" = full ] || return 1 ;;
        *) return 1 ;;
    esac
    pa_alias > /dev/null 2>&1 || return 1
    [ "$PA_ALIAS" != - ] && pa_ok_field "$PA_ALIAS" || return 1
    if [ "$tx" = daily ]; then
        PA_BODY="$(_pa_render_daily)" || PA_BODY=""
        while IFS= read -r line; do
            pa_ok_line "$line" || PA_BODY=""
        done <<< "$PA_BODY"
        if [ -z "$PA_BODY" ]; then
            return 1
        fi
        PA_TITLE="$PA_ALIAS: daily"
        PA_PRIO=2
        return 0
    fi
    PA_TITLE="$PA_ALIAS: test page $id"
    PA_PRIO=3
    PA_BODY="Type back on $PA_ALIAS: status --ack-test $id"
}

# _pa_tp_line: the stored test page. Sets PA_TP_CODE, PA_TP_SENT, PA_TP_BIND, PA_TP_TOKEN8,
# PA_TP_RESULT, PA_TP_ACKED and PA_TP_UID, each checked against its form; status 1 when there is
# no T line whose every field has its form.
_pa_tp_line() {
    local t c s b k r a u found=1
    PA_TP_CODE="" PA_TP_SENT="" PA_TP_BIND="" PA_TP_TOKEN8="" PA_TP_RESULT="" PA_TP_ACKED=- PA_TP_UID=-
    while IFS=$'\t' read -r t c s b k r a u _; do
        [ "$t" = T ] || continue
        [[ ${c:-} =~ ^[0-9a-f]{6}$ && ${b:-} =~ ^[0-9a-f]{16}$ && ${k:-} =~ ^([0-9a-f]{8}|-)$ ]] || continue
        _pa_stamp_split "${s:-}" || continue
        case "${r:-}" in
            pending | sending | ok | nomatch | lockbusy | noclaim | norender | nocurl | notarget) ;;
            perm:[0-9][0-9][0-9] | transient:[0-9][0-9][0-9]) ;;
            *) continue ;;
        esac
        [ "${a:-}" = - ] || _pa_stamp_split "${a:-}" || continue
        [[ ${u:-} =~ ^(-|[0-9]{1,10})$ ]] || continue
        PA_TP_CODE="$c" PA_TP_SENT="$s" PA_TP_BIND="$b" PA_TP_TOKEN8="$k" PA_TP_RESULT="$r"
        PA_TP_ACKED="$a" PA_TP_UID="$u" found=0
    done < <(pa_state_read testpage)
    return "$found"
}

# pa_testpage_write CODE SENT BINDING TOKEN8 RESULT ACKED UID: the testpage file with this one T
# line, replacing any other; lines of a type this release does not know are kept. The caller
# holds the lock.
pa_testpage_write() {
    local line body="" f
    for f in "$@"; do pa_ok_field "$f" || return 2; done
    [ "$#" = 7 ] || return 2
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [[ $line == T$'\t'* ]] || body+="$line"$'\n'
    done < <(pa_state_read testpage)
    body+="$(printf 'T\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$@")"$'\n'
    pa_state_write testpage < <(printf '%s' "$body")
}

# pa_ledger_add CLASS KEYHASH TX MODE RESULT SENDER: one send-ledger line stamped now, written
# before the send; lines over 48 h old (or dated ahead of the clock) are dropped in the same
# write. Sets PA_LEDGER_STAMP to the new line's stamp, by which pa_ledger_result finds it. The
# caller holds the lock.
pa_ledger_add() {
    local f line t s body="" a
    for f in "$@"; do pa_ok_field "$f" || return 2; done
    [ "$#" = 6 ] || return 2
    pa_now
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r t s _ <<< "$line"
        if [ "$t" = L ]; then
            a="$(pa_age "${s:-}")"
            [ "$a" -ge 0 ] && [ "$a" -le 172800 ] || continue
        fi
        body+="$line"$'\n'
    done < <(pa_state_read send-ledger)
    body+="$(printf 'L\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$PA_STAMP" "$@")"$'\n'
    PA_LEDGER_STAMP="$PA_STAMP"
    pa_state_write send-ledger < <(printf '%s' "$body")
}

# pa_ledger_result STAMP CLASS RESULT SENDER: the result (and sender) of the ledger line of CLASS
# stamped STAMP that is still pending or claimed (sending). Status 1 when there is none. The
# caller holds the lock.
pa_ledger_result() {
    local line t s c k x m r w body="" found=1 f
    for f in "$@"; do pa_ok_field "$f" || return 2; done
    [ "$#" = 4 ] || return 2
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r t s c k x m r w _ <<< "$line"
        if [ "$found" = 1 ] && [ "$t" = L ] && [ "$s" = "$1" ] && [ "$c" = "$2" ] \
            && { [ "$r" = pending ] || [ "$r" = sending ]; }; then
            line="$(printf 'L\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$s" "$c" "$k" "$x" "$m" "$3" "$4")"
            found=0
        fi
        body+="$line"$'\n'
    done < <(pa_state_read send-ledger)
    [ "$found" = 0 ] || return 1
    pa_state_write send-ledger < <(printf '%s' "$body")
}

# _pa_budget_ages: the age of each test-page ledger line the budget counts, one a line: every page
# that was or may have been sent, whether it got through or not (sending, ok, perm, transient,
# and pending while the hook may still be running), none that sent nothing (norender, nocurl,
# notarget, lockbusy, nomatch, noclaim), none over 24 h old or dated ahead of the clock. The hook
# claims a page as sending before it sends, so a line still pending once the hook's whole time
# allowance (120 s) has passed was never sent: a failure-alert unit that does not run (masked,
# not installed, its start refused) would otherwise lock the operator out for a day after it is
# fixed. A late hook cannot send for such a line either, once a new test page has replaced the
# record and its code. Each line also carries the seconds until it stops counting, so the time
# the next page is allowed follows the same two limits. CLASS (test when none is given) names the
# class whose lines are counted: the daily message is claimed in the same way, by its witness pass.
_pa_budget_ages() {
    local class="${1:-test}" t s c r a
    while IFS=$'\t' read -r t s c _ _ _ r _; do
        [ "$t" = L ] && [ "$c" = "$class" ] || continue
        case "${r:-}" in pending | sending | ok | perm:* | transient:*) ;; *) continue ;; esac
        a="$(pa_age "${s:-}")"
        [ "$a" -ge 0 ] && [ "$a" -le 86400 ] || continue
        if [ "$r" = pending ]; then
            [ "$a" -lt 120 ] || continue
            printf '%s %s\n' "$a" "$((120 - a))"
        else
            printf '%s %s\n' "$a" "$((86401 - a))"
        fi
    done < <(pa_state_read send-ledger)
}

# pa_budget_admit CLASS KEY TX NEW: admit or withhold:<reason>, from the ledger, which the caller
# read under the lock. This release sends two classes: test (the test page), at most 3 in 24 h,
# and daily (the daily message), none while a line it counts is under 20 h old (the witness also
# holds it to one a local date), each of the lines _pa_budget_ages counts. Every other class is
# withheld (unbuilt), since no other sender exists yet, and a ledger that cannot be read admits
# nothing (ledger): a count that cannot be made is not zero.
pa_budget_admit() {
    local class="${1:-}" a n=0
    case "$class" in
        test | daily) ;;
        *)
            printf 'withhold:unbuilt'
            return 1
            ;;
    esac
    pa_state_read send-ledger > /dev/null
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" send-ledger "* ]]; then
        printf 'withhold:ledger'
        return 1
    fi
    if [ "$class" = daily ]; then
        while read -r a _; do
            [[ ${a:-} =~ ^[0-9]{1,12}$ ]] && [ "$((10#$a))" -lt 72000 ] || continue
            printf 'withhold:daily-cap'
            return 1
        done < <(_pa_budget_ages daily)
        printf admit
        return 0
    fi
    while read -r a; do
        [ -n "$a" ] || continue
        n=$((n + 1))
    done < <(_pa_budget_ages)
    if [ "$n" -ge 3 ]; then
        printf 'withhold:test-cap'
        return 1
    fi
    printf admit
}

# pa_budget_next CLASS: when enough of the lines the test budget counts have stopped counting for
# a page to be admitted (with n counted, once n-2 of them have: a pending line at 120 s, any other
# when it leaves the 24-hour window), as HH:MM UTC rounded up to the minute, so a withheld page
# can say when the next is allowed; `?` for any other class, or with nothing counted. The caller
# read the ledger under the lock.
pa_budget_next() {
    local a r k t
    local -a rem=()
    if [ "${1:-}" = test ]; then
        while read -r a r; do
            [[ $a =~ ^[0-9]{1,12}$ && ${r:-} =~ ^[0-9]{1,12}$ ]] || continue
            rem+=("$r")
        done < <(_pa_budget_ages)
    fi
    if [ "${#rem[@]}" = 0 ]; then
        printf '?'
        return 1
    fi
    k=$((${#rem[@]} - 2))
    [ "$k" -ge 1 ] || k=1
    r="$(printf '%s\n' "${rem[@]}" | sort -n | sed -n "${k}p")"
    [[ $r =~ ^[0-9]{1,12}$ ]] || {
        printf '?'
        return 1
    }
    [ -n "${PA_WALL:-}" ] || pa_now
    t=$((10#$PA_WALL + 10#$r))
    t=$(((t + 59) / 60 * 60))
    date -u -d "@$t" +%H:%M 2> /dev/null || printf '?'
}

# _pa_after A B: stamp A is later than stamp B (A's age is the smaller), or A cannot be dated: a
# fact that cannot be placed before the acknowledgement is taken to come after it.
_pa_after() {
    local a b
    a="$(pa_age "${1:-}")" b="$(pa_age "${2:-}")"
    [ "$a" -lt 0 ] || [ "$a" -lt "$b" ]
}

# pa_verified: `VERIFIED <dur>` (how long ago the operator typed the code back) while every rule
# holds, else `NOT VERIFIED (<word>)` with the first that fails: a test page was recorded (never);
# its code was typed back (pending); it went to the shell target and token in the files now, and,
# where that target is propolis.env's, today's failure hook reads that same target and token,
# none of them ignored here as invalid (changed: the page proves nothing for a hook that would
# post elsewhere, or not at all; a target from alert.env is the shell senders' alone);
# the acknowledgement is at most 30 days old (expired); since then no message was refused for good
# (refused), no alert-path incident opened (path-failed) and the legacy hook left no alert
# undelivered (undelivered). A transient failure undoes nothing. A file it needs and cannot read
# gives unreadable: what cannot be checked is not verified. PA_VERIFIED_WORD is empty when
# verified, else the word; status 0 only when verified. The caller has run pa_settings_load.
pa_verified() {
    local word="" a t s r f k o dir name first m aw
    PA_VERIFIED_WORD=""
    pa_state_read testpage > /dev/null
    pa_state_read send-ledger > /dev/null
    pa_state_read incidents > /dev/null
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" testpage "* ]]; then
        word=unreadable
    elif ! _pa_tp_line; then
        word=never
    elif [ "$PA_TP_ACKED" = - ]; then
        word=pending
    elif [ "${PA_TARGET:-0}" != 1 ] || [ "$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" != "$PA_TP_BIND" ] \
        || [ "$(pa_token8 "${PA_TOKEN:-}")" != "$PA_TP_TOKEN8" ] \
        || { [ "${PA_TARGET_SRC:-}" != "$PA_ALERT_ENV_NAME" ] && pa_hook_differs; }; then
        word=changed
    else
        a="$(pa_age "$PA_TP_ACKED")"
        if [ "$a" -lt 0 ] || [ "$a" -gt 2592000 ]; then
            word=expired
        elif [[ " ${PA_STATE_UNREADABLE:-} " == *" send-ledger "* || " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
            word=unreadable
        fi
    fi
    if [ -z "$word" ]; then
        while IFS=$'\t' read -r t s _ _ _ _ r _; do
            if [ "$t" = L ] && [[ ${r:-} == perm:* ]] && _pa_after "${s:-}" "$PA_TP_ACKED"; then
                word=refused
                break
            fi
        done < <(pa_state_read send-ledger)
    fi
    if [ -z "$word" ]; then
        while IFS=$'\t' read -r t _ _ k _ _ _ _ _ o _; do
            if [ "$t" = I ] && [ "${k:-}" = alert-path ] && [ "${o:--}" != - ] && _pa_after "$o" "$PA_TP_ACKED"; then
                word="path-failed"
                break
            fi
        done < <(pa_state_read incidents)
    fi
    if [ -z "$word" ]; then
        # The legacy hook's own record of an alert it could not deliver: one file per unit,
        # `<first epoch> <count> <logged epoch>`, its time the last attempt.
        dir="$PA_ROOT/run/propolis-alert/undelivered"
        aw="${PA_TP_ACKED%%/*}"
        if [ -e "$dir" ] || [ -L "$dir" ]; then
            if [ ! -d "$dir" ] || [ -L "$dir" ]; then
                word=unreadable
            else
                f="$(timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%T@ %f\n' 2> /dev/null)" || word=unreadable
                while [ -z "$word" ] && read -r m name; do
                    [[ ${name:-} =~ ^[A-Za-z0-9@._:-]{1,200}$ ]] || continue
                    m="${m%%.*}"
                    first=""
                    read -r first _ < "$dir/$name" 2> /dev/null || true
                    if { [[ $m =~ ^[0-9]{1,12}$ ]] && [ "$((10#$m))" -gt "$((10#$aw))" ]; } \
                        || { [[ $first =~ ^[0-9]{1,12}$ ]] && [ "$((10#$first))" -gt "$((10#$aw))" ]; }; then
                        word=undelivered
                    fi
                done <<< "$f"
            fi
        fi
    fi
    if [ -n "$word" ]; then
        PA_VERIFIED_WORD="$word"
        printf 'NOT VERIFIED (%s)' "$word"
        return 1
    fi
    printf 'VERIFIED %s' "$(pa_dur "$a")"
}

# _pa_daemon_enabled: propolis.service is enabled here, by the role the caller set (PA_ROLE) or,
# when none was set, by pa_role.
_pa_daemon_enabled() {
    local role="${PA_ROLE:-}"
    [ -n "$role" ] || role="$(pa_role)"
    case "$role" in single | control) return 0 ;; esac
    return 1
}

# pa_hook_test_page UNIT: the failure hook's test-page path, run by deploy/alert.sh in a child
# process for a unit named propolis-test-page-<CODE>. It sends only when CODE is the stored test
# page's code, that page is still pending and was recorded under 600 s ago. A page that cannot go
# out whatever the server would say (no target, no alias to put it together with, no curl) is
# marked with that word, in the record and in its ledger line, and never claimed. Before it
# releases the lock it claims the page (result sending, in its ledger line and then in the
# record), so a second run for the same code, which takes the lock while this one sends, finds it
# used; a claim the ledger cannot take sends nothing and marks the page noclaim, so a page that
# went out always counts toward the budget, and a claim the record cannot take sends nothing and
# gives the ledger's back as noclaim. Where that give-back cannot be written either, or the hook
# is stopped between the two claims, the ledger line stays claimed and counts for a day although
# nothing went out: the count errs toward fewer pages, never more. It sends with the lock
# released (the request can take 40 s) and writes the result under the lock afterwards, in the
# record and in its ledger line, with the hook as sender; a result that cannot be written leaves
# the claim, which the status command reports as sent with its result not recorded. A pending
# page whose code arrives too late is marked nomatch; a code that is not the stored one (a newer
# page replaced it) or was already used changes nothing, so a stale or repeated unit can never
# overwrite a newer record or a result that got through. A lock busy for the first wait sends
# nothing, and the page is marked lockbusy if the lock frees within a second wait, so the status
# command can tell this from a unit that did not run. The waits fit the child's 85 s: 10 s, then
# 40 s for the send and 30 s for the result, or 10 s and 20 s when nothing is sent. Every case
# that sends nothing logs one line under propolis-witness; none names the target. Returns 0 on
# every outcome.
pa_hook_test_page() {
    local unit="${1:-}" code age result stamp rc
    if ! [[ $unit =~ ^propolis-test-page-([0-9a-f]{6})$ ]]; then
        _pa_tp_log "test page refused: not a test-page unit name"
        return 0
    fi
    code="${BASH_REMATCH[1]}"
    pa_now
    pa_settings_load
    rc=0
    pa_lock 10 || rc=$?
    if [ "$rc" != 0 ]; then
        _pa_tp_log "test page $code not sent: the state lock was not free"
        if [ "$rc" = 1 ] && pa_lock 20; then
            if _pa_tp_line && [ "$PA_TP_CODE" = "$code" ] && [ "$PA_TP_RESULT" = pending ]; then
                pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" lockbusy \
                    "$PA_TP_ACKED" "$PA_TP_UID" || true
                pa_ledger_result "$PA_TP_SENT" test lockbusy hook || true
            fi
            pa_unlock
        fi
        return 0
    fi
    if ! _pa_tp_line || [ "$PA_TP_CODE" != "$code" ]; then
        pa_unlock
        _pa_tp_log "test page $code not sent: no test page with this code is waiting (a newer one replaced it, or none was asked for)"
        return 0
    fi
    age="$(pa_age "$PA_TP_SENT")"
    if [ "$PA_TP_RESULT" != pending ] || [ "$age" -lt 0 ] || [ "$age" -ge 600 ]; then
        if [ "$PA_TP_RESULT" = pending ]; then
            pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" nomatch \
                "$PA_TP_ACKED" "$PA_TP_UID" || true
        fi
        pa_unlock
        _pa_tp_log "test page $code not sent: it was used already or asked for over 10 minutes ago"
        return 0
    fi
    stamp="$PA_TP_SENT"
    # What sends nothing whatever the server would answer is settled before the claim, so a record
    # that reads sending is a page that was handed to curl, or was about to be.
    result=""
    if [ "${PA_TARGET:-0}" != 1 ]; then
        result=notarget
    elif ! pa_render full test "$code"; then
        result=norender
    elif ! command -v curl > /dev/null 2>&1; then
        result=nocurl
    fi
    if [ -n "$result" ]; then
        pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" "$result" \
            "$PA_TP_ACKED" "$PA_TP_UID" || true
        pa_ledger_result "$stamp" test "$result" hook || true
        pa_unlock
        _pa_tp_log "test page $code not delivered ($result)"
        return 0
    fi
    # A page goes out only once its ledger line reads sending: a line left pending stops counting
    # after 120 s, so a page sent without the claim would never count toward the three a day. The
    # ledger is claimed before the record, so a record that reads sending always has its claim: a
    # write that fails here leaves the record pending (or noclaim), never a word that reads as
    # sent.
    if ! pa_ledger_result "$stamp" test sending hook; then
        pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" noclaim \
            "$PA_TP_ACKED" "$PA_TP_UID" || true
        pa_unlock
        _pa_tp_log "test page $code not sent: the claim on the ledger could not be written"
        return 0
    fi
    if ! pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" sending \
        "$PA_TP_ACKED" "$PA_TP_UID"; then
        # Nothing goes out, so the ledger's claim is given back in a word the budget leaves out.
        pa_ledger_result "$stamp" test noclaim hook || true
        pa_unlock
        _pa_tp_log "test page $code not sent: the claim on it could not be written"
        return 0
    fi
    pa_unlock
    pa_send "$PA_TITLE" "$PA_PRIO" < <(printf '%s\n' "$PA_BODY") || true
    result="$PA_SEND_RESULT"
    rc=0
    pa_lock 30 || rc=$?
    if [ "$rc" = 0 ]; then
        if _pa_tp_line && [ "$PA_TP_CODE" = "$code" ] && [ "$PA_TP_RESULT" = sending ]; then
            pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" "$result" \
                "$PA_TP_ACKED" "$PA_TP_UID" || rc=1
        fi
        pa_ledger_result "$stamp" test "$result" hook || true
        pa_unlock
    fi
    if [ "$result" != ok ]; then
        _pa_tp_log "test page $code not delivered ($result)"
    elif [ "$rc" != 0 ]; then
        _pa_tp_log "test page $code delivered; the result could not be recorded"
    fi
    return 0
}

# _pa_tp_log TEXT: the one journal line of the test-page path.
_pa_tp_log() {
    logger -p daemon.notice -t propolis-witness "$1" 2> /dev/null || true
}

# ---- the daily message -------------------------------------------------------------------------
#
# One low-priority message a day from the witness, so that an operator who stops receiving it
# knows to look. It is sent only where the gate is full (a target over https whose topic a fresh
# read check proved to refuse anonymous reads), so it may carry counts and opaque incident ids;
# it never carries a name, a cause, a path or any text read from the host. The time of day is the
# host's: the witness keeps TZ=UTC for everything else, so the zone it was started with is passed
# in PA_HOST_TZ for this one comparison, and when that is unset the host's /etc/localtime decides.

# pa_local_time WALL: the host's local date and time of day at WALL (epoch seconds), in
# PA_LOCAL_DATE (YYYY-MM-DD) and PA_LOCAL_HM (HH:MM). Status 1, both empty, when date cannot tell.
# Without PA_HOST_TZ the zone file is named outright, `:<root>/etc/localtime`, which is what the C
# library reads with TZ unset (a missing file is UTC either way); naming it under the root lets a
# test give the host a zone of its own, so a TZ=UTC that leaked through cannot pass on a UTC host.
pa_local_time() {
    local w="${1:-}" out re='^([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-2][0-9]:[0-5][0-9])$'
    PA_LOCAL_DATE="" PA_LOCAL_HM=""
    [[ $w =~ ^[0-9]{1,12}$ ]] || return 1
    if [ -n "${PA_HOST_TZ+set}" ]; then
        out="$(TZ="$PA_HOST_TZ" date -d "@$w" '+%Y-%m-%d %H:%M' 2> /dev/null)" || out=""
    else
        out="$(TZ=":${PA_ROOT:-}/etc/localtime" date -d "@$w" '+%Y-%m-%d %H:%M' 2> /dev/null)" || out=""
    fi
    [[ $out =~ $re ]] || return 1
    PA_LOCAL_DATE="${BASH_REMATCH[1]}" PA_LOCAL_HM="${BASH_REMATCH[2]}"
}

# pa_daily_due LAST_DATE LAST_STAMP: whether the daily message is due now (PA_WALL), from
# PA_DAILY_AT (pa_settings_load) and the last one sent (meta daily_last, the local date, and
# daily_last_stamp). Due once the local time of day is at or past PA_DAILY_AT, on a local date
# other than LAST_DATE, at least 20 hours after LAST_STAMP. Sets PA_DAILY_WHY: due, off, early,
# sent (today's went), soon (under 20 h), clock (the local time cannot be told: unknown never
# counts as due). A last stamp out of form is taken as none; the send ledger's count
# (pa_budget_admit daily) still holds the 20 hours. A last stamp ahead of the clock (pa_age -1,
# which only a stamp from another boot can give, its age being the wall clock's) counts as none
# too, as the ledger counts such a line, so a clock that was ahead does not hold the message back
# for as long as it was; the local date still allows one a day. Status 0 when due.
pa_daily_due() {
    local last_date="${1:-}" last="${2:-}" a
    PA_DAILY_WHY=""
    [ -n "${PA_STAMP:-}" ] || pa_now
    if [ "${PA_DAILY_AT:-08:41}" = off ]; then
        PA_LOCAL_DATE="" PA_LOCAL_HM="" PA_DAILY_WHY=off
        return 1
    fi
    if ! pa_local_time "$PA_WALL"; then
        PA_DAILY_WHY=clock
        return 1
    fi
    if [[ $PA_LOCAL_HM < ${PA_DAILY_AT:-08:41} ]]; then
        PA_DAILY_WHY=early
        return 1
    fi
    if [ "$last_date" = "$PA_LOCAL_DATE" ]; then
        PA_DAILY_WHY=sent
        return 1
    fi
    if _pa_stamp_split "$last"; then
        a="$(pa_age "$last")"
        if [ "$a" -ge 0 ] && [ "$a" -lt 72000 ]; then
            PA_DAILY_WHY=soon
            return 1
        fi
    fi
    PA_DAILY_WHY=due
}

# _pa_in_day STAMP: STAMP lies within the last 24 hours (and not ahead of the clock).
_pa_in_day() {
    local a
    a="$(pa_age "${1:-}")"
    [ "$a" -ge 0 ] && [ "$a" -le 86400 ]
}

# _pa_render_daily: the daily message's body, from the state files: the open incidents counted
# by tier with up to ten of their opaque ids (PAGE first, then ACT, then NOTICE); the resolves and
# the withheld (W) lines of the last 24 h; the notices opened in the last 24 h (a standing notice
# is in the walk, and a count that could never fall would teach the operator to skip the line)
# and a clock step of that time; VERIFIED; what v2 would have pushed in 24 h, counted from the
# times each record keeps (its last open or reopen, its reminders by their schedule, its last
# change and its resolve), never more than its would_push; on a control node or gateway the
# listed collectors (PA_DAILY_LISTED, `?` when the caller could not count them) and the quiet
# ones; and where the state was kept (PA_WHERE). No key, kind, cause or instance is read into it,
# and no line names the daemon's own sender, which no test page reaches before step 3, so a line
# that said so could never clear. The caller has run pa_settings_load.
_pa_render_daily() {
    local line st tier open=0 page=0 act=0 res=0 notices=0 wp=0 w=0 quiet=0 n k off s cap
    local ids="" idp="" ida="" idn="" nid=0 step="" v where listed id
    local -a f
    pa_state_read incidents > /dev/null
    while IFS= read -r line; do
        case "$line" in
            I$'\t'*)
                IFS=$'\t' read -r -a f <<< "$line"
                st="${f[7]:-}" tier="${f[6]:-}" id="${f[1]:-}"
                [[ $id =~ ^w#[0-9]{1,9}$ ]] || id=""
                case "$st" in
                    open | acked)
                        open=$((open + 1))
                        case "$tier" in
                            PAGE) page=$((page + 1)) idp+="${id:+ $id}" ;;
                            ACT) act=$((act + 1)) ida+="${id:+ $id}" ;;
                            *) idn+="${id:+ $id}" ;;
                        esac
                        [ "${f[3]:-}" != spool-quiet ] || quiet=$((quiet + 1))
                        ;;
                    resolved) if _pa_in_day "${f[21]:-}"; then res=$((res + 1)); fi ;;
                esac
                case "$tier:$st" in
                    NOTICE:open | NOTICE:acked | NOTICE:resolved) if _pa_in_day "${f[9]:-}"; then notices=$((notices + 1)); fi ;;
                esac
                # Only what v2 would push: not a NOTICE, not folded under a parent, not a duplicate.
                if [ "$tier" != NOTICE ] && [ "${f[13]:--}" = - ] && [[ ,${f[30]:--}, != *,dup,* ]]; then
                    n=0
                    if _pa_in_day "${f[9]:-}"; then n=$((n + 1)); fi
                    k=0
                    for off in $(_pa_reminder_offsets "$tier"); do
                        [ "$k" -lt "$(_pa_num "${f[18]:-}")" ] || break
                        k=$((k + 1))
                        if s="$(_pa_stamp_add "${f[9]:-}" "$off")" && _pa_in_day "$s"; then n=$((n + 1)); fi
                    done
                    if [ "${f[16]:-}" = change ] && _pa_in_day "${f[12]:-}"; then n=$((n + 1)); fi
                    if [ "$st" = resolved ] && _pa_in_day "${f[21]:-}"; then n=$((n + 1)); fi
                    cap="$(_pa_num "${f[29]:-}")"
                    [ "$n" -le "$cap" ] || n="$cap"
                    wp=$((wp + n))
                fi
                ;;
            W$'\t'*)
                IFS=$'\t' read -r -a f <<< "$line"
                if _pa_in_day "${f[1]:-}"; then w=$((w + 1)); fi
                ;;
        esac
    done < <(pa_state_read incidents)
    for id in $idp $ida $idn; do
        [ "$nid" -lt 10 ] || break
        ids+=" $id" nid=$((nid + 1))
    done
    v="$(_pa_meta_get clock_step)"
    if [[ $v =~ ^([0-9]{1,12}/([0-9a-f]{8}|-)/[0-9]{1,10})/([+-][0-9]{1,12})$ ]]; then
        step="${BASH_REMATCH[3]}" s="${BASH_REMATCH[1]}"
        _pa_in_day "$s" || step=""
    fi
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
        printf 'open: ? (state unreadable)\n'
    else
        printf 'open: %s (PAGE %s, ACT %s)%s\n' "$open" "$page" "$act" "$ids"
    fi
    printf 'resolved 24 h: %s; withheld by budget 24 h: %s\n' "$res" "$w"
    printf 'new notices 24 h: %s%s\n' "$notices" "${step:+; clock step $step s}"
    v="$(pa_verified)" || true
    case "$v" in
        VERIFIED*) v+=" (shell)" ;;
        "NOT VERIFIED ("*")") ;;
        *) v="NOT VERIFIED (unreadable)" ;;
    esac
    printf 'alerts: %s; profile legacy\n' "$v"
    printf 'v2 would have pushed %s in 24 h\n' "$wp"
    case "${PA_ROLE:-}" in
        control | gateway)
            listed="${PA_DAILY_LISTED:-}"
            [[ $listed =~ ^[0-9]{1,6}$ ]] || listed="?"
            printf 'collectors: %s listed, %s quiet\n' "$listed" "$quiet"
            ;;
    esac
    case "${PA_WHERE:-}" in
        persistent) where=persisted ;;
        run) where="not persisted (run)" ;;
        none) where="not persisted (none)" ;;
        *) where="?" ;;
    esac
    printf 'state: %s\nDo: status\n' "$where"
}
