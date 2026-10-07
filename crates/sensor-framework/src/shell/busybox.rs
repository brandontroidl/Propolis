//! The BusyBox multi-call binary's banner and applet set, captured from the reference build
//! (Ubuntu 22.04's `busybox` 1:1.30.1-7ubuntu3.1, a bare `/bin/busybox` on a pty).
//!
//! The applet rows below are the single source of the applet set: the banner prints them and
//! `busybox <applet>` recognizes exactly the names they list, so the two cannot contradict each
//! other. Every byte is the capture's; nothing here is composed from a template.

use std::sync::LazyLock;

/// The lines before `Currently defined functions:`, as captured. An empty entry is a blank line.
const BANNER_PREAMBLE: [&str; 15] = [
    "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.",
    "BusyBox is copyrighted by many authors between 1998-2015.",
    "Licensed under GPLv2. See source distribution for detailed",
    "copyright notices.",
    "",
    "Usage: busybox [function [arguments]...]",
    "   or: busybox --list[-full]",
    "   or: busybox --install [-s] [DIR]",
    "   or: function [arguments]...",
    "",
    "\tBusyBox is a multi-call binary that combines many common Unix",
    "\tutilities into a single executable.  The shell in this build",
    "\tis configured to run built-in utilities without $PATH search.",
    "\tYou don't need to install a link to busybox for each utility.",
    "\tTo run external program, use full path (/sbin/ip instead of ip).",
];

/// The applet rows exactly as captured, each printed after a tab. The wrap is the build's own.
const APPLET_ROWS: [&str; 30] = [
    "[, [[, acpid, adjtimex, ar, arch, arp, arping, ash, awk, basename, bc,",
    "blkdiscard, blockdev, brctl, bunzip2, busybox, bzcat, bzip2, cal, cat,",
    "chgrp, chmod, chown, chpasswd, chroot, chvt, clear, cmp, cp, cpio,",
    "crond, crontab, cttyhack, cut, date, dc, dd, deallocvt, depmod, devmem,",
    "df, diff, dirname, dmesg, dnsdomainname, dos2unix, dpkg, dpkg-deb, du,",
    "dumpkmap, dumpleases, echo, ed, egrep, env, expand, expr, factor,",
    "fallocate, false, fatattr, fdisk, fgrep, find, fold, free, freeramdisk,",
    "fsfreeze, fstrim, ftpget, ftpput, getopt, getty, grep, groups, gunzip,",
    "gzip, halt, head, hexdump, hostid, hostname, httpd, hwclock, i2cdetect,",
    "i2cdump, i2cget, i2cset, id, ifconfig, ifdown, ifup, init, insmod,",
    "ionice, ip, ipcalc, ipneigh, kill, killall, klogd, last, less, link,",
    "linux32, linux64, linuxrc, ln, loadfont, loadkmap, logger, login,",
    "logname, logread, losetup, ls, lsmod, lsscsi, lzcat, lzma, lzop,",
    "md5sum, mdev, microcom, mkdir, mkdosfs, mke2fs, mkfifo, mknod,",
    "mkpasswd, mkswap, mktemp, modinfo, modprobe, more, mount, mt, mv,",
    "nameif, nc, netstat, nl, nologin, nproc, nsenter, nslookup, nuke, od,",
    "openvt, partprobe, passwd, paste, patch, pidof, ping, ping6,",
    "pivot_root, poweroff, printf, ps, pwd, rdate, readlink, realpath,",
    "reboot, renice, reset, resume, rev, rm, rmdir, rmmod, route, rpm,",
    "rpm2cpio, run-init, run-parts, sed, seq, setkeycodes, setpriv, setsid,",
    "sh, sha1sum, sha256sum, sha512sum, shred, shuf, sleep, sort,",
    "ssl_client, start-stop-daemon, stat, static-sh, strings, stty, su,",
    "sulogin, svc, svok, swapoff, swapon, switch_root, sync, sysctl,",
    "syslogd, tac, tail, tar, taskset, tc, tee, telnet, telnetd, test, tftp,",
    "time, timeout, top, touch, tr, traceroute, traceroute6, true, truncate,",
    "tty, tunctl, ubirename, udhcpc, udhcpd, uevent, umount, uname,",
    "uncompress, unexpand, uniq, unix2dos, unlink, unlzma, unshare, unxz,",
    "unzip, uptime, usleep, uudecode, uuencode, vconfig, vi, w, watch,",
    "watchdog, wc, wget, which, who, whoami, xargs, xxd, xz, xzcat, yes,",
    "zcat",
];

/// The applets the banner lists, in its order.
static APPLETS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    APPLET_ROWS
        .iter()
        .flat_map(|row| row.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
});

/// The applets the multi-call binary lists, which is every name `busybox <name>` runs.
#[cfg(test)]
pub(super) fn applets() -> &'static [&'static str] {
    &APPLETS
}

/// True if `name` is listed in the banner. BusyBox resolves an applet by its bare name only.
pub(super) fn is_applet(name: &str) -> bool {
    APPLETS.contains(&name)
}

/// `wget` run without a URL: `bb_show_usage`'s text on standard error. Composed from BusyBox
/// 1.30.1's `networking/wget.c` usage strings under the Debian package configs this build comes
/// from (`debian/config/pkg/deb` and `static` of 1:1.30.1-7: `FEATURE_WGET_LONG_OPTIONS=y`,
/// `FEATURE_WGET_TIMEOUT` unset, `FEATURE_VERBOSE_USAGE=y`), so `[-T SEC]` and its line are absent.
/// [unverified] against a pty capture of the reference host.
pub(super) fn wget_usage() -> String {
    format!(
        "{}\n\nUsage: wget [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n\
         \t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n\
         \t[-S|--server-response] [-U|--user-agent AGENT] URL...\n\
         \n\
         Retrieve files via HTTP or FTP\n\
         \n\
         \t--spider\tOnly check URL existence: $? is 0 if exists\n\
         \t-c\t\tContinue retrieval of aborted transfer\n\
         \t-q\t\tQuiet\n\
         \t-P DIR\t\tSave to DIR (default .)\n\
         \t-S    \t\tShow server response\n\
         \t-O FILE\t\tSave to FILE ('-' for stdout)\n\
         \t-U STR\t\tUse STR for User-Agent header\n\
         \t-Y on/off\tUse proxy\n",
        BANNER_PREAMBLE[0]
    )
}

/// What a bare `busybox` prints.
pub(super) fn banner() -> String {
    let mut text = String::new();
    for line in BANNER_PREAMBLE {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("\nCurrently defined functions:\n");
    for row in APPLET_ROWS {
        text.push('\t');
        text.push_str(row);
        text.push('\n');
    }
    text
}
