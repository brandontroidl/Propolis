//! The Debian package database the Ubuntu persona answers `dpkg` and `apt` from: one table, so
//! `dpkg -l`, `dpkg -s`, `apt list --installed` and `apt install`'s "already the newest version"
//! cannot disagree about what is installed or at which version.
//!
//! Recorded 2026-10-07 from a systemd-booted `ubuntu:22.04` reference with the `ubuntu-server`
//! metapackage installed (`dpkg-query -W` for the fields, `apt list --installed` for the pockets and
//! the automatic flag). Changed from the recording, so the table agrees with the rest of the
//! persona:
//!
//! - `openssh-client`, `openssh-server` and `openssh-sftp-server` are at the version the SSH banner
//!   announces (`persona::OPENSSH_VERSION`, `3ubuntu0.10`) and `base-files`/`motd-news-config` at
//!   22.04.4's `12ubuntu4.6`, both superseded in the archive, so they list as `now` and upgradable
//!   to the recorded version, as a box last upgraded then would.
//! - `gawk`, `vim`, `vim-runtime` and `xxd` are left out: with `gawk` installed `awk` would be gawk,
//!   and the 2026-09-29 recording of a real 22.04 server has no `xxd`.
//! - The running kernel's two packages are added, `now` only (superseded) [unverified: sizes and
//!   summaries from knowledge of the release, not recorded]. `busybox-static` is added, recorded
//!   the same day: its `/usr/bin/busybox` has the size and header the persona's busybox has.
//! - Every maintainer is the Ubuntu list address; the recording's few personal maintainer names
//!   are not carried.
//!
//! A row is `name|version|arch|pockets|auto|priority|section|installed-size|multi-arch|source|
//! summary`, with an optional twelfth field `pockets version` for an upgrade the archive offers.
//! `auto` is `a` for a package apt installed as a dependency, `m` for one asked for.

/// One installed package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Package {
    pub name: &'static str,
    pub version: &'static str,
    pub arch: &'static str,
    /// Where apt finds this version: `jammy-updates,jammy-security,now`, or `now` for a version
    /// the archive no longer carries.
    pub pockets: &'static str,
    pub automatic: bool,
    pub priority: &'static str,
    pub section: &'static str,
    /// KiB, as `Installed-Size`.
    pub installed_size: &'static str,
    /// `same`, `foreign`, `allowed`, or `no` for none.
    pub multi_arch: &'static str,
    pub source: &'static str,
    pub summary: &'static str,
    /// The pockets and version of an upgrade the archive offers.
    pub upgrade: Option<(&'static str, &'static str)>,
}

impl Package {
    /// The name `dpkg -l` prints: a `Multi-Arch: same` package carries its architecture.
    pub fn qualified_name(&self) -> String {
        if self.multi_arch == "same" {
            format!("{}:{}", self.name, self.arch)
        } else {
            self.name.to_string()
        }
    }
}

fn parse(row: &'static str) -> Option<Package> {
    let mut fields = row.split('|');
    let mut next = || fields.next();
    let package = Package {
        name: next()?,
        version: next()?,
        arch: next()?,
        pockets: next()?,
        automatic: next()? == "a",
        priority: next()?,
        section: next()?,
        installed_size: next()?,
        multi_arch: next()?,
        source: next()?,
        summary: next()?,
        upgrade: next().and_then(|upgrade| upgrade.split_once(' ')),
    };
    Some(package)
}

/// Every installed package, sorted by name as `dpkg -l` lists them.
pub fn installed() -> impl Iterator<Item = Package> {
    ROWS.lines().filter(|row| !row.is_empty()).filter_map(parse)
}

/// The installed package named `name`.
pub fn find(name: &str) -> Option<Package> {
    installed().find(|package| package.name == name)
}

/// The fields `dpkg -s openssh-server` prints after `Version:`, recorded with the rest of the table
/// and set to the persona's version where they name it.
pub const OPENSSH_SERVER_DETAIL: &str = "Replaces: openssh-client (<< 1:7.9p1-8), ssh, ssh-krb5
Provides: ssh-server
Depends: adduser (>= 3.9), dpkg (>= 1.9.0), libpam-modules (>= 0.72-9), libpam-runtime (>= 0.76-14), lsb-base (>= 4.1+Debian3), openssh-client (= 1:8.9p1-3ubuntu0.10), openssh-sftp-server, procps, ucf (>= 0.28), debconf (>= 0.5) | debconf-2.0, libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcom-err2 (>= 1.43.9), libcrypt1 (>= 1:4.1.0), libgssapi-krb5-2 (>= 1.17), libkrb5-3 (>= 1.13~alpha1+dfsg), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), libssl3 (>= 3.0.2), libsystemd0, libwrap0 (>= 7.6-4~), zlib1g (>= 1:1.1.4)
Pre-Depends: init-system-helpers (>= 1.54~)
Recommends: default-logind | logind | libpam-systemd, ncurses-term, xauth, ssh-import-id
Suggests: molly-guard, monkeysphere, ssh-askpass, ufw
Conflicts: sftp, ssh-socks, ssh2
Conffiles:
 /etc/default/ssh 500e3cf069fe9a7b9936108eb9d9c035
 /etc/init.d/ssh 3649a6fe8c18ad1d5245fd91737de507
 /etc/pam.d/sshd 8b4c7a12b031424b2a9946881da59812
 /etc/ssh/moduli e8fbe2dcefa45888cf7341d78d8258ce
 /etc/ufw/applications.d/openssh-server 486b78d54b93cc9fdc950c1d52ff479e
Description: secure shell (SSH) server, for secure access from remote machines
 This is the portable version of OpenSSH, a free implementation of
 the Secure Shell protocol as specified by the IETF secsh working
 group.
 .
 Ssh (Secure Shell) is a program for logging into a remote machine
 and for executing commands on a remote machine.
 It provides secure encrypted communications between two untrusted
 hosts over an insecure network. X11 connections and arbitrary TCP/IP
 ports can also be forwarded over the secure channel.
 It can be used to provide applications with a secure communication
 channel.
 .
 This package provides the sshd server.
 .
 In some countries it may be illegal to use any encryption at all
 without a special permit.
 .
 sshd replaces the insecure rshd program, which is obsolete for most
 purposes.
Homepage: http://www.openssh.com/
Original-Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
";

const ROWS: &str = r#"adduser|3.118ubuntu5|all|jammy,now|m|important|admin|608|foreign|adduser|add and remove users and groups
apparmor|3.0.4-2ubuntu2.5|amd64|jammy-updates,now|a|optional|admin|2688|no|apparmor|user-space parser utility for AppArmor
apport|2.20.11-0ubuntu82.10|all|jammy-updates,jammy-security,now|a|optional|utils|816|no|apport|automatically generate crash reports for debugging
apt|2.4.14|amd64|jammy-updates,now|m|important|admin|4141|no|apt|commandline package manager
apt-utils|2.4.14|amd64|jammy-updates,now|a|important|admin|792|no|apt|package management related utility programs
base-files|12ubuntu4.6|amd64|now|m|required|admin|395|foreign|base-files|Debian base system miscellaneous files|jammy-updates 12ubuntu4.7
base-passwd|3.5.52build1|amd64|jammy,now|m|required|admin|243|foreign|base-passwd|Debian base system master password and group files
bash|5.1-6ubuntu1.1|amd64|jammy-updates,jammy-security,now|m|required|shells|1864|foreign|bash|GNU Bourne Again SHell
bash-completion|1:2.11-5ubuntu1|all|jammy,now|m|standard|shells|1464|foreign|bash-completion|programmable completion for the bash shell
bcache-tools|1.0.8-4ubuntu3|amd64|jammy,now|a|optional|utils|107|no|bcache-tools|bcache userspace tools
bsdutils|1:2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|utils|335|foreign|util-linux|basic utilities from 4.4BSD-Lite
btrfs-progs|5.16.2-1|amd64|jammy,now|a|optional|admin|4190|foreign|btrfs-progs|Checksumming Copy on Write Filesystem utilities
busybox-initramfs|1:1.30.1-7ubuntu3.1|amd64|jammy-updates,jammy-security,now|a|optional|shells|361|no|busybox|Standalone shell setup for initramfs
busybox-static|1:1.30.1-7ubuntu3.1|amd64|jammy-updates,jammy-security,now|m|optional|shells|2245|no|busybox|Standalone rescue shell with tons of builtin utilities
byobu|5.133-1|all|jammy,now|a|optional|misc|624|no|byobu|text window manager, shell multiplexer, integrated DevOps environment
ca-certificates|20260601~22.04.1|all|jammy-updates,jammy-security,now|m|standard|misc|345|foreign|ca-certificates|Common CA certificates
cloud-guest-utils|0.32-22-g45fe84a5-0ubuntu1|all|jammy,now|a|optional|admin|65|no|cloud-utils|cloud guest utilities
cloud-initramfs-copymods|0.47ubuntu1|all|jammy,now|a|optional|admin|25|no|cloud-initramfs-tools|copy initramfs modules into root filesystem for later use
cloud-initramfs-dyn-netconf|0.47ubuntu1|all|jammy,now|a|optional|admin|31|no|cloud-initramfs-tools|write a network interface file in /run for BOOTIF
command-not-found|22.04.0|all|jammy,now|m|optional|admin|37|no|command-not-found|Suggest installation of packages in interactive bash sessions
console-setup|1.205ubuntu3|all|jammy,now|a|optional|utils|426|foreign|console-setup|console font and keymap setup program
console-setup-linux|1.205ubuntu3|all|jammy,now|a|optional|utils|2171|foreign|console-setup|Linux specific part of console-setup
coreutils|8.32-4.1ubuntu1.4|amd64|jammy-updates,jammy-security,now|m|required|utils|7112|foreign|coreutils|GNU core utilities
cpio|2.13+dfsg-7ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|important|utils|328|foreign|cpio|GNU cpio -- a program to manage archives of files
cron|3.0pl1-137ubuntu3|amd64|jammy,now|m|important|admin|255|foreign|cron|process scheduling daemon
cryptsetup|2:2.4.3-1ubuntu1.3|amd64|jammy-updates,now|a|optional|admin|476|foreign|cryptsetup|disk encryption support - startup scripts
cryptsetup-bin|2:2.4.3-1ubuntu1.3|amd64|jammy-updates,now|a|optional|admin|584|foreign|cryptsetup|disk encryption support - command line tools
curl|7.81.0-1ubuntu1.29|amd64|jammy-updates,jammy-security,now|m|optional|web|446|foreign|curl|command line tool for transferring data with URL syntax
dash|0.5.11+git20210903+057cd650a4ed-3build1|amd64|jammy,now|m|required|shells|214|foreign|dash|POSIX-compliant shell
dbus|1.12.20-2ubuntu4.1|amd64|jammy-updates,jammy-security,now|m|standard|admin|582|foreign|dbus|simple interprocess messaging system (daemon and utilities)
dbus-user-session|1.12.20-2ubuntu4.1|amd64|jammy-updates,jammy-security,now|a|optional|admin|130|foreign|dbus|simple interprocess messaging system (systemd --user integration)
debconf|1.5.79ubuntu1|all|jammy,now|m|required|admin|512|foreign|debconf|Debian configuration management system
debconf-i18n|1.5.79ubuntu1|all|jammy,now|a|important|localization|787|no|debconf|full internationalization support for debconf
debianutils|5.5-1ubuntu2|amd64|jammy,now|m|required|utils|243|foreign|debianutils|Miscellaneous utilities specific to Debian
diffutils|1:3.8-0ubuntu2.1|amd64|jammy-updates,jammy-security,now|m|required|utils|424|no|diffutils|File comparison utilities
dirmngr|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|676|foreign|gnupg2|GNU privacy guard - network certificate management service
distro-info|1.1ubuntu0.2|amd64|jammy-updates,now|a|optional|devel|69|no|distro-info|provides information about the distributions' releases
distro-info-data|0.72-0ubuntu0.22.04.1|all|jammy-updates,jammy-security,now|a|optional|devel|23|foreign|distro-info-data|information about the distributions' releases (data files)
dmeventd|2:1.02.175-2.1ubuntu5|amd64|jammy-updates,now|a|optional|admin|246|no|lvm2|Linux Kernel Device Mapper event daemon
dmidecode|3.3-3ubuntu0.2|amd64|jammy-updates,now|a|important|utils|212|foreign|dmidecode|SMBIOS/DMI table decoder
dmsetup|2:1.02.175-2.1ubuntu5|amd64|jammy-updates,now|a|optional|admin|274|foreign|lvm2|Linux Kernel Device Mapper userspace library
dpkg|1.21.1ubuntu2.6|amd64|jammy-updates,jammy-security,now|m|required|admin|6733|foreign|dpkg|Debian package management system
e2fsprogs|1.46.5-2ubuntu1.2|amd64|jammy-updates,now|m|required|admin|1516|foreign|e2fsprogs|ext2/ext3/ext4 file system utilities
eject|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|a|optional|utils|153|foreign|util-linux|ejects CDs and operates CD-Changers under Linux
ethtool|1:5.16-1ubuntu0.2|amd64|jammy-updates,now|a|optional|net|630|no|ethtool|display or change Ethernet device settings
fdisk|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|a|important|utils|438|foreign|util-linux|collection of partitioning utilities
findutils|4.8.0-1ubuntu3|amd64|jammy,now|m|required|utils|620|foreign|findutils|utilities for finding files--find, xargs
fonts-ubuntu-console|0.83-6ubuntu1|all|jammy,now|a|optional|fonts|63|foreign|fonts-ubuntu|console version of the Ubuntu Mono font
fuse3|3.10.5-1build1|amd64|jammy,now|a|optional|utils|90|no|fuse3|Filesystem in Userspace (3.x version)
gcc-12-base|12.3.0-1ubuntu1~22.04.3|amd64|jammy-updates,jammy-security,now|m|required|libs|272|same|gcc-12|GCC, the GNU Compiler Collection (base package)
gdisk|1.0.8-4build1|amd64|jammy,now|a|optional|admin|726|no|gdisk|GPT fdisk text-mode partitioning tool
gettext-base|0.21-4ubuntu4|amd64|jammy,now|a|standard|utils|284|foreign|gettext|GNU Internationalization utilities for the base system
gir1.2-glib-2.0|1.72.0-1|amd64|jammy,now|a|optional|introspection|677|same|gobject-introspection|Introspection data for GLib, GObject, Gio and GModule
gir1.2-packagekitglib-1.0|1.2.5-2ubuntu3.1|amd64|jammy-updates,jammy-security,now|a|optional|introspection|123|no|packagekit|GObject introspection data for the PackageKit GLib library
git|1:2.34.1-1ubuntu1.17|amd64|jammy-updates,jammy-security,now|a|optional|vcs|18484|foreign|git|fast, scalable, distributed revision control system
git-man|1:2.34.1-1ubuntu1.17|all|jammy-updates,jammy-security,now|a|optional|doc|1959|foreign|git|fast, scalable, distributed revision control system (manual pages)
gnupg|2.2.27-3ubuntu2.5|all|jammy-updates,jammy-security,now|a|optional|utils|473|foreign|gnupg2|GNU privacy guard - a free PGP replacement
gnupg-l10n|2.2.27-3ubuntu2.5|all|jammy-updates,jammy-security,now|a|optional|localization|392|foreign|gnupg2|GNU privacy guard - localization files
gnupg-utils|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|787|foreign|gnupg2|GNU privacy guard - utility programs
gpg|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|1121|foreign|gnupg2|GNU Privacy Guard -- minimalist public key operations
gpg-agent|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|595|foreign|gnupg2|GNU privacy guard - cryptographic agent
gpg-wks-client|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|184|foreign|gnupg2|GNU privacy guard - Web Key Service client
gpg-wks-server|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|168|foreign|gnupg2|GNU privacy guard - Web Key Service server
gpgconf|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|280|foreign|gnupg2|GNU privacy guard - core configuration utilities
gpgsm|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|a|optional|utils|480|foreign|gnupg2|GNU privacy guard - S/MIME version
gpgv|2.2.27-3ubuntu2.5|amd64|jammy-updates,jammy-security,now|m|important|utils|324|foreign|gnupg2|GNU privacy guard - signature verification tool
grep|3.7-1build1|amd64|jammy,now|m|required|utils|496|foreign|grep|GNU grep, egrep and fgrep
gzip|1.10-4ubuntu4.2|amd64|jammy-updates,jammy-security,now|m|required|utils|240|no|gzip|GNU compression utilities
hostname|3.23ubuntu2|amd64|jammy,now|m|required|admin|51|no|hostname|utility to set/show the host name or domain name
htop|3.0.5-7build2|amd64|jammy,now|a|optional|utils|334|no|htop|interactive processes viewer
init|1.62|amd64|jammy,now|a|important|metapackages|22|foreign|init-system-helpers|metapackage ensuring an init system is installed
init-system-helpers|1.62|all|jammy,now|m|required|admin|133|foreign|init-system-helpers|helper tools for all init systems
initramfs-tools|0.140ubuntu13.5|all|jammy-updates,now|a|optional|utils|148|foreign|initramfs-tools|generic modular initramfs generator (automation)
initramfs-tools-bin|0.140ubuntu13.5|amd64|jammy-updates,now|a|optional|utils|136|no|initramfs-tools|binaries used by initramfs-tools
initramfs-tools-core|0.140ubuntu13.5|all|jammy-updates,now|a|optional|utils|275|foreign|initramfs-tools|generic modular initramfs generator (core tools)
iproute2|5.15.0-1ubuntu2.2|amd64|jammy-updates,now|m|important|net|2884|foreign|iproute2|networking and traffic control tools
iputils-ping|3:20211215-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|important|net|113|foreign|iputils|Tools to test the reachability of network hosts
isc-dhcp-client|4.4.1-2.3ubuntu2.4|amd64|jammy-updates,now|a|important|net|673|no|isc-dhcp|DHCP client for automatically obtaining an IP address
iso-codes|4.9.0-1|all|jammy,now|a|optional|misc|19769|foreign|iso-codes|ISO language, territory, currency, script codes and their translations
kbd|2.3.0-3ubuntu4.22.04|amd64|jammy-updates,now|a|optional|utils|1328|no|kbd|Linux console font and keytable utilities
keyboard-configuration|1.205ubuntu3|all|jammy,now|a|optional|utils|842|foreign|console-setup|system-wide keyboard preferences
klibc-utils|2.0.10-4ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|547|foreign|klibc|small utilities built with klibc for early boot
kmod|29-1ubuntu1.1|amd64|jammy-updates,jammy-security,now|a|important|admin|252|foreign|kmod|tools for managing Linux kernel modules
kpartx|0.8.8-1ubuntu1.22.04.4|amd64|jammy-updates,now|a|optional|admin|99|no|multipath-tools|create device mappings for partitions
less|590-1ubuntu0.22.04.3|amd64|jammy-updates,jammy-security,now|m|important|text|321|foreign|less|pager program similar to more
libacl1|2.3.1-1|amd64|jammy,now|m|required|libs|67|same|acl|access control list - shared library
libaio1|0.3.112-13build1|amd64|jammy,now|a|optional|libs|37|same|libaio|Linux kernel AIO access library - shared library
libapparmor1|3.0.4-2ubuntu2.5|amd64|jammy-updates,now|a|optional|libs|171|same|apparmor|changehat AppArmor library
libappstream4|0.15.2-2|amd64|jammy,now|a|optional|libs|576|same|appstream|Library to access AppStream services
libapt-pkg6.0|2.4.14|amd64|jammy-updates,now|m|important|libs|3198|same|apt|package management runtime library
libargon2-1|0~20171227-0.3|amd64|jammy,now|a|optional|libs|56|same|argon2|memory-hard hashing function - runtime library
libassuan0|2.5.5-1build1|amd64|jammy,now|a|optional|libs|110|same|libassuan|IPC library for the GnuPG components
libatasmart4|0.19-5build2|amd64|jammy,now|a|optional|libs|82|same|libatasmart|ATA S.M.A.R.T. reading and parsing library
libattr1|1:2.5.1-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|required|libs|57|same|attr|extended attribute handling - shared library
libaudit-common|1:3.0.7-1build1|all|jammy,now|m|required|libs|23|foreign|audit|Dynamic library for security auditing - common files
libaudit1|1:3.0.7-1build1|amd64|jammy,now|m|required|libs|156|same|audit|Dynamic library for security auditing
libblkid1|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|libs|324|same|util-linux|block device ID library
libblockdev-fs2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|82|same|libblockdev|file system plugin for libblockdev
libblockdev-loop2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|35|same|libblockdev|Loop device plugin for libblockdev
libblockdev-part-err2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|36|same|libblockdev|Partition error utility functions for libblockdev
libblockdev-part2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|65|same|libblockdev|Partitioning plugin for libblockdev
libblockdev-swap2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|44|same|libblockdev|Swap plugin for libblockdev
libblockdev-utils2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|61|same|libblockdev|Utility functions for libblockdev
libblockdev2|2.26-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|225|same|libblockdev|Library for manipulating block devices
libbpf0|1:0.5.0-1ubuntu22.04.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|344|same|libbpf|eBPF helper library (shared library)
libbrotli1|1.0.9-2build6|amd64|jammy,now|a|optional|libs|784|same|brotli|library implementing brotli encoder and decoder (shared libraries)
libbsd0|0.11.5-1|amd64|jammy,now|a|optional|libs|136|same|libbsd|utility functions from BSD systems - shared library
libbz2-1.0|1.0.8-5ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|required|libs|100|same|bzip2|high-quality block-sorting file compressor library - runtime
libc-bin|2.35-0ubuntu3.14|amd64|now|m|required|libs|2539|foreign|glibc|GNU C Library: Binaries|jammy-updates,jammy-security 2.35-0ubuntu3.15
libc6|2.35-0ubuntu3.14|amd64|now|m|required|libs|13594|same|glibc|GNU C Library: Shared libraries|jammy-updates,jammy-security 2.35-0ubuntu3.15
libcap-ng0|0.7.9-2.2build3|amd64|jammy,now|m|required|libs|45|same|libcap-ng|An alternate POSIX capabilities library
libcap2|1:2.44-1ubuntu0.22.04.3|amd64|jammy-updates,jammy-security,now|m|required|libs|65|same|libcap2|POSIX 1003.1e capabilities (library)
libcap2-bin|1:2.44-1ubuntu0.22.04.3|amd64|jammy-updates,jammy-security,now|a|important|utils|115|foreign|libcap2|POSIX 1003.1e capabilities (utilities)
libcbor0.8|0.8.0-2ubuntu1|amd64|jammy,now|a|optional|libs|83|same|libcbor|library for parsing and generating CBOR (RFC 7049)
libcom-err2|1.46.5-2ubuntu1.2|amd64|jammy-updates,now|m|required|libs|101|same|e2fsprogs|common error description library
libcrypt1|1:4.4.27-1|amd64|jammy,now|m|required|libs|225|same|libxcrypt|libcrypt shared library
libcryptsetup12|2:2.4.3-1ubuntu1.3|amd64|jammy-updates,now|a|optional|libs|572|same|cryptsetup|disk encryption support - shared library
libcurl3-gnutls|7.81.0-1ubuntu1.29|amd64|jammy-updates,jammy-security,now|a|optional|libs|774|same|curl|easy-to-use client-side URL transfer library (GnuTLS flavour)
libcurl4|7.81.0-1ubuntu1.29|amd64|jammy-updates,jammy-security,now|a|optional|libs|790|same|curl|easy-to-use client-side URL transfer library (OpenSSL flavour)
libdb5.3|5.3.28+dfsg1-0.8ubuntu3|amd64|jammy,now|m|required|libs|1750|same|db5.3|Berkeley v5.3 Database Libraries [runtime]
libdbus-1-3|1.12.20-2ubuntu4.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|457|same|dbus|simple interprocess messaging system (library)
libdebconfclient0|0.261ubuntu1|amd64|jammy,now|m|required|libs|79|same|cdebconf|Debian Configuration Management System (C-implementation library)
libdevmapper-event1.02.1|2:1.02.175-2.1ubuntu5|amd64|jammy-updates,now|a|optional|libs|77|same|lvm2|Linux Kernel Device Mapper event support library
libdevmapper1.02.1|2:1.02.175-2.1ubuntu5|amd64|jammy-updates,now|a|optional|libs|493|same|lvm2|Linux Kernel Device Mapper userspace library
libdns-export1110|1:9.11.19+dfsg-2.1ubuntu3|amd64|jammy,now|a|optional|libs|2262|no|bind9-libs|Exported DNS Shared Library
libdw1|0.186-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|729|same|elfutils|library that provides access to the DWARF debug information
libedit2|3.1-20210910-1build1|amd64|jammy,now|a|optional|libs|260|same|libedit|BSD editline and history libraries
libelf1|0.186-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|192|same|elfutils|library to read and write ELF files
liberror-perl|0.17029-1|all|jammy,now|a|optional|perl|71|foreign|liberror-perl|Perl module for error/exception handling in an OO-ish way
libestr0|0.1.10-2.1build3|amd64|jammy,now|a|extra|libs|31|same|libestr|Helper functions for handling strings (lib)
libevent-core-2.1-7|2.1.12-stable-1ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|256|same|libevent|Asynchronous event notification library (core)
libexpat1|2.4.7-1ubuntu0.9|amd64|jammy-updates,jammy-security,now|a|optional|libs|443|same|expat|XML parsing C library - runtime library
libext2fs2|1.46.5-2ubuntu1.2|amd64|jammy-updates,now|m|required|libs|574|same|e2fsprogs|ext2/ext3/ext4 file system libraries
libfastjson4|0.99.9-1build2|amd64|jammy,now|a|optional|libs|69|same|libfastjson|fast json library for C
libfdisk1|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|a|optional|libs|434|same|util-linux|fdisk partitioning library
libffi8|3.4.2-4|amd64|jammy,now|m|important|libs|69|same|libffi|Foreign Function Interface library runtime
libfido2-1|1.10.0-1|amd64|jammy,now|a|optional|libs|236|same|libfido2|library for generating and verifying FIDO 2.0 objects
libfuse3-3|3.10.5-1build1|amd64|jammy,now|a|optional|libs|282|same|fuse3|Filesystem in Userspace (library) (3.x version)
libgcc-s1|12.3.0-1ubuntu1~22.04.3|amd64|jammy-updates,jammy-security,now|m|required|libs|140|same|gcc-12|GCC support library
libgcrypt20|1.9.4-3ubuntu3.3|amd64|jammy-updates,jammy-security,now|m|required|libs|1363|same|libgcrypt20|LGPL Crypto library - runtime library
libgdbm-compat4|1.23-1|amd64|jammy,now|a|optional|libs|45|same|gdbm|GNU dbm database routines (legacy support runtime version)
libgdbm6|1.23-1|amd64|jammy,now|a|optional|libs|100|same|gdbm|GNU dbm database routines (runtime version)
libgirepository-1.0-1|1.72.0-1|amd64|jammy,now|a|optional|libs|175|same|gobject-introspection|Library for handling GObject introspection data (runtime library)
libglib2.0-0|2.72.4-0ubuntu2.10|amd64|jammy-updates,jammy-security,now|a|optional|libs|4095|same|glib2.0|GLib library of C routines
libglib2.0-bin|2.72.4-0ubuntu2.10|amd64|jammy-updates,jammy-security,now|a|optional|misc|343|foreign|glib2.0|Programs for the GLib library
libglib2.0-data|2.72.4-0ubuntu2.10|all|jammy-updates,jammy-security,now|a|optional|libs|112|foreign|glib2.0|Common files for GLib library
libgmp10|2:6.2.1+dfsg-3ubuntu1|amd64|jammy,now|m|required|libs|544|same|gmp|Multiprecision arithmetic library
libgnutls30|3.7.3-4ubuntu1.9|amd64|jammy-updates,jammy-security,now|m|important|libs|2296|same|gnutls28|GNU TLS library - main runtime library
libgpg-error0|1.43-3|amd64|jammy,now|m|required|libs|189|same|libgpg-error|GnuPG development runtime library
libgpm2|1.20.7-10build1|amd64|jammy,now|a|optional|libs|65|same|gpm|General Purpose Mouse - shared library
libgssapi-krb5-2|1.19.2-2ubuntu0.8|amd64|jammy-security,now|m|required|libs|456|same|krb5|MIT Kerberos runtime libraries - krb5 GSS-API Mechanism
libgstreamer1.0-0|1.20.3-0ubuntu1.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|2984|same|gstreamer1.0|Core GStreamer libraries and elements
libgudev-1.0-0|1:237-2build1|amd64|jammy,now|a|optional|libs|69|same|libgudev|GObject-based wrapper library for libudev
libhogweed6|3.7.3-1build2|amd64|jammy,now|m|important|libs|336|same|nettle|low level cryptographic library (public-key cryptos)
libicu70|70.1-2|amd64|jammy,now|a|optional|libs|34444|same|icu|International Components for Unicode
libidn2-0|2.3.2-2build1|amd64|jammy,now|m|important|libs|220|same|libidn2|Internationalized domain names (IDNA2008/TR46) library
libinih1|53-1ubuntu3|amd64|jammy,now|a|optional|libs|30|same|libinih|simple .INI file parser
libip4tc2|1.8.7-1ubuntu5.2|amd64|jammy-updates,now|a|optional|libs|83|same|iptables|netfilter libip4tc library
libisc-export1105|1:9.11.19+dfsg-2.1ubuntu3|amd64|jammy,now|a|optional|libs|510|same|bind9-libs|Exported ISC Shared Library
libjson-c5|0.15-3~ubuntu1.22.04.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|98|same|json-c|JSON manipulation library - shared library
libk5crypto3|1.19.2-2ubuntu0.8|amd64|jammy-security,now|m|required|libs|293|same|krb5|MIT Kerberos runtime libraries - Crypto Library
libkeyutils1|1.6.1-2ubuntu3|amd64|jammy,now|m|required|misc|47|same|keyutils|Linux Key Management Utilities (library)
libklibc|2.0.10-4ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|115|same|klibc|minimal libc subset for use with initramfs
libkmod2|29-1ubuntu1.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|139|same|kmod|libkmod shared library
libkrb5-3|1.19.2-2ubuntu0.8|amd64|jammy-security,now|m|required|libs|1053|same|krb5|MIT Kerberos runtime libraries
libkrb5support0|1.19.2-2ubuntu0.8|amd64|jammy-security,now|m|required|libs|165|same|krb5|MIT Kerberos runtime libraries - Support library
libksba8|1.6.0-2ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|302|same|libksba|X.509 and CMS support library
libldap-2.5-0|2.5.20+dfsg-0ubuntu0.22.04.1|amd64|jammy-updates,now|a|optional|libs|570|same|openldap|OpenLDAP libraries
liblocale-gettext-perl|1.07-4build3|amd64|jammy,now|a|required|perl|59|no|liblocale-gettext-perl|module using libc functions for internationalization in Perl
liblvm2cmd2.03|2.03.11-2.1ubuntu5|amd64|jammy-updates,now|a|optional|libs|2939|same|lvm2|LVM2 command library
liblz4-1|1.9.3-2build2|amd64|jammy,now|m|required|libs|145|same|lz4|Fast LZ compression algorithm library - runtime
liblzma5|5.2.5-2ubuntu1.1|amd64|jammy-updates,jammy-security,now|m|required|libs|290|same|xz-utils|XZ-format compression library
liblzo2-2|2.10-2build3|amd64|jammy,now|a|optional|libs|159|same|lzo2|data compression library
libmagic-mgc|1:5.41-3ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|7128|foreign|file|File type determination library using "magic" numbers (compiled magic file)
libmagic1|1:5.41-3ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|229|same|file|Recognize the type of data in a file using "magic" numbers - library
libmbim-glib4|1.28.0-1~ubuntu20.04.2|amd64|jammy-updates,now|a|optional|libs|684|same|libmbim|Support library to use the MBIM protocol
libmbim-proxy|1.28.0-1~ubuntu20.04.2|amd64|jammy-updates,now|a|optional|net|33|foreign|libmbim|Proxy to communicate with MBIM ports
libmd0|1.0.4-1build1|amd64|jammy,now|a|optional|libs|71|same|libmd|message digest functions from BSD systems - shared library
libmm-glib0|1.20.0-1~ubuntu22.04.4|amd64|jammy-updates,now|a|optional|libs|1259|same|modemmanager|D-Bus service for managing modems - shared libraries
libmnl0|1.0.4-3build2|amd64|jammy,now|a|optional|libs|47|same|libmnl|minimalistic Netlink communication library
libmount1|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|libs|383|same|util-linux|device mounting library
libmpdec3|2.5.1-2build2|amd64|jammy,now|a|optional|libs|250|same|mpdecimal|library for decimal floating point arithmetic (runtime library)
libmpfr6|4.1.0-3build3|amd64|jammy,now|a|optional|libs|3405|same|mpfr4|multiple precision floating-point computation
libncurses6|6.3-2ubuntu0.3|amd64|jammy-updates,jammy-security,now|m|required|libs|329|same|ncurses|shared libraries for terminal handling
libncursesw6|6.3-2ubuntu0.3|amd64|jammy-updates,jammy-security,now|m|required|libs|422|same|ncurses|shared libraries for terminal handling (wide character support)
libnetplan0|0.107.1-3ubuntu0.22.04.5|amd64|jammy-updates,now|a|optional|libs|343|same|netplan.io|YAML network configuration abstraction runtime library
libnettle8|3.7.3-1build2|amd64|jammy,now|m|important|libs|356|same|nettle|low level cryptographic library (symmetric and one-way cryptos)
libnewt0.52|0.52.21-5ubuntu2|amd64|jammy,now|a|optional|libs|200|same|newt|Not Erik's Windowing Toolkit - text mode windowing with slang
libnghttp2-14|1.43.0-1ubuntu0.4|amd64|jammy-updates,jammy-security,now|a|optional|libs|204|same|nghttp2|library implementing HTTP/2 protocol (shared library)
libnl-3-200|3.5.0-0.1|amd64|jammy,now|a|optional|libs|180|same|libnl3|library for dealing with netlink sockets
libnl-genl-3-200|3.5.0-0.1|amd64|jammy,now|a|optional|libs|61|same|libnl3|library for dealing with netlink sockets - generic netlink
libnpth0|1.6-3build2|amd64|jammy,now|a|optional|libs|40|same|npth|replacement for GNU Pth using system threads
libnsl2|1.3.0-2build2|amd64|jammy,now|m|required|libs|123|same|libnsl|Public client interface for NIS(YP) and NIS+
libp11-kit0|0.24.0-6ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|important|libs|1292|same|p11-kit|library for loading and coordinating access to PKCS#11 modules - runtime
libpackagekit-glib2-18|1.2.5-2ubuntu3.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|463|same|packagekit|Library for accessing PackageKit using GLib
libpam-modules|1.4.0-11ubuntu2.8|amd64|jammy-updates,jammy-security,now|m|required|admin|1144|same|pam|Pluggable Authentication Modules for PAM
libpam-modules-bin|1.4.0-11ubuntu2.8|amd64|jammy-updates,jammy-security,now|m|required|admin|249|foreign|pam|Pluggable Authentication Modules for PAM - helper binaries
libpam-runtime|1.4.0-11ubuntu2.8|all|jammy-updates,jammy-security,now|m|required|admin|312|foreign|pam|Runtime support for the PAM library
libpam-systemd|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|m|standard|admin|650|same|systemd|system and service manager - PAM module
libpam0g|1.4.0-11ubuntu2.8|amd64|jammy-updates,jammy-security,now|m|required|libs|236|same|pam|Pluggable Authentication Modules library
libparted-fs-resize0|3.4-2build1|amd64|jammy,now|a|optional|libs|148|same|parted|disk partition manipulator - shared FS resizing library
libparted2|3.4-2build1|amd64|jammy,now|a|optional|libs|458|same|parted|disk partition manipulator - shared library
libpci3|1:3.7.0-6|amd64|jammy,now|a|optional|libs|90|same|pciutils|PCI utilities (shared library)
libpcre2-8-0|10.39-3ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|required|libs|621|same|pcre2|New Perl Compatible Regular Expression Library- 8 bit runtime files
libpcre3|2:8.39-13ubuntu0.22.04.1|amd64|jammy-updates,jammy-security,now|m|required|libs|683|same|pcre3|Old Perl 5 Compatible Regular Expression Library - runtime files
libperl5.34|5.34.0-3ubuntu1.9|amd64|jammy-updates,jammy-security,now|a|optional|libs|28454|same|perl|shared Perl library
libpolkit-agent-1-0|0.105-33ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|80|same|policykit-1|PolicyKit Authentication Agent API
libpolkit-gobject-1-0|0.105-33ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|158|same|policykit-1|PolicyKit Authorization API
libpopt0|1.18-3build1|amd64|jammy,now|a|optional|libs|120|same|popt|lib for parsing cmdline parameters
libprocps8|2:3.3.17-6ubuntu2.1|amd64|jammy-updates,jammy-security,now|m|required|libs|131|same|procps|library for accessing process information from /proc
libpsl5|0.21.0-1.2build2|amd64|jammy,now|a|optional|libs|95|same|libpsl|Library for Public Suffix List (shared libraries)
libpython3-stdlib|3.10.6-1~22.04.1|amd64|jammy-updates,now|a|optional|python|39|same|python3-defaults|interactive high-level object-oriented language (default python3 version)
libpython3.10|3.10.12-1~22.04.18|amd64|jammy-updates,jammy-security,now|a|optional|libs|5768|same|python3.10|Shared Python runtime library (version 3.10)
libpython3.10-minimal|3.10.12-1~22.04.18|amd64|jammy-updates,jammy-security,now|a|optional|python|5121|same|python3.10|Minimal subset of the Python language (version 3.10)
libpython3.10-stdlib|3.10.12-1~22.04.18|amd64|jammy-updates,jammy-security,now|a|optional|python|8133|same|python3.10|Interactive high-level object-oriented language (standard library, version 3.10)
libqmi-glib5|1.32.0-1ubuntu0.22.04.1|amd64|jammy-updates,now|a|optional|libs|3812|same|libqmi|Support library to use the Qualcomm MSM Interface (QMI) protocol
libqmi-proxy|1.32.0-1ubuntu0.22.04.1|amd64|jammy-updates,now|a|optional|net|32|foreign|libqmi|Proxy to communicate with QMI ports
libreadline8|8.1.2-1|amd64|jammy,now|a|optional|libs|461|same|readline|GNU readline and history libraries, run-time libraries
librtmp1|2.4+20151223.gitfa8646d.1-2build4|amd64|jammy,now|a|optional|libs|141|same|rtmpdump|toolkit for RTMP streams (shared library)
libsasl2-2|2.1.27+dfsg2-3ubuntu1.2|amd64|jammy-updates,now|a|standard|libs|170|same|cyrus-sasl2|Cyrus SASL - authentication abstraction library
libsasl2-modules-db|2.1.27+dfsg2-3ubuntu1.2|amd64|jammy-updates,now|a|standard|libs|93|same|cyrus-sasl2|Cyrus SASL - pluggable authentication modules (DB)
libseccomp2|2.5.3-2ubuntu3~22.04.1|amd64|jammy-updates,now|m|important|libs|145|same|libseccomp|high level interface to Linux seccomp filter
libselinux1|3.3-1build2|amd64|jammy,now|m|required|libs|207|same|libselinux|SELinux runtime shared libraries
libsemanage-common|3.3-1build2|all|jammy,now|m|required|libs|37|foreign|libsemanage|Common files for SELinux policy management libraries
libsemanage2|3.3-1build2|amd64|jammy,now|m|required|libs|300|same|libsemanage|SELinux policy management library
libsepol2|3.3-1build1|amd64|jammy,now|m|required|libs|735|same|libsepol|SELinux library for manipulating binary security policies
libsgutils2-2|1.46-1ubuntu0.22.04.2|amd64|jammy-updates,jammy-security,now|a|optional|libs|294|same|sg3-utils|utilities for devices using the SCSI command set (shared libraries)
libsigsegv2|2.13-1ubuntu3|amd64|jammy,now|a|optional|libs|49|same|libsigsegv|Library for handling page faults in a portable way
libslang2|2.3.2-5build4|amd64|jammy,now|a|optional|libs|1628|same|slang2|S-Lang programming library - runtime version
libsmartcols1|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|libs|210|same|util-linux|smart column output alignment library
libsodium23|1.0.18-1ubuntu0.22.04.1|amd64|jammy-updates,jammy-security,now|a|optional|libs|398|same|libsodium|Network communication, cryptography and signaturing library
libsqlite3-0|3.37.2-2ubuntu0.8|amd64|jammy-updates,jammy-security,now|a|optional|libs|1603|same|sqlite3|SQLite 3 shared library
libss2|1.46.5-2ubuntu1.2|amd64|jammy-updates,now|m|required|libs|113|same|e2fsprogs|command-line interface parsing library
libssh-4|0.9.6-2ubuntu0.22.04.8|amd64|jammy-updates,jammy-security,now|a|optional|libs|492|same|libssh|tiny C SSH library (OpenSSL flavor)
libssl3|3.0.2-0ubuntu1.29|amd64|now|m|required|libs|5837|same|openssl|Secure Sockets Layer toolkit - shared libraries|jammy-updates,jammy-security 3.0.2-0ubuntu1.30
libstdc++6|12.3.0-1ubuntu1~22.04.3|amd64|jammy-updates,jammy-security,now|m|important|libs|2755|same|gcc-12|GNU Standard C++ Library v3
libstemmer0d|2.2.0-1build1|amd64|jammy,now|a|optional|libs|839|same|snowball|Snowball stemming algorithms for use in Information Retrieval
libsystemd0|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|m|required|libs|997|same|systemd|systemd utility library
libtasn1-6|4.18.0-4ubuntu0.2|amd64|jammy-updates,jammy-security,now|m|important|libs|134|same|libtasn1-6|Manage ASN.1 structures (runtime)
libtext-charwidth-perl|0.04-10build3|amd64|jammy,now|a|required|perl|45|no|libtext-charwidth-perl|get display widths of characters on the terminal
libtext-iconv-perl|1.7-7build3|amd64|jammy,now|a|required|perl|52|no|libtext-iconv-perl|module to convert between character sets in Perl
libtext-wrapi18n-perl|0.06-9|all|jammy,now|a|required|perl|25|no|libtext-wrapi18n-perl|internationalized substitute of Text::Wrap
libtinfo6|6.3-2ubuntu0.3|amd64|jammy-updates,jammy-security,now|m|required|libs|559|same|ncurses|shared low-level terminfo library for terminal handling
libtirpc-common|1.3.2-2ubuntu0.1|all|jammy-updates,jammy-security,now|m|required|libs|32|foreign|libtirpc|transport-independent RPC library - common files
libtirpc3|1.3.2-2ubuntu0.1|amd64|jammy-updates,jammy-security,now|m|required|libs|219|same|libtirpc|transport-independent RPC library
libudev1|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|m|required|libs|349|same|systemd|libudev shared library
libudisks2-0|2.9.4-1ubuntu2.3|amd64|jammy-updates,jammy-security,now|a|optional|libs|836|same|udisks2|GObject based library to access udisks2
libunistring2|1.0-1|amd64|jammy,now|m|important|libs|1746|same|libunistring|Unicode string library for C
libunwind8|1.3.2-2build2.1|amd64|jammy-updates,now|a|optional|libs|196|same|libunwind|library to determine the call-chain of a program - runtime
liburcu8|0.13.1-1|amd64|jammy,now|a|optional|libs|331|same|liburcu|userspace RCU (read-copy-update) library
libutempter0|1.2.1-2build2|amd64|jammy,now|a|optional|libs|51|same|libutempter|privileged helper for utmp/wtmp updates (runtime)
libuuid1|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|libs|135|same|util-linux|Universally Unique ID library
libwrap0|7.6.q-31build2|amd64|jammy,now|a|optional|libs|109|same|tcp-wrappers|Wietse Venema's TCP wrappers library
libxml2|2.9.13+dfsg-1ubuntu0.13|amd64|jammy-updates,jammy-security,now|a|optional|libs|2098|same|libxml2|GNOME XML library
libxmlb2|0.3.24-1~ubuntu0.22.04.1|amd64|jammy-updates,now|a|optional|libs|192|same|libxmlb|Binary XML library
libxtables12|1.8.7-1ubuntu5.2|amd64|jammy-updates,now|a|optional|libs|114|same|iptables|netfilter xtables library
libxxhash0|0.8.1-1|amd64|jammy,now|m|important|libs|97|same|xxhash|shared library for xxhash
libyaml-0-2|0.2.2-1build2|amd64|jammy,now|a|optional|libs|144|same|libyaml|Fast YAML 1.1 parser and emitter library
libzstd1|1.4.8+dfsg-3build1|amd64|jammy,now|m|required|libs|846|same|libzstd|fast lossless compression algorithm
linux-base|4.5ubuntu9+22.04.1|all|jammy-updates,now|a|optional|kernel|156|foreign|linux-base|Linux image base package
linux-image-5.15.0-91-generic|5.15.0-91.101|amd64|now|a|optional|kernel|11536|no|linux-signed|Signed kernel image generic
linux-modules-5.15.0-91-generic|5.15.0-91.101|amd64|now|a|optional|kernel|103420|no|linux|Linux kernel extra modules for version 5.15.0 on 64 bit x86 SMP
locales|2.35-0ubuntu3.15|all|jammy-updates,jammy-security,now|a|standard|localization|17068|no|glibc|GNU C Library: National Language (locale) data [support]
login|1:4.8.1-2ubuntu2.2|amd64|jammy-updates,jammy-security,now|m|required|admin|888|foreign|shadow|system login tools
logsave|1.46.5-2ubuntu1.2|amd64|jammy-updates,now|m|required|admin|97|foreign|e2fsprogs|save the output of a command in a log file
lsb-base|11.1.0ubuntu4|all|jammy,now|m|required|misc|58|foreign|lsb|Linux Standard Base init script functionality
lsb-release|11.1.0ubuntu4|all|jammy,now|a|optional|misc|66|foreign|lsb|Linux Standard Base version reporting utility
lshw|02.19.git.2021.06.19.996aaad9c7-2ubuntu0.22.04.1|amd64|jammy-updates,now|m|optional|utils|921|no|lshw|information about hardware configuration
lvm2|2.03.11-2.1ubuntu5|amd64|jammy-updates,now|a|optional|admin|4033|foreign|lvm2|Linux Logical Volume Manager
mawk|1.3.4.20200120-3|amd64|jammy,now|m|required|utils|229|foreign|mawk|Pattern scanning and text processing language
mdadm|4.2-0ubuntu2|amd64|jammy-updates,now|a|optional|admin|1182|no|mdadm|Tool to administer Linux MD arrays (software RAID)
media-types|7.0.0|all|jammy,now|a|standard|net|97|foreign|media-types|List of standard media types and their usual file extension
modemmanager|1.20.0-1~ubuntu22.04.4|amd64|jammy-updates,now|m|optional|net|4708|no|modemmanager|D-Bus service for managing modems
motd-news-config|12ubuntu4.6|all|now|a|optional|admin|48|no|base-files|Configuration for motd-news shipped in base-files|jammy-updates 12ubuntu4.7
mount|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|admin|390|foreign|util-linux|tools for mounting and manipulating filesystems
multipath-tools|0.8.8-1ubuntu1.22.04.4|amd64|jammy-updates,now|m|optional|admin|1223|no|multipath-tools|maintain multipath block device access
nano|6.2-1ubuntu0.2|amd64|jammy-updates,jammy-security,now|m|important|editors|860|no|nano|small, friendly text editor inspired by Pico
ncurses-base|6.3-2ubuntu0.3|all|jammy-updates,jammy-security,now|m|required|utils|394|foreign|ncurses|basic terminal type definitions
ncurses-bin|6.3-2ubuntu0.3|amd64|jammy-updates,jammy-security,now|m|required|utils|647|foreign|ncurses|terminal-related programs and man pages
netbase|6.3|all|jammy,now|a|important|admin|41|foreign|netbase|Basic TCP/IP networking system
netcat-openbsd|1.218-4ubuntu1|amd64|jammy,now|a|important|net|106|no|netcat-openbsd|TCP/IP swiss army knife
netplan-generator|0.107.1-3ubuntu0.22.04.5|amd64|jammy-updates,now|a|optional|net|270|foreign|netplan.io|YAML network configuration abstraction systemd-generator
netplan.io|0.107.1-3ubuntu0.22.04.5|amd64|jammy-updates,now|a|optional|net|266|foreign|netplan.io|YAML network configuration abstraction for various backends
networkd-dispatcher|2.1-2ubuntu0.22.04.2|all|jammy-updates,jammy-security,now|m|optional|utils|69|no|networkd-dispatcher|Dispatcher service for systemd-networkd connection status changes
openssh-client|1:8.9p1-3ubuntu0.10|amd64|now|m|standard|net|3102|foreign|openssh|secure shell (SSH) client, for secure access to remote machines|jammy-updates,jammy-security 1:8.9p1-3ubuntu0.17
openssh-server|1:8.9p1-3ubuntu0.10|amd64|now|m|optional|net|1505|foreign|openssh|secure shell (SSH) server, for secure access from remote machines|jammy-updates,jammy-security 1:8.9p1-3ubuntu0.17
openssh-sftp-server|1:8.9p1-3ubuntu0.10|amd64|now|a|optional|net|101|foreign|openssh|secure shell (SSH) sftp server module, for SFTP access from remote machines|jammy-updates,jammy-security 1:8.9p1-3ubuntu0.17
openssl|3.0.2-0ubuntu1.30|amd64|jammy-updates,jammy-security,now|a|optional|utils|2053|foreign|openssl|Secure Sockets Layer toolkit - cryptographic utility
overlayroot|0.47ubuntu1|all|jammy,now|a|optional|admin|66|no|cloud-initramfs-tools|use an overlayfs on top of a read-only root filesystem
packagekit|1.2.5-2ubuntu3.1|amd64|jammy-updates,jammy-security,now|a|optional|admin|1592|foreign|packagekit|Provides a package management service
parted|3.4-2build1|amd64|jammy,now|a|optional|admin|167|foreign|parted|disk partition manipulator
passwd|1:4.8.1-2ubuntu2.2|amd64|jammy-updates,jammy-security,now|m|required|admin|2325|foreign|shadow|change and administer password and group data
patch|2.7.6-7build2|amd64|jammy,now|a|optional|vcs|229|foreign|patch|Apply a diff file to an original
pci.ids|0.0~2022.01.22-1ubuntu0.1|all|jammy-updates,now|a|optional|admin|1282|foreign|pci.ids|PCI ID Repository
pciutils|1:3.7.0-6|amd64|jammy,now|m|standard|admin|172|foreign|pciutils|PCI utilities
perl|5.34.0-3ubuntu1.9|amd64|jammy-updates,jammy-security,now|a|standard|perl|719|allowed|perl|Larry Wall's Practical Extraction and Report Language
perl-base|5.34.0-3ubuntu1.9|amd64|jammy-updates,jammy-security,now|m|required|perl|7740|no|perl|minimal Perl system
perl-modules-5.34|5.34.0-3ubuntu1.9|all|jammy-updates,jammy-security,now|a|standard|libs|17674|foreign|perl|Core Perl modules
pinentry-curses|1.1.1-1build2|amd64|jammy,now|a|optional|utils|92|foreign|pinentry|curses-based PIN or pass-phrase entry dialog for GnuPG
pkexec|0.105-33ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|admin|65|foreign|policykit-1|run commands as another user with polkit authorization
policykit-1|0.105-33ubuntu0.2|amd64|jammy-updates,jammy-security,now|m|optional|oldlibs|29|foreign|policykit-1|transitional package for polkitd and pkexec
polkitd|0.105-33ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|admin|524|foreign|policykit-1|framework for managing administrative policies and privileges
pollinate|4.33-3ubuntu2.3|all|jammy-updates,jammy-security,now|a|optional|admin|57|no|pollinate|seed the pseudo random number generator
procps|2:3.3.17-6ubuntu2.1|amd64|jammy-updates,jammy-security,now|m|required|admin|1388|foreign|procps|/proc file system utilities
psmisc|23.4-2build3|amd64|jammy,now|m|optional|admin|452|foreign|psmisc|utilities that use the proc file system
python-apt-common|2.4.0ubuntu4.1|all|jammy-updates,jammy-security,now|a|optional|python|188|foreign|python-apt|Python interface to libapt-pkg (locales)
python3|3.10.6-1~22.04.1|amd64|jammy-updates,now|a|optional|python|90|allowed|python3-defaults|interactive high-level object-oriented language (default python3 version)
python3-apport|2.20.11-0ubuntu82.10|all|jammy-updates,jammy-security,now|a|optional|python|600|no|apport|Python 3 library for Apport crash report handling
python3-apt|2.4.0ubuntu4.1|amd64|jammy-updates,jammy-security,now|a|optional|python|705|allowed|python-apt|Python 3 interface to libapt-pkg
python3-blinker|1.4+dfsg1-0.4|all|jammy,now|a|optional|python|55|no|blinker|fast, simple object-to-object and broadcast signaling library
python3-cffi-backend|1.15.0-1build2|amd64|jammy,now|a|optional|python|218|same|python-cffi|Foreign Function Interface for Python 3 calling C code - runtime
python3-chardet|4.0.0-1|all|jammy,now|a|optional|python|1068|foreign|chardet|universal character encoding detector for Python3
python3-commandnotfound|22.04.0|all|jammy,now|a|optional|python|59|no|command-not-found|Python 3 bindings for command-not-found.
python3-cryptography|3.4.8-1ubuntu2.4|amd64|jammy-updates,jammy-security,now|a|optional|python|1590|no|python-cryptography|Python library exposing cryptographic recipes and primitives (Python 3)
python3-dbus|1.2.18-3build1|amd64|jammy,now|a|optional|python|417|no|dbus-python|simple interprocess messaging system (Python 3 interface)
python3-debconf|1.5.79ubuntu1|all|jammy,now|a|optional|python|18|no|debconf|interact with debconf from Python 3
python3-debian|0.1.43ubuntu1.1|all|jammy-updates,now|a|optional|python|553|no|python-debian|Python 3 modules to work with Debian-related data formats
python3-distro|1.7.0-1|all|jammy,now|a|optional|python|77|foreign|python-distro|Linux OS platform information API
python3-distro-info|1.1ubuntu0.2|all|jammy-updates,now|a|optional|python|35|no|distro-info|information about distributions' releases (Python 3 module)
python3-distupgrade|1:22.04.21|all|jammy-updates,now|a|optional|python|643|no|ubuntu-release-upgrader|manage release upgrades
python3-gdbm|3.10.8-1~22.04|amd64|jammy-updates,jammy-security,now|a|optional|python|87|same|python3-stdlib-extensions|GNU dbm database support for Python 3.x
python3-gi|3.42.1-0ubuntu1|amd64|jammy-updates,now|a|optional|python|747|allowed|pygobject|Python 3 bindings for gobject-introspection libraries
python3-httplib2|0.20.2-2ubuntu0.1|all|jammy-updates,jammy-security,now|a|optional|python|137|no|python-httplib2|comprehensive HTTP client library written for Python3
python3-importlib-metadata|4.6.4-1|all|jammy,now|a|optional|python|67|no|python-importlib-metadata|library to access the metadata for a Python package - Python 3.x
python3-jeepney|0.7.1-3|all|jammy,now|a|optional|python|186|no|jeepney|pure Python D-Bus interface
python3-jwt|2.3.0-1ubuntu0.4|all|jammy-updates,jammy-security,now|a|optional|python|85|no|pyjwt|Python 3 implementation of JSON Web Token
python3-keyring|23.5.0-1|all|jammy,now|a|optional|python|154|no|python-keyring|store and access your passwords safely
python3-launchpadlib|1.10.16-1|all|jammy,now|a|optional|python|1762|no|python-launchpadlib|Launchpad web services client library (Python 3)
python3-lazr.restfulclient|0.14.4-1|all|jammy,now|a|optional|python|183|no|lazr.restfulclient|client for lazr.restful-based web services (Python 3)
python3-lazr.uri|1.0.6-2|all|jammy,now|a|optional|python|75|no|lazr.uri|library for parsing, manipulating, and generating URIs
python3-magic|2:0.4.24-2|all|jammy,now|a|optional|python|51|no|python-magic|python3 interface to the libmagic file type identification library
python3-minimal|3.10.6-1~22.04.1|amd64|jammy-updates,now|a|optional|python|122|allowed|python3-defaults|minimal subset of the Python language (default python3 version)
python3-more-itertools|8.10.0-2|all|jammy,now|a|optional|python|226|no|more-itertools|library with routines for operating on iterables, beyond itertools (Python 3)
python3-netifaces|0.11.0-1build2|amd64|jammy,now|a|optional|python|54|same|netifaces|portable network interface information - Python 3.x
python3-netplan|0.107.1-3ubuntu0.22.04.5|amd64|jammy-updates,now|a|optional|python|138|foreign|netplan.io|YAML network configuration abstraction Python bindings
python3-newt|0.52.21-5ubuntu2|amd64|jammy,now|a|optional|python|111|same|newt|NEWT module for Python3
python3-oauthlib|3.2.0-1ubuntu0.1|all|jammy-updates,jammy-security,now|a|optional|python|556|no|python-oauthlib|generic, spec-compliant implementation of OAuth for Python3
python3-packaging|21.3-1|all|jammy,now|a|optional|python|135|no|python-packaging|core utilities for python3 packages
python3-pexpect|4.8.0-2ubuntu1|all|jammy,now|a|optional|python|200|no|pexpect|Python 3 module for automating interactive applications
python3-pkg-resources|59.6.0-1.2ubuntu0.22.04.3|all|jammy-updates,jammy-security,now|a|optional|python|581|foreign|setuptools|Package Discovery and Resource Access using pkg_resources
python3-problem-report|2.20.11-0ubuntu82.10|all|jammy-updates,jammy-security,now|a|optional|python|183|no|apport|Python 3 library to handle problem reports
python3-ptyprocess|0.7.0-3|all|jammy,now|a|optional|python|59|no|ptyprocess|Run a subprocess in a pseudo terminal from Python 3
python3-pyparsing|2.4.7-1|all|jammy,now|a|optional|python|298|no|pyparsing|alternative to creating and executing simple grammars - Python 3.x
python3-secretstorage|3.3.1-1|all|jammy,now|a|optional|python|56|no|python-secretstorage|Python module for storing secrets - Python 3.x version
python3-six|1.16.0-3ubuntu1|all|jammy,now|a|optional|python|59|foreign|six|Python 2 and 3 compatibility library (Python 3 interface)
python3-software-properties|0.99.22.9|all|jammy-updates,now|a|optional|python|175|no|software-properties|manage the repositories that you install software from
python3-update-manager|1:22.04.22|all|jammy-updates,now|a|optional|python|261|no|update-manager|python 3.x module for update-manager
python3-wadllib|1.3.6-1|all|jammy,now|a|optional|python|365|no|python-wadllib|Python 3 library for navigating WADL files
python3-yaml|5.4.1-1ubuntu1|amd64|jammy,now|a|optional|python|529|allowed|pyyaml|YAML parser and emitter for Python3
python3-zipp|1.0.0-3ubuntu0.1|all|jammy-updates,jammy-security,now|a|optional|python|27|no|python-zipp|pathlib-compatible Zipfile object wrapper - Python 3.x
python3.10|3.10.12-1~22.04.18|amd64|jammy-updates,jammy-security,now|a|optional|python|636|allowed|python3.10|Interactive high-level object-oriented language (version 3.10)
python3.10-minimal|3.10.12-1~22.04.18|amd64|jammy-updates,jammy-security,now|a|optional|python|5937|allowed|python3.10|Minimal subset of the Python language (version 3.10)
readline-common|8.1.2-1|all|jammy,now|a|optional|utils|80|foreign|readline|GNU readline and history libraries, common files
rsyslog|8.2112.0-2ubuntu2.5|amd64|jammy-updates,jammy-security,now|m|important|admin|1750|no|rsyslog|reliable system and kernel logging daemon
screen|4.9.0-1ubuntu0.1|amd64|jammy-updates,jammy-security,now|a|standard|misc|1001|no|screen|terminal multiplexer with VT100/ANSI terminal emulation
sed|4.8-1ubuntu2.1|amd64|jammy-updates,jammy-security,now|m|required|utils|328|foreign|sed|GNU stream editor for filtering/transforming text
sensible-utils|0.0.17|all|jammy,now|m|required|utils|59|foreign|sensible-utils|Utilities for sensible alternative selection
sg3-utils|1.46-1ubuntu0.22.04.2|amd64|jammy-updates,jammy-security,now|a|optional|admin|2790|no|sg3-utils|utilities for devices using the SCSI command set
sg3-utils-udev|1.46-1ubuntu0.22.04.2|all|jammy-updates,jammy-security,now|a|optional|admin|34|no|sg3-utils|utilities for devices using the SCSI command set (udev rules)
snapd|2.76.3+ubuntu22.04.1|amd64|jammy-updates,jammy-security,now|m|optional|devel|123600|no|snapd|Daemon and tooling that enable snap packages
software-properties-common|0.99.22.9|all|jammy-updates,now|a|optional|admin|220|no|software-properties|manage the repositories that you install software from (common)
sosreport|4.11.2-0ubuntu0~22.04.1|amd64|jammy-updates,now|a|optional|admin|2391|no|sosreport|Set of tools to gather troubleshooting data from a system
squashfs-tools|1:4.5-3build1|amd64|jammy,now|a|optional|kernel|414|no|squashfs-tools|Tool to create and append to squashfs filesystems
sudo|1.9.9-1ubuntu2.7|amd64|jammy-security,now|m|optional|admin|2508|no|sudo|Provide limited super user privileges to specific users
systemd|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|m|important|admin|16308|foreign|systemd|system and service manager
systemd-sysv|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|m|important|admin|199|foreign|systemd|system and service manager - SysV links
sysvinit-utils|3.01-1ubuntu1|amd64|jammy,now|m|required|admin|83|foreign|sysvinit|System-V-like utilities
tar|1.34+dfsg-1ubuntu0.1.22.04.6|amd64|jammy-updates,jammy-security,now|m|required|utils|964|foreign|tar|GNU version of the tar archiving utility
tmux|3.2a-4ubuntu0.2|amd64|jammy-updates,jammy-security,now|a|optional|admin|1026|no|tmux|terminal multiplexer
tzdata|2026c-0ubuntu0.22.04.1|all|jammy-updates,jammy-security,now|a|required|localization|3913|foreign|tzdata|time zone and daylight-saving time data
ubuntu-advantage-tools|37.2ubuntu~22.04.1|all|jammy-updates,jammy-security,now|a|optional|oldlibs|85|no|ubuntu-advantage-tools|transitional dummy package for ubuntu-pro-client
ubuntu-keyring|2021.03.26|all|jammy,now|m|important|misc|41|foreign|ubuntu-keyring|GnuPG keys of the Ubuntu archive
ubuntu-minimal|1.481.5|amd64|jammy-updates,now|m|optional|metapackages|53|no|ubuntu-meta|Minimal core of Ubuntu
ubuntu-pro-client|37.2ubuntu~22.04.1|amd64|jammy-updates,jammy-security,now|a|important|misc|1376|no|ubuntu-advantage-tools|Management tools for Ubuntu Pro
ubuntu-release-upgrader-core|1:22.04.21|all|jammy-updates,now|a|optional|admin|340|no|ubuntu-release-upgrader|manage release upgrades
ubuntu-server|1.481.5|amd64|jammy-updates,now|m|optional|metapackages|53|no|ubuntu-meta|The Ubuntu Server system
ucf|3.0043|all|jammy,now|a|standard|utils|232|foreign|ucf|Update Configuration File(s): preserve user changes to config files
udev|249.11-0ubuntu3.22|amd64|jammy-updates,jammy-security,now|a|important|admin|9502|foreign|systemd|/dev/ and hotplug management daemon
udisks2|2.9.4-1ubuntu2.3|amd64|jammy-updates,jammy-security,now|m|optional|admin|1180|foreign|udisks2|D-Bus service to access and manipulate storage devices
unattended-upgrades|2.8ubuntu1|all|jammy,now|m|optional|admin|436|no|unattended-upgrades|automatic installation of security upgrades
update-manager-core|1:22.04.22|all|jammy-updates,now|a|optional|admin|192|no|update-manager|manage release upgrades
update-notifier-common|3.192.54.8|all|jammy-updates,now|a|optional|gnome|1469|no|update-notifier|Files shared between update-notifier and other packages
usrmerge|25ubuntu2|all|jammy,now|m|required|admin|200|foreign|usrmerge|Convert the system to the merged /usr directories scheme
util-linux|2.37.2-4ubuntu3.6|amd64|jammy-updates,jammy-security,now|m|required|utils|3396|foreign|util-linux|miscellaneous system utilities
vim-common|2:8.2.3995-1ubuntu2.36|all|jammy-updates,jammy-security,now|a|important|editors|385|foreign|vim|Vi IMproved - Common files
vim-tiny|2:8.2.3995-1ubuntu2.36|amd64|jammy-updates,jammy-security,now|m|important|editors|1731|no|vim|Vi IMproved - enhanced vi editor - compact version
wget|1.21.2-2ubuntu1.5|amd64|jammy-updates,jammy-security,now|m|standard|web|928|foreign|wget|retrieves files from the web
whiptail|0.52.21-5ubuntu2|amd64|jammy,now|a|optional|utils|72|foreign|newt|Displays user-friendly dialog boxes from shell scripts
xfsprogs|5.13.0-1ubuntu2.1|amd64|jammy-updates,now|a|optional|admin|2784|no|xfsprogs|Utilities for managing the XFS filesystem
xkb-data|2.33-1|all|jammy,now|a|optional|x11|4236|foreign|xkeyboard-config|X Keyboard Extension (XKB) configuration data
xz-utils|5.2.5-2ubuntu1.1|amd64|jammy-updates,jammy-security,now|a|standard|utils|372|foreign|xz-utils|XZ-format compression utilities
zlib1g|1:1.2.11.dfsg-2ubuntu9.2|amd64|jammy-updates,jammy-security,now|m|required|libs|164|same|zlib|compression library - runtime
zstd|1.4.8+dfsg-3build1|amd64|jammy,now|a|optional|utils|1655|no|libzstd|fast lossless compression algorithm -- CLI tool
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_parses_and_the_table_is_sorted_and_unique() {
        let rows = ROWS.lines().filter(|row| !row.is_empty()).count();
        let packages: Vec<Package> = installed().collect();
        assert_eq!(packages.len(), rows, "a row that does not parse is dropped");
        assert!(packages.len() > 350);
        for pair in packages.windows(2) {
            if let [a, b] = pair {
                assert!(a.name < b.name, "{} before {}", a.name, b.name);
            }
        }
        for package in &packages {
            assert!(matches!(package.arch, "amd64" | "all"), "{}", package.name);
            assert!(
                matches!(package.multi_arch, "same" | "foreign" | "allowed" | "no"),
                "{}",
                package.name
            );
            assert!(package.pockets.ends_with("now"), "{}", package.name);
            assert!(!package.version.is_empty() && !package.summary.is_empty());
        }
    }

    #[test]
    fn the_ssh_packages_carry_the_version_the_banner_announces() {
        let banner_package = crate::persona::OPENSSH_VERSION
            .strip_prefix("OpenSSH_")
            .and_then(|rest| rest.split_once(" Ubuntu-"))
            .map(|(upstream, revision)| format!("1:{upstream}-{revision}"));
        for name in ["openssh-client", "openssh-server", "openssh-sftp-server"] {
            assert_eq!(
                find(name).map(|p| p.version.to_string()),
                banner_package,
                "{name}"
            );
        }
        assert!(OPENSSH_SERVER_DETAIL.contains("openssh-client (= 1:8.9p1-3ubuntu0.10)"));
    }

    #[test]
    fn the_commands_the_shell_answers_for_have_their_packages() {
        // The awk the box runs is mawk; gawk would take the alternative over.
        assert!(find("mawk").is_some() && find("gawk").is_none());
        for name in [
            "coreutils",
            "procps",
            "iproute2",
            "iputils-ping",
            "cron",
            "systemd",
            "pciutils",
            "lshw",
            "apt",
            "dpkg",
            "curl",
            "wget",
            "busybox-static",
        ] {
            assert!(find(name).is_some(), "{name}");
        }
    }
}
