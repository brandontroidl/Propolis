//! The account database, root's dotfiles and the network configuration of the Ubuntu persona: the
//! `/etc` and `/root` files a survey reads to decide whether it is on a real server.
//!
//! The account lists start from a real Ubuntu 22.04 system's (recorded on 2026-10-07 from a
//! systemd-booted `ubuntu:22.04` reference: every line up to `sshd` and `_ssh` is that system's,
//! byte for byte) and add the accounts a cloud server image carries on top: the time daemon the
//! process table runs (`systemd-timesync`), the packages a server install brings, and the image's
//! login user `ubuntu`. Those additions, their ids and their order are [unverified]. Every daemon
//! the process table lists runs as an account defined here, so `ps`'s `USER` column and
//! `/etc/passwd` cannot disagree.
//!
//! `/root/.bashrc` and `/root/.profile` are the reference system's files, byte for byte (Ubuntu's
//! own `base-files` dotfiles). Their dates are the ones the reference showed.

use std::hash::{BuildHasher, Hasher};
use std::sync::OnceLock;

pub const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin
syslog:x:104:106::/home/syslog:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-timesync:x:106:108:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
uuidd:x:107:111::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:112::/nonexistent:/usr/sbin/nologin
tss:x:109:113:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:114::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:115:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
";

pub const GROUP: &str = "root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:ubuntu
fax:x:21:
voice:x:22:
cdrom:x:24:ubuntu
floppy:x:25:ubuntu
tape:x:26:
sudo:x:27:ubuntu
audio:x:29:ubuntu
dip:x:30:ubuntu
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:ubuntu
sasl:x:45:
plugdev:x:46:ubuntu
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
crontab:x:104:
messagebus:x:105:
syslog:x:106:
_ssh:x:107:
systemd-timesync:x:108:
netdev:x:109:ubuntu
lxd:x:110:ubuntu
uuidd:x:111:
tcpdump:x:112:
tss:x:113:
landscape:x:114:
fwupd-refresh:x:115:
ubuntu:x:1000:
";

/// The `shadow` group's id, which owns `/etc/shadow` and `/etc/gshadow`.
pub const SHADOW_GID: u32 = 42;

/// The day (since the epoch) the image's system accounts were made, and the day root's password
/// was last set: 2024-02-28 and 2024-03-08, inside the 22.04.4 point release's life [unverified].
const ACCOUNTS_DAY: u32 = 19_781;
const ROOT_PASSWORD_DAY: u32 = 19_790;

/// crypt(3)'s base-64 alphabet.
const CRYPT64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// root's password field: a yescrypt string (`$y$j9T$` and Ubuntu 22.04's default cost) whose
/// salt and digest are random bytes drawn once per sensor process. It is the hash of no password:
/// nothing is hashed to make it, so it can verify nothing and reveals nothing, and two deployments
/// never show the same one. root needs a real-looking hash here because the sensors let root log
/// in with a password, which a locked `root:*` entry would contradict.
pub fn root_password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        // `RandomState` is seeded from the operating system's randomness per process.
        let random = std::collections::hash_map::RandomState::new();
        let mut text = String::from("$y$j9T$");
        let draw = |count: usize, out: &mut String, round: u64| {
            for index in 0..count {
                let mut hasher = random.build_hasher();
                hasher.write_u64(round);
                hasher.write_usize(index);
                let value = hasher.finish();
                let symbol = CRYPT64
                    .get(usize::try_from(value % 64).unwrap_or(0))
                    .copied()
                    .unwrap_or(b'.');
                out.push(char::from(symbol));
            }
        };
        draw(22, &mut text, 1);
        text.push('$');
        draw(43, &mut text, 2);
        text
    })
}

/// `/etc/shadow`: root's hash, a locked field for every system account and the image user.
pub fn shadow() -> String {
    let mut out = String::new();
    for line in PASSWD.lines() {
        let Some(name) = line.split(':').next() else {
            continue;
        };
        let entry = match name {
            "root" => format!(
                "root:{}:{ROOT_PASSWORD_DAY}:0:99999:7:::\n",
                root_password_hash()
            ),
            "ubuntu" => format!("ubuntu:!:{ACCOUNTS_DAY}:0:99999:7:::\n"),
            "lxd" => format!("lxd:!:{ACCOUNTS_DAY}::::::\n"),
            other => format!("{other}:*:{ACCOUNTS_DAY}:0:99999:7:::\n"),
        };
        out.push_str(&entry);
    }
    out
}

/// `/etc/gshadow`: the reference system's form, `*` for the base groups and `!` for those made
/// by package scripts.
pub fn gshadow() -> String {
    let mut out = String::new();
    for line in GROUP.lines() {
        let mut fields = line.split(':');
        let (Some(name), Some(_), Some(gid), Some(members)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let gid: u32 = gid.parse().unwrap_or(0);
        let lock = if gid < 100 || name == "users" || name == "nogroup" {
            "*"
        } else {
            "!"
        };
        out.push_str(&format!("{name}:{lock}::{members}\n"));
    }
    out
}

pub const ROOT_BASHRC: &str = r#"# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history. See bash(1) for more options
# ... or force ignoredups and ignorespace
HISTCONTROL=ignoredups:ignorespace

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
#if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
#    . /etc/bash_completion
#fi
"#;

pub const ROOT_PROFILE: &str = "# ~/.profile: executed by Bourne-compatible login shells.

if [ \"$BASH\" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true
";

/// The dates the reference showed for the two dotfiles: 2021-10-15 10:06:05 and 2019-07-09
/// 10:05:50 UTC.
pub const ROOT_BASHRC_MTIME: i64 = 1_634_292_365;
pub const ROOT_PROFILE_MTIME: i64 = 1_562_666_750;

/// The installer's netplan file for the persona's one interface, as Ubuntu Server's installer
/// writes it for a static address [unverified wording; the addresses are the ones `ip addr` and
/// `ip route` show].
pub const NETPLAN: &str = "# This is the network config written by 'subiquity'
network:
  ethernets:
    eth0:
      addresses:
      - 172.31.16.42/20
      nameservers:
        addresses:
        - 172.31.16.1
        search: []
      routes:
      - to: default
        via: 172.31.16.1
  version: 2
";

/// `/usr/lib/os-release` (and `/etc/os-release`, a link to it): the reference system's layout,
/// with this persona's point release.
pub fn os_release() -> String {
    format!(
        "PRETTY_NAME=\"{pretty}\"\n\
         NAME=\"{name}\"\n\
         VERSION_ID=\"{vid}\"\n\
         VERSION=\"{version}\"\n\
         VERSION_CODENAME=jammy\n\
         ID=ubuntu\n\
         ID_LIKE=debian\n\
         HOME_URL=\"https://www.ubuntu.com/\"\n\
         SUPPORT_URL=\"https://help.ubuntu.com/\"\n\
         BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n\
         PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n\
         UBUNTU_CODENAME=jammy\n",
        pretty = crate::persona::OS_PRETTY,
        name = crate::persona::OS_NAME,
        vid = crate::persona::OS_VERSION_ID,
        version = crate::persona::OS_VERSION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dotfiles_are_the_recorded_sizes() {
        assert_eq!(ROOT_BASHRC.len(), 3_106);
        assert_eq!(ROOT_PROFILE.len(), 161);
    }

    #[test]
    fn roots_hash_is_well_formed_stable_and_the_rest_are_locked() {
        let hash = root_password_hash();
        assert!(hash.starts_with("$y$j9T$"), "{hash}");
        let parts: Vec<&str> = hash.split('$').collect();
        assert_eq!(parts.len(), 5, "{hash}");
        assert_eq!(parts[3].len(), 22);
        assert_eq!(parts[4].len(), 43);
        assert!(
            parts[3..]
                .iter()
                .all(|p| p.bytes().all(|b| CRYPT64.contains(&b))),
            "{hash}"
        );
        assert_eq!(root_password_hash(), hash, "one per process");
        let shadow = shadow();
        assert!(shadow.starts_with(&format!("root:{hash}:19790:0:99999:7:::\n")));
        assert_eq!(shadow.lines().count(), PASSWD.lines().count());
        for line in shadow.lines().skip(1) {
            let field = line.split(':').nth(1).unwrap();
            assert!(field == "*" || field == "!", "{line}");
        }
    }

    #[test]
    fn every_group_named_by_an_account_exists() {
        let gids: Vec<&str> = GROUP
            .lines()
            .map(|l| l.split(':').nth(2).unwrap())
            .collect();
        for line in PASSWD.lines() {
            let gid = line.split(':').nth(3).unwrap();
            assert!(gids.contains(&gid), "{line}");
        }
        assert_eq!(gshadow().lines().count(), GROUP.lines().count());
    }
}
