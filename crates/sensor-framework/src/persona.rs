//! Single source of truth for the fictional host every sensor impersonates.
//!
//! Several sensors expose the SAME machine identity through different protocols: the SSH/telnet
//! shell's `uname` and prompt, the fake filesystem's `/etc/hostname` / `/etc/hosts` /
//! `/etc/os-release` / `/proc/version`, the Redis `INFO` `os:` line, the SMTP and FTP greeting
//! hostnames. If any two disagree - a prompt that says `server01` while `/etc/os-release` claims a
//! different distro, an SSH banner whose OpenSSH version never ships on the kernel `uname` reports -
//! the contradiction is a fingerprint an attacker can trip with two commands. Resolving all of them
//! from HERE keeps them mutually consistent by construction, and lets the operator retune the
//! persona (hostname) to blend with their own naming scheme, the same way `PROPOLIS_SSH_BANNER`
//! retunes the advertised SSH version.
//!
//! The identity is one coherent Ubuntu 22.04.4 LTS ("Jammy") host. The kernel, distro, and the
//! tool-version defaults below are chosen to match what that exact release actually ships, so the
//! cross-protocol triple (kernel / distro / package version) holds together.

use std::env;

/// Operator override for the impersonated hostname. A single-node deployment keeping the default is
/// fine; an operator who wants the honeypot to blend with a real naming scheme sets this.
pub const ENV_HOSTNAME: &str = "PROPOLIS_HOSTNAME";
const DEFAULT_HOSTNAME: &str = "server01";

// --- One coherent Ubuntu 22.04.4 LTS host. These strings surface across several sensors and MUST
//     agree with one another; a mismatched kernel/distro/tool-version triple is a detector. ---

/// `uname -r` for this host (jammy's 5.15 HWE-adjacent GA kernel).
pub const KERNEL_RELEASE: &str = "5.15.0-91-generic";
/// The `#NNN-Ubuntu SMP ...` build tag that follows the release in `uname -a` / `/proc/version`.
pub const KERNEL_BUILD: &str = "#101-Ubuntu SMP";
pub const ARCH: &str = "x86_64";
pub const OS_NAME: &str = "Ubuntu";
pub const OS_PRETTY: &str = "Ubuntu 22.04.4 LTS";
pub const OS_VERSION: &str = "22.04.4 LTS (Jammy Jellyfish)";
pub const OS_VERSION_ID: &str = "22.04";
/// The gcc build stamp jammy's kernels are compiled with, for `/proc/version`.
pub const GCC_BUILD: &str = "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0)";

/// The OpenSSH version string that ships on THIS distro (jammy's `openssh-server`), used as the SSH
/// banner default so the advertised version and the shell's `/etc/os-release` cannot contradict.
pub const OPENSSH_VERSION: &str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10";

/// The impersonated hostname, from `PROPOLIS_HOSTNAME` or the default. Resolved per call (cheap);
/// callers that bake it into a per-session snapshot should resolve once at session start.
pub fn hostname() -> String {
    env::var(ENV_HOSTNAME)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_HOSTNAME.to_string())
}

/// `uname -a`-style line for `host` (no trailing newline). Matches the historical shell output
/// exactly so existing behaviour is unchanged for the default hostname.
pub fn uname_all(host: &str) -> String {
    format!("Linux {host} {KERNEL_RELEASE} {KERNEL_BUILD} {ARCH} {ARCH} {ARCH} GNU/Linux")
}

/// `/proc/version` body (no trailing newline).
pub fn proc_version() -> String {
    format!("Linux version {KERNEL_RELEASE} (buildd@lcy02-amd64-051) {GCC_BUILD} {KERNEL_BUILD}")
}

/// The shell prompt for a root session on `host` (`root@host:~# `).
pub fn root_prompt(host: &str) -> String {
    format!("root@{host}:~# ")
}

// --- The Android device sensor-adb impersonates. ADB is Android's own debug protocol, so the
//     device this module describes is a SECOND coherent identity, not a variation on the Ubuntu
//     host above: a bot that reaches port 5555 expects a phone, and handing it an Ubuntu bash
//     after a Nexus 5 banner was a one-command tell. Everything ADB exposes - the CNXN banner's
//     properties, the shell prompt, `uname`, the filesystem, `/system/build.prop` - resolves from
//     here, so the banner and the shell cannot drift apart the way they had.
//
//     The device is ROOTED: it hands out a root shell over ADB, which a stock retail device does
//     not, and that is also why its filesystem carries busybox (near-universal on rooted phones)
//     rather than the toybox-only set a stock image ships.

/// Build properties of a Nexus 5 on its final official build.
pub const ANDROID_DEVICE: &str = "hammerhead";
pub const ANDROID_MODEL: &str = "Nexus 5";
pub const ANDROID_RELEASE: &str = "6.0.1";
pub const ANDROID_SDK: &str = "23";
pub const ANDROID_BUILD_ID: &str = "M4B30Z";
pub const ANDROID_ARCH: &str = "armv7l";
/// `uname -r` on that build.
pub const ANDROID_KERNEL_RELEASE: &str = "3.4.0-gcc3f57d";
pub const ANDROID_KERNEL_BUILD: &str = "#1 SMP PREEMPT Mon Nov 30 21:53:57 UTC 2015";
/// The hostname an Android kernel reports; phones do not carry the marketing name here.
pub const ANDROID_HOSTNAME: &str = "localhost";

/// The full build fingerprint, as `ro.build.fingerprint` and `getprop` report it.
pub fn android_fingerprint() -> String {
    format!(
        "google/{ANDROID_DEVICE}/{ANDROID_DEVICE}:{ANDROID_RELEASE}/{ANDROID_BUILD_ID}/3565761:user/release-keys"
    )
}

/// `uname -a` on the device. Android's uname prints no `GNU/Linux` suffix.
pub fn android_uname_all() -> String {
    format!(
        "Linux {ANDROID_HOSTNAME} {ANDROID_KERNEL_RELEASE} {ANDROID_KERNEL_BUILD} {ANDROID_ARCH}"
    )
}

/// `/proc/version` on the device.
pub fn android_proc_version() -> String {
    format!(
        "Linux version {ANDROID_KERNEL_RELEASE} (android-build@wpiv1.hot.corp.google.com) \
         (gcc version 4.8 (GCC) ) {ANDROID_KERNEL_BUILD}"
    )
}

/// The root shell prompt on Android 6, which shows the device name and the working directory.
pub fn android_root_prompt(cwd: &str) -> String {
    format!("root@{ANDROID_DEVICE}:{cwd} # ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_matches_historical_default() {
        // Locks the exact byte layout the shell emitted before persona was extracted, so the
        // refactor cannot silently change what an attacker's `uname -a` sees.
        assert_eq!(
            uname_all("server01"),
            "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux"
        );
    }

    #[test]
    fn prompt_reflects_hostname() {
        assert_eq!(root_prompt("web-prod-3"), "root@web-prod-3:~# ");
    }

    /// The ADB banner, the prompt, `uname` and `/system/build.prop` all read from these, so a
    /// bot comparing what the device claims with what its shell says finds one device.
    #[test]
    fn the_android_identity_agrees_with_itself() {
        assert!(android_uname_all().contains(ANDROID_KERNEL_RELEASE));
        assert!(android_uname_all().ends_with(ANDROID_ARCH));
        assert!(
            !android_uname_all().contains("GNU/Linux"),
            "Android's uname prints no GNU/Linux suffix"
        );
        assert!(android_proc_version().contains(ANDROID_KERNEL_RELEASE));
        assert_eq!(android_root_prompt("/"), "root@hammerhead:/ # ");
        assert!(android_fingerprint().contains(ANDROID_BUILD_ID));
        assert!(android_fingerprint().contains(ANDROID_RELEASE));
    }

    #[test]
    fn openssh_default_is_a_jammy_build() {
        // The banner default must name the distro the rest of the persona claims, or the SSH
        // version and /etc/os-release contradict.
        assert!(OPENSSH_VERSION.contains("8.9p1"));
        assert!(OPENSSH_VERSION.contains("Ubuntu"));
    }
}
