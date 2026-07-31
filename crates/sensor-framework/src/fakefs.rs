//! In-memory fake filesystem backing the fake shell's `cat`/`ls` canned responses (Task 13). See
//! "Fake shell" in `internal/design/02-sensor-framework.md`. Every path here is static content
//! baked in at construction - there is no real filesystem underneath, so there is nothing for an
//! attacker's path argument to traverse into, and every session gets an identical, fresh
//! snapshot with no state leaking from one attacker to the next.
//!
//! Every file is internally consistent with one fictional host (hostname `server01`, Ubuntu
//! 22.04 "Jammy", kernel matching `/proc/version`): the detectability section of the design doc
//! calls out "not contradicting oneself" as the realistic bar this layer clears, so `/etc/hosts`,
//! `/etc/hostname`, and `/etc/os-release` all agree with each other rather than being independent
//! guesses. No content anywhere references a real public address: every IP is loopback or an
//! IPv6 multicast/link-local group, never a routable address of any kind - stricter than the
//! RFC 5737/RFC 1918 documentation-only ranges this project's *emitted events* use, since a
//! plain default `/etc/hosts` has no routable address in it at all.

use std::collections::HashMap;

/// A static, read-only snapshot of a plausible Linux filesystem. Built fresh by `new()` for
/// every session; `FakeShell` never mutates it, only tracks its own working directory alongside
/// it.
pub struct FakeFs {
    files: HashMap<&'static str, &'static str>,
    dirs: HashMap<&'static str, Vec<&'static str>>,
}

impl Default for FakeFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeFs {
    pub fn new() -> Self {
        let mut files = HashMap::new();
        files.insert("/etc/hostname", "server01\n");
        files.insert(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
             sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
             mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
             www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
             sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n\
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        );
        files.insert(
            "/etc/hosts",
            "127.0.0.1 localhost\n\
             127.0.1.1 server01\n\
             \n\
             ::1 localhost ip6-localhost ip6-loopback\n\
             ff02::1 ip6-allnodes\n\
             ff02::2 ip6-allrouters\n",
        );
        files.insert(
            "/etc/os-release",
            "NAME=\"Ubuntu\"\n\
             VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n\
             ID=ubuntu\n\
             ID_LIKE=debian\n\
             PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n\
             VERSION_ID=\"22.04\"\n",
        );
        files.insert(
            "/proc/version",
            "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-051) \
             (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP\n",
        );
        files.insert(
            "/proc/cpuinfo",
            "processor\t: 0\n\
             vendor_id\t: GenuineIntel\n\
             model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n\
             cpu cores\t: 1\n",
        );

        let mut dirs = HashMap::new();
        dirs.insert(
            "/",
            vec![
                "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc",
                "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
            ],
        );
        // A freshly-booted honeypot has an empty /tmp and an empty (dotfiles-only, so invisible
        // to a plain `ls`) /root - both are present as *known, empty* directories rather than
        // absent, so `ls` on either returns a correct empty listing instead of misreporting a
        // brand-new box as not even having a /root or /tmp at all.
        dirs.insert("/tmp", vec![]);
        dirs.insert("/root", vec![]);
        dirs.insert("/etc", vec!["hostname", "passwd", "hosts", "os-release"]);
        dirs.insert("/home", vec!["ubuntu"]);

        Self { files, dirs }
    }

    pub fn read_file(&self, path: &str) -> Option<String> {
        self.files.get(path).map(|content| content.to_string())
    }

    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        self.dirs
            .get(path)
            .map(|entries| entries.iter().map(|entry| entry.to_string()).collect())
    }
}
