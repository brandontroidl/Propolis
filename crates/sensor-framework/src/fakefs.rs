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

use std::collections::{HashMap, HashSet};

use crate::persona;

/// A snapshot of a plausible Linux filesystem, built fresh by `new()` for every session. The
/// baked-in content is static; the one mutation the shell makes is `create_file`, recording an
/// empty file an attacker wrote with a bare redirection, and that lives only for the session.
/// The hostname- and OS-bearing files are sourced from [`crate::persona`] so they cannot
/// contradict the shell's `uname`, the sensor prompts, or the other sensors' banners.
pub struct FakeFs {
    files: HashMap<&'static str, String>,
    dirs: HashMap<&'static str, Vec<&'static str>>,
    /// Files an attacker created this session with a redirection (`>/tmp/.x`). Loaders probe for
    /// a writable directory this way before choosing where to drop a payload, and the probe must
    /// succeed where a real box would let it, so the `&& cd` that follows runs. Session-scoped,
    /// never persisted: the next session sees a clean box again.
    created: HashSet<String>,
}

impl Default for FakeFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeFs {
    pub fn new() -> Self {
        let host = persona::hostname();

        let mut files: HashMap<&'static str, String> = HashMap::new();
        files.insert("/etc/hostname", format!("{host}\n"));
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
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                .to_string(),
        );
        files.insert(
            "/etc/hosts",
            format!(
                "127.0.0.1 localhost\n\
                 127.0.1.1 {host}\n\
                 \n\
                 ::1 localhost ip6-localhost ip6-loopback\n\
                 ff02::1 ip6-allnodes\n\
                 ff02::2 ip6-allrouters\n"
            ),
        );
        files.insert(
            "/etc/os-release",
            format!(
                "NAME=\"{name}\"\n\
                 VERSION=\"{version}\"\n\
                 ID=ubuntu\n\
                 ID_LIKE=debian\n\
                 PRETTY_NAME=\"{pretty}\"\n\
                 VERSION_ID=\"{vid}\"\n",
                name = persona::OS_NAME,
                version = persona::OS_VERSION,
                pretty = persona::OS_PRETTY,
                vid = persona::OS_VERSION_ID,
            ),
        );
        files.insert("/proc/version", format!("{}\n", persona::proc_version()));
        files.insert(
            "/proc/cpuinfo",
            "processor\t: 0\n\
             vendor_id\t: GenuineIntel\n\
             model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n\
             cpu cores\t: 1\n"
                .to_string(),
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
        // The directories a loader probes for somewhere writable (`>/var/run/.x && cd /var/run`,
        // then /mnt, /usr, /dev, /dev/shm, /tmp, /var). Every one exists on a real Ubuntu box,
        // so each probe must succeed here or the chain's `&& cd` never runs and the loader's
        // final marker, which it keys its next stage on, is never printed. Listings are the
        // stock contents, minus anything that would need a deeper model to be consistent.
        dirs.insert(
            "/var",
            vec![
                "backups", "cache", "lib", "local", "lock", "log", "mail", "opt", "run", "spool",
                "tmp",
            ],
        );
        dirs.insert("/var/run", vec![]);
        dirs.insert("/var/tmp", vec![]);
        dirs.insert("/run", vec![]);
        dirs.insert("/mnt", vec![]);
        dirs.insert(
            "/usr",
            vec![
                "bin", "games", "include", "lib", "lib64", "local", "sbin", "share", "src",
            ],
        );
        dirs.insert(
            "/dev",
            vec![
                "null", "zero", "random", "urandom", "tty", "pts", "shm", "stdin", "stdout",
                "stderr",
            ],
        );
        dirs.insert("/dev/shm", vec![]);

        Self {
            files,
            dirs,
            created: HashSet::new(),
        }
    }

    pub fn read_file(&self, path: &str) -> Option<String> {
        if self.created.contains(path) {
            return Some(String::new());
        }
        self.files.get(path).map(|content| content.to_string())
    }

    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        let mut entries: Vec<String> = self
            .dirs
            .get(path)?
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };
        for file in &self.created {
            if let Some(name) = file.strip_prefix(&prefix)
                && !name.contains('/')
            {
                entries.push(name.to_string());
            }
        }
        Some(entries)
    }

    /// Whether `path` is a directory this box presents: a modeled directory, a directory the
    /// root listing advertises, or an ancestor of a modeled file (`/proc/self` exists because
    /// `/proc/self/cmdline` does). `cd` and the write probes below consult this, so the shell
    /// never lets an attacker enter a directory that `ls /` did not show, and never refuses one
    /// it did.
    pub fn is_dir(&self, path: &str) -> bool {
        if path == "/" || self.dirs.contains_key(path) {
            return true;
        }
        let in_root_listing = path
            .strip_prefix('/')
            .filter(|rest| !rest.contains('/'))
            .is_some_and(|name| self.dirs.get("/").is_some_and(|root| root.contains(&name)));
        if in_root_listing {
            return true;
        }
        let prefix = format!("{path}/");
        self.files.keys().any(|f| f.starts_with(&prefix))
    }

    /// Model `> path` with no command: create an empty file if its directory exists, else fail
    /// the way the shell would. Returns the directory that does not exist on failure.
    pub fn create_file(&mut self, path: &str) -> Result<(), String> {
        let parent = match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(i) => path[..i].to_string(),
            None => return Err(String::new()),
        };
        if !self.is_dir(&parent) {
            return Err(parent);
        }
        self.created.insert(path.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_directory_the_loader_probes_exists_and_is_listable() {
        let fs = FakeFs::new();
        for dir in [
            "/var/run", "/mnt", "/usr", "/dev", "/dev/shm", "/tmp", "/var",
        ] {
            assert!(fs.is_dir(dir), "{dir} must exist");
            assert!(fs.list_dir(dir).is_some(), "{dir} must be listable");
        }
    }

    #[test]
    fn root_listing_entries_and_file_ancestors_are_directories_too() {
        let fs = FakeFs::new();
        assert!(fs.is_dir("/"));
        assert!(fs.is_dir("/bin"), "advertised by ls /");
        assert!(fs.is_dir("/proc"), "ancestor of /proc/cpuinfo");
        assert!(!fs.is_dir("/nonexistent"));
        assert!(!fs.is_dir("/etc/hostname"), "a file is not a directory");
    }

    #[test]
    fn create_file_needs_an_existing_directory_and_then_shows_in_the_listing() {
        let mut fs = FakeFs::new();
        assert_eq!(fs.create_file("/tmp/.x"), Ok(()));
        assert!(fs.list_dir("/tmp").unwrap().contains(&".x".to_string()));
        assert_eq!(fs.read_file("/tmp/.x"), Some(String::new()));
        assert_eq!(
            fs.create_file("/nonexistent/.x"),
            Err("/nonexistent".to_string())
        );
        assert!(
            !fs.list_dir("/").unwrap().contains(&".x".to_string()),
            "a file created in /tmp must not appear at /"
        );
    }
}
