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
    /// Created files the attacker has `chmod`ed executable. A loader's writable-directory probe
    /// is `>/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/`: the empty file must then run
    /// (silently, exit 0) or the `&& cd` never happens.
    executable: HashSet<String>,
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
        // One mount table behind every file that exposes it, so `cat /proc/mounts`,
        // `/proc/self/mounts`, `/etc/mtab` (a symlink to the second on Ubuntu), `mountinfo`
        // and the shell's `mount` cannot disagree. `cat /proc/mounts` used to say "No such
        // file", which no Linux box does.
        let mounts = render_mounts();
        files.insert("/proc/mounts", mounts.clone());
        files.insert("/proc/self/mounts", mounts.clone());
        files.insert("/etc/mtab", mounts);
        files.insert("/proc/self/mountinfo", render_mountinfo());
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
        dirs.insert(
            "/etc",
            vec!["hostname", "mtab", "passwd", "hosts", "os-release"],
        );
        dirs.insert("/home", vec!["ubuntu"]);
        // Every mount point in the table is a directory the box presents, so `cd` into one
        // that `cat /proc/mounts` lists never fails.
        dirs.insert("/boot", vec!["efi", "grub"]);
        dirs.insert("/boot/efi", vec!["EFI"]);
        dirs.insert(
            "/sys",
            vec![
                "block",
                "bus",
                "class",
                "dev",
                "devices",
                "firmware",
                "fs",
                "hypervisor",
                "kernel",
                "module",
                "power",
            ],
        );
        dirs.insert("/sys/fs", vec!["bpf", "cgroup", "ext4", "fuse", "pstore"]);
        dirs.insert("/sys/fs/cgroup", vec![]);
        dirs.insert("/sys/fs/bpf", vec![]);
        dirs.insert("/sys/fs/pstore", vec![]);
        dirs.insert("/sys/fs/fuse", vec!["connections"]);
        dirs.insert("/sys/fs/fuse/connections", vec![]);
        dirs.insert(
            "/sys/kernel",
            vec![
                "config",
                "debug",
                "mm",
                "security",
                "slab",
                "tracing",
                "uevent_seqnum",
            ],
        );
        dirs.insert("/sys/kernel/config", vec![]);
        dirs.insert("/sys/kernel/debug", vec![]);
        dirs.insert("/sys/kernel/security", vec![]);
        dirs.insert("/sys/kernel/tracing", vec![]);
        dirs.insert("/dev/pts", vec!["0", "ptmx"]);
        dirs.insert("/dev/hugepages", vec![]);
        dirs.insert("/dev/mqueue", vec![]);
        dirs.insert("/run/lock", vec![]);
        dirs.insert("/run/user", vec!["0"]);
        dirs.insert("/run/user/0", vec![]);
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
        dirs.insert("/run", vec!["lock", "user"]);
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
                "hugepages",
                "mqueue",
                "null",
                "zero",
                "random",
                "urandom",
                "tty",
                "pts",
                "shm",
                "stdin",
                "stdout",
                "stderr",
            ],
        );
        dirs.insert("/dev/shm", vec![]);

        Self {
            files,
            dirs,
            created: HashSet::new(),
            executable: HashSet::new(),
        }
    }

    /// Mark a file the attacker created this session executable (`chmod +x` / `chmod 777`).
    /// Returns false when `path` is not such a file; the baked-in files keep their modes.
    pub fn mark_executable(&mut self, path: &str) -> bool {
        if !self.created.contains(path) {
            return false;
        }
        self.executable.insert(path.to_string());
        true
    }

    /// Whether running `path` as a command would start: only a created file after `chmod`.
    pub fn is_executable(&self, path: &str) -> bool {
        self.executable.contains(path)
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

/// The mounted filesystems of a stock Ubuntu 22.04 cloud image on one virtual disk: `(source,
/// mount point, type, options)` in mount order. Every mount point exists in the directory
/// model above. Rendered into `/proc/mounts`, `/proc/self/mountinfo` and the `mount` command.
pub const MOUNT_TABLE: [(&str, &str, &str, &str); 20] = [
    ("sysfs", "/sys", "sysfs", "rw,nosuid,nodev,noexec,relatime"),
    ("proc", "/proc", "proc", "rw,nosuid,nodev,noexec,relatime"),
    (
        "udev",
        "/dev",
        "devtmpfs",
        "rw,nosuid,relatime,size=1968376k,nr_inodes=492094,mode=755,inode64",
    ),
    (
        "devpts",
        "/dev/pts",
        "devpts",
        "rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000",
    ),
    (
        "tmpfs",
        "/run",
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime,size=402244k,mode=755,inode64",
    ),
    (
        "/dev/sda1",
        "/",
        "ext4",
        "rw,relatime,discard,errors=remount-ro",
    ),
    (
        "securityfs",
        "/sys/kernel/security",
        "securityfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    ("tmpfs", "/dev/shm", "tmpfs", "rw,nosuid,nodev,inode64"),
    (
        "tmpfs",
        "/run/lock",
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime,size=5120k,inode64",
    ),
    (
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        "rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot",
    ),
    (
        "pstore",
        "/sys/fs/pstore",
        "pstore",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "bpf",
        "/sys/fs/bpf",
        "bpf",
        "rw,nosuid,nodev,noexec,relatime,mode=700",
    ),
    (
        "hugetlbfs",
        "/dev/hugepages",
        "hugetlbfs",
        "rw,relatime,pagesize=2M",
    ),
    (
        "mqueue",
        "/dev/mqueue",
        "mqueue",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "debugfs",
        "/sys/kernel/debug",
        "debugfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "tracefs",
        "/sys/kernel/tracing",
        "tracefs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "fusectl",
        "/sys/fs/fuse/connections",
        "fusectl",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "configfs",
        "/sys/kernel/config",
        "configfs",
        "rw,nosuid,nodev,noexec,relatime",
    ),
    (
        "/dev/sda15",
        "/boot/efi",
        "vfat",
        "rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro",
    ),
    (
        "tmpfs",
        "/run/user/0",
        "tmpfs",
        "rw,nosuid,nodev,relatime,size=402240k,nr_inodes=100560,mode=700,inode64",
    ),
];

/// `/proc/mounts` format: `source mountpoint type options 0 0`.
fn render_mounts() -> String {
    let mut out = String::new();
    for (source, point, fstype, opts) in MOUNT_TABLE {
        out.push_str(&format!("{source} {point} {fstype} {opts} 0 0\n"));
    }
    out
}

/// `/proc/self/mountinfo` format: `id parent major:minor root mountpoint mount-opts - type
/// source super-opts`. Ids are sequential from the table; the per-mount options are the flags
/// (`rw,nosuid,...`) and the super options the rest, as the kernel splits them.
fn render_mountinfo() -> String {
    let root_pos = MOUNT_TABLE.iter().position(|m| m.1 == "/").unwrap_or(0);
    let mut out = String::new();
    for (i, (source, point, fstype, opts)) in MOUNT_TABLE.iter().enumerate() {
        let id = 20 + i;
        let parent = if *point == "/" { 1 } else { 20 + root_pos };
        let (mount_opts, super_opts): (Vec<&str>, Vec<&str>) = opts.split(',').partition(|o| {
            matches!(
                *o,
                "rw" | "ro" | "nosuid" | "nodev" | "noexec" | "relatime" | "noatime"
            )
        });
        let super_opts = if super_opts.is_empty() {
            "rw".to_string()
        } else {
            format!("rw,{}", super_opts.join(","))
        };
        out.push_str(&format!(
            "{id} {parent} 0:{} / {point} {} - {fstype} {source} {super_opts}\n",
            i + 21,
            mount_opts.join(",")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file that exposes the mount table agrees, and every mount point it names is a
    /// directory the shell will `cd` into: a table naming a path `ls` denies is the same
    /// contradiction as the missing file was.
    #[test]
    fn mount_table_is_exposed_consistently_and_every_mount_point_exists() {
        let fs = FakeFs::new();
        let mounts = fs.read_file("/proc/mounts").expect("/proc/mounts exists");
        assert_eq!(fs.read_file("/proc/self/mounts").as_deref(), Some(&*mounts));
        assert_eq!(fs.read_file("/etc/mtab").as_deref(), Some(&*mounts));
        assert!(mounts.contains("/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0\n"));
        assert_eq!(mounts.lines().count(), MOUNT_TABLE.len());
        let info = fs.read_file("/proc/self/mountinfo").unwrap();
        assert_eq!(info.lines().count(), MOUNT_TABLE.len());
        assert!(info.contains(" / / rw,relatime - ext4 /dev/sda1 rw,discard,errors=remount-ro\n"));
        for (_, point, _, _) in MOUNT_TABLE {
            assert!(fs.is_dir(point), "{point} is mounted but not a directory");
        }
        assert!(fs.list_dir("/etc").unwrap().contains(&"mtab".to_string()));
    }

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
