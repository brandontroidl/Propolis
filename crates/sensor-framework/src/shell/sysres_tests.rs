//! `free`, `df` and `du` through `handle_input`. The figures are canned and layouts are procps,
//! coreutils and toybox as remembered, not captured, so the cases check what must hold regardless:
//! `free` and `/proc/meminfo` are one source, a `df` row's columns agree with each other and with
//! the mount table, and a `du` size is the sum of the nodes under it. The exact-layout cases pin
//! the wording the module claims.

use std::collections::HashMap;

use super::sysres::{DU_DEPTH_MAX, DU_VISIT_MAX};
use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
        session_id: None,
    }
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

/// The `Name:  value kB` lines of `/proc/meminfo` by name.
fn meminfo(sh: &mut FakeShell) -> HashMap<String, u64> {
    out(sh, "cat /proc/meminfo")
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let value = rest.split_whitespace().next()?.parse().ok()?;
            Some((name.to_string(), value))
        })
        .collect()
}

/// The words of each line of a table, header included.
fn words(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|line| line.split_whitespace().map(str::to_string).collect())
        .collect()
}

/// The numbers of the row of a `free` table labelled `label`.
fn row(text: &str, label: &str) -> Vec<u64> {
    text.lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} row in {text:?}"))
        .split_whitespace()
        .skip(1)
        .map(|word| word.parse().unwrap())
        .collect()
}

// ----------------------------------------------------------------------------------- /proc/meminfo

#[test]
fn meminfo_is_in_the_kernels_column_layout_on_both_personas() {
    for (label, mut sh) in [("ubuntu", shell()), ("phone", phone())] {
        let text = out(&mut sh, "cat /proc/meminfo");
        assert!(text.starts_with("MemTotal:  "), "{label}");
        for line in text.lines() {
            let (name, rest) = line.split_once(':').unwrap();
            if name == "HardwareCorrupted" {
                // The one name longer than the column has a format of its own.
                assert_eq!(line, "HardwareCorrupted:     0 kB");
                continue;
            }
            // The name and colon fill sixteen columns, the value is right-aligned in eight.
            assert_eq!(&line[..16], format!("{:<16}", format!("{name}:")), "{line}");
            let tail = &line[16..];
            assert!(tail.len() >= 8, "{label}: {line:?}");
            assert!(
                tail.ends_with(" kB") || name.starts_with("HugePages_"),
                "{label}: {line:?}"
            );
            assert!(
                rest.split_whitespace()
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .is_ok()
            );
        }
    }
    let mut sh = shell();
    assert!(out(&mut sh, "cat /proc/meminfo").contains("MemTotal:        4017836 kB\n"));
    assert!(out(&mut sh, "cat /proc/meminfo").contains("HugePages_Total:       0\n"));
    assert!(out(&mut phone(), "cat /proc/meminfo").contains("MemTotal:        1875408 kB\n"));
}

#[test]
fn ubuntu_meminfo_obeys_the_kernels_identities() {
    let mut sh = shell();
    let m = meminfo(&mut sh);
    let get = |name: &str| m[name];
    assert_eq!(
        get("Active(anon)") + get("Inactive(anon)"),
        get("AnonPages")
    );
    assert_eq!(get("Active(anon)") + get("Active(file)"), get("Active"));
    assert_eq!(
        get("Inactive(anon)") + get("Inactive(file)"),
        get("Inactive")
    );
    assert_eq!(
        get("Active(file)") + get("Inactive(file)"),
        get("Buffers") + get("Cached") - get("Shmem")
    );
    assert_eq!(get("SReclaimable") + get("SUnreclaim"), get("Slab"));
    assert!(get("KReclaimable") >= get("SReclaimable"));
    assert!(get("Mlocked") <= get("Unevictable"));
    assert_eq!(
        get("DirectMap4k") + get("DirectMap2M") + get("DirectMap1G"),
        4_194_304
    );
    // Free memory, cache and what is in use make up the whole, and the host is not short of memory.
    let cache = get("Buffers") + get("Cached") + get("SReclaimable");
    assert!(get("MemFree") + cache < get("MemTotal"));
    assert!(get("MemAvailable") >= get("MemFree"));
    assert!(get("MemAvailable") <= get("MemTotal"));
    assert_eq!(get("SwapTotal"), 0);
    assert_eq!(get("SwapFree"), 0);
    assert_eq!(get("CommitLimit"), get("MemTotal") / 2);
}

#[test]
fn phone_meminfo_obeys_the_kernels_identities_and_has_no_memavailable() {
    let mut sh = phone();
    let m = meminfo(&mut sh);
    let get = |name: &str| m[name];
    assert_eq!(
        get("Active(anon)") + get("Inactive(anon)"),
        get("AnonPages")
    );
    assert_eq!(
        get("Active(file)") + get("Inactive(file)"),
        get("Buffers") + get("Cached")
    );
    assert_eq!(get("Active(anon)") + get("Active(file)"), get("Active"));
    assert_eq!(get("SReclaimable") + get("SUnreclaim"), get("Slab"));
    assert_eq!(get("HighTotal") + get("LowTotal"), get("MemTotal"));
    assert_eq!(get("HighFree") + get("LowFree"), get("MemFree"));
    assert_eq!(get("CommitLimit"), get("MemTotal") / 2);
    // MemAvailable arrived in kernel 3.14 and this phone runs 3.4.
    assert!(!m.contains_key("MemAvailable"));
    assert!(get("VmallocUsed") + get("VmallocChunk") <= get("VmallocTotal"));
}

#[test]
fn the_ubuntu_memory_agrees_with_what_top_and_the_mount_table_already_say() {
    let mut sh = shell();
    let total = meminfo(&mut sh)["MemTotal"];
    // `top` prints MiB to one decimal: 4017836 KiB is 3923.7.
    let top = out(&mut sh, "top -bn1");
    let line = top.lines().find(|l| l.starts_with("MiB Mem :")).unwrap();
    let tenths = (total * 10 + 512) / 1024;
    assert!(
        line.contains(&format!("{}.{} total", tenths / 10, tenths % 10)),
        "{line}"
    );
    // The devtmpfs holds about half of memory and /run a tenth.
    let mounts = out(&mut sh, "cat /proc/mounts");
    let size_of = |point: &str| -> u64 {
        let line = mounts
            .lines()
            .find(|l| l.contains(&format!(" {point} ")))
            .unwrap();
        let opt = line.split("size=").nth(1).unwrap();
        opt.split('k').next().unwrap().parse().unwrap()
    };
    assert!((size_of("/dev") * 2).abs_diff(total) < total / 25);
    assert!((size_of("/run") * 10).abs_diff(total) < total / 25);
}

// ----------------------------------------------------------------------------------------- free

#[test]
fn free_total_is_the_meminfo_total_and_the_units_scale_it() {
    let mut sh = shell();
    let total = meminfo(&mut sh)["MemTotal"];
    assert_eq!(row(&out(&mut sh, "free"), "Mem:")[0], total);
    assert_eq!(row(&out(&mut sh, "free -k"), "Mem:")[0], total);
    assert_eq!(row(&out(&mut sh, "free --kibi"), "Mem:")[0], total);
    assert_eq!(row(&out(&mut sh, "free -b"), "Mem:")[0], total * 1024);
    assert_eq!(row(&out(&mut sh, "free -m"), "Mem:")[0], total / 1024);
    assert_eq!(row(&out(&mut sh, "free --mebi"), "Mem:")[0], total / 1024);
    assert_eq!(row(&out(&mut sh, "free -g"), "Mem:")[0], total / 1_048_576);
    assert_eq!(row(&out(&mut sh, "free -g"), "Mem:")[0], 3);
    assert_eq!(row(&out(&mut sh, "free --tebi"), "Mem:")[0], 0);
    // The last unit named wins, as with the real tool.
    assert_eq!(row(&out(&mut sh, "free -b -m"), "Mem:")[0], total / 1024);
    assert_eq!(row(&out(&mut sh, "free -mk"), "Mem:")[0], total);
}

#[test]
fn free_columns_are_computed_from_meminfo_the_way_procps_does() {
    let mut sh = shell();
    let m = meminfo(&mut sh);
    let cache = m["Buffers"] + m["Cached"] + m["SReclaimable"];
    let mem = row(&out(&mut sh, "free"), "Mem:");
    // total used free shared buff/cache available
    assert_eq!(mem[1], m["MemTotal"] - m["MemFree"] - cache);
    assert_eq!(mem[2], m["MemFree"]);
    assert_eq!(mem[3], m["Shmem"]);
    assert_eq!(mem[4], cache);
    assert_eq!(mem[5], m["MemAvailable"]);
    assert_eq!(row(&out(&mut sh, "free"), "Swap:"), [0, 0, 0]);
}

#[test]
fn free_default_table_is_the_procps_layout() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "free"),
        "               total        used        free      shared  buff/cache   available\n\
         Mem:         4017836      330212     2405196        1596     1282428     3452180\n\
         Swap:              0           0           0\n"
    );
    assert_eq!(
        out(&mut sh, "free -m"),
        "               total        used        free      shared  buff/cache   available\n\
         Mem:            3923         322        2348           1        1252        3371\n\
         Swap:              0           0           0\n"
    );
}

#[test]
fn free_t_adds_a_total_row_and_w_splits_buffers_from_cache() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "free -t"),
        "               total        used        free      shared  buff/cache   available\n\
         Mem:         4017836      330212     2405196        1596     1282428     3452180\n\
         Swap:              0           0           0\n\
         Total:       4017836      330212     2405196\n"
    );
    assert_eq!(
        out(&mut sh, "free -w"),
        "               total        used        free      shared     buffers       cache   available\n\
         Mem:         4017836      330212     2405196        1596      163204     1119224     3452180\n\
         Swap:              0           0           0\n"
    );
    assert_eq!(out(&mut sh, "free -tw"), {
        let mut text = out(&mut sh, "free -w");
        text.push_str("Total:       4017836      330212     2405196\n");
        text
    });
}

#[test]
fn free_human_scales_with_binary_suffixes() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "free -h"),
        "               total        used        free      shared  buff/cache   available\n\
         Mem:           3.8Gi       322Mi       2.3Gi       1.6Mi       1.2Gi       3.3Gi\n\
         Swap:             0B          0B          0B\n"
    );
    assert_eq!(out(&mut sh, "free --human"), out(&mut sh, "free -h"));
}

#[test]
fn free_follows_an_edited_meminfo_because_it_reads_that_file() {
    let mut sh = shell();
    out(&mut sh, "echo 'MemTotal:        8192 kB' > /proc/meminfo");
    out(&mut sh, "echo 'MemFree:         1024 kB' >> /proc/meminfo");
    assert_eq!(meminfo(&mut sh)["MemTotal"], 8192);
    let mem = row(&out(&mut sh, "free"), "Mem:");
    assert_eq!((mem[0], mem[1], mem[2]), (8192, 7168, 1024));
    out(&mut sh, "rm /proc/meminfo");
    let (stdout, stderr, status) = answer(&mut sh, "free");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(
        stderr.starts_with("free: Error: /proc must be mounted"),
        "{stderr}"
    );
}

#[test]
fn free_refuses_an_option_it_lacks_and_ignores_what_it_does_not_model() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "free -x");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(stderr.starts_with("free: invalid option -- 'x'\n\nUsage:\n free [options]\n"));
    assert!(stderr.ends_with("For more details see free(1).\n"));
    let (_, stderr, status) = answer(&mut sh, "free --nope");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("free: unrecognized option '--nope'\n"));
    let (_, stderr, status) = answer(&mut sh, "free -s");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("free: option requires an argument -- 's'\n"));
    // Repeating, SI units and the lohi view are not modeled: nothing, not a made-up table.
    for line in [
        "free -s 1",
        "free -c 2",
        "free -l",
        "free --si",
        "free --mega",
        "free --help",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    // A long option may be abbreviated to a unique prefix, and operands are ignored.
    assert_eq!(out(&mut sh, "free --mebi extra"), out(&mut sh, "free -m"));
    assert_eq!(answer(&mut sh, "free --mebib").2, 1);
}

#[test]
fn phone_free_is_the_toybox_layout_in_bytes() {
    let mut sh = phone();
    let m = meminfo(&mut sh);
    let text = out(&mut sh, "free");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert_eq!(
        lines[0],
        "            total       used       free     shared    buffers"
    );
    // Every number column ends where its header does.
    for line in &lines[1..] {
        assert!(line.len() <= 61, "{line}");
    }
    assert_eq!(lines[1].len(), 61);
    assert_eq!(&lines[1][..7], "Mem:   ");
    assert_eq!(lines[2].len(), 39);
    assert!(lines[2].starts_with("-/+ buffers/cache:"));
    assert!(lines[3].starts_with("Swap:"));
    let mem = row(&text, "Mem:");
    assert_eq!(mem[0], m["MemTotal"] * 1024);
    assert_eq!(mem[1], (m["MemTotal"] - m["MemFree"]) * 1024);
    assert_eq!(mem[2], m["MemFree"] * 1024);
    assert_eq!(mem[3], m["Shmem"] * 1024);
    assert_eq!(mem[4], m["Buffers"] * 1024);
    assert_eq!(
        out(&mut sh, "free -k"),
        "            total       used       free     shared    buffers\n\
         Mem:      1875408    1762976     112432      12340       4724\n\
         -/+ buffers/cache:   1145408     730000\n\
         Swap:           0          0          0\n"
    );
}

#[test]
fn phone_free_scales_and_refuses_what_toybox_lacks() {
    let mut sh = phone();
    let m = meminfo(&mut sh);
    assert_eq!(
        row(&out(&mut sh, "free -m"), "Mem:")[0],
        m["MemTotal"] / 1024
    );
    assert_eq!(row(&out(&mut sh, "free -g"), "Mem:")[0], 1);
    assert_eq!(row(&out(&mut sh, "free -t"), "Mem:")[0], 0);
    assert_eq!(out(&mut sh, "toybox free -k"), out(&mut sh, "free -k"));
    // The phone's free has no human or wide forms and no long options.
    for line in ["free -h", "free -w", "free --human"] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!((stdout.as_str(), status), ("", 1), "{line}");
        assert!(
            stderr.starts_with("free: Unknown option "),
            "{line}: {stderr}"
        );
    }
}

// ------------------------------------------------------------------------------------------ df

#[test]
fn df_root_row_has_coherent_columns() {
    let mut sh = shell();
    let table = words(&out(&mut sh, "df"));
    assert_eq!(
        table[0],
        [
            "Filesystem",
            "1K-blocks",
            "Used",
            "Available",
            "Use%",
            "Mounted",
            "on"
        ]
    );
    let root = table.iter().find(|r| r.last().unwrap() == "/").unwrap();
    assert_eq!(root[0], "/dev/sda1");
    let (size, used, avail): (u64, u64, u64) = (
        root[1].parse().unwrap(),
        root[2].parse().unwrap(),
        root[3].parse().unwrap(),
    );
    // ext4 keeps a reserve, so the two never reach the size, but never fall far short of it.
    assert!(used + avail < size && (used + avail) * 10 > size * 9);
    let pct = (used * 100).div_ceil(used + avail);
    assert_eq!(root[4], format!("{pct}%"));
    assert_eq!(pct, 26);
}

#[test]
fn df_exact_layout_for_root_in_each_scale() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "df /"),
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
         /dev/sda1       20134592 4908044  14219818  26% /\n"
    );
    assert_eq!(
        out(&mut sh, "df -h /"),
        "Filesystem      Size  Used Avail Use% Mounted on\n\
         /dev/sda1        20G  4.7G   14G  26% /\n"
    );
    assert_eq!(
        out(&mut sh, "df --human-readable /"),
        out(&mut sh, "df -h /")
    );
    assert_eq!(
        out(&mut sh, "df -m /"),
        "Filesystem     1M-blocks  Used Available Use% Mounted on\n\
         /dev/sda1          19663  4794     13887  26% /\n"
    );
    assert_eq!(out(&mut sh, "df -k /"), out(&mut sh, "df /"));
    // `-H` counts in powers of 1000, so the same blocks read larger.
    assert_eq!(
        out(&mut sh, "df -H /"),
        "Filesystem      Size  Used Avail Use% Mounted on\n\
         /dev/sda1        21G  5.1G   15G  26% /\n"
    );
    assert_eq!(
        out(&mut sh, "df -T /"),
        "Filesystem     Type 1K-blocks    Used Available Use% Mounted on\n\
         /dev/sda1      ext4  20134592 4908044  14219818  26% /\n"
    );
    assert_eq!(
        out(&mut sh, "df -P /"),
        "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
         /dev/sda1         20134592 4908044  14219818      26% /\n"
    );
}

#[test]
fn df_lists_the_filesystems_with_blocks_and_all_adds_the_rest_as_dashes() {
    let mut sh = shell();
    let default = out(&mut sh, "df");
    let mounted: Vec<String> = default
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().last().unwrap().to_string())
        .collect();
    assert_eq!(
        mounted,
        [
            "/dev",
            "/run",
            "/",
            "/dev/shm",
            "/run/lock",
            "/boot/efi",
            "/run/user/0"
        ]
    );
    let all = out(&mut sh, "df -a");
    assert_eq!(all.lines().count(), 21);
    let proc_row = all.lines().find(|l| l.ends_with(" /proc")).unwrap();
    assert_eq!(words(proc_row)[0], ["proc", "0", "0", "0", "-", "/proc"]);
    // Every row of the default listing is also in `-a`, in the same order.
    let in_all: Vec<&str> = all.lines().filter(|l| default.contains(*l)).collect();
    assert_eq!(in_all, default.lines().collect::<Vec<_>>());
    assert_eq!(out(&mut sh, "df --all"), all);
}

#[test]
fn df_path_shows_the_mount_that_holds_it() {
    let mut sh = shell();
    let mount_of = |sh: &mut FakeShell, path: &str| -> Vec<String> {
        let text = out(sh, &format!("df {path}"));
        assert_eq!(text.lines().count(), 2, "{path}: {text}");
        words(&text)[1].clone()
    };
    assert_eq!(mount_of(&mut sh, "/").last().unwrap(), "/");
    for path in ["/tmp", "/etc/passwd", "/home", "/usr/bin/ls", "/bin/ls"] {
        assert_eq!(mount_of(&mut sh, path)[0], "/dev/sda1", "{path}");
    }
    assert_eq!(mount_of(&mut sh, "/run/lock")[0], "tmpfs");
    assert_eq!(mount_of(&mut sh, "/run/lock").last().unwrap(), "/run/lock");
    assert_eq!(mount_of(&mut sh, "/run/user").last().unwrap(), "/run");
    assert_eq!(mount_of(&mut sh, "/boot/efi").last().unwrap(), "/boot/efi");
    assert_eq!(mount_of(&mut sh, "/dev/null").last().unwrap(), "/dev");
    // A relative path resolves against the working directory.
    out(&mut sh, "cd /boot/efi");
    assert_eq!(mount_of(&mut sh, ".").last().unwrap(), "/boot/efi");
    // A pseudo filesystem named on the line is shown, with no blocks and no use.
    assert_eq!(
        mount_of(&mut sh, "/proc/version"),
        ["proc", "0", "0", "0", "-", "/proc"]
    );
    // A device operand names the filesystem on it.
    assert_eq!(mount_of(&mut sh, "/dev/sda15").last().unwrap(), "/boot/efi");
}

#[test]
fn df_of_a_missing_path_is_the_coreutils_error_with_status_one() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "df /nonexistent"),
        (
            "".into(),
            "df: /nonexistent: No such file or directory\n".into(),
            1
        )
    );
    // The paths that exist are still shown, and the status is the failure's.
    let (stdout, stderr, status) = answer(&mut sh, "df / /nonexistent");
    assert_eq!(status, 1);
    assert_eq!(stdout.lines().count(), 2);
    assert_eq!(stderr, "df: /nonexistent: No such file or directory\n");
    assert_eq!(answer(&mut sh, "df ''").2, 1);
}

#[test]
fn df_unknown_options_get_their_own_error_and_unmodeled_ones_print_nothing() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "df -z"),
        (
            "".into(),
            "df: invalid option -- 'z'\nTry 'df --help' for more information.\n".into(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "df --bogus").2, 1);
    for line in [
        "df -i",
        "df -t ext4",
        "df -x tmpfs",
        "df -B1M",
        "df --total",
        "df --output=source",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    // Options that change nothing here leave the listing as it was.
    assert_eq!(out(&mut sh, "df -l --sync"), out(&mut sh, "df"));
}

#[test]
fn df_tmpfs_sizes_match_the_mount_options_and_shm_is_half_of_memory() {
    let mut sh = shell();
    let mounts = out(&mut sh, "cat /proc/mounts");
    let table = words(&out(&mut sh, "df"));
    let mut checked = 0;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(size) = fields[3].split(',').find_map(|o| o.strip_prefix("size=")) else {
            continue;
        };
        let want: u64 = size.trim_end_matches('k').parse().unwrap();
        let row = table
            .iter()
            .find(|r| r.last().unwrap() == fields[1])
            .unwrap();
        assert_eq!(row[1], want.to_string(), "{}", fields[1]);
        checked += 1;
    }
    assert_eq!(checked, 4);
    let total = meminfo(&mut sh)["MemTotal"];
    let shm = table
        .iter()
        .find(|r| r.last().unwrap() == "/dev/shm")
        .unwrap();
    assert!(shm[1].parse::<u64>().unwrap().abs_diff(total / 2) <= 4);
}

#[test]
fn every_real_filesystem_is_coherent_on_both_personas() {
    for (label, mut sh) in [("ubuntu", shell()), ("phone", phone())] {
        let text = out(&mut sh, "df");
        for row in words(&text).iter().skip(1) {
            let [_, size, used, avail, pct, _] = row.as_slice() else {
                panic!("{label}: not a six-column row: {row:?}");
            };
            let (size, used, avail): (u64, u64, u64) = (
                size.parse().unwrap(),
                used.parse().unwrap(),
                avail.parse().unwrap(),
            );
            assert!(used + avail <= size, "{label}: {row:?}");
            assert!((used + avail) * 10 >= size * 9, "{label}: {row:?}");
            assert_eq!(
                *pct,
                format!("{}%", (used * 100).div_ceil(used + avail)),
                "{label}"
            );
        }
    }
}

#[test]
fn phone_df_lists_its_real_partitions_with_long_sources_widening_the_column() {
    let mut sh = phone();
    let text = out(&mut sh, "df");
    let mounted: Vec<String> = text
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().last().unwrap().to_string())
        .collect();
    assert_eq!(
        mounted,
        [
            "/",
            "/dev",
            "/system",
            "/data",
            "/cache",
            "/persist",
            "/storage/emulated",
            "/sdcard"
        ]
    );
    let data = text.lines().find(|l| l.ends_with(" /data")).unwrap();
    assert!(data.starts_with("/dev/block/platform/msm_sdcc.1/by-name/userdata "));
    assert_eq!(
        words(data)[0],
        [
            "/dev/block/platform/msm_sdcc.1/by-name/userdata",
            "12251376",
            "3481544",
            "8769832",
            "29%",
            "/data"
        ]
    );
    // The source column widens to the longest name, so every row's last column starts together,
    // after the 47-character source and the numbers.
    let mut starts = vec![text.lines().next().unwrap().len() - "Mounted on".len()];
    starts.extend(
        text.lines()
            .skip(1)
            .map(|l| l.len() - l.split_whitespace().last().unwrap().len()),
    );
    assert!(
        starts.windows(2).all(|pair| pair[0] == pair[1]),
        "{starts:?}"
    );
    assert!(starts[0] > 47, "{starts:?}");
    assert!(!text.contains("proc "), "{text}");
    // The FUSE views of the emulated card report /data's own numbers.
    let emulated = text.lines().find(|l| l.ends_with(" /sdcard")).unwrap();
    assert_eq!(&words(emulated)[0][1..5], &words(data)[0][1..5]);
    assert_eq!(out(&mut sh, "toybox df"), text);
    assert_eq!(out(&mut sh, "df -h /system").lines().count(), 2);
}

#[test]
fn phone_df_path_human_and_option_handling() {
    let mut sh = phone();
    assert_eq!(
        words(&out(&mut sh, "df /storage/emulated/0"))[1]
            .last()
            .unwrap(),
        "/storage/emulated"
    );
    assert_eq!(
        words(&out(&mut sh, "df /system/bin/sh"))[1].last().unwrap(),
        "/system"
    );
    assert_eq!(
        words(&out(&mut sh, "df /data/local/tmp"))[1]
            .last()
            .unwrap(),
        "/data"
    );
    let human = out(&mut sh, "df -h /data");
    assert!(human.starts_with("Filesystem"), "{human}");
    assert!(human.contains("12G"), "{human}");
    // Coreutils-only flags are not toybox's.
    for line in ["df -T", "df -m", "df --all"] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!((stdout.as_str(), status), ("", 1), "{line}");
        assert!(
            stderr.starts_with("df: Unknown option "),
            "{line}: {stderr}"
        );
    }
    assert_eq!(
        answer(&mut sh, "df /nope"),
        (
            "".into(),
            "df: /nope: No such file or directory\n".into(),
            1
        )
    );
}

// ------------------------------------------------------------------------------------------ du

/// `/tmp/d` holds `a` (5 bytes), `big` (5000), `sub/x` (2) and the empty `sub/deep`.
fn tree(sh: &mut FakeShell) {
    out(sh, "mkdir -p /tmp/d/sub/deep");
    out(sh, "echo hello > /tmp/d/a");
    out(sh, "echo y > /tmp/d/sub/x");
    sh.fs.write_file("/tmp/d/big", &[b'x'; 5000]).unwrap();
}

#[test]
fn du_sums_the_blocks_of_the_nodes_under_a_path() {
    let mut sh = shell();
    tree(&mut sh);
    // deep 4, sub = 4 + x 4 + deep 4, d = 4 + a 4 + big 8 (5000 bytes is two blocks) + sub 12.
    assert_eq!(
        answer(&mut sh, "du /tmp/d"),
        (
            "4\t/tmp/d/sub/deep\n12\t/tmp/d/sub\n28\t/tmp/d\n".into(),
            "".into(),
            0
        )
    );
    assert_eq!(out(&mut sh, "du -s /tmp/d"), "28\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du --summarize /tmp/d"), "28\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -sk /tmp/d"), "28\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -sm /tmp/d"), "1\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -sh /tmp/d"), "28K\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -s /tmp/d/big"), "8\t/tmp/d/big\n");
    // An empty file holds no blocks.
    out(&mut sh, "touch /tmp/empty");
    assert_eq!(out(&mut sh, "du /tmp/empty"), "0\t/tmp/empty\n");
    // With no operand the working directory is measured and named `.`.
    out(&mut sh, "cd /tmp/d/sub");
    assert_eq!(out(&mut sh, "du"), "4\t./deep\n12\t.\n");
}

#[test]
fn du_a_names_the_files_and_depth_limits_what_is_printed() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        out(&mut sh, "du -a /tmp/d"),
        "4\t/tmp/d/a\n8\t/tmp/d/big\n4\t/tmp/d/sub/deep\n4\t/tmp/d/sub/x\n12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "du -d 1 /tmp/d"),
        "12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "du --max-depth=1 /tmp/d"),
        "12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "du --max-depth 1 /tmp/d"),
        "12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "du -d1 /tmp/d"),
        "12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    assert_eq!(out(&mut sh, "du -d 0 /tmp/d"), "28\t/tmp/d\n");
    assert_eq!(
        out(&mut sh, "du -a -d 1 /tmp/d"),
        "4\t/tmp/d/a\n8\t/tmp/d/big\n12\t/tmp/d/sub\n28\t/tmp/d\n"
    );
    // A file named on the line is printed whether or not `-a` is given.
    assert_eq!(out(&mut sh, "du /tmp/d/a"), "4\t/tmp/d/a\n");
    let (_, stderr, status) = answer(&mut sh, "du -d x /tmp/d");
    assert_eq!(
        (stderr.as_str(), status),
        ("du: invalid maximum depth 'x'\n", 1)
    );
}

#[test]
fn du_c_adds_a_grand_total_and_s_with_a_deeper_depth_is_refused() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        out(&mut sh, "du -sc /tmp/d /tmp/d/sub"),
        "28\t/tmp/d\n12\t/tmp/d/sub\n40\ttotal\n"
    );
    assert_eq!(out(&mut sh, "du -c -d 0 /tmp/d"), "28\t/tmp/d\n28\ttotal\n");
    let (_, stderr, status) = answer(&mut sh, "du -sa /tmp/d");
    assert_eq!(status, 1);
    assert_eq!(
        stderr,
        "du: cannot both summarize and show all entries\nTry 'du --help' for more information.\n"
    );
    let (_, stderr, status) = answer(&mut sh, "du -s -d 2 /tmp/d");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("du: warning: summarizing conflicts with --max-depth=2\n"));
    assert_eq!(out(&mut sh, "du -s -d 0 /tmp/d"), "28\t/tmp/d\n");
}

#[test]
fn du_apparent_sizes_are_lengths_and_a_directory_is_one_block() {
    let mut sh = shell();
    tree(&mut sh);
    // dir 4096 + sub (4096 + x 2 + deep 4096) + a 6 (`hello\n`) + big 5000 = 17296.
    assert_eq!(out(&mut sh, "du -sb /tmp/d"), "17296\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -s --apparent-size /tmp/d"), "17\t/tmp/d\n");
    assert_eq!(
        out(&mut sh, "du -sh --apparent-size /tmp/d"),
        "17K\t/tmp/d\n"
    );
    assert_eq!(out(&mut sh, "du -b /tmp/d/a"), "6\t/tmp/d/a\n");
}

#[test]
fn du_of_a_missing_path_is_the_coreutils_error_with_status_one() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        answer(&mut sh, "du /nonexistent"),
        (
            "".into(),
            "du: cannot access '/nonexistent': No such file or directory\n".into(),
            1
        )
    );
    // The paths that exist are still measured, and the status is the failure's.
    let (stdout, stderr, status) = answer(&mut sh, "du -s /tmp/d /nope");
    assert_eq!((stdout.as_str(), status), ("28\t/tmp/d\n", 1));
    assert_eq!(
        stderr,
        "du: cannot access '/nope': No such file or directory\n"
    );
    assert_eq!(answer(&mut sh, "du ''").2, 1);
    // A path removed in the session stops being measured.
    out(&mut sh, "rm -r /tmp/d");
    assert_eq!(answer(&mut sh, "du /tmp/d").2, 1);
}

#[test]
fn du_does_not_follow_a_command_line_link_unless_it_ends_in_a_slash() {
    let mut sh = shell();
    tree(&mut sh);
    out(&mut sh, "ln -s /tmp/d /tmp/l");
    assert_eq!(out(&mut sh, "du /tmp/l"), "0\t/tmp/l\n");
    assert_eq!(out(&mut sh, "du -s /tmp/l/"), "28\t/tmp/l/\n");
    assert_eq!(
        out(&mut sh, "du /tmp/l/"),
        "4\t/tmp/l/sub/deep\n12\t/tmp/l/sub\n28\t/tmp/l/\n"
    );
    // The usrmerge link `/bin` is the same: a link by itself, a directory with the slash.
    assert_eq!(out(&mut sh, "du /bin"), "0\t/bin\n");
    assert_ne!(out(&mut sh, "du -s /bin/"), "0\t/bin/\n");
    // A link inside the tree is a link, with no blocks and not descended.
    out(&mut sh, "ln -s a /tmp/d/lnk");
    assert!(out(&mut sh, "du -a /tmp/d").contains("0\t/tmp/d/lnk\n"));
}

#[test]
fn du_of_a_modeled_directory_is_a_bounded_number() {
    let mut sh = shell();
    let text = out(&mut sh, "du -s /etc");
    let (size, name) = text.trim_end().split_once('\t').unwrap();
    assert_eq!(name, "/etc");
    let kib: u64 = size.parse().unwrap();
    // Six small files at a block each, a link, and the alternatives directory (a block, its one
    // entry a link), under the directory's own block.
    assert_eq!(kib, 32);
    assert_eq!(out(&mut sh, "du -s /etc"), text, "repeatable");
    // The sum is of what `ls` shows: the directory's block plus each listed name measured alone.
    let listed = out(&mut sh, "ls /etc");
    let parts: u64 = listed
        .split_whitespace()
        .map(|name| {
            let line = out(&mut sh, &format!("du -s /etc/{name}"));
            line.split('\t').next().unwrap().parse::<u64>().unwrap()
        })
        .sum();
    assert_eq!(kib, 4 + parts);
    // A whole-tree walk finishes, totals at least its parts, and agrees with a second run.
    let all = out(&mut sh, "du -s /");
    let total: u64 = all.split('\t').next().unwrap().parse().unwrap();
    assert!(total >= kib);
    assert_eq!(out(&mut sh, "du -s /"), all);
    assert!(out(&mut sh, "du -sh /etc").ends_with("\t/etc\n"));
}

#[test]
fn du_stops_descending_a_deep_tree() {
    let mut sh = shell();
    let mut path = String::from("/tmp/deep");
    sh.fs.make_dir(&path).unwrap();
    for _ in 0..100 {
        path.push_str("/d");
        sh.fs.make_dir(&path).unwrap();
    }
    let text = out(&mut sh, "du /tmp/deep");
    let lines: Vec<&str> = text.lines().collect();
    // The operand and DU_DEPTH_MAX levels below it, each one block, and nothing deeper.
    let levels = usize::try_from(DU_DEPTH_MAX).unwrap() + 1;
    assert_eq!(lines.len(), levels, "{text}");
    assert_eq!(
        lines[0],
        format!("4\t{}", "/tmp/deep".to_string() + &"/d".repeat(levels - 1))
    );
    assert_eq!(*lines.last().unwrap(), format!("{}\t/tmp/deep", levels * 4));
}

#[test]
fn du_stops_after_the_node_cap_on_a_wide_tree() {
    let mut sh = shell();
    sh.fs.make_dir("/tmp/wide").unwrap();
    let files = usize::try_from(DU_VISIT_MAX).unwrap() + 500;
    for i in 0..files {
        sh.fs.write_file(&format!("/tmp/wide/f{i}"), b"").unwrap();
    }
    let text = out(&mut sh, "du -a /tmp/wide");
    // The directory and the files visited before the cap, never every file.
    let cap = usize::try_from(DU_VISIT_MAX).unwrap();
    assert_eq!(text.lines().count(), cap);
    assert!(text.lines().count() < files);
    // One unit a node visited, plus the bytes the line produced, plus the parser's own few.
    let produced = u64::try_from(text.len()).unwrap();
    let charged = sh.last_trace().budget.work_charged;
    assert!(
        charged <= u64::from(DU_VISIT_MAX) + produced + 256,
        "charged {charged}, produced {produced}"
    );
    // A second operand still gets its turn at an exhausted cap: it is counted as nothing.
    assert_eq!(answer(&mut sh, "du -s /tmp/wide /tmp").2, 0);
}

#[test]
fn du_charges_the_lines_work_allowance_and_ends_the_line_when_it_runs_out() {
    use crate::budget::{BudgetLimits, ConnectionBudget};
    let budget = ConnectionBudget::new(BudgetLimits {
        work_per_line: 40,
        ..BudgetLimits::standard()
    });
    let mut sh = shell().with_budget(budget);
    let (stdout, _, status) = answer(&mut sh, "du -a / ; echo after");
    assert_eq!(status, 1);
    assert!(!stdout.contains("after"), "the line ended: {stdout}");
    assert!(stdout.lines().count() <= 40);
}

#[test]
fn du_unknown_options_get_their_own_error_and_unmodeled_ones_print_nothing() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        answer(&mut sh, "du -z /tmp/d"),
        (
            "".into(),
            "du: invalid option -- 'z'\nTry 'du --help' for more information.\n".into(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "du --bogus /tmp/d").2, 1);
    let (_, stderr, status) = answer(&mut sh, "du -d");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("du: option requires an argument -- 'd'\n"));
    for line in [
        "du -S /tmp/d",
        "du -B1K /tmp/d",
        "du -t 1 /tmp/d",
        "du --exclude=a /tmp/d",
        "du --si /tmp/d",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    // Options with nothing to change in a one-filesystem, no-hard-link model leave it be.
    assert_eq!(out(&mut sh, "du -sx /tmp/d"), out(&mut sh, "du -s /tmp/d"));
    assert_eq!(out(&mut sh, "du -sL /tmp/d"), out(&mut sh, "du -s /tmp/d"));
    // Long options may be abbreviated.
    assert_eq!(out(&mut sh, "du --summ /tmp/d"), "28\t/tmp/d\n");
    assert_eq!(out(&mut sh, "du -- /tmp/d/a"), "4\t/tmp/d/a\n");
}

#[test]
fn phone_du_has_toybox_wording_and_the_same_sums() {
    let mut sh = phone();
    out(&mut sh, "mkdir -p /data/local/tmp/d/sub");
    out(&mut sh, "echo hello > /data/local/tmp/d/a");
    assert_eq!(
        out(&mut sh, "du /data/local/tmp/d"),
        "4\t/data/local/tmp/d/sub\n12\t/data/local/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "du -sh /data/local/tmp/d"),
        "12K\t/data/local/tmp/d\n"
    );
    assert_eq!(
        out(&mut sh, "toybox du -s /data/local/tmp/d"),
        "12\t/data/local/tmp/d\n"
    );
    assert_eq!(
        answer(&mut sh, "du /nope"),
        (
            "".into(),
            "du: /nope: No such file or directory\n".into(),
            1
        )
    );
    // GNU-only options are not toybox's.
    for line in ["du -b /data", "du --apparent-size /data", "du -P /data"] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!((stdout.as_str(), status), ("", 1), "{line}");
        assert!(
            stderr.starts_with("du: Unknown option "),
            "{line}: {stderr}"
        );
    }
    assert_eq!(
        out(&mut sh, "du -s -d 0 /data/local/tmp/d"),
        "12\t/data/local/tmp/d\n"
    );
}

// -------------------------------------------------------------------------- registration and scope

#[test]
fn the_three_commands_exist_on_both_personas_and_resolve_to_their_own_handlers() {
    let ubuntu_dir = |name: &str| format!("/usr/bin/{name}\n");
    let phone_dir = |name: &str| format!("/system/bin/{name}\n");
    for (name, id) in [
        ("free", HandlerId::Free),
        ("df", HandlerId::Df),
        ("du", HandlerId::Du),
    ] {
        let mut sh = shell();
        assert_eq!(
            out(&mut sh, &format!("command -v {name}")),
            ubuntu_dir(name),
            "{name}"
        );
        assert_eq!(
            out(&mut sh, &format!("type {name}")),
            format!("{name} is /usr/bin/{name}\n")
        );
        sh.handle_input(name);
        let trace = sh.last_trace();
        assert_eq!(
            trace.segments[0].command.as_ref().unwrap().resolved,
            id,
            "{name}"
        );

        let mut sh = phone();
        assert_eq!(
            out(&mut sh, &format!("command -v {name}")),
            phone_dir(name),
            "{name}"
        );
        sh.handle_input(name);
        let trace = sh.last_trace();
        assert_eq!(
            trace.segments[0].command.as_ref().unwrap().resolved,
            id,
            "{name}"
        );
        assert!(FakeFs::android().is_executable(&format!("/system/bin/{name}")));
        assert!(
            FakeFs::android()
                .list_dir("/system/bin")
                .unwrap()
                .contains(&name.to_string())
        );
    }
    // `busybox` runs them as applets of its own list.
    assert_eq!(
        out(&mut shell(), "busybox free -m"),
        out(&mut shell(), "free -m")
    );
    assert_eq!(out(&mut shell(), "busybox df /"), out(&mut shell(), "df /"));
}

#[test]
fn the_commands_read_the_model_and_change_nothing() {
    let mut sh = shell();
    let before = (
        sh.fs.list_dir("/tmp"),
        sh.fs.list_dir("/"),
        sh.fs.list_dir("/proc"),
    );
    for line in [
        "free -h",
        "df -ah",
        "du -a /",
        "free | cat",
        "df / | cat",
        "du -sh /etc",
    ] {
        sh.handle_input(line);
        let trace = sh.last_trace();
        let mut stack: Vec<&super::CommandTrace> = trace
            .segments
            .iter()
            .filter_map(|s| s.command.as_ref())
            .collect();
        while let Some(command) = stack.pop() {
            assert!(command.fs_effects.is_empty(), "{line}: {command:?}");
            stack.extend(command.reentry.iter());
        }
    }
    assert_eq!(
        before,
        (
            sh.fs.list_dir("/tmp"),
            sh.fs.list_dir("/"),
            sh.fs.list_dir("/proc")
        )
    );
}

#[test]
fn the_module_holds_no_process_or_host_access() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell/sysres.rs");
    let text = std::fs::read_to_string(path).unwrap();
    // Built by concatenation so this file does not trip the scan it runs.
    for banned in [
        ["std::process", "::Command"].concat(),
        ["Command", "::new"].concat(),
        ["std::", "fs"].concat(),
        ["std::", "env"].concat(),
        ["std::", "net"].concat(),
        ["libc", "::"].concat(),
        ["/proc/", "self/exe"].concat(),
    ] {
        assert!(!text.contains(&banned), "sysres.rs contains {banned}");
    }
}
