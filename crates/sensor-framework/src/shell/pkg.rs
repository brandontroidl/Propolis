//! `dpkg`, `apt` and `apt-get` over the one modeled package database ([`crate::packages`]), so a
//! survey's `which apt`, `dpkg -l | wc -l`, `dpkg -l openssh-server` and `apt list --installed`
//! agree with each other and with the SSH banner.
//!
//! Nothing is fetched, unpacked or installed, and the database never changes. `apt update`
//! reports the archive's indexes as unchanged (`Hit:`), the answer a box whose lists are current
//! gives. `install` of an installed package is "already the newest version"; of anything else,
//! "Unable to locate package", what apt says when the lists do not carry the name. `upgrade`
//! keeps every upgradable package back, as jammy's phased updates do. `remove` prints apt's plan
//! but the package stays installed [unverified: the database is not a session state].
//!
//! Recorded on the 2026-10-07 Ubuntu 22.04 reference (dpkg 1.21.1, apt 2.4.14): the `dpkg -l`
//! header and column rules (each column at least its header's width, widened to its longest
//! cell), `dpkg -s`'s field order and its not-installed error, `dpkg-query`'s no-match error,
//! apt's script warning, `apt update`/`apt-get update` transcripts, `already the newest version`,
//! `Unable to locate package` with status 100, and `apt list`'s line format.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::fileinfo::glob_match;
use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::packages::{self, OPENSSH_SERVER_DETAIL, Package};

pub(super) fn register(r: &mut Registry) {
    r.register_if("dpkg", ubuntu, HandlerId::Dpkg, FakeShell::cmd_dpkg);
    r.register_if("apt", ubuntu, HandlerId::Apt, FakeShell::cmd_apt);
    r.register_if("apt-get", ubuntu, HandlerId::Apt, FakeShell::cmd_apt);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

const NS_PER_MS: u64 = 1_000_000;

const DPKG_HEADER: &str = "Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
";

const APT_WARNING: &str =
    "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n";

const DPKG_VERSION: &str = "Debian 'dpkg' package management program version 1.21.1 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.
";

const DPKG_NO_ACTION: &str = "dpkg: error: need an action option

Type dpkg --help for help about installing and deinstalling packages [*];
Use 'apt' or 'aptitude' for user-friendly package management;
Type dpkg -Dhelp for a list of dpkg debug flag values;
Type dpkg --force-help for a list of forcing options;
Type dpkg-deb --help for help about manipulating *.deb files;

Options marked [*] produce a lot of output - pipe it through 'less' or 'more' !
";

/// `dpkg -l`'s table for `rows`: each column as wide as its header's minimum (14, 12, 12, 33) or
/// its longest cell.
fn dpkg_table(rows: &[Package]) -> String {
    let width =
        |minimum: usize, cells: &mut dyn Iterator<Item = usize>| cells.fold(minimum, usize::max);
    let names: Vec<String> = rows.iter().map(Package::qualified_name).collect();
    let nw = width(14, &mut names.iter().map(|n| n.chars().count()));
    let vw = width(12, &mut rows.iter().map(|p| p.version.chars().count()));
    let aw = width(12, &mut rows.iter().map(|p| p.arch.chars().count()));
    let dw = width(33, &mut rows.iter().map(|p| p.summary.chars().count()));
    let mut out = String::from(DPKG_HEADER);
    out.push_str(&format!(
        "||/ {:<nw$} {:<vw$} {:<aw$} Description\n",
        "Name", "Version", "Architecture"
    ));
    out.push_str(&format!(
        "+++-{}-{}-{}-{}\n",
        "=".repeat(nw),
        "=".repeat(vw),
        "=".repeat(aw),
        "=".repeat(dw)
    ));
    for (package, name) in rows.iter().zip(&names) {
        out.push_str(&format!(
            "ii  {name:<nw$} {:<vw$} {:<aw$} {}\n",
            package.version, package.arch, package.summary
        ));
    }
    out
}

/// `dpkg -s`'s stanza: the recorded field order, with the long fields only for openssh-server.
fn dpkg_status(package: &Package) -> String {
    let mut out = format!(
        "Package: {}\nStatus: install ok installed\nPriority: {}\nSection: {}\nInstalled-Size: {}\n\
         Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\nArchitecture: {}\n",
        package.name, package.priority, package.section, package.installed_size, package.arch
    );
    if package.multi_arch != "no" {
        out.push_str(&format!("Multi-Arch: {}\n", package.multi_arch));
    }
    if package.source != package.name {
        out.push_str(&format!("Source: {}\n", package.source));
    }
    out.push_str(&format!("Version: {}\n", package.version));
    if package.name == "openssh-server" {
        out.push_str(OPENSSH_SERVER_DETAIL);
    } else {
        out.push_str(&format!("Description: {}\n", package.summary));
    }
    out
}

/// `apt list`'s line for an installed package.
fn apt_line(package: &Package) -> String {
    let mut state = String::from("installed");
    if package.automatic {
        state.push_str(",automatic");
    }
    if let Some((_, version)) = package.upgrade {
        state.push_str(&format!(",upgradable to: {version}"));
    } else if package.pockets == "now" {
        state.push_str(",local");
    }
    format!(
        "{}/{} {} {} [{state}]\n",
        package.name, package.pockets, package.version, package.arch
    )
}

fn upgradable() -> Vec<Package> {
    packages::installed()
        .filter(|package| package.upgrade.is_some())
        .collect()
}

impl FakeShell {
    /// `dpkg -l [PATTERN...]`, `-s PKG...`, `--version`, `--print-architecture`, `-i FILE`.
    pub(super) fn cmd_dpkg(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let Some((action, operands)) = args.split_first() else {
            return CommandResult::stderr(2, DPKG_NO_ACTION);
        };
        let operands: Vec<&str> = operands
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        match *action {
            "-l" | "--list" => self.dpkg_list(&operands),
            "-s" | "--status" => self.dpkg_show_status(&operands),
            "--version" => CommandResult::stdout(DPKG_VERSION),
            "--print-architecture" => CommandResult::stdout("amd64\n"),
            "-i" | "--install" => self.dpkg_install(&operands),
            "-L" | "--listfiles" | "-S" | "--search" | "-c" | "--contents" => {
                CommandResult::silent(0)
            }
            other if other.starts_with('-') => CommandResult::stderr(2, DPKG_NO_ACTION),
            _ => CommandResult::stderr(2, DPKG_NO_ACTION),
        }
    }

    fn dpkg_list(&mut self, patterns: &[&str]) -> CommandResult {
        let all: Vec<Package> = packages::installed().collect();
        if patterns.is_empty() {
            return CommandResult::stdout(dpkg_table(&all));
        }
        let mut rows: Vec<Package> = Vec::new();
        let mut missing = String::new();
        for pattern in patterns {
            let found: Vec<Package> = all
                .iter()
                .filter(|p| glob_match(pattern, p.name, false))
                .copied()
                .collect();
            if found.is_empty() {
                missing.push_str(&format!(
                    "dpkg-query: no packages found matching {}\n",
                    crate::sanitize_value(pattern, 128)
                ));
            }
            for package in found {
                if !rows.contains(&package) {
                    rows.push(package);
                }
            }
        }
        rows.sort_by(|a, b| a.name.cmp(b.name));
        let mut result = if rows.is_empty() {
            CommandResult::silent(1)
        } else {
            CommandResult::stdout(dpkg_table(&rows))
        };
        if !missing.is_empty() {
            result.append(CommandResult::stderr(1, missing));
        }
        result
    }

    fn dpkg_show_status(&mut self, names: &[&str]) -> CommandResult {
        if names.is_empty() {
            return CommandResult::stderr(
                2,
                "dpkg-query: error: --status needs at least one package name argument\n\n\
                 Use --help for help about querying packages.\n",
            );
        }
        let mut result = CommandResult::silent(0);
        let mut missing = false;
        for (index, name) in names.iter().enumerate() {
            match packages::find(name) {
                Some(package) => {
                    let separator = if index > 0 { "\n" } else { "" };
                    result.append(CommandResult::stdout(format!(
                        "{separator}{}",
                        dpkg_status(&package)
                    )));
                }
                None => {
                    missing = true;
                    result.append(CommandResult::stderr(
                        1,
                        format!(
                            "dpkg-query: package '{}' is not installed and no information is available\n",
                            crate::sanitize_value(name, 128)
                        ),
                    ));
                }
            }
        }
        if missing {
            result.append(CommandResult::stderr(
                1,
                "Use dpkg --info (= dpkg-deb --info) to examine archive files.\n",
            ));
        }
        result
    }

    /// `dpkg -i FILE`: nothing is ever unpacked. A missing file is dpkg's access error; an
    /// existing one is refused as not a Debian archive [unverified wording].
    fn dpkg_install(&mut self, files: &[&str]) -> CommandResult {
        let Some(file) = files.first() else {
            return CommandResult::stderr(
                2,
                "dpkg: error: --install needs at least one package archive file argument\n\n\
                 Type dpkg --help for help about installing and deinstalling packages [*];\n",
            );
        };
        let shown = crate::sanitize_value(file, 256);
        let path = self.resolve_logical(file);
        if self.fs.stat(&path, true).is_none() {
            return CommandResult::stderr(
                1,
                format!(
                    "dpkg: error: cannot access archive '{shown}': No such file or directory\n"
                ),
            );
        }
        CommandResult::stderr(
            1,
            format!(
                "dpkg-deb: error: '{shown}' is not a Debian format archive\n\
                 dpkg: error processing archive {shown} (--install):\n \
                 dpkg-deb --control subprocess returned error exit status 2\n\
                 Errors were encountered while processing:\n {shown}\n"
            ),
        )
    }

    /// `apt` and `apt-get`: `update`, `install`, `remove`/`purge`, `upgrade`, `list`, `show`,
    /// `autoremove`, `clean`, `-v`.
    pub(super) fn cmd_apt(&mut self, parts: &[&str]) -> CommandResult {
        let apt = parts.first().is_some_and(|p| p.ends_with("apt"));
        let args = parts.get(1..).unwrap_or(&[]);
        let assume_yes = args
            .iter()
            .any(|a| matches!(*a, "-y" | "--yes" | "--assume-yes" | "-qy" | "-yq"));
        if args.iter().any(|a| matches!(*a, "-v" | "--version")) {
            return CommandResult::stdout(if apt {
                "apt 2.4.14 (amd64)\n"
            } else {
                "apt 2.4.14 (amd64)\nSupported modules:\n*Ver: Standard .deb\n*Pkg:  Debian dpkg interface (Priority 30)\n Pkg:  Debian APT solver interface (Priority -1000)\n Pkg:  Debian APT planner interface (Priority -1000)\n S.L: 'deb' Standard Debian binary tree\n S.L: 'deb-src' Standard Debian source tree\n Idx: Debian Source Index\n Idx: Debian Package Index\n Idx: Debian Translation Index\n Idx: Debian dpkg status file\n Idx: Debian deb file\n Idx: Debian dsc file\n Idx: Debian control file\n Idx: EDSP scenario file\n Idx: EIPP scenario file\n"
            });
        }
        let words: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        let tty = self.stdout_is_terminal();
        let mut out = CommandResult::silent(0);
        if apt && !tty {
            out.append(CommandResult::stderr(0, APT_WARNING));
        }
        let done = if tty { " Done" } else { "" };
        let reading = format!(
            "Reading package lists...{done}\nBuilding dependency tree...{done}\nReading state information...{done}\n"
        );
        let held = upgradable();
        let summary = |installed: usize, removed: usize| {
            format!(
                "0 upgraded, {installed} newly installed, {removed} to remove and {} not upgraded.\n",
                held.len()
            )
        };
        let Some((command, operands)) = words.split_first() else {
            return CommandResult::stderr(
                1,
                "apt 2.4.14 (amd64)\nUsage: apt-get [options] command\n",
            );
        };
        match *command {
            "update" => {
                self.timing.wait(1_800u64.saturating_mul(NS_PER_MS));
                let hits = if apt {
                    "Hit:1 http://security.ubuntu.com/ubuntu jammy-security InRelease\n\
                     Hit:2 http://archive.ubuntu.com/ubuntu jammy InRelease\n\
                     Hit:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n\
                     Hit:4 http://archive.ubuntu.com/ubuntu jammy-backports InRelease\n"
                } else {
                    "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n\
                     Hit:2 http://security.ubuntu.com/ubuntu jammy-security InRelease\n\
                     Hit:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n\
                     Hit:4 http://archive.ubuntu.com/ubuntu jammy-backports InRelease\n"
                };
                let mut text = hits.to_string();
                if apt {
                    text.push_str(&reading);
                    text.push_str(&format!(
                        "{} packages can be upgraded. Run 'apt list --upgradable' to see them.\n",
                        held.len()
                    ));
                } else {
                    text.push_str(&format!("Reading package lists...{done}\n"));
                }
                out.append(CommandResult::stdout(text));
            }
            "install" | "reinstall" => {
                let mut text = reading.clone();
                let mut unknown = String::new();
                for name in operands {
                    match packages::find(name) {
                        Some(package) => text.push_str(&format!(
                            "{} is already the newest version ({}).\n",
                            package.name, package.version
                        )),
                        None => {
                            unknown = crate::sanitize_value(name, 128);
                            break;
                        }
                    }
                }
                if unknown.is_empty() {
                    text.push_str(&summary(0, 0));
                    out.append(CommandResult::stdout(text));
                } else {
                    out.append(CommandResult::stdout(reading));
                    out.append(CommandResult::stderr(
                        100,
                        format!("E: Unable to locate package {unknown}\n"),
                    ));
                }
            }
            "remove" | "purge" | "autoremove" => {
                let mut text = reading.clone();
                let mut removing: Vec<Package> = Vec::new();
                for name in operands {
                    match packages::find(name) {
                        Some(package) => removing.push(package),
                        None => text.push_str(&format!(
                            "Package '{}' is not installed, so not removed\n",
                            crate::sanitize_value(name, 128)
                        )),
                    }
                }
                if removing.is_empty() {
                    text.push_str(&summary(0, 0));
                    out.append(CommandResult::stdout(text));
                } else {
                    let names: Vec<&str> = removing.iter().map(|p| p.name).collect();
                    text.push_str(&format!(
                        "The following packages will be REMOVED:\n  {}\n{}",
                        names.join(" "),
                        summary(0, removing.len())
                    ));
                    if assume_yes {
                        text.push_str("(Reading database ... 64233 files and directories currently installed.)\n");
                        for package in &removing {
                            text.push_str(&format!(
                                "Removing {} ({}) ...\n",
                                package.name, package.version
                            ));
                        }
                        out.append(CommandResult::stdout(text));
                    } else {
                        text.push_str("Do you want to continue? [Y/n] Abort.\n");
                        out.append(CommandResult::stdout(text));
                        out.status = 1;
                    }
                }
            }
            "upgrade" | "full-upgrade" | "dist-upgrade" => {
                let names: Vec<&str> = held.iter().map(|p| p.name).collect();
                let mut text = format!("{reading}Calculating upgrade...{done}\n");
                if !names.is_empty() {
                    text.push_str(&format!(
                        "The following packages have been kept back:\n  {}\n",
                        names.join(" ")
                    ));
                }
                text.push_str(&summary(0, 0));
                out.append(CommandResult::stdout(text));
            }
            "list" => {
                let mut text = format!("Listing...{done}\n");
                let upgradable_only = args.contains(&"--upgradable");
                for package in packages::installed() {
                    let wanted = if upgradable_only {
                        package.upgrade.is_some()
                    } else {
                        operands.is_empty()
                            || operands.iter().any(|p| glob_match(p, package.name, false))
                    };
                    if !wanted {
                        continue;
                    }
                    match (upgradable_only, package.upgrade) {
                        (true, Some((pockets, version))) => text.push_str(&format!(
                            "{}/{pockets} {version} {} [upgradable from: {}]\n",
                            package.name, package.arch, package.version
                        )),
                        _ => text.push_str(&apt_line(&package)),
                    }
                }
                out.append(CommandResult::stdout(text));
            }
            "show" | "policy" => {
                let mut text = String::new();
                for name in operands {
                    if let Some(package) = packages::find(name) {
                        text.push_str(&dpkg_status(&package));
                        text.push('\n');
                    }
                }
                if text.is_empty() {
                    out.append(CommandResult::stderr(100, "E: No packages found\n"));
                } else {
                    out.append(CommandResult::stdout(text));
                }
            }
            "clean" | "autoclean" => {}
            other => {
                out.append(CommandResult::stderr(
                    100,
                    format!(
                        "E: Invalid operation {}\n",
                        crate::sanitize_value(other, 64)
                    ),
                ));
            }
        }
        out
    }
}
