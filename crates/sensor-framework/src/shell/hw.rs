//! `lspci` (pciutils 3.7.0) and `lshw` (B.02.19.2): the devices of the Xen HVM guest the rest of
//! the persona describes (an EC2 instance with a Xeon E5-2686 v4, its disk on `xvda`, its NIC the
//! Xen paravirtual `vif` on `eth0`). The NIC is not a PCI device on such a guest, so `lspci` lists
//! the emulated i440FX chipset, the Cirrus VGA adapter and the Xen platform device only, and
//! `lshw -C network` describes `eth0` from the network model `ip link` renders, MAC and address
//! included.
//!
//! The device list, the IDs, the drivers and `lshw`'s field values are composed from knowledge of
//! Xen HVM guests [unverified]: the reference container showed its host's hardware, which is not
//! this persona's. The layouts follow the tools' formats as the reference printed them.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};

pub(super) fn register(r: &mut Registry) {
    r.register_if("lspci", ubuntu, HandlerId::Lspci, FakeShell::cmd_lspci);
    r.register_if("lshw", ubuntu, HandlerId::Lshw, FakeShell::cmd_lshw);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// One PCI function.
struct Device {
    slot: &'static str,
    class: &'static str,
    class_id: &'static str,
    /// What follows the class: vendor and device names.
    name: &'static str,
    ids: &'static str,
    rev: Option<&'static str>,
    prog_if: Option<&'static str>,
    driver: Option<&'static str>,
    modules: Option<&'static str>,
}

const DEVICES: [Device; 6] = [
    Device {
        slot: "00:00.0",
        class: "Host bridge",
        class_id: "0600",
        name: "Intel Corporation 440FX - 82441FX PMC [Natoma]",
        ids: "8086:1237",
        rev: Some("02"),
        prog_if: None,
        driver: None,
        modules: None,
    },
    Device {
        slot: "00:01.0",
        class: "ISA bridge",
        class_id: "0601",
        name: "Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]",
        ids: "8086:7000",
        rev: None,
        prog_if: None,
        driver: None,
        modules: None,
    },
    Device {
        slot: "00:01.1",
        class: "IDE interface",
        class_id: "0101",
        name: "Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]",
        ids: "8086:7010",
        rev: None,
        prog_if: Some("80 [ISA Compatibility mode-only controller, supports bus mastering]"),
        driver: Some("ata_piix"),
        modules: Some("pata_acpi"),
    },
    Device {
        slot: "00:01.3",
        class: "Bridge",
        class_id: "0680",
        name: "Intel Corporation 82371AB/EB/MB PIIX4 ACPI",
        ids: "8086:7113",
        rev: Some("01"),
        prog_if: None,
        driver: None,
        modules: Some("i2c_piix4"),
    },
    Device {
        slot: "00:02.0",
        class: "VGA compatible controller",
        class_id: "0300",
        name: "Cirrus Logic GD 5446",
        ids: "1013:00b8",
        rev: None,
        prog_if: None,
        driver: Some("cirrus"),
        modules: Some("cirrus"),
    },
    Device {
        slot: "00:03.0",
        class: "Unassigned class",
        class_id: "ff80",
        name: "XenSource, Inc. Xen Platform Device",
        ids: "5853:0001",
        rev: Some("01"),
        prog_if: None,
        driver: Some("xen-platform-pci"),
        modules: None,
    },
];

impl FakeShell {
    /// `lspci [-n|-nn] [-k] [-v]`. The `Unassigned class` device is shown as pciutils shows a
    /// class it has no name for, `[ff80]` included even without `-nn`. `-v` prints what `-k`
    /// does, without the flags and memory lines a real one adds [unverified subset].
    pub(super) fn cmd_lspci(&mut self, parts: &[&str]) -> CommandResult {
        let mut numeric = 0u8;
        let mut kernel = false;
        for arg in parts.get(1..).unwrap_or(&[]) {
            let Some(flags) = arg.strip_prefix('-') else {
                return CommandResult::stderr(
                    1,
                    format!("lspci: Unknown option '{arg}' (see \"lspci --help\")\n"),
                );
            };
            for flag in flags.chars() {
                match flag {
                    'n' => numeric = numeric.saturating_add(1),
                    'k' | 'v' => kernel = true,
                    'm' | 't' | 'x' | 'b' | 'D' | 'P' | 'q' | 'Q' | 'M' => {}
                    other => {
                        return CommandResult::stderr(
                            1,
                            format!(
                                "lspci: invalid option -- '{other}'\nUsage: lspci [<switches>]\n"
                            ),
                        );
                    }
                }
            }
        }
        let mut out = String::new();
        for device in &DEVICES {
            let class = match numeric {
                0 if device.class_id == "ff80" => format!("{} [ff80]", device.class),
                0 => device.class.to_string(),
                1 => device.class_id.to_string(),
                _ => format!("{} [{}]", device.class, device.class_id),
            };
            let name = match numeric {
                0 => device.name.to_string(),
                1 => device.ids.to_string(),
                _ => format!("{} [{}]", device.name, device.ids),
            };
            out.push_str(&format!("{} {class}: {name}", device.slot));
            if let Some(rev) = device.rev {
                out.push_str(&format!(" (rev {rev})"));
            }
            if numeric != 1
                && kernel
                && let Some(prog_if) = device.prog_if
            {
                out.push_str(&format!(" (prog-if {prog_if})"));
            }
            out.push('\n');
            if kernel {
                if device.class_id != "ff80" {
                    out.push_str("\tSubsystem: Red Hat, Inc. Qemu virtual machine\n");
                } else {
                    out.push_str("\tSubsystem: XenSource, Inc. Xen Platform Device\n");
                }
                if let Some(driver) = device.driver {
                    out.push_str(&format!("\tKernel driver in use: {driver}\n"));
                }
                if let Some(modules) = device.modules {
                    out.push_str(&format!("\tKernel modules: {modules}\n"));
                }
                out.push('\n');
            }
        }
        CommandResult::stdout(out)
    }

    /// `lshw [-C CLASS] [-short]`, as root: the display adapter and the network interface. Any
    /// other class has nothing to list; a full listing is the two together under the system node.
    pub(super) fn cmd_lshw(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let mut class: Option<String> = None;
        let mut short = false;
        let mut iter = args.iter();
        while let Some(&arg) = iter.next() {
            match arg {
                "-C" | "-c" | "-class" | "--class" => {
                    class = iter.next().map(|c| c.to_ascii_lowercase());
                }
                "-short" | "--short" | "-businfo" | "--businfo" => short = true,
                "-sanitize" | "--sanitize" | "-numeric" | "--numeric" | "-quiet" | "--quiet"
                | "-notime" | "--notime" => {}
                _ => {
                    return CommandResult::stderr(1, LSHW_USAGE);
                }
            }
        }
        let network = self.lshw_network();
        let display = LSHW_DISPLAY.to_string();
        let (iface, _, _) =
            self.primary_interface()
                .unwrap_or(("eth0", String::new(), String::new()));
        if short {
            let mut out = String::from(
                "H/W path      Device     Class          Description\n\
                 ====================================================\n",
            );
            let rows = [
                ("display", "/0/100/2", "", "display", "GD 5446"),
                ("network", "/1", iface, "network", "Ethernet interface"),
            ];
            for (row_class, path, device, kind, description) in rows {
                if class.as_deref().is_none_or(|c| c == row_class) {
                    out.push_str(&format!("{path:<14}{device:<11}{kind:<15}{description}\n"));
                }
            }
            return CommandResult::stdout(out);
        }
        let out = match class.as_deref() {
            Some("display" | "video") => display,
            Some("network") => network,
            Some(_) => String::new(),
            None => format!("{display}{network}"),
        };
        CommandResult::stdout(out)
    }

    fn lshw_network(&self) -> String {
        let (iface, mac, addr) =
            self.primary_interface()
                .unwrap_or(("eth0", String::new(), String::new()));
        format!(
            "  *-network\n\
             \x20      description: Ethernet interface\n\
             \x20      physical id: 1\n\
             \x20      logical name: {iface}\n\
             \x20      serial: {mac}\n\
             \x20      capabilities: ethernet physical\n\
             \x20      configuration: autonegotiation=off broadcast=yes driver=vif ip={addr} link=yes multicast=yes\n"
        )
    }
}

const LSHW_DISPLAY: &str = "  *-display
       description: VGA compatible controller
       product: GD 5446
       vendor: Cirrus Logic
       physical id: 2
       bus info: pci@0000:00:02.0
       logical name: /dev/fb0
       version: 00
       width: 32 bits
       clock: 33MHz
       capabilities: vga_controller rom fb
       configuration: depth=16 driver=cirrus latency=0 resolution=1024,768
       resources: irq:0 memory:f0000000-f1ffffff memory:f3000000-f3000fff memory:c0000-dffff
";

const LSHW_USAGE: &str = "Hardware Lister (lshw) - B.02.19.2
usage: lshw [-format] [-options ...]
       lshw -version

\t-version        print program version (B.02.19.2)

format can be
\t-html           output hardware tree as HTML
\t-xml            output hardware tree as XML
\t-json           output hardware tree as a JSON object
\t-short          output hardware paths
\t-businfo        output bus information

options can be
\t-class CLASS    only show a certain class of hardware
\t-C CLASS        same as '-class CLASS'
\t-c CLASS        same as '-class CLASS'
\t-disable TEST   disable a test (like pci, isapnp, cpuid, etc. )
\t-enable TEST    enable a test (like pci, isapnp, cpuid, etc. )
\t-quiet          don't display status
\t-sanitize       sanitize output (remove sensitive information like serial numbers, etc.)
\t-numeric        output numeric IDs (for PCI, USB, etc.)
\t-notime         exclude volatile attributes (timestamps) from output

";
