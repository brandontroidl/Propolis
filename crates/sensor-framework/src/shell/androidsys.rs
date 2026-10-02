//! `getenforce`, `pm`, `am`, `wm`, `dumpsys`, `screencap` and `logcat`: the Android system commands
//! an attacker on the ADB shell probes with after `getprop` (is SELinux on, what is installed, what
//! is the screen, can I install an apk, launch an intent, grab the screen).
//!
//! Every reply is the smallest defensible one. No device capture backs any of them, and a long
//! realistic-looking dump that is wrong is a worse tell than a short plain answer, so each command
//! returns a short canned reply or echoes the intent it was given, and nothing more. The raw command
//! line is already recorded by the sensor as a command event, which is what captures the attacker's
//! intent; these handlers only supply a plausible reply. They run no process, open no socket and
//! start no activity. `screencap PATH` writes a few placeholder bytes to the session overlay through
//! the same bounded write path as `touch` and `cp`. Every list and output below is a fixed size, and
//! the only attacker text echoed back is cut to [`ECHO_MAX`] characters.
//!
//! Persona-derived facts (`wm`'s panel size) match the Nexus 5 the persona presents. Only Android's
//! shell has these commands; on bash they are "not found". Anything no capture backs is marked
//! `[unverified]`; `getenforce`'s answer is the stock Android 6.0 default and is not.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, budget_refusal_text};
use crate::fakefs::FsError;

pub(super) fn register(r: &mut Registry) {
    r.register_if(
        "getenforce",
        android,
        HandlerId::Getenforce,
        FakeShell::cmd_getenforce,
    );
    r.register_if("pm", android, HandlerId::Pm, FakeShell::cmd_pm);
    r.register_if("am", android, HandlerId::Am, FakeShell::cmd_am);
    r.register_if("wm", android, HandlerId::Wm, FakeShell::cmd_wm);
    r.register_if(
        "dumpsys",
        android,
        HandlerId::Dumpsys,
        FakeShell::cmd_dumpsys,
    );
    r.register_if(
        "screencap",
        android,
        HandlerId::Screencap,
        FakeShell::cmd_screencap,
    );
    r.register_if("logcat", android, HandlerId::Logcat, FakeShell::cmd_logcat);
}

fn android(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh
}

/// The longest stretch of attacker text any reply repeats.
const ECHO_MAX: usize = 200;

fn clip(text: &str) -> String {
    text.chars().take(ECHO_MAX).collect()
}

// ------------------------------------------------------------------------------------ getenforce

/// A stock Nexus 5 on Android 6.0.1 ships with SELinux enforcing.
const GETENFORCE: &str = "Enforcing\n";

// -------------------------------------------------------------------------------------------- wm

/// The Nexus 5 panel: 1080x1920 at 480 dpi, the same device the persona names.
const WM_SIZE: &str = "Physical size: 1080x1920\n";
const WM_DENSITY: &str = "Physical density: 480\n";
/// [unverified] wording of the usage line.
const WM_USAGE: &str = "usage: wm [subcommand] [options]\n";

// -------------------------------------------------------------------------------------------- pm

/// [unverified] a short canned set of system packages and the apk each lives in. The names are real
/// Android 6.0 / Nexus 5 packages; the apk paths are from AOSP's layout, not a capture. Fixed size,
/// so `pm list packages` is bounded.
const PACKAGES: [(&str, &str); 14] = [
    ("android", "/system/framework/framework-res.apk"),
    (
        "com.android.bluetooth",
        "/system/app/Bluetooth/Bluetooth.apk",
    ),
    (
        "com.android.certinstaller",
        "/system/app/CertInstaller/CertInstaller.apk",
    ),
    ("com.android.chrome", "/system/app/Chrome/Chrome.apk"),
    (
        "com.android.defcontainer",
        "/system/priv-app/DefaultContainerService/DefaultContainerService.apk",
    ),
    (
        "com.android.inputmethod.latin",
        "/system/app/LatinIME/LatinIME.apk",
    ),
    (
        "com.android.packageinstaller",
        "/system/priv-app/PackageInstaller/PackageInstaller.apk",
    ),
    (
        "com.android.phone",
        "/system/priv-app/TeleService/TeleService.apk",
    ),
    (
        "com.android.providers.settings",
        "/system/priv-app/SettingsProvider/SettingsProvider.apk",
    ),
    (
        "com.android.settings",
        "/system/priv-app/Settings/Settings.apk",
    ),
    ("com.android.shell", "/system/priv-app/Shell/Shell.apk"),
    (
        "com.android.systemui",
        "/system/priv-app/SystemUI/SystemUI.apk",
    ),
    (
        "com.google.android.gms",
        "/system/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk",
    ),
    (
        "com.google.android.gsf",
        "/system/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk",
    ),
];

/// [unverified] wording of the usage line.
const PM_USAGE: &str = "usage: pm [subcommand] [options]\n";
const PM_OK: &str = "Success\n";
const PM_FAILED: &str = "Failure\n";

fn package_apk(name: &str) -> Option<&'static str> {
    PACKAGES
        .iter()
        .find(|(package, _)| *package == name)
        .map(|(_, apk)| *apk)
}

// -------------------------------------------------------------------------------------------- am

/// [unverified] wording of the usage line.
const AM_USAGE: &str = "usage: am [subcommand] [options]\n";

/// Options of `am start` and `am broadcast` that take one value, and the ones that take a key and
/// a value (`-e KEY VALUE`, `--es`, `--ez`, ...). Anything else starting with `-` is a bare flag.
const ONE_VALUE: [&str; 10] = [
    "-a",
    "-d",
    "-t",
    "-c",
    "-n",
    "-p",
    "-f",
    "--user",
    "--esn",
    "--receiver-permission",
];

fn takes_key_value(option: &str) -> bool {
    option == "-e" || (option.starts_with("--e") && option != "--esn")
}

/// The `Intent { ... }` body an `am start`/`am broadcast` line describes, in `Intent.toShortString`
/// order, or `None` when the line names no action, category, data, type or component.
/// [unverified] the exact field rendering, from the AOSP source, not a capture.
fn intent_of(args: &[&str]) -> Option<String> {
    let mut action = None;
    let mut categories: Vec<String> = Vec::new();
    let mut data = None;
    let mut mime = None;
    let mut component = None;
    let mut at = 0;
    while let Some(&arg) = args.get(at) {
        at = at.saturating_add(1);
        if !arg.starts_with('-') {
            if arg.contains(':') {
                data = Some(clip(arg));
            } else {
                component = Some(clip(arg));
            }
            continue;
        }
        if takes_key_value(arg) {
            at = at.saturating_add(2);
        } else if ONE_VALUE.contains(&arg) {
            let value = args.get(at).map(|v| clip(v));
            at = at.saturating_add(1);
            match arg {
                "-a" => action = value.or(action),
                "-d" => data = value.or(data),
                "-t" => mime = value.or(mime),
                "-n" => component = value.or(component),
                "-c" => categories.extend(value),
                _ => {}
            }
        }
    }
    let mut fields: Vec<String> = Vec::new();
    if let Some(action) = action {
        fields.push(format!("act={action}"));
    }
    if !categories.is_empty() {
        let shown: Vec<String> = categories.into_iter().take(8).collect();
        fields.push(format!("cat=[{}]", shown.join(",")));
    }
    if let Some(data) = data {
        fields.push(format!("dat={data}"));
    }
    if let Some(mime) = mime {
        fields.push(format!("typ={mime}"));
    }
    if let Some(component) = component {
        fields.push(format!("cmp={component}"));
    }
    (!fields.is_empty()).then(|| format!("Intent {{ {} }}", fields.join(" ")))
}

// ---------------------------------------------------------------------------------------- dumpsys

/// [unverified] a short canned service list, in the order `dumpsys` prints it (sorted). Fixed size.
const SERVICES: [&str; 12] = [
    "SurfaceFlinger",
    "activity",
    "alarm",
    "battery",
    "connectivity",
    "input_method",
    "meminfo",
    "package",
    "power",
    "telephony.registry",
    "wifi",
    "window",
];

// ------------------------------------------------------------------------------------- screencap

/// [unverified] a placeholder, not a real image: the 8-byte PNG signature for `-p`, and for the raw
/// form the 12-byte header (width, height, format `1` = RGBA_8888, little-endian) matching
/// [`WM_SIZE`]. Both are tiny and bounded.
const SCREENCAP_PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const SCREENCAP_RAW: &[u8] = &[0x38, 0x04, 0, 0, 0x80, 0x07, 0, 0, 1, 0, 0, 0];

// --------------------------------------------------------------------------------------- logcat

/// [unverified] a fixed handful of log lines in the default `brief` format. Nothing the model does
/// appends to a log, so a bare `logcat` (which would follow) ends here like `tail -f` does.
const LOGCAT: &str = "--------- beginning of system\n\
    I/SystemServer(  612): Entered the Android system server!\n\
    I/ActivityManager(  612): System now ready\n\
    I/SystemServer(  612): Making services ready\n\
    I/ActivityManager(  612): Start proc com.android.phone for restart com.android.phone\n";

impl FakeShell {
    pub(super) fn cmd_getenforce(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stdout(GETENFORCE)
    }

    /// `wm size` and `wm density` print the panel; setting either (`wm size 720x1280`, `wm density
    /// reset`) succeeds silently and is not applied, so the next read still reports the panel.
    /// Anything else gets the usage line.
    pub(super) fn cmd_wm(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        match (args.first().copied(), args.get(1)) {
            (Some("size"), None) => CommandResult::stdout(WM_SIZE),
            (Some("density"), None) => CommandResult::stdout(WM_DENSITY),
            (Some("size" | "density"), Some(_)) => CommandResult::silent(0),
            _ => CommandResult::stderr(1, WM_USAGE),
        }
    }

    /// `pm list packages [-f] [-s|-3|-d|-e] [FILTER]`, `pm path PKG`, `pm install PATH`,
    /// `pm uninstall PKG`. Installing or removing changes no state, so the package list is the same
    /// before and after.
    pub(super) fn cmd_pm(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        match (args.first().copied(), args.get(1).copied()) {
            (Some("list"), Some("packages")) => pm_list(args.get(2..).unwrap_or(&[])),
            (Some("path"), Some(name)) => match package_apk(name) {
                Some(apk) => CommandResult::stdout(format!("package:{apk}\n")),
                None => CommandResult::silent(1),
            },
            (Some("install"), _) => {
                let path = args
                    .get(1..)
                    .unwrap_or(&[])
                    .iter()
                    .find(|arg| !arg.starts_with('-'));
                match path {
                    Some(_) => CommandResult::stdout(PM_OK),
                    None => CommandResult::stderr(1, PM_USAGE),
                }
            }
            (Some("uninstall"), _) => {
                let name = args
                    .get(1..)
                    .unwrap_or(&[])
                    .iter()
                    .find(|arg| !arg.starts_with('-'));
                match name {
                    Some(name) if package_apk(name).is_some() => CommandResult::stdout(PM_OK),
                    Some(_) => CommandResult::stdout(PM_FAILED),
                    None => CommandResult::stderr(1, PM_USAGE),
                }
            }
            _ => CommandResult::stderr(1, PM_USAGE),
        }
    }

    /// `am start ...` and `am broadcast ...` echo the intent they parsed and start nothing.
    pub(super) fn cmd_am(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let rest = args.get(1..).unwrap_or(&[]);
        match args.first().copied() {
            Some("start") => match intent_of(rest) {
                Some(intent) => CommandResult::stdout(format!("Starting: {intent}\n")),
                None => CommandResult::stderr(1, AM_USAGE),
            },
            Some("broadcast") => match intent_of(rest) {
                Some(intent) => CommandResult::stdout(format!(
                    "Broadcasting: {intent}\nBroadcast completed: result=0\n"
                )),
                None => CommandResult::stderr(1, AM_USAGE),
            },
            _ => CommandResult::stderr(1, AM_USAGE),
        }
    }

    /// `dumpsys` lists the canned services; `dumpsys NAME` for one of them prints only the
    /// `DUMP OF SERVICE` header; any other name is `Can't find service`, status 0 as the real one.
    pub(super) fn cmd_dumpsys(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let name = args.iter().find(|arg| !arg.starts_with('-'));
        let listing = args.is_empty() || args.contains(&"-l");
        match name {
            Some(name) if !listing => {
                if SERVICES.contains(name) {
                    CommandResult::stdout(format!("DUMP OF SERVICE {name}:\n"))
                } else {
                    CommandResult::stdout(format!("Can't find service: {}\n", clip(name)))
                }
            }
            _ => {
                let mut text = String::from("Currently running services:\n");
                for service in SERVICES {
                    text.push_str("  ");
                    text.push_str(service);
                    text.push('\n');
                }
                CommandResult::stdout(text)
            }
        }
    }

    /// `screencap [-p] [PATH]`: with a path, a placeholder file in the session overlay and no
    /// output; with none, no output (the real tool streams raw pixels to standard output, which is
    /// not modeled).
    pub(super) fn cmd_screencap(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let png = args.contains(&"-p");
        let Some(&name) = args.iter().rfind(|arg| !arg.starts_with('-')) else {
            return CommandResult::silent(0);
        };
        let path = self.resolve_logical(name);
        let bytes = if png { SCREENCAP_PNG } else { SCREENCAP_RAW };
        match self.traced_write_file(&path, bytes) {
            Ok(()) => CommandResult::silent(0),
            Err(error) => {
                let why = match &error {
                    FsError::ReadOnly => "Read-only file system",
                    FsError::IsADirectory => "Is a directory",
                    FsError::NotADirectory => "Not a directory",
                    other => budget_refusal_text(other).unwrap_or("No such file or directory"),
                };
                CommandResult::stderr(1, format!("screencap: {}: {why}\n", clip(name)))
            }
        }
    }

    /// `logcat -c` clears and prints nothing; every other form prints the same fixed lines and
    /// ends, so it never hangs.
    pub(super) fn cmd_logcat(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        if args.contains(&"-c") {
            return CommandResult::silent(0);
        }
        CommandResult::stdout(LOGCAT)
    }
}

/// `pm list packages` for the options after `packages`: `-f` adds the apk path, `-3` (third-party)
/// and `-d` (disabled) match nothing here, and a bare word filters by substring.
fn pm_list(options: &[&str]) -> CommandResult {
    let with_path = options.contains(&"-f");
    if options.contains(&"-3") || options.contains(&"-d") {
        return CommandResult::silent(0);
    }
    let filter = options.iter().find(|arg| !arg.starts_with('-'));
    let mut text = String::new();
    for (name, apk) in PACKAGES {
        if filter.is_some_and(|f| !name.contains(*f)) {
            continue;
        }
        if with_path {
            text.push_str(&format!("package:{apk}={name}\n"));
        } else {
            text.push_str(&format!("package:{name}\n"));
        }
    }
    CommandResult::stdout(text)
}
