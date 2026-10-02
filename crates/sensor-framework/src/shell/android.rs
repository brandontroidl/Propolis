//! `getprop` and `setprop`: how an attacker on the ADB shell fingerprints the phone
//! (`getprop ro.product.model`, `getprop ro.build.version.release`, `getprop ro.product.cpu.abi`).
//!
//! The values come from one table built from [`crate::persona`]'s Android half, so the properties
//! cannot contradict `uname`, `/system/build.prop` or the banner ADB sent. `setprop` writes only
//! a session overlay held by the shell; nothing reaches the host, the filesystem or the network.
//!
//! The overlay lives on [`FakeShell`] rather than in a shell frame's state: Android's property
//! service is system-wide, so a `setprop` run in a subshell, pipeline stage or `$( )` must survive
//! it, where frame state is copied and discarded.
//!
//! Both commands exist only on the Android shell; on bash they are "not found". They are toolbox
//! commands, not BusyBox applets. Wording that no capture backs is marked `[unverified]`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::persona;

pub(super) fn register(r: &mut Registry) {
    r.register_if(
        "getprop",
        android,
        HandlerId::Getprop,
        FakeShell::cmd_getprop,
    );
    r.register_if(
        "setprop",
        android,
        HandlerId::Setprop,
        FakeShell::cmd_setprop,
    );
}

fn android(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh
}

/// The ABI of a Nexus 5: 32-bit ARM, the same device `uname -m` reports as `armv7l` and
/// `/system/build.prop` as `ro.product.cpu.abi`.
const ABI: &str = "armeabi-v7a";
const ABI2: &str = "armeabi";
const ABILIST: &str = "armeabi-v7a,armeabi";
const MANUFACTURER: &str = "LGE";
const BRAND: &str = "google";
const PLATFORM: &str = "msm8974";
/// The build number inside [`persona::android_fingerprint`].
const INCREMENTAL: &str = "3565761";
/// [unverified] the December 2016 patch level carried by build M4B30Z; derived from the build id,
/// not captured from a device.
const SECURITY_PATCH: &str = "2016-12-01";

/// Android's `PROP_NAME_MAX` and `PROP_VALUE_MAX`: a longer key, or a longer value outside `ro.`,
/// is refused by the property service.
const NAME_MAX: usize = 32;
const VALUE_MAX: usize = 92;
/// Properties a session may add, so a loop of `setprop` cannot grow the overlay without bound.
const OVERLAY_MAX: usize = 512;

const SETPROP_USAGE: &str = "usage: setprop <key> <value>\n";
const SETPROP_FAILED: &str = "could not set property\n";

/// The modeled properties, from the persona alone.
fn table() -> Vec<(&'static str, String)> {
    vec![
        ("ro.build.id", persona::ANDROID_BUILD_ID.to_string()),
        (
            "ro.build.display.id",
            format!("{} release-keys", persona::ANDROID_BUILD_ID),
        ),
        ("ro.build.version.incremental", INCREMENTAL.to_string()),
        ("ro.build.version.sdk", persona::ANDROID_SDK.to_string()),
        (
            "ro.build.version.release",
            persona::ANDROID_RELEASE.to_string(),
        ),
        ("ro.build.version.codename", "REL".to_string()),
        (
            "ro.build.version.security_patch",
            SECURITY_PATCH.to_string(),
        ),
        ("ro.build.type", "user".to_string()),
        ("ro.build.tags", "release-keys".to_string()),
        ("ro.build.fingerprint", persona::android_fingerprint()),
        ("ro.product.model", persona::ANDROID_MODEL.to_string()),
        ("ro.product.brand", BRAND.to_string()),
        ("ro.product.name", persona::ANDROID_DEVICE.to_string()),
        ("ro.product.device", persona::ANDROID_DEVICE.to_string()),
        ("ro.product.board", persona::ANDROID_DEVICE.to_string()),
        ("ro.product.manufacturer", MANUFACTURER.to_string()),
        ("ro.product.cpu.abi", ABI.to_string()),
        ("ro.product.cpu.abi2", ABI2.to_string()),
        ("ro.product.cpu.abilist", ABILIST.to_string()),
        ("ro.product.cpu.abilist32", ABILIST.to_string()),
        ("ro.board.platform", PLATFORM.to_string()),
        ("ro.hardware", persona::ANDROID_DEVICE.to_string()),
    ]
}

impl FakeShell {
    /// The value of `name`: the session overlay first, then the persona table.
    fn property(&self, name: &str) -> Option<String> {
        if let Some(value) = self.props.get(name) {
            return Some(value.clone());
        }
        table()
            .into_iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }

    /// `getprop` with no argument lists every property as `[name]: [value]`, sorted by name;
    /// `getprop NAME [DEFAULT]` prints the value, or the default (empty if none), for an unset
    /// name. Status is 0 either way. [unverified] from the AOSP 6.0 toolbox source, not a capture.
    pub(super) fn cmd_getprop(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let Some(name) = args.first() else {
            let mut all: std::collections::BTreeMap<String, String> = table()
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect();
            all.extend(self.props.iter().map(|(k, v)| (k.clone(), v.clone())));
            let listing: String = all
                .iter()
                .map(|(key, value)| format!("[{key}]: [{value}]\n"))
                .collect();
            return CommandResult::stdout(listing);
        };
        let value = self
            .property(name)
            .or_else(|| args.get(1).map(|default| (*default).to_string()))
            .unwrap_or_default();
        CommandResult::stdout(format!("{value}\n"))
    }

    /// `setprop NAME VALUE` stores the pair in the session overlay. adbd runs as root, so `ro.*`
    /// is writable here too. A name or value past the property service's limits, or a full
    /// overlay, fails as the service does. [unverified] wording, from the AOSP 6.0 toolbox.
    pub(super) fn cmd_setprop(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let (Some(name), Some(value), None) = (args.first(), args.get(1), args.get(2)) else {
            return CommandResult::stderr(1, SETPROP_USAGE);
        };
        let too_long =
            name.len() >= NAME_MAX || (value.len() >= VALUE_MAX && !name.starts_with("ro."));
        let full = !self.props.contains_key(*name) && self.props.len() >= OVERLAY_MAX;
        if name.is_empty() || too_long || full {
            return CommandResult::stderr(255, SETPROP_FAILED);
        }
        self.props.insert((*name).to_string(), (*value).to_string());
        CommandResult::silent(0)
    }
}
