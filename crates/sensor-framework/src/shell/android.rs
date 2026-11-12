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
//! Both commands exist only on the Android shell; on bash they are "not found". They are toybox
//! applets, not toolbox's or BusyBox's: `toys/android/getprop.c` and `setprop.c` of
//! `external/toybox` at tag `android-6.0.1_r81` are in its `ALL_TOOLS`, and
//! `system/core/toolbox` of that tag has no source for either. Their operand counts are
//! `toyopt`'s (`>2` and `<2>2`); the checks `setprop` makes before asking the property service are
//! that file's, in its words. Wording that no capture backs is marked `[unverified]`.
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

/// Bionic's `PROP_NAME_MAX` and `PROP_VALUE_MAX` (`sys/system_properties.h`, tag
/// `android-6.0.1_r81`): toybox's `setprop` refuses a name of 32 bytes or more and a value of 92 or
/// more, `ro.` names included.
const NAME_MAX: usize = 32;
const VALUE_MAX: usize = 92;
/// Properties a session may add, so a loop of `setprop` cannot grow the overlay without bound.
const OVERLAY_MAX: usize = 512;

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
    /// name. Status is 0 either way. From `getprop_main` of toybox 6.0.1, not a capture.
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
    /// is writable here too. The refusals are `setprop_main` of toybox 6.0.1 in order, each
    /// `setprop: <text>` with status 1; an empty name passes them all and the property service
    /// ignores it, so it is a silent success that stores nothing. A full overlay is the one
    /// failure `property_set` itself reports.
    pub(super) fn cmd_setprop(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
            return CommandResult::silent(0);
        };
        let fail = |text: Vec<u8>| {
            let mut line = b"setprop: ".to_vec();
            line.extend(text);
            line.push(b'\n');
            CommandResult::stderr(1, line)
        };
        let clip = |text: &str, max: usize| {
            text.bytes()
                .take(max.saturating_sub(1))
                .collect::<Vec<u8>>()
        };
        if name.len() >= NAME_MAX {
            let mut text = format!("name '{name}' too long; try '").into_bytes();
            text.extend(clip(name, NAME_MAX));
            text.push(b'\'');
            return fail(text);
        }
        if value.len() >= VALUE_MAX {
            let mut text = format!("value '{value}' too long; try '").into_bytes();
            text.extend(clip(value, VALUE_MAX));
            text.push(b'\'');
            return fail(text);
        }
        if name.starts_with('.') || name.ends_with('.') {
            return fail(b"property names must not start or end with '.'".to_vec());
        }
        if name.contains("..") {
            return fail(b"'..' is not allowed in a property name".to_vec());
        }
        if let Some(bad) = name
            .bytes()
            .find(|b| !b.is_ascii_alphanumeric() && !b"_.-".contains(b))
        {
            let mut text = b"invalid character '".to_vec();
            text.push(bad);
            text.extend_from_slice(format!("' in name '{name}'").as_bytes());
            return fail(text);
        }
        if name.is_empty() {
            return CommandResult::silent(0);
        }
        if !self.props.contains_key(*name) && self.props.len() >= OVERLAY_MAX {
            return fail(format!("failed to set property '{name}' to '{value}'").into_bytes());
        }
        self.props.insert((*name).to_string(), (*value).to_string());
        CommandResult::silent(0)
    }
}
