// The compile-time version stamp, shared verbatim by `crates/propolis/build.rs` and
// `crates/console/build.rs` through `include!`.
//
// WHY IT EXISTS. `env!("CARGO_PKG_VERSION")` was the only thing either binary knew about itself,
// and the workspace version has not moved since 0.1.0, so "which code is this process actually
// running" had no answer at all. The console's fleet pane needs one: a deploy that built new
// binaries and never restarted the service leaves a box running code older than the code on disk,
// and nothing on the box could see that.
//
// WHY IT SHELLS OUT TO GIT RATHER THAN TAKING A CRATE. `vergen` and friends would mean vendoring a
// build-time dependency tree for three strings, into a workspace that vendors everything it
// builds. Two `Command::new("git")` calls have no such cost.
//
// WHY IT IS SHARED RATHER THAN DUPLICATED. Each binary stamps ITSELF: the fleet pane reports the
// revision of the process that is rendering it, not of some other crate that happened to be built
// alongside. That means two build scripts, and two copies of this logic would drift.
//
// FAILING SOFT IS THE POINT. A build from a tarball, a container without `git`, or a checkout with
// no `.git` yields "unknown", and the pane renders that as `not recorded` rather than `current`.
// A build that cannot identify itself must never be presented as a build that matches the deploy.

use std::process::Command;

/// Emits `PROPOLIS_GIT_SHA` and `PROPOLIS_BUILD_TIMESTAMP` for the crate being built.
///
/// `PROPOLIS_GIT_SHA` is the short commit id, with `+dirty` appended when the working tree had
/// uncommitted changes at build time, or the literal `unknown`. The dirty marker matters to the
/// verdict: no recorded commit describes a build made from a modified tree, so the pane treats it
/// as unrecorded rather than comparing it against the deploy stamp and calling it current.
fn emit_build_stamp() {
    // The commit id changes when HEAD moves (a checkout) and when the branch ref moves (a pull or
    // a commit), so both are watched. A path that does not exist simply makes cargo re-run this
    // script every build, which costs two `git` invocations and is the safe direction: a stale
    // stamp would report the wrong revision with no way to notice.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    if let Some(reference) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        println!("cargo:rerun-if-changed=../../.git/{reference}");
    }

    let sha = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(sha) if !sha.is_empty() => {
            let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
            if dirty { format!("{sha}+dirty") } else { sha }
        }
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=PROPOLIS_GIT_SHA={sha}");

    // SOURCE_DATE_EPOCH first, so a reproducible-build environment can pin this the way it pins
    // every other timestamp. Formatted here rather than by shelling out to `date`, which is one
    // more external tool this has no reason to depend on.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or_else(now_unix);
    println!(
        "cargo:rustc-env=PROPOLIS_BUILD_TIMESTAMP={}",
        rfc3339_utc(epoch)
    );
}

/// Runs `git` and returns its trimmed stdout, or `None` for any failure at all: no binary, no
/// repository, a non-zero exit, output that is not UTF-8. Every one of those means the same thing
/// here, which is that this build cannot identify itself.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Seconds since the Unix epoch as an RFC 3339 UTC timestamp, which is what the console parses
/// everywhere else it reads a time.
fn rfc3339_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs_of_day = epoch.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the Unix epoch to a civil (proleptic Gregorian) date. Howard Hinnant's
/// `civil_from_days`, which is the standard closed-form version of this conversion; it is here
/// because a build script that pulled in `chrono` would pull in a build-time dependency tree.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the era to start on 0000-03-01, which puts the leap day at the end of the year and
    // makes the month arithmetic below a single closed form.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
