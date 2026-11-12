//! Mints a private CA, a gateway server cert, and a per-collector client cert with
//! `rcgen`, isolated in its own crate so `rcgen` never enters the daemon dependency
//! trees (the gateway and shipper only ever load PEMs `provision` already wrote). Also mints
//! per-sensor self-signed TLS leaves (`provision_sensor_tls`) for the honeypot sensors' own TLS
//! listeners.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("collector id is not a safe filename component: {0:?}")]
    InvalidCollectorId(String),
    #[error("sensor name is not a safe filename component: {0:?}")]
    InvalidSensorName(String),
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("failed to write {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Writes through a newly-created file in the destination directory, then atomically renames it
/// into place. On Unix the requested mode is applied when the inode is created, so a private key
/// is never briefly visible with the process's ordinary (often `0644`) creation mode. The rename
/// also replaces a pre-existing symlink itself instead of following it to an attacker-chosen file.
fn write(path: PathBuf, contents: impl AsRef<[u8]>, mode: u32) -> Result<(), ProvisionError> {
    let parent = path
        .parent()
        .expect("provisioned paths always have a parent");
    let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".provision-certs.{}.{}.tmp",
        std::process::id(),
        temp_id
    ));

    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }

        let mut file = options.open(&temp_path)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&temp_path, &path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if let Err(source) = result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(ProvisionError::Io { path, source });
    }
    Ok(())
}

fn is_safe_path_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
}

/// Mint a private CA, a gateway server leaf (SAN = `gateway_dns`), and a collector
/// client leaf (CN = `collector_id`) signed by that CA, writing all five PEM files
/// into `out`. Key files (`gateway.key`, `<collector_id>.key`) are written `0600`.
pub fn provision(out: &Path, gateway_dns: &str, collector_id: &str) -> Result<(), ProvisionError> {
    if !is_safe_path_component(collector_id) {
        return Err(ProvisionError::InvalidCollectorId(collector_id.to_string()));
    }

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "propolis collector CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    write(out.join("ca.crt"), ca_cert.pem(), 0o644)?;

    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let gateway_key = KeyPair::generate()?;
    let mut gateway_params = CertificateParams::new(vec![gateway_dns.to_string()])?;
    gateway_params.distinguished_name = DistinguishedName::new();
    gateway_params
        .distinguished_name
        .push(DnType::CommonName, gateway_dns);
    let gateway_cert = gateway_params.signed_by(&gateway_key, &issuer)?;
    write(out.join("gateway.crt"), gateway_cert.pem(), 0o644)?;
    let gateway_key_path = out.join("gateway.key");
    write(gateway_key_path, gateway_key.serialize_pem(), 0o600)?;

    let collector_key = KeyPair::generate()?;
    let mut collector_params = CertificateParams::new(Vec::<String>::new())?;
    collector_params.distinguished_name = DistinguishedName::new();
    collector_params
        .distinguished_name
        .push(DnType::CommonName, collector_id);
    let collector_cert = collector_params.signed_by(&collector_key, &issuer)?;
    write(
        out.join(format!("{collector_id}.crt")),
        collector_cert.pem(),
        0o644,
    )?;
    let collector_key_path = out.join(format!("{collector_id}.key"));
    write(collector_key_path, collector_key.serialize_pem(), 0o600)?;

    Ok(())
}

/// Common name and only SAN of every per-sensor self-signed certificate. Fixed on purpose: a
/// deploy-host name here would fingerprint the box to anyone who scans the TLS port, and an
/// operator who wants a real name supplies a real certificate (kept untouched, see below).
pub const SENSOR_TLS_COMMON_NAME: &str = "localhost";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorTlsOutcome {
    /// A new key and self-signed certificate were written.
    Minted,
    /// Both files already existed and were left untouched.
    Kept,
}

/// Mint a self-signed leaf for one sensor into `out` as `<sensor>.crt` (0644) and `<sensor>.key`
/// (0600), unless BOTH already exist (an earlier mint or an operator-supplied real certificate),
/// in which case neither is touched. `out` must already exist (deploy/provision.sh owns its mode).
/// Existence is judged by `std::fs::metadata` (follows symlinks) being a non-empty regular file, so
/// an operator's symlink to a real certificate counts as present and is never replaced.
/// If only one of the pair is present (an interrupted mint), the stray is removed first so a new
/// pair is never mixed with an old half: a mismatched pair would make the sensor refuse to start
/// and a re-run would then skip it forever. The certificate is written before the key.
pub fn provision_sensor_tls(out: &Path, sensor: &str) -> Result<SensorTlsOutcome, ProvisionError> {
    if !is_safe_path_component(sensor) {
        return Err(ProvisionError::InvalidSensorName(sensor.to_string()));
    }
    let crt_path = out.join(format!("{sensor}.crt"));
    let key_path = out.join(format!("{sensor}.key"));
    let present = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() > 0);
    if present(&crt_path) && present(&key_path) {
        return Ok(SensorTlsOutcome::Kept);
    }
    for stray in [&crt_path, &key_path] {
        match std::fs::remove_file(stray) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ProvisionError::Io {
                    path: stray.clone(),
                    source,
                });
            }
        }
    }
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![SENSOR_TLS_COMMON_NAME.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, SENSOR_TLS_COMMON_NAME);
    let cert = params.self_signed(&key)?;
    write(crt_path, cert.pem(), 0o644)?;
    write(key_path, key.serialize_pem(), 0o600)?;
    Ok(SensorTlsOutcome::Minted)
}
