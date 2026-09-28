//! Mints a private CA, a gateway server cert, and a per-collector client cert with
//! `rcgen`, isolated in its own crate so `rcgen` never enters the daemon dependency
//! trees (the gateway and shipper only ever load PEMs `provision` already wrote).

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
