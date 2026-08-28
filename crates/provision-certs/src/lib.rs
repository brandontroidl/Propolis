//! Mints a private CA, a gateway server cert, and a per-collector client cert with
//! `rcgen`, isolated in its own crate so `rcgen` never enters the daemon dependency
//! trees (the gateway and shipper only ever load PEMs `provision` already wrote).

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("failed to write {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn write(path: PathBuf, contents: impl AsRef<[u8]>) -> Result<(), ProvisionError> {
    std::fs::write(&path, contents).map_err(|source| ProvisionError::Io { path, source })
}

/// Restrict a written key file to owner-only read/write (`0600`).
#[cfg(unix)]
fn restrict_key_perms(path: &Path) -> Result<(), ProvisionError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        ProvisionError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_key_perms(_path: &Path) -> Result<(), ProvisionError> {
    Ok(())
}

/// Mint a private CA, a gateway server leaf (SAN = `gateway_dns`), and a collector
/// client leaf (CN = `collector_id`) signed by that CA, writing all five PEM files
/// into `out`. Key files (`gateway.key`, `<collector_id>.key`) are written `0600`.
pub fn provision(out: &Path, gateway_dns: &str, collector_id: &str) -> Result<(), ProvisionError> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "propolis collector CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    write(out.join("ca.crt"), ca_cert.pem())?;

    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let gateway_key = KeyPair::generate()?;
    let mut gateway_params = CertificateParams::new(vec![gateway_dns.to_string()])?;
    gateway_params.distinguished_name = DistinguishedName::new();
    gateway_params
        .distinguished_name
        .push(DnType::CommonName, gateway_dns);
    let gateway_cert = gateway_params.signed_by(&gateway_key, &issuer)?;
    write(out.join("gateway.crt"), gateway_cert.pem())?;
    let gateway_key_path = out.join("gateway.key");
    write(gateway_key_path.clone(), gateway_key.serialize_pem())?;
    restrict_key_perms(&gateway_key_path)?;

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
    )?;
    let collector_key_path = out.join(format!("{collector_id}.key"));
    write(collector_key_path.clone(), collector_key.serialize_pem())?;
    restrict_key_perms(&collector_key_path)?;

    Ok(())
}
