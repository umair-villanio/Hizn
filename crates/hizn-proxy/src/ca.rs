//! Root CA: load the persisted `~/.hizn` CA (or create one), and mint per-host
//! leaf certificates signed by it for TLS interception.
//!
//! The CA must stay stable across runs: devices and Firefox profiles that
//! imported it would otherwise reject every leaf (SEC_ERROR_BAD_SIGNATURE).
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// Leaf certificates kept in memory; the cache is cleared when it grows past this.
const MAX_CACHED_LEAVES: usize = 2000;

pub struct CertAuthority {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    /// One key pair shared by every leaf (as mockttp does), so minting a leaf
    /// is just a signature.
    leaf_key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<LeafCert>>>,
    fingerprint: String,
}

struct LeafCert {
    chain: Vec<CertificateDer<'static>>,
}

#[derive(Debug)]
pub struct CaError(pub String);

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CaError {}

fn err(context: &str, e: impl std::fmt::Display) -> CaError {
    CaError(format!("{context}: {e}"))
}

/// `~/.hizn`, the same directory the Node backend uses.
pub fn hizn_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".hizn")
}

impl CertAuthority {
    /// Reuse `<dir>/ca-key.pem` + `ca-cert.pem` if present; otherwise create a
    /// CA and try to persist it (falling back to in-memory for this run).
    pub fn load_or_create(dir: &Path) -> Result<Self, CaError> {
        let key_path = dir.join("ca-key.pem");
        let cert_path = dir.join("ca-cert.pem");

        if let (Ok(key), Ok(cert)) = (
            std::fs::read_to_string(&key_path),
            std::fs::read_to_string(&cert_path),
        ) && key.contains("PRIVATE KEY")
            && cert.contains("CERTIFICATE")
        {
            return Self::from_pem(&key, &cert);
        }

        let (key, cert) = generate_ca()?;
        if std::fs::create_dir_all(dir).is_ok() {
            let _ = write_private(&key_path, &key);
            let _ = std::fs::write(&cert_path, &cert);
        }
        Self::from_pem(&key, &cert)
    }

    pub fn from_pem(key_pem: &str, cert_pem: &str) -> Result<Self, CaError> {
        let ca_key = KeyPair::from_pem(key_pem).map_err(|e| err("CA key", e))?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, ca_key).map_err(|e| err("CA cert", e))?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| err("CA cert PEM", e))?;
        let leaf_key = KeyPair::generate().map_err(|e| err("leaf key", e))?;
        Ok(Self {
            fingerprint: fingerprint(&cert_der),
            cert_pem: cert_pem.to_owned(),
            cert_der,
            issuer,
            leaf_key,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate exactly as stored (served by `GET /api/ca`).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// First 16 hex chars of SHA-256 over the CA's DER — same as Node's
    /// `caFingerprint`.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// A TLS server config presenting a leaf for `host`, offering `alpn`.
    pub fn server_config(
        &self,
        host: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>, CaError> {
        let leaf = self.leaf(host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| err("TLS versions", e))?
                .with_no_client_auth()
                .with_single_cert(leaf.chain.clone(), key)
                .map_err(|e| err("TLS cert", e))?;
        config.alpn_protocols = alpn;
        Ok(Arc::new(config))
    }

    fn leaf(&self, host: &str) -> Result<Arc<LeafCert>, CaError> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let mut leaves = self.leaves.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(leaf) = leaves.get(&host) {
            return Ok(leaf.clone());
        }

        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![match host.parse() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.clone().try_into().map_err(|e| err("leaf SAN", e))?),
        }];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.as_str());
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);
        params.serial_number = Some(SerialNumber::from_slice(uuid::Uuid::new_v4().as_bytes()));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(|e| err("leaf cert", e))?;
        let leaf = Arc::new(LeafCert {
            chain: vec![cert.der().clone(), self.cert_der.clone()],
        });
        if leaves.len() >= MAX_CACHED_LEAVES {
            leaves.clear();
        }
        leaves.insert(host, leaf.clone());
        Ok(leaf)
    }
}

fn fingerprint(der: &CertificateDer<'_>) -> String {
    Sha256::digest(der.as_ref())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A new root CA with the same subject the Node backend uses. (New installs
/// get an ECDSA P-256 key; an existing RSA CA is always reused as-is.)
fn generate_ca() -> Result<(String, String), CaError> {
    let key = KeyPair::generate().map_err(|e| err("CA key", e))?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "XX");
    dn.push(DnType::OrganizationName, "hizn");
    dn.push(DnType::CommonName, "hizn CA - interception only");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    params.serial_number = Some(SerialNumber::from_slice(uuid::Uuid::new_v4().as_bytes()));
    let cert = params.self_signed(&key).map_err(|e| err("CA cert", e))?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// Write the private key owner-only where the platform supports it.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hizn-ca-test-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creates_persists_and_reloads_the_same_ca() {
        let dir = temp_dir("persist");
        let first = CertAuthority::load_or_create(&dir).unwrap();
        assert!(dir.join("ca-key.pem").is_file() && dir.join("ca-cert.pem").is_file());
        let second = CertAuthority::load_or_create(&dir).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 16);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn mints_and_caches_leaves_for_names_and_ips() {
        let dir = temp_dir("leaf");
        let ca = CertAuthority::load_or_create(&dir).unwrap();
        ca.server_config("Example.COM", vec![b"http/1.1".to_vec()])
            .unwrap();
        ca.server_config("example.com", vec![]).unwrap();
        ca.server_config("127.0.0.1", vec![]).unwrap();
        ca.server_config("[::1]", vec![]).unwrap();
        assert_eq!(ca.leaves.lock().unwrap().len(), 3);
        std::fs::remove_dir_all(dir).ok();
    }
}
