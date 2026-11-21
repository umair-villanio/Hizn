//! Signing certificate extraction and analysis.
//!
//! Extracts the first signer certificate from the APK Signing Block (v2/v3) or
//! the v1 PKCS#7 JAR signature, then describes it the way the Node analyzer did
//! (node-forge + crypto), so the report's `certificate` section matches.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::report::{CertInfo, Finding, Report, Severity};

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

/// First signer certificate (DER) from the APK Signing Block (v2 id 0x7109871a,
/// v3 0xf05368c0), which sits right before the central directory.
pub fn cert_from_signing_block(buf: &[u8], cd_offset: usize) -> Option<Vec<u8>> {
    if cd_offset < 32 || cd_offset > buf.len() {
        return None;
    }
    if &buf[cd_offset - 16..cd_offset] != b"APK Sig Block 42" {
        return None;
    }
    let block_size = u64le(buf, cd_offset - 24) as usize;
    let block_start = cd_offset.checked_sub(block_size + 8)?;
    let mut p = block_start + 8;
    let end = cd_offset - 24;
    while p + 12 <= end {
        let pair_len = u64le(buf, p) as usize;
        p += 8;
        if pair_len < 4 || p + pair_len > end + 8 {
            break;
        }
        let id = u32le(buf, p);
        let val_start = p + 4;
        if (id == 0x7109871a || id == 0xf05368c0)
            && let Some(cert) = first_cert_from_scheme(buf, val_start)
        {
            return Some(cert);
        }
        p += pair_len;
    }
    None
}

/// Walk signers → first signer → signed data → certificates → first cert DER.
fn first_cert_from_scheme(buf: &[u8], start: usize) -> Option<Vec<u8>> {
    let mut p = start;
    p += 4; // signers sequence length
    p += 4; // first signer length
    p += 4; // signed-data length
    if p + 4 > buf.len() {
        return None;
    }
    let digests_len = u32le(buf, p) as usize;
    p += 4 + digests_len; // skip digests
    p += 4; // certificates sequence length
    if p + 4 > buf.len() {
        return None;
    }
    let cert_len = u32le(buf, p) as usize;
    p += 4;
    if cert_len == 0 || p + cert_len > buf.len() {
        return None;
    }
    Some(buf[p..p + cert_len].to_vec())
}

/// First X.509 certificate (DER) from a v1 PKCS#7 signature block.
pub fn pkcs7_first_cert_der(pkcs7_der: &[u8]) -> Option<Vec<u8>> {
    let ci = ContentInfo::from_der(pkcs7_der).ok()?;
    let sd = ci.content.decode_as::<SignedData>().ok()?;
    let certs = sd.certificates?;
    certs.0.iter().find_map(|choice| match choice {
        cms::cert::CertificateChoices::Certificate(cert) => cert.to_der().ok(),
        _ => None,
    })
}

/// An X.509 signature-algorithm OID → the name node-forge would print.
fn sig_alg_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.10040.4.3" => "dsa-with-sha1",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-sha256",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        other => return other.to_owned(),
    }
    .to_owned()
}

/// A DN attribute-type OID → the short name node-forge prints (`a.shortName ||
/// a.name`).
fn dn_short(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.5" => "serialName",
        "2.5.4.4" => "surname",
        "2.5.4.42" => "givenName",
        "1.2.840.113549.1.9.1" => "E",
        other => return other.to_owned(),
    }
    .to_owned()
}

/// Format a DN as forge's `shortName=value, …`, in the order the names appear.
fn format_dn(name: &X509Name) -> String {
    name.iter()
        .flat_map(|rdn| rdn.iter())
        .map(|attr| {
            let oid = attr.attr_type().to_id_string();
            let value = attr
                .attr_value()
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(attr.attr_value().data).into_owned());
            format!("{}={}", dn_short(&oid), value)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `Date.toISOString()`: `YYYY-MM-DDTHH:MM:SS.000Z`.
fn iso(ts: ASN1Time) -> String {
    let t = ts.to_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Parse and describe the certificate, filling `report.certificate` and adding
/// any certificate findings.
pub fn analyze_cert_der(cert_der: &[u8], scheme: &str, report: &mut Report) {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        report.push_error(format!(
            "Certificate: could not parse the signing certificate ({scheme})."
        ));
        return;
    };

    let subject = format_dn(cert.subject());
    let issuer = format_dn(cert.issuer());
    let sha1 = hex(&Sha1::digest(cert_der));
    let sha256 = hex(&Sha256::digest(cert_der));
    let serial = hex(cert.raw_serial());
    let sig_alg = sig_alg_name(&cert.signature_algorithm.algorithm.to_id_string());

    // Public key: RSA → "RSA" + modulus bits (forge path); EC/other → the node
    // crypto type name, no key size.
    let (key_alg, key_bits) = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => ("RSA".to_owned(), Some((rsa.key_size()) as u64)),
        Ok(PublicKey::EC(_)) => ("ec".to_owned(), None),
        Ok(_) => {
            let oid = cert.public_key().algorithm.algorithm.to_id_string();
            (public_key_type(&oid), None)
        }
        Err(_) => ("unknown".to_owned(), None),
    };

    let not_before = cert.validity().not_before;
    let not_after = cert.validity().not_after;
    let self_signed = subject == issuer;

    report.certificate = Some(CertInfo {
        subject: subject.clone(),
        issuer,
        serial_number: Some(serial),
        valid_from: Some(iso(not_before)),
        valid_to: Some(iso(not_after)),
        signature_algorithm: Some(sig_alg.clone()),
        public_key_algorithm: Some(key_alg.clone()),
        key_size_bits: key_bits,
        sha1: Some(sha1),
        sha256: Some(sha256),
        self_signed: Some(self_signed),
        signature_scheme: Some(scheme.to_owned()),
    });

    // Certificate analysis.
    let sig_lower = sig_alg.to_lowercase();
    if sig_lower.contains("sha1") || sig_lower.contains("md5") {
        report.add(
            Finding::new(
                "Certificate",
                format!("Weak signature algorithm ({sig_alg})"),
                Severity::High,
            )
            .detail("SHA-1/MD5 signatures are collision-prone; re-sign with SHA-256."),
        );
    }
    if key_alg == "RSA" && key_bits.is_some_and(|b| b < 2048) {
        report.add(
            Finding::new(
                "Certificate",
                format!("Weak RSA key ({}-bit)", key_bits.unwrap()),
                Severity::High,
            )
            .detail("Use a ≥2048-bit RSA (or EC) signing key."),
        );
    }
    if subject.to_lowercase().contains("cn=android debug") {
        report.add(
            Finding::new(
                "Certificate",
                "Signed with the Android debug certificate",
                Severity::High,
            )
            .detail("A debug-signed APK must never be released."),
        );
    }
    if not_after.timestamp() < now_unix() {
        report.add(
            Finding::new(
                "Certificate",
                "Signing certificate expired",
                Severity::Medium,
            )
            .detail(format!("notAfter {}", iso(not_after))),
        );
    }
}

fn public_key_type(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "rsa",
        "1.2.840.10045.2.1" => "ec",
        "1.3.101.112" => "ed25519",
        "1.3.101.113" => "ed448",
        _ => "unknown",
    }
    .to_owned()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
