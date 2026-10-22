//! Hash algorithms and signature verification for Authenticode.

use alloc::vec::Vec;

use der::Decode;
use der::asn1::ObjectIdentifier;
use md5::Md5;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

use crate::error::{Error, Result, malformed};

const OID_MD5: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Hash algorithms supported for Authenticode hashes and signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        [
            (OID_MD5, Self::Md5),
            (OID_SHA1, Self::Sha1),
            (OID_SHA256, Self::Sha256),
            (OID_SHA384, Self::Sha384),
            (OID_SHA512, Self::Sha512),
        ]
        .into_iter()
        .find(|(o, _)| o == oid)
        .map(|(_, a)| a)
    }

    /// The algorithm producing digests of the given length.
    pub(crate) fn from_digest_length(length: usize) -> Option<Self> {
        match length {
            16 => Some(Self::Md5),
            20 => Some(Self::Sha1),
            32 => Some(Self::Sha256),
            48 => Some(Self::Sha384),
            64 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn hasher(self) -> Hasher {
        match self {
            Self::Md5 => Hasher::Md5(Md5::new()),
            Self::Sha1 => Hasher::Sha1(Sha1::new()),
            Self::Sha256 => Hasher::Sha256(Sha256::new()),
            Self::Sha384 => Hasher::Sha384(Sha384::new()),
            Self::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        hasher.update(data);
        hasher.finalize()
    }

    /// The DER encoded DigestInfo prefix of a PKCS#1 v1.5 signature.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Md5 => &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                0x05, 0x00, 0x04, 0x10,
            ],
            Self::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// An incremental hash of one of the [`HashAlgorithm`]s.
pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(h) => h.update(data),
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Md5(h) => h.finalize().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Verify a signature over `digest` with the public key of `certificate`. RSA signatures must be
/// PKCS#1 v1.5 with a DigestInfo, ECDSA signatures DER encoded on P-256 or P-384.
pub(crate) fn verify_signature(
    certificate: &Certificate,
    algorithm: HashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<()> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let key = spki.subject_public_key.raw_bytes();
    if spki.algorithm.oid == OID_RSA_ENCRYPTION {
        return verify_rsa(key, algorithm, digest, signature);
    }
    if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            .ok_or_else(invalid_key)?;
        if curve == OID_SECP256R1 {
            return verify_ecdsa!(p256, key, digest, signature);
        }
        if curve == OID_SECP384R1 {
            return verify_ecdsa!(p384, key, digest, signature);
        }
    }
    Err(Error::Unsupported("public key algorithm of the signer"))
}

fn verify_rsa(key: &[u8], algorithm: HashAlgorithm, digest: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = RsaPublicKey::from_pkcs1_der(key).map_err(|_| invalid_key())?;
    let scheme = Pkcs1v15Sign {
        hash_len: Some(digest.len()),
        prefix: algorithm.digest_info_prefix().into(),
    };
    public_key
        .verify(scheme, digest, signature)
        .map_err(invalid_signature)
}

/// Verify a DER encoded ECDSA signature with the curve crate `$curve`.
macro_rules! verify_ecdsa {
    ($curve:ident, $key:expr, $digest:expr, $signature:expr) => {{
        let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes($key).map_err(|_| invalid_key())?;
        let signature =
            $curve::ecdsa::Signature::from_der($signature).map_err(invalid_signature)?;
        key.verify_prehash($digest, &signature)
            .map_err(invalid_signature)
    }};
}
use verify_ecdsa;

fn invalid_signature<E>(_: E) -> Error {
    malformed("signature", "verification failed")
}

fn invalid_key() -> Error {
    malformed("public key", "cannot be decoded")
}

/// Parse a DER encoded certificate.
pub(crate) fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|_| malformed("certificate", "invalid DER"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = include_bytes!("../../tests/Authenticode/ecdsa_message.bin");

    fn verify(
        certificate: &[u8],
        algorithm: HashAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let certificate = parse_certificate(certificate).unwrap();
        verify_signature(
            &certificate,
            algorithm,
            &algorithm.digest(message),
            signature,
        )
        .is_ok()
    }

    #[test]
    fn verify_signature_ecdsa_p256_valid_and_tampered() {
        let certificate = include_bytes!("../../tests/Authenticode/ecdsa_p256.der");
        let signature = include_bytes!("../../tests/Authenticode/ecdsa_p256.sig");

        assert!(verify(
            certificate,
            HashAlgorithm::Sha256,
            MESSAGE,
            signature
        ));
        assert!(!verify(
            certificate,
            HashAlgorithm::Sha256,
            b"tampered",
            signature
        ));
    }

    #[test]
    fn verify_signature_ecdsa_p384_valid_and_tampered() {
        let certificate = include_bytes!("../../tests/Authenticode/ecdsa_p384.der");
        let signature = include_bytes!("../../tests/Authenticode/ecdsa_p384.sig");

        assert!(verify(
            certificate,
            HashAlgorithm::Sha384,
            MESSAGE,
            signature
        ));
        assert!(!verify(
            certificate,
            HashAlgorithm::Sha384,
            b"tampered",
            signature
        ));
    }
}
