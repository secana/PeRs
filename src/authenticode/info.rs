use alloc::string::String;

use der::asn1::ObjectIdentifier;
use x509_cert::Certificate;

use super::asn1::{TAG_OCTET_STRING, TAG_SEQUENCE, Tlv};
use super::crypto::HashAlgorithm;
use super::signed_data::{OID_SIGNING_TIME, SignedData, SignerInfo};
use super::time::{Timestamp, decode_time};
use crate::PeFile;
use crate::error::{Result, malformed};
use crate::pe::WinCertificateType;

const OID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
const OID_RFC3161_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

/// Information about the Authenticode signature of a PE file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticodeInfo<'a> {
    /// Serial number of the first signer's certificate as uppercase hex string.
    pub signer_serial_number: Option<String>,
    /// The Authenticode hash stored in the signature.
    pub signed_hash: Option<&'a [u8]>,
    /// True if the stored hash matches the file and all signatures are valid. The certificate
    /// chain and its trust are not checked.
    pub is_valid: bool,
    pub signing_certificate: Option<Certificate>,
    /// Time stamp of an RFC 3161 or legacy counter signature.
    pub signing_timestamp: Option<Timestamp>,
}

impl<'a> AuthenticodeInfo<'a> {
    /// `Ok(None)` for unsigned files, an error if the certificate data cannot be decoded as
    /// PKCS#7 signed data.
    pub fn parse(pe_file: &PeFile<'a>) -> Result<Option<Self>> {
        let Some(win_certificate) = pe_file.win_certificate()? else {
            return Ok(None);
        };
        let signed_data = win_certificate
            .b_certificate
            .and_then(|bytes| SignedData::decode(bytes).ok())
            .ok_or(malformed("certificate table", "no PKCS#7 signed data"))?;

        let signer_serial_number = signed_data
            .signer_infos
            .first()
            .and_then(|si| signer_serial_number(&signed_data, si));
        let signed_hash = signed_hash(&signed_data);
        let is_valid = verify_hash(pe_file, signed_hash)? && signed_data.check_signatures().is_ok();
        let signing_certificate =
            if win_certificate.w_certificate_type == WinCertificateType::PkcsSignedData {
                signing_certificate(&signed_data, signer_serial_number.as_deref())?
            } else {
                None
            };
        let signing_timestamp = signing_timestamp(&signed_data);

        Ok(Some(Self {
            signer_serial_number,
            signed_hash,
            is_valid,
            signing_certificate,
            signing_timestamp,
        }))
    }
}

fn signer_serial_number(signed_data: &SignedData, signer: &SignerInfo) -> Option<String> {
    signed_data
        .signer_certificate(signer)
        .map(|c| hex::encode_upper(c.tbs_certificate.serial_number.as_bytes()))
}

/// The digest of the SpcIndirectDataContent: SEQUENCE { SpcAttributeTypeAndOptionalValue,
/// DigestInfo SEQUENCE { AlgorithmIdentifier, OCTET STRING } }.
fn signed_hash<'a>(signed_data: &SignedData<'a>) -> Option<&'a [u8]> {
    if signed_data.content_type != OID_SPC_INDIRECT_DATA {
        return None;
    }
    let spc = Tlv::parse_tagged(signed_data.content?, TAG_SEQUENCE).ok()?;
    let digest_info = spc.child(1, TAG_SEQUENCE).ok()?;
    Some(digest_info.child(1, TAG_OCTET_STRING).ok()?.value)
}

fn verify_hash(pe_file: &PeFile, signed_hash: Option<&[u8]>) -> Result<bool> {
    let Some(signed_hash) = signed_hash else {
        return Ok(false);
    };
    let Some(algorithm) = HashAlgorithm::from_digest_length(signed_hash.len()) else {
        return Ok(false);
    };
    Ok(pe_file.authenticode_hash(algorithm)? == signed_hash)
}

/// The certificate of the only signer with the given serial number. More or less than one such
/// signer is an error.
fn signing_certificate(
    signed_data: &SignedData,
    serial_number: Option<&str>,
) -> Result<Option<Certificate>> {
    let matching: alloc::vec::Vec<_> = signed_data
        .signer_infos
        .iter()
        .filter(|si| {
            match (
                signer_serial_number(signed_data, si).as_deref(),
                serial_number,
            ) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => true,
                _ => false,
            }
        })
        .collect();
    match matching.as_slice() {
        [signer] => Ok(signed_data.signer_certificate(signer).cloned()),
        _ => Err(malformed(
            "PKCS#7 signed data",
            "not exactly one signer with the signing serial number",
        )),
    }
}

fn signing_timestamp(signed_data: &SignedData) -> Option<Timestamp> {
    signed_data.signer_infos.iter().find_map(|signer| {
        signer
            .unsigned_attributes
            .iter()
            .filter(|a| a.oid == OID_RFC3161_TIMESTAMP)
            .find_map(|a| rfc3161_timestamp(a.values.first()?).ok())
            .or_else(|| counter_signature_timestamp(signer).ok().flatten())
    })
}

/// The `genTime` of the TSTInfo in an RFC 3161 time stamp token.
fn rfc3161_timestamp(token: &Tlv) -> Result<Timestamp> {
    let token = SignedData::decode(token.raw)?;
    let tst_info = Tlv::parse_tagged(token.content.unwrap_or_default(), TAG_SEQUENCE)?;
    let gen_time = tst_info
        .children()?
        .get(4)
        .copied()
        .ok_or(malformed("TSTInfo", "missing genTime"))?;
    decode_time(&gen_time)
}

/// The signing time attribute of the first legacy counter signer that has one.
fn counter_signature_timestamp(signer: &SignerInfo) -> Result<Option<Timestamp>> {
    for counter_signer in signer.counter_signers()? {
        if let Some(value) = counter_signer
            .signed_attribute(&OID_SIGNING_TIME)
            .and_then(|a| a.values.first())
        {
            return decode_time(value).map(Some);
        }
    }
    Ok(None)
}
