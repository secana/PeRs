//! PKCS#7 / CMS SignedData as used by Authenticode, with the verification semantics of .NET's
//! `SignedCms.CheckSignature(verifySignatureOnly: true)`: every signer and every legacy counter
//! signer must have a valid signature, the certificate chain is not checked.

use alloc::vec::Vec;

use der::Encode;
use der::asn1::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use super::asn1::{
    TAG_CONTEXT_0, TAG_CONTEXT_1, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
    Tlv,
};
use super::crypto::{HashAlgorithm, parse_certificate, verify_signature};
use crate::error::{Error, Result};

pub(crate) const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub(crate) const OID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub(crate) const OID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
pub(crate) const OID_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
pub(crate) const OID_COUNTER_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// A decoded SignedData structure. All byte slices point into the decoded input.
#[derive(Debug)]
pub(crate) struct SignedData<'a> {
    /// Type of the encapsulated content, e.g. SPC indirect data content for Authenticode.
    pub content_type: ObjectIdentifier,
    /// The encapsulated content: the inner value of an OCTET STRING, otherwise the complete
    /// encoded element (PKCS#7 style content like the Authenticode SpcIndirectDataContent).
    pub content: Option<&'a [u8]>,
    /// The bytes covered by the message digest attribute.
    hashable_content: Option<&'a [u8]>,
    pub certificates: Vec<Certificate>,
    pub signer_infos: Vec<SignerInfo<'a>>,
}

#[derive(Debug)]
pub(crate) enum SignerIdentifier<'a> {
    IssuerAndSerialNumber {
        issuer: &'a [u8],
        serial_number: &'a [u8],
    },
    SubjectKeyIdentifier(&'a [u8]),
}

#[derive(Debug)]
pub(crate) struct Attribute<'a> {
    pub oid: ObjectIdentifier,
    pub values: Vec<Tlv<'a>>,
}

#[derive(Debug)]
pub(crate) struct SignerInfo<'a> {
    pub sid: SignerIdentifier<'a>,
    pub digest_algorithm: ObjectIdentifier,
    /// The complete `[0] IMPLICIT` encoded signed attributes.
    signed_attributes_raw: Option<&'a [u8]>,
    pub signed_attributes: Vec<Attribute<'a>>,
    pub signature: &'a [u8],
    pub unsigned_attributes: Vec<Attribute<'a>>,
}

impl<'a> SignedData<'a> {
    /// Decode a ContentInfo with SignedData content.
    pub fn decode(data: &'a [u8]) -> Result<Self> {
        let content_info = Tlv::parse_tagged(data, TAG_SEQUENCE)?;
        if oid(&content_info.child(0, TAG_OID)?)? != OID_SIGNED_DATA {
            return Err(malformed("content is not SignedData"));
        }
        let signed_data =
            Tlv::parse_tagged(content_info.child(1, TAG_CONTEXT_0)?.value, TAG_SEQUENCE)?;
        let elements = signed_data.children()?;
        // Skip version and digest algorithms.
        let mut elements = elements.into_iter().skip(2);
        let encapsulated = elements
            .next()
            .ok_or_else(|| malformed("missing content info"))?;
        let (content_type, content) = decode_encapsulated_content(&encapsulated)?;

        let mut certificates = Vec::new();
        let mut signer_infos = Vec::new();
        for element in elements {
            match element.tag {
                TAG_CONTEXT_0 => certificates = decode_certificates(&element)?,
                TAG_SET => {
                    signer_infos = element
                        .children()?
                        .iter()
                        .map(SignerInfo::decode)
                        .collect::<Result<_>>()?;
                }
                _ => {}
            }
        }

        Ok(Self {
            content_type,
            content: content.map(|c| {
                if c.tag == TAG_OCTET_STRING {
                    c.value
                } else {
                    c.raw
                }
            }),
            hashable_content: content.map(|c| c.value),
            certificates,
            signer_infos,
        })
    }

    /// The certificate identified by the signer identifier.
    pub fn signer_certificate(&self, signer: &SignerInfo) -> Option<&Certificate> {
        self.certificates.iter().find(|c| signer.sid.matches(c))
    }

    /// Verify all signers and their counter signers.
    pub fn check_signatures(&self) -> Result<()> {
        if self.signer_infos.is_empty() {
            return Err(malformed("no signers"));
        }
        let content = self.hashable_content.unwrap_or_default();
        for signer in &self.signer_infos {
            self.check_signer(signer, content, Some(&self.content_type))?;
        }
        Ok(())
    }

    /// Verify one signer over `content` and recursively all of its counter signers, which sign
    /// the signature value of their parent.
    fn check_signer(
        &self,
        signer: &SignerInfo,
        content: &[u8],
        content_type: Option<&ObjectIdentifier>,
    ) -> Result<()> {
        let certificate = self
            .signer_certificate(signer)
            .ok_or_else(|| malformed("signer certificate not found"))?;
        let algorithm = HashAlgorithm::from_oid(&signer.digest_algorithm)
            .ok_or(Error::Unsupported("digest algorithm of the signer"))?;
        let content_digest = algorithm.digest(content);

        let signed_digest = match signer.signed_attributes_raw {
            None => content_digest,
            Some(raw) => {
                signer.check_message_digest(&content_digest)?;
                if let Some(expected) = content_type {
                    signer.check_content_type(expected)?;
                }
                // The signature covers the attributes encoded as SET OF instead of [0] IMPLICIT.
                let mut encoded = raw.to_vec();
                encoded[0] = TAG_SET;
                algorithm.digest(&encoded)
            }
        };
        verify_signature(certificate, algorithm, &signed_digest, signer.signature)?;

        for counter_signer in signer.counter_signers()? {
            self.check_signer(&counter_signer, signer.signature, None)?;
        }
        Ok(())
    }
}

impl<'a> SignerInfo<'a> {
    fn decode(tlv: &Tlv<'a>) -> Result<Self> {
        let elements = tlv.expect_tag(TAG_SEQUENCE)?.children()?;
        let mut elements = elements.into_iter().skip(1).peekable();
        let mut next = || {
            elements
                .next()
                .ok_or_else(|| malformed("incomplete SignerInfo"))
        };

        let sid = SignerIdentifier::decode(&next()?)?;
        let digest_algorithm = algorithm_oid(&next()?)?;
        let mut element = next()?;
        let (signed_attributes_raw, signed_attributes) = if element.tag == TAG_CONTEXT_0 {
            let attributes = decode_attributes(&element)?;
            let raw = element.raw;
            element = next()?;
            (Some(raw), attributes)
        } else {
            (None, Vec::new())
        };
        // Signature algorithm, not needed: the key type decides the verification.
        algorithm_oid(&element)?;
        let signature = next()?.expect_tag(TAG_OCTET_STRING)?.value;
        let unsigned_attributes = match next() {
            Ok(element) if element.tag == TAG_CONTEXT_1 => decode_attributes(&element)?,
            _ => Vec::new(),
        };

        Ok(Self {
            sid,
            digest_algorithm,
            signed_attributes_raw,
            signed_attributes,
            signature,
            unsigned_attributes,
        })
    }

    /// The legacy counter signatures (PKCS#9 countersignature attributes).
    pub fn counter_signers(&self) -> Result<Vec<SignerInfo<'a>>> {
        self.unsigned_attributes
            .iter()
            .filter(|a| a.oid == OID_COUNTER_SIGNATURE)
            .flat_map(|a| a.values.iter())
            .map(SignerInfo::decode)
            .collect()
    }

    pub fn signed_attribute(&self, oid: &ObjectIdentifier) -> Option<&Attribute<'a>> {
        self.signed_attributes.iter().find(|a| a.oid == *oid)
    }

    fn check_message_digest(&self, digest: &[u8]) -> Result<()> {
        let value = self
            .signed_attribute(&OID_MESSAGE_DIGEST)
            .and_then(|a| a.values.first())
            .ok_or_else(|| malformed("missing message digest attribute"))?;
        if value.expect_tag(TAG_OCTET_STRING)?.value != digest {
            return Err(malformed("message digest does not match the content"));
        }
        Ok(())
    }

    fn check_content_type(&self, expected: &ObjectIdentifier) -> Result<()> {
        match self
            .signed_attribute(&OID_CONTENT_TYPE)
            .and_then(|a| a.values.first())
        {
            Some(value) if oid(value)? != *expected => {
                Err(malformed("content type attribute does not match"))
            }
            _ => Ok(()),
        }
    }
}

impl<'a> SignerIdentifier<'a> {
    fn decode(tlv: &Tlv<'a>) -> Result<Self> {
        match tlv.tag {
            TAG_SEQUENCE => {
                let children = tlv.children()?;
                let issuer = children
                    .first()
                    .ok_or_else(|| malformed("missing issuer"))?;
                let serial = children
                    .get(1)
                    .ok_or_else(|| malformed("missing serial number"))?;
                Ok(Self::IssuerAndSerialNumber {
                    issuer: issuer.expect_tag(TAG_SEQUENCE)?.raw,
                    serial_number: serial.expect_tag(TAG_INTEGER)?.value,
                })
            }
            0x80 => Ok(Self::SubjectKeyIdentifier(tlv.value)),
            _ => Err(malformed("unknown signer identifier")),
        }
    }

    fn matches(&self, certificate: &Certificate) -> bool {
        let tbs = &certificate.tbs_certificate;
        match self {
            Self::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                tbs.serial_number.as_bytes() == *serial_number
                    && tbs.issuer.to_der().is_ok_and(|der| der == *issuer)
            }
            Self::SubjectKeyIdentifier(id) => tbs
                .extensions
                .iter()
                .flatten()
                .filter(|e| e.extn_id == OID_SUBJECT_KEY_IDENTIFIER)
                .any(|e| {
                    der::Decode::from_der(e.extn_value.as_bytes())
                        .is_ok_and(|ski: SubjectKeyIdentifier| ski.0.as_bytes() == *id)
                }),
        }
    }
}

/// Content type and the optional `[0] EXPLICIT` content of an EncapsulatedContentInfo.
fn decode_encapsulated_content<'a>(tlv: &Tlv<'a>) -> Result<(ObjectIdentifier, Option<Tlv<'a>>)> {
    let elements = tlv.expect_tag(TAG_SEQUENCE)?.children()?;
    let content_type = oid(elements
        .first()
        .ok_or_else(|| malformed("missing content type"))?)?;
    let content = elements
        .get(1)
        .map(|c| {
            c.expect_tag(TAG_CONTEXT_0)
                .and_then(|c| Tlv::parse(c.value))
        })
        .transpose()?;
    Ok((content_type, content))
}

/// The certificates of the `[0] IMPLICIT` certificate set. Other certificate formats are skipped.
fn decode_certificates(tlv: &Tlv) -> Result<Vec<Certificate>> {
    tlv.children()?
        .iter()
        .filter(|c| c.tag == TAG_SEQUENCE)
        .map(|c| parse_certificate(c.raw))
        .collect()
}

fn decode_attributes<'a>(tlv: &Tlv<'a>) -> Result<Vec<Attribute<'a>>> {
    tlv.children()?
        .iter()
        .map(|attribute| {
            let oid_tlv = attribute.child(0, TAG_OID)?;
            let values = attribute.child(1, TAG_SET)?.children()?;
            Ok(Attribute {
                oid: oid(&oid_tlv)?,
                values,
            })
        })
        .collect()
}

/// The OID of an AlgorithmIdentifier.
fn algorithm_oid(tlv: &Tlv) -> Result<ObjectIdentifier> {
    oid(&tlv.expect_tag(TAG_SEQUENCE)?.child(0, TAG_OID)?)
}

pub(crate) fn oid(tlv: &Tlv) -> Result<ObjectIdentifier> {
    ObjectIdentifier::from_bytes(tlv.expect_tag(TAG_OID)?.value)
        .map_err(|_| malformed("invalid OID"))
}

fn malformed(reason: &'static str) -> Error {
    crate::error::malformed("PKCS#7 signed data", reason)
}
