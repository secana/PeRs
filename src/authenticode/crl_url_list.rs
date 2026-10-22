use alloc::string::{String, ToString};
use alloc::vec::Vec;

use der::Decode;
use der::asn1::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

use crate::error::{Result, malformed};

const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");

/// The certificate revocation list URLs of a certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CrlUrlList {
    pub urls: Vec<String>,
}

impl CrlUrlList {
    /// The URIs of all CRL distribution points extensions of a certificate.
    pub fn from_certificate(certificate: &Certificate) -> Result<Self> {
        let mut urls = Vec::new();
        for extension in certificate.tbs_certificate.extensions.iter().flatten() {
            if extension.extn_id == OID_CRL_DISTRIBUTION_POINTS {
                urls.extend(Self::from_raw(extension.extn_value.as_bytes())?.urls);
            }
        }
        Ok(Self { urls })
    }

    /// The URIs of the full names in the DER encoded value of a CRL distribution points
    /// extension.
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let points = CrlDistributionPoints::from_der(raw)
            .map_err(|_| malformed("CRL distribution points", "invalid DER"))?;
        let urls = points
            .0
            .iter()
            .filter_map(|point| match &point.distribution_point {
                Some(DistributionPointName::FullName(names)) => Some(names),
                _ => None,
            })
            .flatten()
            .filter_map(|name| match name {
                GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect();
        Ok(Self { urls })
    }
}

impl core::fmt::Display for CrlUrlList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "CRL URLs:")?;
        for url in &self.urls {
            writeln!(f, "\t{url}")?;
        }
        Ok(())
    }
}
