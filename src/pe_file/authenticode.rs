//! Authenticode accessors and the Authenticode hash of the file.

use alloc::vec::Vec;

use x509_cert::Certificate;

use super::PeFile;
use crate::authenticode::{AuthenticodeInfo, CrlUrlList, HashAlgorithm};
use crate::bytes::Bytes;
use crate::error::{Result, malformed};
use crate::lazy::cached;
use crate::pe::{DataDirectoryType, field_offset};

impl<'a> PeFile<'a> {
    /// The Authenticode signature, `Ok(None)` for unsigned files and an error if the certificate
    /// data cannot be decoded.
    pub fn authenticode_info(&self) -> Result<Option<&AuthenticodeInfo<'a>>> {
        cached(&self.cache.authenticode, || AuthenticodeInfo::parse(self)).map(Option::as_ref)
    }

    /// The certificate the file was signed with.
    pub fn signing_certificate(&self) -> Result<Option<&Certificate>> {
        Ok(self
            .authenticode_info()?
            .and_then(|i| i.signing_certificate.as_ref()))
    }

    /// True if the file is signed. The signature is not validated.
    pub fn is_signed(&self) -> bool {
        self.signing_certificate().is_ok_and(|c| c.is_some())
    }

    /// True if the signature is valid. The trust of the certificate chain is not checked.
    pub fn has_valid_signature(&self) -> bool {
        self.authenticode_info()
            .is_ok_and(|i| i.is_some_and(|i| i.is_valid))
    }

    /// The CRL URLs of the signing certificate, `Ok(None)` if the file is not signed.
    pub fn crl_url_list(&self) -> Result<Option<CrlUrlList>> {
        self.signing_certificate()?
            .map(CrlUrlList::from_certificate)
            .transpose()
    }

    /// The Authenticode hash: the hash of the file without the checksum, the certificate table
    /// entry and the certificate data.
    pub fn authenticode_hash(&self, algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        let nt_headers = &self.nt_headers;
        let certificate_table_entry = nt_headers.data_directory_offset(DataDirectoryType::Security);
        let size_of_headers = nt_headers.optional_header.size_of_headers() as usize;
        let check_sum = nt_headers.optional_header_offset() + field_offset::CHECK_SUM;
        let bytes = Bytes(self.data);
        let range = |start: usize, end: usize| {
            end.checked_sub(start)
                .ok_or(malformed("Authenticode hash", "overlapping ranges"))
                .and_then(|length| bytes.slice(start, length))
        };

        let mut hasher = algorithm.hasher();
        hasher.update(range(0, check_sum)?);
        hasher.update(range(check_sum + 4, certificate_table_entry)?);
        hasher.update(range(certificate_table_entry + 8, size_of_headers)?);
        let mut end_of_hashed_data = size_of_headers;
        if let Some(certificate) = self.win_certificate()? {
            hasher.update(range(size_of_headers, certificate.offset)?);
            let size = self.data_directory(DataDirectoryType::Security).size() as usize;
            end_of_hashed_data = certificate.offset + size;
        }
        if self.data.len() > end_of_hashed_data {
            hasher.update(range(end_of_hashed_data, self.data.len())?);
        }
        Ok(hasher.finalize())
    }
}
