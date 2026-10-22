use alloc::borrow::Cow;

use crate::bytes::Bytes;
use crate::error::Result;

/// The WIN_CERTIFICATE structure of the security directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WinCertificate<'a> {
    pub offset: usize,
    pub dw_length: u32,
    pub w_revision: u16,
    pub w_certificate_type: WinCertificateType,
    /// The certificate content, `None` if it exceeds the data.
    pub b_certificate: Option<&'a [u8]>,
}

impl<'a> WinCertificate<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let dw_length = bytes.u32(offset)?;
        Ok(Self {
            offset,
            dw_length,
            w_revision: bytes.u16(offset + 4)?,
            w_certificate_type: WinCertificateType::from(bytes.u16(offset + 6)?),
            b_certificate: (dw_length as usize)
                .checked_sub(8)
                .and_then(|length| bytes.slice(offset + 8, length).ok()),
        })
    }
}

pe_enum! {
    pub enum WinCertificateType: u16 {
        X509 = 0x0001,
        PkcsSignedData = 0x0002,
        Reserved1 = 0x0003,
        Pkcs1Sign = 0x0009,
    }
}

/// The copyright (architecture) data: a zero terminated ASCII string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Copyright<'a> {
    pub copyright_string: Cow<'a, str>,
}

impl<'a> Copyright<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        Ok(Self {
            copyright_string: Bytes(data).ascii_string(offset)?,
        })
    }
}
