use crate::common::load;
use pers::PeFile;
use pers::authenticode::CrlUrlList;

#[test]
fn crl_url_list_given_signed_binary_returns_crl_urls() {
    let data = load("pidgin.exe");
    let crl_url_list = PeFile::parse(&data)
        .unwrap()
        .crl_url_list()
        .unwrap()
        .unwrap();

    assert_eq!(
        vec!["http://crl.startssl.com/crtc2-crl.crl".to_string()],
        crl_url_list.urls
    );
}

#[test]
fn crl_url_list_given_unsigned_binary_returns_none() {
    let data = load("TLSCallback_x86.exe");

    assert!(
        PeFile::parse(&data)
            .unwrap()
            .crl_url_list()
            .unwrap()
            .is_none()
    );
}

/// A DER element with a short length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut element = vec![tag, content.len() as u8];
    element.extend_from_slice(content);
    element
}

/// A distribution point with one URI as full name.
fn distribution_point(uri: &str) -> Vec<u8> {
    tlv(0x30, &tlv(0xA0, &tlv(0xA0, &tlv(0x86, uri.as_bytes()))))
}

#[test]
fn crl_url_list_given_raw_extension_returns_http_and_ldap_urls() {
    let http = "http://crl.example.com/ca.crl";
    let ldap = "ldap://ldap.example.com/CN=CA?certificateRevocationList";
    let raw = tlv(
        0x30,
        &[distribution_point(http), distribution_point(ldap)].concat(),
    );

    let crl_url_list = CrlUrlList::from_raw(&raw).unwrap();

    assert_eq!(vec![http.to_string(), ldap.to_string()], crl_url_list.urls);
}

#[test]
fn crl_url_list_given_invalid_extension_returns_error() {
    assert!(CrlUrlList::from_raw(&[0x30, 0x05, 0x00]).is_err());
}
