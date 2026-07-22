use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::net::IpAddr;
use std::sync::Arc;

/// The production TLS configuration is intentionally built for each connection.
/// It keeps no resumption or credential state between independently admitted runs.
pub(super) fn production_client_config() -> Result<Arc<ClientConfig>, ()> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if roots.is_empty() {
        return Err(());
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| ())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// D-8C1 permits only DNS-name HTTPS targets.  This conversion must never use
/// the connected peer IP address as the certificate identity.
pub(super) fn server_name(host_ascii: &str) -> Result<ServerName<'static>, ()> {
    if host_ascii.parse::<IpAddr>().is_ok() {
        return Err(());
    }
    ServerName::try_from(host_ascii.to_owned()).map_err(|_| ())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // PUBLIC TEST FIXTURE – NOT A REAL SECRET.  This inert, long-lived test key and
    // certificate chain originate from tokio-rustls' public test fixtures.
    const LEAF_CERT_B64: &str = concat!(
        "MIIBszCCAVmgAwIBAgIUUg3keFcU1xXWK8BNVb1KynPulV8wCgYIKoZIzj0EAwIw",
        "JjEkMCIGA1UEAwwbUnVzdGxzIFJvYnVzdCBSb290IC0gUnVuZyAyMCAXDTc1MDEw",
        "MTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAhMR8wHQYDVQQDDBZyY2dlbiBzZWxm",
        "IHNpZ25lZCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEud6w4gtZ0xbw",
        "J3E69SSMy5TZfdIifl9L5ZY+hgEe4UiUsBWS32f6Y5NR5Jo8FO1f6o13b3+FvVHR",
        "EHCGdvppL6NoMGYwFQYDVR0RBA4wDIIKZm9vYmFyLmNvbTAdBgNVHSUEFjAUBggr",
        "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFELvxbj5tD75n4pYFvJyr+c8qVEi",
        "MA8GA1UdEwEB/wQFMAMBAQAwCgYIKoZIzj0EAwIDSAAwRQIhALxSSdUsrRFnwNMu",
        "/doBqI8i8u5HdohVAheFTDwObkOMAiASSjULUtkWSD15u/7Sr01Wm9J1MpqW1pob",
        "BVqU3CNRlA=="
    );
    const ROOT_CERT_B64: &str = concat!(
        "MIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw",
        "HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY",
        "DzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw",
        "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+",
        "5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP",
        "BgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP",
        "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop",
        "PAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik",
        "cy4eNw=="
    );
    const INTERMEDIATE_CERT_B64: &str = concat!(
        "MIIBiTCCATCgAwIBAgIUHWiVYIvMMWoZEFYvSz46COf2FqowCgYIKoZIzj0EAwIw",
        "HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY",
        "DzQwOTYwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtSdXN0bHMgUm9idXN0IFJvb3Qg",
        "LSBSdW5nIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAOCcBD7dXjmAZ3te5",
        "D47cCJ9ec93PWv7BKYIL826CJsKfXQOGrBTthLm77hXLhHu6uv8E5QXNLZpfowLQ",
        "Do1ao0MwQTAPBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRdza76r11Ok9vRmlg6",
        "Nn/wL/N+jTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFmZrXeK",
        "hnfkahocvkhhNT3cDv1LWf6WBoFaCiBwZXFPAiARaKRiSCMG7PCHmSqFe82TBVmL",
        "odHGogAVax1Dh/aYAA=="
    );
    const LEAF_KEY_B64: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTbAQpfjAT46fgF4B",
        "mP15n37woNG5ZNJmwcqsred/7tmhRANCAAS53rDiC1nTFvAncTr1JIzLlNl90iJ+",
        "X0vllj6GAR7hSJSwFZLfZ/pjk1HkmjwU7V/qjXdvf4W9UdEQcIZ2+mkv"
    );

    fn decode_fixture_base64(input: &str) -> Vec<u8> {
        fn value(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("fixture contains invalid base64"),
            }
        }

        let bytes = input.as_bytes();
        assert_eq!(bytes.len() % 4, 0, "fixture has complete base64 groups");
        let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
        for group in bytes.chunks_exact(4) {
            let a = value(group[0]);
            let b = value(group[1]);
            output.push((a << 2) | (b >> 4));
            if group[2] != b'=' {
                let c = value(group[2]);
                output.push((b << 4) | (c >> 2));
                if group[3] != b'=' {
                    output.push((c << 6) | value(group[3]));
                }
            }
        }
        output
    }

    pub(crate) fn fixture_server_config(alpn: Vec<Vec<u8>>) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(decode_fixture_base64(LEAF_CERT_B64)),
                    CertificateDer::from(decode_fixture_base64(INTERMEDIATE_CERT_B64)),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode_fixture_base64(
                    LEAF_KEY_B64,
                ))),
            )
            .unwrap();
        config.alpn_protocols = alpn;
        Arc::new(config)
    }

    pub(crate) fn fixture_client_config(trust_fixture_root: bool) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        if trust_fixture_root {
            roots
                .add(CertificateDer::from(decode_fixture_base64(ROOT_CERT_B64)))
                .unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    async fn fixture_listener() -> TcpListener {
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
    }

    #[test]
    fn production_configuration_has_only_the_frozen_http11_profile() {
        let config = production_client_config().expect("fixed webpki roots are available");
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
        assert!(!config.enable_early_data);
        assert!(!config.enable_secret_extraction);
        assert!(config.enable_sni);
    }

    #[test]
    fn server_name_accepts_dns_names_but_not_ip_literals() {
        assert!(server_name("example.com").is_ok());
        assert!(server_name("127.0.0.1").is_err());
        assert!(server_name("::1").is_err());
    }

    #[tokio::test]
    async fn local_fixture_handshake_validates_hostname_and_negotiates_http11() {
        let listener = fixture_listener().await;
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(fixture_server_config(vec![b"http/1.1".to_vec()]))
                .accept(stream)
                .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(fixture_client_config(true))
            .connect(server_name("foobar.com").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn local_fixture_rejects_wrong_hostname_and_untrusted_root() {
        for trust_fixture_root in [true, false] {
            let listener = fixture_listener().await;
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                TlsAcceptor::from(fixture_server_config(vec![b"http/1.1".to_vec()]))
                    .accept(stream)
                    .await
            });
            let name = if trust_fixture_root {
                "wrong.example"
            } else {
                "foobar.com"
            };
            let stream = TcpStream::connect(address).await.unwrap();
            assert!(
                TlsConnector::from(fixture_client_config(trust_fixture_root))
                    .connect(server_name(name).unwrap(), stream)
                    .await
                    .is_err()
            );
            assert!(server.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn local_fixture_offering_only_h2_never_negotiates_a_different_protocol() {
        let listener = fixture_listener().await;
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(fixture_server_config(vec![b"h2".to_vec()]))
                .accept(stream)
                .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        assert!(TlsConnector::from(fixture_client_config(true))
            .connect(server_name("foobar.com").unwrap(), stream)
            .await
            .is_err());
        assert!(server.await.unwrap().is_err());
    }
}
