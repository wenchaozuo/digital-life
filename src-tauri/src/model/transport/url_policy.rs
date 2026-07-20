use super::{TransportPolicyError, MAX_TRANSPORT_BASE_URL_BYTES};
use std::fmt;
use url::{Host, Url};

/// D-8C2 dispatches connection behavior only through this fixed target kind.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportTargetKind {
    RemoteHttps,
    LoopbackHttp,
}

/// D-8C2 receives parsed segments, never an arbitrary normalized path string.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ValidatedBasePath {
    segments: Vec<String>,
    trailing_slash: bool,
}

#[allow(dead_code)]
impl ValidatedBasePath {
    pub(crate) fn segments(&self) -> impl ExactSizeIterator<Item = &str> {
        self.segments.iter().map(String::as_str)
    }

    pub(crate) const fn has_trailing_slash(&self) -> bool {
        self.trailing_slash
    }
}

impl fmt::Debug for ValidatedBasePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedBasePath { redacted: true }")
    }
}

/// D-8C2 receives this sealed URL policy result before any connection is made.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ValidatedTransportTarget {
    kind: TransportTargetKind,
    host_ascii: String,
    port: u16,
    base_path: ValidatedBasePath,
}

#[allow(dead_code)]
impl ValidatedTransportTarget {
    pub(crate) const fn kind(&self) -> TransportTargetKind {
        self.kind
    }

    pub(crate) fn host_ascii(&self) -> &str {
        &self.host_ascii
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn base_path(&self) -> &ValidatedBasePath {
        &self.base_path
    }

    pub(crate) const fn allows_stored_api_key(&self) -> bool {
        matches!(self.kind, TransportTargetKind::RemoteHttps)
    }
}

impl fmt::Debug for ValidatedTransportTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedTransportTarget")
            .field("kind", &self.kind)
            .field("redacted", &true)
            .finish()
    }
}

/// D-8C2 enters URL policy only through this parser and validator.
#[allow(dead_code)]
pub(crate) fn validate_and_normalize_url(
    url_str: &str,
) -> Result<ValidatedTransportTarget, TransportPolicyError> {
    if url_str.len() > MAX_TRANSPORT_BASE_URL_BYTES {
        return Err(TransportPolicyError::BaseUrlTooLong);
    }
    if url_str.contains('\\') {
        return Err(TransportPolicyError::UnsafePath);
    }

    let raw_authority = raw_authority(url_str);
    let raw_host = raw_authority.and_then(raw_host_from_authority);
    if raw_host.is_some_and(|host| host.ends_with('.')) {
        return Err(TransportPolicyError::ForbiddenTrailingDot);
    }

    let base_path = validate_raw_base_path(raw_path(url_str))?;
    let parsed = Url::parse(url_str).map_err(|_| TransportPolicyError::UnsupportedScheme)?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(TransportPolicyError::ForbiddenUserinfo);
    }
    if parsed.query().is_some() {
        return Err(TransportPolicyError::ForbiddenQuery);
    }
    if parsed.fragment().is_some() {
        return Err(TransportPolicyError::ForbiddenFragment);
    }

    let host = parsed.host().ok_or(TransportPolicyError::MissingHost)?;
    let kind = match parsed.scheme() {
        "https" => TransportTargetKind::RemoteHttps,
        "http" if is_canonical_loopback_host(&host, raw_host) => TransportTargetKind::LoopbackHttp,
        "http" => return Err(TransportPolicyError::UnsupportedScheme),
        _ => return Err(TransportPolicyError::UnsupportedScheme),
    };

    let host_ascii = match kind {
        TransportTargetKind::RemoteHttps => match host {
            Host::Domain(domain) => validate_remote_dns_hostname(domain)?,
            Host::Ipv4(_) | Host::Ipv6(_) => {
                return Err(TransportPolicyError::ForbiddenRemoteIpLiteral);
            }
        },
        TransportTargetKind::LoopbackHttp => normalize_loopback_host(host, raw_host)?,
    };

    let port = match parsed.port() {
        Some(0) => return Err(TransportPolicyError::InvalidPort),
        Some(port) => port,
        None => match kind {
            TransportTargetKind::RemoteHttps => 443,
            TransportTargetKind::LoopbackHttp => 80,
        },
    };

    Ok(ValidatedTransportTarget {
        kind,
        host_ascii,
        port,
        base_path,
    })
}

fn raw_authority(url_str: &str) -> Option<&str> {
    let scheme_end = url_str.find("://")?;
    let after_scheme = &url_str[scheme_end + 3..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    Some(&after_scheme[..authority_end])
}

fn raw_host_from_authority(authority: &str) -> Option<&str> {
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    if host_and_port.starts_with('[') {
        let end = host_and_port.find(']')?;
        return Some(&host_and_port[..=end]);
    }
    Some(host_and_port.split(':').next().unwrap_or_default())
}

fn raw_path(url_str: &str) -> Option<&str> {
    let scheme_end = url_str.find("://")?;
    let after_scheme = &url_str[scheme_end + 3..];
    let path_start = after_scheme.find('/')?;
    let path_and_suffix = &after_scheme[path_start..];
    let path_end = path_and_suffix
        .find(['?', '#'])
        .unwrap_or(path_and_suffix.len());
    Some(&path_and_suffix[..path_end])
}

fn validate_raw_base_path(
    raw_path: Option<&str>,
) -> Result<ValidatedBasePath, TransportPolicyError> {
    let raw_path = raw_path.unwrap_or("");
    if raw_path.is_empty() || raw_path == "/" {
        return Ok(ValidatedBasePath {
            segments: Vec::new(),
            trailing_slash: true,
        });
    }

    if !raw_path.starts_with('/') || raw_path.contains('\\') {
        return Err(TransportPolicyError::UnsafePath);
    }

    let trailing_slash = raw_path.ends_with('/');
    let mut segments = Vec::new();
    for (index, segment) in raw_path[1..].split('/').enumerate() {
        let is_last = index + 1 == raw_path[1..].split('/').count();
        if segment.is_empty() {
            if trailing_slash && is_last {
                continue;
            }
            return Err(TransportPolicyError::UnsafePath);
        }
        if segment == "." || segment == ".." || !segment.bytes().all(is_safe_path_byte) {
            return Err(TransportPolicyError::UnsafePath);
        }
        segments.push(segment.to_string());
    }

    Ok(ValidatedBasePath {
        segments,
        trailing_slash,
    })
}

const fn is_safe_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

fn validate_remote_dns_hostname(domain: &str) -> Result<String, TransportPolicyError> {
    let normalized = domain.to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.eq_ignore_ascii_case("localhost")
        || normalized.starts_with('.')
        || normalized.ends_with('.')
    {
        return Err(TransportPolicyError::ForbiddenHostForm);
    }

    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(TransportPolicyError::ForbiddenHostForm);
        }
    }

    Ok(normalized)
}

fn is_canonical_loopback_host(host: &Host<&str>, raw_host: Option<&str>) -> bool {
    let Some(raw_host) = raw_host else {
        return false;
    };
    match host {
        Host::Domain(domain) => {
            domain.eq_ignore_ascii_case("localhost") && raw_host.eq_ignore_ascii_case("localhost")
        }
        Host::Ipv4(ip) => ip.is_loopback() && is_canonical_ipv4_literal(raw_host, *ip),
        Host::Ipv6(ip) => ip.is_loopback() && raw_host == "[::1]",
    }
}

fn normalize_loopback_host(
    host: Host<&str>,
    raw_host: Option<&str>,
) -> Result<String, TransportPolicyError> {
    if !is_canonical_loopback_host(&host, raw_host) {
        return Err(TransportPolicyError::ForbiddenHostForm);
    }
    match host {
        Host::Domain(_) => Ok("localhost".to_string()),
        Host::Ipv4(ip) => Ok(ip.to_string()),
        Host::Ipv6(_) => Ok("::1".to_string()),
    }
}

fn is_canonical_ipv4_literal(raw_host: &str, parsed: std::net::Ipv4Addr) -> bool {
    raw_host == parsed.to_string()
        && raw_host.split('.').count() == 4
        && raw_host.split('.').all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeated(byte: char, count: usize) -> String {
        std::iter::repeat_n(byte, count).collect()
    }

    fn remote_url_with_total_length(length: usize) -> String {
        let prefix = "https://example.com/";
        format!("{prefix}{}", repeated('a', length - prefix.len()))
    }

    fn hostname_with_lengths(lengths: &[usize]) -> String {
        lengths
            .iter()
            .map(|length| repeated('a', *length))
            .collect::<Vec<_>>()
            .join(".")
    }

    #[test]
    fn url_length_is_checked_before_parse() {
        let exact = remote_url_with_total_length(MAX_TRANSPORT_BASE_URL_BYTES);
        assert_eq!(exact.len(), MAX_TRANSPORT_BASE_URL_BYTES);
        assert!(validate_and_normalize_url(&exact).is_ok());

        let over = remote_url_with_total_length(MAX_TRANSPORT_BASE_URL_BYTES + 1);
        assert_eq!(
            validate_and_normalize_url(&over).unwrap_err(),
            TransportPolicyError::BaseUrlTooLong
        );
    }

    #[test]
    fn valid_remote_https_normalizes_idna_and_path() {
        let ascii = validate_and_normalize_url("https://xn--0zwm56d.com/api/v1/").unwrap();
        let unicode = validate_and_normalize_url("https://测试.com/api/v1/").unwrap();
        assert_eq!(ascii.kind(), TransportTargetKind::RemoteHttps);
        assert_eq!(ascii.host_ascii(), unicode.host_ascii());
        assert_eq!(ascii.port(), 443);
        assert!(ascii.allows_stored_api_key());
        assert_eq!(
            ascii.base_path().segments().collect::<Vec<_>>(),
            ["api", "v1"]
        );
        assert!(ascii.base_path().has_trailing_slash());
    }

    #[test]
    fn remote_hostname_grammar_is_strict() {
        for host in [
            ".example.com",
            "example..com",
            "-a.example",
            "a-.example",
            "a_b.example",
            "localhost",
        ] {
            assert_eq!(
                validate_and_normalize_url(&format!("https://{host}/")).unwrap_err(),
                TransportPolicyError::ForbiddenHostForm,
                "{host}"
            );
        }
        assert_eq!(
            validate_and_normalize_url("https://example.com./").unwrap_err(),
            TransportPolicyError::ForbiddenTrailingDot
        );

        let label_63 = repeated('a', 63);
        assert!(validate_and_normalize_url(&format!("https://{label_63}.example/")).is_ok());
        let label_64 = repeated('a', 64);
        assert_eq!(
            validate_and_normalize_url(&format!("https://{label_64}.example/")).unwrap_err(),
            TransportPolicyError::ForbiddenHostForm
        );

        let host_253 = hostname_with_lengths(&[63, 63, 63, 61]);
        assert_eq!(host_253.len(), 253);
        assert!(validate_and_normalize_url(&format!("https://{host_253}/")).is_ok());
        let host_254 = hostname_with_lengths(&[63, 63, 63, 62]);
        assert_eq!(host_254.len(), 254);
        assert_eq!(
            validate_and_normalize_url(&format!("https://{host_254}/")).unwrap_err(),
            TransportPolicyError::ForbiddenHostForm
        );
    }

    #[test]
    fn loopback_hosts_must_be_canonical() {
        for url in [
            "http://127.0.0.1/",
            "http://127.255.255.255/",
            "http://LOCALHOST/",
            "http://[::1]/",
        ] {
            let target = validate_and_normalize_url(url).unwrap();
            assert_eq!(target.kind(), TransportTargetKind::LoopbackHttp);
            assert!(!target.allows_stored_api_key());
        }

        for url in [
            "http://127.1/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "http://[::ffff:127.0.0.1]/",
            "http://localhost./",
            "http://localhost.example/",
            "http://ⅼocalhost/",
            "https://localhost/",
            "http://example.com/",
        ] {
            assert!(validate_and_normalize_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn path_grammar_rejects_ambiguous_encodings() {
        for path in [
            "/.",
            "/..",
            "/%2e",
            "/%2E",
            "/%2e%2e",
            "/.%2e",
            "/%2e.",
            "/%252e",
            "/%252e%252e",
            "/%255c",
            "/%252f",
            "/%2f",
            "/%5c",
            "/%25",
            "/foo\\bar",
            "/foo//bar",
            "/测试",
        ] {
            assert_eq!(
                validate_and_normalize_url(&format!("https://example.com{path}")).unwrap_err(),
                TransportPolicyError::UnsafePath,
                "{path}"
            );
        }

        for path in ["", "/", "/.well-known", "/v1.2", "/v1/"] {
            let target = validate_and_normalize_url(&format!("https://example.com{path}")).unwrap();
            assert!(
                target.base_path().has_trailing_slash() == path.is_empty() || path.ends_with('/')
            );
        }
    }

    #[test]
    fn ports_and_non_loopback_schemes_are_rejected() {
        assert_eq!(
            validate_and_normalize_url("https://example.com:0/").unwrap_err(),
            TransportPolicyError::InvalidPort
        );
        assert_eq!(
            validate_and_normalize_url("http://example.com/").unwrap_err(),
            TransportPolicyError::UnsupportedScheme
        );
        assert_eq!(
            validate_and_normalize_url("https://127.0.0.1/").unwrap_err(),
            TransportPolicyError::ForbiddenRemoteIpLiteral
        );
    }

    #[test]
    fn errors_and_debug_are_redacted() {
        let canary = "https://secret_user:secret_password@internal-host.example/path?secret_query=1#secret_fragment";
        let error = validate_and_normalize_url(canary).unwrap_err();
        let rendered = format!("{error:?} {error}");
        for secret in [
            "secret_user",
            "secret_password",
            "internal-host",
            "secret_query",
            "secret_fragment",
        ] {
            assert!(!rendered.contains(secret));
        }

        let target =
            validate_and_normalize_url("https://private-host.example/sensitive-path").unwrap();
        let target_debug = format!("{target:?}");
        assert!(!target_debug.contains("private-host"));
        assert!(!target_debug.contains("sensitive-path"));
        let path_debug = format!("{:?}", target.base_path());
        assert!(!path_debug.contains("sensitive-path"));
    }
}
