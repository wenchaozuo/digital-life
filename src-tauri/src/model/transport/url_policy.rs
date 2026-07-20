use super::TransportPolicyError;
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportTargetKind {
    RemoteHttps,
    LoopbackHttp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedTransportTarget {
    pub(crate) kind: TransportTargetKind,
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) base_path: String,
}

impl ValidatedTransportTarget {
    pub(crate) fn allows_stored_api_key(&self) -> bool {
        match self.kind {
            TransportTargetKind::RemoteHttps => true,
            TransportTargetKind::LoopbackHttp => false,
        }
    }
}

pub(crate) fn validate_and_normalize_url(
    url_str: &str,
) -> Result<ValidatedTransportTarget, TransportPolicyError> {
    if url_str.contains('\\') {
        return Err(TransportPolicyError::UnsafePath);
    }
    if has_trailing_dot_in_raw_host(url_str) {
        return Err(TransportPolicyError::ForbiddenTrailingDot);
    }
    if has_unsafe_path_segments_in_raw_url(url_str) {
        return Err(TransportPolicyError::UnsafePath);
    }

    let parsed = Url::parse(url_str).map_err(|_| TransportPolicyError::UnsupportedScheme)?;

    // Validate scheme
    let scheme = parsed.scheme();
    let kind = match scheme {
        "https" => TransportTargetKind::RemoteHttps,
        "http" => {
            let host = parsed.host().ok_or(TransportPolicyError::MissingHost)?;
            let is_loopback = match host {
                Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
            };
            if is_loopback {
                TransportTargetKind::LoopbackHttp
            } else {
                return Err(TransportPolicyError::UnsupportedScheme);
            }
        }
        _ => return Err(TransportPolicyError::UnsupportedScheme),
    };

    // Userinfo, query, fragment validation
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(TransportPolicyError::ForbiddenUserinfo);
    }
    if parsed.query().is_some() {
        return Err(TransportPolicyError::ForbiddenQuery);
    }
    if parsed.fragment().is_some() {
        return Err(TransportPolicyError::ForbiddenFragment);
    }

    // Host validation
    let host = parsed.host().ok_or(TransportPolicyError::MissingHost)?;
    let normalized_host = match kind {
        TransportTargetKind::RemoteHttps => match host {
            Host::Domain(domain) => {
                if domain.eq_ignore_ascii_case("localhost") {
                    return Err(TransportPolicyError::ForbiddenHostForm);
                }
                domain.to_ascii_lowercase()
            }
            Host::Ipv4(_) | Host::Ipv6(_) => {
                return Err(TransportPolicyError::ForbiddenRemoteIpLiteral);
            }
        },
        TransportTargetKind::LoopbackHttp => match host {
            Host::Domain(domain) => {
                if !domain.eq_ignore_ascii_case("localhost") {
                    return Err(TransportPolicyError::ForbiddenHostForm);
                }
                "localhost".to_string()
            }
            Host::Ipv4(ip) => {
                if !ip.is_loopback() {
                    return Err(TransportPolicyError::ForbiddenHostForm);
                }
                ip.to_string()
            }
            Host::Ipv6(ip) => {
                if !ip.is_loopback() {
                    return Err(TransportPolicyError::ForbiddenHostForm);
                }
                "[::1]".to_string()
            }
        },
    };

    // Port validation
    let port = match parsed.port() {
        Some(0) => return Err(TransportPolicyError::InvalidPort),
        Some(p) => p,
        None => match kind {
            TransportTargetKind::RemoteHttps => 443,
            TransportTargetKind::LoopbackHttp => 80,
        },
    };

    // Path validation
    let path = parsed.path();
    if path.contains("//") {
        return Err(TransportPolicyError::UnsafePath);
    }

    if let Some(segments) = parsed.path_segments() {
        for segment in segments {
            if contains_unsafe_path_segment(segment) {
                return Err(TransportPolicyError::UnsafePath);
            }
        }
    }

    Ok(ValidatedTransportTarget {
        kind,
        scheme: scheme.to_string(),
        host: normalized_host,
        port,
        base_path: path.to_string(),
    })
}

fn has_trailing_dot_in_raw_host(url_str: &str) -> bool {
    if let Some(pos) = url_str.find("://") {
        let host_part = &url_str[pos + 3..];
        let host_end = host_part
            .find(['/', '?', '#', ':'])
            .unwrap_or(host_part.len());
        let raw_host = &host_part[..host_end];
        raw_host.ends_with('.')
    } else {
        false
    }
}

fn contains_unsafe_path_segment(segment: &str) -> bool {
    let mut bytes = Vec::new();
    let chars: Vec<char> = segment.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            let h1 = chars[i + 1].to_digit(16);
            let h2 = chars[i + 2].to_digit(16);
            if let (Some(d1), Some(d2)) = (h1, h2) {
                bytes.push((d1 * 16 + d2) as u8);
                i += 3;
                continue;
            }
        }
        bytes.push(chars[i] as u8);
        i += 1;
    }

    if bytes == b"." || bytes == b".." {
        return true;
    }
    if bytes.contains(&b'/') || bytes.contains(&b'\\') {
        return true;
    }
    false
}

fn has_unsafe_path_segments_in_raw_url(url_str: &str) -> bool {
    if let Some(pos) = url_str.find("://") {
        let after_scheme = &url_str[pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            let raw_path = &after_scheme[slash_pos..];
            for segment in raw_path.split('/') {
                if contains_unsafe_path_segment(segment) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_remote_https() {
        let res = validate_and_normalize_url("https://example.com/api/v1").unwrap();
        assert_eq!(res.kind, TransportTargetKind::RemoteHttps);
        assert_eq!(res.scheme, "https");
        assert_eq!(res.host, "example.com");
        assert_eq!(res.port, 443);
        assert_eq!(res.base_path, "/api/v1");
        assert!(res.allows_stored_api_key());

        // Custom port
        let res = validate_and_normalize_url("https://example.com:8443/").unwrap();
        assert_eq!(res.port, 8443);
        assert_eq!(res.base_path, "/");
    }

    #[test]
    fn test_valid_loopback_http() {
        let res = validate_and_normalize_url("http://127.0.0.1/").unwrap();
        assert_eq!(res.kind, TransportTargetKind::LoopbackHttp);
        assert_eq!(res.host, "127.0.0.1");
        assert_eq!(res.port, 80);
        assert!(!res.allows_stored_api_key());

        // Localhost
        let res = validate_and_normalize_url("http://localhost:8080/foo").unwrap();
        assert_eq!(res.host, "localhost");
        assert_eq!(res.port, 8080);
        assert_eq!(res.base_path, "/foo");

        // IPv6 loopback
        let res = validate_and_normalize_url("http://[::1]:9000/").unwrap();
        assert_eq!(res.host, "[::1]");
        assert_eq!(res.port, 9000);
    }

    #[test]
    fn test_rejected_schemes() {
        assert_eq!(
            validate_and_normalize_url("http://example.com/").unwrap_err(),
            TransportPolicyError::UnsupportedScheme
        );
        assert_eq!(
            validate_and_normalize_url("ftp://example.com/").unwrap_err(),
            TransportPolicyError::UnsupportedScheme
        );
        assert_eq!(
            validate_and_normalize_url("ws://localhost/").unwrap_err(),
            TransportPolicyError::UnsupportedScheme
        );
        assert_eq!(
            validate_and_normalize_url("wss://localhost/").unwrap_err(),
            TransportPolicyError::UnsupportedScheme
        );
    }

    #[test]
    fn test_remote_https_rejected_literals() {
        assert_eq!(
            validate_and_normalize_url("https://127.0.0.1/").unwrap_err(),
            TransportPolicyError::ForbiddenRemoteIpLiteral
        );
        assert_eq!(
            validate_and_normalize_url("https://[::1]/").unwrap_err(),
            TransportPolicyError::ForbiddenRemoteIpLiteral
        );
        assert_eq!(
            validate_and_normalize_url("https://localhost/").unwrap_err(),
            TransportPolicyError::ForbiddenHostForm
        );
        assert_eq!(
            validate_and_normalize_url("https://8.8.8.8/").unwrap_err(),
            TransportPolicyError::ForbiddenRemoteIpLiteral
        );
    }

    #[test]
    fn test_userinfo_query_fragment_rejections() {
        assert_eq!(
            validate_and_normalize_url("https://user:pass@example.com/").unwrap_err(),
            TransportPolicyError::ForbiddenUserinfo
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/?query=1").unwrap_err(),
            TransportPolicyError::ForbiddenQuery
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/#frag").unwrap_err(),
            TransportPolicyError::ForbiddenFragment
        );
    }

    #[test]
    fn test_trailing_dot_rejections() {
        assert_eq!(
            validate_and_normalize_url("https://example.com./").unwrap_err(),
            TransportPolicyError::ForbiddenTrailingDot
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com.:8443/").unwrap_err(),
            TransportPolicyError::ForbiddenTrailingDot
        );
    }

    #[test]
    fn test_invalid_ports() {
        assert_eq!(
            validate_and_normalize_url("https://example.com:0/").unwrap_err(),
            TransportPolicyError::InvalidPort
        );
    }

    #[test]
    fn test_path_safety() {
        // Backslash in path
        assert_eq!(
            validate_and_normalize_url("https://example.com/foo\\bar").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        // Duplicate slash in path
        assert_eq!(
            validate_and_normalize_url("https://example.com/foo//bar").unwrap_err(),
            TransportPolicyError::UnsafePath
        );

        // Path traversals (encoded / decoded)
        assert_eq!(
            validate_and_normalize_url("https://example.com/.").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/..").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/%2e").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/%2E").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/%2e%2e").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/.%2e").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
        assert_eq!(
            validate_and_normalize_url("https://example.com/%2e.").unwrap_err(),
            TransportPolicyError::UnsafePath
        );
    }

    #[test]
    fn test_unicode_punycode_dns() {
        // Punycode should be normalized and allowed
        let res = validate_and_normalize_url("https://xn--tiq49xqgb.com/").unwrap();
        assert_eq!(res.host, "xn--tiq49xqgb.com");

        // Unicode should be parsed and converted to punycode by the url parser
        let res = validate_and_normalize_url("https://测试.com/").unwrap();
        assert_eq!(res.host, "xn--0zwm56d.com");
    }

    #[test]
    fn test_error_leakage_safety() {
        let canary_url = "https://secret_user:secret_password@canary.hostname.internal:8080/path?secret_query=1#secret_fragment";

        // 1. Userinfo violation
        let err = validate_and_normalize_url(canary_url).unwrap_err();
        let display_str = format!("{}", err);
        let debug_str = format!("{:?}", err);

        assert!(
            !display_str.contains("secret_user"),
            "Leaks username in Display"
        );
        assert!(
            !display_str.contains("secret_password"),
            "Leaks password in Display"
        );
        assert!(
            !display_str.contains("canary.hostname.internal"),
            "Leaks hostname in Display"
        );
        assert!(
            !display_str.contains("secret_query"),
            "Leaks query in Display"
        );
        assert!(
            !display_str.contains("secret_fragment"),
            "Leaks fragment in Display"
        );

        assert!(
            !debug_str.contains("secret_user"),
            "Leaks username in Debug"
        );
        assert!(
            !debug_str.contains("secret_password"),
            "Leaks password in Debug"
        );
        assert!(
            !debug_str.contains("canary.hostname.internal"),
            "Leaks hostname in Debug"
        );
        assert!(!debug_str.contains("secret_query"), "Leaks query in Debug");
        assert!(
            !debug_str.contains("secret_fragment"),
            "Leaks fragment in Debug"
        );
    }
}
