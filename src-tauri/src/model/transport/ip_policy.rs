use super::url_policy::{TransportTargetKind, ValidatedTransportTarget};
use super::{TransportPolicyError, MAX_DNS_CANDIDATES};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpSafetyClass {
    Global,
    Loopback,
    Private,
    LinkLocal,
    CarrierGradeNat,
    Multicast,
    Unspecified,
    Documentation,
    Benchmark,
    ReservedOrSpecial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedCandidateSet {
    pub(crate) candidates: Vec<IpAddr>,
}

pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                IpAddr::V4(ipv4)
            } else {
                IpAddr::V6(ipv6)
            }
        }
    }
}

pub(crate) fn classify_ip(ip: IpAddr) -> IpSafetyClass {
    let normalized = normalize_ip(ip);
    match normalized {
        IpAddr::V4(ipv4) => classify_ipv4(ipv4),
        IpAddr::V6(ipv6) => classify_ipv6(ipv6),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpSafetyClass {
    let octets = ip.octets();

    // 127.0.0.0/8 -> Loopback
    if octets[0] == 127 {
        return IpSafetyClass::Loopback;
    }

    // 10.0.0.0/8 -> Private
    if octets[0] == 10 {
        return IpSafetyClass::Private;
    }

    // 172.16.0.0/12 -> Private (172.16.0.0 to 172.31.255.255)
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return IpSafetyClass::Private;
    }

    // 192.168.0.0/16 -> Private
    if octets[0] == 192 && octets[1] == 168 {
        return IpSafetyClass::Private;
    }

    // 0.0.0.0/8 -> ReservedOrSpecial
    if octets[0] == 0 {
        return IpSafetyClass::ReservedOrSpecial;
    }

    // 100.64.0.0/10 -> CarrierGradeNat (100.64.0.0 to 100.127.255.255)
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return IpSafetyClass::CarrierGradeNat;
    }

    // 169.254.0.0/16 -> LinkLocal
    if octets[0] == 169 && octets[1] == 254 {
        return IpSafetyClass::LinkLocal;
    }

    // 192.0.0.0/24 -> ReservedOrSpecial
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return IpSafetyClass::ReservedOrSpecial;
    }

    // 192.0.2.0/24 -> Documentation
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return IpSafetyClass::Documentation;
    }

    // 198.18.0.0/15 -> Benchmark (198.18.0.0 to 199.19.255.255)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return IpSafetyClass::Benchmark;
    }

    // 198.51.100.0/24 -> Documentation
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return IpSafetyClass::Documentation;
    }

    // 203.0.113.0/24 -> Documentation
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return IpSafetyClass::Documentation;
    }

    // 224.0.0.0/4 -> Multicast (224.0.0.0 to 239.255.255.255)
    if octets[0] >= 224 && octets[0] <= 239 {
        return IpSafetyClass::Multicast;
    }

    // 240.0.0.0/4 -> ReservedOrSpecial (includes 255.255.255.255)
    if octets[0] >= 240 {
        return IpSafetyClass::ReservedOrSpecial;
    }

    IpSafetyClass::Global
}

fn classify_ipv6(ip: Ipv6Addr) -> IpSafetyClass {
    let segments = ip.segments();

    // ::1/128 -> Loopback
    if ip.is_loopback() {
        return IpSafetyClass::Loopback;
    }

    // ::/128 -> Unspecified
    if ip.is_unspecified() {
        return IpSafetyClass::Unspecified;
    }

    // fc00::/7 -> Private (Unique Local Addresses)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return IpSafetyClass::Private;
    }

    // fe80::/10 -> LinkLocal
    if (segments[0] & 0xffc0) == 0xfe80 {
        return IpSafetyClass::LinkLocal;
    }

    // ff00::/8 -> Multicast
    if (segments[0] & 0xff00) == 0xff00 {
        return IpSafetyClass::Multicast;
    }

    // 100::/64 -> ReservedOrSpecial (Discard-only prefix)
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return IpSafetyClass::ReservedOrSpecial;
    }

    // 2001:2::/48 -> Benchmark
    if segments[0] == 0x2001 && segments[1] == 2 && segments[2] == 0 {
        return IpSafetyClass::Benchmark;
    }

    // 2001:db8::/32 -> Documentation
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return IpSafetyClass::Documentation;
    }

    IpSafetyClass::Global
}

pub(crate) fn validate_resolved_candidates(
    target: &ValidatedTransportTarget,
    candidates: impl IntoIterator<Item = IpAddr>,
) -> Result<ValidatedCandidateSet, TransportPolicyError> {
    let raw_candidates: Vec<IpAddr> = candidates.into_iter().collect();

    if raw_candidates.is_empty() {
        return Err(TransportPolicyError::EmptyDnsResult);
    }

    if raw_candidates.len() > MAX_DNS_CANDIDATES {
        return Err(TransportPolicyError::TooManyDnsCandidates);
    }

    // Normalize and deduplicate while keeping insertion order
    let mut normalized = Vec::new();
    for ip in raw_candidates {
        let norm_ip = normalize_ip(ip);
        if !normalized.contains(&norm_ip) {
            normalized.push(norm_ip);
        }
    }

    // Validate candidates based on target kind
    match target.kind {
        TransportTargetKind::RemoteHttps => {
            let mut has_global = false;
            let mut has_non_global = false;
            for ip in &normalized {
                let class = classify_ip(*ip);
                if let IpSafetyClass::Global = class {
                    has_global = true;
                } else {
                    has_non_global = true;
                }
            }
            if has_non_global {
                if has_global {
                    return Err(TransportPolicyError::MixedUnsafeDnsResult);
                } else {
                    return Err(TransportPolicyError::UnsafeDnsCandidate);
                }
            }
        }
        TransportTargetKind::LoopbackHttp => {
            let mut has_loopback = false;
            let mut has_non_loopback = false;
            for ip in &normalized {
                let class = classify_ip(*ip);
                if let IpSafetyClass::Loopback = class {
                    has_loopback = true;
                } else {
                    has_non_loopback = true;
                }
            }
            if has_non_loopback {
                if has_loopback {
                    return Err(TransportPolicyError::MixedUnsafeDnsResult);
                } else {
                    return Err(TransportPolicyError::UnsafeDnsCandidate);
                }
            }
        }
    }

    Ok(ValidatedCandidateSet {
        candidates: normalized,
    })
}

pub(crate) fn validate_connected_peer(
    target: &ValidatedTransportTarget,
    selected_candidate: IpAddr,
    actual_peer: SocketAddr,
) -> Result<(), TransportPolicyError> {
    let normalized_peer_ip = normalize_ip(actual_peer.ip());
    let normalized_candidate = normalize_ip(selected_candidate);

    if normalized_peer_ip != normalized_candidate {
        return Err(TransportPolicyError::PeerMismatch);
    }

    if actual_peer.port() != target.port {
        return Err(TransportPolicyError::PeerMismatch);
    }

    // Re-verify the address classification
    let class = classify_ip(normalized_peer_ip);
    match target.kind {
        TransportTargetKind::RemoteHttps => {
            if let IpSafetyClass::Global = class {
                Ok(())
            } else {
                Err(TransportPolicyError::UnsafePeer)
            }
        }
        TransportTargetKind::LoopbackHttp => {
            if let IpSafetyClass::Loopback = class {
                Ok(())
            } else {
                Err(TransportPolicyError::UnsafePeer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn parse_ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn test_normalize_ip() {
        assert_eq!(
            normalize_ip(parse_ip("::ffff:127.0.0.1")),
            parse_ip("127.0.0.1")
        );
        assert_eq!(
            normalize_ip(parse_ip("::ffff:192.168.1.1")),
            parse_ip("192.168.1.1")
        );
        assert_eq!(normalize_ip(parse_ip("1.1.1.1")), parse_ip("1.1.1.1"));
        assert_eq!(normalize_ip(parse_ip("::1")), parse_ip("::1"));
    }

    #[test]
    fn test_ip_classification() {
        // Table for IPv4 boundary and target checks
        let cases = vec![
            // 127.0.0.0/8
            ("127.0.0.1", IpSafetyClass::Loopback),
            ("127.0.0.0", IpSafetyClass::Loopback),
            ("127.255.255.255", IpSafetyClass::Loopback),
            ("126.255.255.255", IpSafetyClass::Global),
            ("128.0.0.0", IpSafetyClass::Global),
            // 10.0.0.0/8
            ("10.0.0.0", IpSafetyClass::Private),
            ("10.255.255.255", IpSafetyClass::Private),
            ("9.255.255.255", IpSafetyClass::Global),
            ("11.0.0.0", IpSafetyClass::Global),
            // 172.16.0.0/12
            ("172.16.0.0", IpSafetyClass::Private),
            ("172.31.255.255", IpSafetyClass::Private),
            ("172.15.255.255", IpSafetyClass::Global),
            ("172.32.0.0", IpSafetyClass::Global),
            // 192.168.0.0/16
            ("192.168.0.0", IpSafetyClass::Private),
            ("192.168.255.255", IpSafetyClass::Private),
            ("192.167.255.255", IpSafetyClass::Global),
            ("192.169.0.0", IpSafetyClass::Global),
            // 0.0.0.0/8
            ("0.0.0.0", IpSafetyClass::ReservedOrSpecial),
            ("0.255.255.255", IpSafetyClass::ReservedOrSpecial),
            ("1.0.0.0", IpSafetyClass::Global),
            // 100.64.0.0/10
            ("100.64.0.0", IpSafetyClass::CarrierGradeNat),
            ("100.127.255.255", IpSafetyClass::CarrierGradeNat),
            ("100.63.255.255", IpSafetyClass::Global),
            ("100.128.0.0", IpSafetyClass::Global),
            // 169.254.0.0/16
            ("169.254.0.0", IpSafetyClass::LinkLocal),
            ("169.254.255.255", IpSafetyClass::LinkLocal),
            ("169.253.255.255", IpSafetyClass::Global),
            ("169.255.0.0", IpSafetyClass::Global),
            // 192.0.2.0/24
            ("192.0.2.0", IpSafetyClass::Documentation),
            ("192.0.2.255", IpSafetyClass::Documentation),
            ("192.0.0.255", IpSafetyClass::ReservedOrSpecial),
            ("192.0.1.255", IpSafetyClass::Global),
            ("192.0.3.0", IpSafetyClass::Global),
            // 198.18.0.0/15
            ("198.18.0.0", IpSafetyClass::Benchmark),
            ("199.19.255.255", IpSafetyClass::Global), // wait, 198.18.0.0/15 is 198.18.0.0 to 198.19.255.255.
            ("198.19.255.255", IpSafetyClass::Benchmark),
            ("198.17.255.255", IpSafetyClass::Global),
            ("198.20.0.0", IpSafetyClass::Global),
            // 224.0.0.0/4
            ("224.0.0.0", IpSafetyClass::Multicast),
            ("239.255.255.255", IpSafetyClass::Multicast),
            ("223.255.255.255", IpSafetyClass::Global),
            // 240.0.0.0/4
            ("240.0.0.0", IpSafetyClass::ReservedOrSpecial),
            ("255.255.255.255", IpSafetyClass::ReservedOrSpecial),
            // IPv6 Link-Local fe80::/10
            ("fe80::1", IpSafetyClass::LinkLocal),
            ("fec0::1", IpSafetyClass::Global), // Site-Local deprecated, treated as Global in our rule or Private depending on spec, but fe80::/10 is Fe80..Febf.
            // IPv6 Unique-Local fc00::/7
            ("fc00::1", IpSafetyClass::Private),
            ("fdff::1", IpSafetyClass::Private),
            // IPv6 Documentation 2001:db8::/32
            ("2001:db8::1", IpSafetyClass::Documentation),
            // IPv6 Benchmark 2001:2::/48
            ("2001:2::1", IpSafetyClass::Benchmark),
            // IPv6 Discard 100::/64
            ("100::1", IpSafetyClass::ReservedOrSpecial),
            // Mapped IP
            ("::ffff:127.0.0.1", IpSafetyClass::Loopback),
            ("::ffff:10.0.0.1", IpSafetyClass::Private),
        ];

        for (ip_str, expected) in cases {
            let ip = parse_ip(ip_str);
            assert_eq!(classify_ip(ip), expected, "IP: {}", ip_str);
        }
    }

    #[test]
    fn test_dns_candidate_policy_remote_https() {
        let target = ValidatedTransportTarget {
            kind: TransportTargetKind::RemoteHttps,
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: 443,
            base_path: "/".to_string(),
        };

        // Empty DNS candidates
        let err = validate_resolved_candidates(&target, vec![]).unwrap_err();
        assert_eq!(err, TransportPolicyError::EmptyDnsResult);

        // 17 candidates (max 16)
        let mut seventeen = Vec::new();
        for i in 1..=17 {
            seventeen.push(parse_ip(&format!("1.1.1.{}", i)));
        }
        let err = validate_resolved_candidates(&target, seventeen).unwrap_err();
        assert_eq!(err, TransportPolicyError::TooManyDnsCandidates);

        // Deduplication
        let candidates = vec![
            parse_ip("1.1.1.1"),
            parse_ip("1.1.1.1"),
            parse_ip("::ffff:1.1.1.1"), // mapped duplicate
            parse_ip("2.2.2.2"),
        ];
        let set = validate_resolved_candidates(&target, candidates).unwrap();
        assert_eq!(set.candidates.len(), 2);
        assert_eq!(set.candidates[0], parse_ip("1.1.1.1"));
        assert_eq!(set.candidates[1], parse_ip("2.2.2.2"));

        // Global only
        let set =
            validate_resolved_candidates(&target, vec![parse_ip("1.1.1.1"), parse_ip("8.8.8.8")])
                .unwrap();
        assert_eq!(set.candidates.len(), 2);

        // Unsafe candidate (all unsafe)
        let err = validate_resolved_candidates(
            &target,
            vec![parse_ip("10.0.0.1"), parse_ip("192.168.1.1")],
        )
        .unwrap_err();
        assert_eq!(err, TransportPolicyError::UnsafeDnsCandidate);

        // Mixed candidate
        let err =
            validate_resolved_candidates(&target, vec![parse_ip("1.1.1.1"), parse_ip("10.0.0.1")])
                .unwrap_err();
        assert_eq!(err, TransportPolicyError::MixedUnsafeDnsResult);
    }

    #[test]
    fn test_dns_candidate_policy_loopback_http() {
        let target = ValidatedTransportTarget {
            kind: TransportTargetKind::LoopbackHttp,
            scheme: "http".to_string(),
            host: "localhost".to_string(),
            port: 80,
            base_path: "/".to_string(),
        };

        // Loopback only
        let set =
            validate_resolved_candidates(&target, vec![parse_ip("127.0.0.1"), parse_ip("::1")])
                .unwrap();
        assert_eq!(set.candidates.len(), 2);

        // Unsafe (all non-loopback)
        let err =
            validate_resolved_candidates(&target, vec![parse_ip("1.1.1.1"), parse_ip("8.8.8.8")])
                .unwrap_err();
        assert_eq!(err, TransportPolicyError::UnsafeDnsCandidate);

        // Mixed candidates
        let err =
            validate_resolved_candidates(&target, vec![parse_ip("127.0.0.1"), parse_ip("1.1.1.1")])
                .unwrap_err();
        assert_eq!(err, TransportPolicyError::MixedUnsafeDnsResult);
    }

    #[test]
    fn test_peer_verification() {
        let target_remote = ValidatedTransportTarget {
            kind: TransportTargetKind::RemoteHttps,
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: 443,
            base_path: "/".to_string(),
        };

        let target_loopback = ValidatedTransportTarget {
            kind: TransportTargetKind::LoopbackHttp,
            scheme: "http".to_string(),
            host: "localhost".to_string(),
            port: 80,
            base_path: "/".to_string(),
        };

        // Perfect match
        let res = validate_connected_peer(
            &target_remote,
            parse_ip("1.1.1.1"),
            SocketAddr::new(parse_ip("1.1.1.1"), 443),
        );
        assert!(res.is_ok());

        // Port mismatch
        let res = validate_connected_peer(
            &target_remote,
            parse_ip("1.1.1.1"),
            SocketAddr::new(parse_ip("1.1.1.1"), 8443),
        );
        assert_eq!(res.unwrap_err(), TransportPolicyError::PeerMismatch);

        // IP mismatch
        let res = validate_connected_peer(
            &target_remote,
            parse_ip("1.1.1.1"),
            SocketAddr::new(parse_ip("2.2.2.2"), 443),
        );
        assert_eq!(res.unwrap_err(), TransportPolicyError::PeerMismatch);

        // Remote peer is not global (private IP)
        let res = validate_connected_peer(
            &target_remote,
            parse_ip("10.0.0.1"),
            SocketAddr::new(parse_ip("10.0.0.1"), 443),
        );
        assert_eq!(res.unwrap_err(), TransportPolicyError::UnsafePeer);

        // Loopback match
        let res = validate_connected_peer(
            &target_loopback,
            parse_ip("127.0.0.1"),
            SocketAddr::new(parse_ip("127.0.0.1"), 80),
        );
        assert!(res.is_ok());

        // Loopback peer is not loopback
        let res = validate_connected_peer(
            &target_loopback,
            parse_ip("1.1.1.1"),
            SocketAddr::new(parse_ip("1.1.1.1"), 80),
        );
        assert_eq!(res.unwrap_err(), TransportPolicyError::UnsafePeer);
    }
}
