use super::url_policy::{TransportTargetKind, ValidatedTransportTarget};
use super::{TransportPolicyError, MAX_DNS_CANDIDATES};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

/// D-8C2 consumes this opaque set identity when binding a connect attempt.
#[allow(dead_code)]
static NEXT_CANDIDATE_SET_ID: AtomicU64 = AtomicU64::new(1);

/// D-8C2 uses this closed classification before any socket is opened.
#[allow(dead_code)]
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

/// D-8C2 receives this sealed result instead of DNS addresses it can mutate.
#[allow(dead_code)]
pub(crate) struct ValidatedCandidateSet {
    set_id: u64,
    candidates: Vec<IpAddr>,
}

/// D-8C2 presents this opaque token to the peer-validation boundary.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct ValidatedCandidate {
    set_id: u64,
    index: usize,
    ip: IpAddr,
}

#[allow(dead_code)]
impl ValidatedCandidateSet {
    pub(crate) const fn len(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    pub(crate) fn candidate(&self, index: usize) -> Option<ValidatedCandidate> {
        self.candidates
            .get(index)
            .copied()
            .map(|ip| ValidatedCandidate {
                set_id: self.set_id,
                index,
                ip,
            })
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = ValidatedCandidate> + '_ {
        self.candidates
            .iter()
            .copied()
            .enumerate()
            .map(|(index, ip)| ValidatedCandidate {
                set_id: self.set_id,
                index,
                ip,
            })
    }

    pub(crate) fn contains_normalized(&self, ip: IpAddr) -> bool {
        self.candidates.contains(&normalize_ip(ip))
    }

    pub(crate) fn validate_connected_peer(
        &self,
        target: &ValidatedTransportTarget,
        selected: &ValidatedCandidate,
        actual_peer: SocketAddr,
    ) -> Result<(), TransportPolicyError> {
        let selected_ip = self.selected_ip(selected)?;
        let normalized_peer_ip = normalize_ip(actual_peer.ip());

        if normalized_peer_ip != selected_ip || actual_peer.port() != target.port() {
            return Err(TransportPolicyError::PeerMismatch);
        }

        match (target.kind(), classify_ip(normalized_peer_ip)) {
            (TransportTargetKind::RemoteHttps, IpSafetyClass::Global)
            | (TransportTargetKind::LoopbackHttp, IpSafetyClass::Loopback) => Ok(()),
            _ => Err(TransportPolicyError::UnsafePeer),
        }
    }

    fn selected_ip(&self, selected: &ValidatedCandidate) -> Result<IpAddr, TransportPolicyError> {
        if selected.set_id != self.set_id
            || self.candidates.get(selected.index).copied() != Some(selected.ip)
        {
            return Err(TransportPolicyError::PeerMismatch);
        }
        Ok(selected.ip)
    }
}

#[allow(dead_code)]
impl ValidatedCandidate {
    pub(crate) const fn ip(&self) -> IpAddr {
        self.ip
    }
}

impl fmt::Debug for ValidatedCandidateSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedCandidateSet { redacted: true }")
    }
}

impl fmt::Debug for ValidatedCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedCandidate { redacted: true }")
    }
}

/// D-8C2 normalizes a connected peer only through this policy helper.
#[allow(dead_code)]
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
    }
}

/// D-8C2 checks every DNS answer and connected peer with this classifier.
#[allow(dead_code)]
pub(crate) fn classify_ip(ip: IpAddr) -> IpSafetyClass {
    match normalize_ip(ip) {
        IpAddr::V4(ipv4) => classify_ipv4(ipv4),
        IpAddr::V6(ipv6) => classify_ipv6(ipv6),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpSafetyClass {
    if ipv4_in_cidr(ip, [127, 0, 0, 0], 8) {
        return IpSafetyClass::Loopback;
    }
    if ipv4_in_cidr(ip, [10, 0, 0, 0], 8)
        || ipv4_in_cidr(ip, [172, 16, 0, 0], 12)
        || ipv4_in_cidr(ip, [192, 168, 0, 0], 16)
    {
        return IpSafetyClass::Private;
    }
    if ipv4_in_cidr(ip, [169, 254, 0, 0], 16) {
        return IpSafetyClass::LinkLocal;
    }
    if ipv4_in_cidr(ip, [100, 64, 0, 0], 10) {
        return IpSafetyClass::CarrierGradeNat;
    }
    if ipv4_in_cidr(ip, [192, 0, 2, 0], 24)
        || ipv4_in_cidr(ip, [198, 51, 100, 0], 24)
        || ipv4_in_cidr(ip, [203, 0, 113, 0], 24)
    {
        return IpSafetyClass::Documentation;
    }
    if ipv4_in_cidr(ip, [198, 18, 0, 0], 15) {
        return IpSafetyClass::Benchmark;
    }
    if ipv4_in_cidr(ip, [224, 0, 0, 0], 4) {
        return IpSafetyClass::Multicast;
    }

    // Reject IANA special-purpose and infrastructure prefixes conservatively.
    if ipv4_in_cidr(ip, [0, 0, 0, 0], 8)
        || ipv4_in_cidr(ip, [192, 0, 0, 0], 24)
        || ipv4_in_cidr(ip, [192, 31, 196, 0], 24)
        || ipv4_in_cidr(ip, [192, 52, 193, 0], 24)
        || ipv4_in_cidr(ip, [192, 88, 99, 0], 24)
        || ipv4_in_cidr(ip, [192, 175, 48, 0], 24)
        || ipv4_in_cidr(ip, [240, 0, 0, 0], 4)
    {
        return IpSafetyClass::ReservedOrSpecial;
    }

    IpSafetyClass::Global
}

fn classify_ipv6(ip: Ipv6Addr) -> IpSafetyClass {
    if ip.is_loopback() {
        return IpSafetyClass::Loopback;
    }
    if ip.is_unspecified() {
        return IpSafetyClass::Unspecified;
    }
    if ipv6_in_cidr(ip, Ipv6Addr::UNSPECIFIED, 96) {
        return IpSafetyClass::ReservedOrSpecial;
    }
    if ipv6_in_cidr(ip, "64:ff9b::".parse().expect("valid IPv6 CIDR base"), 96)
        || ipv6_in_cidr(ip, "64:ff9b:1::".parse().expect("valid IPv6 CIDR base"), 48)
        || ipv6_in_cidr(ip, "100::".parse().expect("valid IPv6 CIDR base"), 64)
        || ipv6_in_cidr(ip, "2002::".parse().expect("valid IPv6 CIDR base"), 16)
        || ipv6_in_cidr(ip, "3ffe::".parse().expect("valid IPv6 CIDR base"), 16)
        || ipv6_in_cidr(ip, "3fff::".parse().expect("valid IPv6 CIDR base"), 20)
        || ipv6_in_cidr(ip, "fec0::".parse().expect("valid IPv6 CIDR base"), 10)
    {
        return IpSafetyClass::ReservedOrSpecial;
    }
    if ipv6_in_cidr(ip, "fc00::".parse().expect("valid IPv6 CIDR base"), 7) {
        return IpSafetyClass::Private;
    }
    if ipv6_in_cidr(ip, "fe80::".parse().expect("valid IPv6 CIDR base"), 10) {
        return IpSafetyClass::LinkLocal;
    }
    if ipv6_in_cidr(ip, "ff00::".parse().expect("valid IPv6 CIDR base"), 8) {
        return IpSafetyClass::Multicast;
    }
    if ipv6_in_cidr(ip, "2001:db8::".parse().expect("valid IPv6 CIDR base"), 32) {
        return IpSafetyClass::Documentation;
    }
    if ipv6_in_cidr(ip, "2001:2::".parse().expect("valid IPv6 CIDR base"), 48) {
        return IpSafetyClass::Benchmark;
    }
    if ipv6_in_cidr(ip, "2001::".parse().expect("valid IPv6 CIDR base"), 23) {
        return IpSafetyClass::ReservedOrSpecial;
    }

    if ipv6_in_cidr(ip, "2000::".parse().expect("valid IPv6 CIDR base"), 3) {
        IpSafetyClass::Global
    } else {
        IpSafetyClass::ReservedOrSpecial
    }
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    let ip = u32::from_be_bytes(ip.octets());
    let network = u32::from_be_bytes(network);
    let mask = u32::MAX << (32 - prefix);
    ip & mask == network & mask
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let ip = u128::from_be_bytes(ip.octets());
    let network = u128::from_be_bytes(network.octets());
    let mask = u128::MAX << (128 - prefix);
    ip & mask == network & mask
}

/// D-8C2 validates the bounded DNS batch before selecting one opaque candidate.
#[allow(dead_code)]
pub(crate) fn validate_resolved_candidates(
    target: &ValidatedTransportTarget,
    candidates: impl IntoIterator<Item = IpAddr>,
) -> Result<ValidatedCandidateSet, TransportPolicyError> {
    let mut raw = Vec::with_capacity(MAX_DNS_CANDIDATES);
    for candidate in candidates {
        if raw.len() == MAX_DNS_CANDIDATES {
            return Err(TransportPolicyError::TooManyDnsCandidates);
        }
        raw.push(candidate);
    }

    if raw.is_empty() {
        return Err(TransportPolicyError::EmptyDnsResult);
    }

    let mut normalized = Vec::with_capacity(raw.len());
    for ip in raw {
        let normalized_ip = normalize_ip(ip);
        if !normalized.contains(&normalized_ip) {
            normalized.push(normalized_ip);
        }
    }

    let expected = match target.kind() {
        TransportTargetKind::RemoteHttps => IpSafetyClass::Global,
        TransportTargetKind::LoopbackHttp => IpSafetyClass::Loopback,
    };
    let has_expected = normalized.iter().any(|ip| classify_ip(*ip) == expected);
    if normalized.iter().any(|ip| classify_ip(*ip) != expected) {
        return Err(if has_expected {
            TransportPolicyError::MixedUnsafeDnsResult
        } else {
            TransportPolicyError::UnsafeDnsCandidate
        });
    }

    Ok(ValidatedCandidateSet {
        set_id: NEXT_CANDIDATE_SET_ID.fetch_add(1, Ordering::Relaxed),
        candidates: normalized,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::url_policy::validate_and_normalize_url;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::str::FromStr;

    fn parse_ip(value: &str) -> IpAddr {
        IpAddr::from_str(value).unwrap()
    }

    fn parse_ipv4(value: &str) -> Ipv4Addr {
        value.parse().unwrap()
    }

    fn parse_ipv6(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    fn assert_ipv4_range_bounds(
        network: &str,
        prefix: u8,
        expected: IpSafetyClass,
        before: Option<IpSafetyClass>,
        after: Option<IpSafetyClass>,
    ) {
        let start = u32::from(parse_ipv4(network));
        let width = 32 - prefix;
        let end = start | ((1_u32 << width) - 1);
        for value in [start, end] {
            assert_eq!(
                classify_ip(IpAddr::V4(Ipv4Addr::from(value))),
                expected,
                "{network}/{prefix} boundary {value}"
            );
        }
        if let Some(expected) = before {
            assert_eq!(
                classify_ip(IpAddr::V4(Ipv4Addr::from(start - 1))),
                expected,
                "before {network}/{prefix}"
            );
        }
        if let Some(expected) = after {
            assert_eq!(
                classify_ip(IpAddr::V4(Ipv4Addr::from(end + 1))),
                expected,
                "after {network}/{prefix}"
            );
        }
    }

    fn assert_ipv6_range_bounds(
        network: &str,
        prefix: u8,
        expected: IpSafetyClass,
        before_is_global: Option<bool>,
        after_is_global: Option<bool>,
    ) {
        let start = u128::from(parse_ipv6(network));
        let width = 128 - prefix;
        let end = start | ((1_u128 << width) - 1);
        for value in [start, end] {
            assert_eq!(
                classify_ip(IpAddr::V6(Ipv6Addr::from(value))),
                expected,
                "{network}/{prefix} boundary {value:x}"
            );
        }
        if let Some(expected) = before_is_global {
            assert_eq!(
                classify_ip(IpAddr::V6(Ipv6Addr::from(start - 1))) == IpSafetyClass::Global,
                expected,
                "before {network}/{prefix}"
            );
        }
        if let Some(expected) = after_is_global {
            assert_eq!(
                classify_ip(IpAddr::V6(Ipv6Addr::from(end + 1))) == IpSafetyClass::Global,
                expected,
                "after {network}/{prefix}"
            );
        }
    }

    fn remote_target() -> ValidatedTransportTarget {
        validate_and_normalize_url("https://example.com/").unwrap()
    }

    fn loopback_target() -> ValidatedTransportTarget {
        validate_and_normalize_url("http://localhost/").unwrap()
    }

    #[test]
    fn normalize_mapped_ipv6_only() {
        assert_eq!(
            normalize_ip(parse_ip("::ffff:127.0.0.1")),
            parse_ip("127.0.0.1")
        );
        assert_eq!(
            normalize_ip(parse_ip("::ffff:10.0.0.1")),
            parse_ip("10.0.0.1")
        );
        assert_eq!(
            normalize_ip(parse_ip("::ffff:192.0.2.1")),
            parse_ip("192.0.2.1")
        );
        assert_eq!(
            normalize_ip(parse_ip("::192.0.2.1")),
            parse_ip("::192.0.2.1")
        );

        let cases = [
            ("::ffff:127.0.0.1", "127.0.0.1", IpSafetyClass::Loopback),
            ("::ffff:10.0.0.1", "10.0.0.1", IpSafetyClass::Private),
            (
                "::ffff:192.0.2.1",
                "192.0.2.1",
                IpSafetyClass::Documentation,
            ),
            ("::ffff:198.18.0.1", "198.18.0.1", IpSafetyClass::Benchmark),
        ];

        for (mapped_str, normalized_str, expected_class) in cases {
            let mapped_ip = parse_ip(mapped_str);
            let normalized_ip = parse_ip(normalized_str);

            assert_eq!(normalize_ip(mapped_ip), normalized_ip);
            assert_eq!(classify_ip(mapped_ip), expected_class);
            assert_eq!(classify_ip(normalized_ip), expected_class);
            assert_ne!(classify_ip(mapped_ip), IpSafetyClass::Global);
        }

        let non_mapped = parse_ip("2001:db8::1");
        assert_eq!(normalize_ip(non_mapped), non_mapped);
        assert_eq!(classify_ip(non_mapped), IpSafetyClass::Documentation);
    }

    #[test]
    fn ipv4_special_ranges_have_boundaries() {
        assert_ipv4_range_bounds(
            "0.0.0.0",
            8,
            IpSafetyClass::ReservedOrSpecial,
            None,
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "10.0.0.0",
            8,
            IpSafetyClass::Private,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "100.64.0.0",
            10,
            IpSafetyClass::CarrierGradeNat,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "127.0.0.0",
            8,
            IpSafetyClass::Loopback,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "169.254.0.0",
            16,
            IpSafetyClass::LinkLocal,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "172.16.0.0",
            12,
            IpSafetyClass::Private,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.0.0.0",
            24,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.0.2.0",
            24,
            IpSafetyClass::Documentation,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.31.196.0",
            24,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.52.193.0",
            24,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.88.99.0",
            24,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.168.0.0",
            16,
            IpSafetyClass::Private,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "192.175.48.0",
            24,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "198.18.0.0",
            15,
            IpSafetyClass::Benchmark,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "198.51.100.0",
            24,
            IpSafetyClass::Documentation,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "203.0.113.0",
            24,
            IpSafetyClass::Documentation,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::Global),
        );
        assert_ipv4_range_bounds(
            "224.0.0.0",
            4,
            IpSafetyClass::Multicast,
            Some(IpSafetyClass::Global),
            Some(IpSafetyClass::ReservedOrSpecial),
        );
        assert_ipv4_range_bounds(
            "240.0.0.0",
            4,
            IpSafetyClass::ReservedOrSpecial,
            Some(IpSafetyClass::Multicast),
            None,
        );

        let cases = [
            ("192.88.98.255", IpSafetyClass::Global),
            ("192.88.99.0", IpSafetyClass::ReservedOrSpecial),
            ("192.88.99.255", IpSafetyClass::ReservedOrSpecial),
            ("192.88.100.0", IpSafetyClass::Global),
            ("198.17.255.255", IpSafetyClass::Global),
            ("198.18.0.0", IpSafetyClass::Benchmark),
            ("198.19.255.255", IpSafetyClass::Benchmark),
            ("198.20.0.0", IpSafetyClass::Global),
            ("224.0.0.0", IpSafetyClass::Multicast),
            ("239.255.255.255", IpSafetyClass::Multicast),
            ("240.0.0.0", IpSafetyClass::ReservedOrSpecial),
            ("255.255.255.255", IpSafetyClass::ReservedOrSpecial),
            ("192.0.0.0", IpSafetyClass::ReservedOrSpecial),
            ("192.0.0.255", IpSafetyClass::ReservedOrSpecial),
            ("192.0.1.255", IpSafetyClass::Global),
        ];
        for (input, expected) in cases {
            assert_eq!(classify_ip(parse_ip(input)), expected, "{input}");
        }
    }

    #[test]
    fn ipv6_is_positive_global_only() {
        assert_ipv6_range_bounds(
            "64:ff9b::",
            96,
            IpSafetyClass::ReservedOrSpecial,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "64:ff9b:1::",
            48,
            IpSafetyClass::ReservedOrSpecial,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "100::",
            64,
            IpSafetyClass::ReservedOrSpecial,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "2001::",
            23,
            IpSafetyClass::ReservedOrSpecial,
            Some(true),
            Some(true),
        );
        assert_ipv6_range_bounds(
            "2001:2::",
            48,
            IpSafetyClass::Benchmark,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "2001:db8::",
            32,
            IpSafetyClass::Documentation,
            Some(true),
            Some(true),
        );
        assert_ipv6_range_bounds(
            "2002::",
            16,
            IpSafetyClass::ReservedOrSpecial,
            Some(true),
            Some(true),
        );
        assert_ipv6_range_bounds(
            "3ffe::",
            16,
            IpSafetyClass::ReservedOrSpecial,
            Some(true),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "3fff::",
            20,
            IpSafetyClass::ReservedOrSpecial,
            Some(false),
            Some(true),
        );
        assert_ipv6_range_bounds(
            "fc00::",
            7,
            IpSafetyClass::Private,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "fec0::",
            10,
            IpSafetyClass::ReservedOrSpecial,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds(
            "fe80::",
            10,
            IpSafetyClass::LinkLocal,
            Some(false),
            Some(false),
        );
        assert_ipv6_range_bounds("ff00::", 8, IpSafetyClass::Multicast, Some(false), None);

        let cases = [
            ("2001:4860:4860::8888", IpSafetyClass::Global),
            ("::192.0.2.1", IpSafetyClass::ReservedOrSpecial),
            ("64:ff9b::1", IpSafetyClass::ReservedOrSpecial),
            ("64:ff9b:1::1", IpSafetyClass::ReservedOrSpecial),
            ("100::1", IpSafetyClass::ReservedOrSpecial),
            ("2001::1", IpSafetyClass::ReservedOrSpecial),
            ("2001:2::1", IpSafetyClass::Benchmark),
            ("2001:10::1", IpSafetyClass::ReservedOrSpecial),
            ("2001:20::1", IpSafetyClass::ReservedOrSpecial),
            ("2001:db8::1", IpSafetyClass::Documentation),
            ("2002::1", IpSafetyClass::ReservedOrSpecial),
            ("3ffe::1", IpSafetyClass::ReservedOrSpecial),
            ("fec0::1", IpSafetyClass::ReservedOrSpecial),
            ("fe80::1", IpSafetyClass::LinkLocal),
            ("fc00::1", IpSafetyClass::Private),
            ("ff02::1", IpSafetyClass::Multicast),
        ];
        for (input, expected) in cases {
            assert_eq!(classify_ip(parse_ip(input)), expected, "{input}");
        }
    }

    #[test]
    fn dns_reads_no_more_than_seventeen_items() {
        struct CountingIter {
            values: Vec<IpAddr>,
            next_index: usize,
            polls: Rc<Cell<usize>>,
        }

        impl Iterator for CountingIter {
            type Item = IpAddr;

            fn next(&mut self) -> Option<Self::Item> {
                self.polls.set(self.polls.get() + 1);
                let value = self.values.get(self.next_index).copied();
                self.next_index += usize::from(value.is_some());
                value
            }
        }

        let polls = Rc::new(Cell::new(0));
        let values = (1..=64)
            .map(|last| parse_ip(&format!("8.8.8.{last}")))
            .collect();
        let result = validate_resolved_candidates(
            &remote_target(),
            CountingIter {
                values,
                next_index: 0,
                polls: Rc::clone(&polls),
            },
        );
        assert_eq!(
            result.unwrap_err(),
            TransportPolicyError::TooManyDnsCandidates
        );
        assert_eq!(polls.get(), 17);
    }

    #[test]
    fn dns_policy_is_bounded_deduplicated_and_sealed() {
        let target = remote_target();
        assert_eq!(
            validate_resolved_candidates(&target, Vec::<IpAddr>::new()).unwrap_err(),
            TransportPolicyError::EmptyDnsResult
        );

        let sixteen_duplicates = vec![parse_ip("1.1.1.1"); 16];
        let set = validate_resolved_candidates(&target, sixteen_duplicates).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains_normalized(parse_ip("::ffff:1.1.1.1")));

        let seventeen_duplicates = vec![parse_ip("1.1.1.1"); 17];
        assert_eq!(
            validate_resolved_candidates(&target, seventeen_duplicates).unwrap_err(),
            TransportPolicyError::TooManyDnsCandidates
        );

        let set = validate_resolved_candidates(
            &target,
            [
                parse_ip("1.1.1.1"),
                parse_ip("::ffff:1.1.1.1"),
                parse_ip("8.8.8.8"),
            ],
        )
        .unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.iter()
                .map(|candidate| candidate.ip())
                .collect::<Vec<_>>(),
            [parse_ip("1.1.1.1"), parse_ip("8.8.8.8")]
        );

        assert_eq!(
            validate_resolved_candidates(&target, [parse_ip("1.1.1.1"), parse_ip("10.0.0.1")])
                .unwrap_err(),
            TransportPolicyError::MixedUnsafeDnsResult
        );
        assert_eq!(
            validate_resolved_candidates(
                &loopback_target(),
                [parse_ip("127.0.0.1"), parse_ip("10.0.0.1")]
            )
            .unwrap_err(),
            TransportPolicyError::MixedUnsafeDnsResult
        );

        assert!(!format!("{set:?}").contains("1.1.1.1"));
    }

    #[test]
    fn peer_must_use_a_candidate_from_its_own_set() {
        let target = remote_target();
        let first = validate_resolved_candidates(&target, [parse_ip("1.1.1.1")]).unwrap();
        let second = validate_resolved_candidates(&target, [parse_ip("8.8.8.8")]).unwrap();
        let first_candidate = first.candidate(0).unwrap();
        let second_candidate = second.candidate(0).unwrap();

        assert!(first
            .validate_connected_peer(
                &target,
                &first_candidate,
                SocketAddr::new(parse_ip("1.1.1.1"), target.port()),
            )
            .is_ok());
        assert_eq!(
            first
                .validate_connected_peer(
                    &target,
                    &second_candidate,
                    SocketAddr::new(parse_ip("8.8.8.8"), target.port()),
                )
                .unwrap_err(),
            TransportPolicyError::PeerMismatch
        );
        assert_eq!(
            first
                .validate_connected_peer(
                    &target,
                    &first_candidate,
                    SocketAddr::new(parse_ip("8.8.8.8"), target.port()),
                )
                .unwrap_err(),
            TransportPolicyError::PeerMismatch
        );
        assert_eq!(
            first
                .validate_connected_peer(
                    &target,
                    &first_candidate,
                    SocketAddr::new(parse_ip("1.1.1.1"), target.port() + 1),
                )
                .unwrap_err(),
            TransportPolicyError::PeerMismatch
        );

        let mapped_global =
            validate_resolved_candidates(&target, [parse_ip("::ffff:1.1.1.1")]).unwrap();
        let mapped_candidate = mapped_global.candidate(0).unwrap();
        assert!(mapped_global
            .validate_connected_peer(
                &target,
                &mapped_candidate,
                SocketAddr::new(parse_ip("1.1.1.1"), target.port()),
            )
            .is_ok());

        let loopback =
            validate_resolved_candidates(&loopback_target(), [parse_ip("127.0.0.1")]).unwrap();
        let candidate = loopback.candidate(0).unwrap();
        assert!(loopback
            .validate_connected_peer(
                &loopback_target(),
                &candidate,
                SocketAddr::new(parse_ip("127.0.0.1"), 80),
            )
            .is_ok());
        assert_eq!(
            loopback
                .validate_connected_peer(
                    &loopback_target(),
                    &candidate,
                    SocketAddr::new(parse_ip("127.0.0.2"), 80),
                )
                .unwrap_err(),
            TransportPolicyError::PeerMismatch
        );
        assert!(!format!("{candidate:?}").contains("127.0.0.1"));
    }

    #[test]
    fn cross_kind_loopback_set_remote_target_rejection() {
        let loopback_tgt = loopback_target();
        let remote_tgt = remote_target();

        let loopback_set =
            validate_resolved_candidates(&loopback_tgt, [parse_ip("127.0.0.1")]).unwrap();
        let loopback_cand = loopback_set.candidate(0).unwrap();

        let peer_addr = SocketAddr::new(parse_ip("127.0.0.1"), remote_tgt.port());
        let err = loopback_set
            .validate_connected_peer(&remote_tgt, &loopback_cand, peer_addr)
            .unwrap_err();
        assert_eq!(err, TransportPolicyError::UnsafePeer);

        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains("127.0.0.1"));
        assert!(!display.contains("443"));
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("443"));
    }

    #[test]
    fn cross_kind_global_set_loopback_target_rejection() {
        let loopback_tgt = loopback_target();
        let remote_tgt = remote_target();

        let global_set = validate_resolved_candidates(&remote_tgt, [parse_ip("1.1.1.1")]).unwrap();
        let global_cand = global_set.candidate(0).unwrap();

        let peer_addr = SocketAddr::new(parse_ip("1.1.1.1"), loopback_tgt.port());
        let err = global_set
            .validate_connected_peer(&loopback_tgt, &global_cand, peer_addr)
            .unwrap_err();
        assert_eq!(err, TransportPolicyError::UnsafePeer);

        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains("1.1.1.1"));
        assert!(!display.contains("80"));
        assert!(!debug.contains("1.1.1.1"));
        assert!(!debug.contains("80"));
    }

    #[test]
    fn same_ip_different_candidateset_rejection() {
        let target = remote_target();
        let first = validate_resolved_candidates(&target, [parse_ip("1.1.1.1")]).unwrap();
        let third = validate_resolved_candidates(&target, [parse_ip("1.1.1.1")]).unwrap();
        let third_candidate = third.candidate(0).unwrap();

        let err = first
            .validate_connected_peer(
                &target,
                &third_candidate,
                SocketAddr::new(parse_ip("1.1.1.1"), target.port()),
            )
            .unwrap_err();
        assert_eq!(err, TransportPolicyError::PeerMismatch);

        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains("1.1.1.1"));
        assert!(!display.contains("443"));
        assert!(!debug.contains("1.1.1.1"));
        assert!(!debug.contains("443"));
    }
}
