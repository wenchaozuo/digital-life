#![allow(dead_code)]

pub(crate) mod ip_policy;
pub(crate) mod url_policy;

use std::fmt;

pub(crate) const MAX_DNS_CANDIDATES: usize = 16;
pub(crate) const CONNECT_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const TRANSPORT_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
pub(crate) const MAX_REQUEST_BODY_BYTES: u64 = 262144;
pub(crate) const MAX_RESPONSE_BODY_BYTES: u64 = 1048576;
pub(crate) const MAX_RESPONSE_HEADER_BYTES: usize = 32768;
pub(crate) const MAX_HEADERS_PER_BLOCK: usize = 128;
pub(crate) const HEADER_STAGING_BYTES: usize = 8192;
pub(crate) const MAX_TRANSPORT_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportPolicyError {
    UnsupportedScheme,
    MissingHost,
    ForbiddenUserinfo,
    ForbiddenQuery,
    ForbiddenFragment,
    ForbiddenHostForm,
    ForbiddenRemoteIpLiteral,
    ForbiddenTrailingDot,
    InvalidPort,
    UnsafePath,
    EmptyDnsResult,
    TooManyDnsCandidates,
    UnsafeDnsCandidate,
    MixedUnsafeDnsResult,
    PeerMismatch,
    UnsafePeer,
}

impl fmt::Display for TransportPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UnsupportedScheme => "Unsupported scheme",
            Self::MissingHost => "Missing host",
            Self::ForbiddenUserinfo => "Forbidden userinfo",
            Self::ForbiddenQuery => "Forbidden query",
            Self::ForbiddenFragment => "Forbidden fragment",
            Self::ForbiddenHostForm => "Forbidden host form",
            Self::ForbiddenRemoteIpLiteral => "Forbidden remote IP literal",
            Self::ForbiddenTrailingDot => "Forbidden trailing dot in hostname",
            Self::InvalidPort => "Invalid port number",
            Self::UnsafePath => "Unsafe base path traversal or format",
            Self::EmptyDnsResult => "Empty DNS resolution results",
            Self::TooManyDnsCandidates => "Too many DNS resolution candidates",
            Self::UnsafeDnsCandidate => "Unsafe address found in DNS candidates",
            Self::MixedUnsafeDnsResult => "DNS returned a mix of safe and unsafe candidates",
            Self::PeerMismatch => "Connected peer does not match selected candidate or port",
            Self::UnsafePeer => "Connected peer address classification is unsafe",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for TransportPolicyError {}
