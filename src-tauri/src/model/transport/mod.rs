pub(crate) mod connector;
pub(crate) mod header_limit_io;
pub(crate) mod http1;
pub(crate) mod ip_policy;
pub(crate) mod tls;
pub(crate) mod url_policy;

use std::fmt;

/// D-8C2 applies this DNS-answer cap before opening a connection.
#[allow(dead_code)]
pub(crate) const MAX_DNS_CANDIDATES: usize = 16;
/// D-8C2 enforces this raw URL input bound at the policy boundary.
#[allow(dead_code)]
pub(crate) const MAX_TRANSPORT_BASE_URL_BYTES: usize = 4096;
/// Frozen for D-8C2 request admission.
#[allow(dead_code)]
pub(crate) const CONNECT_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Frozen for D-8C2 request admission.
#[allow(dead_code)]
pub(crate) const TRANSPORT_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
/// Frozen for D-8C3 outbound request framing.
#[allow(dead_code)]
pub(crate) const MAX_REQUEST_BODY_BYTES: u64 = 262144;
/// Dedicated D26-A bound for a single sensitive multimodal request body.
/// Regular Chat, Embedding, and Candidate Extraction requests keep the
/// smaller `MAX_REQUEST_BODY_BYTES` admission unchanged.
pub(crate) const MAX_SENSITIVE_REQUEST_BODY_BYTES: u64 = 12 * 1024 * 1024;
/// Frozen for D-8C3 inbound body collection.
#[allow(dead_code)]
pub(crate) const MAX_RESPONSE_BODY_BYTES: u64 = 1048576;
/// Frozen for D-8C3 HTTP/1 header admission.
#[allow(dead_code)]
pub(crate) const MAX_RESPONSE_HEADER_BYTES: usize = 32768;
/// Frozen for D-8C3 HTTP/1 header admission.
#[allow(dead_code)]
pub(crate) const MAX_HEADERS_PER_BLOCK: usize = 128;
/// Frozen for D-8C3 bounded header staging.
#[allow(dead_code)]
pub(crate) const HEADER_STAGING_BYTES: usize = 8192;
/// Frozen for D-8C2 transport scheduling.
#[allow(dead_code)]
pub(crate) const MAX_TRANSPORT_CONCURRENCY: usize = 4;

/// D-8C2 maps only these fixed, non-sensitive policy outcomes across its boundary.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportPolicyError {
    BaseUrlTooLong,
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
            Self::BaseUrlTooLong => "Transport base URL is too long",
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
