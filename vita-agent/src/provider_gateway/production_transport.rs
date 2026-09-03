//! Production-only provider HTTPS transport foundation.
//!
//! This module is intentionally below the gateway's library seam.  It is not
//! wired into the Tauri command surface, frontend, Chat Completions listener,
//! or autonomy/CapabilityGrant code in D29-G1.

use std::fmt::{self, Formatter};
use std::io::Read;
use std::marker::PhantomData;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use zeroize::Zeroizing;

use super::{
    is_forbidden_ip, is_forbidden_network_host, ProviderEndpoint, ProviderRequestTransport,
    ProviderRetryPolicy, ResolvedCredential, VitaAgentError,
};

const MAX_RETRY_COUNT: u8 = 2;
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(5);
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Independent bounds used by the production transport.
///
/// reqwest's blocking client applies `connect_timeout` to the TCP/TLS
/// connection phase and `timeout` to the request, including response-body
/// reads.  The two configured handshake bounds are combined with the smaller
/// value, so neither TCP connect nor TLS handshake can exceed its limit.  DNS
/// is resolved before the client is built and has its own bounded wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProductionTransportLimits {
    pub(crate) dns_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) tls_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) body_timeout: Duration,
    pub(crate) total_timeout: Duration,
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_response_header_bytes: usize,
    pub(crate) max_response_body_bytes: usize,
}

impl Default for ProductionTransportLimits {
    fn default() -> Self {
        Self {
            dns_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(10),
            tls_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(120),
            body_timeout: Duration::from_secs(120),
            total_timeout: Duration::from_secs(120),
            max_request_body_bytes: MAX_REQUEST_BODY_BYTES,
            max_response_header_bytes: MAX_RESPONSE_HEADER_BYTES,
            max_response_body_bytes: MAX_RESPONSE_BODY_BYTES,
        }
    }
}

impl ProductionTransportLimits {
    fn validate(self) -> Result<(), VitaAgentError> {
        let timeouts = [
            self.dns_timeout,
            self.connect_timeout,
            self.tls_timeout,
            self.request_timeout,
            self.body_timeout,
            self.total_timeout,
        ];
        if timeouts.iter().any(Duration::is_zero) {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "production transport timeouts must be greater than zero",
            });
        }
        if timeouts.iter().any(|timeout| *timeout > MAX_TIMEOUT) {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "production transport timeouts exceed the 300-second bound",
            });
        }
        if self.max_request_body_bytes == 0
            || self.max_response_header_bytes == 0
            || self.max_response_body_bytes == 0
        {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "production transport size limits must be greater than zero",
            });
        }
        if self.max_request_body_bytes > MAX_REQUEST_BODY_BYTES
            || self.max_response_header_bytes > MAX_RESPONSE_HEADER_BYTES
            || self.max_response_body_bytes > MAX_RESPONSE_BODY_BYTES
        {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "production transport size limits exceed the hard bound",
            });
        }
        Ok(())
    }
}

/// A DNS resolver kept behind a small seam so every returned address can be
/// checked before a socket connection is attempted.
trait DnsResolver: Clone + Send + Sync + 'static {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, VitaAgentError>;
}

#[derive(Debug, Clone, Copy, Default)]
struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, VitaAgentError> {
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|_| VitaAgentError::ProviderTransportRejected {
                reason: "provider DNS resolution failed",
            })
    }
}

struct DnsWork {
    host: String,
    port: u16,
    reply: mpsc::SyncSender<Result<Vec<SocketAddr>, VitaAgentError>>,
}

/// Owns one long-lived resolver worker for one production transport.
///
/// The rendezvous channel is intentional: while the resolver is blocked, a
/// later request cannot enqueue another job and cannot create another thread.
/// If the underlying OS resolver cannot be cancelled, at most this one worker
/// remains occupied until it returns; callers fail closed while it is busy.
struct BoundedDnsWorker<D> {
    sender: mpsc::SyncSender<DnsWork>,
    _thread: thread::JoinHandle<()>,
    _resolver: PhantomData<fn() -> D>,
}

impl<D> BoundedDnsWorker<D>
where
    D: DnsResolver,
{
    fn new(resolver: D) -> Result<Self, VitaAgentError> {
        let (sender, receiver) = mpsc::sync_channel::<DnsWork>(0);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("vita-provider-dns".to_string())
            .spawn(move || {
                let _ = ready_sender.send(());
                while let Ok(work) = receiver.recv() {
                    let result = resolver.resolve(&work.host, work.port);
                    let _ = work.reply.send(result);
                }
            })
            .map_err(|_| VitaAgentError::ProviderTransportRejected {
                reason: "provider DNS resolver worker could not start",
            })?;
        ready_receiver
            .recv()
            .map_err(|_| VitaAgentError::ProviderTransportRejected {
                reason: "provider DNS resolver worker stopped during startup",
            })?;
        Ok(Self {
            sender,
            _thread: thread,
            _resolver: PhantomData,
        })
    }

    fn resolve_with_timeout(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, VitaAgentError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(DnsWork {
                host: host.to_string(),
                port,
                reply: reply_sender,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => VitaAgentError::ProviderTransportRejected {
                    reason: "provider DNS resolver is busy after an earlier timeout",
                },
                mpsc::TrySendError::Disconnected(_) => VitaAgentError::ProviderTransportRejected {
                    reason: "provider DNS resolver stopped without a result",
                },
            })?;
        match reply_receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(VitaAgentError::ProviderTransportTimeout {
                phase: "DNS resolution",
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(VitaAgentError::ProviderTransportRejected {
                    reason: "provider DNS resolver stopped without a result",
                })
            }
        }
    }
}

/// The HTTP executor is separated from the policy so DNS/SSRF and retry tests
/// can run without making an external request.
trait HttpExecutor {
    fn post_json(
        &self,
        request: &OutboundRequest<'_>,
        timeouts: EffectiveTimeouts,
        deadline: Instant,
        limits: ProductionTransportLimits,
    ) -> Result<ProviderHttpResponse, HttpExecutionError>;
}

#[derive(Debug, Clone, Copy, Default)]
struct ReqwestHttpExecutor;

/// The request view passed to an executor.  Its Debug implementation never
/// includes request bytes or credential material.
struct OutboundRequest<'a> {
    url: String,
    host: &'a str,
    port: u16,
    path: String,
    addresses: &'a [SocketAddr],
    body: &'a [u8],
    authorization: Option<&'a ResolvedCredential>,
}

impl fmt::Debug for OutboundRequest<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundRequest")
            .field("url", &self.url)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("resolved_address_count", &self.addresses.len())
            .field("body_len", &self.body.len())
            .field("authorization_present", &self.authorization.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct ProviderHttpResponse {
    status: u16,
    header_bytes: usize,
    body: Vec<u8>,
}

impl fmt::Debug for ProviderHttpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderHttpResponse")
            .field("status", &self.status)
            .field("header_bytes", &self.header_bytes)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Debug)]
enum HttpExecutionError {
    Retryable(VitaAgentError),
    Fatal(VitaAgentError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EffectiveTimeouts {
    connect: Duration,
    tls: Duration,
    request: Duration,
    body: Duration,
    total: Duration,
}

impl EffectiveTimeouts {
    fn from_remaining(remaining: Duration, limits: ProductionTransportLimits) -> Self {
        Self {
            connect: min_duration(remaining, limits.connect_timeout),
            tls: min_duration(remaining, limits.tls_timeout),
            request: min_duration(
                remaining,
                min_duration(limits.request_timeout, limits.body_timeout),
            ),
            body: min_duration(remaining, limits.body_timeout),
            total: remaining,
        }
    }
}

/// Library-only production transport.  It is not constructed by the current
/// Tauri or Chat route code; G1 only establishes the security foundation.
struct ProductionProviderTransport<D = SystemDnsResolver, H = ReqwestHttpExecutor> {
    dns: BoundedDnsWorker<D>,
    http: H,
    limits: ProductionTransportLimits,
}

impl ProductionProviderTransport<SystemDnsResolver, ReqwestHttpExecutor> {
    /// Creates a production transport with platform certificate validation and
    /// redirect handling disabled by the reqwest executor.
    fn new(limits: ProductionTransportLimits) -> Result<Self, VitaAgentError> {
        limits.validate()?;
        Ok(Self {
            dns: BoundedDnsWorker::new(SystemDnsResolver)?,
            http: ReqwestHttpExecutor,
            limits,
        })
    }
}

impl<D, H> ProductionProviderTransport<D, H>
where
    D: DnsResolver,
    H: HttpExecutor,
{
    #[cfg(test)]
    fn with_components(dns: D, http: H, limits: ProductionTransportLimits) -> Self {
        Self {
            dns: BoundedDnsWorker::new(dns).expect("test DNS worker should start"),
            http,
            limits,
        }
    }

    fn post_json_inner(
        &self,
        endpoint: &ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
    ) -> Result<Vec<u8>, VitaAgentError> {
        self.limits.validate()?;
        let total_timeout = min_duration(timeout, self.limits.total_timeout);
        if total_timeout.is_zero() {
            return Err(VitaAgentError::ProviderTransportTimeout { phase: "request" });
        }
        // This absolute deadline is created before DNS and is shared by every
        // later phase.  No phase, retry, or response-body read gets a fresh
        // copy of the caller's timeout.
        let deadline = Instant::now() + total_timeout;
        validate_production_endpoint(endpoint)?;
        validate_retry_policy(retry_policy)?;
        if body.len() > self.limits.max_request_body_bytes {
            return Err(VitaAgentError::ProviderRequestTooLarge {
                limit: self.limits.max_request_body_bytes,
            });
        }
        if let Some(credential) = authorization {
            if credential.is_empty() {
                return Err(VitaAgentError::CredentialResolution(
                    "resolved credential is empty",
                ));
            }
            credential.validate_header_safety()?;
        }

        // Resolve first, validate every answer, and pass the complete checked
        // set to reqwest's resolver override.  The URL remains the hostname,
        // so TLS SNI/certificate validation is still performed for that host;
        // the connection cannot silently perform a fresh unchecked DNS lookup.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VitaAgentError::ProviderTransportTimeout {
                phase: "DNS resolution",
            });
        }
        let mut addresses = self.dns.resolve_with_timeout(
            endpoint.host.as_str(),
            endpoint.port,
            min_duration(self.limits.dns_timeout, remaining),
        )?;
        validate_resolved_addresses(endpoint, &addresses)?;
        addresses.sort_unstable();
        addresses.dedup();

        let url = format!(
            "{}{suffix}",
            endpoint.normalized_base_url.trim_end_matches('/'),
            suffix = "/chat/completions"
        );
        if url::Url::parse(&url).is_err() {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "validated provider endpoint could not form a request URL",
            });
        }
        let path = endpoint.request_path("chat/completions");
        let attempts = retry_policy.max_retries + 1;

        for attempt in 0..attempts {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VitaAgentError::ProviderTransportTimeout { phase: "request" });
            }
            let request = OutboundRequest {
                url: url.clone(),
                host: endpoint.host.as_str(),
                port: endpoint.port,
                path: path.clone(),
                addresses: &addresses,
                body,
                authorization,
            };
            let response = match self.http.post_json(
                &request,
                EffectiveTimeouts::from_remaining(remaining, self.limits),
                deadline,
                self.limits,
            ) {
                Ok(response) => response,
                Err(HttpExecutionError::Retryable(_error)) if attempt + 1 < attempts => {
                    wait_before_retry(retry_policy.backoff, deadline)?;
                    continue;
                }
                Err(HttpExecutionError::Retryable(error)) => return Err(error),
                Err(HttpExecutionError::Fatal(error)) => return Err(error),
            };

            if Instant::now() >= deadline {
                return Err(VitaAgentError::ProviderTransportTimeout { phase: "request" });
            }
            enforce_response_limits(&response, self.limits)?;
            if (200..300).contains(&response.status) {
                return Ok(response.body);
            }
            // This includes 3xx and all retryable status classes.  A model
            // generation POST is not assumed idempotent, so an HTTP response
            // is never replayed without a future explicit idempotency design.
            // No Location header is followed and the reqwest executor is
            // configured with Policy::none, so credentials cannot be forwarded
            // to another host.
            return if (300..400).contains(&response.status) {
                Err(VitaAgentError::ProviderTransportRejected {
                    reason: "provider redirects are disabled; explicit 3xx response rejected",
                })
            } else {
                Err(VitaAgentError::ProviderHttpStatus {
                    status: response.status,
                })
            };
        }

        Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider transport retry loop terminated without a result",
        })
    }
}

impl<D, H> ProviderRequestTransport for ProductionProviderTransport<D, H>
where
    D: DnsResolver,
    H: HttpExecutor,
{
    fn post_json(
        &self,
        endpoint: &ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
    ) -> Result<Vec<u8>, VitaAgentError> {
        self.post_json_inner(endpoint, authorization, body, timeout, retry_policy)
    }
}

impl HttpExecutor for ReqwestHttpExecutor {
    fn post_json(
        &self,
        request: &OutboundRequest<'_>,
        timeouts: EffectiveTimeouts,
        deadline: Instant,
        limits: ProductionTransportLimits,
    ) -> Result<ProviderHttpResponse, HttpExecutionError> {
        let headers = build_request_headers(request.authorization)?;

        let connect_timeout = min_duration(timeouts.connect, timeouts.tls);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Do not let ambient proxy configuration replace the validated
            // destination or become an unreviewed credential recipient.
            .no_proxy()
            .connect_timeout(connect_timeout)
            // The request timeout is the strictest of request, body, and
            // caller deadline; a body read can never outlive those bounds.
            .timeout(min_duration(timeouts.request, timeouts.total))
            // The checked set is retained for this client instance.  The URL
            // itself remains the original hostname for HTTPS verification.
            .resolve_to_addrs(request.host, request.addresses)
            .build()
            .map_err(|_| {
                HttpExecutionError::Fatal(VitaAgentError::ProviderTransportRejected {
                    reason: "provider HTTPS client could not be built",
                })
            })?;

        let response = client
            .post(&request.url)
            .headers(headers)
            .body(request.body.to_vec())
            .send()
            .map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let header_bytes = response_header_bytes(response.headers());
        if header_bytes > limits.max_response_header_bytes {
            return Err(HttpExecutionError::Fatal(
                VitaAgentError::ProviderResponseTooLarge {
                    limit: limits.max_response_header_bytes,
                },
            ));
        }
        if response.content_length().is_some_and(|length| {
            usize::try_from(length)
                .map(|length| length > limits.max_response_body_bytes)
                .unwrap_or(true)
        }) {
            return Err(HttpExecutionError::Fatal(
                VitaAgentError::ProviderResponseTooLarge {
                    limit: limits.max_response_body_bytes,
                },
            ));
        }
        let body = read_bounded_response_body(response, timeouts, deadline, limits)?;
        Ok(ProviderHttpResponse {
            status,
            header_bytes,
            body,
        })
    }
}

fn build_request_headers(
    credential: Option<&ResolvedCredential>,
) -> Result<HeaderMap, HttpExecutionError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("DigitalLife/VitaAgent"),
    );
    if let Some(credential) = credential {
        let mut authorization = Zeroizing::new(Vec::with_capacity(
            b"Bearer ".len() + credential.as_bytes().len(),
        ));
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(credential.as_bytes());
        let mut value = HeaderValue::from_bytes(authorization.as_slice()).map_err(|_| {
            HttpExecutionError::Fatal(VitaAgentError::CredentialResolution(
                "resolved credential is not a valid HTTP header value",
            ))
        })?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    Ok(headers)
}

fn validate_production_endpoint(endpoint: &ProviderEndpoint) -> Result<(), VitaAgentError> {
    if endpoint.scope != super::EndpointScope::Production || endpoint.scheme != "https" {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "production transport accepts HTTPS production endpoints only",
        });
    }
    if is_forbidden_network_host(&endpoint.host) {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider endpoint host is not a permitted production destination",
        });
    }
    let reparsed = ProviderEndpoint::parse_production(&endpoint.normalized_base_url)?;
    if reparsed != *endpoint {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider endpoint changed after profile validation",
        });
    }
    Ok(())
}

fn validate_retry_policy(policy: ProviderRetryPolicy) -> Result<(), VitaAgentError> {
    if policy.max_retries > MAX_RETRY_COUNT {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider retry count exceeds the bounded production policy",
        });
    }
    if policy.backoff > MAX_RETRY_BACKOFF {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider retry backoff exceeds the bounded production policy",
        });
    }
    Ok(())
}

fn validate_resolved_addresses(
    endpoint: &ProviderEndpoint,
    addresses: &[SocketAddr],
) -> Result<(), VitaAgentError> {
    if addresses.is_empty() {
        return Err(VitaAgentError::ProviderTransportRejected {
            reason: "provider DNS returned no destination addresses",
        });
    }
    for address in addresses {
        if address.port() != endpoint.port {
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "provider DNS returned an unexpected destination port",
            });
        }
        if is_forbidden_ip(address.ip()) {
            // Check every answer and reject the entire set.  A public answer
            // does not make a mixed public/private resolution safe.
            return Err(VitaAgentError::ProviderTransportRejected {
                reason: "provider DNS resolved to loopback, private, link-local, CGNAT, multicast, documentation, or other special-use address",
            });
        }
    }
    Ok(())
}

fn enforce_response_limits(
    response: &ProviderHttpResponse,
    limits: ProductionTransportLimits,
) -> Result<(), VitaAgentError> {
    if response.header_bytes > limits.max_response_header_bytes {
        return Err(VitaAgentError::ProviderResponseTooLarge {
            limit: limits.max_response_header_bytes,
        });
    }
    if response.body.len() > limits.max_response_body_bytes {
        return Err(VitaAgentError::ProviderResponseTooLarge {
            limit: limits.max_response_body_bytes,
        });
    }
    Ok(())
}

fn response_header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())
                .and_then(|total| total.checked_add(value.as_bytes().len()))
                .and_then(|total| total.checked_add(4))
        })
        .unwrap_or(usize::MAX)
}

fn read_bounded_response_body(
    mut response: reqwest::blocking::Response,
    timeouts: EffectiveTimeouts,
    overall_deadline: Instant,
    limits: ProductionTransportLimits,
) -> Result<Vec<u8>, HttpExecutionError> {
    let body_deadline = min_instant(
        overall_deadline,
        Instant::now() + min_duration(timeouts.body, timeouts.total),
    );
    let mut body = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if Instant::now() >= body_deadline {
            return Err(HttpExecutionError::Fatal(
                VitaAgentError::ProviderTransportTimeout {
                    phase: "response body",
                },
            ));
        }
        let read = response.read(&mut buffer).map_err(|_error| {
            let mapped = VitaAgentError::ProviderTransportRejected {
                reason: "provider HTTPS response body could not be read",
            };
            // A POST may already have been accepted by the provider when a
            // body read fails.  Truncation and body timeouts are therefore
            // fail-closed instead of being replayed; only connection errors
            // are eligible for the bounded retry policy.
            HttpExecutionError::Fatal(mapped)
        })?;
        if Instant::now() >= body_deadline {
            return Err(HttpExecutionError::Fatal(
                VitaAgentError::ProviderTransportTimeout {
                    phase: "response body",
                },
            ));
        }
        if read == 0 {
            break;
        }
        if read > limits.max_response_body_bytes.saturating_sub(body.len()) {
            return Err(HttpExecutionError::Fatal(
                VitaAgentError::ProviderResponseTooLarge {
                    limit: limits.max_response_body_bytes,
                },
            ));
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

fn map_reqwest_error(error: reqwest::Error) -> HttpExecutionError {
    let mapped = VitaAgentError::ProviderTransportRejected {
        reason: "provider HTTPS request failed",
    };
    if error.is_connect() {
        HttpExecutionError::Retryable(mapped)
    } else {
        HttpExecutionError::Fatal(mapped)
    }
}

fn min_instant(left: Instant, right: Instant) -> Instant {
    left.min(right)
}

fn wait_before_retry(backoff: Duration, deadline: Instant) -> Result<(), VitaAgentError> {
    if backoff.is_zero() {
        return Ok(());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if backoff > remaining {
        return Err(VitaAgentError::ProviderTransportTimeout {
            phase: "retry backoff",
        });
    }
    thread::sleep(backoff);
    Ok(())
}

fn min_duration(left: Duration, right: Duration) -> Duration {
    left.min(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const PUBLIC_IP: [u8; 4] = [93, 184, 216, 34];
    const TEST_PORT: u16 = 443;

    #[derive(Clone)]
    enum DnsBehavior {
        Answers(Vec<SocketAddr>),
        Sleep(Duration),
    }

    #[derive(Clone)]
    struct TestDns(Arc<Mutex<DnsBehavior>>);

    impl TestDns {
        fn answers(addresses: Vec<SocketAddr>) -> Self {
            Self(Arc::new(Mutex::new(DnsBehavior::Answers(addresses))))
        }

        fn sleep(duration: Duration) -> Self {
            Self(Arc::new(Mutex::new(DnsBehavior::Sleep(duration))))
        }
    }

    impl DnsResolver for TestDns {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, VitaAgentError> {
            match self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                DnsBehavior::Answers(addresses) => Ok(addresses),
                DnsBehavior::Sleep(duration) => {
                    thread::sleep(duration);
                    Ok(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))])
                }
            }
        }
    }

    #[derive(Debug, Default)]
    struct ResolverStats {
        calls: usize,
        active: usize,
        max_active: usize,
    }

    #[derive(Clone)]
    struct StressDns {
        stats: Arc<Mutex<ResolverStats>>,
        sleep: Duration,
    }

    impl DnsResolver for StressDns {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, VitaAgentError> {
            {
                let mut stats = self
                    .stats
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                stats.calls += 1;
                stats.active += 1;
                stats.max_active = stats.max_active.max(stats.active);
            }
            thread::sleep(self.sleep);
            let mut stats = self
                .stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            stats.active -= 1;
            Ok(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))])
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Observation {
        url: String,
        host: String,
        port: u16,
        address_count: usize,
        body_len: usize,
        authorization_present: bool,
        timeouts: EffectiveTimeouts,
    }

    #[derive(Clone, Default)]
    struct TestHttp {
        responses: Arc<Mutex<VecDeque<Result<ProviderHttpResponse, HttpExecutionError>>>>,
        observations: Arc<Mutex<Vec<Observation>>>,
        delay: Duration,
    }

    impl TestHttp {
        fn with_responses(
            responses: impl IntoIterator<Item = Result<ProviderHttpResponse, HttpExecutionError>>,
        ) -> Self {
            Self::with_delay(responses, Duration::ZERO)
        }

        fn with_delay(
            responses: impl IntoIterator<Item = Result<ProviderHttpResponse, HttpExecutionError>>,
            delay: Duration,
        ) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                observations: Arc::new(Mutex::new(Vec::new())),
                delay,
            }
        }

        fn observations(&self) -> Vec<Observation> {
            self.observations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl HttpExecutor for TestHttp {
        fn post_json(
            &self,
            request: &OutboundRequest<'_>,
            timeouts: EffectiveTimeouts,
            _deadline: Instant,
            _limits: ProductionTransportLimits,
        ) -> Result<ProviderHttpResponse, HttpExecutionError> {
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            self.observations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Observation {
                    url: request.url.clone(),
                    host: request.host.to_string(),
                    port: request.port,
                    address_count: request.addresses.len(),
                    body_len: request.body.len(),
                    authorization_present: request.authorization.is_some(),
                    timeouts,
                });
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| {
                    Err(HttpExecutionError::Fatal(
                        VitaAgentError::ProviderTransportRejected {
                            reason: "test HTTP executor response queue was exhausted",
                        },
                    ))
                })
        }
    }

    fn endpoint() -> ProviderEndpoint {
        ProviderEndpoint::parse_production("https://provider.example/v1")
            .expect("production HTTPS endpoint")
    }

    fn response(status: u16, body: &[u8]) -> Result<ProviderHttpResponse, HttpExecutionError> {
        response_with_headers(status, 0, body)
    }

    fn response_with_headers(
        status: u16,
        header_bytes: usize,
        body: &[u8],
    ) -> Result<ProviderHttpResponse, HttpExecutionError> {
        Ok(ProviderHttpResponse {
            status,
            header_bytes,
            body: body.to_vec(),
        })
    }

    fn transport(dns: TestDns, http: TestHttp) -> ProductionProviderTransport<TestDns, TestHttp> {
        ProductionProviderTransport::with_components(
            dns,
            http,
            ProductionTransportLimits::default(),
        )
    }

    #[test]
    fn public_hostname_is_accepted_after_all_answers_are_checked() {
        let http = TestHttp::with_responses([response(200, br#"{}"#)]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let body = transport
            .post_json(
                &endpoint(),
                None,
                br#"{"model":"mock"}"#,
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect("public resolved destination should be accepted");
        assert_eq!(body, br#"{}"#);
        let observations = observations.observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].host, "provider.example");
        assert_eq!(observations[0].port, TEST_PORT);
        assert_eq!(observations[0].address_count, 1);
    }

    #[test]
    fn loopback_resolution_is_rejected_before_http() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from(([127, 0, 0, 1], TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("loopback must be rejected");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn rfc1918_resolution_is_rejected_before_http() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from(([10, 0, 0, 7], TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("RFC1918 must be rejected");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn mixed_public_and_private_resolution_is_rejected_as_a_set() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![
                SocketAddr::from((PUBLIC_IP, TEST_PORT)),
                SocketAddr::from(([192, 168, 1, 8], TEST_PORT)),
            ]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("mixed public/private answers must be rejected");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn mapped_forbidden_ipv6_resolution_is_rejected() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let mapped = "::ffff:10.0.0.8".parse().expect("mapped address");
        let transport = transport(
            TestDns::answers(vec![SocketAddr::new(mapped, TEST_PORT)]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("mapped private IPv6 must be rejected");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn explicit_redirect_is_rejected_without_a_second_credentialed_request() {
        let http = TestHttp::with_responses([response(302, b"")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let credential = ResolvedCredential::new("g1-test-secret");
        let error = transport
            .post_json(
                &endpoint(),
                Some(&credential),
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(2, Duration::ZERO),
            )
            .expect_err("3xx must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        let observations = observations.observations();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].authorization_present);
    }

    #[test]
    fn carriage_return_or_line_feed_in_credential_is_rejected_before_http() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let credential = ResolvedCredential::new("safe-prefix\r\nX-Injected: yes");
        let error = transport
            .post_json(
                &endpoint(),
                Some(&credential),
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("header injection bytes must be rejected");
        assert!(matches!(error, VitaAgentError::CredentialResolution(_)));
        assert!(!error.to_string().contains("X-Injected"));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn oversized_request_is_rejected_before_dns_or_http() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let observations = http.clone();
        let limits = ProductionTransportLimits {
            max_request_body_bytes: 4,
            ..ProductionTransportLimits::default()
        };
        let transport = ProductionProviderTransport::with_components(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
            limits,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"12345",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("oversized request must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::ProviderRequestTooLarge { limit: 4 }
        ));
        assert!(observations.observations().is_empty());
    }

    #[test]
    fn oversized_response_is_rejected_before_gateway_parsing() {
        let http = TestHttp::with_responses([response(200, b"12345")]);
        let observations = http.clone();
        let limits = ProductionTransportLimits {
            max_response_body_bytes: 4,
            ..ProductionTransportLimits::default()
        };
        let transport = ProductionProviderTransport::with_components(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
            limits,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("oversized response must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::ProviderResponseTooLarge { limit: 4 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn oversized_response_headers_are_rejected() {
        let http = TestHttp::with_responses([response_with_headers(200, 5, b"ok")]);
        let observations = http.clone();
        let limits = ProductionTransportLimits {
            max_response_header_bytes: 4,
            ..ProductionTransportLimits::default()
        };
        let transport = ProductionProviderTransport::with_components(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
            limits,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("oversized response headers must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::ProviderResponseTooLarge { limit: 4 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn dns_timeout_is_bounded() {
        let http = TestHttp::with_responses([response(200, b"ok")]);
        let limits = ProductionTransportLimits {
            dns_timeout: Duration::from_millis(20),
            ..ProductionTransportLimits::default()
        };
        let transport = ProductionProviderTransport::with_components(
            TestDns::sleep(Duration::from_millis(200)),
            http,
            limits,
        );
        let started = Instant::now();
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("DNS timeout must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportTimeout {
                phase: "DNS resolution"
            }
        ));
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn caller_deadline_caps_configured_dns_timeout() {
        let http = TestHttp::with_responses([response(200, b"must-not-be-called")]);
        let limits = ProductionTransportLimits {
            dns_timeout: Duration::from_secs(1),
            ..ProductionTransportLimits::default()
        };
        let transport = ProductionProviderTransport::with_components(
            TestDns::sleep(Duration::from_millis(200)),
            http,
            limits,
        );
        let started = Instant::now();
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_millis(20),
                ProviderRetryPolicy::default(),
            )
            .expect_err("caller deadline must cap DNS");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportTimeout {
                phase: "DNS resolution"
            }
        ));
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn repeated_dns_timeouts_keep_one_worker_ownership_bound() {
        let stats = Arc::new(Mutex::new(ResolverStats::default()));
        let http = TestHttp::with_responses([response(200, b"must-not-be-called")]);
        let transport = ProductionProviderTransport::with_components(
            StressDns {
                stats: stats.clone(),
                sleep: Duration::from_millis(100),
            },
            http,
            ProductionTransportLimits {
                dns_timeout: Duration::from_millis(5),
                ..ProductionTransportLimits::default()
            },
        );
        for _ in 0..8 {
            let error = transport
                .post_json(
                    &endpoint(),
                    None,
                    b"{}",
                    Duration::from_millis(20),
                    ProviderRetryPolicy::default(),
                )
                .expect_err("repeated DNS timeout must fail closed");
            assert!(matches!(
                error,
                VitaAgentError::ProviderTransportTimeout {
                    phase: "DNS resolution"
                } | VitaAgentError::ProviderTransportRejected {
                    reason: "provider DNS resolver is busy after an earlier timeout"
                }
            ));
        }
        thread::sleep(Duration::from_millis(120));
        let stats = stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.max_active, 1);
        assert_eq!(stats.active, 0);
    }

    #[test]
    fn overall_deadline_is_shared_with_http_after_dns() {
        let http = TestHttp::with_delay([response(200, b"late")], Duration::from_millis(35));
        let observations = http.clone();
        let transport = ProductionProviderTransport::with_components(
            TestDns::sleep(Duration::from_millis(35)),
            http,
            ProductionTransportLimits::default(),
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_millis(60),
                ProviderRetryPolicy::default(),
            )
            .expect_err("HTTP must not receive a fresh caller budget after DNS");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportTimeout { phase: "request" }
        ));
        let observations = observations.observations();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].timeouts.total < Duration::from_millis(35));
    }

    #[test]
    fn unauthorized_response_is_never_retried() {
        let http = TestHttp::with_responses([response(401, b"unauthorized"), response(200, b"ok")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                Some(&ResolvedCredential::new("g1-test-secret")),
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(2, Duration::ZERO),
            )
            .expect_err("401 must not be retried");
        assert!(matches!(
            error,
            VitaAgentError::ProviderHttpStatus { status: 401 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn too_many_requests_are_not_retried_for_model_post() {
        let http = TestHttp::with_responses([
            response(429, b"retry"),
            response(200, b"must-not-be-called"),
        ]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(2, Duration::ZERO),
            )
            .expect_err("429 must not replay the model POST");
        assert!(matches!(
            error,
            VitaAgentError::ProviderHttpStatus { status: 429 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn server_error_is_not_retried_for_model_post() {
        let http = TestHttp::with_responses([
            response(503, b"unavailable"),
            response(200, b"must-not-be-called"),
        ]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(2, Duration::ZERO),
            )
            .expect_err("5xx retry budget must stop");
        assert!(matches!(
            error,
            VitaAgentError::ProviderHttpStatus { status: 503 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn request_timeout_status_is_not_retried_for_model_post() {
        let http = TestHttp::with_responses([
            response(408, b"timeout"),
            response(200, b"must-not-be-called"),
        ]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(2, Duration::ZERO),
            )
            .expect_err("408 must not replay the model POST");
        assert!(matches!(
            error,
            VitaAgentError::ProviderHttpStatus { status: 408 }
        ));
        assert_eq!(observations.observations().len(), 1);
    }

    #[test]
    fn connection_retry_is_bounded_and_can_recover() {
        let http = TestHttp::with_responses([
            Err(HttpExecutionError::Retryable(
                VitaAgentError::ProviderTransportRejected {
                    reason: "test connection failure",
                },
            )),
            response(200, b"ok"),
            response(200, b"must-not-be-called"),
        ]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let body = transport
            .post_json(
                &endpoint(),
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::new(1, Duration::ZERO),
            )
            .expect("bounded connection retry should recover");
        assert_eq!(body, b"ok");
        assert_eq!(observations.observations().len(), 2);
    }

    #[test]
    fn credential_debug_and_transport_errors_do_not_contain_the_raw_value() {
        let raw = "g1-super-secret-value";
        let credential = ResolvedCredential::new(raw);
        assert!(!format!("{credential:?}").contains(raw));
        let http = TestHttp::with_responses([response(401, b"no")]);
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from((PUBLIC_IP, TEST_PORT))]),
            http,
        );
        let error = transport
            .post_json(
                &endpoint(),
                Some(&credential),
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("test unauthorized response");
        assert!(!format!("{error:?}").contains(raw));
        assert!(!error.to_string().contains(raw));
    }

    #[test]
    fn authorization_header_is_sensitive_without_exposing_credential() {
        let headers = build_request_headers(Some(&ResolvedCredential::new("test-only-secret")))
            .expect("valid test credential header");
        let authorization_present = headers.contains_key(AUTHORIZATION);
        let authorization_sensitive = headers
            .get(AUTHORIZATION)
            .is_some_and(HeaderValue::is_sensitive);
        assert!(authorization_present);
        assert!(authorization_sensitive);
    }

    #[test]
    fn production_constructor_is_https_only_and_uses_bounded_defaults() {
        let limits = ProductionTransportLimits::default();
        let transport = ProductionProviderTransport::new(limits).expect("valid defaults");
        let _ = transport;
        assert_eq!(limits.max_request_body_bytes, MAX_REQUEST_BODY_BYTES);
        assert_eq!(limits.max_response_body_bytes, MAX_RESPONSE_BODY_BYTES);
        assert!(ProviderEndpoint::parse_production("http://provider.example/v1").is_err());
    }

    #[test]
    fn production_transport_cannot_inherit_test_localhost_authority() {
        let http = TestHttp::with_responses([response(200, b"must-not-be-called")]);
        let observations = http.clone();
        let transport = transport(
            TestDns::answers(vec![SocketAddr::from(([127, 0, 0, 1], 43123))]),
            http,
        );
        let local_endpoint = ProviderEndpoint::parse_test_localhost("http://127.0.0.1:43123/v1")
            .expect("test-only endpoint");
        let error = transport
            .post_json(
                &local_endpoint,
                None,
                b"{}",
                Duration::from_secs(1),
                ProviderRetryPolicy::default(),
            )
            .expect_err("production transport must reject test localhost");
        assert!(matches!(
            error,
            VitaAgentError::ProviderTransportRejected { .. }
        ));
        assert!(observations.observations().is_empty());
    }
}
