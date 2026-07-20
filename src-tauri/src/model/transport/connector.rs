use super::ip_policy::{validate_resolved_candidates, ValidatedCandidateSet};
use super::tls;
use super::url_policy::{TransportTargetKind, ValidatedTransportTarget};
use super::CONNECT_PHASE_TIMEOUT;
use std::fmt;
#[cfg(test)]
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::TlsConnector;

/// Fixed outcomes deliberately exclude resolver, socket, certificate, and target details.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportConnectError {
    DnsResolutionFailed,
    DnsResultRejected,
    ConnectPhaseTimeout,
    TcpConnectFailed,
    PeerValidationFailed,
    TlsConfigurationFailed,
    TlsHandshakeFailed,
    TlsIdentityFailed,
}

impl fmt::Display for TransportConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DnsResolutionFailed => "DNS resolution failed",
            Self::DnsResultRejected => "DNS results were rejected",
            Self::ConnectPhaseTimeout => "Connection phase timed out",
            Self::TcpConnectFailed => "TCP connection failed",
            Self::PeerValidationFailed => "Connected peer validation failed",
            Self::TlsConfigurationFailed => "TLS configuration failed",
            Self::TlsHandshakeFailed => "TLS handshake failed",
            Self::TlsIdentityFailed => "TLS identity validation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for TransportConnectError {}

/// An established stream intentionally carries no target, peer, resolver, or credential data.
#[allow(dead_code)]
pub(crate) struct EstablishedTransport {
    stream: EstablishedTransportStream,
}

#[allow(dead_code)]
enum EstablishedTransportStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for EstablishedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.stream {
            EstablishedTransportStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            EstablishedTransportStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EstablishedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.stream {
            EstablishedTransportStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            EstablishedTransportStream::Tls(stream) => {
                Pin::new(stream.as_mut()).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.stream {
            EstablishedTransportStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            EstablishedTransportStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.stream {
            EstablishedTransportStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            EstablishedTransportStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Resolves, validates, connects, verifies the observed peer, and (for HTTPS) handshakes TLS.
/// The caller owns the total deadline; this layer never creates a replacement total timeout.
#[allow(dead_code)]
pub(crate) async fn establish_connection(
    target: &ValidatedTransportTarget,
    total_deadline: Instant,
) -> Result<EstablishedTransport, TransportConnectError> {
    let now = Instant::now();
    if total_deadline <= now {
        return Err(TransportConnectError::ConnectPhaseTimeout);
    }
    let phase_deadline = std::cmp::min(now + CONNECT_PHASE_TIMEOUT, total_deadline);
    timeout_at(phase_deadline, establish_with_system_dns(target))
        .await
        .map_err(|_| TransportConnectError::ConnectPhaseTimeout)?
}

async fn establish_with_system_dns(
    target: &ValidatedTransportTarget,
) -> Result<EstablishedTransport, TransportConnectError> {
    let candidates = resolve_system_candidates(target).await?;
    connect_validated_candidates(target, candidates).await
}

async fn resolve_system_candidates(
    target: &ValidatedTransportTarget,
) -> Result<ValidatedCandidateSet, TransportConnectError> {
    match (target.kind(), target.host_ascii().parse::<IpAddr>()) {
        (TransportTargetKind::LoopbackHttp, Ok(ip)) => validate_resolved_candidates(target, [ip])
            .map_err(|_| TransportConnectError::DnsResultRejected),
        _ => {
            let addresses = tokio::net::lookup_host((target.host_ascii(), target.port()))
                .await
                .map_err(|_| TransportConnectError::DnsResolutionFailed)?;
            validate_resolved_candidates(target, addresses.map(|address| address.ip()))
                .map_err(|_| TransportConnectError::DnsResultRejected)
        }
    }
}

#[allow(dead_code)]
async fn connect_validated_candidates(
    target: &ValidatedTransportTarget,
    candidates: ValidatedCandidateSet,
) -> Result<EstablishedTransport, TransportConnectError> {
    let mut saw_peer_failure = false;
    for candidate in candidates.iter() {
        let address = SocketAddr::new(candidate.ip(), target.port());
        let stream = match TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(_) => {
                continue;
            }
        };
        let peer = match stream.peer_addr() {
            Ok(peer) => peer,
            Err(_) => {
                saw_peer_failure = true;
                continue;
            }
        };
        if candidates
            .validate_connected_peer(target, &candidate, peer)
            .is_err()
        {
            saw_peer_failure = true;
            continue;
        }
        return establish_protocol(target, stream).await;
    }

    Err(if saw_peer_failure {
        TransportConnectError::PeerValidationFailed
    } else {
        TransportConnectError::TcpConnectFailed
    })
}

async fn establish_protocol(
    target: &ValidatedTransportTarget,
    stream: TcpStream,
) -> Result<EstablishedTransport, TransportConnectError> {
    match target.kind() {
        TransportTargetKind::LoopbackHttp => Ok(EstablishedTransport {
            stream: EstablishedTransportStream::Plain(stream),
        }),
        TransportTargetKind::RemoteHttps => {
            let config = tls::production_client_config()
                .map_err(|_| TransportConnectError::TlsConfigurationFailed)?;
            let server_name = tls::server_name(target.host_ascii())
                .map_err(|_| TransportConnectError::TlsIdentityFailed)?;
            let stream = TlsConnector::from(config)
                .connect(server_name, stream)
                .await
                .map_err(|_| TransportConnectError::TlsHandshakeFailed)?;
            Ok(EstablishedTransport {
                stream: EstablishedTransportStream::Tls(Box::new(stream)),
            })
        }
    }
}

#[cfg(test)]
async fn establish_with_test_resolver<R, F>(
    target: &ValidatedTransportTarget,
    total_deadline: Instant,
    resolver: R,
) -> Result<EstablishedTransport, TransportConnectError>
where
    R: FnOnce() -> F,
    F: Future<Output = Result<Vec<SocketAddr>, ()>>,
{
    let now = Instant::now();
    if total_deadline <= now {
        return Err(TransportConnectError::ConnectPhaseTimeout);
    }
    let phase_deadline = std::cmp::min(now + CONNECT_PHASE_TIMEOUT, total_deadline);
    timeout_at(phase_deadline, async {
        let resolved = resolver()
            .await
            .map_err(|_| TransportConnectError::DnsResolutionFailed)?;
        let candidates =
            validate_resolved_candidates(target, resolved.into_iter().map(|item| item.ip()))
                .map_err(|_| TransportConnectError::DnsResultRejected)?;
        connect_validated_candidates(target, candidates).await
    })
    .await
    .map_err(|_| TransportConnectError::ConnectPhaseTimeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::url_policy::validate_and_normalize_url;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn loopback_literal_connects_without_dns_and_exposes_only_a_stream() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = validate_and_normalize_url(&format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let result = establish_connection(
            &target,
            Instant::now() + std::time::Duration::from_millis(250),
        )
        .await;
        assert!(result.is_ok());
        accepted.await.unwrap();
    }

    #[tokio::test]
    async fn resolver_errors_and_rejected_results_are_fixed_and_redacted() {
        let target = validate_and_normalize_url("http://localhost:80/").unwrap();
        let deadline = Instant::now() + std::time::Duration::from_millis(250);
        let error =
            match establish_with_test_resolver(&target, deadline, || async { Err(()) }).await {
                Err(error) => error,
                Ok(_) => panic!("resolver failure must not establish a connection"),
            };
        assert_eq!(error, TransportConnectError::DnsResolutionFailed);
        let error = match establish_with_test_resolver(&target, deadline, || async {
            Ok(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                9,
            )])
        })
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("unsafe DNS result must not establish a connection"),
        };
        assert_eq!(error, TransportConnectError::DnsResultRejected);
        let rendered = format!("{error:?} {error}");
        for canary in [
            "secret-host-canary",
            "secret-ip-canary",
            "secret-port-canary",
            "secret-cert-canary",
        ] {
            assert!(!rendered.contains(canary));
        }
    }

    #[tokio::test]
    async fn resolver_socket_ports_are_replaced_with_the_validated_target_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = validate_and_normalize_url(&format!(
            "http://localhost:{}/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let transport = establish_with_test_resolver(
            &target,
            Instant::now() + std::time::Duration::from_millis(250),
            || async { Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)]) },
        )
        .await;
        assert!(transport.is_ok());
        accepted.await.unwrap();
    }

    #[tokio::test]
    async fn resolver_deadline_covers_waiting_before_any_tcp_attempt() {
        let target = validate_and_normalize_url("http://localhost:80/").unwrap();
        let error = match establish_with_test_resolver(
            &target,
            Instant::now() + std::time::Duration::from_millis(20),
            std::future::pending::<Result<Vec<SocketAddr>, ()>>,
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("an unresolved DNS future must time out"),
        };
        assert_eq!(error, TransportConnectError::ConnectPhaseTimeout);
    }

    #[tokio::test]
    async fn expired_total_deadline_fails_without_starting_resolution() {
        let target = validate_and_normalize_url("http://localhost:80/").unwrap();
        let error = match establish_with_test_resolver(&target, Instant::now(), || async {
            panic!("resolver must not be called after the deadline")
        })
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("expired deadline must not establish a connection"),
        };
        assert_eq!(error, TransportConnectError::ConnectPhaseTimeout);
    }
}
