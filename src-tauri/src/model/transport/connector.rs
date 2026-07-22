use super::ip_policy::{validate_resolved_candidates, ValidatedCandidateSet};
use super::tls;
use super::url_policy::{TransportTargetKind, ValidatedTransportTarget};
use super::CONNECT_PHASE_TIMEOUT;
use rustls::pki_types::ServerName;
use std::fmt;
#[cfg(test)]
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
#[cfg(test)]
use std::sync::Arc;
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
    TlsProtocolMismatch,
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
            Self::TlsProtocolMismatch => "TLS protocol negotiation failed",
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
    timeout_at(
        phase_deadline,
        establish_connection_orchestrated(
            target,
            ProductionResolver,
            ProductionDialer,
            ProductionTlsProvider(target),
        ),
    )
    .await
    .map_err(|_| TransportConnectError::ConnectPhaseTimeout)?
}

trait TransportResolver {
    async fn resolve(
        &self,
        target: &ValidatedTransportTarget,
    ) -> Result<Vec<IpAddr>, TransportConnectError>;
}

trait TransportDialer {
    async fn dial(&self, candidate_ip: IpAddr, port: u16) -> io::Result<(TcpStream, SocketAddr)>;
}

trait TlsConnectorProvider {
    fn connector(&self) -> Result<(TlsConnector, ServerName<'static>), TransportConnectError>;
}

struct ProductionResolver;

impl TransportResolver for ProductionResolver {
    async fn resolve(
        &self,
        target: &ValidatedTransportTarget,
    ) -> Result<Vec<IpAddr>, TransportConnectError> {
        match (target.kind(), target.host_ascii().parse::<IpAddr>()) {
            (TransportTargetKind::LoopbackHttp, Ok(ip)) => Ok(vec![ip]),
            _ => {
                let addresses = tokio::net::lookup_host((target.host_ascii(), target.port()))
                    .await
                    .map_err(|_| TransportConnectError::DnsResolutionFailed)?;
                Ok(addresses.map(|address| address.ip()).collect())
            }
        }
    }
}

struct ProductionDialer;

impl TransportDialer for ProductionDialer {
    async fn dial(&self, candidate_ip: IpAddr, port: u16) -> io::Result<(TcpStream, SocketAddr)> {
        let address = SocketAddr::new(candidate_ip, port);
        let stream = TcpStream::connect(address).await?;
        let peer = stream.peer_addr()?;
        Ok((stream, peer))
    }
}

struct ProductionTlsProvider<'a>(&'a ValidatedTransportTarget);

impl<'a> TlsConnectorProvider for ProductionTlsProvider<'a> {
    fn connector(&self) -> Result<(TlsConnector, ServerName<'static>), TransportConnectError> {
        let config = tls::production_client_config()
            .map_err(|_| TransportConnectError::TlsConfigurationFailed)?;
        let server_name = tls::server_name(self.0.host_ascii())
            .map_err(|_| TransportConnectError::TlsIdentityFailed)?;
        Ok((TlsConnector::from(config), server_name))
    }
}

async fn establish_connection_orchestrated<R, D, T>(
    target: &ValidatedTransportTarget,
    resolver: R,
    dialer: D,
    tls_provider: T,
) -> Result<EstablishedTransport, TransportConnectError>
where
    R: TransportResolver,
    D: TransportDialer,
    T: TlsConnectorProvider,
{
    let resolved_ips = resolver.resolve(target).await?;
    let candidates = validate_resolved_candidates(target, resolved_ips)
        .map_err(|_| TransportConnectError::DnsResultRejected)?;

    let mut saw_peer_failure = false;
    for candidate in candidates.iter() {
        let (stream, peer) = match dialer.dial(candidate.ip(), target.port()).await {
            Ok(res) => res,
            Err(_) => {
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

        return establish_protocol_orchestrated(target, stream, &tls_provider).await;
    }

    Err(if saw_peer_failure {
        TransportConnectError::PeerValidationFailed
    } else {
        TransportConnectError::TcpConnectFailed
    })
}

async fn establish_protocol_orchestrated<T: TlsConnectorProvider>(
    target: &ValidatedTransportTarget,
    stream: TcpStream,
    tls_provider: &T,
) -> Result<EstablishedTransport, TransportConnectError> {
    match target.kind() {
        TransportTargetKind::LoopbackHttp => Ok(EstablishedTransport {
            stream: EstablishedTransportStream::Plain(stream),
        }),
        TransportTargetKind::RemoteHttps => {
            let (connector, server_name) = tls_provider.connector()?;
            establish_tls_stream(connector, server_name, stream).await
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
            establish_tls_stream(TlsConnector::from(config), server_name, stream).await
        }
    }
}

async fn establish_tls_stream(
    connector: TlsConnector,
    server_name: ServerName<'static>,
    stream: TcpStream,
) -> Result<EstablishedTransport, TransportConnectError> {
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| TransportConnectError::TlsHandshakeFailed)?;
    if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(TransportConnectError::TlsProtocolMismatch);
    }
    Ok(EstablishedTransport {
        stream: EstablishedTransportStream::Tls(Box::new(stream)),
    })
}

#[cfg(test)]
async fn establish_tls_stream_for_test(
    host_ascii: &str,
    config: Arc<rustls::ClientConfig>,
    stream: TcpStream,
) -> Result<EstablishedTransport, TransportConnectError> {
    let server_name =
        tls::server_name(host_ascii).map_err(|_| TransportConnectError::TlsIdentityFailed)?;
    establish_tls_stream(TlsConnector::from(config), server_name, stream).await
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
struct TestResolver {
    ips: Vec<IpAddr>,
    call_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(test)]
impl TransportResolver for TestResolver {
    async fn resolve(
        &self,
        _target: &ValidatedTransportTarget,
    ) -> Result<Vec<IpAddr>, TransportConnectError> {
        if let Some(ref count) = self.call_count {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(self.ips.clone())
    }
}

#[cfg(test)]
struct LocalTestDialer {
    connect_addr: SocketAddr,
    reported_peer: Option<SocketAddr>,
    dial_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(test)]
impl TransportDialer for LocalTestDialer {
    async fn dial(&self, candidate_ip: IpAddr, port: u16) -> io::Result<(TcpStream, SocketAddr)> {
        if let Some(ref count) = self.dial_count {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let stream = TcpStream::connect(self.connect_addr).await?;
        let peer = self
            .reported_peer
            .unwrap_or_else(|| SocketAddr::new(candidate_ip, port));
        Ok((stream, peer))
    }
}

#[cfg(test)]
struct TestTlsProvider<'a> {
    target: &'a ValidatedTransportTarget,
    config: Arc<rustls::ClientConfig>,
}

#[cfg(test)]
impl<'a> TlsConnectorProvider for TestTlsProvider<'a> {
    fn connector(&self) -> Result<(TlsConnector, ServerName<'static>), TransportConnectError> {
        let server_name = tls::server_name(self.target.host_ascii())
            .map_err(|_| TransportConnectError::TlsIdentityFailed)?;
        Ok((TlsConnector::from(self.config.clone()), server_name))
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn establish_connection_for_test(
    target: &ValidatedTransportTarget,
    total_deadline: Instant,
    resolved_ips: Vec<IpAddr>,
    connect_addr: SocketAddr,
    reported_peer: Option<SocketAddr>,
    tls_config: Arc<rustls::ClientConfig>,
    resolver_calls: Option<Arc<std::sync::atomic::AtomicUsize>>,
    dial_calls: Option<Arc<std::sync::atomic::AtomicUsize>>,
) -> Result<EstablishedTransport, TransportConnectError> {
    let now = Instant::now();
    if total_deadline <= now {
        return Err(TransportConnectError::ConnectPhaseTimeout);
    }
    let phase_deadline = std::cmp::min(now + CONNECT_PHASE_TIMEOUT, total_deadline);
    timeout_at(
        phase_deadline,
        establish_connection_orchestrated(
            target,
            TestResolver {
                ips: resolved_ips,
                call_count: resolver_calls,
            },
            LocalTestDialer {
                connect_addr,
                reported_peer,
                dial_count: dial_calls,
            },
            TestTlsProvider {
                target,
                config: tls_config,
            },
        ),
    )
    .await
    .map_err(|_| TransportConnectError::ConnectPhaseTimeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::tls::test_support::{
        fixture_client_config, fixture_server_config,
    };
    use crate::model::transport::url_policy::validate_and_normalize_url;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

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

    #[tokio::test]
    async fn production_tls_stream_requires_exact_http11_alpn() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(fixture_server_config(vec![b"http/1.1".to_vec()]))
                .accept(stream)
                .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        assert!(
            establish_tls_stream_for_test("foobar.com", fixture_client_config(true), stream)
                .await
                .is_ok()
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn production_tls_stream_rejects_missing_alpn_without_leaking_protocol_data() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(fixture_server_config(Vec::new()))
                .accept(stream)
                .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let error =
            match establish_tls_stream_for_test("foobar.com", fixture_client_config(true), stream)
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("missing ALPN must not produce an established transport"),
            };
        assert_eq!(error, TransportConnectError::TlsProtocolMismatch);
        let rendered = format!("{error:?} {error}");
        for canary in ["h2", "http/1.1", "foobar.com", "secret-cert-canary", "443"] {
            assert!(!rendered.contains(canary));
        }
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn production_tls_stream_never_establishes_h2_only_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(fixture_server_config(vec![b"h2".to_vec()]))
                .accept(stream)
                .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let error =
            match establish_tls_stream_for_test("foobar.com", fixture_client_config(true), stream)
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("h2-only peer must not produce an established transport"),
            };
        assert!(matches!(
            error,
            TransportConnectError::TlsHandshakeFailed | TransportConnectError::TlsProtocolMismatch
        ));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("h2"));
        server.await.unwrap().unwrap_err();
    }

    #[tokio::test]
    async fn full_connector_path_http11_alpn_negotiation_succeeds() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let port = local_addr.port();
        let target = validate_and_normalize_url(&format!("https://foobar.com:{port}/")).unwrap();
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let dial_calls = Arc::new(AtomicUsize::new(0));
        let tls_accepted = Arc::new(AtomicBool::new(false));
        let tls_accepted_clone = Arc::clone(&tls_accepted);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(fixture_server_config(vec![b"http/1.1".to_vec()]));
            let res = acceptor.accept(stream).await;
            if res.is_ok() {
                tls_accepted_clone.store(true, Ordering::SeqCst);
            }
            res
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let global_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let res = establish_connection_for_test(
            &target,
            deadline,
            vec![global_ip],
            local_addr,
            None,
            fixture_client_config(true),
            Some(Arc::clone(&resolver_calls)),
            Some(Arc::clone(&dial_calls)),
        )
        .await;

        assert!(res.is_ok());
        server.await.unwrap().unwrap();
        assert!(tls_accepted.load(Ordering::SeqCst));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(dial_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn full_connector_path_no_alpn_rejected_with_redacted_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let port = local_addr.port();
        let target = validate_and_normalize_url(&format!("https://foobar.com:{port}/")).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(fixture_server_config(Vec::new()));
            acceptor.accept(stream).await
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let global_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let res = establish_connection_for_test(
            &target,
            deadline,
            vec![global_ip],
            local_addr,
            None,
            fixture_client_config(true),
            None,
            None,
        )
        .await;

        let err = match res {
            Err(err) => err,
            Ok(_) => panic!("missing ALPN must not establish a connection"),
        };
        assert_eq!(err, TransportConnectError::TlsProtocolMismatch);
        server.await.unwrap().unwrap();

        let rendered = format!("{err:?} {err}");
        for canary in ["h2", "http/1.1", "foobar.com", "93.184.216.34"] {
            assert!(!rendered.contains(canary));
        }
    }

    #[tokio::test]
    async fn full_connector_path_h2_only_rejected_without_establishing_transport() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let port = local_addr.port();
        let target = validate_and_normalize_url(&format!("https://foobar.com:{port}/")).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(fixture_server_config(vec![b"h2".to_vec()]));
            acceptor.accept(stream).await
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let global_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let res = establish_connection_for_test(
            &target,
            deadline,
            vec![global_ip],
            local_addr,
            None,
            fixture_client_config(true),
            None,
            None,
        )
        .await;

        let err = match res {
            Err(err) => err,
            Ok(_) => panic!("h2-only ALPN must not establish a connection"),
        };
        assert!(matches!(
            err,
            TransportConnectError::TlsHandshakeFailed | TransportConnectError::TlsProtocolMismatch
        ));
        let _ = server.await;

        let rendered = format!("{err:?} {err}");
        assert!(!rendered.contains("h2"));
    }

    #[tokio::test]
    async fn full_connector_path_peer_mismatch_blocks_tls_handshake() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let port = local_addr.port();
        let target = validate_and_normalize_url(&format!("https://foobar.com:{port}/")).unwrap();
        let tls_accepted = Arc::new(AtomicBool::new(false));
        let tls_accepted_clone = Arc::clone(&tls_accepted);

        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let acceptor = TlsAcceptor::from(fixture_server_config(vec![b"http/1.1".to_vec()]));
                let res = acceptor.accept(stream).await;
                if res.is_ok() {
                    tls_accepted_clone.store(true, Ordering::SeqCst);
                }
                res
            } else {
                Err(io::Error::other("accept failed"))
            }
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let global_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        // Report mismatched peer IP 93.184.216.35 instead of candidate 93.184.216.34
        let mismatched_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), port);

        let res = establish_connection_for_test(
            &target,
            deadline,
            vec![global_ip],
            local_addr,
            Some(mismatched_peer),
            fixture_client_config(true),
            None,
            None,
        )
        .await;

        let err = match res {
            Err(err) => err,
            Ok(_) => panic!("peer mismatch must not establish a connection"),
        };
        assert_eq!(err, TransportConnectError::PeerValidationFailed);
        assert!(!tls_accepted.load(Ordering::SeqCst));
        server.abort();
    }
}
