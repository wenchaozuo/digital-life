#![allow(dead_code)]

use super::connector::{establish_connection, TransportConnectError};
use super::header_limit_io::{HeaderLimitError, HeaderLimitIo};
use super::url_policy::ValidatedTransportTarget;
use super::{
    MAX_HEADERS_PER_BLOCK, MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_BYTES,
    MAX_SENSITIVE_REQUEST_BODY_BYTES, TRANSPORT_TOTAL_TIMEOUT,
};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use hyper::http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, PROXY_AUTHORIZATION, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{timeout_at, Instant};
use zeroize::Zeroizing;

const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const EXPECT: HeaderName = HeaderName::from_static("expect");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendDisposition {
    DefinitelyNotSent,
    PossiblySent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Http1ErrorKind {
    RequestTooLarge,
    RequestHeaderRejected,
    InvalidRequestTarget,
    HttpHandshakeFailed,
    HttpSendFailed,
    ResponseHeaderTooLarge,
    ResponseHeaderCountExceeded,
    ResponseHeaderMalformed,
    ProtocolUpgradeRejected,
    ContentEncodingRejected,
    ResponseBodyTooLarge,
    ResponseBodyFailed,
    TransportTimeout,
    ConnectionDriverFailed,
}

/// A fixed, redacted error that keeps only the conservative send boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Http1TransportError {
    kind: Http1ErrorKind,
    disposition: SendDisposition,
}

impl Http1TransportError {
    const fn new(kind: Http1ErrorKind, disposition: SendDisposition) -> Self {
        Self { kind, disposition }
    }

    pub(crate) const fn kind(self) -> Http1ErrorKind {
        self.kind
    }

    pub(crate) const fn disposition(self) -> SendDisposition {
        self.disposition
    }
}

impl fmt::Display for Http1TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            Http1ErrorKind::RequestTooLarge => "HTTP request body exceeds the transport limit",
            Http1ErrorKind::RequestHeaderRejected => "HTTP request headers were rejected",
            Http1ErrorKind::InvalidRequestTarget => "HTTP request target is invalid",
            Http1ErrorKind::HttpHandshakeFailed => "HTTP connection setup failed",
            Http1ErrorKind::HttpSendFailed => "HTTP request failed",
            Http1ErrorKind::ResponseHeaderTooLarge => {
                "HTTP response headers exceed the transport limit"
            }
            Http1ErrorKind::ResponseHeaderCountExceeded => {
                "HTTP response header count exceeds the transport limit"
            }
            Http1ErrorKind::ResponseHeaderMalformed => "HTTP response headers are malformed",
            Http1ErrorKind::ProtocolUpgradeRejected => "HTTP protocol upgrades are not supported",
            Http1ErrorKind::ContentEncodingRejected => {
                "HTTP response content encoding is not supported"
            }
            Http1ErrorKind::ResponseBodyTooLarge => {
                "HTTP response body exceeds the transport limit"
            }
            Http1ErrorKind::ResponseBodyFailed => "HTTP response body failed",
            Http1ErrorKind::TransportTimeout => "HTTP transport timed out",
            Http1ErrorKind::ConnectionDriverFailed => "HTTP connection driver failed",
        };
        f.write_str(message)
    }
}

impl Error for Http1TransportError {}

/// Generic sensitive-exchange outcome. The callback remains transport
/// agnostic so perception authority does not leak into this HTTP module.
pub(crate) enum SensitiveExchangeError<E> {
    PreSendGuard(E),
    Transport(Http1TransportError),
}

impl<E> From<Http1TransportError> for SensitiveExchangeError<E> {
    fn from(error: Http1TransportError) -> Self {
        Self::Transport(error)
    }
}

/// A bounded, one-shot request. It deliberately has no Clone implementation.
pub(crate) struct PreparedHttpRequest {
    method: Method,
    origin_form: String,
    headers: HeaderMap,
    body: Bytes,
}

impl PreparedHttpRequest {
    pub(crate) fn new(
        method: Method,
        origin_form: String,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Self, Http1TransportError> {
        if body.len() as u64 > MAX_REQUEST_BODY_BYTES {
            return Err(Http1TransportError::new(
                Http1ErrorKind::RequestTooLarge,
                SendDisposition::DefinitelyNotSent,
            ));
        }
        validate_origin_form(&origin_form)?;
        validate_request_headers(&headers)?;
        Ok(Self {
            method,
            origin_form,
            headers,
            body: Bytes::from(body),
        })
    }
}

impl fmt::Debug for PreparedHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedHttpRequest")
            .field("method", &self.method)
            .field("origin_form", &"redacted")
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A bounded, one-shot sensitive request. Its body remains a zeroizing byte
/// vector until ownership crosses the Hyper body boundary; it is never
/// converted to `Bytes`.
pub(crate) struct PreparedSensitiveHttpRequest {
    method: Method,
    origin_form: String,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}

impl PreparedSensitiveHttpRequest {
    pub(crate) fn new(
        method: Method,
        origin_form: String,
        headers: HeaderMap,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Self, Http1TransportError> {
        if body.len() as u64 > MAX_SENSITIVE_REQUEST_BODY_BYTES {
            return Err(Http1TransportError::new(
                Http1ErrorKind::RequestTooLarge,
                SendDisposition::DefinitelyNotSent,
            ));
        }
        validate_origin_form(&origin_form)?;
        validate_request_headers(&headers)?;
        Ok(Self {
            method,
            origin_form,
            headers,
            body,
        })
    }

    pub(crate) fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}

impl fmt::Debug for PreparedSensitiveHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSensitiveHttpRequest")
            .field("method", &self.method)
            .field("origin_form", &"redacted")
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

struct ZeroizingBody {
    data: Option<ZeroizingBodyData>,
}

impl ZeroizingBody {
    fn new(body: Zeroizing<Vec<u8>>) -> Self {
        let data = (!body.is_empty()).then_some(ZeroizingBodyData { body, offset: 0 });
        Self { data }
    }
}

impl Body for ZeroizingBody {
    type Data = ZeroizingBodyData;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.data
            .as_ref()
            .map(|data| SizeHint::with_exact(data.remaining() as u64))
            .unwrap_or_else(|| SizeHint::with_exact(0))
    }
}

struct ZeroizingBodyData {
    body: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl Buf for ZeroizingBodyData {
    fn remaining(&self) -> usize {
        self.body.len().saturating_sub(self.offset)
    }

    fn chunk(&self) -> &[u8] {
        &self.body[self.offset..]
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining());
        self.offset += count;
    }
}

/// A sealed exchange result. Response headers are intentionally filtered to empty in D-8C3.
pub(crate) struct Http1Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Http1Response {
    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for Http1Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http1Response")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Executes exactly one HTTP/1.1 exchange on a new D-8C2 connection.
pub(crate) async fn exchange(
    target: &ValidatedTransportTarget,
    request: PreparedHttpRequest,
) -> Result<Http1Response, Http1TransportError> {
    exchange_with_deadline(target, request, Instant::now() + TRANSPORT_TOTAL_TIMEOUT).await
}

/// Executes one bounded sensitive HTTP/1.1 exchange. The transport policy and
/// response handling are shared with `exchange`; only the request body owner
/// differs so the sensitive bytes are zeroized on drop.
pub(crate) async fn exchange_sensitive(
    target: &ValidatedTransportTarget,
    request: PreparedSensitiveHttpRequest,
) -> Result<Http1Response, Http1TransportError> {
    exchange_sensitive_with_guard(target, request, || Ok::<(), Infallible>(()))
        .await
        .map_err(|error| match error {
            SensitiveExchangeError::PreSendGuard(never) => match never {},
            SensitiveExchangeError::Transport(error) => error,
        })
}

/// Executes one sensitive HTTP/1.1 exchange and runs the generic authority
/// guard after handshake but immediately before the sole `send_request`.
/// Guard failure drops the zeroizing body without entering `PossiblySent`.
pub(crate) async fn exchange_sensitive_with_guard<E, F>(
    target: &ValidatedTransportTarget,
    request: PreparedSensitiveHttpRequest,
    pre_send_guard: F,
) -> Result<Http1Response, SensitiveExchangeError<E>>
where
    E: Send,
    F: FnOnce() -> Result<(), E> + Send,
{
    let PreparedSensitiveHttpRequest {
        method,
        origin_form,
        headers,
        body,
    } = request;
    let body_len = body.len();
    let hyper_request = build_hyper_request(
        target,
        method,
        origin_form,
        headers,
        body_len,
        ZeroizingBody::new(body),
    )?;
    exchange_request_with_guard(
        target,
        hyper_request,
        Instant::now() + TRANSPORT_TOTAL_TIMEOUT,
        pre_send_guard,
    )
    .await
}

async fn exchange_with_deadline(
    target: &ValidatedTransportTarget,
    request: PreparedHttpRequest,
    deadline: Instant,
) -> Result<Http1Response, Http1TransportError> {
    let PreparedHttpRequest {
        method,
        origin_form,
        headers,
        body,
    } = request;
    let body_len = body.len();
    let hyper_request = build_hyper_request(
        target,
        method,
        origin_form,
        headers,
        body_len,
        Full::new(body),
    )?;
    exchange_request_with_guard(target, hyper_request, deadline, || Ok::<(), Infallible>(()))
        .await
        .map_err(|error| match error {
            SensitiveExchangeError::PreSendGuard(never) => match never {},
            SensitiveExchangeError::Transport(error) => error,
        })
}

async fn exchange_request_with_guard<B, E, F>(
    target: &ValidatedTransportTarget,
    hyper_request: Request<B>,
    deadline: Instant,
    pre_send_guard: F,
) -> Result<Http1Response, SensitiveExchangeError<E>>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
    E: Send,
    F: FnOnce() -> Result<(), E> + Send,
{
    let transport = establish_connection(target, deadline)
        .await
        .map_err(map_connect_error)?;
    let io = TokioIo::new(HeaderLimitIo::new(transport));

    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_headers(MAX_HEADERS_PER_BLOCK);
    let (mut sender, connection) = timeout_at(deadline, builder.handshake(io))
        .await
        .map_err(|_| timeout_error(SendDisposition::DefinitelyNotSent))?
        .map_err(|_| {
            Http1TransportError::new(
                Http1ErrorKind::HttpHandshakeFailed,
                SendDisposition::DefinitelyNotSent,
            )
        })?;
    tokio::pin!(connection);

    // The guard is the final authority check. It runs before the send
    // disposition changes to PossiblySent and before Hyper receives the
    // request body.
    pre_send_guard().map_err(SensitiveExchangeError::PreSendGuard)?;

    // This is the sole send boundary: no code below retries or reconnects.
    let disposition = SendDisposition::PossiblySent;
    let response = {
        let send = sender.send_request(hyper_request);
        tokio::pin!(send);
        tokio::select! {
            biased;
            result = timeout_at(deadline, &mut send) => {
                result
                    .map_err(|_| timeout_error(disposition))?
                    .map_err(|error| map_post_send_hyper_error(&error, Http1ErrorKind::HttpSendFailed))?
            }
            driver = &mut connection => {
                match driver {
                    Ok(()) => timeout_at(deadline, &mut send)
                        .await
                        .map_err(|_| timeout_error(disposition))?
                        .map_err(|error| map_post_send_hyper_error(&error, Http1ErrorKind::HttpSendFailed))?,
                    Err(error) => {
                        return Err(SensitiveExchangeError::Transport(
                            map_post_send_hyper_error(
                                &error,
                                Http1ErrorKind::ConnectionDriverFailed,
                            ),
                        ))
                    }
                }
            }
        }
    };

    if !content_encoding_is_identity(response.headers()) {
        return Err(SensitiveExchangeError::Transport(Http1TransportError::new(
            Http1ErrorKind::ContentEncodingRejected,
            disposition,
        )));
    }
    if content_length_exceeds_limit(response.headers()) {
        return Err(SensitiveExchangeError::Transport(Http1TransportError::new(
            Http1ErrorKind::ResponseBodyTooLarge,
            disposition,
        )));
    }

    let (parts, mut body) = response.into_parts();
    let mut collected = Vec::new();
    loop {
        let frame = body.frame();
        tokio::pin!(frame);
        tokio::select! {
            biased;
            result = timeout_at(deadline, &mut frame) => {
                match result.map_err(|_| timeout_error(disposition))? {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(data) => append_body_frame(&mut collected, data, disposition)?,
                        Err(_) => {
                            return Err(SensitiveExchangeError::Transport(
                                Http1TransportError::new(
                                    Http1ErrorKind::ResponseBodyFailed,
                                    disposition,
                                ),
                            ))
                        }
                    },
                    Some(Err(_)) => {
                        return Err(SensitiveExchangeError::Transport(
                            Http1TransportError::new(
                                Http1ErrorKind::ResponseBodyFailed,
                                disposition,
                            ),
                        ))
                    }
                    None => break,
                }
            }
            driver = &mut connection => {
                match driver {
                    Ok(()) if body.is_end_stream() => break,
                    Ok(()) => {
                        return Err(SensitiveExchangeError::Transport(
                            Http1TransportError::new(
                                Http1ErrorKind::ConnectionDriverFailed,
                                disposition,
                            ),
                        ))
                    }
                    Err(error) => {
                        return Err(SensitiveExchangeError::Transport(
                            map_post_send_hyper_error(
                                &error,
                                Http1ErrorKind::ConnectionDriverFailed,
                            ),
                        ))
                    }
                }
            }
        }
    }

    Ok(Http1Response {
        status: parts.status,
        headers: HeaderMap::new(),
        body: Bytes::from(collected),
    })
}

fn validate_origin_form(origin_form: &str) -> Result<(), Http1TransportError> {
    if !origin_form.starts_with('/') || origin_form.contains('#') || origin_form.contains("//") {
        return Err(Http1TransportError::new(
            Http1ErrorKind::InvalidRequestTarget,
            SendDisposition::DefinitelyNotSent,
        ));
    }
    let uri = Uri::from_str(origin_form).map_err(|_| {
        Http1TransportError::new(
            Http1ErrorKind::InvalidRequestTarget,
            SendDisposition::DefinitelyNotSent,
        )
    })?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path_and_query().is_none() {
        return Err(Http1TransportError::new(
            Http1ErrorKind::InvalidRequestTarget,
            SendDisposition::DefinitelyNotSent,
        ));
    }
    Ok(())
}

fn validate_request_headers(headers: &HeaderMap) -> Result<(), Http1TransportError> {
    let rejected = [
        HOST,
        CONNECTION,
        PROXY_CONNECTION,
        PROXY_AUTHORIZATION,
        UPGRADE,
        TRANSFER_ENCODING,
        TE,
        TRAILER,
        EXPECT,
        ACCEPT_ENCODING,
        CONTENT_LENGTH,
    ];
    if rejected.iter().any(|name| headers.contains_key(name)) {
        return Err(Http1TransportError::new(
            Http1ErrorKind::RequestHeaderRejected,
            SendDisposition::DefinitelyNotSent,
        ));
    }
    Ok(())
}

fn build_hyper_request<B>(
    target: &ValidatedTransportTarget,
    method: Method,
    origin_form: String,
    mut headers: HeaderMap,
    body_len: usize,
    body: B,
) -> Result<Request<B>, Http1TransportError> {
    let host = format!("{}:{}", target.host_ascii(), target.port());
    let host_value = HeaderValue::from_str(&host).map_err(|_| {
        Http1TransportError::new(
            Http1ErrorKind::RequestHeaderRejected,
            SendDisposition::DefinitelyNotSent,
        )
    })?;
    let length_value = HeaderValue::from_str(&body_len.to_string()).map_err(|_| {
        Http1TransportError::new(
            Http1ErrorKind::RequestHeaderRejected,
            SendDisposition::DefinitelyNotSent,
        )
    })?;
    headers.insert(HOST, host_value);
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    headers.insert(CONTENT_LENGTH, length_value);
    Request::builder()
        .method(method)
        .uri(origin_form)
        .body(body)
        .map_err(|_| {
            Http1TransportError::new(
                Http1ErrorKind::InvalidRequestTarget,
                SendDisposition::DefinitelyNotSent,
            )
        })
        .map(|mut request| {
            *request.headers_mut() = headers;
            request
        })
}

fn append_body_frame(
    collected: &mut Vec<u8>,
    data: Bytes,
    disposition: SendDisposition,
) -> Result<(), Http1TransportError> {
    if data.len() > MAX_RESPONSE_BODY_BYTES.saturating_sub(collected.len() as u64) as usize {
        return Err(Http1TransportError::new(
            Http1ErrorKind::ResponseBodyTooLarge,
            disposition,
        ));
    }
    collected.extend_from_slice(&data);
    Ok(())
}

fn content_length_exceeds_limit(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_LENGTH).iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES)
    })
}

fn content_encoding_is_identity(headers: &HeaderMap) -> bool {
    let values: Vec<_> = headers.get_all(CONTENT_ENCODING).iter().collect();
    values.is_empty()
        || (values.len() == 1
            && values[0]
                .to_str()
                .is_ok_and(|value| value.eq_ignore_ascii_case("identity")))
}

fn map_connect_error(error: TransportConnectError) -> Http1TransportError {
    let kind = if error == TransportConnectError::ConnectPhaseTimeout {
        Http1ErrorKind::TransportTimeout
    } else {
        Http1ErrorKind::HttpHandshakeFailed
    };
    Http1TransportError::new(kind, SendDisposition::DefinitelyNotSent)
}

fn timeout_error(disposition: SendDisposition) -> Http1TransportError {
    Http1TransportError::new(Http1ErrorKind::TransportTimeout, disposition)
}

fn map_driver_result(result: Result<(), hyper::Error>) -> Http1TransportError {
    match result {
        Ok(()) => Http1TransportError::new(
            Http1ErrorKind::ConnectionDriverFailed,
            SendDisposition::PossiblySent,
        ),
        Err(error) => map_post_send_hyper_error(&error, Http1ErrorKind::ConnectionDriverFailed),
    }
}

fn map_post_send_hyper_error(
    error: &hyper::Error,
    fallback: Http1ErrorKind,
) -> Http1TransportError {
    let kind = find_header_limit_error(error)
        .map(map_header_limit_error)
        .unwrap_or(fallback);
    Http1TransportError::new(kind, SendDisposition::PossiblySent)
}

fn find_header_limit_error(error: &(dyn Error + 'static)) -> Option<HeaderLimitError> {
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(header_error) = item.downcast_ref::<HeaderLimitError>() {
            return Some(*header_error);
        }
        current = item.source();
    }
    None
}

const fn map_header_limit_error(error: HeaderLimitError) -> Http1ErrorKind {
    match error {
        HeaderLimitError::HeaderTooLarge => Http1ErrorKind::ResponseHeaderTooLarge,
        HeaderLimitError::HeaderCountExceeded => Http1ErrorKind::ResponseHeaderCountExceeded,
        HeaderLimitError::HeaderMalformed => Http1ErrorKind::ResponseHeaderMalformed,
        HeaderLimitError::ProtocolUpgradeRejected => Http1ErrorKind::ProtocolUpgradeRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::url_policy::validate_and_normalize_url;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn prepared(body: Vec<u8>) -> PreparedHttpRequest {
        PreparedHttpRequest::new(
            Method::POST,
            "/v1/test?fixed=1".to_string(),
            HeaderMap::new(),
            body,
        )
        .unwrap()
    }

    fn prepared_sensitive(body: Vec<u8>) -> PreparedSensitiveHttpRequest {
        PreparedSensitiveHttpRequest::new(
            Method::POST,
            "/v1/test?fixed=1".to_string(),
            HeaderMap::new(),
            Zeroizing::new(body),
        )
        .unwrap()
    }

    async fn loopback_target(listener: &TcpListener) -> ValidatedTransportTarget {
        validate_and_normalize_url(&format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn one_http11_request_succeeds_and_connection_is_not_reused() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 2048];
            let count = stream.read(&mut request).await.unwrap();
            let request = &request[..count];
            assert!(request
                .windows(b"connection: close".len())
                .any(|part| part.eq_ignore_ascii_case(b"connection: close")));
            assert!(request
                .windows(b"accept-encoding: identity".len())
                .any(|part| part.eq_ignore_ascii_case(b"accept-encoding: identity")));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let response = exchange(&target, prepared(Vec::new())).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"ok");
        assert!(response.headers().is_empty());
        server.await.unwrap();
    }

    #[test]
    fn request_limits_and_redaction_hold_before_send() {
        let exact = PreparedHttpRequest::new(
            Method::POST,
            "/".to_string(),
            HeaderMap::new(),
            vec![0; MAX_REQUEST_BODY_BYTES as usize],
        );
        assert!(exact.is_ok());
        let error = PreparedHttpRequest::new(
            Method::POST,
            "/".to_string(),
            HeaderMap::new(),
            vec![0; MAX_REQUEST_BODY_BYTES as usize + 1],
        )
        .unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::RequestTooLarge);
        assert_eq!(error.disposition(), SendDisposition::DefinitelyNotSent);
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("secret.example"));
        let rejected = PreparedHttpRequest::new(Method::GET, "/".to_string(), headers, Vec::new())
            .unwrap_err();
        let rendered = format!("{rejected:?} {rejected}");
        assert!(!rendered.contains("secret.example"));
        assert!(!rendered.contains("/private"));
    }

    #[test]
    fn sensitive_request_has_separate_limit_and_redacted_debug() {
        let exact_regular = PreparedSensitiveHttpRequest::new(
            Method::POST,
            "/".to_string(),
            HeaderMap::new(),
            Zeroizing::new(vec![0; MAX_REQUEST_BODY_BYTES as usize]),
        );
        assert!(exact_regular.is_ok());

        let above_regular = PreparedSensitiveHttpRequest::new(
            Method::POST,
            "/".to_string(),
            HeaderMap::new(),
            Zeroizing::new(vec![b'x'; MAX_REQUEST_BODY_BYTES as usize + 1]),
        );
        assert!(above_regular.is_ok());

        let error = PreparedSensitiveHttpRequest::new(
            Method::POST,
            "/private-sensitive-path".to_string(),
            HeaderMap::new(),
            Zeroizing::new(vec![b'x'; MAX_SENSITIVE_REQUEST_BODY_BYTES as usize + 1]),
        )
        .unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::RequestTooLarge);
        assert_eq!(error.disposition(), SendDisposition::DefinitelyNotSent);
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("sensitive.example"));
        let rejected = PreparedSensitiveHttpRequest::new(
            Method::POST,
            "/private-sensitive-path".to_string(),
            headers,
            Zeroizing::new(b"sensitive-body-canary".to_vec()),
        )
        .unwrap_err();
        let rendered = format!("{rejected:?} {rejected}");
        assert!(!rendered.contains("sensitive.example"));
        assert!(!rendered.contains("private-sensitive-path"));
        assert!(!rendered.contains("sensitive-body-canary"));
    }

    #[tokio::test]
    async fn sensitive_exchange_accepts_body_above_regular_limit_without_retry() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let body_len = MAX_REQUEST_BODY_BYTES as usize + 1;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::with_capacity(body_len + 4096);
            let mut chunk = [0_u8; 8192];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4);
                if header_end.is_some_and(|index| request.len() >= index + body_len) {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap();
            assert_eq!(request.len() - header_end, body_len);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        });

        let response = exchange_sensitive(&target, prepared_sensitive(vec![b'x'; body_len]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sensitive_send_disconnect_preserves_possibly_sent_without_retry() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            drop(stream);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        });
        let error = exchange_sensitive(&target, prepared_sensitive(Vec::new()))
            .await
            .unwrap_err();
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sensitive_final_guard_blocks_request_bytes_before_send() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            request
        });

        let result = exchange_sensitive_with_guard(
            &target,
            prepared_sensitive(b"guarded-sensitive-body".to_vec()),
            || Err::<(), _>("authority changed"),
        )
        .await;
        match result {
            Err(SensitiveExchangeError::PreSendGuard(error)) => {
                assert_eq!(error, "authority changed")
            }
            Err(SensitiveExchangeError::Transport(error)) => {
                panic!("guard must fail before transport send: {error:?}")
            }
            Ok(_) => panic!("guard failure must prevent the request"),
        }
        assert!(server.await.unwrap().is_empty());
    }

    #[test]
    fn body_frame_limit_accepts_exact_boundary_and_rejects_next_byte() {
        let mut exact = Vec::new();
        append_body_frame(
            &mut exact,
            Bytes::from(vec![b'x'; MAX_RESPONSE_BODY_BYTES as usize]),
            SendDisposition::PossiblySent,
        )
        .unwrap();
        assert_eq!(exact.len(), MAX_RESPONSE_BODY_BYTES as usize);
        let error = append_body_frame(
            &mut exact,
            Bytes::from_static(b"x"),
            SendDisposition::PossiblySent,
        )
        .unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::ResponseBodyTooLarge);
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);

        let mut identity = HeaderMap::new();
        identity.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        assert!(content_encoding_is_identity(&identity));
    }

    #[tokio::test]
    async fn response_body_limits_and_content_encoding_are_enforced() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").await.unwrap();
        });
        let error = exchange(&target, prepared(Vec::new())).await.unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::ContentEncodingRejected);
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let body = vec![b'x'; MAX_RESPONSE_BODY_BYTES as usize + 1];
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        });
        let error = exchange(&target, prepared(Vec::new())).await.unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::ResponseBodyTooLarge);
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn send_disconnect_and_total_deadline_are_possibly_sent() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let error = exchange(&target, prepared(Vec::new())).await.unwrap_err();
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        });
        let error = exchange_with_deadline(
            &target,
            prepared(Vec::new()),
            Instant::now() + std::time::Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::TransportTimeout);
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirects_are_returned_without_a_second_connection() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = loopback_target(&listener).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let response = exchange(&target, prepared(Vec::new())).await.unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        server.await.unwrap();
    }
}
