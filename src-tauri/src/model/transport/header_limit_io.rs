#![allow(dead_code)]

use super::{HEADER_STAGING_BYTES, MAX_HEADERS_PER_BLOCK, MAX_RESPONSE_HEADER_BYTES};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Fixed header-admission outcomes.  They intentionally carry no peer or wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderLimitError {
    HeaderTooLarge,
    HeaderCountExceeded,
    HeaderMalformed,
    ProtocolUpgradeRejected,
}

impl fmt::Display for HeaderLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HeaderTooLarge => "Response headers exceed the transport limit",
            Self::HeaderCountExceeded => "Response header count exceeds the transport limit",
            Self::HeaderMalformed => "Response header framing is malformed",
            Self::ProtocolUpgradeRejected => "Protocol upgrades are not supported",
        };
        f.write_str(message)
    }
}

impl std::error::Error for HeaderLimitError {}

/// An incremental, byte-transparent admission guard placed before Hyper's parser.
///
/// The fixed staging buffer is only for an individual underlying read. Header state
/// consists of counters and a short status-line prefix, never a collected header block.
pub(crate) struct HeaderLimitIo<T> {
    inner: T,
    scanner: HeaderScanner,
    staging: [u8; HEADER_STAGING_BYTES],
    pending_start: usize,
    pending_end: usize,
    terminal_error: Option<HeaderLimitError>,
}

impl<T> HeaderLimitIo<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            scanner: HeaderScanner::new(),
            staging: [0; HEADER_STAGING_BYTES],
            pending_start: 0,
            pending_end: 0,
            terminal_error: None,
        }
    }

    #[cfg(test)]
    fn staging_capacity(&self) -> usize {
        self.staging.len()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for HeaderLimitIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if let Some(error) = this.terminal_error {
            return Poll::Ready(Err(header_io_error(error)));
        }
        if this.pending_start < this.pending_end {
            drain_staging(this, buf);
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        this.pending_start = 0;
        this.pending_end = 0;
        let mut staging = ReadBuf::new(&mut this.staging);
        match Pin::new(&mut this.inner).poll_read(cx, &mut staging) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let read = staging.filled().len();
                if read == 0 {
                    if this.scanner.is_scanning_headers() {
                        this.terminal_error = Some(HeaderLimitError::HeaderMalformed);
                        return Poll::Ready(Err(header_io_error(
                            HeaderLimitError::HeaderMalformed,
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }

                if let Err(error) = this.scanner.inspect(&this.staging[..read]) {
                    this.terminal_error = Some(error);
                    return Poll::Ready(Err(header_io_error(error)));
                }

                this.pending_end = read;
                drain_staging(this, buf);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for HeaderLimitIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

fn drain_staging<T>(io: &mut HeaderLimitIo<T>, out: &mut ReadBuf<'_>) {
    let available = io.pending_end - io.pending_start;
    let take = available.min(out.remaining());
    let end = io.pending_start + take;
    out.put_slice(&io.staging[io.pending_start..end]);
    io.pending_start = end;
}

fn header_io_error(error: HeaderLimitError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

struct HeaderScanner {
    scanning_headers: bool,
    expecting_status: bool,
    informational_block: bool,
    total_header_bytes: usize,
    fields_in_block: usize,
    line_bytes: usize,
    line_has_content: bool,
    status_prefix: [u8; 16],
    status_prefix_len: usize,
}

impl HeaderScanner {
    fn new() -> Self {
        Self {
            scanning_headers: true,
            expecting_status: true,
            informational_block: false,
            total_header_bytes: 0,
            fields_in_block: 0,
            line_bytes: 0,
            line_has_content: false,
            status_prefix: [0; 16],
            status_prefix_len: 0,
        }
    }

    fn is_scanning_headers(&self) -> bool {
        self.scanning_headers
    }

    fn inspect(&mut self, bytes: &[u8]) -> Result<(), HeaderLimitError> {
        for &byte in bytes {
            if !self.scanning_headers {
                break;
            }

            self.total_header_bytes = self.total_header_bytes.saturating_add(1);
            if self.total_header_bytes > MAX_RESPONSE_HEADER_BYTES {
                return Err(HeaderLimitError::HeaderTooLarge);
            }

            self.line_bytes = self.line_bytes.saturating_add(1);

            match byte {
                b'\n' => self.finish_line()?,
                b'\r' => {}
                value => {
                    self.line_has_content = true;
                    if self.expecting_status && self.status_prefix_len < self.status_prefix.len() {
                        self.status_prefix[self.status_prefix_len] = value;
                        self.status_prefix_len += 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn finish_line(&mut self) -> Result<(), HeaderLimitError> {
        if self.expecting_status {
            if !self.line_has_content {
                return Err(HeaderLimitError::HeaderMalformed);
            }
            let status = status_code(&self.status_prefix[..self.status_prefix_len]);
            if status == Some(101) {
                return Err(HeaderLimitError::ProtocolUpgradeRejected);
            }
            self.informational_block = status.is_some_and(|code| (100..200).contains(&code));
            self.expecting_status = false;
            self.fields_in_block = 0;
        } else if !self.line_has_content {
            if self.informational_block {
                self.expecting_status = true;
                self.informational_block = false;
            } else {
                self.scanning_headers = false;
            }
        } else {
            self.fields_in_block = self.fields_in_block.saturating_add(1);
            if self.fields_in_block > MAX_HEADERS_PER_BLOCK {
                return Err(HeaderLimitError::HeaderCountExceeded);
            }
        }

        self.line_bytes = 0;
        self.line_has_content = false;
        self.status_prefix_len = 0;
        Ok(())
    }
}

fn status_code(prefix: &[u8]) -> Option<u16> {
    if prefix.len() < 12 || !prefix.starts_with(b"HTTP/") || prefix[8] != b' ' {
        return None;
    }
    let digits = &prefix[9..12];
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0'),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read_all_with_chunks(input: &[u8], chunk_size: usize) -> io::Result<Vec<u8>> {
        let (mut writer, reader) = tokio::io::duplex(HEADER_STAGING_BYTES * 2);
        let input = input.to_vec();
        let writer_task = tokio::spawn(async move {
            for chunk in input.chunks(chunk_size) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        let mut guarded = HeaderLimitIo::new(reader);
        let mut output = Vec::new();
        let result = guarded.read_to_end(&mut output).await;
        if result.is_err() {
            writer_task.abort();
            let _ = writer_task.await;
            return result.map(|_| output);
        }
        writer_task.await.unwrap();
        result.map(|_| output)
    }

    fn response_with_fields(field_count: usize) -> Vec<u8> {
        let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..field_count {
            response.extend_from_slice(b"X: a\r\n");
        }
        response.extend_from_slice(b"\r\nbody");
        response
    }

    #[tokio::test]
    async fn passes_final_headers_and_body_transparently() {
        let response = b"HTTP/1.1 200 OK\r\nX-Test: one\r\n\r\nbody";
        assert_eq!(read_all_with_chunks(response, 3).await.unwrap(), response);
    }

    #[tokio::test]
    async fn handles_terminator_and_lines_across_single_byte_reads() {
        let response = b"HTTP/1.1 200 OK\r\nX-Test: one\r\n\r\nbody";
        assert_eq!(read_all_with_chunks(response, 1).await.unwrap(), response);
    }

    #[tokio::test]
    async fn accepts_exact_header_byte_limit_and_rejects_next_byte() {
        let start = b"HTTP/1.1 200 OK\r\n";
        let final_crlf = b"\r\n";
        let fill = MAX_RESPONSE_HEADER_BYTES - start.len() - final_crlf.len() - 5;
        let mut exact = start.to_vec();
        exact.extend_from_slice(b"X: ");
        exact.extend(std::iter::repeat_n(b'a', fill));
        exact.extend_from_slice(b"\r\n\r\n");
        assert_eq!(exact.len(), MAX_RESPONSE_HEADER_BYTES);
        assert_eq!(read_all_with_chunks(&exact, 37).await.unwrap(), exact);

        let mut too_large = exact.clone();
        too_large.insert(too_large.len() - 2, b'a');
        let error = read_all_with_chunks(&too_large, 37).await.unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::HeaderTooLarge));
    }

    #[tokio::test]
    async fn counts_128_fields_and_rejects_129th() {
        assert!(read_all_with_chunks(&response_with_fields(128), 5)
            .await
            .is_ok());
        let error = read_all_with_chunks(&response_with_fields(129), 5)
            .await
            .unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::HeaderCountExceeded));
    }

    #[tokio::test]
    async fn accumulates_informational_blocks_and_rejects_101() {
        let response = b"HTTP/1.1 100 Continue\r\nX: a\r\n\r\nHTTP/1.1 200 OK\r\nY: b\r\n\r\nbody";
        assert_eq!(read_all_with_chunks(response, 2).await.unwrap(), response);

        let error = read_all_with_chunks(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", 1)
            .await
            .unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::ProtocolUpgradeRejected));
    }

    #[tokio::test]
    async fn multiple_informational_blocks_share_the_same_byte_budget() {
        let mut response = Vec::new();
        for _ in 0..2 {
            response.extend_from_slice(b"HTTP/1.1 100 Continue\r\nX: ");
            response.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEADER_BYTES / 2));
            response.extend_from_slice(b"\r\n\r\n");
        }
        let error = read_all_with_chunks(&response, 97).await.unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::HeaderTooLarge));
    }

    #[tokio::test]
    async fn rejects_long_lines_and_eof_before_header_termination() {
        let mut long = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEADER_BYTES));
        let error = read_all_with_chunks(&long, 31).await.unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::HeaderTooLarge));

        let error = read_all_with_chunks(b"HTTP/1.1 200 OK\r\nX: a\r\n", 2)
            .await
            .unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HeaderLimitError>())
            .is_some_and(|kind| *kind == HeaderLimitError::HeaderMalformed));
    }

    #[test]
    fn error_text_is_fixed_and_staging_is_bounded() {
        let io = HeaderLimitIo::new(tokio::io::empty());
        assert_eq!(io.staging_capacity(), HEADER_STAGING_BYTES);
        let rendered = format!(
            "{:?} {}",
            HeaderLimitError::HeaderTooLarge,
            HeaderLimitError::HeaderTooLarge
        );
        for canary in ["example.com", "secret", "Authorization", "/private"] {
            assert!(!rendered.contains(canary));
        }
    }
}
