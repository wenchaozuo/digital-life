use std::fmt;

/// A bounded successful provider response. It intentionally exposes neither
/// the request, endpoint, credential, peer, nor underlying HTTP response.
pub(crate) struct ProviderHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl ProviderHttpResponse {
    pub(super) fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub(crate) const fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for ProviderHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}
