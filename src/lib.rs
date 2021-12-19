use std::{
    io::{self, Cursor, Read},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{prelude::*, ready};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Framed io with noise protocol support.
pub type SnowFlakes<S> = Framed<SnowFramed<S>, LengthDelimitedCodec>;

/// Maximum length of the noise protocol.
pub const NOISE_MSG_LEN: usize = 65535;
/// Length of length field of a message. Actually 2 could be used, but here we
/// use 3 due to the possibility of breaking:
/// <https://github.com/tokio-rs/tokio/issues/4184>
pub const LENGTH_FIELD_LEN: usize = 3;
/// Tag length of `ChaCha20-Poly1305` and `AES-256-GCM`
pub const TAG_LEN: usize = 16;
/// Length of the overhead of handshake message: [`TAG_LEN`] + `Length of cipher key(32 bytes)`
pub const HANDSHAKE_LEN: usize = 48;

pin_project! {
    /// A convenient framed stream writer with noise protocol support. After the
    /// handshake completes, it should be converted to [`SnowFramed`].
    ///
    /// `Stream` and `Sink` are implemented. But you should only use them
    /// directly due to the length limitation of sending chunk.
    pub struct WinterFramed<S> {
        #[pin]
        frame: Framed<S, LengthDelimitedCodec>,
        handshake: snow::HandshakeState,
    }
}

impl<S> WinterFramed<S>
where
    S: AsyncRead + AsyncWrite,
{
    pub fn new(stream: S, handshake: snow::HandshakeState) -> Self {
        let frame = LengthDelimitedCodec::builder()
            .little_endian()
            .length_field_length(LENGTH_FIELD_LEN)
            .max_frame_length(NOISE_MSG_LEN)
            .new_framed(stream);
        Self { frame, handshake }
    }

    /// Convert self into a [`SnowFramed`]. If handshake hasn't completed, [`snow::Error`] will be returned.
    pub fn into_snow_framed(self) -> Result<SnowFramed<S>, snow::Error> {
        let Self { frame, handshake } = self;
        Ok(SnowFramed {
            frame,
            transport: handshake.into_transport_mode()?,
            current_item: None,
        })
    }
}

/// ATTENTION: It's just a convenient api around [`WinterFramed`], which should
/// only be used directly due to the length limitation of a sending chunk.
impl<S> Sink<Bytes> for WinterFramed<S>
where
    S: AsyncWrite,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_ready(cx)
    }

    /// item.length should not exceed [`NOISE_MSG_LEN`] - [`HANDSHAKE_LEN`] - [`LENGTH_FIELD_LEN`].
    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.project();
        let crypto_len = item.len() + HANDSHAKE_LEN;
        let mut crypto_item = vec![0; crypto_len];
        let ret = this.handshake.write_message(&item, &mut crypto_item);
        match ret {
            Ok(x) => debug_assert_eq!(x, crypto_len),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("snow write msg error: {}", e),
                ))
            }
        }
        this.frame.start_send(crypto_item.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_close(cx)
    }
}

impl<S> Stream for WinterFramed<S>
where
    S: AsyncRead,
{
    type Item = Result<Vec<u8>, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let encrypted_msg = match ready!(this.frame.poll_next(cx)) {
            Some(Ok(x)) => x,
            Some(Err(e)) => return Poll::Ready(Some(Err(e))),
            None => return Poll::Ready(None),
        };
        if encrypted_msg.len() < HANDSHAKE_LEN {
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("message doesn't have AEAD: {:?}", encrypted_msg),
            ))));
        }
        let len = encrypted_msg.len() - HANDSHAKE_LEN;

        let mut item = vec![0; len];
        let ret = this.handshake.read_message(&encrypted_msg, &mut item);

        match ret {
            Ok(x) => debug_assert_eq!(x, len),
            Err(e) => {
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("snow read msg error: {}", e),
                ))))
            }
        }
        Poll::Ready(Some(Ok(item)))
    }
}

pin_project! {
    /// Convenient framed stream io with noise protocol support.
    /// `AsyncRead` and `AsyncWrite` are implemented.
    ///
    /// Should only be used in message transport phase.
    ///
    /// ATTENTION: Since each frame's length is limited to [`NOISE_MSG_LEN`] -
    /// [`TAG_LEN`] - [`LENGTH_FIELD_LEN`].  Use it with [`SnowFlakes`] or
    /// custom framed layer is suggested.
    pub struct SnowFramed<S> {
        #[pin]
        frame: Framed<S, LengthDelimitedCodec>,
        transport: snow::TransportState,
        current_item: Option<Cursor<Vec<u8>>>
    }
}

impl<S: AsyncRead + AsyncWrite> SnowFramed<S> {
    /// Add a framed layer above the [`SnowFramed`]. Now each frame could be
    /// enlarged to any size smaller than `length`. But the `length` should not
    /// exceed u32 since header is fixed to 4 bytes.
    pub fn into_snow_flakes(self, length: usize) -> SnowFlakes<S> {
        LengthDelimitedCodec::builder()
            .little_endian()
            .length_field_length(4)
            .max_frame_length(length)
            .new_framed(self)
    }
}

impl<S> AsyncRead for SnowFramed<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        // Grab the item to copy from.
        let (item_to_copy, len_to_read) = loop {
            if let Some(ref mut i) = this.current_item {
                let len = i.get_ref().len() as u64;
                let pos = i.position();
                if pos < len {
                    break (i, len - pos);
                }
            }

            // Decrypt message.
            let encrypted_msg = match ready!(this.frame.as_mut().poll_next(cx)) {
                Some(Ok(x)) => x,
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Ready(Ok(())), // EOF
            };
            if encrypted_msg.len() < TAG_LEN {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("message doesn't have AEAD: {:?}", encrypted_msg),
                )));
            }
            let len = encrypted_msg.len() - TAG_LEN;

            let mut item = vec![0; len];
            let ret = this.transport.read_message(&encrypted_msg, &mut item);

            match ret {
                Ok(x) => debug_assert_eq!(x, len),
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("snow read msg error: {}", e),
                    )))
                }
            }

            *this.current_item = Some(Cursor::new(item));
        };
        // Copy it!
        let len_to_read = buf
            .remaining()
            .min(len_to_read.min(usize::MAX as u64) as usize);
        let unfilled_buf = buf.initialize_unfilled_to(len_to_read);
        let len = item_to_copy.read(unfilled_buf)?;
        buf.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for SnowFramed<S>
where
    S: AsyncWrite,
{
    /// Length of written won't be greater than [`NOISE_MSG_LEN`] - [`TAG_LEN`] - [`LENGTH_FIELD_LEN`].
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        ready!(this.frame.as_mut().poll_ready(cx)?);

        let chunk_len = buf.len().min(NOISE_MSG_LEN - TAG_LEN - LENGTH_FIELD_LEN);
        let crypto_len = chunk_len + TAG_LEN;
        let mut crypto_item = vec![0; crypto_len];
        let ret = this
            .transport
            .write_message(&buf[..chunk_len], &mut crypto_item);

        match ret {
            Ok(x) => debug_assert_eq!(x, crypto_len),
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("snow write msg error: {}", e),
                )));
            }
        }

        Poll::Ready(
            this.frame
                .start_send(crypto_item.into())
                .map(|()| chunk_len),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().frame.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().frame.poll_close(cx)
    }
}
