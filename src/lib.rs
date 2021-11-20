use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bytes::{Bytes, BytesMut};
use futures::prelude::*;
use futures::ready;
use pin_project_lite::pin_project;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_rw_stream_sink::RwStreamSink;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

pub type SnowFlakes<S> = Framed<RwStreamSink<SnowFramed<S>>, LengthDelimitedCodec>;

pin_project! {
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
            .length_field_length(2)
            .max_frame_length(65535)
            .new_framed(stream);
        Self { frame, handshake }
    }

    pub fn into_snow_framed(self) -> Result<SnowFramed<S>, snow::Error> {
        let Self { frame, handshake } = self;
        Ok(SnowFramed {
            frame,
            transport: handshake.into_transport_mode()?,
        })
    }
}

impl<S> Sink<Bytes> for WinterFramed<S>
where
    S: AsyncWrite,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_ready(cx)
    }

    /// item.length <= 65535 - 48
    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.project();
        let crypto_len = item.len() + 48;
        let mut crypto_item = BytesMut::with_capacity(crypto_len);
        crypto_item.resize(crypto_len, 0);
        let ret = this
            .handshake
            .write_message(item.as_ref(), crypto_item.as_mut());
        match ret {
            Ok(x) => debug_assert_eq!(x, crypto_len),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("snow write msg error: {}", e),
                ))
            }
        }
        this.frame.start_send(crypto_item.freeze())
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
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let msg = this.frame.poll_next(cx);
        let msg = ready!(msg);
        Poll::Ready(match msg {
            Some(Ok(crypto_item)) => {
                assert!(crypto_item.len() >= 48);
                let len = crypto_item.len() - 48;
                let mut item = BytesMut::with_capacity(len);
                item.resize(len, 0);
                let ret = this
                    .handshake
                    .read_message(crypto_item.as_ref(), item.as_mut());
                Some(match ret {
                    Ok(x) => {
                        debug_assert_eq!(x, len);
                        Ok(item)
                    }
                    Err(e) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("snow read msg error: {}", e),
                    )),
                })
            }
            x => x,
        })
    }
}

pin_project! {
    pub struct SnowFramed<S> {
        #[pin]
        frame: Framed<S, LengthDelimitedCodec>,
        transport: snow::TransportState,
    }
}

impl<S: AsyncRead + AsyncWrite> SnowFramed<S> {
    /// Length should not exceed u32 since header is fixed to 4 bytes.
    pub fn into_snow_flakes(
        self,
        length: usize,
    ) -> Framed<RwStreamSink<SnowFramed<S>>, LengthDelimitedCodec> {
        LengthDelimitedCodec::builder()
            .little_endian()
            .length_field_length(4)
            .max_frame_length(length)
            .new_framed(RwStreamSink::new(self))
    }
}

impl<S> Sink<Bytes> for SnowFramed<S>
where
    S: AsyncWrite,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_ready(cx)
    }

    /// item will be split and send in chunks not greater than 65535 - 16.
    fn start_send(self: Pin<&mut Self>, mut item: Bytes) -> Result<(), Self::Error> {
        let mut this = self.project();
        loop {
            let chunk_len = item.len().min(65535 - 16);
            let chunk = item.split_to(chunk_len);

            let crypto_len = chunk_len + 16;
            let mut crypto_item = BytesMut::with_capacity(crypto_len);
            crypto_item.resize(crypto_len, 0);
            let ret = this
                .transport
                .write_message(chunk.as_ref(), crypto_item.as_mut());

            match ret {
                Ok(x) => debug_assert_eq!(x, crypto_len),
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("snow write msg error: {}", e),
                    ))
                }
            }
            Pin::new(&mut this.frame).start_send(crypto_item.freeze())?;

            if item.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_close(cx)
    }
}

impl<S> Stream for SnowFramed<S>
where
    S: AsyncRead,
{
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let msg = this.frame.poll_next(cx);
        let msg = ready!(msg);
        Poll::Ready(match msg {
            Some(Ok(crypto_item)) => {
                assert!(crypto_item.len() >= 16);
                let len = crypto_item.len() - 16;
                let mut item = BytesMut::with_capacity(len);
                item.resize(len, 0);
                let ret = this
                    .transport
                    .read_message(crypto_item.as_ref(), item.as_mut());
                Some(match ret {
                    Ok(x) => {
                        debug_assert_eq!(x, len);
                        Ok(item)
                    }
                    Err(e) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("snow read msg error: {}", e),
                    )),
                })
            }
            x => x,
        })
    }
}
