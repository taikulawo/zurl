//! 支持国密SM2，NTLS的TLS stream
use openssl::ex_data::Index;
use openssl::ssl::SslContextBuilder;
use openssl::{
    async_stream::SslStream as AsyncSslStream,
    ssl::{AlpnError, Ssl, SslContext, SslMethod, SslRef},
};

use std::io;
use std::net::SocketAddr;
use std::task::{ready, Context, Poll};
use std::{pin::Pin, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::subcommands::client::BoxStream;
use crate::subcommands::{ClientArgs, ServerArgs};
use crate::{certificates};

pub enum TlsAlpn {
    H1,
    H2,
    Unknown,
}

#[derive(Default)]
pub struct Certificates {
    pub tls_cert_file_path: Option<String>,
    pub tls_key_file_path: Option<String>,
    pub sm2_cert_file_path: Option<String>,
    pub sm2_key_file_path: Option<String>,

    // ntls
    pub ntls_enc_cert_file_path: Option<String>,
    pub ntls_enc_key_file_path: Option<String>,
    pub ntls_sign_cert_file_path: Option<String>,
    pub ntls_sign_key_file_path: Option<String>,

    pub tls_cert_content: Option<Vec<String>>,

    pub tls_key_content: Option<String>,

    pub sm2_cert_content: Option<Vec<String>>,

    pub sm2_key_content: Option<String>,

    // ntls
    pub ntls_enc_cert_content: Option<String>,

    pub ntls_enc_key_content: Option<String>,

    pub ntls_sign_cert_content: Option<String>,

    pub ntls_sign_key_content: Option<String>,
}

pub struct TlsBuilder {
    ctx: SslContextBuilder,
    alpn_index: Option<Index<Ssl, AlpnCallbackArgument>>,
}

struct AlpnCallbackArgument(TlsAlpn);

pub struct SslFactory {
    ctx: Arc<SslContext>,
    alpn_index: Option<Index<Ssl, AlpnCallbackArgument>>,
}
impl TlsBuilder {
    pub fn new() -> Self {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();

        Self {
            ctx,
            alpn_index: None,
        }
    }
    pub fn with_alpn_callback(&mut self) {
        let alpn_index = Ssl::new_ex_index::<AlpnCallbackArgument>().unwrap();
        self.alpn_index = Some(alpn_index);
        let alpn_index = self.alpn_index.clone().unwrap();
        self.ctx
            .set_alpn_select_callback(move |ssl: &mut SslRef, buf: &[u8]| {
                let data = ssl.ex_data(alpn_index);
                if let Some(_data) = data {
                    return Ok(buf);
                }
                Err(AlpnError::ALERT_FATAL)
            });
    }
    pub fn build(self) -> SslFactory {
        let ctx = self.ctx.build();
        SslFactory {
            ctx: Arc::new(ctx),
            alpn_index: self.alpn_index.clone(),
        }
    }
    pub fn get_inner_ctx(&mut self) -> &mut SslContextBuilder {
        &mut self.ctx
    }
}

impl SslFactory {
    pub fn ssl<'a, T>(&'a self, inner: T, certificates: Certificates) -> TlsStreamBuilder<T> {
        TlsStreamBuilder {
            certificates,
            inner,
            ssl: Ssl::new(&self.ctx).unwrap(),
            alpn_index: self.alpn_index.as_ref().cloned(),
            state: State::Handshake,
        }
    }
}
pub struct TlsStreamBuilder<T> {
    certificates: Certificates,
    inner: T,
    ssl: Ssl,
    alpn_index: Option<Index<Ssl, AlpnCallbackArgument>>,
    state: State,
}
impl<T> TlsStreamBuilder<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn spawn(self) -> anyhow::Result<TlsStream<T>> {
        let stream = AsyncSslStream::new(self.ssl, self.inner).unwrap();
        let s = TlsStream {
            inner: stream,
            state: self.state,
        };
        Ok(s)
    }
    pub fn set_server_name(&mut self, hostname: &str) {
        self.ssl.set_hostname(hostname).expect("set hostname success");
    }
    pub fn set_connect_state(&mut self) {
        self.state = State::Connecting;
        self.ssl.set_connect_state();
    }
    pub fn set_alpn(mut self, alpn: TlsAlpn) -> Self {
        if let Some(alpn_index) = self.alpn_index {
            let data = AlpnCallbackArgument(alpn);
            self.ssl.set_ex_data(alpn_index, data);
        }
        self
    }
    pub fn set_accept_state(&mut self) {
        certificates::set_certificate(&self.certificates, &mut self.ssl)
            .expect("set certificates success");
        self.state = State::Handshake;
        self.ssl.set_accept_state();
    }
}

enum State {
    Handshake,
    Connecting,
    Running,
}

pub struct TlsStream<T> {
    inner: AsyncSslStream<T>,
    state: State,
}

impl<T> AsyncRead for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                State::Handshake => {
                    ready!(Pin::new(&mut self.inner).poll_do_handshake(cx)).map_err(|err| {
                        io::Error::new(io::ErrorKind::Other, format!("handshake error {}", err))
                    })?;
                    self.state = State::Running;
                }
                State::Connecting => {
                    ready!(Pin::new(&mut self.inner).poll_connect(cx)).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            format!("connect error {}", err),
                        )
                    })?;
                    self.state = State::Running;
                }
                State::Running => return Pin::new(&mut self.inner).poll_read(cx, buf),
            }
        }
    }
}
impl<T> AsyncWrite for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
pub async fn open_connected_ssl_stream<'a>(
    ssl_factory: Arc<SslFactory>,
    addr: SocketAddr,
    certificates: Certificates,
) -> anyhow::Result<BoxStream> {
    let remote = tokio::net::TcpStream::connect(addr).await?;
    let mut ssl_stream_builder = ssl_factory.ssl(remote, certificates);
    ssl_stream_builder.set_connect_state();
    let stream = ssl_stream_builder.spawn()?;
    Ok(Box::new(stream))
}
impl Into<Certificates> for ServerArgs {
    fn into(self) -> Certificates {
        Certificates {
            ntls_enc_cert_content: self.ntls_enc_cert_content,
            ntls_enc_cert_file_path: self.ntls_enc_cert_file_path,
            ntls_enc_key_content: self.ntls_enc_key_content,
            ntls_enc_key_file_path: self.ntls_enc_key_file_path,
            ntls_sign_cert_content: self.ntls_sign_cert_content,
            ntls_sign_cert_file_path: self.ntls_sign_cert_file_path,
            ntls_sign_key_content: self.ntls_sign_key_content,
            ntls_sign_key_file_path: self.ntls_sign_key_file_path,
            sm2_cert_content: self.sm2_cert_content,
            sm2_key_content: self.sm2_key_content,
            tls_cert_content: self.tls_cert_content,
            tls_key_file_path: self.tls_key_file_path,
            tls_cert_file_path: self.tls_cert_file_path,
            tls_key_content: self.tls_key_content,
            sm2_cert_file_path: self.sm2_cert_file_path,
            sm2_key_file_path: self.sm2_key_file_path,
        }
    }
}
impl Into<Certificates> for ClientArgs {
    fn into(self) -> Certificates {
        Certificates {
            ntls_enc_cert_content: self.ntls_enc_cert_content,
            ntls_enc_cert_file_path: self.ntls_enc_cert_file_path,
            ntls_enc_key_content: self.ntls_enc_key_content,
            ntls_enc_key_file_path: self.ntls_enc_key_file_path,
            ntls_sign_cert_content: self.ntls_sign_cert_content,
            ntls_sign_cert_file_path: self.ntls_sign_cert_file_path,
            ntls_sign_key_content: self.ntls_sign_key_content,
            ntls_sign_key_file_path: self.ntls_sign_key_file_path,
            ..Default::default()
        }
    }
}
