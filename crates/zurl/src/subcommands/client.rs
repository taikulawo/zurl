use std::{any::Any, collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use hyper::{body, Body, HeaderMap, Request};
use lazy_static::__Deref;
use openssl::ssl::SslMethod;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use url::{Host, Url};

use crate::{
    dns::DnsClient,
    stream::{SslFactory, TlsBuilder},
    subcommands::ClientArgs,
    DEFAULT_CIPHER,
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type BoxStream = Box<dyn ProxyStream>;
pub type Payload = Box<dyn Any + Send + 'static>;
pub type RealAdaptor = Box<dyn Adaptor>;
#[async_trait]
pub trait Adaptor {
    async fn request(&self, payload: ClientArgs) -> anyhow::Result<()>;
}

pub async fn create_adaptor(client: ClientArgs) -> anyhow::Result<()> {
    let url = client.url.clone();
    let parts = url.split("://").collect::<Vec<&str>>();
    let prefix = parts
        .get(0)
        .ok_or_else(|| anyhow!("no avaliable prefix {}", url))?;

    let mut builder = TlsBuilder::new(SslMethod::tls());
    if client.enable_ntls {
        builder.enable_ntls();
    }
    let ssl_ctx = builder.get_inner_ctx();
    match &*client.tls_version {
        "1.3" => {
            ssl_ctx
                .set_ciphersuites(if let Some(ref x) = client.cipher {
                    &*x
                } else {
                    DEFAULT_CIPHER
                })
                .unwrap();
        }
        "1.2" => {
            ssl_ctx
                .set_cipher_list(if let Some(ref x) = client.cipher {
                    &*x
                } else {
                    DEFAULT_CIPHER
                })
                .unwrap();
        }
        _ => {
            bail!("invalid version {}", client.tls_version)
        }
    }
    let factory = builder.build();

    let x: RealAdaptor = match *prefix {
        "http" | "https" => {
            let x = HttpAdaptor::new(client.clone(), factory)?;
            Box::new(x)
        }
        _ => {
            bail!("unknown protocol {}", url);
        }
    };
    x.request(client).await?;
    Ok(())
}

struct HttpAdaptor {
    dns_client: Arc<DnsClient>,
    factory: Arc<SslFactory>,
}
impl HttpAdaptor {
    pub fn new(cli: ClientArgs, ssl_factory: SslFactory) -> anyhow::Result<Self> {
        let dns_client = Arc::new(DnsClient::new_with_default_resolver()?);
        let s = Self {
            dns_client,
            factory: Arc::new(ssl_factory),
        };
        Ok(s)
    }
    async fn remote_addr(
        &self,
        dns_client: Arc<DnsClient>,
        real_url: &Url,
    ) -> anyhow::Result<SocketAddr> {
        let prefix = real_url.scheme();
        let is_https = prefix.contains("https");
        let host = real_url.host();
        let port = real_url
            .port()
            .unwrap_or_else(|| if is_https { 443 } else { 80 });
        let addr = match host {
            Some(x) => match x {
                Host::Ipv4(x) => SocketAddr::from((x, port)),
                Host::Ipv6(x) => SocketAddr::from((x, port)),
                Host::Domain(x) => {
                    let resp = dns_client.lookup(x.to_string()).await?;
                    let ip_addr = resp.get(0).ok_or_else(|| anyhow!("no endpoint found"))?;
                    SocketAddr::from((ip_addr.clone(), port))
                }
            },
            _ => {
                bail!("no host found")
            }
        };
        Ok(addr)
    }
}

#[async_trait]
impl Adaptor for HttpAdaptor {
    async fn request(&self, payload: ClientArgs) -> anyhow::Result<()> {
        let real_url = Url::parse(&payload.url)?;
        let addr = self.remote_addr(self.dns_client.clone(), &real_url).await?;
        let stream = TcpStream::connect(addr).await?;
        let stream: BoxStream = if real_url.scheme() == "https" {
            let mut ssl = self.factory.ssl(stream, payload.clone().into());
            ssl.set_connect_state();
            if payload.enable_ntls {
                ssl.enable_ntls();
            }
            if let Some(sni) = payload.sni {
                ssl.set_server_name(&*sni);
            }
            Box::new(ssl.spawn()?)
        } else {
            Box::new(stream)
        };
        let builder = hyper::client::conn::Builder::new();
        let (mut sender, connection) = builder.handshake(stream).await?;
        let mut req = Request::builder()
            .method(payload.method.deref())
            .uri(payload.url);
        match (payload.header, req.headers_mut()) {
            (Some(headers), Some(target)) => {
                let mut h = HashMap::with_capacity(headers.len());
                for header in headers {
                    let x = header.split("=").collect::<Vec<&str>>();
                    if let (Some(key), Some(value)) = (x.get(0), x.get(1)) {
                        h.insert(key.to_string(), value.to_string());
                    }
                }
                let x: HeaderMap = HeaderMap::try_from(&h)?;
                target.extend(x);
            }
            _ => {}
        };
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });
        let req = if let Some(x) = payload.body {
            req.body(Body::from(x))
        } else {
            req.body(Body::empty())
        }?;
        let response = sender.send_request(req).await?;
        let body = body::to_bytes(response.into_body()).await?;
        let body = String::from_utf8_lossy(&*body);
        println!("{}", body);
        Ok(())
    }
}
#[cfg(test)]
#[tokio::test]
async fn test_sm2() {
    use crate::test_utils::listen_at;
    let response = "HTTP/1.1 200 OK\r\n\r\n";
    let (addr, handle) = listen_at(None, Some(response)).await;
    let mut args = ClientArgs::default();
    args.sni = Some("test.com".to_string());
    args.cipher = Some("TLS_SM4_GCM_SM3".to_string());
    args.tls_version = "1.3".to_string();
    args.method = "GET".to_string();
    args.url = format!("https://{}", addr);
    create_adaptor(args).await.unwrap();
    handle.abort()
}
