use std::{any::Any, collections::HashMap, net::SocketAddr, sync::Arc};
use std::ops::Deref;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use hyper::{body, Body, HeaderMap, Request};
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
pub async fn to_final_addr(args: &ClientArgs, dns_client: Arc<DnsClient>) -> anyhow::Result<SocketAddr> {
    let real_url = Url::parse(&args.url)?;
    let port = match real_url.scheme() {
        "https" => {
            real_url.port().unwrap_or(443)
        },
        "tcp" => {
            real_url.port().ok_or(anyhow!(""))?
        },
        x@_ => {
            bail!("unsupport protocol {}", x)
        }
    };
    let host = real_url.host();
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

pub async fn create_adaptor(client: ClientArgs) -> anyhow::Result<()> {
    let url = client.url.clone();
    let parts = url.split("://").collect::<Vec<&str>>();
    let prefix = parts
        .get(0)
        .ok_or_else(|| anyhow!("no avaliable prefix {}", url))?;

    let mut builder;
    if client.enable_ntls {
        builder = TlsBuilder::new(SslMethod::ntls());
        builder.enable_ntls();
    } else {
        builder = TlsBuilder::new(SslMethod::tls());
        let ssl_ctx = builder.get_inner_ctx();
        if client.tls_version.is_none() {
            bail!("for no ntls request, add --tls-version arguments");
        }
        let version = &*client.tls_version.clone().unwrap();
        match version {
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
                bail!("invalid version {}", version)
            }
        }
    }

    let factory = builder.build();

    let x: RealAdaptor = match *prefix {
        "http" | "https" => {
            let x = HttpsAdaptor::new(client.clone(), factory)?;
            Box::new(x)
        },
        "tcp" => {
            let x = TcpAdaptor::new(client.clone(), factory)?;
            Box::new(x)
        },
        _ => {
            bail!("unknown protocol {}", url);
        }
    };
    x.request(client).await?;
    Ok(())
}

struct TcpAdaptor {
    dns_client: Arc<DnsClient>,
    factory: Arc<SslFactory>,
}

impl TcpAdaptor {
    pub fn new(cli: ClientArgs, ssl_factory: SslFactory) -> anyhow::Result<Self> {
        let dns_client = Arc::new(DnsClient::new_with_default_resolver()?);
        let s = Self {
            dns_client,
            factory: Arc::new(ssl_factory),
        };
        Ok(s)
    }
}

#[async_trait]
impl Adaptor for TcpAdaptor {
    async fn request(&self, args: ClientArgs) -> anyhow::Result<()> {
        let addr = to_final_addr(&args, self.dns_client.clone()).await?;
        let stream = TcpStream::connect(addr).await?;
        let mut ssl = self.factory.ssl(stream, args.clone().into());
        if args.enable_ntls {
            ssl.enable_ntls();
            ssl.set_ssl_method(SslMethod::ntls());
        }
        let stream = ssl.spawn()?;
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let fut1 = tokio::spawn(async move{
            tokio::io::copy(&mut stdin, &mut write_half).await?;
            Ok::<_, anyhow::Error>(())
        });
        let fut2 = tokio::spawn(async move {
            tokio::io::copy(&mut read_half, &mut stdout).await?;
            Ok::<_, anyhow::Error>(())
        });
        let (a, b) = futures::future::join(fut1, fut2).await;
        a??;
        b??;
        Ok(())
    }
}

struct HttpsAdaptor {
    dns_client: Arc<DnsClient>,
    factory: Arc<SslFactory>,
}
impl HttpsAdaptor {
    pub fn new(cli: ClientArgs, ssl_factory: SslFactory) -> anyhow::Result<Self> {
        let dns_client = Arc::new(DnsClient::new_with_default_resolver()?);
        let s = Self {
            dns_client,
            factory: Arc::new(ssl_factory),
        };
        Ok(s)
    }
}

#[async_trait]
impl Adaptor for HttpsAdaptor {
    async fn request(&self, args: ClientArgs) -> anyhow::Result<()> {
        let real_url = Url::parse(&args.url)?;
        
        let addr = to_final_addr(&args, self.dns_client.clone()).await?;
        let stream = TcpStream::connect(addr).await?;
        if real_url.scheme() == "http" {
            // 我们要求每个请求都必须是TLS的
            // 如果没有使用TLS的需求，那就没必要用zurl，curl就可以
            bail!("for http protocol, only https supported");
        }
        let stream: BoxStream = {
            let mut ssl = self.factory.ssl(stream, args.clone().into());
            ssl.set_connect_state();
            if args.enable_ntls {
                ssl.enable_ntls();
            }
            if let Some(sni) = args.sni {
                ssl.set_server_name(&*sni);
            }
            Box::new(ssl.spawn()?)
        };
        let builder = hyper::client::conn::Builder::new();
        let (mut sender, connection) = builder.handshake(stream).await?;
        let mut req = Request::builder()
            .method(args.method.deref())
            .uri(args.url);
        match (args.header, req.headers_mut()) {
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
        let req = if let Some(x) = args.body {
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
    args.tls_version = Some("1.3".to_string());
    args.method = "GET".to_string();
    args.url = format!("https://{}", addr);
    create_adaptor(args).await.unwrap();
    handle.abort()
}
