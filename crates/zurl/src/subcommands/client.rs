use std::net::IpAddr;
use std::ops::Deref;
use std::{any::Any, collections::HashMap, net::SocketAddr, sync::Arc};

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
pub async fn to_final_addr(
    args: &ClientArgs,
    dns_client: Arc<DnsClient>,
) -> anyhow::Result<SocketAddr> {
    let real_url = Url::parse(&args.url)?;
    let port = match real_url.scheme() {
        "https" => real_url.port().unwrap_or(443),
        "tcp" => real_url.port().ok_or(anyhow!(
            "for tcp protocol, port required. like tcp://1.2.3.4:1080"
        ))?,
        x @ _ => {
            bail!("unsupport protocol {}", x)
        }
    };
    let host = real_url.host();
    let addr = match host {
        Some(x) => match x {
            Host::Ipv4(x) => SocketAddr::from((x, port)),
            Host::Ipv6(x) => SocketAddr::from((x, port)),
            Host::Domain(x) => {
                let addr = match x.parse::<IpAddr>() {
                    Ok(x) => SocketAddr::from((x, port)),
                    Err(_) => {
                        let resp = dns_client.lookup(x.to_string()).await?;
                        let ip_addr = resp.get(0).ok_or_else(|| anyhow!("no endpoint found"))?;
                        SocketAddr::from((ip_addr.clone(), port))
                    }
                };
                addr
            }
        },
        _ => {
            bail!("no host found")
        }
    };
    Ok(addr)
}

pub async fn create_adaptor(args: ClientArgs) -> anyhow::Result<()> {
    let url = args.url.clone();
    let parts = url.split("://").collect::<Vec<&str>>();
    let prefix = parts
        .get(0)
        .ok_or_else(|| anyhow!("no avaliable prefix {}", url))?;

    let mut builder = TlsBuilder::new(args.enable_ntls);
    let ssl_ctx = builder.get_inner_ctx();
    if !args.enable_ntls{
        if args.tls_version.is_none() {
            bail!("for no ntls request, add --tls-version arguments");
        }
        let version = &*args.tls_version.clone().unwrap();
        match version {
            "1.3" => {
                ssl_ctx
                    .set_ciphersuites(if let Some(ref x) = args.cipher {
                        &*x
                    } else {
                        DEFAULT_CIPHER
                    })
                    .unwrap();
            }
            "1.2" => {
                ssl_ctx
                    .set_cipher_list(if let Some(ref x) = args.cipher {
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
            let x = HttpsAdaptor::new(args.clone(), factory)?;
            Box::new(x)
        }
        "tcp" => {
            let x = TcpAdaptor::new(args.clone(), factory)?;
            Box::new(x)
        }
        _ => {
            bail!("unknown protocol {}", url);
        }
    };
    x.request(args).await?;
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
        ssl.set_connect_state();
        if let Some(ref sni) = args.sni {
            ssl.set_server_name(&*sni);
        }
        if args.enable_ntls {
            ssl.enable_ntls();
            ssl.set_ssl_method(SslMethod::ntls());
        }
        let stream = ssl.spawn()?;
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let fut1 = tokio::spawn(async move {
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
        let mut req = Request::builder().method(args.method.deref()).uri(args.url);
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

#[cfg(test)]
pub mod test_client {
    use std::{net::SocketAddr, time::Duration};

    use crate::subcommands::{
        gen::Authority, server::create_server, ClientArgs, GenArgs, ServerArgs,
    };

    use super::create_adaptor;

    #[test]
    fn test_ntls_tcp_adaptor() {
        let mut server_rt = tokio::runtime::Builder::new_current_thread();
        let authority = Authority::new();
        let gen_args = GenArgs::default_sm2_root_ca();

        // root ca
        let (root_ca, root_key) = authority.mk_ca_cert(&gen_args).unwrap();

        let root_ca_pem = root_ca.to_pem().unwrap();
        let root_key_pem = root_key.private_key_to_pem_pkcs8().unwrap();

        // leaf key/cert
        let (sm2_enc_cert, sm2_enc_key) = {
            let sm2_key_pair = Authority::gen_sm2_pair().unwrap();
            let name = "leaf.example.org";
            let ty = "sm2";
            let leaf_cert = authority
                .mk_signed_cert(name, ty, &sm2_key_pair, &root_ca)
                .unwrap();

            let sm2_leaf_cert_pem = leaf_cert.to_pem().unwrap();
            let sm2_leaf_key_pem = sm2_key_pair.private_key_to_pem_pkcs8().unwrap();
            (
                String::from_utf8(sm2_leaf_cert_pem).unwrap(),
                String::from_utf8(sm2_leaf_key_pem).unwrap(),
            )
        };

        let (sm2_sign_cert, sm2_sign_key) = {
            let sm2_key_pair = Authority::gen_sm2_pair().unwrap();
            let name = "leaf.example.org";
            let ty = "sm2";
            let leaf_cert = authority
                .mk_signed_cert(name, ty, &sm2_key_pair, &root_ca)
                .unwrap();

            let sm2_leaf_cert_pem = leaf_cert.to_pem().unwrap();
            let sm2_leaf_key_pem = sm2_key_pair.private_key_to_pem_pkcs8().unwrap();
            (
                String::from_utf8(sm2_leaf_cert_pem).unwrap(),
                String::from_utf8(sm2_leaf_key_pem).unwrap(),
            )
        };

        let runtime = server_rt.enable_all().build().unwrap();
        let addr = "[::]:4000".parse::<SocketAddr>().unwrap();
        runtime.spawn(async move {
            let server_args = ServerArgs {
                enable_ntls: true,
                addr,
                ntls_enc_cert_content: Some(sm2_enc_cert),
                ntls_enc_key_content: Some(sm2_enc_key),
                ntls_sign_cert_content: Some(sm2_sign_cert),
                ntls_sign_key_content: Some(sm2_sign_key),
                ntls_enc_cert_file: None,
                ntls_enc_key_file: None,
                ntls_sign_cert_file: None,
                ntls_sign_key_file: None,
                sm2_cert_content: None,
                sm2_cert_file: None,
                sm2_key_content: None,
                sm2_key_file: None,
                tls_cert_content: None,
                tls_cert_file: None,
                tls_key_content: None,
                tls_key_file: None,
            };
            create_server(server_args).await.unwrap();
        });
        runtime.block_on(async {
            let mut args = ClientArgs::default();
            args.url = "tcp://127.0.0.1:4000".to_string();
            args.enable_ntls = true;
            let cipher = "ECC-SM2-WITH-SM4-SM3".to_string();
            args.cipher = Some(cipher);
            args.sni = Some("leaf.example.org".to_string());
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("type character in stdin console");
            create_adaptor(args).await.unwrap();
        });
    }
}
