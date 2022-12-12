use std::{net::SocketAddr, sync::Arc};

use openssl::ssl::SslMethod;

use crate::stream::TlsBuilder;

use super::ServerArgs;

pub trait ListenerServer {
    async fn listen(&mut self, addr: SocketAddr) -> anyhow::Result<()>;
}

struct EchoServer {
    args: ServerArgs,
}
pub async fn create_server(args: ServerArgs) -> anyhow::Result<()> {
    let addr = args.addr.clone();
    let mut server = EchoServer::new(args.clone());
    server.listen(addr).await
}

impl EchoServer {
    pub fn new(args: ServerArgs) -> Self {
        Self {
            args
        }
    }
}

impl ListenerServer for EchoServer {
    async fn listen(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let mut tls_builder = TlsBuilder::new(SslMethod::tls());
        if self.args.enable_ntls {
            tls_builder.enable_ntls();
        }
        let factory = Arc::new(tls_builder.build());
        loop {
            let (stream, _local_addr) = match listener.accept().await {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("accept error {}", err);
                    continue;
                }
            };
            let mut ssl = factory.ssl(stream, self.args.clone().into());
            ssl.set_accept_state();
            if let Ok(stream) = ssl.spawn() {
                tokio::spawn(async move {
                    let (mut read_half, mut write_half) = tokio::io::split(stream);
                    if let Err(err) = tokio::io::copy(&mut read_half, &mut write_half).await {
                        eprintln!("error when copy from reader to writer {}", err)
                    }
                });
            }else {
                continue
            }
        }
    }
}

struct HttpServer {}

impl ListenerServer for HttpServer {
    async fn listen(&mut self, _addr: SocketAddr) -> anyhow::Result<()> {
        todo!()
    }
}

#[cfg(test)]
#[tokio::test]
async fn test_echo_server() {

}