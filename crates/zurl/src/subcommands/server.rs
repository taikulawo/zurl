use std::net::SocketAddr;

use super::ServerArgs;

pub trait ListenerServer {
    async fn listen(&mut self, addr: SocketAddr) -> anyhow::Result<()>;
}

struct EchoServer {}
pub async fn create_server(_server: ServerArgs) -> anyhow::Result<()> {
    todo!()
}
impl ListenerServer for EchoServer {
    async fn listen(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        loop {
            let (stream, _local_addr) = match listener.accept().await {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("accept error {}", err);
                    continue;
                }
            };
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = stream.into_split();
                if let Err(err) = tokio::io::copy(&mut read_half, &mut write_half).await {
                    eprintln!("error when copy from reader to writer {}", err)
                }
            });
        }
    }
}

struct HttpServer {}

impl ListenerServer for HttpServer {
    async fn listen(&mut self, _addr: SocketAddr) -> anyhow::Result<()> {
        todo!()
    }
}
