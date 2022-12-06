#![feature(async_fn_in_trait)]

use clap::{command, Parser};
use std::{io, path::Path};
use subcommands::ServerArgs;

pub mod certificates;
pub mod constant;
pub mod dns;
pub mod stream;
pub mod subcommands;

#[derive(Default)]
pub struct TlsRecord {
    pub sni: Option<String>,
}

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    #[command(subcommand)]
    pub commands: subcommands::Subcommands,
}
impl Arguments {
    pub async fn resolve_pair(&mut self) -> io::Result<()> {
        match self.commands {
            subcommands::Subcommands::Server(ref mut server) => {
                let ServerArgs {
                    addr: _,
                    tls_cert_file_path,
                    tls_key_file_path,
                    sm2_cert_file_path,
                    sm2_key_file_path,
                    ntls_enc_cert_file_path,
                    ntls_enc_key_file_path,
                    ntls_sign_cert_file_path,
                    ntls_sign_key_file_path,
                    tls_cert_content,
                    tls_key_content,
                    sm2_cert_content,
                    sm2_key_content,
                    ntls_enc_cert_content,
                    ntls_enc_key_content,
                    ntls_sign_cert_content,
                    ntls_sign_key_content,
                } = server;
                if let (Some(ref f), None) = (&tls_cert_file_path, &tls_cert_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *tls_cert_content = Some(cert_string_to_vec(&s))
                }
                if let (Some(ref f), None) = (&tls_key_file_path, &tls_key_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *tls_key_content = Some(s)
                }
                if let (Some(ref f), None) = (&sm2_cert_file_path, &sm2_cert_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *sm2_cert_content = Some(cert_string_to_vec(&s))
                }
                if let (Some(ref f), None) = (&sm2_key_file_path, &sm2_key_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *sm2_key_content = Some(s)
                }
                if let (Some(ref f), None) = (&ntls_enc_cert_file_path, &ntls_enc_cert_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *ntls_enc_cert_content = Some(s)
                }
                if let (Some(ref f), None) = (&ntls_enc_key_file_path, &ntls_enc_key_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *ntls_enc_key_content = Some(s)
                }
                if let (Some(ref f), None) = (&ntls_sign_cert_file_path, &ntls_sign_cert_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *ntls_sign_cert_content = Some(s)
                }
                if let (Some(ref f), None) = (&ntls_sign_key_file_path, &ntls_sign_key_content) {
                    let s = tokio::fs::read_to_string(Path::new(&**f)).await?;
                    *ntls_sign_key_content = Some(s);
                };
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn cert_string_to_vec(certs: &str) -> Vec<String> {
    certs
        .split_inclusive("-----END CERTIFICATE-----\n")
        .map(String::from)
        .collect::<Vec<String>>()
}

pub const DEFAULT_CIPHER: &str = "HIGH:!aNULL:!MD5";


pub mod utils {
    use std::{path::{Path, PathBuf}, fs};

    pub fn abs_path<P: AsRef<Path>>(path: P) -> PathBuf {
        fs::canonicalize(path.as_ref()).expect(path.as_ref().to_str().unwrap_or("unknown"))
    }
}


#[cfg(test)]
pub mod test_utils {
    use std::net::SocketAddr;

    use futures::stream::AbortHandle;
    use tokio::io::AsyncWriteExt;

    pub async fn listen_at(addr: Option<SocketAddr>, response: Option<&'static str>) -> (SocketAddr, AbortHandle) {
        let addr = if let Some(addr) = addr {
            addr
        }else {
            "127.0.0.1:0".parse::<SocketAddr>().unwrap()
        };
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (abort_future, handle) = futures::future::abortable(async move{
            loop {
                let (mut stream, addr) = match listener.accept().await {
                    Ok(x) => x,
                    Err(err) => {
                        eprintln!("listen at {} error {}", addr, err);
                        continue;
                    }
                };
                tokio::spawn(async move{
                    if let Some(response) = response {
                        stream.write_all(response.as_bytes()).await;
                    }
                });
            };
        });
        tokio::spawn(abort_future);
        (addr, handle)
    }
}