use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand};

pub mod client;
pub mod server;
pub mod gen;
#[cfg(test)]
mod gen_test;
#[derive(Args, Clone, Debug, Default)]
pub struct ClientArgs {
    pub url: String,
    #[arg(long, default_value = "1.2")]
    pub tls_version: String,
    #[arg(short, long)]
    pub cipher: Option<String>,
    #[arg(long)]
    pub sni: Option<String>,
    // http 参数
    #[arg(long, default_value = "GET")]
    pub method: String,
    #[arg(long)]
    pub body: Option<String>,
    // --header key=value --header key=value
    pub header: Option<Vec<String>>,

    // ntls
    #[arg(long)]
    pub ntls_enc_cert_file_path: Option<String>,
    #[arg(long)]
    pub ntls_enc_key_file_path: Option<String>,
    #[arg(long)]
    pub ntls_sign_cert_file_path: Option<String>,
    #[arg(long)]
    pub ntls_sign_key_file_path: Option<String>,
    // ntls
    #[arg(long)]
    pub ntls_enc_cert_content: Option<String>,
    #[arg(long)]
    pub ntls_enc_key_content: Option<String>,
    #[arg(long)]
    pub ntls_sign_cert_content: Option<String>,
    #[arg(long)]
    pub ntls_sign_key_content: Option<String>,
}
#[derive(Args, Clone, Debug)]
pub struct ServerArgs {
    pub addr: SocketAddr,
    #[arg(long)]
    pub tls_cert_file_path: Option<String>,
    #[arg(long)]
    pub tls_key_file_path: Option<String>,
    #[arg(long)]
    pub sm2_cert_file_path: Option<String>,
    #[arg(long)]
    pub sm2_key_file_path: Option<String>,

    // ntls
    #[arg(long)]
    pub ntls_enc_cert_file_path: Option<String>,
    #[arg(long)]
    pub ntls_enc_key_file_path: Option<String>,
    #[arg(long)]
    pub ntls_sign_cert_file_path: Option<String>,
    #[arg(long)]
    pub ntls_sign_key_file_path: Option<String>,

    #[arg(long)]
    pub tls_cert_content: Option<Vec<String>>,
    #[arg(long)]
    pub tls_key_content: Option<String>,
    #[arg(long)]
    pub sm2_cert_content: Option<Vec<String>>,
    #[arg(long)]
    pub sm2_key_content: Option<String>,

    // ntls
    #[arg(long)]
    pub ntls_enc_cert_content: Option<String>,
    #[arg(long)]
    pub ntls_enc_key_content: Option<String>,
    #[arg(long)]
    pub ntls_sign_cert_content: Option<String>,
    #[arg(long)]
    pub ntls_sign_key_content: Option<String>,
}
#[derive(Args, Clone, Debug)]
pub struct GenArgs {
    #[arg(long, default_value = "rsa")]
    // rsa | ecc | sm2
    // 证书类型
    ty: String,
    // CA证书
    #[arg(long, default_value_t = false)]
    ca: bool,
    #[arg(long)]
    ca_key_path: Option<PathBuf>,
    #[arg(long)]
    ca_cert_path: Option<PathBuf>,
    // common name
    // 除ca外，common name必须为签发的域名
    name: String,
    out_path: PathBuf,
}

impl GenArgs {
    pub fn default_rsa_root_ca() -> Self {
        Self {
            ca: true,
            ca_key_path: None,
            name: "test.example.org".to_string(),
            ty: "rsa".to_string(),
            out_path: "./".into(),
            ca_cert_path: Some("./".try_into().unwrap()),
        }
    }
}

#[derive(Subcommand, Clone, Debug)]
pub enum Subcommands {
    //
    Client(ClientArgs),
    Server(ServerArgs),
    Gen(GenArgs),
}
