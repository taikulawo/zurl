use anyhow::bail;
use openssl::{ssl::{Ssl, SslMethod}, x509::X509};

use crate::stream::Certificates;

pub fn set_certificate(info: &Certificates, ssl: &mut Ssl) -> anyhow::Result<()> {
    let (key, content) = match (
        info.tls_key_content.as_ref(),
        info.tls_cert_content.as_ref(),
        info.sm2_key_content.as_ref(),
        info.sm2_cert_content.as_ref(),
        info.ntls_sign_key_content.as_ref(),
        info.ntls_sign_cert_content.as_ref(),
        info.ntls_enc_key_content.as_ref(),
        info.ntls_enc_cert_content.as_ref(),
    ) {
        (Some(tls_key), Some(tls_content), ..) => (tls_key, tls_content),
        (_, _, Some(sm2_key), Some(sm2_content), ..) => (sm2_key, sm2_content),
        (.., Some(sign_key), Some(sign_cert_content), Some(enc_key), Some(enc_cert_content)) => {
            ssl.set_ssl_method(SslMethod::ntls());
            match ssl.use_ntls_key_content_and_cert_content_pem(
                &*sign_key.as_bytes(),
                &*sign_cert_content.as_bytes(),
                &*enc_key.as_bytes(),
                &*enc_cert_content.as_bytes(),
            ) {
                Err(err) => {
                    bail!(
                        "has ntls enabled, but setting sm2 key/cert failed. {}. connection closed",
                        err
                    );
                }
                _ => return Ok(()),
            }
        }
        _ => {
            bail!("unsupport key/cert")
        }
    };
    ssl.disable_ntls();
    for (index, cert) in content.iter().enumerate() {
        if index == 0 {
            ssl.use_certificate_pem(cert.as_bytes())?;
        } else {
            let x509 = X509::from_pem(cert.as_bytes())?;
            ssl.add_chain_cert(x509)?;
        }
    }
    ssl.use_private_key_pem(&key.as_bytes())?;
    Ok(())
}
