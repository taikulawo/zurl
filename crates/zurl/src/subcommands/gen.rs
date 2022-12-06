use std::{
    fs,
    path::{Path},
};

use anyhow::{bail};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
    }, ec::{EcGroup, EcKey}, nid::Nid, ssl::tongsuo::NID_SM2,
};


use super::GenArgs;

pub fn gen_cert(args: GenArgs) -> anyhow::Result<()> {
    if args.ca {
        sign_ca_cert(args.try_into()?)
    } else {
        sign_cert(args.try_into()?)
    }
}


fn sign_ca_cert(mut args: GenArgs) -> anyhow::Result<()> {
    let (cert, key) = match mk_ca_cert(&args) {
        Ok(x) => x,
        Err(err) => {
            bail!("{}", err)
        }
    };

    let pem = cert.to_pem()?;
    let out_path = &mut args.out_path;
    let name = args.name;
    let cert_name = format!("{}.ca.cert.pem", &*name);
    let out_cert_path = out_path.join(Path::new(&*cert_name));
    fs::write(out_cert_path, pem)?;

    let key_name = format!("{}.ca.key.pem", &*name);
    let out_key_path = out_path.join(Path::new(&*key_name));
    fs::write(out_key_path, key.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

// 创建CA证书
fn mk_ca_cert(args: &GenArgs) -> anyhow::Result<(X509, PKey<Private>)> {
    let key_pair = match &*args.ty {
        "sm2" => {
            gen_sm2_pair()?
        },
        "rsa" => {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)?
        },
        "ec" => {
            //TODO 用哪个curve name?
            gen_ec_pair(Nid::X9_62_PRIME256V1)?
        },
        _ => {
            bail!("unsupported key type {} found", args.ty);
        }
    };
    mk_request(args, &key_pair)?;
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some CA organization")?;
    x509_name.append_entry_by_text("CN", &args.name)?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;
    match &*args.ty {
        "sm2" => {
            cert_builder.sign(&key_pair, MessageDigest::sm3())?;
        },
        _ => {
            cert_builder.sign(&key_pair, MessageDigest::sha256())?;
        }
    }
    let cert = cert_builder.build();
    Ok((cert, key_pair))
}

/// 利用预先生成的证书pub/key生成证书请求
fn mk_request(args: &GenArgs, key_pair: &PKey<Private>) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some organization")?;
    x509_name.append_entry_by_text("CN", &args.name)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;
    match &*args.ty {
        "sm2" => {
            req_builder.sign(key_pair, MessageDigest::sm3())?;
        },
        _ => {
            req_builder.sign(key_pair, MessageDigest::sha256())?;
        }
    }
    let req = req_builder.build();
    Ok(req)
}

fn sign_cert(args: GenArgs) -> anyhow::Result<()> {
    let ca_cert_path = args.ca_cert_path.as_ref().expect("missing ca-cert-path ");
    let ca_key_path = args.ca_key_path.as_ref().expect("missing ca-key-path");
    let ca_cert = fs::read(ca_cert_path)?;
    let ca_key = fs::read(ca_key_path)?;
    let ca_cert = X509::from_pem(&*ca_cert)?;
    let ca_key = PKey::private_key_from_pem(&*ca_key)?;
    let req = mk_request(&args, &ca_key)?;


    
    let key_pair = match &*args.ty {
        "sm2" => {
            gen_sm2_pair()?
        },
        "rsa" => {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)?
        },
        "ecc" => {
            gen_ec_pair(Nid::X9_62_PRIME256V1)?
        },
        _ => {
            bail!("unsupport key type {}", &*args.ty);
        }
    };

    let cert = mk_ca_signed_cert(&args, &req, &key_pair,ca_cert.as_ref(), ca_key.as_ref())?;

    let name = args.name;
    let out_path = args.out_path;
    let cert_name = format!("{}.cert.pem", &*name);
    let out_cert_path = out_path.join(Path::new(&*cert_name));
    fs::write(out_cert_path, cert.to_pem()?)?;

    let key_name = format!("{}.key.pem", &*name);
    let out_key_path = out_path.join(Path::new(&*key_name));
    fs::write(out_key_path, key_pair.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

/// CA使用自己的私钥将证书公钥签发到证书上
fn mk_ca_signed_cert(
    args: &GenArgs,
    req: &X509Req,
    key_pair: &PKey<Private>,
    ca_cert: &X509Ref,
    _ca_key_pair: &PKeyRef<Private>,
) -> Result<X509, ErrorStack> {
    
    // 似乎CSR没用？
    // 我倾向于CSR是发送给CA机构签发才用到的
    // 如果在本地代码里生成CA，签发证书。实际上证书的信息都能拿到，CSR就不是必须
    mk_request(args, &key_pair)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns("*.example.com")
        .dns("hello.com")
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    match &*args.ty {
        "sm2" => {
            cert_builder.sign(&key_pair, MessageDigest::sm3())?;
        },
        _ => {
            cert_builder.sign(&key_pair, MessageDigest::sha256())?;
        }
    }
    let cert = cert_builder.build();

    Ok(cert)
}

// sm2 用的是ec，不是rsa
pub(super) fn gen_sm2_pair() -> Result<PKey<Private>, ErrorStack>{
    let mut pkey = gen_ec_pair(Nid::from_raw(NID_SM2))?;
    pkey.set_alias_type(NID_SM2);
    Ok(pkey)
}


fn gen_ec_pair(nid: Nid) -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(nid)?;
    let _key = EcKey::from_group(group.as_ref())?;
    let pair = EcKey::generate(&group)?;
    PKey::from_ec_key(pair)
}
