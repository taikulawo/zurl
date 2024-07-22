use std::{fs, path::Path};

use super::GenArgs;
use anyhow::bail;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::tongsuo::NID_SM2,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509VerifyResult, X509,
    },
};

pub fn gen_cert(args: GenArgs) -> anyhow::Result<()> {
    let authority = Authority::new();
    if args.ca {
        authority.sign_ca_cert(args.try_into()?)
    } else {
        authority.sign_cert(args.try_into()?)
    }
}

pub struct Authority {}

impl Authority {
    pub fn new() -> Self {
        Self {}
    }

    fn sign_ca_cert(&self, mut args: GenArgs) -> anyhow::Result<()> {
        let (cert, key) = match self.mk_ca_cert(&args) {
            Ok(x) => x,
            Err(err) => {
                bail!("{}", err)
            }
        };

        let pem = cert.to_pem()?;
        let out_path = &mut args.out_dir;
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
    pub fn mk_ca_cert(&self, args: &GenArgs) -> anyhow::Result<(X509, PKey<Private>)> {
        let key_pair = match &*args.ty {
            "sm2" => Self::gen_sm2_pair()?,
            "rsa" => {
                let rsa = Rsa::generate(2048)?;
                PKey::from_rsa(rsa)?
            }
            "ecc" => {
                //TODO 用哪个curve name?
                Self::gen_ec_pair(Nid::X9_62_PRIME256V1)?
            }
            _ => {
                bail!("unsupported key type {} found", args.ty);
            }
        };
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
            }
            _ => {
                cert_builder.sign(&key_pair, MessageDigest::sha256())?;
            }
        }
        let cert = cert_builder.build();
        Ok((cert, key_pair))
    }

    fn sign_cert(&self, args: GenArgs) -> anyhow::Result<()> {
        let ca_cert_path = args.ca_cert.as_ref().expect("missing ca-cert-path ");
        let ca_key_path = args.ca_key.as_ref().expect("missing ca-key-path");
        let ca_cert = fs::read(ca_cert_path)?;
        let ca_key = fs::read(ca_key_path)?;
        let ca_cert = X509::from_pem(&ca_cert)?;
        let ca_key = PKey::private_key_from_pem(&ca_key)?;
        let key_pair = match &*args.ty {
            "sm2" => Self::gen_sm2_pair()?,
            "rsa" => {
                let rsa = Rsa::generate(2048)?;
                PKey::from_rsa(rsa)?
            }
            "ecc" => Self::gen_ec_pair(Nid::X9_62_PRIME256V1)?,
            _ => {
                bail!("unsupport key type {}", &*args.ty);
            }
        };
        let cert =
            self.mk_signed_cert(&args.name, &args.ty, &key_pair, ca_cert.as_ref(), &ca_key)?;

        let name = args.name;
        let out_path = args.out_dir;
        let cert_name = format!("{}.cert.pem", &*name);
        let out_cert_path = out_path.join(Path::new(&*cert_name));
        fs::write(out_cert_path, cert.to_pem()?)?;

        let key_name = format!("{}.key.pem", &*name);
        let out_key_path = out_path.join(Path::new(&*key_name));
        fs::write(out_key_path, key_pair.private_key_to_pem_pkcs8()?)?;
        Ok(())
    }

    /// CA使用自己的私钥将证书公钥签发到证书上
    pub fn mk_signed_cert(
        &self,
        name: &str,
        ty: &str,
        key_pair: &PKey<Private>,
        ca_cert: &X509Ref,
        ca_key: &PKey<Private>,
    ) -> Result<X509, ErrorStack> {
        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("C", "US").unwrap();
        x509_name.append_entry_by_text("ST", "CA").unwrap();
        x509_name
            .append_entry_by_text("O", "Some organization")
            .unwrap();
        x509_name.append_entry_by_text("CN", name).unwrap();
        let x509_name = x509_name.build();

        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;
        cert_builder.set_pubkey(key_pair)?;
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

        match ty {
            "sm2" => {
                cert_builder.sign(&ca_key, MessageDigest::sm3())?;
            }
            _ => {
                cert_builder.sign(&ca_key, MessageDigest::sha256())?;
            }
        }
        let cert = cert_builder.build();
        match ca_cert.issued(&cert) {
            err @ X509VerifyResult::APPLICATION_VERIFICATION => {
                println!("Failed to verify certificate: {}", err)
            }
            _ => {}
        }
        Ok(cert)
    }

    // sm2 用的是ec，不是rsa
    pub fn gen_sm2_pair() -> Result<PKey<Private>, ErrorStack> {
        let mut pkey = Self::gen_ec_pair(Nid::from_raw(NID_SM2))?;
        pkey.set_alias_type(NID_SM2);
        Ok(pkey)
    }

    pub fn gen_ec_pair(nid: Nid) -> Result<PKey<Private>, ErrorStack> {
        let group = EcGroup::from_curve_name(nid)?;

        let _key = EcKey::from_group(group.as_ref())?;
        let pair = EcKey::generate(&group)?;
        PKey::from_ec_key(pair)
    }
}

#[test]
fn test_sign_ca() {
    let args = GenArgs::default_rsa_root_ca();
    gen_cert(args).unwrap();
}
#[test]
fn test_gen_sm2() {
    let pair = Authority::gen_sm2_pair().unwrap();
    let pkey = pair.private_key_to_pem_pkcs8().unwrap();
    let s = String::from_utf8_lossy(&*pkey);
    println!("{}", s);
}

#[test]
fn test_sign_sm2_ca() {
    let mut args = GenArgs::default_rsa_root_ca();
    args.ty = "sm2".to_string();
    gen_cert(args).unwrap();
}
