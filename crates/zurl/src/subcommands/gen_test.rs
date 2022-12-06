use super::{GenArgs, gen::{self, gen_sm2_pair}};

#[test]
fn test_sign_ca() {
    let args = GenArgs::default_rsa_root_ca();
    gen::gen_cert(args).unwrap();
}
#[test]
fn test_gen_sm2() {
    let pair = gen_sm2_pair().unwrap();
    let pkey = pair.private_key_to_pem_pkcs8().unwrap();
    let s = String::from_utf8_lossy(&*pkey);
    println!("{}", s);
}


#[test]
fn test_sign_sm2_ca() {
    let mut args = GenArgs::default_rsa_root_ca();
    args.ty = "sm2".to_string();
    gen::gen_cert(args).unwrap();
}