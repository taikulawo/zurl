国密 http client cli

gen command 支持签发RSA，ECC，SM2证书
client 支持指定加密套件(支持国密套件)请求https server


安装方式

```
cargo install --git https://github.com/iamwwc/zurl
```

签发CA

```
zurl gen --ca www.example.com .
```

签发leaf

```
zurl gen www.test.com . --ca-cert ./www.example.com.cert.pem --ca-key ./www.example.com.key.pem
```

请求
```
zurl client --sni test.com --tls-version 1.3 --cipher TLS_SM4_GCM_SM3 https://127.0.0.1:3000
```


Debian如何安装RootCA

```
sudo mkdir /usr/local/share/ca-certificates/extra
sudo cp root.cert.pem /usr/local/share/ca-certificates/extra/root.cert.crt
sudo update-ca-certificates
```


---------------

本地开发测试

```
cargo install --path ./crates/zurl
```
