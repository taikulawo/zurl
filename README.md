国密 http client cli

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
zurl gen www.test.com . --ca-cert-path ./www.example.com.cert.pem --ca-key-path ./www.example.com.key.pem
```

请求
```
zurl client --sni test.com --tls-version 1.3 --cipher TLS_SM4_GCM_SM3 https://127.0.0.1:3000
```


---------------

本地开发测试

```
cargo install --path ./crates/zurl
```
