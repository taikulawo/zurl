use clap::{command, Arg, value_parser};

fn main() {

    let matches = command!()
    .arg(
        // 默认编译时include配置，运行时可覆盖，从文件路径中加载
        Arg::new("c")
            .long("cipher")
            .required(true)
            .value_parser(value_parser!(String)),
    )
    .get_matches();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    let rt = builder.enable_all().build().unwrap();
    println!("Hello, world!");
}
