use clap::Parser;
use zurl::{
    subcommands::{client::create_adaptor, server::create_server, Subcommands, gen::gen_cert},
    Arguments,
};

fn main() {
    let mut cli = Arguments::parse();
    let mut builder = tokio::runtime::Builder::new_current_thread();
    let rt = builder.enable_all().build().unwrap();
    rt.block_on(async {
        cli.resolve_pair().await?;
        match cli.commands {
            Subcommands::Client(client) => {
                create_adaptor(client).await?;
            }
            Subcommands::Server(server) => {
                create_server(server).await?;
            }
            Subcommands::Gen(ca) => {
                gen_cert(ca)?;
            }
        };
        Ok::<_, anyhow::Error>(())
    })
    .unwrap();
}
