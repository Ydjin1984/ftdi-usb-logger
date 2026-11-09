use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = ftdi_logger::config::Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(cli.log_level.clone())),
        )
        .with_target(false)
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(ftdi_logger::run(cli))
}
