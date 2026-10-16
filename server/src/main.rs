use std::{env, path::PathBuf};

use prediction_demo_server::{App, Config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("server/config.toml"));
    let config = Config::load(&config_path).await?;
    let app = App::new(config).await?;
    let listener = tokio::net::TcpListener::bind(app.listen_address()).await?;

    tracing::info!(address = %listener.local_addr()?, "prediction demo server listening");
    axum::serve(listener, app.router()).await?;
    Ok(())
}
