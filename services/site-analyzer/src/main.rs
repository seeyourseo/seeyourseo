use std::{sync::Arc, time::Duration};

use site_analyzer::{AppState, Config, router};
use tokio::net::TcpListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    site_sandbox::apply(site_sandbox::Service::Analyzer)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let state = Arc::new(AppState::new(config.clone()));
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired().await;
        }
    });

    let listener = TcpListener::bind(config.listen).await?;
    eprintln!("site analyzer listening on {}", config.listen);
    axum::serve(listener, router(state)).await?;
    Ok(())
}
