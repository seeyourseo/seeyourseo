use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use site_crawler::{
    AppState, Config, create_crawl, delete_crawl, get_crawl, get_pages, health, require_api_key,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let state = Arc::new(AppState::new(config.clone()));
    let api = Router::new()
        .route("/v1/crawls", post(create_crawl))
        .route("/v1/crawls/{crawl_id}", get(get_crawl).delete(delete_crawl))
        .route("/v1/crawls/{crawl_id}/pages", get(get_pages))
        .layer(from_fn_with_state(config.api_key.clone(), require_api_key));
    let app = Router::new()
        .route("/healthz", get(health))
        .merge(api)
        .with_state(state.clone());

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired().await;
        }
    });

    let listener = TcpListener::bind(config.listen).await?;
    eprintln!("site crawler listening on {}", config.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
