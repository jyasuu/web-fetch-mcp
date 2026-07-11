mod fetch_tool;
mod robots;
mod ssrf;

use fetch_tool::WebFetchServer;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    // Set RESPECT_ROBOTS=false to disable robots.txt checks (e.g. for internal/personal use).
    let respect_robots = std::env::var("RESPECT_ROBOTS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    // Comma-separated allowed Host header values, e.g. "localhost:8080,mcp.example.com".
    // Note: rmcp 0.16 doesn't expose an allowed_hosts config method; this is kept
    // for future use or custom middleware if needed.
    let _allowed_hosts: Vec<String> = std::env::var("ALLOWED_HOSTS")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|_| vec![bind_addr.clone()]);

    let config = StreamableHttpServerConfig::default();

    let service = StreamableHttpService::new(
        move || Ok(WebFetchServer::new(respect_robots)),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let router = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("web-fetch-mcp listening at http://{bind_addr}/mcp (robots.txt check: {respect_robots})");

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    Ok(())
}
