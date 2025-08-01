use axum::{
    routing::{get, post},
    Router,
};
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use config::Config;
use std::error::Error;
use tracing::{event, Level};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

mod config;
mod error;
mod oauth2_handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // 初始化配置
    let cfg = Arc::new(Config::load()?);
    event!(Level::INFO,"Loaded config: {:?}", cfg);
    
    // 构建路由
    let app = Router::new()
        .route("/oauth2/login", get(oauth2_handler::oauth2_login))
        .route("/cas/callback", get(oauth2_handler::cas_callback))
        .route("/oauth2/token", post(oauth2_handler::exchange_token))
        .route("/oauth2/userinfo", get(oauth2_handler::get_user_info))
        .with_state(cfg.clone());
    event!(Level::INFO,"Registered routes: /oauth2/login, /cas/callback, /oauth2/token, /oauth2/userinfo");

    // 启动服务器
    let host: Ipv4Addr = cfg.server.host.parse()?;
    let addr = SocketAddr::from((host, cfg.server.port));
    event!(Level::INFO,"Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    event!(Level::INFO,"Server started successfully on {}", addr);
    event!(Level::INFO,"Starting to serve requests...");
    
    event!(Level::INFO,"Entering main request handling loop");
    axum::serve(listener,app.into_make_service()).await?;
    
    event!(Level::INFO,"Server received shutdown signal");
    event!(Level::INFO,"Server shutdown gracefully");
    event!(Level::INFO,"All connections closed, exiting process");
    Ok(())
}
