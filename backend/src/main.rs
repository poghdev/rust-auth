mod models;
mod routes;
mod security;

use models::AppState;
use security::rate_limit::{spawn_cleanup_task, RateLimitConfigs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    tracing::info!("Database connected!");

    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState::from_env(pool);

    let rl_configs = RateLimitConfigs::new();
    spawn_cleanup_task(&rl_configs, 60);

    let app = routes::create_router(state, rl_configs);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Listening on 0.0.0.0:3000");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}