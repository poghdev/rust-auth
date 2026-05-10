use sqlx::postgres::PgPoolOptions;
use axum::{Router, routing::get, routing::post};
use dotenvy::dotenv;
use std::env;
use tower_http::cors::{CorsLayer, Any};

mod routes;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE URL must be set in .env");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    println!("Database connected !");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed !");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(|| async { "Auth API is running !" }))
        .route("/register", post(routes::auth::register))
        .route("/login", post(routes::auth::login))
        .layer(cors)
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    
    axum::serve(listener, app).await.unwrap();
}