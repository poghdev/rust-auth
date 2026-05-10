use axum::{Router, routing::{post, get}};
use sqlx::PgPool;
use tower_http::cors::{CorsLayer, Any};

pub mod auth;

pub fn create_router(pool: PgPool) -> Router {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let auth_routes = Router::new().route("/register", post(auth::register)).route("/login", post(auth::login)).route("/me", get(auth::get_token)); 

    Router::new().nest("/api/v1/auth", auth_routes).layer(cors).with_state(pool)
}