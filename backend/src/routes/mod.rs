use axum::{Router, routing::{get, post}};
use axum::http::{HeaderValue, Method, header::{CONTENT_TYPE, COOKIE}};
use tower_http::cors::CorsLayer;

use crate::models::AppState;
use crate::security::rate_limit::{RateLimitConfigs, auth_rate_limit_layer, general_rate_limit_layer};

pub mod auth;
pub mod cookies;
pub mod extractor;
pub mod jwt;

pub fn create_router(state: AppState, rl: RateLimitConfigs) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:5500".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:5500".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE, COOKIE])
        .allow_credentials(true);

    let auth_sensitive = Router::new()
        .route("/register", post(auth::register))
        .route("/login",    post(auth::login))
        .layer(auth_rate_limit_layer(rl.auth.clone()));

    let auth_general = Router::new()
        .route("/logout",          post(auth::logout))
        .route("/refresh-token",   post(auth::do_refresh_token))
        .route("/access-token",    get(auth::get_access_token))
        .route("/protected-route", get(auth::protected_route))
        .layer(general_rate_limit_layer(rl.general.clone()));

    Router::new()
        .nest("/api/v1/auth", auth_sensitive)
        .nest("/api/v1/auth", auth_general)
        .layer(cors)
        .with_state(state)
}