use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use validator::Validate;

#[derive(Clone)]
pub struct AppState {
    pub pool:       PgPool,
    pub jwt_secret: String,
    pub dummy_hash: String,
}

impl AppState {
    pub fn from_env(pool: PgPool) -> Self {
        Self {
            pool,
            jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env"),
            dummy_hash: std::env::var("DUMMY_HASH").expect("DUMMY_HASH must be set in .env"),
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct AuthRequest {
    #[validate(length(min = 3, max = 10))]
    pub username: String,

    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub:        String,
    pub exp:        usize,
    pub token_type: String,
}