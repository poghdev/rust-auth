use serde::{Deserialize, Serialize};
use validator::Validate;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
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
    pub sub: String,
    pub exp: usize,
    pub token_type: String,
}