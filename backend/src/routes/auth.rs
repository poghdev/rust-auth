use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize, 
}

pub async fn register(
    State(pool): State<PgPool>, 
    Json(payload): Json<AuthRequest>
) -> impl IntoResponse {
    let hashed_password = match hash(payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error hashing").into_response(),
    };

    let result = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        payload.username,
        hashed_password
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "User registered").into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "User already exists").into_response(),
    }
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    let user = sqlx::query!("SELECT password_hash FROM users WHERE username = $1", payload.username)
        .fetch_optional(&pool)
        .await;

    if let Ok(Some(row)) = user {
        if verify(payload.password, &row.password_hash).unwrap_or(false) {
            let expiration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600;

            let claims = Claims { sub: payload.username, exp: expiration as usize };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret("secret".as_ref()),
            ).unwrap();

            return (StatusCode::OK, Json(AuthResponse { token })).into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
}