use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum::http::header::{HeaderMap, SET_COOKIE};
use jsonwebtoken::{EncodingKey, Header, encode};
use axum::http::header::COOKIE;
use sqlx::PgPool;
use validator::Validate;
use argon2::{password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},Argon2,};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

use crate::models::{AuthRequest, AuthResponse, Claims};

pub async fn register(State(pool): State<PgPool>, Json(payload): Json<AuthRequest>) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(payload.password.as_bytes(), &salt).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.to_string();

    sqlx::query!("INSERT INTO users (username, password_hash) VALUES ($1, $2)",payload.username,password_hash).execute(&pool).await.map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok((StatusCode::CREATED, "User registered"))
}

pub async fn login(State(pool): State<PgPool>, Json(payload): Json<AuthRequest>) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
    let row = sqlx::query!("SELECT password_hash FROM users WHERE username = $1", payload.username).fetch_optional(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::UNAUTHORIZED)?;

    let parsed_hash = PasswordHash::new(&row.password_hash).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let expiration = now.as_secs() + 3600;
    let claims = Claims { sub: payload.username, exp: expiration as usize };
    
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "temporary_dev_secret".to_string());
    
    let token = encode(&Header::default(),&claims,&EncodingKey::from_secret(secret.as_ref()),).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie_value = format!("jwt={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600",token);

    let mut headers = HeaderMap::new();
    let header_value = cookie_value.parse().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    headers.insert(SET_COOKIE, header_value);

    Ok((headers, Json(AuthResponse { message: "Success".into() })))
}

pub async fn get_token(headers: HeaderMap) -> Result<impl IntoResponse, StatusCode> {
    let cookie_header = headers.get(COOKIE).and_then(|h| h.to_str().ok()).ok_or(StatusCode:: UNAUTHORIZED)?;

    let token = cookie_header.split(';').find(|s| s.trim().starts_with("jwt=")).and_then(|s| s.split('=').nth(1)).ok_or(StatusCode::UNAUTHORIZED)?;
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "temporary_dev_secret".to_string());
    let token_data = jsonwebtoken::decode::<Claims>(token,&jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),&jsonwebtoken::Validation::default(),).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(serde_json::json!({ "username": token_data.claims.sub })))
}