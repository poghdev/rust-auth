use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use validator::Validate;

use crate::models::{AppState, AuthRequest, AuthResponse};
use crate::routes::cookies::{append_cookie, cookie_clear, cookie_set, get_cookie};
use crate::routes::extractor::AuthenticatedUser;
use crate::routes::jwt::{
    make_access_token, make_refresh_token, verify_jwt,
    ACCESS_TTL, REFRESH_TTL, JwtError,
};

fn sha256(input: &str) -> String {
    format!("{:x}", Sha256::new().chain_update(input).finalize())
}

fn jwt_err_to_status(e: JwtError) -> StatusCode {
    match e {
        JwtError::TimeError => {
            tracing::error!("System clock error when creating JWT");
            StatusCode::INTERNAL_SERVER_ERROR
        }
        JwtError::EncodingError => {
            tracing::error!("JWT encoding failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
        JwtError::DecodingError => {
            tracing::warn!("JWT decoding failed (invalid or expired token)");
            StatusCode::UNAUTHORIZED
        }
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| {
            tracing::error!("Argon2 hashing failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        payload.username,
        hash,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505") {
                return StatusCode::CONFLICT;
            }
        }
        tracing::error!("DB error on register: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let row = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username = $1",
        payload.username,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error on login lookup: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let hash_to_check = row
        .as_ref()
        .map(|r| r.password_hash.as_str())
        .unwrap_or(&state.dummy_hash);

    let parsed = PasswordHash::new(hash_to_check).map_err(|e| {
        tracing::error!("Failed to parse password hash: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let password_ok = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed)
        .is_ok();

    let user = match (row, password_ok) {
        (Some(u), true) => u,
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    let access_token  = make_access_token(&payload.username, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;
    let refresh_token = make_refresh_token(&payload.username, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;

    let token_hash = sha256(&refresh_token);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(REFRESH_TTL as i64);

    sqlx::query!("DELETE FROM refresh_tokens WHERE user_id = $1", user.id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting old refresh tokens: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user.id,
        token_hash,
        expires_at,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error inserting refresh token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut headers = HeaderMap::new();
    append_cookie(&mut headers, cookie_set("access_token",  &access_token,  ACCESS_TTL))?;
    append_cookie(&mut headers, cookie_set("refresh_token", &refresh_token, REFRESH_TTL))?;

    Ok((headers, Json(AuthResponse { message: "Login successful".into() })))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(raw) = get_cookie(&headers, "refresh_token") {
        let token_hash = sha256(&raw);
        if let Err(e) = sqlx::query!(
            "DELETE FROM refresh_tokens WHERE token_hash = $1",
            token_hash,
        )
        .execute(&state.pool)
        .await
        {
            tracing::warn!("DB error during logout (non-fatal): {}", e);
        }
    }

    let mut resp = HeaderMap::new();
    append_cookie(&mut resp, cookie_clear("access_token"))?;
    append_cookie(&mut resp, cookie_clear("refresh_token"))?;

    Ok((resp, Json(AuthResponse { message: "Logged out".into() })))
}

// Rotation: старый refresh токен уничтожается атомарно, выдаётся новый access + refresh.
// Frontend вызывает этот endpoint каждые 14 минут чтобы не дать access_token истечь.
pub async fn do_refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let raw = get_cookie(&headers, "refresh_token").ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = verify_jwt(&raw, &state.jwt_secret).map_err(jwt_err_to_status)?;
    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_hash = sha256(&raw);

    let row = sqlx::query!(
        "DELETE FROM refresh_tokens
         WHERE token_hash = $1 AND expires_at > NOW()
         RETURNING user_id",
        token_hash,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error on refresh token delete: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    let new_access  = make_access_token(&claims.sub, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;
    let new_refresh = make_refresh_token(&claims.sub, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;

    let new_hash   = sha256(&new_refresh);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(REFRESH_TTL as i64);

    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        row.user_id,
        new_hash,
        expires_at,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error inserting new refresh token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut resp = HeaderMap::new();
    append_cookie(&mut resp, cookie_set("access_token",  &new_access,  ACCESS_TTL))?;
    append_cookie(&mut resp, cookie_set("refresh_token", &new_refresh, REFRESH_TTL))?;

    Ok((resp, Json(AuthResponse { message: "Token refreshed".into() })))
}

// Верифицирует access_token через глобальный AuthenticatedUser extractor.
// Возвращает username из payload.
pub async fn get_access_token(
    AuthenticatedUser(claims): AuthenticatedUser,
) -> impl IntoResponse {
    Json(serde_json::json!({ "username": claims.sub }))
}

// Проверяет авторизацию:
// 1. Если access_token валидный — сразу OK.
// 2. Если истёк — проверяет refresh_token в БД.
// 3. Если refresh валидный — выдаёт новый access_token (без rotation refresh).
//    Для полного rotation пусть frontend вызывает /refresh-token явно.
pub async fn protected_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // Сначала пробуем access token
    if let Some(raw) = get_cookie(&headers, "access_token") {
        if let Ok(claims) = verify_jwt(&raw, &state.jwt_secret) {
            if claims.token_type == "access" {
                return Ok((
                    HeaderMap::new(),
                    Json(serde_json::json!({
                        "authorized": true,
                        "username":   claims.sub,
                        "refreshed":  false,
                    })),
                ));
            }
        }
    }

    // Access истёк — пробуем refresh token
    let raw_refresh = get_cookie(&headers, "refresh_token")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = verify_jwt(&raw_refresh, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;

    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_hash = sha256(&raw_refresh);

    // Проверяем что refresh токен живёт в БД и не истёк
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(
            SELECT 1 FROM refresh_tokens
            WHERE token_hash = $1 AND expires_at > NOW()
        )",
        token_hash,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error checking refresh token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(false);

    if !exists {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Выдаём новый access token. Refresh не трогаем — rotation только через /refresh-token.
    let new_access = make_access_token(&claims.sub, &state.jwt_secret)
        .map_err(jwt_err_to_status)?;

    let mut resp = HeaderMap::new();
    append_cookie(&mut resp, cookie_set("access_token", &new_access, ACCESS_TTL))?;

    Ok((
        resp,
        Json(serde_json::json!({
            "authorized": true,
            "username":   claims.sub,
            "refreshed":  true,
        })),
    ))
}