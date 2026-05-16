use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum::http::header::{HeaderMap, SET_COOKIE, COOKIE};
use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode};
use validator::Validate;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{AppState, AuthRequest, AuthResponse, Claims};

const ACCESS_TOKEN_TTL:  u64 = 15 * 60;
const REFRESH_TOKEN_TTL: u64 = 7 * 24 * 3600;

pub fn extract_claims(headers: &HeaderMap, cookie_name: &str, secret: &str) -> Result<Claims, StatusCode> {
    let cookie_header = headers
        .get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = cookie_header
        .split(';')
        .find(|s| s.trim().starts_with(&format!("{}=", cookie_name)))
        .and_then(|s| s.trim().splitn(2, '=').nth(1))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(token_data.claims)
}

fn make_token(username: &str, ttl_secs: u64, token_type: &str, secret: &str) -> Result<String, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();

    let claims = Claims {
        sub: username.to_string(),
        exp: (now + ttl_secs) as usize,
        token_type: token_type.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn make_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        name, value, max_age
    )
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        payload.username,
        password_hash
    )
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok((StatusCode::CREATED, "User registered"))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let row = sqlx::query!(
        "SELECT password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    let parsed_hash = PasswordHash::new(&row.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let access_token  = make_token(&payload.username, ACCESS_TOKEN_TTL,  "access",  &state.jwt_secret)?;
    let refresh_token = make_token(&payload.username, REFRESH_TOKEN_TTL, "refresh", &state.jwt_secret)?;

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, make_cookie("access_token",  &access_token,  ACCESS_TOKEN_TTL) .parse().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    headers.append(SET_COOKIE, make_cookie("refresh_token", &refresh_token, REFRESH_TOKEN_TTL).parse().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);

    Ok((headers, Json(AuthResponse { message: "Login successful".into() })))
}

pub async fn access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let claims = extract_claims(&headers, "access_token", &state.jwt_secret)?;

    if claims.token_type != "access" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Json(serde_json::json!({ "username": claims.sub })))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let claims = extract_claims(&headers, "refresh_token", &state.jwt_secret)?;

    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        claims.sub
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(false);

    if !exists {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_access_token = make_token(&claims.sub, ACCESS_TOKEN_TTL, "access", &state.jwt_secret)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        make_cookie("access_token", &new_access_token, ACCESS_TOKEN_TTL)
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    Ok((headers, Json(AuthResponse { message: "Token refreshed".into() })))
}

pub async fn protected_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(claims) = extract_claims(&headers, "access_token", &state.jwt_secret) {
        if claims.token_type == "access" {
            return Ok((
                HeaderMap::new(),
                Json(serde_json::json!({
                    "authorized": true,
                    "username": claims.sub,
                    "token_refreshed": false
                })),
            ));
        }
    }

    let refresh_claims = extract_claims(&headers, "refresh_token", &state.jwt_secret)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if refresh_claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        refresh_claims.sub
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(false);

    if !exists {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_access_token = make_token(&refresh_claims.sub, ACCESS_TOKEN_TTL, "access", &state.jwt_secret)?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        SET_COOKIE,
        make_cookie("access_token", &new_access_token, ACCESS_TOKEN_TTL)
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    Ok((
        response_headers,
        Json(serde_json::json!({
            "authorized": true,
            "username": refresh_claims.sub,
            "token_refreshed": true
        })),
    ))
}