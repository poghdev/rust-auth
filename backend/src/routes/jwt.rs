use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Claims;

pub const ACCESS_TTL:  u64 = 15 * 60;
pub const REFRESH_TTL: u64 = 7 * 24 * 3600;

#[derive(Debug)]
pub enum JwtError {
    TimeError,
    EncodingError,
    DecodingError,
}

fn now_secs() -> Result<u64, JwtError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| JwtError::TimeError)
}

pub fn make_access_token(username: &str, secret: &str) -> Result<String, JwtError> {
    make_jwt(username, ACCESS_TTL, "access", secret)
}

pub fn make_refresh_token(username: &str, secret: &str) -> Result<String, JwtError> {
    make_jwt(username, REFRESH_TTL, "refresh", secret)
}

fn make_jwt(username: &str, ttl: u64, token_type: &str, secret: &str) -> Result<String, JwtError> {
    let exp = (now_secs()? + ttl) as usize;
    let claims = Claims {
        sub:        username.to_string(),
        exp,
        token_type: token_type.to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| JwtError::EncodingError)
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, JwtError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|_| JwtError::DecodingError)
}