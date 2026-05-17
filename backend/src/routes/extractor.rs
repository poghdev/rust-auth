use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use crate::models::{AppState, Claims};
use crate::routes::cookies::get_cookie_from_parts;
use crate::routes::jwt::verify_jwt;

pub struct AuthenticatedUser(pub Claims);

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw = get_cookie_from_parts(parts, "access_token")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let claims = verify_jwt(&raw, &state.jwt_secret).map_err(|e| {
            tracing::warn!("AuthenticatedUser extractor JWT error: {:?}", e);
            StatusCode::UNAUTHORIZED
        })?;

        if claims.token_type != "access" {
            return Err(StatusCode::UNAUTHORIZED);
        }

        Ok(AuthenticatedUser(claims))
    }
}