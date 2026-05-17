use axum::http::{
    header::{COOKIE, SET_COOKIE},
    request::Parts,
    HeaderMap, StatusCode,
};

pub fn cookie_set(name: &str, value: &str, max_age: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        name, value, max_age
    )
}

pub fn cookie_clear(name: &str) -> String {
    format!("{}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0", name)
}

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    extract_cookie(
        headers.get(COOKIE).and_then(|h| h.to_str().ok()),
        name,
    )
}

pub fn get_cookie_from_parts(parts: &Parts, name: &str) -> Option<String> {
    extract_cookie(
        parts.headers.get(COOKIE).and_then(|h| h.to_str().ok()),
        name,
    )
}

fn extract_cookie(raw: Option<&str>, name: &str) -> Option<String> {
    raw.and_then(|raw| {
        raw.split(';')
            .find(|s| s.trim().starts_with(&format!("{}=", name)))
            .and_then(|s| s.trim().splitn(2, '=').nth(1))
            .map(|s| s.to_string())
    })
}

pub fn append_cookie(headers: &mut HeaderMap, cookie: String) -> Result<(), StatusCode> {
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok(())
}