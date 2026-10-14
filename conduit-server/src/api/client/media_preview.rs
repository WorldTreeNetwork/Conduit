//! URL previews: `GET /_matrix/client/v1/media/preview_url` and the
//! deprecated `GET /_matrix/media/v3/preview_url` (both authenticated).
//!
//! The page is fetched through [`safe_fetch`] (SSRF denylist, size and time
//! limits, re-validated redirects). HTML is reduced to its OpenGraph `og:*`
//! properties (with `<title>` / `description` fallbacks); `og:image` is
//! fetched the same way and re-hosted in the media repository, replacing
//! the URL with an `mxc://` URI plus `matrix:image:size`. A URL that is
//! itself an image previews as that image. Results are cached per URL; one
//! row per fetch lets `ts` select the newest preview generated at or
//! before the requested time (the spec allows a newer one otherwise).
//!
//! Configuration (environment):
//! * `CONDUIT_URL_PREVIEW=0` disables the endpoints (`404 M_UNRECOGNIZED`).
//! * `CONDUIT_URL_PREVIEW_IP_ALLOWLIST` CIDRs exempt from the denylist.
//! * `CONDUIT_URL_PREVIEW_MAX_BYTES` page/image size cap (10 MiB).
//! * `CONDUIT_URL_PREVIEW_TIMEOUT_MS` per-fetch deadline (10 s).
//! * `CONDUIT_URL_PREVIEW_CACHE_MS` cache lifetime (1 h).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{TimeZone, Utc};
use regex::Regex;
use serde_json::{Map, Value};
use url::Url;

use conduit::storage::{MediaMetadata, UrlPreview};

use crate::api::client::media::{env_u64, matrix_error, MediaState};
use crate::api::client::safe_fetch::{self, FetchError, FetchPolicy};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

const MAX_OG_KEYS: usize = 64;
const MAX_VALUE_CHARS: usize = 1000;

pub fn allowlist_from_env() -> Vec<safe_fetch::Cidr> {
    std::env::var("CONDUIT_URL_PREVIEW_IP_ALLOWLIST")
        .map(|v| safe_fetch::parse_cidr_list(&v))
        .unwrap_or_default()
}

fn preview_enabled() -> bool {
    !matches!(
        std::env::var("CONDUIT_URL_PREVIEW").ok().as_deref().map(str::trim),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
}

fn preview_policy(max_bytes: u64) -> Arc<FetchPolicy> {
    Arc::new(FetchPolicy {
        allow: allowlist_from_env(),
        max_bytes: max_bytes.min(usize::MAX as u64) as usize,
        timeout: Duration::from_millis(env_u64("CONDUIT_URL_PREVIEW_TIMEOUT_MS", 10_000)),
        max_redirects: 5,
    })
}

fn fetch_error_response(e: FetchError) -> Response {
    match e {
        FetchError::InvalidUrl(m) => matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", m),
        FetchError::Blocked(m) => {
            tracing::info!(reason = %m, "URL preview refused by SSRF policy");
            MatrixError::forbidden("URL preview of this destination is not permitted").into_response()
        }
        FetchError::TooLarge => matrix_error(StatusCode::BAD_GATEWAY, "M_TOO_LARGE", "Previewed content is too large"),
        FetchError::TimedOut => matrix_error(StatusCode::GATEWAY_TIMEOUT, "M_UNKNOWN", "Timed out fetching URL"),
        FetchError::Upstream(m) => matrix_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", format!("Failed to fetch URL: {m}")),
    }
}

/// `GET /_matrix/client/v1/media/preview_url` and `/_matrix/media/v3/preview_url`.
pub async fn preview_url<S: MediaState + AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !preview_enabled() {
        return matrix_error(StatusCode::NOT_FOUND, "M_UNRECOGNIZED", "URL previews are disabled");
    }
    let Some(raw) = params.get("url") else {
        return matrix_error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "Missing url");
    };
    let mut url = match Url::parse(raw) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => u,
        _ => return matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "url must be an absolute http(s) URL"),
    };
    url.set_fragment(None);
    let key = url.to_string();
    let ts = match params.get("ts") {
        None => None,
        Some(v) => match v.parse::<i64>().ok().and_then(|ms| Utc.timestamp_millis_opt(ms).single()) {
            Some(t) => Some(t),
            None => return matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "ts must be a millisecond timestamp"),
        },
    };

    let storage = MediaState::storage(&state);
    if ts.is_some() {
        match storage.latest_url_preview(&key, ts).await {
            Ok(Some(p)) => return Json(p.og).into_response(),
            Ok(None) => {}
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }
    let now = Utc::now();
    match storage.latest_url_preview(&key, None).await {
        Ok(Some(p)) if p.expires_at > now => return Json(p.og).into_response(),
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let page_limit = env_u64("CONDUIT_URL_PREVIEW_MAX_BYTES", 10 * 1024 * 1024);
    let fetched = match safe_fetch::fetch(preview_policy(page_limit), &key).await {
        Ok(f) => f,
        Err(e) => return fetch_error_response(e),
    };
    let image_limit = page_limit.min(MediaState::max_upload_bytes(&state));
    let og = build_preview(&state, fetched, image_limit).await;

    let ttl = chrono::Duration::milliseconds(env_u64("CONDUIT_URL_PREVIEW_CACHE_MS", 3_600_000) as i64);
    let row = UrlPreview { url: key, fetched_at: now, expires_at: now + ttl, og: Value::Object(og.clone()) };
    if let Err(e) = storage.insert_url_preview(&row).await {
        tracing::warn!(error = %e, "failed to cache URL preview");
    }
    Json(Value::Object(og)).into_response()
}

fn base_type(content_type: Option<&str>) -> String {
    content_type
        .and_then(|c| c.split(';').next())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

async fn build_preview<S: MediaState>(state: &S, fetched: safe_fetch::Fetched, image_limit: u64) -> Map<String, Value> {
    let ct = base_type(fetched.content_type.as_deref());
    let looks_html = ct == "text/html"
        || ct == "application/xhtml+xml"
        || (ct.is_empty() && {
            let head = String::from_utf8_lossy(&fetched.body[..fetched.body.len().min(1024)]).to_ascii_lowercase();
            head.contains("<html") || head.contains("<!doctype html")
        });
    if ct.starts_with("image/") || (ct.is_empty() && infer::is_image(&fetched.body)) {
        let mut og = Map::new();
        if fetched.body.len() as u64 <= image_limit {
            if let Some(image) = rehost_image(state, &fetched.body, fetched.content_type.as_deref()).await {
                image.apply(&mut og);
            }
        }
        return og;
    }
    if !looks_html {
        return Map::new();
    }
    let html = String::from_utf8_lossy(&fetched.body);
    let mut og = parse_html_preview(&html, &fetched.final_url);
    if let Some(Value::String(image_url)) = og.remove("og:image") {
        let image = match safe_fetch::fetch(preview_policy(image_limit), &image_url).await {
            Ok(img) => rehost_image(state, &img.body, img.content_type.as_deref()).await,
            Err(e) => {
                tracing::debug!(error = %e, url = %image_url, "og:image fetch failed");
                None
            }
        };
        match image {
            Some(image) => image.apply(&mut og),
            None => og.retain(|k, _| !k.starts_with("og:image")),
        }
    }
    og
}

struct RehostedImage {
    mxc: String,
    content_type: String,
    size: usize,
    width: u32,
    height: u32,
}

impl RehostedImage {
    fn apply(self, og: &mut Map<String, Value>) {
        og.insert("og:image".into(), Value::String(self.mxc));
        og.insert("og:image:type".into(), Value::String(self.content_type));
        og.insert("og:image:width".into(), Value::from(self.width));
        og.insert("og:image:height".into(), Value::from(self.height));
        og.insert("matrix:image:size".into(), Value::from(self.size as u64));
    }
}

/// Store a fetched image as local media; None when it is not a decodable image.
async fn rehost_image<S: MediaState>(state: &S, bytes: &[u8], declared: Option<&str>) -> Option<RehostedImage> {
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let format = reader.format()?;
    let (width, height) = reader.into_dimensions().ok()?;
    let content_type = match base_type(declared) {
        t if t.starts_with("image/") => t,
        _ => format.to_mime_type().to_owned(),
    };
    let (sha256, storage_path, size) = state.blob_store().put(bytes).await.ok()?;
    let now = Utc::now();
    let media_id = {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut raw = [0u8; 18];
        rand::thread_rng().fill_bytes(&mut raw);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    };
    let meta = MediaMetadata {
        media_id: media_id.clone(),
        origin_server: state.server_name().to_owned(),
        uploader: None,
        content_type: Some(content_type.clone()),
        upload_name: None,
        file_size: size as i64,
        sha256,
        storage_path,
        uploaded_at: now,
        last_accessed: now,
    };
    state.storage().insert_media(&meta).await.ok()?;
    Some(RehostedImage {
        mxc: format!("mxc://{}/{media_id}", state.server_name()),
        content_type,
        size: size as usize,
        width,
        height,
    })
}

struct HtmlPatterns {
    strip: Regex,
    meta: Regex,
    attr: Regex,
    title: Regex,
}

fn patterns() -> &'static HtmlPatterns {
    static P: OnceLock<HtmlPatterns> = OnceLock::new();
    P.get_or_init(|| HtmlPatterns {
        strip: Regex::new(r"(?is)<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>").unwrap(),
        meta: Regex::new(r"(?is)<meta\b([^>]*)>").unwrap(),
        attr: Regex::new(r#"(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))"#).unwrap(),
        title: Regex::new(r"(?is)<title\b[^>]*>(.*?)</title\s*>").unwrap(),
    })
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[..rest.len().min(12)].find(';');
        let decoded = end.and_then(|end| {
            let name = &rest[1..end];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ if name.starts_with("#x") || name.starts_with("#X") => {
                    u32::from_str_radix(&name[2..], 16).ok().and_then(char::from_u32)
                }
                _ if name.starts_with('#') => name[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            ch.map(|c| (c, end + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn clean(s: &str) -> String {
    let decoded = decode_entities(s);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(MAX_VALUE_CHARS).collect()
}

/// Extract OpenGraph properties from an HTML document.
pub fn parse_html_preview(html: &str, base: &Url) -> Map<String, Value> {
    let p = patterns();
    let html = p.strip.replace_all(html, " ");
    let mut og = Map::new();
    let mut description = None;
    for m in p.meta.captures_iter(&html) {
        let mut attrs: HashMap<String, String> = HashMap::new();
        for a in p.attr.captures_iter(&m[1]) {
            let value = a.get(2).or(a.get(3)).or(a.get(4)).map_or("", |v| v.as_str());
            attrs.entry(a[1].to_ascii_lowercase()).or_insert_with(|| value.to_owned());
        }
        let Some(content) = attrs.get("content") else { continue };
        let key = attrs
            .get("property")
            .or_else(|| attrs.get("name"))
            .map(|k| k.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if key.starts_with("og:") {
            if og.len() < MAX_OG_KEYS && !og.contains_key(&key) {
                og.insert(key, Value::String(clean(content)));
            }
        } else if key == "description" && description.is_none() {
            description = Some(clean(content));
        }
    }
    if !og.contains_key("og:title") {
        if let Some(t) = p.title.captures(&html) {
            let title = clean(&t[1]);
            if !title.is_empty() {
                og.insert("og:title".into(), Value::String(title));
            }
        }
    }
    if !og.contains_key("og:description") {
        if let Some(d) = description.filter(|d| !d.is_empty()) {
            og.insert("og:description".into(), Value::String(d));
        }
    }
    // og:image must become an absolute http(s) URL (fetched later).
    let image = og
        .get("og:image")
        .or_else(|| og.get("og:image:url"))
        .or_else(|| og.get("og:image:secure_url"))
        .and_then(Value::as_str)
        .and_then(|v| base.join(v).ok())
        .filter(|u| matches!(u.scheme(), "http" | "https"));
    og.remove("og:image:url");
    og.remove("og:image:secure_url");
    match image {
        Some(u) => {
            og.insert("og:image".into(), Value::String(u.to_string()));
        }
        None => {
            og.retain(|k, _| !k.starts_with("og:image"));
        }
    }
    og
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_opengraph_with_fallbacks() {
        let html = r#"<!doctype html><html><head>
            <title>  Fallback   &amp; Title </title>
            <meta name="description" content="Plain description">
            <meta property="og:title" content="Matrix &quot;Blog&quot; Post &#x2014; &#169;">
            <meta content='Relative image' property='og:image:alt'>
            <meta property="og:image" content="/img/logo.png?x=1">
            <meta property="og:image" content="https://second.example/ignored.png">
            <meta property="og:type" content=website>
            <!-- <meta property="og:site_name" content="commented out"> -->
            <script>var s = '<meta property="og:url" content="https://evil">';</script>
            </head><body>hi</body></html>"#;
        let base = Url::parse("https://example.org/blog/post").unwrap();
        let og = parse_html_preview(html, &base);
        assert_eq!(og["og:title"], "Matrix \"Blog\" Post \u{2014} \u{a9}");
        assert_eq!(og["og:description"], "Plain description");
        assert_eq!(og["og:image"], "https://example.org/img/logo.png?x=1");
        assert_eq!(og["og:image:alt"], "Relative image");
        assert_eq!(og["og:type"], "website");
        assert!(!og.contains_key("og:site_name"));
        assert!(!og.contains_key("og:url"));
    }

    #[test]
    fn title_fallback_and_unsafe_image_scheme() {
        let html = "<html><head><title>Only a title</title><meta property=\"og:image\" content=\"javascript:alert(1)\"><meta property=\"og:image:width\" content=\"10\"></head></html>";
        let og = parse_html_preview(html, &Url::parse("http://h.example/").unwrap());
        assert_eq!(og["og:title"], "Only a title");
        assert!(!og.contains_key("og:image"));
        assert!(!og.contains_key("og:image:width"));
    }

    #[test]
    fn bounds_values_and_key_count() {
        let mut html = String::from("<head>");
        for i in 0..200 {
            html.push_str(&format!("<meta property=\"og:k{i}\" content=\"{}\">", "x".repeat(5000)));
        }
        let og = parse_html_preview(&html, &Url::parse("http://h.example/").unwrap());
        assert!(og.len() <= MAX_OG_KEYS + 1);
        assert!(og.values().all(|v| v.as_str().is_none_or(|s| s.chars().count() <= MAX_VALUE_CHARS)));
    }

    #[test]
    fn entity_decoding_is_conservative() {
        assert_eq!(decode_entities("a &amp; b &bogus; &#65;&#x42; &"), "a & b &bogus; AB &");
        assert_eq!(decode_entities("&#xD800;"), "&#xD800;");
    }
}
