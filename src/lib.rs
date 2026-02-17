use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;
const DEFAULT_BASE_URL: &str = "https://api.nebulauth.com/api/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayProtectionMode {
    None,
    Nonce,
    Strict,
}

#[derive(Debug, Clone)]
pub struct NebulAuthClientOptions {
    pub base_url: String,
    pub bearer_token: Option<String>,
    pub signing_secret: Option<String>,
    pub service_slug: Option<String>,
    pub replay_protection: ReplayProtectionMode,
    pub timeout_ms: u64,
}

impl Default for NebulAuthClientOptions {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            bearer_token: None,
            signing_secret: None,
            service_slug: None,
            replay_protection: ReplayProtectionMode::Strict,
            timeout_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NebulAuthResponse {
    pub status_code: u16,
    pub ok: bool,
    pub data: Value,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Error)]
pub enum NebulAuthError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("url parse failed: {0}")]
    Url(#[from] url::ParseError),
    #[error("crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, Default)]
pub struct PopAuthOptions {
    pub use_pop: bool,
    pub access_token: Option<String>,
    pub pop_key: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyKeyInput {
    pub key: String,
    pub request_id: Option<String>,
    pub hwid: Option<String>,
    pub use_pop: bool,
    pub access_token: Option<String>,
    pub pop_key: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthVerifyInput {
    pub key: String,
    pub hwid: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RedeemKeyInput {
    pub key: String,
    pub discord_id: String,
    pub service_slug: Option<String>,
    pub request_id: Option<String>,
    pub use_pop: bool,
    pub access_token: Option<String>,
    pub pop_key: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResetHwidInput {
    pub discord_id: Option<String>,
    pub key: Option<String>,
    pub request_id: Option<String>,
    pub use_pop: bool,
    pub access_token: Option<String>,
    pub pop_key: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GenericPostOptions {
    pub use_pop: bool,
    pub access_token: Option<String>,
    pub pop_key: Option<String>,
    pub extra_headers: HashMap<String, String>,
}

pub struct NebulAuthClient {
    options: NebulAuthClientOptions,
    client: reqwest::Client,
    base_url: String,
    base_path: String,
}

impl NebulAuthClient {
    pub fn new(mut options: NebulAuthClientOptions) -> Result<Self, NebulAuthError> {
        if options.base_url.trim().is_empty() {
            options.base_url = DEFAULT_BASE_URL.to_string();
        }

        let normalized = options.base_url.trim_end_matches('/').to_string();
        let parsed = Url::parse(&normalized)?;
        let base_path = parsed.path().trim_end_matches('/').to_string();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(options.timeout_ms))
            .build()?;

        Ok(Self {
            options,
            client,
            base_url: normalized,
            base_path,
        })
    }

    pub async fn verify_key(
        &self,
        input: VerifyKeyInput,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        let mut payload = json!({ "key": input.key });
        if let Some(request_id) = input.request_id {
            payload["requestId"] = Value::String(request_id);
        }

        let mut extra_headers = HashMap::new();
        if let Some(hwid) = input.hwid {
            extra_headers.insert("X-HWID".to_string(), hwid);
        }

        self.post_internal(
            "/keys/verify",
            &payload,
            GenericPostOptions {
                use_pop: input.use_pop,
                access_token: input.access_token,
                pop_key: input.pop_key,
                extra_headers,
            },
        )
        .await
    }

    pub async fn auth_verify(
        &self,
        input: AuthVerifyInput,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        let mut payload = json!({ "key": input.key });
        if let Some(hwid) = input.hwid {
            payload["hwid"] = Value::String(hwid);
        }
        if let Some(request_id) = input.request_id {
            payload["requestId"] = Value::String(request_id);
        }

        self.post_internal("/auth/verify", &payload, GenericPostOptions::default())
            .await
    }

    pub async fn redeem_key(
        &self,
        input: RedeemKeyInput,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        let slug = input
            .service_slug
            .or_else(|| self.options.service_slug.clone())
            .ok_or_else(|| {
                NebulAuthError::Config(
                    "service_slug is required either in client options or redeem_key input"
                        .to_string(),
                )
            })?;

        let mut payload = json!({
            "key": input.key,
            "discordId": input.discord_id,
            "serviceSlug": slug,
        });
        if let Some(request_id) = input.request_id {
            payload["requestId"] = Value::String(request_id);
        }

        self.post_internal(
            "/keys/redeem",
            &payload,
            GenericPostOptions {
                use_pop: input.use_pop,
                access_token: input.access_token,
                pop_key: input.pop_key,
                extra_headers: HashMap::new(),
            },
        )
        .await
    }

    pub async fn reset_hwid(
        &self,
        input: ResetHwidInput,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        if input.discord_id.is_none() && input.key.is_none() {
            return Err(NebulAuthError::Config(
                "reset_hwid requires at least discord_id or key".to_string(),
            ));
        }

        let mut payload = json!({});
        if let Some(discord_id) = input.discord_id {
            payload["discordId"] = Value::String(discord_id);
        }
        if let Some(key) = input.key {
            payload["key"] = Value::String(key);
        }
        if let Some(request_id) = input.request_id {
            payload["requestId"] = Value::String(request_id);
        }

        self.post_internal(
            "/keys/reset-hwid",
            &payload,
            GenericPostOptions {
                use_pop: input.use_pop,
                access_token: input.access_token,
                pop_key: input.pop_key,
                extra_headers: HashMap::new(),
            },
        )
        .await
    }

    pub async fn post<T: Serialize>(
        &self,
        endpoint: &str,
        payload: &T,
        options: GenericPostOptions,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        let payload_value = serde_json::to_value(payload)
            .map_err(|e| NebulAuthError::Config(format!("invalid payload serialization: {e}")))?;
        self.post_internal(endpoint, &payload_value, options).await
    }

    async fn post_internal(
        &self,
        endpoint: &str,
        payload: &Value,
        options: GenericPostOptions,
    ) -> Result<NebulAuthResponse, NebulAuthError> {
        let url = self.endpoint_url(endpoint)?;
        let body_string = serde_json::to_string(payload)
            .map_err(|e| NebulAuthError::Config(format!("failed to serialize payload: {e}")))?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let auth_headers = self.build_auth_headers(
            "POST",
            &url,
            &body_string,
            options.use_pop,
            options.access_token.as_deref(),
            options.pop_key.as_deref(),
        )?;

        for (key, value) in auth_headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                NebulAuthError::Config(format!("invalid auth header name '{key}': {e}"))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                NebulAuthError::Config(format!("invalid auth header value for '{key}': {e}"))
            })?;
            headers.insert(header_name, header_value);
        }

        for (key, value) in options.extra_headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                NebulAuthError::Config(format!("invalid extra header name '{key}': {e}"))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                NebulAuthError::Config(format!("invalid extra header value for '{key}': {e}"))
            })?;
            headers.insert(header_name, header_value);
        }

        let response = self
            .client
            .post(url)
            .headers(headers)
            .body(body_string)
            .send()
            .await?;

        let status = response.status();
        let mut response_headers = HashMap::new();
        for (key, value) in response.headers() {
            let value_string = match value.to_str() {
                Ok(v) => v.to_string(),
                Err(_) => String::new(),
            };
            response_headers.insert(key.to_string(), value_string);
        }

        let text = response.text().await?;
        let data = if text.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "error": text }))
        };

        Ok(NebulAuthResponse {
            status_code: status.as_u16(),
            ok: status.is_success(),
            data,
            headers: response_headers,
        })
    }

    fn build_auth_headers(
        &self,
        method: &str,
        url: &str,
        body_string: &str,
        use_pop: bool,
        access_token: Option<&str>,
        pop_key: Option<&str>,
    ) -> Result<HashMap<String, String>, NebulAuthError> {
        if use_pop {
            let token = access_token.ok_or_else(|| {
                NebulAuthError::Config("access_token is required when use_pop=true".to_string())
            })?;
            let key = pop_key.ok_or_else(|| {
                NebulAuthError::Config("pop_key is required when use_pop=true".to_string())
            })?;

            let mut headers = self.build_signing_headers(method, url, body_string, key)?;
            headers.insert("Authorization".to_string(), format!("Bearer {token}"));
            return Ok(headers);
        }

        let token = self.options.bearer_token.clone().ok_or_else(|| {
            NebulAuthError::Config("bearer_token is required for bearer mode".to_string())
        })?;

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {token}"));

        if self.options.replay_protection != ReplayProtectionMode::None {
            let signing_secret = self.options.signing_secret.clone().ok_or_else(|| {
                NebulAuthError::Config(
                    "signing_secret is required when replay_protection is nonce/strict".to_string(),
                )
            })?;

            let mut signing_headers =
                self.build_signing_headers(method, url, body_string, &signing_secret)?;
            if self.options.replay_protection == ReplayProtectionMode::Nonce {
                signing_headers.remove("X-Body-Sha256");
            }

            headers.extend(signing_headers);
        }

        Ok(headers)
    }

    fn build_signing_headers(
        &self,
        method: &str,
        url: &str,
        body_string: &str,
        secret: &str,
    ) -> Result<HashMap<String, String>, NebulAuthError> {
        let path = self.canonical_path(url)?;
        let timestamp = current_timestamp_ms().to_string();
        let nonce = random_nonce();
        let body_hash = sha256_hex(body_string);

        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}",
            method.to_uppercase(),
            path,
            timestamp,
            nonce,
            body_hash
        );

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| NebulAuthError::Crypto(format!("invalid signing secret: {e}")))?;
        mac.update(canonical.as_bytes());
        let signature = hex_lower(&mac.finalize().into_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Timestamp".to_string(), timestamp);
        headers.insert("X-Nonce".to_string(), nonce);
        headers.insert("X-Signature".to_string(), signature);
        headers.insert("X-Body-Sha256".to_string(), body_hash);
        Ok(headers)
    }

    fn canonical_path(&self, url: &str) -> Result<String, NebulAuthError> {
        let target = Url::parse(url)?;
        let mut path = target.path().to_string();

        if !self.base_path.is_empty() && path.starts_with(&self.base_path) {
            path = path[self.base_path.len()..].to_string();
            if path.is_empty() {
                path = "/".to_string();
            }
        }

        if !path.starts_with('/') {
            path = format!("/{path}");
        }

        Ok(path)
    }

    fn endpoint_url(&self, endpoint: &str) -> Result<String, NebulAuthError> {
        let base = Url::parse(&(self.base_url.clone() + "/"))?;
        let full = base.join(endpoint.trim_start_matches('/'))?;
        Ok(full.to_string())
    }
}

fn current_timestamp_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(nibble_to_hex((byte >> 4) & 0x0f));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}
