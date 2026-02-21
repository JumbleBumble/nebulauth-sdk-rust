use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

use crate::NebulAuthError;

const DEFAULT_DASHBOARD_BASE_URL: &str = "https://api.nebulauth.com/dashboard";

#[derive(Debug, Clone)]
pub enum DashboardAuth {
    Session { session_cookie: String },
    Bearer { bearer_token: String },
}

#[derive(Debug, Clone)]
pub struct NebulAuthDashboardClientOptions {
    pub base_url: String,
    pub auth: Option<DashboardAuth>,
    pub timeout_ms: u64,
}

impl Default for NebulAuthDashboardClientOptions {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_DASHBOARD_BASE_URL.to_string(),
            auth: None,
            timeout_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DashboardRequestOptions {
    pub auth: Option<DashboardAuth>,
    pub query: HashMap<String, String>,
    pub extra_headers: HashMap<String, String>,
}

impl Default for DashboardRequestOptions {
    fn default() -> Self {
        Self {
            auth: None,
            query: HashMap::new(),
            extra_headers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DashboardResponse {
    pub status_code: u16,
    pub ok: bool,
    pub data: Value,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CustomerUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_discord_redeem: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_hwid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TeamMemberCreateRequest {
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TeamMemberUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct KeyCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_hours: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyBatchCreateRequest {
    pub count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_hours: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct KeyUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_hours: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct KeyRevokeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RevokeSessionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_hwid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blacklist_discord: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminate_all_for_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminate_all_for_token: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RevokeAllSessionsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointStepInput {
    pub ad_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointCreateRequest {
    pub name: String,
    pub duration_hours: i64,
    pub is_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_domain_only: Option<bool>,
    pub steps: Vec<CheckpointStepInput>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CheckpointUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_hours: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_domain_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<CheckpointStepInput>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlacklistCreateRequest {
    pub r#type: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenCreateRequest {
    pub scopes: Vec<String>,
    pub replay_protection: String,
    pub auth_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApiTokenUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_protection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

pub struct NebulAuthDashboardClient {
    base_url: String,
    default_auth: Option<DashboardAuth>,
    client: reqwest::Client,
}

impl NebulAuthDashboardClient {
    pub fn new(options: NebulAuthDashboardClientOptions) -> Result<Self, NebulAuthError> {
        let base_url = if options.base_url.trim().is_empty() {
            DEFAULT_DASHBOARD_BASE_URL.to_string()
        } else {
            options.base_url.trim_end_matches('/').to_string()
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(options.timeout_ms))
            .build()?;

        Ok(Self {
            base_url,
            default_auth: options.auth,
            client,
        })
    }

    pub async fn login(
        &self,
        payload: LoginRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/auth/login",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn logout(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("POST", "/auth/logout", Some(json!({})), options)
            .await
    }

    pub async fn me(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/me", None, options).await
    }

    pub async fn get_customer(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/customer", None, options).await
    }

    pub async fn update_customer(
        &self,
        payload: CustomerUpdateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "PATCH",
            "/customer",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn create_user(
        &self,
        payload: TeamMemberCreateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/users",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn list_users(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/users", None, options).await
    }

    pub async fn update_user(
        &self,
        id: &str,
        payload: TeamMemberUpdateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "PATCH",
            &format!("/users/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn delete_user(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("DELETE", &format!("/users/{id}"), None, options)
            .await
    }

    pub async fn create_key(
        &self,
        payload: KeyCreateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/keys",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn bulk_create_keys(
        &self,
        payload: KeyBatchCreateRequest,
        format: &str,
        mut options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        options
            .query
            .insert("format".to_string(), format.to_string());
        self.request(
            "POST",
            "/keys/batch",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn extend_key_durations(
        &self,
        hours: i64,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/keys/extend-duration",
            Some(json!({ "hours": hours })),
            options,
        )
        .await
    }

    pub async fn get_key(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", &format!("/keys/{id}"), None, options)
            .await
    }

    pub async fn list_keys(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/keys", None, options).await
    }

    pub async fn update_key(
        &self,
        id: &str,
        payload: KeyUpdateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "PATCH",
            &format!("/keys/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn reset_key_hwid(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            &format!("/keys/{id}/reset-hwid"),
            Some(json!({})),
            options,
        )
        .await
    }

    pub async fn delete_key(
        &self,
        id: &str,
        payload: KeyRevokeRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "DELETE",
            &format!("/keys/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn list_key_sessions(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/key-sessions", None, options).await
    }

    pub async fn revoke_key_session(
        &self,
        id: &str,
        payload: RevokeSessionRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "DELETE",
            &format!("/key-sessions/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn revoke_all_key_sessions(
        &self,
        payload: RevokeAllSessionsRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/key-sessions/revoke-all",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn list_checkpoints(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/checkpoints", None, options).await
    }

    pub async fn get_checkpoint(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", &format!("/checkpoints/{id}"), None, options)
            .await
    }

    pub async fn create_checkpoint(
        &self,
        payload: CheckpointCreateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/checkpoints",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn update_checkpoint(
        &self,
        id: &str,
        payload: CheckpointUpdateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "PATCH",
            &format!("/checkpoints/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn delete_checkpoint(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("DELETE", &format!("/checkpoints/{id}"), None, options)
            .await
    }

    pub async fn list_blacklist(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/blacklist", None, options).await
    }

    pub async fn create_blacklist_entry(
        &self,
        payload: BlacklistCreateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/blacklist",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn delete_blacklist_entry(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("DELETE", &format!("/blacklist/{id}"), None, options)
            .await
    }

    pub async fn create_api_token(
        &self,
        payload: ApiTokenCreateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "POST",
            "/api-tokens",
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn update_api_token(
        &self,
        id: &str,
        payload: ApiTokenUpdateRequest,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request(
            "PATCH",
            &format!("/api-tokens/{id}"),
            Some(serde_json::to_value(payload).map_err(|e| NebulAuthError::Config(e.to_string()))?),
            options,
        )
        .await
    }

    pub async fn list_api_tokens(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/api-tokens", None, options).await
    }

    pub async fn delete_api_token(
        &self,
        id: &str,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("DELETE", &format!("/api-tokens/{id}"), None, options)
            .await
    }

    pub async fn analytics_summary(
        &self,
        days: Option<i64>,
        mut options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        if let Some(d) = days {
            options.query.insert("days".to_string(), d.to_string());
        }
        self.request("GET", "/analytics/summary", None, options)
            .await
    }

    pub async fn analytics_geo(
        &self,
        days: Option<i64>,
        mut options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        if let Some(d) = days {
            options.query.insert("days".to_string(), d.to_string());
        }
        self.request("GET", "/analytics/geo", None, options).await
    }

    pub async fn analytics_activity(
        &self,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        self.request("GET", "/analytics/activity", None, options)
            .await
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        options: DashboardRequestOptions,
    ) -> Result<DashboardResponse, NebulAuthError> {
        let endpoint = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };

        let mut url = reqwest::Url::parse(&format!("{}{}", self.base_url, endpoint))?;
        for (key, value) in options.query {
            url.query_pairs_mut().append_pair(&key, &value);
        }

        let mut headers = HeaderMap::new();
        for (key, value) in options.extra_headers {
            let header_name = HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| NebulAuthError::Config(format!("invalid header name '{key}': {e}")))?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                NebulAuthError::Config(format!("invalid header value for '{key}': {e}"))
            })?;
            headers.insert(header_name, header_value);
        }

        let auth = options.auth.or_else(|| self.default_auth.clone());
        if let Some(auth_mode) = auth {
            match auth_mode {
                DashboardAuth::Session { session_cookie } => {
                    let value = format!("mc_session={session_cookie}");
                    headers.insert(
                        HeaderName::from_static("cookie"),
                        HeaderValue::from_str(&value).map_err(|e| {
                            NebulAuthError::Config(format!("invalid cookie header: {e}"))
                        })?,
                    );
                }
                DashboardAuth::Bearer { bearer_token } => {
                    let value = format!("Bearer {bearer_token}");
                    headers.insert(
                        HeaderName::from_static("authorization"),
                        HeaderValue::from_str(&value).map_err(|e| {
                            NebulAuthError::Config(format!("invalid authorization header: {e}"))
                        })?,
                    );
                }
            }
        }

        let method_upper = method.to_uppercase();
        let request_method = match method_upper.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            _ => {
                return Err(NebulAuthError::Config(format!(
                    "unsupported dashboard method: {method}"
                )))
            }
        };

        let mut request = self.client.request(request_method, url).headers(headers);
        if let Some(payload) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(
                serde_json::to_string(&payload)
                    .map_err(|e| NebulAuthError::Config(e.to_string()))?,
            );
        }

        let response = request.send().await?;
        let status = response.status();

        let mut response_headers = HashMap::new();
        for (key, value) in response.headers() {
            response_headers.insert(
                key.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            );
        }

        let text = response.text().await?;
        let data = if text.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str::<Value>(&text).unwrap_or_else(|_| Value::String(text))
        };

        Ok(DashboardResponse {
            status_code: status.as_u16(),
            ok: status.is_success(),
            data,
            headers: response_headers,
        })
    }
}
