use nebulauth_sdk::{NebulAuthClient, NebulAuthClientOptions, ReplayProtectionMode, VerifyKeyInput};

const DEFAULT_BASE_URL: &str = "https://api.nebulauth.com/api/v1";

#[tokio::test]
async fn verify_key_live_env_gated() {
    if std::env::var("NEBULAUTH_LIVE_TEST").ok().as_deref() != Some("1") {
        eprintln!("Skipping live test: set NEBULAUTH_LIVE_TEST=1 to enable");
        return;
    }

    let base_url = std::env::var("NEBULAUTH_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    let bearer_token = match std::env::var("NEBULAUTH_BEARER_TOKEN") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("Skipping live test: missing NEBULAUTH_BEARER_TOKEN");
            return;
        }
    };

    let test_key = match std::env::var("NEBULAUTH_TEST_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("Skipping live test: missing NEBULAUTH_TEST_KEY");
            return;
        }
    };

    let signing_secret = std::env::var("NEBULAUTH_SIGNING_SECRET").ok();

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url,
        bearer_token: Some(bearer_token),
        signing_secret: signing_secret.clone(),
        service_slug: None,
        replay_protection: if signing_secret.is_some() {
            ReplayProtectionMode::Strict
        } else {
            ReplayProtectionMode::None
        },
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let response = client
        .verify_key(VerifyKeyInput {
            key: test_key,
            request_id: Some(format!(
                "live-rust-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or_default()
            )),
            hwid: std::env::var("NEBULAUTH_TEST_HWID").ok(),
            ..Default::default()
        })
        .await
        .expect("live request should complete");

    assert!(response.data.is_object());
    assert!(response.data.get("valid").is_some());
}
