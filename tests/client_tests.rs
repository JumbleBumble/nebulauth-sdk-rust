use mockito::{Matcher, Server};
use nebulauth_sdk::{
    AuthVerifyInput, NebulAuthClient, NebulAuthClientOptions, NebulAuthError, RedeemKeyInput,
    ReplayProtectionMode, ResetHwidInput, VerifyKeyInput,
};

#[tokio::test]
async fn verify_key_sends_bearer_hwid_and_body() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/api/v1/keys/verify")
        .match_header("authorization", "Bearer mk_at_test")
        .match_header("x-hwid", "HWID-1")
        .match_body(Matcher::JsonString(
            r#"{"key":"mk_live_test","requestId":"req-1"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"valid":true}"#)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let response = client
        .verify_key(VerifyKeyInput {
            key: "mk_live_test".to_string(),
            request_id: Some("req-1".to_string()),
            hwid: Some("HWID-1".to_string()),
            ..Default::default()
        })
        .await
        .expect("request should succeed");

    assert_eq!(response.status_code, 200);
    assert_eq!(response.data["valid"], true);
    mock.assert_async().await;
}

#[tokio::test]
async fn strict_replay_adds_signature_headers() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/api/v1/keys/verify")
        .match_header("authorization", "Bearer mk_at_test")
        .match_header("x-timestamp", Matcher::Regex(".+".to_string()))
        .match_header("x-nonce", Matcher::Regex(".+".to_string()))
        .match_header("x-signature", Matcher::Regex(".+".to_string()))
        .match_header("x-body-sha256", Matcher::Regex(".+".to_string()))
        .with_status(200)
        .with_body(r#"{"valid":true}"#)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: Some("mk_sig_test".to_string()),
        service_slug: None,
        replay_protection: ReplayProtectionMode::Strict,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    client
        .verify_key(VerifyKeyInput {
            key: "mk_live_test".to_string(),
            ..Default::default()
        })
        .await
        .expect("request should succeed");

    mock.assert_async().await;
}

#[tokio::test]
async fn pop_mode_requires_credentials() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/api/v1/keys/verify")
        .with_status(200)
        .with_body(r#"{"valid":true}"#)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let err = client
        .verify_key(VerifyKeyInput {
            key: "mk_live_test".to_string(),
            use_pop: true,
            ..Default::default()
        })
        .await
        .expect_err("missing pop credentials should error");

    assert!(matches!(err, NebulAuthError::Config(_)));
}

#[tokio::test]
async fn redeem_requires_service_slug() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/api/v1/keys/redeem")
        .with_status(200)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let err = client
        .redeem_key(RedeemKeyInput {
            key: "mk_live_test".to_string(),
            discord_id: "123".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("missing service slug should error");

    assert!(matches!(err, NebulAuthError::Config(_)));
}

#[tokio::test]
async fn reset_hwid_requires_discord_or_key() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/api/v1/keys/reset-hwid")
        .with_status(200)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let err = client
        .reset_hwid(ResetHwidInput::default())
        .await
        .expect_err("missing identifiers should error");

    assert!(matches!(err, NebulAuthError::Config(_)));
}

#[tokio::test]
async fn text_response_falls_back_to_error_field() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/api/v1/keys/verify")
        .with_status(400)
        .with_header("content-type", "text/plain")
        .with_body("something broke")
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let response = client
        .verify_key(VerifyKeyInput {
            key: "mk_live_test".to_string(),
            ..Default::default()
        })
        .await
        .expect("request should complete");

    assert!(!response.ok);
    assert_eq!(response.data["error"], "something broke");
    mock.assert_async().await;
}

#[tokio::test]
async fn auth_verify_hits_expected_endpoint() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/api/v1/auth/verify")
        .match_header("authorization", "Bearer mk_at_test")
        .with_status(200)
        .with_body(r#"{"valid":true}"#)
        .create_async()
        .await;

    let client = NebulAuthClient::new(NebulAuthClientOptions {
        base_url: format!("{}/api/v1", server.url()),
        bearer_token: Some("mk_at_test".to_string()),
        signing_secret: None,
        service_slug: None,
        replay_protection: ReplayProtectionMode::None,
        timeout_ms: 15_000,
    })
    .expect("client init should succeed");

    let response = client
        .auth_verify(AuthVerifyInput {
            key: "mk_live_test".to_string(),
            hwid: Some("HWID-1".to_string()),
            request_id: Some("req-bootstrap".to_string()),
        })
        .await
        .expect("request should complete");

    assert_eq!(response.data["valid"], true);
    mock.assert_async().await;
}
