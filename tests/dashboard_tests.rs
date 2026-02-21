use mockito::{Matcher, Server};
use nebulauth_sdk::{
    DashboardAuth, DashboardRequestOptions, NebulAuthDashboardClient,
    NebulAuthDashboardClientOptions,
};

#[tokio::test]
async fn me_uses_bearer_token_header() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dashboard/me")
        .match_header("authorization", "Bearer mk_at_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"user-1"}"#)
        .create_async()
        .await;

    let client = NebulAuthDashboardClient::new(NebulAuthDashboardClientOptions {
        base_url: format!("{}/dashboard", server.url()),
        auth: Some(DashboardAuth::Bearer {
            bearer_token: "mk_at_test".to_string(),
        }),
        ..Default::default()
    })
    .expect("client init should succeed");

    let response = client
        .me(DashboardRequestOptions::default())
        .await
        .expect("request should succeed");

    assert!(response.ok);
    assert_eq!(response.data["id"], "user-1");
    mock.assert_async().await;
}

#[tokio::test]
async fn list_users_uses_session_cookie_header() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dashboard/users")
        .match_header("cookie", "mc_session=sess-123")
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let client = NebulAuthDashboardClient::new(NebulAuthDashboardClientOptions {
        base_url: format!("{}/dashboard", server.url()),
        auth: Some(DashboardAuth::Session {
            session_cookie: "sess-123".to_string(),
        }),
        ..Default::default()
    })
    .expect("client init should succeed");

    let _ = client
        .list_users(DashboardRequestOptions::default())
        .await
        .expect("request should succeed");

    mock.assert_async().await;
}

#[tokio::test]
async fn analytics_summary_sends_days_query() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dashboard/analytics/summary")
        .match_query(Matcher::UrlEncoded("days".to_string(), "30".to_string()))
        .with_status(200)
        .with_body(r#"{"totals":{}}"#)
        .create_async()
        .await;

    let client = NebulAuthDashboardClient::new(NebulAuthDashboardClientOptions {
        base_url: format!("{}/dashboard", server.url()),
        auth: Some(DashboardAuth::Bearer {
            bearer_token: "mk_at_test".to_string(),
        }),
        ..Default::default()
    })
    .expect("client init should succeed");

    let _ = client
        .analytics_summary(Some(30), DashboardRequestOptions::default())
        .await
        .expect("request should succeed");

    mock.assert_async().await;
}

#[tokio::test]
async fn bulk_create_keys_uses_format_query() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/dashboard/keys/batch")
        .match_query(Matcher::UrlEncoded("format".to_string(), "txt".to_string()))
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("key-1")
        .create_async()
        .await;

    let client = NebulAuthDashboardClient::new(NebulAuthDashboardClientOptions {
        base_url: format!("{}/dashboard", server.url()),
        auth: Some(DashboardAuth::Bearer {
            bearer_token: "mk_at_test".to_string(),
        }),
        ..Default::default()
    })
    .expect("client init should succeed");

    let _ = client
        .bulk_create_keys(
            nebulauth_sdk::KeyBatchCreateRequest {
                count: 1,
                label_prefix: Some("Promo".to_string()),
                duration_hours: None,
                key_only: Some(false),
                metadata: None,
            },
            "txt",
            DashboardRequestOptions::default(),
        )
        .await
        .expect("request should succeed");

    mock.assert_async().await;
}
