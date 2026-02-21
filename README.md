# NebulAuth Rust SDK Crate

Rust crate for NebulAuth runtime API.

## Structure

- `src/lib.rs` — SDK implementation
- `tests/client_tests.rs` — unit/contract tests (mock HTTP)
- `tests/live_tests.rs` — env-gated live integration test

## Add dependency

```toml
[dependencies]
nebulauth-sdk = "0.2.0"
```

## Quick start

```rust
use nebulauth_sdk::{NebulAuthClient, NebulAuthClientOptions, ReplayProtectionMode, VerifyKeyInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = NebulAuthClient::new(NebulAuthClientOptions {
        bearer_token: Some("mk_at_...".to_string()),
        signing_secret: Some("mk_sig_...".to_string()),
        service_slug: Some("your-service".to_string()),
        replay_protection: ReplayProtectionMode::Strict,
        timeout_ms: 15_000,
        ..Default::default()
    })?;

    let response = client
        .verify_key(VerifyKeyInput {
            key: "mk_live_...".to_string(),
            request_id: Some("req-123".to_string()),
            hwid: Some("WIN-DEVICE-12345".to_string()),
            ..Default::default()
        })
        .await?;

    println!("{} {}", response.status_code, response.data);
    Ok(())
}
```

## Run tests

```bash
cargo test
```

## Dashboard API usage

```rust
use nebulauth_sdk::{
    DashboardAuth,
    DashboardRequestOptions,
    NebulAuthDashboardClient,
    NebulAuthDashboardClientOptions,
};

let dashboard = NebulAuthDashboardClient::new(NebulAuthDashboardClientOptions {
    auth: Some(DashboardAuth::Bearer {
        bearer_token: "mk_at_...".to_string(),
    }),
    ..Default::default()
})?;

let me = dashboard.me(DashboardRequestOptions::default()).await?;
let users = dashboard.list_users(DashboardRequestOptions::default()).await?;
```

## Live test (optional)

```bash
set NEBULAUTH_LIVE_TEST=1
set NEBULAUTH_BEARER_TOKEN=mk_at_...
set NEBULAUTH_SIGNING_SECRET=mk_sig_...
set NEBULAUTH_TEST_KEY=mk_live_...
set NEBULAUTH_DASHBOARD_BEARER_TOKEN=mk_at_...

cargo test --test live_tests -- --nocapture
```

Live test env vars:

- Required to enable live tests:
    - `NEBULAUTH_LIVE_TEST=1`
- Required for runtime live tests:
    - `NEBULAUTH_BEARER_TOKEN`
    - `NEBULAUTH_TEST_KEY`
- Required for dashboard live test:
    - `NEBULAUTH_DASHBOARD_BEARER_TOKEN`
- Optional:
    - `NEBULAUTH_SIGNING_SECRET`
    - `NEBULAUTH_TEST_HWID`
