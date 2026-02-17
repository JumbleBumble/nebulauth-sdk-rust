# NebulAuth Rust SDK Crate

Rust crate for NebulAuth runtime API.

## Structure

- `src/lib.rs` — SDK implementation
- `tests/client_tests.rs` — unit/contract tests (mock HTTP)
- `tests/live_tests.rs` — env-gated live integration test

## Add dependency

```toml
[dependencies]
nebulauth-sdk = "0.1.0"
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

## Live test (optional)

```bash
set NEBULAUTH_LIVE_TEST=1
set NEBULAUTH_BEARER_TOKEN=mk_at_...
set NEBULAUTH_SIGNING_SECRET=mk_sig_...
set NEBULAUTH_TEST_KEY=mk_live_...

cargo test --test live_tests -- --nocapture
```
