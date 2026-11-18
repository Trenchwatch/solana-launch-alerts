# solana-launch-alerts (Rust) · alpha

Rust SDK for the **[Solana Launch Alerts](https://github.com/Trenchwatch/solana-launch-alerts/blob/main/README.md)** open standard: verify signed launch-risk alert webhooks and parse alerts (spec version `2026-10`).

Same behaviour as the TypeScript and Python reference SDKs, checked against the same cross-language test vectors in [`examples/test-vectors.json`](https://github.com/Trenchwatch/solana-launch-alerts/blob/main/examples/test-vectors.json).

> **Status: alpha (`0.1.0-alpha.1`).** The API may still change before 1.0.

## Install

```bash
cargo add solana-launch-alerts@0.1.0-alpha.1
```

Minimum Rust version: 1.70. Dependencies: `hmac`, `sha2`, `hex`, `serde_json`. No `unsafe` code.

## Receive an alert

```rust
use solana_launch_alerts::{parse_alert, verify_request, VerifyOptions};

fn handle(headers: &[(String, String)], raw_body: &[u8], secret: &str) -> u16 {
    // Verify the RAW body first: the signature covers the exact bytes sent.
    let headers = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    if !verify_request(headers, raw_body, secret, &VerifyOptions::default()) {
        return 401;
    }
    let Ok(alert) = parse_alert(raw_body) else { return 400 };
    if !alert.sandbox && alert.is_known_type() {
        // your code; use alert.id to drop duplicates
    }
    200
}
```

With `http::HeaderMap` (axum, hyper, actix):

```rust
let pairs = headers.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")));
let ok = verify_request(pairs, &body, &secret, &VerifyOptions::default());
```

Another provider's headers? Set `VerifyOptions { provider: "Acme".into(), ..Default::default() }`.

## API

| Item | What it does |
| --- | --- |
| `sign(secret, timestamp, raw_body)` | Hex HMAC-SHA256 of `"<timestamp>.<raw body>"` (for providers and tests). |
| `verify_signature(secret, timestamp, raw_body, signature, &opts)` | Freshness check (300 s by default) and constant-time signature comparison. |
| `verify_request(headers, raw_body, secret, &opts)` | Same, reading `X-<Provider>-Timestamp` / `X-<Provider>-Signature` (case-insensitive). |
| `parse_alert(bytes)` / `parse_alert_value(json)` | Checks required fields and types; returns `Alert` or `InvalidAlert`. Unknown fields are kept in `alert.raw`; unknown type codes are accepted. |
| `Alert::is_known_type()` / `Alert::level_rank()` | Filter by known codes and by minimum evidence level (0 = `RELATED` … 3 = `CONFIRMED`). |

## Tests and example

From a clone of the [repository](https://github.com/Trenchwatch/solana-launch-alerts) (the tests read the shared vectors in `examples/`):

```bash
cd rust
cargo test                      # 16 tests, including the shared test vectors
cargo run --example receive     # sign and verify a synthetic alert
```

## Responsible use

Alerts are probabilistic observations from public on-chain data. They describe addresses and patterns, not people, and are not financial advice. Show them to users as context, not as accusations.

MIT licence · Maintained by EMERGE · [trenchwatch.dev](https://trenchwatch.dev)
