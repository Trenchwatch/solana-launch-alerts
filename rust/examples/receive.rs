//! Minimal example: verify a webhook and parse the alert, without any web framework.
//! Run with: cargo run --example receive

use solana_launch_alerts::{parse_alert, sign, verify_request, VerifyOptions};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let secret = "test_secret_do_not_use_in_production";
    let body = br#"{"api_version":"2026-10","id":"EX-0003","type":"operator_launch","level":"RELATED","detected_at_utc":"2026-10-15 01:00:00","token":null,"operator":{"id":"TW-9001","address":null},"summary":"Synthetic example.","evidence":[],"transaction":null,"sandbox":true}"#;

    // What a provider would send:
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    let headers = vec![
        ("X-Trenchwatch-Timestamp".to_string(), ts.clone()),
        ("X-Trenchwatch-Signature".to_string(), sign(secret, &ts, body)),
    ];

    // What a consumer does: verify the RAW body first, then parse.
    let ok = verify_request(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())), body, secret, &VerifyOptions::default());
    println!("signature valid: {ok}");
    if !ok {
        return;
    }
    let alert = parse_alert(body).expect("valid alert");
    println!("{} · {} · level {} · sandbox {}", alert.id, alert.alert_type, alert.level.as_str(), alert.sandbox);
}
