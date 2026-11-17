//! Cross-language tests: the same vectors and examples used by the TypeScript and Python SDKs.

use serde_json::{json, Value};
use solana_launch_alerts::*;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn vectors() -> Value {
    serde_json::from_str(&fs::read_to_string(root().join("examples/test-vectors.json")).unwrap()).unwrap()
}

fn secret_ts() -> (String, String) {
    let v = vectors();
    (v["secret"].as_str().unwrap().to_string(), v["timestamp"].as_str().unwrap().to_string())
}

fn opts_at(now: i64) -> VerifyOptions {
    VerifyOptions { now: Some(now), ..Default::default() }
}

fn now_ok() -> i64 {
    secret_ts().1.parse::<i64>().unwrap() + 10
}

fn cases() -> Vec<(String, String, String)> {
    vectors()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap().into(), c["body"].as_str().unwrap().into(), c["signature"].as_str().unwrap().into()))
        .collect()
}

fn examples() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(root().join("examples"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            n.ends_with(".json") && n.contains('_') && n.chars().next().unwrap().is_ascii_lowercase() && n != "test-vectors.json"
        })
        .collect();
    v.sort();
    assert!(!v.is_empty());
    v
}

fn example_value() -> Value {
    serde_json::from_slice(&fs::read(&examples()[0]).unwrap()).unwrap()
}

#[test]
fn vectors_sign() {
    let (secret, ts) = secret_ts();
    for (name, body, sig) in cases() {
        assert_eq!(sign(&secret, &ts, body.as_bytes()), sig, "case {name}");
    }
}

#[test]
fn vectors_verify() {
    let (secret, ts) = secret_ts();
    for (name, body, sig) in cases() {
        assert!(verify_signature(&secret, Some(&ts), body.as_bytes(), Some(&sig), &opts_at(now_ok())), "case {name}");
    }
}

#[test]
fn rejects_tampered_body() {
    let (secret, ts) = secret_ts();
    let (_, body, sig) = cases().remove(0);
    let tampered = format!("{body} ");
    assert!(!verify_signature(&secret, Some(&ts), tampered.as_bytes(), Some(&sig), &opts_at(now_ok())));
}

#[test]
fn rejects_wrong_secret() {
    let (_, ts) = secret_ts();
    let (_, body, sig) = cases().remove(0);
    assert!(!verify_signature("other", Some(&ts), body.as_bytes(), Some(&sig), &opts_at(now_ok())));
}

#[test]
fn rejects_stale_or_future_timestamp() {
    let (secret, ts) = secret_ts();
    let (_, body, sig) = cases().remove(0);
    let t: i64 = ts.parse().unwrap();
    for delta in [301, -301, 10_000] {
        assert!(!verify_signature(&secret, Some(&ts), body.as_bytes(), Some(&sig), &opts_at(t + delta)), "delta {delta}");
    }
    assert!(verify_signature(&secret, Some(&ts), body.as_bytes(), Some(&sig), &opts_at(t + 300)));
}

#[test]
fn rejects_missing_or_malformed() {
    let (secret, ts) = secret_ts();
    let o = opts_at(now_ok());
    assert!(!verify_signature(&secret, None, b"{}", Some("ab"), &o));
    assert!(!verify_signature(&secret, Some(&ts), b"{}", None, &o));
    assert!(!verify_signature(&secret, Some(&ts), b"{}", Some(""), &o));
    assert!(!verify_signature(&secret, Some("not-a-number"), b"{}", Some("ab"), &o));
    assert!(!verify_signature(&secret, Some(&ts), b"{}", Some("zz-not-hex"), &o));
    assert!(!verify_signature("", Some(&ts), b"{}", Some("ab"), &o));
}

#[test]
fn signature_is_case_insensitive() {
    let (secret, ts) = secret_ts();
    let (_, body, sig) = cases().remove(0);
    assert!(verify_signature(&secret, Some(&ts), body.as_bytes(), Some(&sig.to_uppercase()), &opts_at(now_ok())));
}

#[test]
fn verify_request_headers_any_case() {
    let (secret, ts) = secret_ts();
    let (_, body, sig) = cases().remove(2);
    let headers = [("x-trenchwatch-timestamp", ts.as_str()), ("X-TRENCHWATCH-SIGNATURE", sig.as_str())];
    assert!(verify_request(headers, body.as_bytes(), &secret, &opts_at(now_ok())));
}

#[test]
fn verify_request_other_provider() {
    let (secret, ts) = secret_ts();
    let (_, body, sig) = cases().remove(0);
    let headers = [("X-Acme-Timestamp", ts.as_str()), ("X-Acme-Signature", sig.as_str())];
    let acme = VerifyOptions { provider: "Acme".into(), now: Some(now_ok()), ..Default::default() };
    assert!(verify_request(headers, body.as_bytes(), &secret, &acme));
    assert!(!verify_request(headers, body.as_bytes(), &secret, &opts_at(now_ok())));
}

#[test]
fn examples_parse() {
    for path in examples() {
        let alert = parse_alert(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(alert.alert_type, path.file_stem().unwrap().to_string_lossy());
        assert!(alert.is_known_type());
        assert!(alert.sandbox);
        assert_eq!(alert.api_version, API_VERSION);
    }
}

#[test]
fn unknown_type_and_fields_are_accepted() {
    let mut d = example_value();
    d["type"] = json!("future_code");
    d["new_field"] = json!(1);
    let alert = parse_alert_value(d).unwrap();
    assert!(!alert.is_known_type());
    assert_eq!(alert.raw["new_field"], json!(1));
}

#[test]
fn invalid_alerts_are_rejected() {
    let mutations: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|d| { d.as_object_mut().unwrap().remove("id"); }),
        Box::new(|d| d["level"] = json!("HIGH")),
        Box::new(|d| d["sandbox"] = json!("yes")),
        Box::new(|d| d["operator"] = json!({})),
        Box::new(|d| d["evidence"] = json!(["x"])),
        Box::new(|d| d["token"] = json!(5)),
        Box::new(|d| d["id"] = json!("")),
        Box::new(|d| d["operator"]["address"] = json!(7)),
    ];
    for (i, m) in mutations.iter().enumerate() {
        let mut d = example_value();
        m(&mut d);
        assert!(parse_alert_value(d).is_err(), "mutation {i}");
    }
}

#[test]
fn bad_json_and_non_object_are_rejected() {
    assert!(parse_alert(b"{not json").is_err());
    assert!(parse_alert(b"[1,2]").is_err());
}

#[test]
fn level_rank_order() {
    let mut ranks = vec![];
    for level in LEVELS {
        let mut d = example_value();
        d["level"] = json!(level);
        let a = parse_alert_value(d).unwrap();
        assert_eq!(a.level.as_str(), level);
        ranks.push(a.level_rank());
    }
    assert_eq!(ranks, vec![0, 1, 2, 3]);
}

#[test]
fn known_types_listed_in_spec() {
    let spec = fs::read_to_string(root().join("SPEC.md")).unwrap();
    for t in KNOWN_TYPES {
        assert!(spec.contains(&format!("`{t}`")), "{t}");
    }
}

#[test]
fn sign_then_verify_roundtrip() {
    let body = br#"{"api_version":"2026-10","id":"RT-1"}"#;
    let ts = "1791770943";
    let sig = sign("s3cret", ts, body);
    assert!(verify_signature("s3cret", Some(ts), body, Some(&sig), &opts_at(1791770943)));
}
