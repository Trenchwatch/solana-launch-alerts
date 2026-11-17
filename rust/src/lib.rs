//! # Solana Launch Alerts (Rust SDK, alpha)
//!
//! Verify signed launch-risk alert webhooks and parse alerts, as defined in the
//! [Solana Launch Alerts specification](https://github.com/Trenchwatch/solana-launch-alerts/blob/main/SPEC.md)
//! (version `2026-10`). Same behaviour as the TypeScript and Python reference SDKs,
//! checked against the same test vectors.
//!
//! ```no_run
//! use solana_launch_alerts::{verify_request, parse_alert, VerifyOptions};
//!
//! # fn handle(headers: &[(String, String)], raw_body: &[u8], secret: &str) -> u16 {
//! if !verify_request(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())), raw_body, secret, &VerifyOptions::default()) {
//!     return 401;
//! }
//! let alert = match parse_alert(raw_body) {
//!     Ok(a) => a,
//!     Err(_) => return 400,
//! };
//! if !alert.sandbox && alert.is_known_type() {
//!     // queue the alert for your own processing; use alert.id to drop duplicates
//! }
//! 200
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Version of the alert format implemented by this SDK.
pub const API_VERSION: &str = "2026-10";

/// Maximum distance, in seconds, between the signed timestamp and the current time.
pub const DEFAULT_TOLERANCE_S: u64 = 300;

/// Alert type codes known to this version of the SDK. New codes may appear and must be ignored if unknown.
pub const KNOWN_TYPES: [&str; 8] = [
    "operator_launch",
    "operator_cluster_buy",
    "coordinated_support",
    "linked_wallet_buy",
    "funding_batch",
    "linked_wallet",
    "profit_sweep",
    "exit_route",
];

/// Evidence levels, in increasing strength.
pub const LEVELS: [&str; 4] = ["RELATED", "COORDINATED", "SUSPECTED", "CONFIRMED"];

/// Options for signature verification.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Provider name used in the headers `X-<Provider>-Timestamp` / `X-<Provider>-Signature`.
    pub provider: String,
    /// Allowed clock distance in seconds (replay protection). Default: 300.
    pub tolerance_s: u64,
    /// Current Unix time in seconds; `None` uses the system clock. Useful for tests.
    pub now: Option<i64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { provider: "Trenchwatch".to_string(), tolerance_s: DEFAULT_TOLERANCE_S, now: None }
    }
}

/// Lowercase hex HMAC-SHA256 of `"<timestamp>.<raw body>"`. Used by providers, and by tests.
pub fn sign(secret: &str, timestamp: &str, raw_body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    hex::encode(mac.finalize().into_bytes())
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `true` only if the timestamp is fresh and the signature matches. The comparison runs in constant time.
pub fn verify_signature(
    secret: &str,
    timestamp: Option<&str>,
    raw_body: &[u8],
    signature: Option<&str>,
    opts: &VerifyOptions,
) -> bool {
    let (Some(timestamp), Some(signature)) = (timestamp, signature) else { return false };
    let (timestamp, signature) = (timestamp.trim(), signature.trim());
    if secret.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(ts) = timestamp.parse::<i64>() else { return false };
    let now = opts.now.unwrap_or_else(now_unix);
    if now.abs_diff(ts) > opts.tolerance_s {
        return false;
    }
    let Ok(received) = hex::decode(signature) else { return false };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    mac.verify_slice(&received).is_ok()
}

/// Verify a webhook request from its headers. Header names are matched case-insensitively.
///
/// `headers` is any iterator of `(name, value)` pairs, for example
/// `map.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))` for an `http::HeaderMap`.
pub fn verify_request<I, K, V>(headers: I, raw_body: &[u8], secret: &str, opts: &VerifyOptions) -> bool
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let ts_name = format!("x-{}-timestamp", opts.provider.to_ascii_lowercase());
    let sig_name = format!("x-{}-signature", opts.provider.to_ascii_lowercase());
    let (mut ts, mut sig) = (None, None);
    for (k, v) in headers {
        let k = k.as_ref().to_ascii_lowercase();
        if ts.is_none() && k == ts_name {
            ts = Some(v.as_ref().to_string());
        } else if sig.is_none() && k == sig_name {
            sig = Some(v.as_ref().to_string());
        }
    }
    verify_signature(secret, ts.as_deref(), raw_body, sig.as_deref(), opts)
}

/// The body is not a valid launch alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAlert(pub String);

impl fmt::Display for InvalidAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid alert: {}", self.0)
    }
}

impl std::error::Error for InvalidAlert {}

/// Evidence level of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// A transactional relationship was observed.
    Related,
    /// Coordinated technical or timing behaviour between linked wallets.
    Coordinated,
    /// Several independent signals point in the same direction.
    Suspected,
    /// Assigned only after external verification.
    Confirmed,
}

impl Level {
    /// Parse a level code (`"RELATED"`, `"COORDINATED"`, `"SUSPECTED"`, `"CONFIRMED"`).
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "RELATED" => Some(Self::Related),
            "COORDINATED" => Some(Self::Coordinated),
            "SUSPECTED" => Some(Self::Suspected),
            "CONFIRMED" => Some(Self::Confirmed),
            _ => None,
        }
    }
    /// The level code as written in the alert.
    pub fn as_str(&self) -> &'static str {
        LEVELS[self.rank() as usize]
    }
    /// 0 (RELATED) to 3 (CONFIRMED), for filtering by minimum strength.
    pub fn rank(&self) -> u8 {
        *self as u8
    }
}

/// The address group an alert refers to (field `operator` in v1; it identifies addresses, not a person).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// Provider's stable group id.
    pub id: String,
    /// Main address of the group, if any.
    pub address: Option<String>,
}

/// A parsed launch-risk alert.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    /// Version of the format, `"2026-10"` for v1.
    pub api_version: String,
    /// Unique alert id; retries keep the same id.
    pub id: String,
    /// Alert type code (field `type`).
    pub alert_type: String,
    /// Strength of the evidence.
    pub level: Level,
    /// UTC detection time.
    pub detected_at_utc: String,
    /// Token mint address, or `None`.
    pub token: Option<String>,
    /// Address group the alert refers to.
    pub operator: Operator,
    /// Human-readable summary.
    pub summary: String,
    /// On-chain facts behind the alert (each item a JSON object).
    pub evidence: Vec<Map<String, Value>>,
    /// Main transaction signature, if any.
    pub transaction: Option<String>,
    /// `true` for synthetic or test alerts. Never act on these in production.
    pub sandbox: bool,
    /// The full JSON object, including fields this SDK does not know.
    pub raw: Map<String, Value>,
}

impl Alert {
    /// `false` for codes added after this SDK version; ignore or log those.
    pub fn is_known_type(&self) -> bool {
        KNOWN_TYPES.contains(&self.alert_type.as_str())
    }
    /// 0 (RELATED) to 3 (CONFIRMED).
    pub fn level_rank(&self) -> u8 {
        self.level.rank()
    }
}

fn need<'a>(d: &'a Map<String, Value>, key: &str) -> Result<&'a Value, InvalidAlert> {
    d.get(key).ok_or_else(|| InvalidAlert(format!("missing field: {key}")))
}

fn need_str(d: &Map<String, Value>, key: &str) -> Result<String, InvalidAlert> {
    need(d, key)?.as_str().map(str::to_string).ok_or_else(|| InvalidAlert(format!("wrong type for field: {key}")))
}

fn need_opt_str(d: &Map<String, Value>, key: &str) -> Result<Option<String>, InvalidAlert> {
    match need(d, key)? {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        _ => Err(InvalidAlert(format!("wrong type for field: {key}"))),
    }
}

/// Parse and check an alert from raw JSON bytes. Unknown fields are kept in `raw`; unknown type codes are accepted.
pub fn parse_alert(body: &[u8]) -> Result<Alert, InvalidAlert> {
    let v: Value = serde_json::from_slice(body).map_err(|e| InvalidAlert(format!("body is not valid JSON: {e}")))?;
    parse_alert_value(v)
}

/// Parse and check an alert that is already a `serde_json::Value`.
pub fn parse_alert_value(v: Value) -> Result<Alert, InvalidAlert> {
    let Value::Object(d) = v else { return Err(InvalidAlert("alert must be a JSON object".into())) };

    let level_code = need_str(&d, "level")?;
    let level = Level::from_code(&level_code).ok_or_else(|| InvalidAlert(format!("unknown level: {level_code}")))?;

    let op = need(&d, "operator")?.as_object().ok_or_else(|| InvalidAlert("wrong type for field: operator".into()))?;
    let op_id = need_str(op, "id")?;
    let op_address = match op.get("address") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(InvalidAlert("wrong type for field: operator.address".into())),
    };

    let evidence_v = need(&d, "evidence")?.as_array().ok_or_else(|| InvalidAlert("wrong type for field: evidence".into()))?;
    let mut evidence = Vec::with_capacity(evidence_v.len());
    for item in evidence_v {
        match item {
            Value::Object(m) => evidence.push(m.clone()),
            _ => return Err(InvalidAlert("evidence items must be objects".into())),
        }
    }

    let id = need_str(&d, "id")?;
    let alert_type = need_str(&d, "type")?;
    if id.is_empty() {
        return Err(InvalidAlert("empty field: id".into()));
    }
    if alert_type.is_empty() {
        return Err(InvalidAlert("empty field: type".into()));
    }

    let sandbox = need(&d, "sandbox")?.as_bool().ok_or_else(|| InvalidAlert("wrong type for field: sandbox".into()))?;

    Ok(Alert {
        api_version: need_str(&d, "api_version")?,
        id,
        alert_type,
        level,
        detected_at_utc: need_str(&d, "detected_at_utc")?,
        token: need_opt_str(&d, "token")?,
        operator: Operator { id: op_id, address: op_address },
        summary: need_str(&d, "summary")?,
        evidence,
        transaction: need_opt_str(&d, "transaction")?,
        sandbox,
        raw: d,
    })
}
