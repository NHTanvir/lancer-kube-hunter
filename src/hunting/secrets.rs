use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

async fn api_get(ctx: &HunterCtx, host: std::net::IpAddr, port: u16, tls: bool, path: &str) -> Option<reqwest::Response> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}{path}");
    let mut req = ctx.http_insecure.get(&url);
    if let Some(tok) = &ctx.sa_token { req = req.bearer_auth(tok); }
    req.send().await.ok()
}

// ── KHV050 — Access to all cluster secrets ────────────────────────────────────

pub struct ListAllSecrets;

#[async_trait]
impl Hunter for ListAllSecrets {
    fn name(&self)          -> &'static str { "ListAllSecrets" }
    fn description(&self)   -> &'static str { "Lists secrets across all namespaces (anonymously or via the token)." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/api/v1/secrets").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("SecretList") {
                let count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV050 {} secrets accessible at {}:{}", count, host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV050", self.name(), host, Some(port),
                    Some(format!("{count} secrets listed across all namespaces")),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV050 — Per-namespace secret access ──────────────────────────────────────

pub struct ListNamespacedSecrets;

#[async_trait]
impl Hunter for ListNamespacedSecrets {
    fn name(&self)          -> &'static str { "ListNamespacedSecrets" }
    fn description(&self)   -> &'static str { "Lists secrets in the default namespace (anonymously or via the token)." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/api/v1/namespaces/default/secrets").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("SecretList") {
                let count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                if count > 0 {
                    tracing::warn!("  [!] KHV050 {} secrets in default ns at {}:{}", count, host, port);
                    return vec![Output::Finding(Finding::khv(
                        "KHV050", self.name(), host, Some(port),
                        Some(format!("{count} secrets readable in the 'default' namespace")),
                    ))];
                }
            }
        }
        vec![]
    }
}

// ── KHV036 — Read access to the pod's service-account token ───────────────────

pub struct AccessPodServiceAccountToken;

#[async_trait]
impl Hunter for AccessPodServiceAccountToken {
    fn name(&self)          -> &'static str { "AccessPodServiceAccountToken" }
    fn description(&self)   -> &'static str { "Reads the mounted service-account token and validates its JWT shape." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let token = match std::fs::read_to_string(SA_TOKEN_PATH) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        // Validate JWT shape only (header.payload.signature) — never verify the signature.
        let parts = token.trim().split('.').count();
        let looks_jwt = parts == 3;
        tracing::info!("  [*] Service account token readable in-pod");
        vec![Output::Finding(Finding::khv(
            "KHV036", self.name(), "localhost", None,
            Some(format!(
                "Token readable at {SA_TOKEN_PATH} ({} bytes, {})",
                token.trim().len(),
                if looks_jwt { "valid JWT shape" } else { "non-JWT" },
            )),
        ))]
    }
}
