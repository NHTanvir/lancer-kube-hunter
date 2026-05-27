use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

// ── KHV050 — Anonymous access to pod secrets ─────────────────────────────────

pub struct ListAllSecrets;

#[async_trait]
impl Hunter for ListAllSecrets {
    fn name(&self)          -> &'static str { "ListAllSecrets" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };

        let scheme = if tls { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/api/v1/secrets");

        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("SecretList") {
                let count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV050 {} secrets accessible at {}:{}", count, host, port);
                return vec![Output::Finding(Finding {
                    id:          "KHV050".to_string(),
                    name:        "Access to Pod's Secrets".to_string(),
                    description: "Anonymous access to the API server allows listing all \
                                  cluster secrets, potentially exposing TLS certificates, \
                                  credentials, and service account tokens.".to_string(),
                    severity:    Severity::Critical,
                    host:        host.to_string(),
                    port:        Some(port),
                    evidence:    Some(format!("{} secrets listed anonymously", count)),
                    category:    "vulnerability".to_string(),
                })];
            }
        }
        vec![]
    }
}

// ── KHV036 — Service account token readable ───────────────────────────────────

pub struct ServiceAccountTokenExposed;

#[async_trait]
impl Hunter for ServiceAccountTokenExposed {
    fn name(&self)          -> &'static str { "ServiceAccountTokenExposed" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        // When running in-cluster, check if the SA token is world-readable
        match std::fs::metadata("/var/run/secrets/kubernetes.io/serviceaccount/token") {
            Ok(meta) => {
                // Check if the token file exists — it always does in a pod
                // The real check is whether the token has broad permissions (probed by other hunters)
                tracing::info!("  [*] Service account token found in-pod");
                vec![Output::Finding(Finding {
                    id:          "KHV036".to_string(),
                    name:        "Read Access to Pod's Service Account Token".to_string(),
                    description: "The pod has access to a service account token. If the \
                                  token has cluster-admin or broad RBAC permissions, it \
                                  can be used to access the API server.".to_string(),
                    severity:    Severity::Medium,
                    host:        "localhost".to_string(),
                    port:        None,
                    evidence:    Some(format!("Token file size: {} bytes", meta.len())),
                    category:    "vulnerability".to_string(),
                })]
            }
            Err(_) => vec![],
        }
    }
}
