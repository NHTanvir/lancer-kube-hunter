use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

/// KHV049 — Exposed kube-proxy / kubectl proxy
pub struct KubeProxyExposed;

#[async_trait]
impl Hunter for KubeProxyExposed {
    fn name(&self)          -> &'static str { "KubeProxyExposed" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeProxy }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeProxy { host, port } => (*host, *port),
            _ => return vec![],
        };

        let url = format!("http://{host}:{port}/api/v1");
        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("APIResourceList") {
                tracing::warn!("  [!] KHV049 exposed kube-proxy at {}:{}", host, port);
                return vec![Output::Finding(Finding {
                    id:          "KHV049".to_string(),
                    name:        "Exposed Kubernetes Proxy".to_string(),
                    description: "kubectl proxy or kube-proxy is exposed externally. \
                                  It forwards requests directly to the API server without \
                                  additional authentication.".to_string(),
                    severity:    Severity::High,
                    host:        host.to_string(),
                    port:        Some(port),
                    evidence:    Some(format!("GET /api/v1 returned APIResourceList")),
                    category:    "vulnerability".to_string(),
                })];
            }
        }
        vec![]
    }
}
