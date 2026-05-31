use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV049 — Exposed kubectl proxy / kube-proxy.
pub struct KubeProxy;

#[async_trait]
impl Hunter for KubeProxy {
    fn name(&self)          -> &'static str { "KubeProxy" }
    fn description(&self)   -> &'static str { "Detects an exposed kubectl proxy forwarding to the API server." }
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
                return vec![Output::Finding(Finding::khv(
                    "KHV049", self.name(), host, Some(port),
                    Some("GET /api/v1 via proxy returned APIResourceList".into()),
                ))];
            }
        }
        vec![]
    }
}
