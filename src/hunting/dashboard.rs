use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

/// KHV029 — Kubernetes Dashboard exposed (probed through the API server proxy path)
pub struct KubeDashboard;

#[async_trait]
impl Hunter for KubeDashboard {
    fn name(&self)          -> &'static str { "KubeDashboard" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };

        let scheme = if tls { "https" } else { "http" };

        // Kubernetes Dashboard is accessible via the API server proxy
        let path = "/api/v1/namespaces/kubernetes-dashboard/services/\
                    https:kubernetes-dashboard:/proxy/";
        let url = format!("{scheme}://{host}:{port}{path}");

        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if body.contains("kubernetes-dashboard")
                    || body.contains("Kubernetes Dashboard")
                {
                    tracing::warn!("  [!] KHV029 Kubernetes Dashboard exposed at {}:{}", host, port);
                    return vec![Output::Finding(Finding {
                        id:          "KHV029".to_string(),
                        name:        "Kubernetes Dashboard Exposed".to_string(),
                        description: "The Kubernetes Dashboard is accessible via the API \
                                      server proxy without authentication. In older versions \
                                      it provides full unauthenticated cluster control."
                            .to_string(),
                        severity:    Severity::High,
                        host:        host.to_string(),
                        port:        Some(port),
                        evidence:    Some(format!("Dashboard accessible at {url}")),
                        category:    "vulnerability".to_string(),
                    })];
                }
            }
        }
        vec![]
    }
}
