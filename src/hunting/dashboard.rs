use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV029 — Kubernetes Dashboard exposed (probed through the API server proxy path).
pub struct KubeDashboard;

#[async_trait]
impl Hunter for KubeDashboard {
    fn name(&self)          -> &'static str { "KubeDashboard" }
    fn description(&self)   -> &'static str { "Detects the Kubernetes Dashboard exposed via the API-server proxy." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        let path = "/api/v1/namespaces/kubernetes-dashboard/services/\
                    https:kubernetes-dashboard:/proxy/";
        let url = format!("{scheme}://{host}:{port}{path}");

        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if body.contains("kubernetes-dashboard") || body.contains("Kubernetes Dashboard") {
                    tracing::warn!("  [!] KHV029 Kubernetes Dashboard exposed at {}:{}", host, port);
                    return vec![Output::Finding(Finding::khv(
                        "KHV029", self.name(), host, Some(port),
                        Some(format!("Dashboard reachable at {url}")),
                    ))];
                }
            }
        }
        vec![]
    }
}

/// KHV029 — Dashboard exposed directly on an open port (detected by service discovery).
pub struct DashboardExposed;

#[async_trait]
impl Hunter for DashboardExposed {
    fn name(&self)          -> &'static str { "KubeDashboard" }
    fn description(&self)   -> &'static str { "Reports a Kubernetes Dashboard exposed on a discovered port." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::Dashboard }

    async fn execute(&self, _ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::Dashboard { host, port } => (*host, *port),
            _ => return vec![],
        };
        tracing::warn!("  [!] KHV029 Kubernetes Dashboard exposed at {}:{}", host, port);
        vec![Output::Finding(Finding::khv(
            "KHV029", self.name(), host, Some(port),
            Some(format!("Dashboard reachable directly on port {port}")),
        ))]
    }
}

/// Active variant — confirms the Dashboard grants cluster control by listing pods
/// through its backend API.
pub struct DashboardActive;

#[async_trait]
impl Hunter for DashboardActive {
    fn name(&self)          -> &'static str { "DashboardActive" }
    fn description(&self)   -> &'static str { "Active: queries the Dashboard backend API to confirm cluster control." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        let path = "/api/v1/namespaces/kubernetes-dashboard/services/\
                    https:kubernetes-dashboard:/proxy/api/v1/pod";
        let url = format!("{scheme}://{host}:{port}{path}");
        if let Ok(r) = ctx.http_insecure.get(&url).send().await {
            if r.status().is_success() {
                let body = r.text().await.unwrap_or_default();
                if body.contains("\"pods\"") || body.contains("listMeta") {
                    tracing::warn!("  [!] KHV029 (active) Dashboard backend grants pod listing at {}:{}", host, port);
                    return vec![Output::Finding(
                        Finding::khv("KHV029", self.name(), host, Some(port),
                            Some("Dashboard backend API returned pod data without authentication".into()))
                            .with_description("The exposed Kubernetes Dashboard backend answered an authenticated-equivalent query (pod listing) anonymously, confirming attacker-usable cluster control.")
                    )];
                }
            }
        }
        vec![]
    }
}
