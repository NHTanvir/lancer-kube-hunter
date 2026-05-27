use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

fn finding(
    id: &str, name: &str, desc: &str, severity: Severity,
    host: std::net::IpAddr, port: u16, evidence: Option<String>,
) -> Output {
    Output::Finding(Finding {
        id:          id.to_string(),
        name:        name.to_string(),
        description: desc.to_string(),
        severity,
        host:        host.to_string(),
        port:        Some(port),
        evidence,
        category:    "vulnerability".to_string(),
    })
}

// ── KHV005 / KHV044 — Anonymous access to API server ─────────────────────────

pub struct AnonymousApiAccess;

#[async_trait]
impl Hunter for AnonymousApiAccess {
    fn name(&self)          -> &'static str { "AnonymousApiAccess" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };

        let scheme = if tls { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/api/v1");

        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if !resp.status().is_success() {
            return vec![];
        }

        let json: Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => return vec![],
        };

        if json["kind"].as_str() == Some("APIResourceList") {
            tracing::warn!("  [!] KHV005 anonymous API access at {}:{}", host, port);
            return vec![finding(
                "KHV005",
                "Access to API server via anonymous auth",
                "The Kubernetes API server allows anonymous access. An attacker \
                 can enumerate API resources, pods, and namespaces without credentials.",
                Severity::High,
                host, port,
                Some(format!("GET {} returned 200 with APIResourceList", url)),
            )];
        }
        vec![]
    }
}

// ── KHV006 — Insecure HTTP API (port 8080) ────────────────────────────────────

pub struct InsecureApiAccess;

#[async_trait]
impl Hunter for InsecureApiAccess {
    fn name(&self)          -> &'static str { "InsecureApiAccess" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    fn predicate(&self, event: &Event) -> bool {
        matches!(event, Event::ApiServer { tls: false, .. })
    }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::ApiServer { host, port, tls: false } => (*host, *port),
            _ => return vec![],
        };

        let url = format!("http://{host}:{port}/version");
        if ctx.http_insecure.get(&url).send().await.is_ok() {
            tracing::warn!("  [!] KHV006 insecure HTTP API at {}:{}", host, port);
            return vec![finding(
                "KHV006",
                "Insecure access to API server via HTTP",
                "The Kubernetes API server is accessible over plain HTTP. \
                 Traffic can be intercepted and requests are unauthenticated.",
                Severity::High,
                host, port, None,
            )];
        }
        vec![]
    }
}

// ── KHV007 — RBAC info disclosure ─────────────────────────────────────────────

pub struct ApiServerRbacInfo;

#[async_trait]
impl Hunter for ApiServerRbacInfo {
    fn name(&self)          -> &'static str { "ApiServerRbacInfo" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };

        let scheme = if tls { "https" } else { "http" };

        // Try to list namespaces anonymously
        let url = format!("{scheme}://{host}:{port}/api/v1/namespaces");
        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            let json: Value = match resp.json().await {
                Ok(j) => j,
                Err(_) => return vec![],
            };
            if json["kind"].as_str() == Some("NamespaceList") {
                let ns_count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV007 RBAC info disclosure: {} namespaces at {}:{}", ns_count, host, port);
                return vec![finding(
                    "KHV007",
                    "K8s API information disclosure via RBAC",
                    "Anonymous access reveals cluster namespaces and resource metadata \
                     through the API server.",
                    Severity::Medium,
                    host, port,
                    Some(format!("Listed {} namespaces anonymously", ns_count)),
                )];
            }
        }
        vec![]
    }
}
