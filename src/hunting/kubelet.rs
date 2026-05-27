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

// ── KHV052 — Exposed read-only kubelet port ───────────────────────────────────

pub struct ReadOnlyKubeletPort;

#[async_trait]
impl Hunter for ReadOnlyKubeletPort {
    fn name(&self)          -> &'static str { "ReadOnlyKubeletPort" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletReadOnly }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletReadOnly { host, port } => (*host, *port),
            _ => return vec![],
        };

        let url = format!("http://{host}:{port}/pods");
        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            let pod_count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
            tracing::warn!("  [!] KHV052 read-only kubelet port at {}:{}", host, port);
            return vec![finding(
                "KHV052",
                "Exposed Read-Only Kubelet Port",
                "The kubelet read-only port (10255) is exposed and allows listing pods \
                 without authentication.",
                Severity::High,
                host, port,
                Some(format!("Listed {} pods via /pods endpoint", pod_count)),
            )];
        }
        vec![]
    }
}

// ── KHV053 — Anonymous access to secure kubelet port ─────────────────────────

pub struct SecureKubeletAnonymous;

#[async_trait]
impl Hunter for SecureKubeletAnonymous {
    fn name(&self)          -> &'static str { "SecureKubeletAnonymous" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };

        let url = format!("https://{host}:{port}/pods");
        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            let pod_count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
            tracing::warn!("  [!] KHV053 anonymous kubelet access at {}:{}", host, port);
            return vec![finding(
                "KHV053",
                "Anonymous Access to Kubelet",
                "The kubelet secure port allows anonymous access. An attacker can list \
                 pods, retrieve logs, and probe cluster state without credentials.",
                Severity::High,
                host, port,
                Some(format!("Listed {} pods anonymously", pod_count)),
            )];
        }
        vec![]
    }
}

// ── KHV054 — Anonymous RCE via kubelet /exec ──────────────────────────────────

pub struct KubeletAnonymousRce;

#[async_trait]
impl Hunter for KubeletAnonymousRce {
    fn name(&self)          -> &'static str { "KubeletAnonymousRce" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };

        // Check if /runningpods is accessible (implies anonymous auth is on)
        let url = format!("https://{host}:{port}/runningpods/");
        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if resp.status().is_success() {
            tracing::warn!("  [!] KHV054 kubelet anonymous RCE risk at {}:{}", host, port);
            return vec![finding(
                "KHV054",
                "Anonymous Access to Kubelet — RCE via /exec",
                "The kubelet allows anonymous access to /runningpods and likely /exec, \
                 enabling unauthenticated remote code execution in any container on this node.",
                Severity::Critical,
                host, port,
                Some(format!("GET /runningpods/ returned {}", resp.status())),
            )];
        }
        vec![]
    }
}
