use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

// ── KHV052 — Exposed read-only kubelet port (10255) ───────────────────────────

pub struct ReadOnlyKubeletPort;

#[async_trait]
impl Hunter for ReadOnlyKubeletPort {
    fn name(&self)          -> &'static str { "ReadOnlyKubeletPortHunter" }
    fn description(&self)   -> &'static str { "Lists pods via the unauthenticated read-only kubelet port." }
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
            return vec![Output::Finding(Finding::khv(
                "KHV052", self.name(), host, Some(port),
                Some(format!("Listed {pod_count} pods via /pods on the read-only port")),
            ))];
        }
        vec![]
    }
}

// ── Secure kubelet port handlers (10250, anonymous) ───────────────────────────
// Emits the handler-specific KHV ids: KHV038 (running pods), KHV051 (privileged
// containers), KHV045 (system logs), KHV046 (cmdline/spec), KHV037 (container logs).

pub struct KubeletHandlers;

#[async_trait]
impl Hunter for KubeletHandlers {
    fn name(&self)          -> &'static str { "KubeletHandlers" }
    fn description(&self)   -> &'static str { "Probes anonymous kubelet handlers: /pods /spec /metrics /logs." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };
        let base = format!("https://{host}:{port}");
        let mut out = vec![];

        // /pods → running pods (KHV038) + privileged container detection (KHV051)
        if let Ok(r) = ctx.http_insecure.get(format!("{base}/pods")).send().await {
            if r.status().is_success() {
                let json: Value = r.json().await.unwrap_or_default();
                let items = json["items"].as_array().cloned().unwrap_or_default();
                tracing::warn!("  [!] KHV038 running pods exposed at {}:{}", host, port);
                out.push(Output::Finding(Finding::khv(
                    "KHV038", self.name(), host, Some(port),
                    Some(format!("Anonymous /pods exposed {} pods", items.len())),
                )));
                let privileged = items.iter().filter(|p| pod_has_privileged(p)).count();
                if privileged > 0 {
                    tracing::warn!("  [!] KHV051 {} privileged containers at {}:{}", privileged, host, port);
                    out.push(Output::Finding(Finding::khv(
                        "KHV051", self.name(), host, Some(port),
                        Some(format!("{privileged} pod(s) run privileged/with dangerous capabilities")),
                    )));
                }
            }
        }

        // /logs/ → host system logs (KHV045)
        if let Ok(r) = ctx.http_insecure.get(format!("{base}/logs/")).send().await {
            if r.status().is_success() {
                tracing::warn!("  [!] KHV045 system logs exposed at {}:{}", host, port);
                out.push(Output::Finding(Finding::khv(
                    "KHV045", self.name(), host, Some(port),
                    Some("Anonymous /logs/ directory listing exposed".into()),
                )));
            }
        }

        // /spec → cmdline / node spec (KHV046)
        if let Ok(r) = ctx.http_insecure.get(format!("{base}/spec/")).send().await {
            if r.status().is_success() {
                tracing::warn!("  [!] KHV046 kubelet spec/cmdline exposed at {}:{}", host, port);
                out.push(Output::Finding(Finding::khv(
                    "KHV046", self.name(), host, Some(port),
                    Some("Anonymous /spec/ exposed node configuration".into()),
                )));
            }
        }

        // /metrics → information disclosure (KHV001)
        if let Ok(r) = ctx.http_insecure.get(format!("{base}/metrics")).send().await {
            if r.status().is_success() {
                tracing::warn!("  [!] KHV001 kubelet /metrics exposed at {}:{}", host, port);
                out.push(Output::Finding(Finding::khv(
                    "KHV001", self.name(), host, Some(port),
                    Some("Anonymous /metrics exposed kubelet metrics".into()),
                )));
            }
        }

        out
    }
}

/// True if a pod spec (from the kubelet /pods response) runs any privileged
/// container or requests dangerous capabilities.
fn pod_has_privileged(pod: &Value) -> bool {
    let containers = pod["spec"]["containers"].as_array();
    if let Some(cs) = containers {
        for c in cs {
            let sc = &c["securityContext"];
            if sc["privileged"].as_bool() == Some(true) {
                return true;
            }
            if let Some(adds) = sc["capabilities"]["add"].as_array() {
                for cap in adds {
                    if let Some(s) = cap.as_str() {
                        if s.eq_ignore_ascii_case("SYS_ADMIN") || s.eq_ignore_ascii_case("SYS_PTRACE") || s == "ALL" {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

// ── KHV037 — Exposed container logs ───────────────────────────────────────────

pub struct KubeletContainerLogs;

#[async_trait]
impl Hunter for KubeletContainerLogs {
    fn name(&self)          -> &'static str { "KubeletContainerLogs" }
    fn description(&self)   -> &'static str { "Detects anonymous access to kubelet /containerLogs." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };
        // The /containerLogs handler exists if it responds (even 400) rather than 401/403.
        let url = format!("https://{host}:{port}/containerLogs/default/probe/probe");
        if let Ok(r) = ctx.http_insecure.get(&url).send().await {
            let code = r.status().as_u16();
            if code != 401 && code != 403 {
                tracing::warn!("  [!] KHV037 container logs handler reachable at {}:{}", host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV037", self.name(), host, Some(port),
                    Some(format!("/containerLogs reachable anonymously (HTTP {code})")),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV046 — Exposed kubelet cmdline (/configz) ───────────────────────────────

pub struct KubeletExposedCmdline;

#[async_trait]
impl Hunter for KubeletExposedCmdline {
    fn name(&self)          -> &'static str { "KubeletExposedCmdline" }
    fn description(&self)   -> &'static str { "Detects anonymous access to kubelet /configz (effective config/cmdline)." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };
        let url = format!("https://{host}:{port}/configz");
        if let Ok(r) = ctx.http_insecure.get(&url).send().await {
            if r.status().is_success() {
                tracing::warn!("  [!] KHV046 kubelet /configz exposed at {}:{}", host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV046", self.name(), host, Some(port),
                    Some("Anonymous /configz exposed the kubelet's effective configuration".into()),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV054 + KHV039/040/041/042 — Debug handlers (active RCE) ──────────────────

pub struct KubeletDebugHandlers;

#[async_trait]
impl Hunter for KubeletDebugHandlers {
    fn name(&self)          -> &'static str { "KubeletDebugHandlers" }
    fn description(&self)   -> &'static str { "Active: probes kubelet /exec /run /attach /portForward for anonymous RCE." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::KubeletSecure }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::KubeletSecure { host, port } => (*host, *port),
            _ => return vec![],
        };
        let base = format!("https://{host}:{port}");

        // First confirm anonymous reachability via /runningpods.
        let reachable = match ctx.http_insecure.get(format!("{base}/runningpods/")).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => return vec![],
        };
        if !reachable {
            return vec![];
        }

        let mut out = vec![Output::Finding(Finding::khv(
            "KHV054", self.name(), host, Some(port),
            Some("Anonymous /runningpods reachable — kubelet debug handlers likely permit RCE".into()),
        ))];

        // Probe each debug handler; a non-401/403 response implies the handler
        // is reachable without auth.
        let handlers = [
            ("/exec/default/probe/probe",        "KHV039"),
            ("/run/default/probe/probe",         "KHV040"),
            ("/portForward/default/probe",       "KHV041"),
            ("/attach/default/probe/probe",      "KHV042"),
        ];
        for (path, vid) in handlers {
            if let Ok(r) = ctx.http_insecure.post(format!("{base}{path}")).send().await {
                let code = r.status().as_u16();
                if code != 401 && code != 403 {
                    tracing::warn!("  [!] {} kubelet {} reachable at {}:{}", vid, path, host, port);
                    out.push(Output::Finding(Finding::khv(
                        vid, self.name(), host, Some(port),
                        Some(format!("Handler {path} reachable anonymously (HTTP {code})")),
                    )));
                }
            }
        }
        out
    }
}
