use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// Helper: GET a path on the discovered API server, optionally with the SA token.
async fn api_get(ctx: &HunterCtx, host: std::net::IpAddr, port: u16, tls: bool, path: &str) -> Option<reqwest::Response> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}{path}");
    let mut req = ctx.http_insecure.get(&url);
    if let Some(tok) = &ctx.sa_token {
        req = req.bearer_auth(tok);
    }
    req.send().await.ok()
}

// ── KHV005 — Anonymous access to API server (passive) ─────────────────────────

pub struct AnonymousApiAccess;

#[async_trait]
impl Hunter for AnonymousApiAccess {
    fn name(&self)          -> &'static str { "AnonymousApiAccess" }
    fn description(&self)   -> &'static str { "Probes the API server for anonymous access to /api/v1." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/api/v1").await {
            Some(r) => r,
            None => return vec![],
        };
        if !resp.status().is_success() {
            return vec![];
        }
        let json: Value = resp.json().await.unwrap_or_default();
        if json["kind"].as_str() == Some("APIResourceList") {
            tracing::warn!("  [!] KHV005 anonymous API access at {}:{}", host, port);
            return vec![Output::Finding(Finding::khv(
                "KHV005", self.name(), host, Some(port),
                Some("GET /api/v1 returned 200 with APIResourceList".into()),
            ))];
        }
        vec![]
    }
}

// ── KHV006 — Insecure HTTP API (plaintext / insecure port) ────────────────────

pub struct InsecureApiAccess;

#[async_trait]
impl Hunter for InsecureApiAccess {
    fn name(&self)          -> &'static str { "InsecureApiAccess" }
    fn description(&self)   -> &'static str { "Detects API server access over plaintext HTTP." }
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
            return vec![Output::Finding(Finding::khv(
                "KHV006", self.name(), host, Some(port),
                Some(format!("API server reachable over plaintext HTTP on port {port}")),
            ))];
        }
        vec![]
    }
}

// ── KHV007 — Specific access / RBAC info disclosure (passive) ─────────────────

pub struct ApiServerRbacInfo;

#[async_trait]
impl Hunter for ApiServerRbacInfo {
    fn name(&self)          -> &'static str { "ApiServerPassiveHunterFinished" }
    fn description(&self)   -> &'static str { "Enumerates namespaces/resources reachable anonymously." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/api/v1/namespaces").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("NamespaceList") {
                let ns_count = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV007 RBAC info disclosure: {} namespaces at {}:{}", ns_count, host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV007", self.name(), host, Some(port),
                    Some(format!("Listed {ns_count} namespaces anonymously")),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV001 — Information disclosure (/metrics) ────────────────────────────────

pub struct ApiServerInfoDisclosure;

#[async_trait]
impl Hunter for ApiServerInfoDisclosure {
    fn name(&self)          -> &'static str { "ApiServerInfoDisclosure" }
    fn description(&self)   -> &'static str { "Detects anonymously-readable /metrics on the API server." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/metrics").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("apiserver_") || body.contains("# TYPE") {
                tracing::warn!("  [!] KHV001 /metrics readable at {}:{}", host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV001", self.name(), host, Some(port),
                    Some("GET /metrics returned Prometheus metrics anonymously".into()),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV043 — Cluster health disclosure (/healthz) ─────────────────────────────

pub struct ClusterHealthDisclosure;

#[async_trait]
impl Hunter for ClusterHealthDisclosure {
    fn name(&self)          -> &'static str { "ClusterHealthDisclosure" }
    fn description(&self)   -> &'static str { "Detects anonymously-readable /healthz on the API server." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/healthz").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.trim() == "ok" || body.contains("ok") {
                tracing::warn!("  [!] KHV043 cluster health disclosure at {}:{}", host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV043", self.name(), host, Some(port),
                    Some("GET /healthz returned cluster health anonymously".into()),
                ))];
            }
        }
        vec![]
    }
}

// ── KHV002 — Kubernetes version disclosure ────────────────────────────────────

pub struct K8sVersionDisclosureProberOutside;

#[async_trait]
impl Hunter for K8sVersionDisclosureProberOutside {
    fn name(&self)          -> &'static str { "K8sVersionDisclosureProberOutside" }
    fn description(&self)   -> &'static str { "Reports disclosure of the Kubernetes version via /version." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::K8sVersion }

    async fn execute(&self, _ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, raw) = match event.as_ref() {
            Event::K8sVersion { host, port, raw, .. } => (*host, *port, raw.clone()),
            _ => return vec![],
        };
        tracing::warn!("  [!] KHV002 version disclosure {} at {}:{}", raw, host, port);
        vec![Output::Finding(Finding::khv(
            "KHV002", self.name(), host, Some(port),
            Some(format!("API server disclosed version: {raw}")),
        ))]
    }
}

// ── KHV005 (active) — Access to API server using the service-account token ────

pub struct AccessApiServerActive;

#[async_trait]
impl Hunter for AccessApiServerActive {
    fn name(&self)          -> &'static str { "AccessApiServerActive" }
    fn description(&self)   -> &'static str { "Uses the supplied/discovered SA token to probe authenticated API access." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        // Only meaningful when we hold a token to impersonate.
        if ctx.sa_token.is_none() {
            return vec![];
        }
        let resp = match api_get(&ctx, host, port, tls, "/api/v1/namespaces/default/pods").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("PodList") {
                let n = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV005 (active) token has pod-list access at {}:{}", host, port);
                return vec![Output::Finding(
                    Finding::khv("KHV005", self.name(), host, Some(port),
                        Some(format!("Service-account token authorized to list pods ({n} pods in default ns)")))
                        .with_description("The provided service-account token is authorized against the API server and can enumerate workloads — confirming over-permissive RBAC.")
                )];
            }
        }
        vec![]
    }
}

// ── ListPodsAndNamespaces — pod/namespace enumeration ────────────────────────

pub struct ListPodsAndNamespaces;

#[async_trait]
impl Hunter for ListPodsAndNamespaces {
    fn name(&self)          -> &'static str { "ListPodsAndNamespaces" }
    fn description(&self)   -> &'static str { "Lists pods across all namespaces anonymously or with the token." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let resp = match api_get(&ctx, host, port, tls, "/api/v1/pods").await {
            Some(r) => r,
            None => return vec![],
        };
        if resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or_default();
            if json["kind"].as_str() == Some("PodList") {
                let n = json["items"].as_array().map(|a| a.len()).unwrap_or(0);
                tracing::warn!("  [!] KHV007 pod enumeration: {} pods at {}:{}", n, host, port);
                return vec![Output::Finding(
                    Finding::khv("KHV007", self.name(), host, Some(port),
                        Some(format!("Listed {n} pods across all namespaces")))
                        .with_description("Cluster-wide pod listing is permitted without proper authorization, disclosing every workload in the cluster.")
                )];
            }
        }
        vec![]
    }
}

// ── CreateANamespace / DeleteANamespace (active) ──────────────────────────────

pub struct CreateANamespace;

#[async_trait]
impl Hunter for CreateANamespace {
    fn name(&self)          -> &'static str { "CreateANamespace" }
    fn description(&self)   -> &'static str { "Attempts to create (then delete) a namespace — proves write access." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        let ns = "kube-hunter-probe";
        let body = json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": ns }
        });
        let url = format!("{scheme}://{host}:{port}/api/v1/namespaces");
        let mut req = ctx.http_insecure.post(&url).json(&body);
        if let Some(tok) = &ctx.sa_token { req = req.bearer_auth(tok); }
        let resp = match req.send().await { Ok(r) => r, Err(_) => return vec![] };
        let created = resp.status().is_success();
        if created {
            // Clean up: delete the namespace we just created.
            let del = format!("{scheme}://{host}:{port}/api/v1/namespaces/{ns}");
            let mut dreq = ctx.http_insecure.delete(&del);
            if let Some(tok) = &ctx.sa_token { dreq = dreq.bearer_auth(tok); }
            let _ = dreq.send().await;
            tracing::warn!("  [!] KHV005 (active) namespace create succeeded at {}:{}", host, port);
            return vec![Output::Finding(
                Finding::khv("KHV005", self.name(), host, Some(port),
                    Some(format!("Created and deleted namespace '{ns}' (HTTP write access)")))
                    .with_description("The client can create cluster-scoped Namespace objects — full write access to the API server. The probe namespace was deleted afterwards.")
                    .with_severity(crate::types::Severity::Critical)
            )];
        }
        vec![]
    }
}

pub struct CreateAClusterRole;

#[async_trait]
impl Hunter for CreateAClusterRole {
    fn name(&self)          -> &'static str { "CreateAClusterRole" }
    fn description(&self)   -> &'static str { "Attempts to create (then delete) a ClusterRole — proves RBAC write access." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        let name = "kube-hunter-probe-role";
        let body = json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": { "name": name },
            "rules": [ { "apiGroups": [""], "resources": ["pods"], "verbs": ["get"] } ]
        });
        let url = format!("{scheme}://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles");
        let mut req = ctx.http_insecure.post(&url).json(&body);
        if let Some(tok) = &ctx.sa_token { req = req.bearer_auth(tok); }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                let del = format!("{scheme}://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}");
                let mut dreq = ctx.http_insecure.delete(&del);
                if let Some(tok) = &ctx.sa_token { dreq = dreq.bearer_auth(tok); }
                let _ = dreq.send().await;
                tracing::warn!("  [!] KHV026 (active) clusterrole create succeeded at {}:{}", host, port);
                return vec![Output::Finding(
                    Finding::khv("KHV026", self.name(), host, Some(port),
                        Some(format!("Created and deleted ClusterRole '{name}'")))
                        .with_description("The client can create cluster-scoped RBAC ClusterRole objects, enabling privilege escalation. The probe role was deleted afterwards.")
                )];
            }
        }
        vec![]
    }
}

// ── CreateARole — namespaced RBAC Role creation (active) ──────────────────────

pub struct CreateARole;

#[async_trait]
impl Hunter for CreateARole {
    fn name(&self)          -> &'static str { "CreateARole" }
    fn description(&self)   -> &'static str { "Attempts to create (then delete) a namespaced Role — proves RBAC write access." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        let name = "kube-hunter-probe-role";
        let body = json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": { "name": name, "namespace": "default" },
            "rules": [ { "apiGroups": [""], "resources": ["pods"], "verbs": ["get"] } ]
        });
        let url = format!("{scheme}://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles");
        let mut req = ctx.http_insecure.post(&url).json(&body);
        if let Some(tok) = &ctx.sa_token { req = req.bearer_auth(tok); }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                let del = format!("{scheme}://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/{name}");
                let mut dreq = ctx.http_insecure.delete(&del);
                if let Some(tok) = &ctx.sa_token { dreq = dreq.bearer_auth(tok); }
                let _ = dreq.send().await;
                tracing::warn!("  [!] KHV005 (active) namespaced role create succeeded at {}:{}", host, port);
                return vec![Output::Finding(
                    Finding::khv("KHV005", self.name(), host, Some(port),
                        Some(format!("Created and deleted namespaced Role '{name}' in default ns")))
                        .with_description("The client can create namespaced RBAC Role objects — write access to the API server. The probe role was deleted afterwards.")
                )];
            }
        }
        vec![]
    }
}

// ── DeleteANamespace — namespace delete authorization probe (active) ──────────

pub struct DeleteANamespace;

#[async_trait]
impl Hunter for DeleteANamespace {
    fn name(&self)          -> &'static str { "DeleteANamespace" }
    fn description(&self)   -> &'static str { "Non-destructively probes namespace DELETE authorization against a sentinel name." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };
        let scheme = if tls { "https" } else { "http" };
        // Delete a guaranteed-nonexistent namespace: a 404 (rather than 401/403)
        // proves the client is authorized to delete namespaces without destroying any.
        let url = format!("{scheme}://{host}:{port}/api/v1/namespaces/kube-hunter-nonexistent-probe");
        let mut req = ctx.http_insecure.delete(&url);
        if let Some(tok) = &ctx.sa_token { req = req.bearer_auth(tok); }
        if let Ok(resp) = req.send().await {
            let code = resp.status().as_u16();
            if code == 404 {
                tracing::warn!("  [!] KHV005 (active) namespace DELETE authorized at {}:{}", host, port);
                return vec![Output::Finding(
                    Finding::khv("KHV005", self.name(), host, Some(port),
                        Some("DELETE on a nonexistent namespace returned 404 (authorized to delete namespaces; none were removed)".into()))
                        .with_description("The client is authorized to delete cluster-scoped Namespace objects — destructive write access to the API server. No namespace was actually deleted.")
                        .with_severity(crate::types::Severity::Critical)
                )];
            }
        }
        vec![]
    }
}
