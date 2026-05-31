use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV200 — Cluster-admin via `kubectl exec` on a master pod.
///
/// Active hunter: when an anonymous secure kubelet is found, inspect the running
/// pods for control-plane components (kube-apiserver / kube-controller-manager /
/// etcd) scheduled on the node. Exec'ing into such a pod yields the master's
/// credentials and therefore cluster-admin.
pub struct KubectlExecOnMaster;

#[async_trait]
impl Hunter for KubectlExecOnMaster {
    fn name(&self)          -> &'static str { "KubectlExecOnMaster" }
    fn description(&self)   -> &'static str { "Active: detects control-plane pods reachable via an anonymous kubelet." }
    fn mode(&self)          -> Mode         { Mode::Active }
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
        if !resp.status().is_success() {
            return vec![];
        }
        let json: Value = resp.json().await.unwrap_or_default();
        let items = json["items"].as_array().cloned().unwrap_or_default();

        const MASTER_MARKERS: &[&str] = &[
            "kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd",
        ];
        for pod in &items {
            let name = pod["metadata"]["name"].as_str().unwrap_or("");
            if MASTER_MARKERS.iter().any(|m| name.contains(m)) {
                tracing::warn!("  [!] KHV200 control-plane pod '{}' reachable via anonymous kubelet at {}:{}", name, host, port);
                return vec![Output::Finding(Finding::khv(
                    "KHV200", self.name(), host, Some(port),
                    Some(format!("Control-plane pod '{name}' is exec-reachable via the anonymous kubelet — exec yields cluster-admin")),
                ))];
            }
        }
        vec![]
    }
}

/// Always-on "StartedInfo" module — emits the run banner as an informational
/// finding/event at scan start (upstream parity: StartedInfo is always registered).
pub struct StartedInfo;

#[async_trait]
impl Hunter for StartedInfo {
    fn name(&self)          -> &'static str { "StartedInfo" }
    fn description(&self)   -> &'static str { "Emits the run-started banner metadata (always-on)." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ScanStarted }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        tracing::info!(
            "  [*] StartedInfo: mode={}, interface_scan={}",
            if ctx.mode == Mode::Active { "active" } else { "passive" },
            ctx.interface_mode,
        );
        // StartedInfo is metadata-only — it does not raise a vulnerability finding.
        vec![]
    }
}
