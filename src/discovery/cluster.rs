use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, HunterCtx, Mode, Output};
use crate::version::parse_k8s_version;

/// Fingerprints the K8s version via /version and emits K8sVersion.
pub struct KubernetesClusterDiscovery;

#[async_trait]
impl Hunter for KubernetesClusterDiscovery {
    fn name(&self)          -> &'static str { "KubernetesClusterDiscovery" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, tls) = match event.as_ref() {
            Event::ApiServer { host, port, tls } => (*host, *port, *tls),
            _ => return vec![],
        };

        let scheme = if tls { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/version");

        let resp = match ctx.http_insecure.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("KubernetesClusterDiscovery: {e}");
                return vec![];
            }
        };

        let json: Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => return vec![],
        };

        let raw = json["gitVersion"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        if raw.is_empty() {
            return vec![];
        }

        let parsed = parse_k8s_version(&raw);
        tracing::info!("  [*] Kubernetes {} at {}:{}", raw, host, port);

        vec![Output::Event(Event::K8sVersion { host, port, raw, parsed })]
    }
}
