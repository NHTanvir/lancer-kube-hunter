use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, HunterCtx, Mode, Output};

/// Always-on host discovery. Concrete target IPs are seeded from CLI args
/// (`--remote`/`--cidr`/`--interface`) before the run; this module is the
/// registered upstream-parity counterpart and a hook for future expansion
/// (e.g. interface enumeration). It is a no-op event-wise.
pub struct HostDiscovery;

#[async_trait]
impl Hunter for HostDiscovery {
    fn name(&self)          -> &'static str { "HostDiscovery" }
    fn description(&self)   -> &'static str { "Generates the set of target hosts to scan." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ScanStarted }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        tracing::debug!("HostDiscovery active (targets seeded from CLI)");
        vec![]
    }
}

/// When running inside a pod: queries the K8s API for all node IPs and emits NewHost.
pub struct FromPodHostDiscovery;

#[async_trait]
impl Hunter for FromPodHostDiscovery {
    fn name(&self)          -> &'static str { "FromPodHostDiscovery" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, token) = match event.as_ref() {
            Event::InCluster { host, port, token } => (host.clone(), port.clone(), token.clone()),
            _ => return vec![],
        };

        let url = format!("https://{}:{}/api/v1/nodes", host, port);
        let resp = ctx.http_insecure
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("FromPodHostDiscovery: {e}");
                return vec![];
            }
        };

        let json: Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => return vec![],
        };

        let mut out = vec![];
        if let Some(items) = json["items"].as_array() {
            for item in items {
                if let Some(addresses) = item["status"]["addresses"].as_array() {
                    for addr in addresses {
                        if addr["type"] == "InternalIP" {
                            if let Some(ip_str) = addr["address"].as_str() {
                                if let Ok(ip) = ip_str.parse() {
                                    out.push(Output::Event(Event::NewHost { host: ip }));
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }
}
