use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV003 — Azure Instance Metadata Service (IMDS) reachable from within the node.
pub struct AKSInstanceMetadataAPI;

#[async_trait]
impl Hunter for AKSInstanceMetadataAPI {
    fn name(&self)          -> &'static str { "AKSInstanceMetadataAPI" }
    fn description(&self)   -> &'static str { "Probes the Azure IMDS endpoint for subscription/identity exposure." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
        let resp = match ctx.http_insecure.get(url).header("Metadata", "true").send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        if !resp.status().is_success() {
            return vec![];
        }
        let json: Value = match resp.json().await { Ok(j) => j, Err(_) => return vec![] };
        let subscription = json["compute"]["subscriptionId"].as_str().unwrap_or("unknown");
        let resource_group = json["compute"]["resourceGroupName"].as_str().unwrap_or("unknown");
        tracing::warn!("  [!] KHV003 Azure IMDS accessible — subscription {}", subscription);
        vec![Output::Finding(Finding::khv(
            "KHV003", self.name(), "169.254.169.254", Some(80),
            Some(format!("subscription={subscription}, resource_group={resource_group}")),
        ))]
    }
}

/// KHV004 — Azure Service Principal credentials file readable inside the node.
pub struct AzureSpnHunter;

#[async_trait]
impl Hunter for AzureSpnHunter {
    fn name(&self)          -> &'static str { "AzureSpnHunter" }
    fn description(&self)   -> &'static str { "Reads /etc/kubernetes/azure.json for Service Principal credentials." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let candidates = ["/etc/kubernetes/azure.json", "/etc/kubernetes/azurestackcloud.json"];
        for path in candidates {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(json) = serde_json::from_str::<Value>(&contents) {
                    if json.get("aadClientId").is_some() || json.get("aadClientSecret").is_some() {
                        let client_id = json["aadClientId"].as_str().unwrap_or("present");
                        tracing::warn!("  [!] KHV004 Azure SPN credentials readable at {}", path);
                        return vec![Output::Finding(Finding::khv(
                            "KHV004", self.name(), "localhost", None,
                            Some(format!("Azure SPN credentials readable at {path} (aadClientId={client_id})")),
                        ))];
                    }
                }
            }
        }
        vec![]
    }
}
