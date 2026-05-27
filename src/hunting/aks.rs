use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

/// Checks Azure Instance Metadata Service (IMDS) — only reachable from within Azure VMs.
pub struct AksInstanceMetadata;

#[async_trait]
impl Hunter for AksInstanceMetadata {
    fn name(&self)          -> &'static str { "AksInstanceMetadata" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

        let resp = match ctx.http_insecure
            .get(url)
            .header("Metadata", "true")
            .send()
            .await
        {
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

        let subscription = json["compute"]["subscriptionId"].as_str().unwrap_or("unknown");
        let resource_group = json["compute"]["resourceGroupName"].as_str().unwrap_or("unknown");

        tracing::warn!("  [!] AKS IMDS accessible — subscription: {}", subscription);

        vec![Output::Finding(Finding {
            id:          "KHV-AKS-001".to_string(),
            name:        "Azure Instance Metadata Service Accessible".to_string(),
            description: "The Azure IMDS endpoint is accessible. It exposes subscription \
                          IDs, resource group names, and potentially managed identity tokens \
                          that can be used to access Azure resources.".to_string(),
            severity:    Severity::High,
            host:        "169.254.169.254".to_string(),
            port:        Some(80),
            evidence:    Some(format!(
                "subscription={}, resource_group={}",
                subscription, resource_group
            )),
            category:    "vulnerability".to_string(),
        })]
    }
}
