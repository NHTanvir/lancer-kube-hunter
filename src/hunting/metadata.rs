use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV053 — AWS EC2 Instance Metadata Service (IMDS) exposure.
/// Tries IMDSv2 (token) first, then falls back to IMDSv1.
pub struct AwsMetadataApi;

#[async_trait]
impl Hunter for AwsMetadataApi {
    fn name(&self)          -> &'static str { "AwsMetadataApi" }
    fn description(&self)   -> &'static str { "Probes the AWS IMDS for exposed IAM role credentials." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        // IMDSv2: obtain a session token.
        let token = ctx.http_insecure
            .put("http://169.254.169.254/latest/api/token")
            .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
            .send()
            .await
            .ok()
            .and_then(|r| if r.status().is_success() { Some(r) } else { None });

        let creds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let mut req = ctx.http_insecure.get(creds_url);
        if let Some(tok_resp) = token {
            if let Ok(tok) = tok_resp.text().await {
                req = req.header("X-aws-ec2-metadata-token", tok);
            }
        }
        let resp = match req.send().await { Ok(r) => r, Err(_) => return vec![] };
        if resp.status().is_success() {
            let role = resp.text().await.unwrap_or_default();
            let role = role.lines().next().unwrap_or("").trim().to_string();
            if !role.is_empty() {
                tracing::warn!("  [!] KHV053 AWS IMDS role credentials exposed: {}", role);
                return vec![Output::Finding(Finding::khv(
                    "KHV053", self.name(), "169.254.169.254", Some(80),
                    Some(format!("IAM role credentials retrievable for role '{role}'")),
                ))];
            }
        }
        vec![]
    }
}
