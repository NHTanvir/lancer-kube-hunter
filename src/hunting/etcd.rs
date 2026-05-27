use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

pub struct EtcdUnauthenticatedAccess;

#[async_trait]
impl Hunter for EtcdUnauthenticatedAccess {
    fn name(&self)          -> &'static str { "EtcdUnauthenticatedAccess" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::Etcd }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::Etcd { host, port } => (*host, *port),
            _ => return vec![],
        };

        let mut out = vec![];

        // Try etcd v3 /version (no auth)
        for scheme in &["http", "https"] {
            let url = format!("{scheme}://{host}:{port}/version");
            if let Ok(r) = ctx.http_insecure.get(url).send().await {
                if r.status().is_success() {
                    let json: Value = r.json().await.unwrap_or_default();
                    let version = json["etcdserver"].as_str().unwrap_or("unknown");
                    tracing::warn!("  [!] etcd unauthenticated access at {}:{}", host, port);
                    out.push(Output::Finding(Finding {
                        id:          "KHV-ETCD-001".to_string(),
                        name:        "Unauthenticated etcd Access".to_string(),
                        description: "The etcd instance is accessible without authentication. \
                                      An attacker can read all cluster secrets, certificates, \
                                      and configuration data.".to_string(),
                        severity:    Severity::Critical,
                        host:        host.to_string(),
                        port:        Some(port),
                        evidence:    Some(format!("etcd version: {}", version)),
                        category:    "vulnerability".to_string(),
                    }));
                    break;
                }
            }
        }

        out
    }
}
