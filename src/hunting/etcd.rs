use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

// ── KHV032 / KHV033 / KHV034 — etcd remote read / version / insecure (passive) ─

pub struct EtcdRemoteAccess;

#[async_trait]
impl Hunter for EtcdRemoteAccess {
    fn name(&self)          -> &'static str { "EtcdRemoteAccess" }
    fn description(&self)   -> &'static str { "Probes etcd for unauthenticated version disclosure and remote reads." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::Etcd }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::Etcd { host, port } => (*host, *port),
            _ => return vec![],
        };
        let mut out = vec![];

        for scheme in ["https", "http"] {
            let base = format!("{scheme}://{host}:{port}");

            // Version disclosure (KHV033) + insecure HTTP (KHV034)
            if let Ok(r) = ctx.http_insecure.get(format!("{base}/version")).send().await {
                if r.status().is_success() {
                    let json: Value = r.json().await.unwrap_or_default();
                    let version = json["etcdserver"].as_str().unwrap_or("unknown").to_string();
                    tracing::warn!("  [!] KHV033 etcd version disclosure at {}:{}", host, port);
                    out.push(Output::Finding(Finding::khv(
                        "KHV033", self.name(), host, Some(port),
                        Some(format!("etcd server version: {version}")),
                    )));
                    if scheme == "http" {
                        tracing::warn!("  [!] KHV034 etcd reachable over plaintext HTTP at {}:{}", host, port);
                        out.push(Output::Finding(Finding::khv(
                            "KHV034", self.name(), host, Some(port),
                            Some("etcd /version reachable over plaintext HTTP".into()),
                        )));
                    }

                    // Remote read access (KHV032) — etcd v3 range over the grpc-gateway.
                    let body = json!({ "key": "AA==", "range_end": "AA==" });
                    if let Ok(rr) = ctx.http_insecure.post(format!("{base}/v3/kv/range")).json(&body).send().await {
                        if rr.status().is_success() {
                            tracing::warn!("  [!] KHV032 etcd remote read at {}:{}", host, port);
                            out.push(Output::Finding(Finding::khv(
                                "KHV032", self.name(), host, Some(port),
                                Some("etcd /v3/kv/range answered an unauthenticated read".into()),
                            )));
                        }
                    }
                    break; // first working scheme wins
                }
            }
        }
        out
    }
}

// ── KHV031 — etcd remote write access (active) ────────────────────────────────

pub struct EtcdRemoteWriteAccessActive;

#[async_trait]
impl Hunter for EtcdRemoteWriteAccessActive {
    fn name(&self)          -> &'static str { "EtcdRemoteWriteAccessActive" }
    fn description(&self)   -> &'static str { "Active: writes (then deletes) a probe key to detect unauthenticated etcd writes." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::Etcd }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::Etcd { host, port } => (*host, *port),
            _ => return vec![],
        };
        for scheme in ["https", "http"] {
            let base = format!("{scheme}://{host}:{port}");
            // key "kube-hunter-probe" / value "1" base64-encoded.
            let key = "a3ViZS1odW50ZXItcHJvYmU=";   // "kube-hunter-probe"
            let val = "MQ==";                          // "1"
            let body = json!({ "key": key, "value": val });
            if let Ok(r) = ctx.http_insecure.post(format!("{base}/v3/kv/put")).json(&body).send().await {
                if r.status().is_success() {
                    // Clean up the probe key.
                    let del = json!({ "key": key });
                    let _ = ctx.http_insecure.post(format!("{base}/v3/kv/deleterange")).json(&del).send().await;
                    tracing::warn!("  [!] KHV031 etcd remote WRITE at {}:{}", host, port);
                    return vec![Output::Finding(Finding::khv(
                        "KHV031", self.name(), host, Some(port),
                        Some("etcd accepted an unauthenticated /v3/kv/put (probe key deleted afterwards)".into()),
                    ))];
                }
            }
        }
        vec![]
    }
}
