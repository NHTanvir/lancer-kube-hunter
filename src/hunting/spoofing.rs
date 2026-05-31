use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

// Upstream removed the scapy-based raw-L2 ARP/DNS spoof hunters in v0.6.8 (GPL2
// concern). Raw layer-2 probing is not portable to safe Rust without a pcap
// dependency, so these hunters surface the *risk* (KHV020/KHV030) when running
// an interface scan in active mode, rather than performing live spoofing.

/// KHV020 — Possible ARP spoof surface (interface scan, active).
pub struct PossibleArpSpoof;

#[async_trait]
impl Hunter for PossibleArpSpoof {
    fn name(&self)          -> &'static str { "PossibleArpSpoofHunter" }
    fn description(&self)   -> &'static str { "Flags ARP-spoof exposure on the scanned interface (active interface scan)." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ScanStarted }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        if !ctx.interface_mode {
            return vec![];
        }
        tracing::warn!("  [!] KHV020 ARP-spoof surface present on scanned interface");
        vec![Output::Finding(Finding::khv(
            "KHV020", self.name(), "local-interface", None,
            Some("Pods share an L2 segment without ARP protections; raw-socket confirmation not performed (scapy removed upstream in v0.6.8)".into()),
        ))]
    }
}

/// KHV030 — Possible DNS spoof surface (interface scan, active).
pub struct PossibleDnsSpoof;

#[async_trait]
impl Hunter for PossibleDnsSpoof {
    fn name(&self)          -> &'static str { "PossibleDnsSpoofHunter" }
    fn description(&self)   -> &'static str { "Flags DNS-spoof/CoreDNS-poisoning exposure (active interface scan)." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::ScanStarted }

    async fn execute(&self, ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        if !ctx.interface_mode {
            return vec![];
        }
        tracing::warn!("  [!] KHV030 DNS-spoof surface present on scanned interface");
        vec![Output::Finding(Finding::khv(
            "KHV030", self.name(), "local-interface", None,
            Some("In-cluster DNS can be poisoned via ARP/DNS spoofing on the shared segment; live spoof not performed (scapy removed upstream in v0.6.8)".into()),
        ))]
    }
}
