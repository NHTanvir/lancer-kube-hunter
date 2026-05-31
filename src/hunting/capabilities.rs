use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV044 — Privileged container / dangerous Linux capabilities.
///
/// Inspects the current process's effective capability set (the `CapEff` mask in
/// /proc/self/status) to determine whether the container runs privileged (full
/// capability set) or holds escalation-grade capabilities such as CAP_SYS_ADMIN
/// or CAP_SYS_PTRACE.
pub struct PrivilegedContainer;

// Capability bit positions (Linux capability.h).
const CAP_SYS_ADMIN: u64  = 21;
const CAP_SYS_PTRACE: u64 = 19;
const CAP_SYS_MODULE: u64 = 16;
const CAP_NET_ADMIN: u64  = 12;
const CAP_DAC_READ_SEARCH: u64 = 2;

#[async_trait]
impl Hunter for PrivilegedContainer {
    fn name(&self)          -> &'static str { "PrivilegedContainer" }
    fn description(&self)   -> &'static str { "Inspects /proc/self/status capabilities for privileged/dangerous grants." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let status = match std::fs::read_to_string("/proc/self/status") {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let cap_eff = status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok());

        let cap_eff = match cap_eff {
            Some(c) => c,
            None => return vec![],
        };

        // A privileged container has the full capability set (all 40+ bits set).
        let full = cap_eff == 0x0000_003f_ffff_ffff || cap_eff.count_ones() >= 38;
        let has = |bit: u64| cap_eff & (1 << bit) != 0;

        let mut dangerous = vec![];
        if has(CAP_SYS_ADMIN)  { dangerous.push("SYS_ADMIN"); }
        if has(CAP_SYS_PTRACE) { dangerous.push("SYS_PTRACE"); }
        if has(CAP_SYS_MODULE) { dangerous.push("SYS_MODULE"); }
        if has(CAP_NET_ADMIN)  { dangerous.push("NET_ADMIN"); }
        if has(CAP_DAC_READ_SEARCH) { dangerous.push("DAC_READ_SEARCH"); }

        if full || !dangerous.is_empty() {
            let evidence = if full {
                format!("CapEff=0x{cap_eff:016x} — full capability set (privileged container)")
            } else {
                format!("CapEff=0x{cap_eff:016x} — dangerous capabilities: {}", dangerous.join(", "))
            };
            tracing::warn!("  [!] KHV044 privileged/over-capable container: {}", evidence);
            return vec![Output::Finding(Finding::khv(
                "KHV044", self.name(), "localhost", None, Some(evidence),
            ))];
        }
        vec![]
    }
}
