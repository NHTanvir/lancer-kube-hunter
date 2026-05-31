use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

/// KHV047 — Active hunter: checks for writable host mounts inside a pod
/// (notably /var/log, which enables a symlink-based host-read primitive).
pub struct WriteMountToVarLog;

#[async_trait]
impl Hunter for WriteMountToVarLog {
    fn name(&self)          -> &'static str { "WriteMountToVarLog" }
    fn description(&self)   -> &'static str { "Active: probes for writable host mounts (/var/log, /host, init root)." }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let mut out = vec![];

        let paths = [
            ("/var/log", "host /var/log"),
            ("/host", "host root"),
            ("/proc/1/root", "init process root"),
        ];
        for (path, label) in &paths {
            let test_file = format!("{path}/.kube_hunter_probe");
            if std::fs::write(&test_file, "kube-hunter probe").is_ok() {
                let _ = std::fs::remove_file(&test_file);
                tracing::warn!("  [!] KHV047 writable mount {} at {}", label, path);
                out.push(Output::Finding(
                    Finding::khv("KHV047", self.name(), "localhost", None,
                        Some(format!("Successfully wrote to {test_file} ({label})")))
                ));
            }
        }

        // CVE-2020-8557 — /etc/hosts writable from container (DoS via disk fill).
        if let Ok(meta) = std::fs::metadata("/etc/hosts") {
            if !meta.permissions().readonly() {
                out.push(Output::Finding(
                    Finding::khv("KHV047", self.name(), "localhost", None,
                        Some("/etc/hosts is writable from the container".into()))
                        .with_cve("CVE-2020-8557")
                        .with_severity(Severity::Medium)
                        .with_description("The /etc/hosts file is writable. Containers can exhaust node disk space (CVE-2020-8557) or manipulate name resolution for co-located pods.")
                ));
            }
        }

        out
    }
}
