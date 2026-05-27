use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};

/// Active hunter: checks for writable sensitive mounts inside a pod.
/// Only runs in active mode AND when running in-cluster.
pub struct WriteMountToVarLog;

#[async_trait]
impl Hunter for WriteMountToVarLog {
    fn name(&self)          -> &'static str { "WriteMountToVarLog" }
    fn mode(&self)          -> Mode         { Mode::Active }
    fn subscribes_to(&self) -> EventKind    { EventKind::InCluster }

    async fn execute(&self, _ctx: Arc<HunterCtx>, _event: Arc<Event>) -> Vec<Output> {
        let mut out = vec![];

        // Check common sensitive mount paths
        let paths = [
            ("/var/log", "host /var/log"),
            ("/host", "host root"),
            ("/proc/1/root", "init process root"),
        ];

        for (path, label) in &paths {
            let test_file = format!("{path}/.kube_hunter_probe");
            if let Ok(_) = std::fs::write(&test_file, "kube-hunter probe") {
                // Clean up
                let _ = std::fs::remove_file(&test_file);
                tracing::warn!("  [!] Writable mount {} at {}", label, path);
                out.push(Output::Finding(Finding {
                    id:          "KHV-MOUNT-001".to_string(),
                    name:        format!("Writable Mount: {}", label),
                    description: format!(
                        "The container has write access to {}. A malicious container \
                         can write to host paths and potentially escalate privileges.",
                        label
                    ),
                    severity:    Severity::Critical,
                    host:        "localhost".to_string(),
                    port:        None,
                    evidence:    Some(format!("Successfully wrote to {}", test_file)),
                    category:    "active".to_string(),
                }));
            }
        }

        // Check if /etc/hosts is writable (CVE-2020-8557)
        if let Ok(meta) = std::fs::metadata("/etc/hosts") {
            if !meta.permissions().readonly() {
                out.push(Output::Finding(Finding {
                    id:          "CVE-2020-8557".to_string(),
                    name:        "/etc/hosts Writable from Container".to_string(),
                    description: "The /etc/hosts file is writable. Containers can exhaust \
                                  node disk space or manipulate DNS resolution for other pods."
                        .to_string(),
                    severity:    Severity::Medium,
                    host:        "localhost".to_string(),
                    port:        None,
                    evidence:    Some("/etc/hosts is writable".to_string()),
                    category:    "active".to_string(),
                }));
            }
        }

        out
    }
}
