use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{AttackCategory, Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};
use crate::version::in_affected_range;

struct CveEntry {
    id:          &'static str,
    /// Linked KHV id when upstream allocated one ("None" otherwise).
    khv:         Option<&'static str>,
    name:        &'static str,
    description: &'static str,
    severity:    Severity,
    category:    AttackCategory,
    // (min_inclusive, max_exclusive) pairs.
    ranges:      &'static [(&'static str, &'static str)],
}

use AttackCategory::*;

static CVES: &[CveEntry] = &[
    CveEntry {
        id: "CVE-2018-1002105", khv: Some("KHV022"),
        name: "API Server Proxy Privilege Escalation",
        description: "A request handler in the Kubernetes API server allows websocket \
                      upgrades through aggregated API servers, bypassing authentication.",
        severity: Severity::Critical, category: PrivilegeEscalation,
        ranges: &[("1.0.0", "1.10.11"), ("1.11.0", "1.11.5"), ("1.12.0", "1.12.3")],
    },
    CveEntry {
        id: "CVE-2019-1002100", khv: Some("KHV023"),
        name: "JSON-Patch DoS",
        description: "A user with patch permission can send a JSON-patch request that \
                      consumes excessive API-server resources (denial of service).",
        severity: Severity::Medium, category: Impact,
        ranges: &[("1.0.0", "1.11.8"), ("1.12.0", "1.12.6"), ("1.13.0", "1.13.4")],
    },
    CveEntry {
        id: "CVE-2019-9512", khv: Some("KHV024"),
        name: "HTTP/2 Ping Flood DoS",
        description: "An attacker can exhaust server resources by sending HTTP/2 PING frames.",
        severity: Severity::High, category: Impact,
        ranges: &[("1.0.0", "1.13.10"), ("1.14.0", "1.14.6"), ("1.15.0", "1.15.3")],
    },
    CveEntry {
        id: "CVE-2019-9514", khv: Some("KHV025"),
        name: "HTTP/2 Reset Flood DoS",
        description: "An attacker can exhaust server resources by sending HTTP/2 RST_STREAM frames.",
        severity: Severity::High, category: Impact,
        ranges: &[("1.0.0", "1.13.10"), ("1.14.0", "1.14.6"), ("1.15.0", "1.15.3")],
    },
    CveEntry {
        id: "CVE-2019-11247", khv: Some("KHV026"),
        name: "Cluster-Scoped Resource Access via Namespace",
        description: "The API server mistakenly allows access to cluster-scoped resources \
                      through a namespace-scoped request.",
        severity: Severity::High, category: PrivilegeEscalation,
        ranges: &[("1.0.0", "1.13.9"), ("1.14.0", "1.14.5"), ("1.15.0", "1.15.2")],
    },
    CveEntry {
        id: "CVE-2019-1002101", khv: Some("KHV028"),
        name: "kubectl cp Path Traversal",
        description: "`kubectl cp` allows path traversal that can overwrite files outside \
                      the destination directory.",
        severity: Severity::Medium, category: LateralMovement,
        ranges: &[("1.0.0", "1.11.9"), ("1.12.0", "1.12.7"), ("1.13.0", "1.13.5")],
    },
    CveEntry {
        id: "CVE-2019-11246", khv: Some("KHV027"),
        name: "kubectl cp Incomplete Fix (Path Traversal)",
        description: "Incomplete fix for CVE-2019-1002101; crafted container names still \
                      cause path traversal in kubectl cp.",
        severity: Severity::Medium, category: LateralMovement,
        ranges: &[("1.0.0", "1.12.9"), ("1.13.0", "1.13.6"), ("1.14.0", "1.14.2")],
    },
    CveEntry {
        id: "CVE-2020-8554", khv: None,
        name: "MITM via Service ExternalIPs",
        description: "A user who can create/modify services can intercept traffic to \
                      arbitrary IPs via the ExternalIPs field.",
        severity: Severity::Medium, category: LateralMovement,
        ranges: &[("1.0.0", "1.21.0")],
    },
    CveEntry {
        id: "CVE-2020-8559", khv: None,
        name: "Privilege Escalation via API Redirect",
        description: "An attacker who can intercept certain kubelet requests can escalate \
                      privileges via a crafted redirect.",
        severity: Severity::High, category: PrivilegeEscalation,
        ranges: &[("1.0.0", "1.16.13"), ("1.17.0", "1.17.9"), ("1.18.0", "1.18.7")],
    },
    CveEntry {
        id: "CVE-2020-8557", khv: None,
        name: "/etc/hosts Writable from Container (DoS)",
        description: "Containers can exhaust node disk space by writing to /etc/hosts, \
                      which is mounted from the host.",
        severity: Severity::Medium, category: Impact,
        ranges: &[("1.0.0", "1.18.5")],
    },
    CveEntry {
        id: "CVE-2021-25741", khv: None,
        name: "Subpath Symlink Container Escape",
        description: "A user who can create pods with subPath mounts can escape the container \
                      and read arbitrary host files.",
        severity: Severity::High, category: PrivilegeEscalation,
        ranges: &[("1.0.0", "1.19.16"), ("1.20.0", "1.20.12"), ("1.21.0", "1.21.6"), ("1.22.0", "1.22.3")],
    },
    CveEntry {
        id: "CVE-2021-25737", khv: None,
        name: "Endpoint Redirect HTTP Body Smuggling",
        description: "Endpoint slices in certain configurations allow redirects exploitable \
                      for HTTP request smuggling.",
        severity: Severity::Low, category: LateralMovement,
        ranges: &[("1.0.0", "1.21.0")],
    },
    CveEntry {
        id: "CVE-2022-3172", khv: None,
        name: "Aggregated API Request Forwarding (SSRF)",
        description: "An aggregated API server can cause the API server to forward requests \
                      to arbitrary hosts (SSRF).",
        severity: Severity::High, category: LateralMovement,
        ranges: &[("1.0.0", "1.24.6"), ("1.25.0", "1.25.4")],
    },
    CveEntry {
        id: "CVE-2024-3177", khv: None,
        name: "Bypass Mountable Secrets Policy",
        description: "A user who can create pods can bypass the mountable-secrets restriction \
                      in certain service-account configurations.",
        severity: Severity::Medium, category: CredentialAccess,
        ranges: &[("1.0.0", "1.29.4")],
    },
];

/// Number of CVEs in the static catalog (used by --self-test).
pub fn cve_count() -> usize {
    CVES.len()
}

pub struct CveVersionHunter;

#[async_trait]
impl Hunter for CveVersionHunter {
    fn name(&self)          -> &'static str { "CveHunter" }
    fn description(&self)   -> &'static str { "Maps the discovered Kubernetes version to known CVEs." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::K8sVersion }

    async fn execute(&self, _ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port, raw, parsed) = match event.as_ref() {
            Event::K8sVersion { host, port, raw, parsed } => (*host, *port, raw.clone(), parsed.clone()),
            _ => return vec![],
        };
        let ver = match parsed {
            Some(v) => v,
            None => {
                tracing::debug!("CveHunter: could not parse version {}", raw);
                return vec![];
            }
        };

        let mut out = vec![];
        for cve in CVES {
            if in_affected_range(&ver, cve.ranges) {
                tracing::warn!("  [!] {} affects {} at {}:{}", cve.id, raw, host, port);
                out.push(Output::Finding(Finding {
                    vid:         cve.khv.unwrap_or("None").to_string(),
                    cve:         Some(cve.id.to_string()),
                    name:        cve.name.to_string(),
                    description: cve.description.to_string(),
                    severity:    cve.severity,
                    category:    cve.category,
                    hunter:      self.name().to_string(),
                    host:        host.to_string(),
                    port:        Some(port),
                    evidence:    Some(format!("Kubernetes version: {raw}")),
                }));
            }
        }
        out
    }
}
