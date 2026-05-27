use std::sync::Arc;
use async_trait::async_trait;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output, Severity};
use crate::version::in_affected_range;

struct CveEntry {
    id:          &'static str,
    name:        &'static str,
    description: &'static str,
    severity:    Severity,
    // (min_inclusive, max_exclusive) pairs — empty first component = "any prior"
    ranges:      &'static [(&'static str, &'static str)],
}

static CVES: &[CveEntry] = &[
    CveEntry {
        id: "CVE-2018-1002105",
        name: "API Server Proxy Privilege Escalation",
        description: "A request handler in the Kubernetes API server allows websocket \
                      upgrades through aggregated API servers, bypassing authentication.",
        severity: Severity::Critical,
        ranges: &[
            ("1.0.0", "1.10.11"),
            ("1.11.0", "1.11.5"),
            ("1.12.0", "1.12.3"),
        ],
    },
    CveEntry {
        id: "CVE-2019-1002100",
        name: "JSON-Patch DoS",
        description: "A malicious user with patch permission can send a JSON-patch \
                      request that consumes excessive server resources.",
        severity: Severity::Medium,
        ranges: &[
            ("1.0.0", "1.11.8"),
            ("1.12.0", "1.12.6"),
            ("1.13.0", "1.13.4"),
        ],
    },
    CveEntry {
        id: "CVE-2019-9512",
        name: "HTTP/2 Ping Flood DoS",
        description: "An attacker can cause a server to allocate excessive resources \
                      by sending HTTP/2 PING frames.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.13.10"),
            ("1.14.0", "1.14.6"),
            ("1.15.0", "1.15.3"),
        ],
    },
    CveEntry {
        id: "CVE-2019-9514",
        name: "HTTP/2 Reset Flood DoS",
        description: "An attacker can cause a server to allocate excessive resources \
                      by sending RST_STREAM frames.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.13.10"),
            ("1.14.0", "1.14.6"),
            ("1.15.0", "1.15.3"),
        ],
    },
    CveEntry {
        id: "CVE-2019-11247",
        name: "Cluster-Scoped Resource Access via Namespace",
        description: "The Kubernetes API server mistakenly allows access to cluster-scoped \
                      resources through a namespace-scoped request.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.13.9"),
            ("1.14.0", "1.14.5"),
            ("1.15.0", "1.15.2"),
        ],
    },
    CveEntry {
        id: "CVE-2019-1002101",
        name: "kubectl cp Path Traversal",
        description: "`kubectl cp` allows path traversal that can overwrite files \
                      outside the destination directory.",
        severity: Severity::Medium,
        ranges: &[
            ("1.0.0", "1.11.9"),
            ("1.12.0", "1.12.7"),
            ("1.13.0", "1.13.5"),
        ],
    },
    CveEntry {
        id: "CVE-2019-11246",
        name: "kubectl cp Incomplete Fix (Path Traversal)",
        description: "Incomplete fix for CVE-2019-1002101. Specially crafted container \
                      names can still cause path traversal in kubectl cp.",
        severity: Severity::Medium,
        ranges: &[
            ("1.0.0", "1.12.9"),
            ("1.13.0", "1.13.6"),
            ("1.14.0", "1.14.2"),
        ],
    },
    CveEntry {
        id: "CVE-2020-8554",
        name: "MITM via Service ExternalIPs",
        description: "A cluster user who can create or modify services can intercept \
                      traffic to arbitrary IPs via the ExternalIPs field.",
        severity: Severity::Medium,
        // Affects all Kubernetes versions without mitigation
        ranges: &[("1.0.0", "1.21.0")],
    },
    CveEntry {
        id: "CVE-2020-8559",
        name: "Privilege Escalation via API Redirect",
        description: "An attacker who can intercept certain requests to the kubelet \
                      can escalate privileges via a specially crafted redirect.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.16.13"),
            ("1.17.0", "1.17.9"),
            ("1.18.0", "1.18.7"),
        ],
    },
    CveEntry {
        id: "CVE-2020-8557",
        name: "/etc/hosts Writable from Container (DoS)",
        description: "Containers can exhaust disk space on the node by writing to \
                      /etc/hosts, which is mounted from the host.",
        severity: Severity::Medium,
        ranges: &[("1.0.0", "1.18.5")],
    },
    CveEntry {
        id: "CVE-2021-25741",
        name: "Subpath Symlink Container Escape",
        description: "A user who can create pods with subPath volume mounts can \
                      escape the container and read arbitrary host files.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.19.16"),
            ("1.20.0", "1.20.12"),
            ("1.21.0", "1.21.6"),
            ("1.22.0", "1.22.3"),
        ],
    },
    CveEntry {
        id: "CVE-2021-25737",
        name: "Endpoint Redirect HTTP Body Smuggling",
        description: "Endpoint slices in certain configurations allow redirects that \
                      can be exploited for HTTP request smuggling.",
        severity: Severity::Low,
        ranges: &[("1.0.0", "1.21.0")],
    },
    CveEntry {
        id: "CVE-2022-3172",
        name: "Aggregated API Request Forwarding",
        description: "An aggregated API server can cause the Kubernetes API server to \
                      forward requests to arbitrary hosts, enabling SSRF.",
        severity: Severity::High,
        ranges: &[
            ("1.0.0", "1.24.6"),
            ("1.25.0", "1.25.4"),
        ],
    },
    CveEntry {
        id: "CVE-2024-3177",
        name: "Bypass Mountable Secrets Policy",
        description: "A user with the ability to create pods can bypass the enforcedmountable secrets \
                      restriction in certain service account configurations.",
        severity: Severity::Medium,
        ranges: &[("1.0.0", "1.29.4")],
    },
];

pub struct CveVersionHunter;

#[async_trait]
impl Hunter for CveVersionHunter {
    fn name(&self)          -> &'static str { "CveVersionHunter" }
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
                tracing::debug!("CveVersionHunter: could not parse version {}", raw);
                return vec![];
            }
        };

        let mut out = vec![];
        for cve in CVES {
            if in_affected_range(&ver, cve.ranges) {
                tracing::warn!("  [!] {} ({}) affects {} at {}:{}", cve.id, raw, raw, host, port);
                out.push(Output::Finding(Finding {
                    id:          cve.id.to_string(),
                    name:        cve.name.to_string(),
                    description: cve.description.to_string(),
                    severity:    cve.severity,
                    host:        host.to_string(),
                    port:        Some(port),
                    evidence:    Some(format!("Kubernetes version: {}", raw)),
                    category:    "cve".to_string(),
                }));
            }
        }
        out
    }
}
