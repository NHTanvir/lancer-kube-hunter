//! KHV knowledge base — the canonical catalog of every allocated kube-hunter
//! vulnerability id (KHV###), mirroring the upstream KB at
//! aquasecurity.github.io/kube-hunter/kbindex.html.
//!
//! Each entry carries the upstream title, a description, a severity, and the
//! MITRE ATT&CK for Kubernetes category (introduced upstream in v0.6.2).
//! Hunters reference these entries via [`crate::types::Finding::khv`] so that
//! every finding is tagged consistently and the full catalog is enumerable
//! (`--list`, `--self-test`, the GUI knowledge-base panel).
//!
//! NOTE on KHV036 / KHV050: the upstream docs ship two slightly divergent
//! tables. We follow the *behavioural* mapping used by the real tool —
//! KHV036 = read access to the pod service-account token, KHV050 = access to
//! pod secrets — rather than the conflicting wording in the KB index.

use crate::types::{AttackCategory, Severity};
use AttackCategory::*;
use Severity::*;

pub struct KhvMeta {
    pub vid:         &'static str,
    pub title:       &'static str,
    pub description: &'static str,
    pub severity:    Severity,
    pub category:    AttackCategory,
}

/// Every allocated KHV id. IDs KHV008–019, KHV035, KHV048 and KHV055–199 are
/// intentionally unallocated upstream and therefore absent here.
pub static CATALOG: &[KhvMeta] = &[
    KhvMeta { vid: "KHV001", title: "Information Disclosure",
        description: "A Kubernetes component exposed informational endpoints (e.g. /metrics, /version) to an unauthenticated client.",
        severity: Low, category: Discovery },
    KhvMeta { vid: "KHV002", title: "Kubernetes Version Disclosure",
        description: "The Kubernetes version was disclosed via the /version endpoint, allowing an attacker to target version-specific CVEs.",
        severity: Low, category: Discovery },
    KhvMeta { vid: "KHV003", title: "Azure Metadata Exposure",
        description: "The Azure Instance Metadata Service (IMDS) is reachable, exposing subscription/resource-group details and potentially managed-identity tokens.",
        severity: High, category: CredentialAccess },
    KhvMeta { vid: "KHV004", title: "Azure SPN Exposure",
        description: "An Azure Service Principal Name credential file (azure.json) is readable, exposing cloud credentials.",
        severity: High, category: CredentialAccess },
    KhvMeta { vid: "KHV005", title: "Access to Kubernetes API",
        description: "The Kubernetes API server allows anonymous or over-permissive access, enabling resource enumeration without valid credentials.",
        severity: High, category: InitialAccess },
    KhvMeta { vid: "KHV006", title: "Insecure (HTTP) Access to Kubernetes API",
        description: "The Kubernetes API server is reachable over plaintext HTTP (insecure port), exposing unauthenticated, interceptable requests.",
        severity: High, category: InitialAccess },
    KhvMeta { vid: "KHV007", title: "Specific Access to Kubernetes API",
        description: "Anonymous access reveals specific API resources (namespaces, RBAC metadata), disclosing cluster structure.",
        severity: Medium, category: Discovery },
    KhvMeta { vid: "KHV020", title: "Possible ARP Spoof",
        description: "The node's network configuration permits ARP spoofing between pods on the same subnet, enabling man-in-the-middle attacks.",
        severity: Medium, category: LateralMovement },
    KhvMeta { vid: "KHV021", title: "Certificate Includes Email Address",
        description: "The API server TLS certificate embeds an email address in its subject/SAN, leaking operator information.",
        severity: Low, category: Discovery },
    KhvMeta { vid: "KHV022", title: "Critical Privilege Escalation CVE",
        description: "The cluster runs a Kubernetes version vulnerable to a critical privilege-escalation CVE (CVE-2018-1002105).",
        severity: Critical, category: PrivilegeEscalation },
    KhvMeta { vid: "KHV023", title: "Denial of Service to Kubernetes API Server",
        description: "The cluster runs a version vulnerable to an API-server denial-of-service (CVE-2019-1002100).",
        severity: High, category: Impact },
    KhvMeta { vid: "KHV024", title: "Possible Ping Flood Attack",
        description: "The cluster runs a version vulnerable to the HTTP/2 ping-flood DoS (CVE-2019-9512).",
        severity: High, category: Impact },
    KhvMeta { vid: "KHV025", title: "Possible Reset Flood Attack",
        description: "The cluster runs a version vulnerable to the HTTP/2 reset-flood DoS (CVE-2019-9514).",
        severity: High, category: Impact },
    KhvMeta { vid: "KHV026", title: "Arbitrary Access To Cluster Scoped Resources",
        description: "The cluster runs a version vulnerable to cluster-scoped resource access via namespaced requests (CVE-2019-11247).",
        severity: High, category: PrivilegeEscalation },
    KhvMeta { vid: "KHV027", title: "Kubectl Vulnerable To CVE-2019-11246",
        description: "The reported version is affected by the kubectl cp path-traversal CVE-2019-11246.",
        severity: Medium, category: LateralMovement },
    KhvMeta { vid: "KHV028", title: "Kubectl Vulnerable To CVE-2019-1002101",
        description: "The reported version is affected by the kubectl cp path-traversal CVE-2019-1002101.",
        severity: Medium, category: LateralMovement },
    KhvMeta { vid: "KHV029", title: "Dashboard Exposed",
        description: "The Kubernetes Dashboard is exposed and reachable without authentication, granting cluster control through the UI.",
        severity: High, category: InitialAccess },
    KhvMeta { vid: "KHV030", title: "Possible DNS Spoof",
        description: "The cluster DNS configuration permits spoofing/poisoning of in-cluster name resolution, enabling man-in-the-middle attacks.",
        severity: Medium, category: LateralMovement },
    KhvMeta { vid: "KHV031", title: "Etcd Remote Write Access Event",
        description: "etcd accepts unauthenticated remote writes. An attacker can mutate cluster state directly in the datastore.",
        severity: Critical, category: Impact },
    KhvMeta { vid: "KHV032", title: "Etcd Remote Read Access Event",
        description: "etcd allows unauthenticated remote reads, exposing all cluster secrets, certificates, and configuration.",
        severity: High, category: CredentialAccess },
    KhvMeta { vid: "KHV033", title: "Etcd Remote Version Disclosure",
        description: "The etcd version is disclosed remotely, aiding targeted exploitation.",
        severity: Low, category: Discovery },
    KhvMeta { vid: "KHV034", title: "Etcd Accessible Using Insecure Connection (HTTP)",
        description: "etcd is reachable over plaintext HTTP, exposing datastore traffic to interception.",
        severity: Medium, category: Discovery },
    KhvMeta { vid: "KHV036", title: "Read access to Pod's service account token",
        description: "The pod's service-account token is readable. If broadly scoped it grants API access; a foundational credential-access primitive.",
        severity: High, category: CredentialAccess },
    KhvMeta { vid: "KHV037", title: "Exposed Container Logs",
        description: "The kubelet exposes container logs (/containerLogs) without authentication, leaking application data.",
        severity: Medium, category: Collection },
    KhvMeta { vid: "KHV038", title: "Exposed Running Pods",
        description: "The kubelet exposes the list of running pods (/runningpods, /pods) without authentication.",
        severity: Medium, category: Discovery },
    KhvMeta { vid: "KHV039", title: "Exposed Exec On Container",
        description: "The kubelet exposes /exec, allowing unauthenticated command execution inside containers.",
        severity: Critical, category: Execution },
    KhvMeta { vid: "KHV040", title: "Exposed Run Inside Container",
        description: "The kubelet exposes /run, allowing unauthenticated command execution inside containers.",
        severity: Critical, category: Execution },
    KhvMeta { vid: "KHV041", title: "Exposed Port Forward",
        description: "The kubelet exposes /portForward, allowing unauthenticated tunneling into container network namespaces.",
        severity: High, category: LateralMovement },
    KhvMeta { vid: "KHV042", title: "Exposed Attaching To Container",
        description: "The kubelet exposes /attach, allowing unauthenticated attachment to running container processes.",
        severity: Critical, category: Execution },
    KhvMeta { vid: "KHV043", title: "Cluster Health Disclosure",
        description: "Cluster health endpoints (/healthz) are reachable anonymously, disclosing component status.",
        severity: Low, category: Discovery },
    KhvMeta { vid: "KHV044", title: "Privileged Container",
        description: "A privileged container (or one with dangerous capabilities such as SYS_ADMIN/SYS_PTRACE) was detected, enabling host escape.",
        severity: High, category: PrivilegeEscalation },
    KhvMeta { vid: "KHV045", title: "Exposed System Logs",
        description: "The kubelet exposes host system logs (/logs) without authentication.",
        severity: Medium, category: Collection },
    KhvMeta { vid: "KHV046", title: "Exposed Kubelet Cmdline",
        description: "The kubelet exposes its command line / configuration (/configz, /spec), disclosing flags and topology.",
        severity: Medium, category: Discovery },
    KhvMeta { vid: "KHV047", title: "Pod With Mount To /var/log",
        description: "A pod mounts the host /var/log directory writable, enabling a symlink-based host-filesystem read primitive.",
        severity: High, category: Persistence },
    KhvMeta { vid: "KHV049", title: "kubectl proxy Exposed",
        description: "kubectl proxy / kube-proxy is exposed externally, forwarding requests to the API server without additional authentication.",
        severity: High, category: InitialAccess },
    KhvMeta { vid: "KHV050", title: "Access to Pod's Secrets",
        description: "Cluster secrets are readable (anonymously or via the discovered token), exposing TLS keys, credentials, and tokens.",
        severity: Critical, category: CredentialAccess },
    KhvMeta { vid: "KHV051", title: "Exposed Existing Privileged Containers Via Secure Kubelet Port",
        description: "The secure kubelet port reveals existing privileged containers, an escalation target.",
        severity: High, category: Discovery },
    KhvMeta { vid: "KHV052", title: "Exposed Pods",
        description: "The read-only kubelet port (10255) exposes the pod list without authentication.",
        severity: Medium, category: Discovery },
    KhvMeta { vid: "KHV053", title: "AWS Metadata Exposure",
        description: "The AWS EC2 Instance Metadata Service is reachable, exposing IAM role credentials usable against the AWS account.",
        severity: High, category: CredentialAccess },
    KhvMeta { vid: "KHV054", title: "Anonymous Access to Kubelet",
        description: "The kubelet allows anonymous access to debug handlers, enabling unauthenticated remote code execution via /exec or /run.",
        severity: Critical, category: Execution },
    KhvMeta { vid: "KHV200", title: "Cluster-Admin via kubectl exec on a Master Pod",
        description: "A pod scheduled on a master node can be exec'd into, yielding cluster-admin via the master's kubelet/api credentials.",
        severity: Critical, category: PrivilegeEscalation },
];

/// Look up a KHV entry by id (e.g. "KHV050").
pub fn lookup(vid: &str) -> Option<&'static KhvMeta> {
    CATALOG.iter().find(|m| m.vid == vid)
}

/// Total count of allocated KHV ids in the catalog.
pub fn count() -> usize {
    CATALOG.len()
}
