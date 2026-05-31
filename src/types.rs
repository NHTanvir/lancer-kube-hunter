use std::net::IpAddr;
use serde::{Deserialize, Serialize};

// ── Scan mode ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Passive,
    Active,
}

// ── Events emitted on the internal bus ───────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Event {
    /// Seeded once at the start of every run — drives always-on modules
    /// (StartedInfo) and run-context hunters (ARP/DNS-spoof surface).
    ScanStarted,
    NewHost       { host: IpAddr },
    OpenPort      { host: IpAddr, port: u16 },
    ApiServer     { host: IpAddr, port: u16, tls: bool },
    KubeletSecure { host: IpAddr, port: u16 },
    KubeletReadOnly { host: IpAddr, port: u16 },
    Etcd          { host: IpAddr, port: u16 },
    Dashboard     { host: IpAddr, port: u16 },
    KubeProxy     { host: IpAddr, port: u16 },
    K8sVersion    {
        host:     IpAddr,
        port:     u16,
        raw:      String,
        parsed:   Option<semver::Version>,
    },
    InCluster     { host: String, port: String, token: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    ScanStarted,
    NewHost,
    OpenPort,
    ApiServer,
    KubeletSecure,
    KubeletReadOnly,
    Etcd,
    Dashboard,
    KubeProxy,
    K8sVersion,
    InCluster,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        match self {
            Event::ScanStarted          => EventKind::ScanStarted,
            Event::NewHost       { .. } => EventKind::NewHost,
            Event::OpenPort      { .. } => EventKind::OpenPort,
            Event::ApiServer     { .. } => EventKind::ApiServer,
            Event::KubeletSecure { .. } => EventKind::KubeletSecure,
            Event::KubeletReadOnly { .. } => EventKind::KubeletReadOnly,
            Event::Etcd          { .. } => EventKind::Etcd,
            Event::Dashboard     { .. } => EventKind::Dashboard,
            Event::KubeProxy     { .. } => EventKind::KubeProxy,
            Event::K8sVersion    { .. } => EventKind::K8sVersion,
            Event::InCluster     { .. } => EventKind::InCluster,
        }
    }
}

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Numeric rank, higher = more severe (used for sorting reports).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High     => 3,
            Severity::Medium   => 2,
            Severity::Low      => 1,
            Severity::Info     => 0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        };
        write!(f, "{s}")
    }
}

// ── MITRE ATT&CK for Kubernetes categories ───────────────────────────────────
// Introduced upstream in kube-hunter v0.6.2; every Vulnerability carries one.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackCategory {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Impact,
}

impl AttackCategory {
    /// Upstream-parity display string (matches kube-hunter's category labels).
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackCategory::InitialAccess       => "Initial Access",
            AttackCategory::Execution           => "Execution",
            AttackCategory::Persistence         => "Persistence",
            AttackCategory::PrivilegeEscalation => "Privilege Escalation",
            AttackCategory::DefenseEvasion      => "Defense Evasion",
            AttackCategory::CredentialAccess    => "Credential Access",
            AttackCategory::Discovery           => "Discovery",
            AttackCategory::LateralMovement     => "Lateral Movement",
            AttackCategory::Collection          => "Collection",
            AttackCategory::Impact              => "Impact",
        }
    }

    pub const ALL: &'static [AttackCategory] = &[
        AttackCategory::InitialAccess,
        AttackCategory::Execution,
        AttackCategory::Persistence,
        AttackCategory::PrivilegeEscalation,
        AttackCategory::DefenseEvasion,
        AttackCategory::CredentialAccess,
        AttackCategory::Discovery,
        AttackCategory::LateralMovement,
        AttackCategory::Collection,
        AttackCategory::Impact,
    ];
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Findings ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// KHV vulnerability id (e.g. "KHV050"). "None" when the finding is CVE-only.
    pub vid:         String,
    /// Associated CVE id when applicable (e.g. "CVE-2018-1002105").
    pub cve:         Option<String>,
    pub name:        String,
    pub description: String,
    pub severity:    Severity,
    /// MITRE ATT&CK for Kubernetes category.
    pub category:    AttackCategory,
    /// Name of the hunter that raised this finding.
    pub hunter:      String,
    pub host:        String,
    pub port:        Option<u16>,
    pub evidence:    Option<String>,
}

impl Finding {
    /// Build a finding, looking up canonical title/severity/category from the
    /// KHV knowledge base. `extra` augments the KB description with run-specific
    /// detail; `evidence` is the proof captured by the hunter.
    pub fn khv(
        vid: &str,
        hunter: &str,
        host: impl ToString,
        port: Option<u16>,
        evidence: Option<String>,
    ) -> Self {
        let meta = crate::knowledge_base::lookup(vid);
        Finding {
            vid:         vid.to_string(),
            cve:         None,
            name:        meta.map(|m| m.title.to_string()).unwrap_or_else(|| vid.to_string()),
            description: meta.map(|m| m.description.to_string()).unwrap_or_default(),
            severity:    meta.map(|m| m.severity).unwrap_or(Severity::Info),
            category:    meta.map(|m| m.category).unwrap_or(AttackCategory::Discovery),
            hunter:      hunter.to_string(),
            host:        host.to_string(),
            port,
            evidence,
        }
    }

    /// Override the description (used when a hunter has richer context than the KB).
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Attach a CVE id to the finding.
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve = Some(cve.into());
        self
    }

    /// Override the severity.
    pub fn with_severity(mut self, sev: Severity) -> Self {
        self.severity = sev;
        self
    }
}

// ── Hunter output ─────────────────────────────────────────────────────────────

pub enum Output {
    Finding(Finding),
    Event(Event),
}

// ── Shared context ────────────────────────────────────────────────────────────

pub struct HunterCtx {
    pub mode:           Mode,
    #[allow(dead_code)]
    pub http:           reqwest::Client,  // verifies certs; reserved for authed non-K8s probes
    pub http_insecure:  reqwest::Client,  // accepts invalid certs (anonymous probing)
    pub port_timeout:   std::time::Duration,
    pub custom_ports:   Option<Vec<u16>>,
    /// Bearer token supplied via --service-account-token (impersonate an SA).
    pub sa_token:       Option<String>,
    /// True when scanning local interfaces (gates ARP/DNS-spoof surface hunters).
    pub interface_mode: bool,
}

impl HunterCtx {
    pub fn new(
        mode:         Mode,
        port_timeout: std::time::Duration,
        custom_ports: Option<Vec<u16>>,
    ) -> anyhow::Result<Self> {
        let timeout = std::time::Duration::from_secs(5);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()?;
        let http_insecure = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self {
            mode,
            http,
            http_insecure,
            port_timeout,
            custom_ports,
            sa_token: None,
            interface_mode: false,
        })
    }

    /// Attach runtime scan options (service-account token, interface mode).
    pub fn with_options(mut self, sa_token: Option<String>, interface_mode: bool) -> Self {
        self.sa_token = sa_token;
        self.interface_mode = interface_mode;
        self
    }
}
