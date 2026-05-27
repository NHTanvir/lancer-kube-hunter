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
    NewHost       { host: IpAddr },
    OpenPort      { host: IpAddr, port: u16 },
    ApiServer     { host: IpAddr, port: u16, tls: bool },
    KubeletSecure { host: IpAddr, port: u16 },
    KubeletReadOnly { host: IpAddr, port: u16 },
    Etcd          { host: IpAddr, port: u16 },
    #[allow(dead_code)]
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

// ── Findings ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Info     => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id:          String,
    pub name:        String,
    pub description: String,
    pub severity:    Severity,
    pub host:        String,
    pub port:        Option<u16>,
    pub evidence:    Option<String>,
    pub category:    String,
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
    pub http:           reqwest::Client,  // available for non-K8s probes
    pub http_insecure:  reqwest::Client,
    pub port_timeout:   std::time::Duration,
    pub custom_ports:   Option<Vec<u16>>,
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
        Ok(Self { mode, http, http_insecure, port_timeout, custom_ports })
    }
}
