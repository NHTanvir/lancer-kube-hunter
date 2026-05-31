use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, HunterCtx, Mode, Output};

/// K8s standard service ports to scan (API server, etcd, kubelet, proxy, dashboard).
const K8S_PORTS: &[u16] = &[
    443, 2379, 2380, 4443, 6443, 8001, 8080, 8443, 10250, 10255,
];

/// NodePort service range — upstream kube-hunter sweeps 30000-32767.
const NODEPORT_LO: u16 = 30000;
const NODEPORT_HI: u16 = 32767;

/// Build the default port set: the well-known K8s ports plus the NodePort range.
fn default_ports() -> Vec<u16> {
    let mut v: Vec<u16> = K8S_PORTS.to_vec();
    v.extend(NODEPORT_LO..=NODEPORT_HI);
    v
}

pub struct PortDiscovery;

#[async_trait]
impl Hunter for PortDiscovery {
    fn name(&self)          -> &'static str { "PortDiscovery" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::NewHost }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let host = match event.as_ref() {
            Event::NewHost { host } => *host,
            _ => return vec![],
        };

        let default = default_ports();
        let ports: &[u16] = ctx.custom_ports
            .as_deref()
            .unwrap_or(&default);

        scan_ports(host, ports, ctx.port_timeout).await
    }
}

pub async fn scan_ports(host: IpAddr, ports: &[u16], timeout: Duration) -> Vec<Output> {
    let sem = Arc::new(Semaphore::new(256));
    let mut set: JoinSet<Option<u16>> = JoinSet::new();

    for &port in ports {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
                Ok(Ok(_)) => {
                    tracing::info!("  [+] {}:{} open", host, port);
                    Some(port)
                }
                _ => None,
            }
        });
    }

    let mut out = vec![];
    while let Some(res) = set.join_next().await {
        if let Ok(Some(port)) = res {
            out.push(Output::Event(Event::OpenPort { host, port }));
        }
    }
    out
}
