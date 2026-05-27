pub mod cluster;
pub mod host;
pub mod ports;
pub mod service;

use std::sync::Arc;
use crate::hunter::Hunter;

pub fn all_hunters() -> Vec<Arc<dyn Hunter>> {
    vec![
        Arc::new(host::FromPodHostDiscovery),
        Arc::new(ports::PortDiscovery),
        Arc::new(service::ServiceDiscovery),
        Arc::new(cluster::KubernetesClusterDiscovery),
    ]
}
