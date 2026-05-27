pub mod aks;
pub mod apiserver;
pub mod cves;
pub mod dashboard;
pub mod etcd;
pub mod kubelet;
pub mod mounts;
pub mod proxy;
pub mod secrets;

use std::sync::Arc;
use crate::hunter::Hunter;

pub fn all_hunters() -> Vec<Arc<dyn Hunter>> {
    vec![
        // API server
        Arc::new(apiserver::AnonymousApiAccess),
        Arc::new(apiserver::InsecureApiAccess),
        Arc::new(apiserver::ApiServerRbacInfo),
        // Kubelet
        Arc::new(kubelet::ReadOnlyKubeletPort),
        Arc::new(kubelet::SecureKubeletAnonymous),
        Arc::new(kubelet::KubeletAnonymousRce),
        // etcd
        Arc::new(etcd::EtcdUnauthenticatedAccess),
        // Dashboard
        Arc::new(dashboard::KubeDashboard),
        // Proxy
        Arc::new(proxy::KubeProxyExposed),
        // Secrets
        Arc::new(secrets::ListAllSecrets),
        Arc::new(secrets::ServiceAccountTokenExposed),
        // AKS
        Arc::new(aks::AksInstanceMetadata),
        // CVE hunters
        Arc::new(cves::CveVersionHunter),
        // Active hunters
        Arc::new(mounts::WriteMountToVarLog),
    ]
}
