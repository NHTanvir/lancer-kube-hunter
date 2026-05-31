pub mod aks;
pub mod apiserver;
pub mod capabilities;
pub mod certificates;
pub mod cves;
pub mod dashboard;
pub mod etcd;
pub mod kubelet;
pub mod metadata;
pub mod misc;
pub mod mounts;
pub mod proxy;
pub mod secrets;
pub mod spoofing;

use std::sync::Arc;
use crate::hunter::Hunter;

/// Every hunting (vulnerability-probing) hunter, passive and active.
/// The runner filters out `Mode::Active` hunters unless `--active` is set,
/// and `cli` filters by name when `--custom` is provided.
pub fn all_hunters() -> Vec<Arc<dyn Hunter>> {
    vec![
        // ── API server ───────────────────────────────────────────────
        Arc::new(apiserver::AnonymousApiAccess),
        Arc::new(apiserver::InsecureApiAccess),
        Arc::new(apiserver::ApiServerRbacInfo),
        Arc::new(apiserver::ApiServerInfoDisclosure),
        Arc::new(apiserver::ClusterHealthDisclosure),
        Arc::new(apiserver::K8sVersionDisclosureProberOutside),
        Arc::new(apiserver::ListPodsAndNamespaces),
        Arc::new(apiserver::AccessApiServerActive),
        Arc::new(apiserver::CreateANamespace),
        Arc::new(apiserver::DeleteANamespace),
        Arc::new(apiserver::CreateARole),
        Arc::new(apiserver::CreateAClusterRole),
        // ── Kubelet ──────────────────────────────────────────────────
        Arc::new(kubelet::ReadOnlyKubeletPort),
        Arc::new(kubelet::KubeletHandlers),
        Arc::new(kubelet::KubeletContainerLogs),
        Arc::new(kubelet::KubeletExposedCmdline),
        Arc::new(kubelet::KubeletDebugHandlers),
        // ── etcd ─────────────────────────────────────────────────────
        Arc::new(etcd::EtcdRemoteAccess),
        Arc::new(etcd::EtcdRemoteWriteAccessActive),
        // ── Dashboard ────────────────────────────────────────────────
        Arc::new(dashboard::KubeDashboard),
        Arc::new(dashboard::DashboardExposed),
        Arc::new(dashboard::DashboardActive),
        // ── Proxy ────────────────────────────────────────────────────
        Arc::new(proxy::KubeProxy),
        // ── Secrets / SA token ───────────────────────────────────────
        Arc::new(secrets::ListAllSecrets),
        Arc::new(secrets::ListNamespacedSecrets),
        Arc::new(secrets::AccessPodServiceAccountToken),
        // ── Cloud metadata ───────────────────────────────────────────
        Arc::new(aks::AKSInstanceMetadataAPI),
        Arc::new(aks::AzureSpnHunter),
        Arc::new(metadata::AwsMetadataApi),
        // ── Mounts / capabilities / certificates ─────────────────────
        Arc::new(mounts::WriteMountToVarLog),
        Arc::new(capabilities::PrivilegedContainer),
        Arc::new(certificates::CertificateEmail),
        // ── Spoofing surface (active, interface scan) ────────────────
        Arc::new(spoofing::PossibleArpSpoof),
        Arc::new(spoofing::PossibleDnsSpoof),
        // ── Master exec / always-on banner ───────────────────────────
        Arc::new(misc::KubectlExecOnMaster),
        Arc::new(misc::StartedInfo),
        // ── CVE hunter ───────────────────────────────────────────────
        Arc::new(cves::CveVersionHunter),
    ]
}
