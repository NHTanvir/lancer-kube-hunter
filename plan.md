# RESEARCH DOSSIER: kube-hunter

> Part of the Lancer ecosystem. A Rust clone of Aqua Security's kube-hunter — Kubernetes attack-surface scanner. Build with Claude Code.
> Upstream: github.com/aquasecurity/kube-hunter (Python, in maintenance since 2023). ~40 hunters, ~80 KHV vulnerability IDs.

## Feature Parity Mandate

**`lancer-kube-hunter` MUST ship with 100% feature parity to the upstream `kube-hunter` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `kube-hunter --help` (and the long-form man page / docs) must work in `lancer-kube-hunter --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-kube-hunter` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-kube-hunter --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

kube-hunter is Aqua Security's **Kubernetes attack-surface scanner**. Run it against an IP, CIDR, kubeconfig context, or from inside a pod, and it discovers exposed K8s services (API server, kubelet, etcd, dashboard, proxy) then probes each for misconfigurations, anonymous access, known CVEs, and exfiltratable data. **Two modes**: *passive* (default — read-only) and *active* (`--active` — writes/exploits). ~40 hunters, ~80 KHV vulnerability IDs catalogued. Python. Output: stdout table, JSON, or POST to a collector URL. Modern alternative is Trivy's k8s scanning, but kube-hunter remains the canonical *external* scanner.

## Internal architecture

```
kube_hunter/
  __main__.py
  core/
    types/
      __init__.py
      hunters.py            # HunterBase, Hunter, ActiveHunter, Discovery
      components.py         # Service, RemoteCodeExec, etc.
      vulnerabilities.py    # Vulnerability subclasses (severity-tagged)
    events/
      handler.py            # Event bus: @handler.subscribe(EventType)
      types.py              # NewHostEvent, OpenPortEvent, K8sVersionDisclosure, ...
    pubsub/
      subscription.py
  modules/
    discovery/              # passive discovery
      hosts.py              # HostDiscovery + FromPodHostDiscovery
      ports.py              # PortDiscovery
      kubernetes_client.py  # ApiServiceDiscovery
      apiserver.py
      etcd.py
      kubelet.py
      dashboard.py
      proxy.py
    hunting/                # vulnerability probing
      aks.py
      apiserver.py          # KHV005/006/007 + auth/RBAC probes
      capabilities.py
      certificates.py
      cves.py               # CVE-2018-1002105, CVE-2019-9512/9514, CVE-2019-11247...
      dashboard.py
      etcd.py
      kubelet.py            # KHV052 KHV053 KHV054 ...
      mounts.py
      proxy.py
      secrets.py
    report/                 # output handlers
      collector.py
      dispatchers.py
      plain.py
      json.py
      yaml.py
  conf/
    log.py
```

**The event bus pattern is everything.** Hunters don't call each other; they publish events. Subscribers process events. A new IP triggers `NewHostEvent` → port scanner fires → emits `OpenPortEvent` → API server hunter fires → emits `K8sVersion` → CVE hunter fires.

**Hunter base classes** (`core/types/hunters.py`):
```python
class HunterBase:
    publishedVulnerabilities = 0
    @classmethod
    def parse_docs(cls): ...     # extract name/desc from docstring
    @classmethod
    def get_name(cls): ...
    def publish_event(self, event): ...

class Discovery(HunterBase): pass       # passive discovery
class Hunter(HunterBase): pass          # passive vulnerability check
class ActiveHunter(HunterBase): pass    # active exploit attempt
```

**Registration via decorator:**
```python
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 6443)
class ApiServer(Hunter):
    def __init__(self, event):
        self.event = event
    def execute(self):
        # probe self.event.host:6443
        if vulnerable:
            self.publish_event(Vulnerability(...))
```

The `handler` module maintains `subscribers: Dict[Type[Event], List[Hunter]]`. When `publish_event(e)` is called, it iterates `subscribers[type(e)]`, filters by predicate, and spawns a `threading.Thread` per matching hunter. Concurrency = thread per event, max-out at thread pool limit.

**Modes:**
- **Remote** (`--remote 1.2.3.4`) — scan from outside, against an IP.
- **Internal / Interface** (`--interface`) — scan all local network interfaces.
- **Network** (`--cidr 10.0.0.0/24`) — scan a CIDR.
- **Pod** (auto when running in a pod, K8s API discovers nodes) — uses `KUBERNETES_SERVICE_HOST` env var.
- **K8s auto-discover** (`--k8s-auto-discover-nodes`) — query the K8s API for nodes and add them as targets (works with `--kubeconfig <path>`).
- **Quick** (`--quick`) — in cloud environments, cap subnet scanning to a /24 CIDR (avoid scanning the entire VPC).
- **Active** (`--active`) — enables ActiveHunter subclasses (exploit attempts, may mutate cluster state).
- **Custom** (`--custom Hunter1 Hunter2 ...`) — whitelist a subset of hunters; only those run plus the always-on discovery/report core.

### Full CLI flag matrix (upstream parity)

| Flag | Purpose |
|------|---------|
| `--remote <host>` | Scan a single remote IP / hostname |
| `--interface` | Probe all local network interfaces |
| `--cidr <CIDR>` | Scan a CIDR block |
| `--k8s-auto-discover-nodes` | Use K8s API to enumerate nodes |
| `--kubeconfig <path>` | Explicit kubeconfig (for auto-discover) |
| `--pod` | Force pod mode |
| `--quick` | Cloud quick scan (limit to /24) |
| `--active` | Enable ActiveHunter classes (exploit) |
| `--service-account-token <token>` | Impersonate a specific SA |
| `--custom <Hunter...>` | Run only listed hunters (+ always-on core) |
| `--list` | List all available tests; combine with `--active` to include active tests |
| `--mapping` | Print discovered node network mapping only (no vulnerability output) |
| `--raw-hunter-names` | Use raw Python class names instead of docstring names |
| `--log <LEVEL>` | `DEBUG` / `INFO` (default) / `WARNING` |
| `--report <format>` | `plain` (default) / `json` / `yaml` |
| `--dispatch <method>` | `stdout` (default) / `http` |

**Always-on modules** (registered even when `--custom` is in effect):
- `HostDiscovery`, `FromPodHostDiscovery`, `PortDiscovery` (discovery seeds)
- `Collector` (gathers events into the report)
- `StartedInfo` (emits the run banner / metadata header)
- `SendFullReport` (terminal flush of the assembled report through the active dispatcher)

### Environment variables

- `KUBEHUNTER_HTTP_DISPATCH_URL` — collector endpoint when `--dispatch http` is selected.
- `KUBEHUNTER_HTTP_DISPATCH_METHOD` — HTTP verb (`POST` default).
- `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` — auto-trigger pod mode when set.

## Hunter catalog

**Discovery hunters (always-on, passive)**
- `HostDiscovery` — generates target IPs from CLI args
- `FromPodHostDiscovery` — when in-pod, calls K8s API for nodes
- `PortDiscovery` — port-scans known K8s ports (443, 6443, 8443, 8080, 8001, 10250, 10255, 2379, 2380, 4443, 30000-32767)
- `ApiServiceDiscovery` — identifies API server vs kubelet vs etcd vs dashboard by probing
- `KubernetesClusterDiscovery` — fingerprints K8s version (used by CVE hunters)

**Service-specific hunters (modules/hunting/*.py)**

`apiserver.py`: `AccessApiServerActive` (KHV005), `AccessApiServerInsecureViaHttp` (KHV006), `ApiServerPassiveHunterFinished` (KHV007), `CreateANamespace`/`DeleteANamespace` (active), `CreateARole`/`CreateAClusterRole` (active), `ListNamespacedSecrets`/`ListAllSecrets`, `ListPodsAndNamespaces`, `K8sVersionDisclosureProberOutside`.

`kubelet.py`: `ReadOnlyKubeletPortHunter` (KHV052), `SecureKubeletPortHunter` (KHV053), `KubeletHandlers` (`/runningpods`, `/spec`, `/metrics`, `/logs`), `KubeletDebugHandlers` (KHV054 — Anonymous Kubelet RCE), `KubeletPortForwardActive`, `KubeletContainerLogs`, `KubeletExposedCmdline`.

`etcd.py`: `EtcdRemoteAccessActive`, `EtcdRemoteWriteAccessActive` (active), `EtcdRemoteVersionDisclosure`.

`dashboard.py`: `KubeDashboard` (KHV029), `DashboardActive`.

`proxy.py`: `KubeProxy` (KHV049).

`cves.py`: full CVE catalog — see below.

`aks.py`: `AzureSpnHunter`, `AKSInstanceMetadataAPI`.

`mounts.py`: `WriteMountToVarLog` (active).

`secrets.py`: `AccessSecrets` (KHV050), `AccessPodServiceAccountToken`.

`capabilities.py`: detects SYS_ADMIN, SYS_PTRACE, etc. via cgroup inspection.

`certificates.py`: examines TLS certs of API server for misconfigurations.

## CVE catalog (covered by `modules/hunting/cves.py` + extensions)

| CVE | Description | Affected | Detection |
|-----|-------------|----------|-----------|
| CVE-2018-1002105 | API server proxy privilege escalation | <1.10.11, <1.11.5, <1.12.3 | Version check from `/version` |
| CVE-2019-1002100 | DoS via JSON-patch | <1.11.8, <1.12.6, <1.13.4 | Version check |
| CVE-2019-9512 | HTTP/2 Ping flood DoS | <1.13.10, <1.14.6, <1.15.3 | Version check |
| CVE-2019-9514 | HTTP/2 Reset flood DoS | <1.13.10, <1.14.6, <1.15.3 | Version check |
| CVE-2019-11247 | Cluster-scoped resource access | <1.13.9, <1.14.5, <1.15.2 | Version check |
| CVE-2019-1002101 | kubectl cp path traversal | kubectl <1.11.9 etc. | Kubectl version |
| CVE-2019-11246 | Incomplete fix to above | kubectl <1.12.9 etc. | Kubectl version |
| CVE-2020-8554 | MITM via Service ExternalIPs | All (pre-mitigation) | Probe API server for ExternalIP permission |
| CVE-2020-8559 | Privilege escalation via API redirect | <1.16.13 | Version check |
| CVE-2020-8557 | /etc/hosts writable from container (DoS) | <1.16.13 | — |
| CVE-2021-25741 | Subpath symlink container escape | <1.19.16 | Version check |
| CVE-2021-25737 | Endpoint redirect HTTP body smuggling | <1.19.16 | — |
| CVE-2022-3172 | Aggregated API request forwarding | <1.25.4 | Version check |
| CVE-2024-3177 | Bypass mountable secrets restriction | <1.29.4 | Version check |

## Engineering hard parts

**In-pod detection:** check for `KUBERNETES_SERVICE_HOST` env var + presence of `/var/run/secrets/kubernetes.io/serviceaccount/token`. If both present, switch to pod mode: use the SA token for API calls.

**SA token handling:**
```rust
fn detect_in_cluster() -> Option<InClusterCreds> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
    let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").ok()?;
    let ca = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok()?;
    Some(InClusterCreds { host, port, token, ca })
}
```

**Active vs passive separation:** every Hunter struct in Rust carries a `Mode` (`Passive` | `Active`). The runner iterates only matching hunters. Rust trait:
```rust
trait Hunter: Send + Sync {
    fn name(&self) -> &'static str;
    fn mode(&self) -> Mode;
    fn subscribes_to(&self) -> EventTypeId;
    fn predicate(&self, event: &Event) -> bool { true }
    async fn execute(&self, ctx: Arc<HunterCtx>, event: Event) -> Vec<Finding>;
}
```

**Event bus in Rust:** use `tokio::sync::broadcast::channel` for events. Each hunter subscribes by spawning a task that filters incoming events by type. Or simpler: `Arc<DashMap<EventTypeId, Vec<Box<dyn Hunter>>>>` + dispatch loop. Inventory crate registers hunters at startup.

**Port scanning:** k8s standard ports baked in. Use `tokio::net::TcpStream::connect` with timeout (1-2s). For CIDR sweep, parallelize via `JoinSet` with semaphore (max 256 concurrent connects).

**Version comparison:** semver crate `semver = "1.0"`; vendor downstream version quirks (EKS prepends `v`, GKE has `-gke.X` suffix, OpenShift has `+X`). Strip suffixes before parse.

**TLS probing:** `rustls` + `tokio-rustls` for raw TLS handshakes. API server cert SAN names hint at install method.

## Rust library mapping

```toml
[dependencies]
# Kubernetes
kube = { version = "3.1", features = ["runtime", "derive", "ws"] }
k8s-openapi = { version = "0.27", features = ["latest"] }

# Networking
tokio = { version = "1.40", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls", "stream"] }
rustls = "0.23"
tokio-rustls = "0.26"
hickory-resolver = "0.24"

# CIDR / IP
ipnet = "2.10"
cidr = "0.2"

# Event bus + concurrency
inventory = "0.3"
dashmap = "6"

# Version comparison
semver = "1.0"
regex = "1.10"

# Output
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
comfy-table = "7"
colored = "2"
clap = { version = "4.5", features = ["derive"] }

# CVE DB
phf = { version = "0.11", features = ["macros"] }  # static CVE map
```

## SDK-specific gotchas

- **kube::Client::try_default()** does the right thing: reads `~/.kube/config` if present, otherwise tries in-cluster. But for *anonymous probing* (the whole point of kube-hunter), do NOT use the auth-loaded client. Issue raw `reqwest` GETs without auth headers to `/api/v1`, `/version`, `/healthz`.
- **`k8s-openapi` feature flags**: `v1_31` (latest) gives type definitions for K8s 1.31+. Use `latest` feature to track the most recent.
- **Cross-namespace operations:** `Api::all(client)` lists across namespaces.
- **WebSocket exec:** kubelet's `/exec` is WebSocket-based; need `kube`'s `ws` feature.
- **HTTP/2 raw probes** (CVE-2019-9512 ping flood detection): not directly supported by reqwest's high-level API. For DoS *probing* (not exploitation), use version check instead. For actually checking the vuln (which kube-hunter doesn't do — only version-checks), use `h2` crate directly.
- **Service account token JWT:** validate format only — don't try to decode/verify signature. Bearer-token usage is `Authorization: Bearer <token>`.

## Vulnerability ID catalog (KHV###)

Partial list (from source + kube-hunter docs):
- KHV001 Information Disclosure
- KHV002 Kubernetes Version Disclosure
- KHV003 K8s API Anonymous Access
- KHV004 Cluster Health Disclosure
- KHV005 Access to API server via service account token
- KHV006 Insecure HTTP API access (port 8080)
- KHV007 K8s API Information Disclosure via RBAC
- KHV020 Possible Arp Spoofing
- KHV021 CoreDNS Poisoning
- KHV029 Kubernetes Dashboard
- KHV031 Container with privileged
- KHV034 Privileged Container
- KHV036 Read access to pod's service account token
- KHV038 Validation of K8s ApiServer ConfigMap
- KHV041 Access to Kubernetes API via Insecure Port
- KHV044 K8s API Server uses an Anonymous Auth (which is the default)
- KHV049 Exposed Kubernetes Proxy
- KHV050 Access to Pod's Secrets
- KHV051 K8s CronJob Privilege Escalation
- KHV052 Exposed Read-Only Kubelet Port
- KHV053 Anonymous Access to Cluster
- KHV054 Anonymous Access to Kubelet (RCE via /exec, /run)
- KHV200 Cluster admin via kubectl exec on master pod

### Full KHV catalog (knowledge-base parity — source: aquasecurity.github.io/kube-hunter/kbindex.html)

| VID | Title |
|-----|-------|
| KHV001 | Information Disclosure |
| KHV002 | Kubernetes Version Disclosure |
| KHV003 | Azure Metadata Exposure |
| KHV004 | Azure SPN Exposure |
| KHV005 | Access to Kubernetes API (anonymous / over-permissive) |
| KHV006 | Insecure (HTTP) access to Kubernetes API |
| KHV007 | Specific Access to Kubernetes API (RBAC info disclosure) |
| KHV020 | Possible ARP Spoof |
| KHV021 | Certificate Includes Email Address |
| KHV022 | Critical Privilege Escalation CVE |
| KHV023 | Denial of Service to Kubernetes API Server |
| KHV024 | Possible Ping Flood Attack (CVE-2019-9512) |
| KHV025 | Possible Reset Flood Attack (CVE-2019-9514) |
| KHV026 | Arbitrary Access To Cluster Scoped Resources (CVE-2019-11247) |
| KHV027 | Kubectl Vulnerable To CVE-2019-11246 |
| KHV028 | Kubectl Vulnerable To CVE-2019-1002101 |
| KHV029 | Dashboard Exposed |
| KHV030 | Possible DNS Spoof |
| KHV031 | Etcd Remote Write Access Event |
| KHV032 | Etcd Remote Read Access Event |
| KHV033 | Etcd Remote Version Disclosure |
| KHV034 | Etcd Accessible via Insecure Connection (HTTP) |
| KHV036 | Anonymous Authentication |
| KHV037 | Exposed Container Logs |
| KHV038 | Exposed Running Pods |
| KHV039 | Exposed Exec On Container |
| KHV040 | Exposed Run Inside Container |
| KHV041 | Exposed Port Forward |
| KHV042 | Exposed Attaching To Container |
| KHV043 | Cluster Health Disclosure |
| KHV044 | Privileged Container |
| KHV045 | Exposed System Logs |
| KHV046 | Exposed Kubelet Cmdline |
| KHV047 | Pod With Mount To /var/log |
| KHV049 | kubectl proxy Exposed |
| KHV050 | Read access to Pod Service Account Token |
| KHV051 | Exposed Existing Privileged Containers Via Secure Kubelet Port |
| KHV052 | Exposed Pods (via read-only kubelet port) |
| KHV053 | AWS Metadata Exposure |
| KHV054 | Anonymous Access to Kubelet (RCE via /exec, /run) |
| KHV200 | Cluster Admin via `kubectl exec` on Master Pod |

(IDs KHV008–KHV019, KHV035, KHV048, and the KHV055–KHV199 range are intentionally unallocated in upstream's KB.)

## MITRE ATT&CK for Kubernetes (added v0.6.2)

Since v0.6.2 (Oct 2023), kube-hunter tags every finding with a Kubernetes ATT&CK category. The Rust port MUST emit the same `category` field on every `Vulnerability` record. Upstream categories used:

- `Initial Access` — e.g., exposed dashboard, anonymous API.
- `Execution` — kubelet `/exec`, `/run`, pod exec.
- `Persistence` — privileged container, mount to `/var/log`.
- `Privilege Escalation` — cluster-admin via API, CronJob abuse.
- `Defense Evasion` — log tampering paths.
- `Credential Access` — SA token read, secrets enumeration, etcd dump.
- `Discovery` — version / pods / namespaces / health endpoints.
- `Lateral Movement` — exposed kubelet, port-forward, attach.
- `Collection` — container log access.
- `Impact` — DoS CVEs, etcd write, namespace delete.

Each Rust `Vulnerability` struct carries `category: AttackCategory` + `severity` + `vid` + optional `cve`.

## Reporting & dispatch (full upstream parity)

**Report formats** (`--report`):
- `plain` (default) — terminal table, colored via `comfy-table` + `colored`.
- `json` — machine-readable; schema must match upstream's `kube_hunter/modules/report/json.py`.
- `yaml` — same schema, YAML-encoded.

**Dispatchers** (`--dispatch`):
- `stdout` (default) — write the rendered report to terminal.
- `http` — POST/PUT the rendered report (in the chosen format) to `KUBEHUNTER_HTTP_DISPATCH_URL` using `KUBEHUNTER_HTTP_DISPATCH_METHOD`.

**Lancer-specific add-on (not upstream, allowed-to-add):**
- `sarif` — Trivy/GitHub Code Scanning compatible.
- `markdown` — bug-bounty report snippet.

## CIS Kubernetes Benchmark — explicit non-goal (upstream parity)

Upstream kube-hunter does **not** implement CIS Kubernetes Benchmark checks — that is the explicit job of `kube-bench` (also Aqua Security). To preserve parity, `lancer-kube-hunter` likewise does NOT ship CIS controls. Users who want CIS coverage are pointed at the future `lancer-kube-bench` companion clone. Documenting this gap so reviewers don't file it as missing scope.

## Upstream release history (v0.5.2 → v0.6.8)

| Version | Date | Notable change |
|---------|------|----------------|
| v0.5.2 | 2023-06-10 | K8s node autodiscovery from pod environments |
| v0.6.0 | 2023-07-22 | `--service-account-token` flag |
| v0.6.1 | 2023-07-23 | Gateway discovery always runs in pod mode |
| v0.6.2 | 2023-10-16 | Vulnerability categories refactored → MITRE ATT&CK for K8s |
| v0.6.3 | 2023-10-16 | CVE hunting made optional (off by default; opt-in flag) |
| v0.6.4 | 2024-01-22 | HTTPS cert verification fixes; metadata API error handling |
| v0.6.5 | 2024-01-28 | Custom hunting (`--custom`) for selective hunter execution |
| v0.6.6 | 2024-05-07 | Begin removing `scapy` dependency |
| v0.6.8 | 2024-05-18 | Final `scapy` removal (GPL2 license concern); handler import fix |

**Maintenance status (2025-2026):** no further upstream releases. Aqua's K8s security focus is now Trivy + Tracee. The Rust port should follow upstream v0.6.8 as the parity baseline.

## 2024-2026 state

- kube-hunter has been in maintenance mode since 2023. Aqua's focus is Trivy + Tracee.
- No major releases in 2025-2026.
- This makes the clone opportunity *better* — modernize what's stalled. Add: post-2022 CVEs, eBPF-based hunters (in-cluster), CSI Driver / OPA Gatekeeper checks, KEDA / Argo CD exposure checks.

### 2026-05-30 deep-research note

Cross-checked the existing dossier against upstream README, GitHub releases, and the published KHV knowledge base.

**Confirmed:** v0.6.8 (2024-05-18) remains the most recent release; no v0.7.x cut in 2025-2026. Upstream is effectively frozen.

**Gaps filled into this plan:**
- Complete CLI flag matrix — added `--interface`, `--k8s-auto-discover-nodes`, `--kubeconfig`, `--quick`, `--service-account-token`, `--custom`, `--list`, `--mapping`, `--raw-hunter-names`, `--log`, `--report`, `--dispatch`.
- Always-on module trio — `Collector`, `StartedInfo`, `SendFullReport` (registered even under `--custom`).
- Environment variables — `KUBEHUNTER_HTTP_DISPATCH_URL`, `KUBEHUNTER_HTTP_DISPATCH_METHOD`.
- Full KHV knowledge-base table (KHV001–KHV054, KHV200) including the cloud-metadata IDs (KHV003 Azure metadata, KHV004 Azure SPN, KHV053 AWS metadata) and the ARP/DNS spoofing IDs (KHV020, KHV030).
- MITRE ATT&CK for Kubernetes category mapping (introduced upstream in v0.6.2) — every finding now carries an `AttackCategory`.
- Reporting / dispatcher matrix — `plain` / `json` / `yaml` × `stdout` / `http`.
- Upstream release-history table (v0.5.2 → v0.6.8) with one-line change summaries.

**Explicit non-goal documented:** CIS Kubernetes Benchmark — upstream kube-hunter does NOT do CIS (that's `kube-bench`'s scope); to preserve byte-equivalent parity the Rust port likewise omits CIS. CIS coverage is deferred to the future `lancer-kube-bench` companion clone.

**No content was deleted** during this update — only additive.

## Validation environment

- **`kind`** (`kind create cluster`) — instant local K8s.
- **Intentionally vulnerable clusters:** `kubernetesgoat/Kubernetes-Goat`, `madhuakula/kubernetes-goat`.
- **`minikube --extra-config=apiserver.anonymous-auth=true`** to test KHV003/005.
- **`bustakube`** — purpose-built vulnerable k8s lab.
- **Real cloud K8s sandboxes:** GKE/EKS/AKS free tiers with insecure defaults.

## Real-world authorized usage

K8s programs on H1/Bugcrowd (e.g., Shopify, GitLab) routinely allow kube-hunter scans of their public-facing K8s endpoints. Read-only/passive mode is universally OK; **active mode requires explicit permission**. Many programs expect:
1. CIDR scope from the program.
2. Passive scan first.
3. Detailed VID/CVE reference in the report.
4. PoC for any FAIL — but only data-disclosure PoC, never destructive.

For pod-mode usage (e.g., when the bounty includes "you got RCE in a pod, escalate"): always run in `--active` is fine because you're already inside. Capture session log.

## AI augmentation ideas

- **Exploit chain narrator:** given a set of findings (e.g., KHV049 + KHV050 + KHV003), LLM constructs a kill-chain narrative suitable for the bug report.
- **CVE relevance ranker:** for the discovered K8s version, LLM scores active CVEs by exploit availability.
- **Cluster hardening recommendations:** turn findings into Kustomize/Helm patch suggestions.
- **Trivy/Falco rule generation:** for each finding, generate a detection rule.

## Implementation phases (12 weeks)

| Week | Deliverable |
|------|-------------|
| 1 | Repo skeleton, CLI (clap) with remote/internal/cidr/pod modes, event bus with broadcast channel |
| 2 | `HostDiscovery`, `PortDiscovery` (tokio TCP), `ApiServiceDiscovery` (probe well-known ports) |
| 3 | `KubernetesClusterDiscovery` (fingerprint via `/version`), version comparator, CVE static DB |
| 4 | API server hunters: anonymous access (KHV005), insecure HTTP (KHV006), RBAC info disclosure (KHV007) |
| 5 | Kubelet hunters: read-only port (KHV052), secure port anonymous (KHV053), exec/run RCE (KHV054) |
| 6 | etcd, dashboard, proxy hunters (KHV029, KHV049, etcd anonymous access) |
| 7 | Secrets enumeration (KHV050), SA token reading (KHV036), AKS instance-metadata hunter |
| 8 | CVE hunters: 2018-1002105, 2019-9512/9514/11247, 2019-1002100 |
| 9 | Modern CVEs: 2020-8554, 2020-8559, 2021-25741, 2022-3172, 2024-3177 |
| 10 | Active hunters: CreateNamespace, CreateClusterRole, EtcdRemoteWriteAccess, Kubelet exec |
| 11 | In-pod mode auto-detect, SA token bearer auth, FromPodHostDiscovery, mounts checks |
| 12 | Report dispatchers (stdout/JSON/YAML/HTTP), Trivy-compatible SARIF export, benchmark vs upstream kube-hunter |

---

## GUI (Lancer-standard pattern)

`lancer-kube-hunter` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-kube-hunter-cli` companion binary), but the **plain `lancer-kube-hunter` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-kube-hunter/`, `%APPDATA%\lancer-kube-hunter\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-kube-hunter-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-kube-hunter.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-kube-hunter.exe` (double-click opens the GUI window).
- Linux: `build/lancer-kube-hunter` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-kube-hunter` (bundled into `lancer-kube-hunter.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-kube-hunter/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-kube-hunter.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-kube-hunter-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-kube-hunter
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-kube-hunter.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-kube-hunter-windows-x86_64\bin\lancer-kube-hunter.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-kube-hunter`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
