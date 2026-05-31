# lancer-kube-hunter

A Rust clone of Aqua Security's [`kube-hunter`](https://github.com/aquasecurity/kube-hunter) — a Kubernetes attack-surface scanner — with full upstream feature parity **plus a native desktop GUI**. Part of the Lancer ecosystem, a 2026 AI-era bug-bounty toolkit.

Point it at an IP, CIDR, hostname, kubeconfig context, or run it from inside a pod. It discovers exposed Kubernetes services (API server, kubelet, etcd, dashboard, proxy) and probes each for misconfigurations, anonymous access, known CVEs, and exfiltratable data.

## Highlights

- **40+ hunters** across discovery, API server, kubelet, etcd, dashboard, proxy, secrets, cloud-metadata (Azure/AWS), capabilities, and certificates.
- **Full KHV catalog** — every allocated `KHV###` id (41 entries; `KHV008–019`, `KHV035`, `KHV048`, `KHV055–199` are unallocated upstream) with title, severity, and MITRE ATT&CK for Kubernetes category.
- **14 CVEs** detected via version comparison, with downstream-suffix handling (EKS `v`, GKE `-gke.X`, OpenShift `+X`).
- **Passive (default) and active (`--active`)** modes — active hunters write/exploit and clean up after themselves.
- **Report formats:** `plain` (colored table), `json`, `yaml`, `sarif` (Trivy / GitHub Code Scanning), `markdown` (bug-bounty snippet).
- **Dispatchers:** `stdout` (default) and `http` (honors `KUBEHUNTER_HTTP_DISPATCH_URL` / `KUBEHUNTER_HTTP_DISPATCH_METHOD`).
- **Native GUI** (egui/eframe) — three-pane layout, live results table, detail pane, theme persistence, and a local HTTP integration server for the rest of the Lancer suite.

## Usage

The bare invocation opens the **GUI**. Pass `--cli` (or any scan target) for the headless terminal surface.

```bash
# GUI
lancer-kube-hunter

# Scan a remote host (CLI)
lancer-kube-hunter --remote 10.0.0.5

# Scan a CIDR, JSON report
lancer-kube-hunter --cidr 10.0.0.0/24 --report json

# Active scan of a kubeconfig's nodes, SARIF to a collector
lancer-kube-hunter --k8s-auto-discover-nodes --kubeconfig ~/.kube/config \
    --active --report sarif --dispatch http

# List every available test + the KHV knowledge base
lancer-kube-hunter --list --active

# Run the built-in parity self-test
lancer-kube-hunter --self-test
```

### CLI flag matrix (upstream parity)

| Flag | Purpose |
|------|---------|
| `--remote <host>` | Scan a remote IP / hostname (repeatable) |
| `--interface` | Probe the local interface subnet (alias `--internal`) |
| `--cidr <CIDR>` | Scan a CIDR block (repeatable) |
| `--k8s-auto-discover-nodes` | Enumerate nodes via the K8s API |
| `--kubeconfig <path>` | Explicit kubeconfig for auto-discovery |
| `--pod` | Force pod (in-cluster) mode |
| `--quick` | Cloud quick scan (cap subnet to /24) |
| `--active` | Enable active (exploit) hunters |
| `--service-account-token <tok>` | Impersonate a service account |
| `--custom <Hunter...>` | Run only the listed hunters (+ always-on core) |
| `--list` | List available tests (combine with `--active`) |
| `--mapping` | Print discovered node/service map only |
| `--raw-hunter-names` | Use raw class names |
| `--log <LEVEL>` | `DEBUG` / `INFO` / `WARNING` |
| `--report <fmt>` | `plain` / `json` / `yaml` / `sarif` / `markdown` (alias `--output`) |
| `--dispatch <method>` | `stdout` / `http` |
| `--cli` | Force the headless CLI (default opens the GUI) |
| `--self-test` | Run the parity self-test matrix |

## Build

> Builds produce a single static binary. The same binary is both the GUI app and (with `--cli`) the terminal tool.

### Windows
```
build.bat
```
Output: `build\lancer-kube-hunter.exe`. For a packaged dist build: `build-windows.bat` → `dist\lancer-kube-hunter-windows-x86_64\bin\`.

### Linux
```bash
./build-linux.sh
```
Output: `build/lancer-kube-hunter`.

### macOS
```bash
./build-mac.sh
```
Output: `build/lancer-kube-hunter` (plus a `.app` bundle if `cargo-bundle` is installed).

### Requirements
- [Rust / Cargo](https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022

## Lancer integration

While the GUI is open it runs a local HTTP server on `127.0.0.1:<port>` (the port is written to `%TEMP%/lancer-kube-hunter.port`):

- `GET  /v1/state` — current status and finding count
- `POST /v1/import` — accept a target from another Lancer tool
- `GET  /v1/export?format=json|csv|sarif|markdown|yaml` — pull the current result set

## Implementation notes (intentional divergences from upstream)

Parity is measured by behavior — flags, hunters, KHV/CVE coverage, report schemas — not by the exact crate list. A few crates from the original design notes were substituted for equivalents that keep the build lean and portable:

- **Kubernetes access** uses raw `reqwest` + manual kubeconfig parsing rather than the heavyweight `kube`/`k8s-openapi` SDKs (anonymous probing — the whole point — does not benefit from an auth-loaded client).
- **TLS certificate inspection** (KHV021) uses `native-tls` (+ `x509-parser`) to capture the peer certificate.
- **ARP / DNS spoofing** (KHV020 / KHV030) is surfaced as a risk in active interface scans rather than performed live — upstream removed the `scapy` raw-L2 hunters in v0.6.8, and portable raw-L2 probing is out of scope.
- The egui GUI stack replaces the suggested `egui_plot`/`muda`/`egui-notify` add-ons with core egui equivalents (in-window menu bar, severity bars, status line).

Like upstream, this tool does **not** implement CIS Kubernetes Benchmark checks — that is `kube-bench`'s scope.
