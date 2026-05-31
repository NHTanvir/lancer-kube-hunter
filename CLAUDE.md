# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-kube-hunter` — A Rust clone of Aqua Security's `kube-hunter`, a Kubernetes attack-surface scanner, with full upstream feature parity plus a native desktop GUI. It discovers exposed Kubernetes services (API server, kubelet, etcd, dashboard, proxy) and probes each for misconfigurations, anonymous access, known CVEs, and exfiltratable data. Part of the Lancer ecosystem, a 2026 AI-era bug-bounty toolkit.

## Architecture

- `src/main.rs` — Binary entry point; dispatches to GUI or CLI based on flags.
- `src/lib.rs` — Library entry point; re-exports public API for the crate.
- `src/cli.rs` — CLI surface; clap-derived argument parsing and flag matrix.
- `src/types.rs` — Shared domain types (findings, severities, KHV IDs, etc.).
- `src/hunter.rs` — Core `Hunter` trait and hunter registry.
- `src/runner.rs` — Scan orchestration; fan-out dispatch of hunters and result collection.
- `src/scan.rs` — Scan session state and target resolution.
- `src/knowledge_base.rs` — Full KHV catalog (41 entries) with titles, severities, and MITRE ATT&CK mappings.
- `src/version.rs` — Kubernetes version parsing with downstream-suffix handling (EKS, GKE, OpenShift).
- `src/selftest.rs` — Parity self-test matrix (`--self-test` flag).
- `src/discovery/` — Host/cluster/port/service discovery modules (`host.rs`, `cluster.rs`, `ports.rs`, `service.rs`).
- `src/hunting/` — 40+ hunter implementations: `apiserver.rs`, `kubelet.rs`, `etcd.rs`, `dashboard.rs`, `proxy.rs`, `secrets.rs`, `certificates.rs`, `cves.rs`, `capabilities.rs`, `metadata.rs`, `mounts.rs`, `spoofing.rs`, `misc.rs`, `aks.rs`.
- `src/report/` — Report formatters: `table.rs` (plain/colored), `json.rs`, `yaml.rs`, `sarif.rs`, `markdown.rs`, `http.rs`.
- `src/gui/` — egui/eframe desktop GUI (`mod.rs`, `server.rs`); three-pane layout with live results, detail pane, theme persistence, and local HTTP integration server.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is driven by egui/eframe; the same binary serves both GUI (default) and headless CLI (`--cli` or any scan target).
- Library code lives in `src/lib.rs`; binary entry point in `src/main.rs`.
- Hunters implement the `Hunter` trait in `src/hunter.rs`; active hunters must clean up after themselves.
- Report formats are selected via `--report` (`plain` / `json` / `yaml` / `sarif` / `markdown`); dispatchers via `--dispatch` (`stdout` / `http`).
- CVE detection uses semantic version comparison via the `semver` crate, with downstream-suffix stripping for EKS, GKE, and OpenShift variants.

## Build / test / run

```
build.bat                   # Windows → build\lancer-kube-hunter.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
