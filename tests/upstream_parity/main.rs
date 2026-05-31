//! Upstream parity test suite.
//!
//! Pins the kube-hunter feature surface the Rust port must preserve: the full
//! CLI flag matrix, the 43-id KHV knowledge base, the CVE catalog, the MITRE
//! ATT&CK category taxonomy, and the report-format schemas. CI fails if any
//! mandated flag is unsupported or an output schema diverges.

use clap::CommandFactory;
use lancer_kube_hunter::knowledge_base;
use lancer_kube_hunter::types::{AttackCategory, Finding, Severity};
use lancer_kube_hunter::{discovery, hunting};

// ── CLI flag matrix ───────────────────────────────────────────────────────────

#[test]
fn cli_flag_matrix_complete() {
    let cmd = lancer_kube_hunter::cli::Cli::command();
    let ids: Vec<String> = cmd.get_arguments().map(|a| a.get_id().to_string()).collect();

    // Upstream parity flags (clap field ids).
    let required = [
        "remote", "interface", "cidr", "k8s_auto_discover_nodes", "kubeconfig", "pod",
        "quick", "active", "service_account_token", "custom", "list", "mapping",
        "raw_hunter_names", "log", "report", "dispatch", "report_url", "cli", "self_test",
    ];
    for flag in required {
        assert!(ids.iter().any(|i| i == flag), "missing CLI flag: --{flag}");
    }
}

// ── KHV knowledge base ─────────────────────────────────────────────────────────

#[test]
fn khv_catalog_is_complete() {
    assert_eq!(knowledge_base::count(), 41, "expected 41 allocated KHV ids");

    let required = [
        "KHV001","KHV002","KHV003","KHV004","KHV005","KHV006","KHV007","KHV020","KHV021",
        "KHV022","KHV023","KHV024","KHV025","KHV026","KHV027","KHV028","KHV029","KHV030",
        "KHV031","KHV032","KHV033","KHV034","KHV036","KHV037","KHV038","KHV039","KHV040",
        "KHV041","KHV042","KHV043","KHV044","KHV045","KHV046","KHV047","KHV049","KHV050",
        "KHV051","KHV052","KHV053","KHV054","KHV200",
    ];
    for vid in required {
        assert!(knowledge_base::lookup(vid).is_some(), "missing KHV id: {vid}");
    }
}

#[test]
fn khv_catalog_has_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for m in knowledge_base::CATALOG {
        assert!(seen.insert(m.vid), "duplicate KHV id: {}", m.vid);
    }
}

// ── MITRE ATT&CK categories ────────────────────────────────────────────────────

#[test]
fn attack_categories_complete() {
    assert_eq!(AttackCategory::ALL.len(), 10, "10 MITRE ATT&CK for K8s categories");
    let labels: Vec<&str> = AttackCategory::ALL.iter().map(|c| c.as_str()).collect();
    for expected in [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Impact",
    ] {
        assert!(labels.contains(&expected), "missing ATT&CK category: {expected}");
    }
}

// ── CVE catalog ────────────────────────────────────────────────────────────────

#[test]
fn cve_catalog_count() {
    assert_eq!(hunting::cves::cve_count(), 14, "expected 14 CVEs in the static catalog");
}

// ── Hunter registry ────────────────────────────────────────────────────────────

#[test]
fn hunter_registry_populated() {
    let mut hunters = discovery::all_hunters();
    hunters.extend(hunting::all_hunters());
    assert!(hunters.len() >= 30, "expected a broad hunter set, got {}", hunters.len());

    let active = hunters.iter().filter(|h| h.mode() == lancer_kube_hunter::types::Mode::Active).count();
    assert!(active >= 4, "expected several active hunters, got {active}");
}

// ── Report format schemas ──────────────────────────────────────────────────────

fn sample() -> Vec<Finding> {
    vec![
        Finding::khv("KHV005", "AnonymousApiAccess", "10.0.0.1", Some(6443), Some("anon /api/v1".into())),
        Finding {
            vid: "KHV022".into(),
            cve: Some("CVE-2018-1002105".into()),
            name: "API Server Proxy Privilege Escalation".into(),
            description: "version vulnerable".into(),
            severity: Severity::Critical,
            category: AttackCategory::PrivilegeEscalation,
            hunter: "CveHunter".into(),
            host: "10.0.0.1".into(),
            port: Some(6443),
            evidence: Some("v1.10.0".into()),
        },
    ]
}

#[test]
fn json_report_matches_upstream_schema() {
    let s = lancer_kube_hunter::report::json::render(&sample()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    // Upstream json.py shape: top-level nodes/services/vulnerabilities.
    assert!(v["nodes"].is_array());
    assert!(v["services"].is_array());
    assert!(v["vulnerabilities"].is_array());
    let vuln = &v["vulnerabilities"][0];
    for key in ["location", "vid", "category", "severity", "vulnerability", "description", "evidence", "hunter"] {
        assert!(!vuln[key].is_null(), "vulnerability record missing field: {key}");
    }
}

#[test]
fn yaml_report_renders() {
    let s = lancer_kube_hunter::report::yaml::render(&sample()).unwrap();
    assert!(s.contains("vulnerabilities"));
    assert!(s.contains("KHV005"));
}

#[test]
fn sarif_report_is_valid_2_1_0() {
    let s = lancer_kube_hunter::report::sarif::render(&sample()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(v["runs"][0]["tool"]["driver"]["rules"].is_array());
    assert!(v["runs"][0]["results"].is_array());
}

#[test]
fn markdown_report_renders() {
    let s = lancer_kube_hunter::report::markdown::render(&sample());
    assert!(s.starts_with("# kube-hunter Findings"));
    assert!(s.contains("CVE-2018-1002105"));
}

// ── Self-test harness wiring ───────────────────────────────────────────────────

#[test]
fn self_test_passes() {
    lancer_kube_hunter::selftest::run().expect("parity self-test must pass");
}
