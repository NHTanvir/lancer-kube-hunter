//! `--self-test` — runs the parity matrix against the bundled reference data and
//! prints pass/fail per feature group. Exits non-zero if any group fails.

use crate::knowledge_base::{self, CATALOG};
use crate::types::{AttackCategory, Finding, Severity};
use crate::{discovery, hunting};

struct Report {
    failures: usize,
    total:    usize,
}

impl Report {
    fn new() -> Self { Report { failures: 0, total: 0 } }

    fn check(&mut self, group: &str, ok: bool, detail: &str) {
        self.total += 1;
        if !ok { self.failures += 1; }
        let mark = if ok { "PASS" } else { "FAIL" };
        println!("  [{mark}] {group}: {detail}");
    }
}

pub fn run() -> anyhow::Result<()> {
    println!("\n=== lancer-kube-hunter parity self-test ===\n");
    let mut r = Report::new();

    // 1. KHV knowledge base (41 allocated ids; 008-019/035/048/055-199 are unallocated upstream).
    r.check("KHV catalog", knowledge_base::count() == 41,
        &format!("{} allocated KHV ids (expected 41)", knowledge_base::count()));

    let expected: &[&str] = &[
        "KHV001","KHV002","KHV003","KHV004","KHV005","KHV006","KHV007","KHV020","KHV021",
        "KHV022","KHV023","KHV024","KHV025","KHV026","KHV027","KHV028","KHV029","KHV030",
        "KHV031","KHV032","KHV033","KHV034","KHV036","KHV037","KHV038","KHV039","KHV040",
        "KHV041","KHV042","KHV043","KHV044","KHV045","KHV046","KHV047","KHV049","KHV050",
        "KHV051","KHV052","KHV053","KHV054","KHV200",
    ];
    let missing: Vec<&str> = expected.iter().copied().filter(|v| knowledge_base::lookup(v).is_none()).collect();
    r.check("KHV coverage", missing.is_empty(),
        &if missing.is_empty() { "all required ids present".into() } else { format!("missing {missing:?}") });

    // 2. MITRE ATT&CK categories.
    r.check("MITRE categories", AttackCategory::ALL.len() == 10,
        &format!("{} ATT&CK categories", AttackCategory::ALL.len()));

    // 3. CVE catalog.
    r.check("CVE catalog", hunting::cves::cve_count() == 14,
        &format!("{} CVEs (expected 14)", hunting::cves::cve_count()));

    // 4. Hunter registry.
    let mut hunters = discovery::all_hunters();
    hunters.extend(hunting::all_hunters());
    let active = hunters.iter().filter(|h| h.mode() == crate::types::Mode::Active).count();
    r.check("Hunter registry", hunters.len() >= 30,
        &format!("{} hunters registered ({active} active)", hunters.len()));

    // 5. Report rendering across all formats.
    let sample = sample_findings();
    let json_ok = crate::report::json::render(&sample).map(|s| s.contains("vulnerabilities")).unwrap_or(false);
    r.check("Report: json", json_ok, "renders upstream-shaped object");

    let yaml_ok = crate::report::yaml::render(&sample).map(|s| s.contains("vulnerabilities")).unwrap_or(false);
    r.check("Report: yaml", yaml_ok, "renders YAML report");

    let sarif_ok = crate::report::sarif::render(&sample)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| v["version"] == "2.1.0")
        .unwrap_or(false);
    r.check("Report: sarif", sarif_ok, "valid SARIF 2.1.0");

    let md = crate::report::markdown::render(&sample);
    r.check("Report: markdown", md.contains("# kube-hunter Findings"), "renders markdown");

    // 6. CLI flag-matrix surface (verified via clap metadata).
    use clap::CommandFactory;
    let cmd = crate::cli::Cli::command();
    let required_flags = [
        "remote","interface","cidr","k8s_auto_discover_nodes","kubeconfig","pod","quick",
        "active","service_account_token","custom","list","mapping","raw_hunter_names",
        "log","report","dispatch","cli","self_test",
    ];
    let present: Vec<&str> = required_flags.iter().copied()
        .filter(|f| cmd.get_arguments().any(|a| a.get_id() == *f))
        .collect();
    r.check("CLI flag matrix", present.len() == required_flags.len(),
        &format!("{}/{} mandated flags present", present.len(), required_flags.len()));

    // Summary.
    println!("\n{} checks, {} failure(s).", r.total, r.failures);
    if r.failures > 0 {
        anyhow::bail!("self-test failed: {} group(s) did not pass", r.failures);
    }
    println!("All parity groups passed.\n");
    Ok(())
}

fn sample_findings() -> Vec<Finding> {
    vec![
        Finding::khv("KHV005", "AnonymousApiAccess", "10.0.0.1", Some(6443), Some("anonymous /api/v1".into())),
        Finding::khv("KHV050", "ListAllSecrets", "10.0.0.1", Some(6443), Some("12 secrets".into())),
        Finding {
            vid: "KHV022".into(),
            cve: Some("CVE-2018-1002105".into()),
            name: "API Server Proxy Privilege Escalation".into(),
            description: "version-vulnerable".into(),
            severity: Severity::Critical,
            category: AttackCategory::PrivilegeEscalation,
            hunter: "CveHunter".into(),
            host: "10.0.0.1".into(),
            port: Some(6443),
            evidence: Some("v1.10.0".into()),
        },
    ]
}

/// Sanity that the catalog has no duplicate ids (used by integration tests).
#[allow(dead_code)]
pub fn catalog_has_duplicates() -> bool {
    let mut seen = std::collections::HashSet::new();
    CATALOG.iter().any(|m| !seen.insert(m.vid))
}
