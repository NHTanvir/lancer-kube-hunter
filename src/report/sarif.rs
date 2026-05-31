use std::collections::BTreeMap;
use serde_json::{json, Value};

use crate::types::{Finding, Severity};

/// Map our severity to a SARIF result level + security-severity score.
fn sarif_level(sev: Severity) -> (&'static str, &'static str) {
    match sev {
        Severity::Critical => ("error",   "9.5"),
        Severity::High     => ("error",   "8.0"),
        Severity::Medium   => ("warning", "5.5"),
        Severity::Low      => ("note",    "3.0"),
        Severity::Info     => ("none",    "0.0"),
    }
}

/// Render findings as a SARIF 2.1.0 document (Trivy / GitHub Code Scanning
/// compatible). Each distinct KHV/CVE id becomes a rule; each finding a result.
pub fn render(findings: &[Finding]) -> anyhow::Result<String> {
    // Collect unique rules keyed by id (vid, falling back to cve).
    let mut rules_map: BTreeMap<String, Value> = BTreeMap::new();
    for f in findings {
        let id = rule_id(f);
        rules_map.entry(id.clone()).or_insert_with(|| {
            let (_, score) = sarif_level(f.severity);
            json!({
                "id": id,
                "name": f.name,
                "shortDescription": { "text": f.name },
                "fullDescription":  { "text": f.description },
                "helpUri": help_uri(f),
                "properties": {
                    "security-severity": score,
                    "category": f.category.as_str(),
                    "tags": ["kubernetes", "security", f.category.as_str()],
                }
            })
        });
    }
    let rules: Vec<Value> = rules_map.into_values().collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let (level, _) = sarif_level(f.severity);
            let location = f.port
                .map(|p| format!("{}:{}", f.host, p))
                .unwrap_or_else(|| f.host.clone());
            json!({
                "ruleId": rule_id(f),
                "level": level,
                "message": { "text": format!("{}: {}", f.name,
                    f.evidence.clone().unwrap_or_else(|| f.description.clone())) },
                "locations": [ {
                    "physicalLocation": {
                        "artifactLocation": { "uri": location }
                    }
                } ],
                "properties": {
                    "vid": f.vid,
                    "cve": f.cve,
                    "category": f.category.as_str(),
                    "hunter": f.hunter,
                }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [ {
            "tool": {
                "driver": {
                    "name": "lancer-kube-hunter",
                    "informationUri": "https://github.com/NHTanvir/lancer-kube-hunter",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
        } ]
    });

    Ok(serde_json::to_string_pretty(&doc)?)
}

fn rule_id(f: &Finding) -> String {
    if f.vid != "None" && !f.vid.is_empty() {
        f.vid.clone()
    } else if let Some(cve) = &f.cve {
        cve.clone()
    } else {
        f.name.clone()
    }
}

fn help_uri(f: &Finding) -> String {
    if let Some(cve) = &f.cve {
        format!("https://nvd.nist.gov/vuln/detail/{cve}")
    } else {
        format!("https://aquasecurity.github.io/kube-hunter/kb/{}.html", f.vid)
    }
}
