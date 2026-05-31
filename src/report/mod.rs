pub mod http;
pub mod json;
pub mod markdown;
pub mod sarif;
pub mod table;
pub mod yaml;

use std::collections::BTreeSet;
use serde_json::{json, Value};

use crate::types::Finding;

/// Output format selected via `--report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Plain,
    Json,
    Yaml,
    Sarif,
    Markdown,
}

impl Format {
    pub fn parse(s: &str) -> Format {
        match s.to_ascii_lowercase().as_str() {
            "json"            => Format::Json,
            "yaml" | "yml"    => Format::Yaml,
            "sarif"           => Format::Sarif,
            "markdown" | "md" => Format::Markdown,
            _                 => Format::Plain,
        }
    }

    fn content_type(&self) -> &'static str {
        match self {
            Format::Json     => "application/json",
            Format::Yaml     => "application/x-yaml",
            Format::Sarif    => "application/sarif+json",
            Format::Markdown => "text/markdown",
            Format::Plain    => "text/plain",
        }
    }
}

/// Dispatch method selected via `--dispatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    Stdout,
    Http,
}

impl Dispatch {
    pub fn parse(s: &str) -> Dispatch {
        match s.to_ascii_lowercase().as_str() {
            "http" => Dispatch::Http,
            _      => Dispatch::Stdout,
        }
    }
}

/// Render `findings` in `format` and route them through the chosen dispatcher.
/// `explicit_url` is the optional --report-url override; the http dispatcher also
/// reads KUBEHUNTER_HTTP_DISPATCH_URL / KUBEHUNTER_HTTP_DISPATCH_METHOD.
pub async fn dispatch(
    findings:     &[Finding],
    format:       Format,
    dispatch:     Dispatch,
    explicit_url: Option<&str>,
) -> anyhow::Result<()> {
    // Render once into a string (plain renders to a colored terminal table directly).
    let rendered: Option<String> = match format {
        Format::Plain    => { if dispatch == Dispatch::Stdout { table::print(findings); } None }
        Format::Json     => Some(json::render(findings)?),
        Format::Yaml     => Some(yaml::render(findings)?),
        Format::Sarif    => Some(sarif::render(findings)?),
        Format::Markdown => Some(markdown::render(findings)),
    };

    match dispatch {
        Dispatch::Stdout => {
            if let Some(s) = &rendered {
                println!("{s}");
            }
        }
        Dispatch::Http => {
            // For http dispatch of the plain format, send the JSON representation.
            let body = match &rendered {
                Some(s) => s.clone(),
                None    => json::render(findings)?,
            };
            let ct = if format == Format::Plain { "application/json" } else { format.content_type() };
            http::dispatch_http(&body, ct, explicit_url).await?;
        }
    }

    // A --report-url override always also POSTs, regardless of dispatcher, for
    // backwards compatibility with the collector workflow.
    if dispatch != Dispatch::Http {
        if let Some(url) = explicit_url {
            let body = rendered.clone().unwrap_or(json::render(findings)?);
            let ct = if format == Format::Plain { "application/json" } else { format.content_type() };
            http::dispatch_http(&body, ct, Some(url)).await?;
        }
    }

    Ok(())
}

/// Build the upstream-shaped report object: { kube-hunter-version, nodes,
/// services, vulnerabilities } — matching kube_hunter/modules/report/json.py.
pub fn report_value(findings: &[Finding]) -> Value {
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut services: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        nodes.insert(f.host.clone());
        if let Some(p) = f.port {
            services.insert(format!("{}:{}", f.host, p));
        }
    }

    let nodes_json: Vec<Value> = nodes
        .iter()
        .map(|h| json!({ "type": "Node/Master", "location": h }))
        .collect();

    let services_json: Vec<Value> = services
        .iter()
        .map(|s| json!({ "service": "Kubernetes Service", "location": s }))
        .collect();

    let vulns: Vec<Value> = findings
        .iter()
        .map(|f| json!({
            "location":      f.port.map(|p| format!("{}:{}", f.host, p)).unwrap_or_else(|| f.host.clone()),
            "vid":           f.vid,
            "cve":           f.cve,
            "category":      f.category.as_str(),
            "severity":      f.severity.to_string().to_lowercase(),
            "vulnerability": f.name,
            "description":   f.description,
            "evidence":      f.evidence.clone().unwrap_or_default(),
            "hunter":        f.hunter,
        }))
        .collect();

    json!({
        "kube-hunter-version": env!("CARGO_PKG_VERSION"),
        "nodes":           nodes_json,
        "services":        services_json,
        "vulnerabilities": vulns,
    })
}
