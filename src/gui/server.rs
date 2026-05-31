//! Local HTTP server for cross-tool Lancer integration. Binds an ephemeral port
//! on 127.0.0.1, writes it to %TEMP%/lancer-kube-hunter.port, and exposes:
//!   GET  /v1/state                       — current jobs / progress / counts
//!   POST /v1/import                       — accept a target (IP / host) from another tool
//!   GET  /v1/export?format=json|csv|sarif|markdown — pull the current result set

use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::json;

use crate::types::Finding;

#[derive(Default)]
pub struct SharedState {
    pub status:   String,
    pub findings: Vec<Finding>,
    /// Targets pushed in via POST /v1/import, consumed by the GUI.
    pub imported: Vec<String>,
}

/// Start the integration server on a background thread. Returns the bound port.
pub fn start(shared: Arc<Mutex<SharedState>>) -> u16 {
    let server = match tiny_http::Server::http("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("integration server failed to bind: {e}");
            return 0;
        }
    };

    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .unwrap_or(0);

    // Advertise the port so the Lancer mothership can discover this tool.
    let port_file = std::env::temp_dir().join("lancer-kube-hunter.port");
    let _ = std::fs::write(&port_file, port.to_string());

    thread::spawn(move || {
        for request in server.incoming_requests() {
            handle(request, &shared);
        }
    });

    tracing::info!("Lancer integration server on 127.0.0.1:{port}");
    port
}

fn handle(mut request: tiny_http::Request, shared: &Arc<Mutex<SharedState>>) {
    let method = request.method().as_str().to_string();
    let url = request.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };

    let (status, content_type, body): (u16, &str, String) = match (method.as_str(), path.as_str()) {
        ("GET", "/v1/state") => {
            let s = shared.lock().unwrap();
            let body = json!({
                "tool": "lancer-kube-hunter",
                "version": env!("CARGO_PKG_VERSION"),
                "status": s.status,
                "findings": s.findings.len(),
            }).to_string();
            (200, "application/json", body)
        }
        ("POST", "/v1/import") => {
            let mut content = String::new();
            let _ = request.as_reader().read_to_string(&mut content);
            let target = content.trim().to_string();
            if !target.is_empty() {
                shared.lock().unwrap().imported.push(target.clone());
            }
            (200, "application/json", json!({ "imported": target }).to_string())
        }
        ("GET", "/v1/export") => {
            let format = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("format="))
                .unwrap_or("json");
            let findings = shared.lock().unwrap().findings.clone();
            let (ct, rendered) = render_export(format, &findings);
            (200, ct, rendered)
        }
        _ => (404, "text/plain", "not found".to_string()),
    };

    let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
        .expect("valid header");
    let response = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}

fn render_export(format: &str, findings: &[Finding]) -> (&'static str, String) {
    match format.to_ascii_lowercase().as_str() {
        "csv" => ("text/csv", export_csv(findings)),
        "sarif" => (
            "application/sarif+json",
            crate::report::sarif::render(findings).unwrap_or_default(),
        ),
        "markdown" | "md" => ("text/markdown", crate::report::markdown::render(findings)),
        "yaml" | "yml" => (
            "application/x-yaml",
            crate::report::yaml::render(findings).unwrap_or_default(),
        ),
        _ => (
            "application/json",
            crate::report::json::render(findings).unwrap_or_default(),
        ),
    }
}

pub fn export_csv(findings: &[Finding]) -> String {
    let mut out = String::from("vid,cve,severity,category,host,port,name,evidence\n");
    for f in findings {
        let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            esc(&f.vid),
            esc(f.cve.as_deref().unwrap_or("")),
            f.severity,
            esc(f.category.as_str()),
            esc(&f.host),
            f.port.map(|p| p.to_string()).unwrap_or_default(),
            esc(&f.name),
            esc(f.evidence.as_deref().unwrap_or("")),
        ));
    }
    out
}
