use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, Finding, HunterCtx, Mode, Output};

/// KHV021 — API server TLS certificate embeds an email address (subject or SAN),
/// leaking operator/organisation information.
pub struct CertificateEmail;

#[async_trait]
impl Hunter for CertificateEmail {
    fn name(&self)          -> &'static str { "CertificateDiscovery" }
    fn description(&self)   -> &'static str { "Inspects the API server TLS certificate for an embedded email address." }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::ApiServer }

    fn predicate(&self, event: &Event) -> bool {
        matches!(event, Event::ApiServer { tls: true, .. })
    }

    async fn execute(&self, _ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::ApiServer { host, port, tls: true } => (*host, *port),
            _ => return vec![],
        };

        let der = match fetch_peer_cert(host, port).await {
            Some(d) => d,
            None => return vec![],
        };

        if let Some(email) = extract_email(&der) {
            tracing::warn!("  [!] KHV021 certificate includes email {} at {}:{}", email, host, port);
            return vec![Output::Finding(Finding::khv(
                "KHV021", self.name(), host, Some(port),
                Some(format!("API server certificate embeds email address: {email}")),
            ))];
        }
        vec![]
    }
}

/// Open a raw TLS connection (ignoring validation) and capture the peer's
/// leaf certificate in DER form.
async fn fetch_peer_cert(host: IpAddr, port: u16) -> Option<Vec<u8>> {
    let native = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let connector = tokio_native_tls::TlsConnector::from(native);

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await.ok()?.ok()?;
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(&host.to_string(), tcp),
    ).await.ok()?.ok()?;

    let cert = stream.get_ref().peer_certificate().ok()??;
    cert.to_der().ok()
}

/// Parse the DER certificate and return the first embedded email address found
/// in the subject DN or the Subject Alternative Name extension.
fn extract_email(der: &[u8]) -> Option<String> {
    let re = regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").ok()?;
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
        let subject = cert.subject().to_string();
        if let Some(m) = re.find(&subject) {
            return Some(m.as_str().to_string());
        }
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            let rendered = format!("{:?}", san.value);
            if let Some(m) = re.find(&rendered) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}
