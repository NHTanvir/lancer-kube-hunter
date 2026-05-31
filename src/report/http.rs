/// POST/PUT the rendered report to the collector endpoint.
///
/// URL resolution order: `explicit_url` (--report-url) → `KUBEHUNTER_HTTP_DISPATCH_URL`.
/// The HTTP verb comes from `KUBEHUNTER_HTTP_DISPATCH_METHOD` (default POST).
pub async fn dispatch_http(
    body:         &str,
    content_type: &str,
    explicit_url: Option<&str>,
) -> anyhow::Result<()> {
    let url = explicit_url
        .map(String::from)
        .or_else(|| std::env::var("KUBEHUNTER_HTTP_DISPATCH_URL").ok());

    let url = match url {
        Some(u) => u,
        None => {
            tracing::warn!("http dispatch selected but no URL provided (set --report-url or KUBEHUNTER_HTTP_DISPATCH_URL)");
            return Ok(());
        }
    };

    let method = std::env::var("KUBEHUNTER_HTTP_DISPATCH_METHOD")
        .unwrap_or_else(|_| "POST".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let req = match method.to_ascii_uppercase().as_str() {
        "PUT"  => client.put(&url),
        "POST" => client.post(&url),
        other  => {
            tracing::warn!("unsupported dispatch method '{other}', falling back to POST");
            client.post(&url)
        }
    };

    let resp = req
        .header("Content-Type", content_type)
        .body(body.to_string())
        .send()
        .await?;

    tracing::info!("Report dispatched to {} via {}: {}", url, method, resp.status());
    Ok(())
}
