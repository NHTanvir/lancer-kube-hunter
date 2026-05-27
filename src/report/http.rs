use crate::types::Finding;

pub async fn post(findings: &[Finding], url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .post(url)
        .json(findings)
        .send()
        .await?;

    tracing::info!("Report posted to {}: {}", url, resp.status());
    Ok(())
}
