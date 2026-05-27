pub mod http;
pub mod json;
pub mod table;
pub mod yaml;

use crate::types::Finding;

pub async fn dispatch(
    findings:   &[Finding],
    format:     &str,
    report_url: Option<&str>,
) -> anyhow::Result<()> {
    match format {
        "json"  => json::print(findings)?,
        "yaml"  => yaml::print(findings)?,
        _       => table::print(findings),
    }

    if let Some(url) = report_url {
        http::post(findings, url).await?;
    }

    Ok(())
}
