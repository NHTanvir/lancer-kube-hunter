use crate::types::Finding;

/// Render the upstream-shaped report as pretty JSON.
pub fn render(findings: &[Finding]) -> anyhow::Result<String> {
    let value = super::report_value(findings);
    Ok(serde_json::to_string_pretty(&value)?)
}

#[allow(dead_code)]
pub fn print(findings: &[Finding]) -> anyhow::Result<()> {
    println!("{}", render(findings)?);
    Ok(())
}
