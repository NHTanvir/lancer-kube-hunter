use crate::types::Finding;

/// Render the upstream-shaped report as YAML.
pub fn render(findings: &[Finding]) -> anyhow::Result<String> {
    let value = super::report_value(findings);
    Ok(serde_yaml::to_string(&value)?)
}

#[allow(dead_code)]
pub fn print(findings: &[Finding]) -> anyhow::Result<()> {
    println!("{}", render(findings)?);
    Ok(())
}
