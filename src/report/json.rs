use crate::types::Finding;

pub fn print(findings: &[Finding]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    println!("{json}");
    Ok(())
}
