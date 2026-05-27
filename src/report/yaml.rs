use crate::types::Finding;

pub fn print(findings: &[Finding]) -> anyhow::Result<()> {
    let yaml = serde_yaml::to_string(findings)?;
    println!("{yaml}");
    Ok(())
}
