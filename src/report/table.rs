use colored::Colorize;
use comfy_table::{ContentArrangement, Table, Cell, Color, Attribute};

use crate::types::{Finding, Severity};

pub fn print(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "[+] No vulnerabilities found.".green());
        return;
    }

    println!("\n{}", "=== Findings ===".bold());

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("ID").add_attribute(Attribute::Bold),
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("Name").add_attribute(Attribute::Bold),
        Cell::new("Host").add_attribute(Attribute::Bold),
        Cell::new("Evidence").add_attribute(Attribute::Bold),
    ]);

    for f in findings {
        let sev_cell = severity_cell(f.severity);
        let host_str = match f.port {
            Some(p) => format!("{}:{}", f.host, p),
            None    => f.host.clone(),
        };
        table.add_row(vec![
            Cell::new(&f.id),
            sev_cell,
            Cell::new(&f.name),
            Cell::new(&host_str),
            Cell::new(f.evidence.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");
    println!("\n{} finding(s) total", findings.len());
}

fn severity_cell(sev: Severity) -> Cell {
    let cell = Cell::new(sev.to_string());
    match sev {
        Severity::Critical => cell.fg(Color::Red).add_attribute(Attribute::Bold),
        Severity::High     => cell.fg(Color::Red),
        Severity::Medium   => cell.fg(Color::Yellow),
        Severity::Low      => cell.fg(Color::Cyan),
        Severity::Info     => cell,
    }
}
