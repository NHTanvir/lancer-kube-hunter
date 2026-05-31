//! Native GUI frontend (egui/eframe). The plain `lancer-kube-hunter` invocation
//! opens this window; `--cli` (or any scan flag) falls through to the headless
//! CLI surface. The GUI is an alternate frontend over the same `scan` engine the
//! CLI uses — it does not duplicate scanning logic.

mod server;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;
use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};

use crate::cli::Cli;
use crate::report::Format;
use crate::scan::{self, ScanConfig};
use crate::types::{Finding, Severity};
use server::SharedState;

enum ScanMsg {
    Done(Vec<Finding>),
    Error(String),
}

/// Launch the GUI window. Owns the Tokio runtime so background scans outlive
/// individual frames.
pub fn run(rt: tokio::runtime::Runtime, cli: Cli) -> anyhow::Result<()> {
    let shared = Arc::new(Mutex::new(SharedState::default()));
    let port = server::start(Arc::clone(&shared));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("lancer-kube-hunter"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "lancer-kube-hunter",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(KubeHunterApp::new(rt, cli, shared, port)) as Box<dyn eframe::App>)
        }),
    );

    result.map_err(|e| anyhow::anyhow!("GUI failed: {e}"))
}

struct KubeHunterApp {
    rt:     tokio::runtime::Runtime,
    shared: Arc<Mutex<SharedState>>,
    tx:     crossbeam_channel::Sender<ScanMsg>,
    rx:     crossbeam_channel::Receiver<ScanMsg>,
    job:    Option<tokio::task::JoinHandle<()>>,

    // ── form inputs ─────────────────────────────────────────────
    remote:     String,
    cidr:       String,
    custom:     String,
    interface:  bool,
    active:     bool,
    quick:      bool,
    report_fmt: Format,

    // ── results / state ─────────────────────────────────────────
    results:   Vec<Finding>,
    selected:  Option<usize>,
    status:    String,
    scanning:  bool,
    dark:      bool,
    server_port: u16,
}

impl KubeHunterApp {
    fn new(rt: tokio::runtime::Runtime, cli: Cli, shared: Arc<Mutex<SharedState>>, port: u16) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        KubeHunterApp {
            rt,
            shared,
            tx,
            rx,
            job: None,
            remote:     cli.remote.join(" "),
            cidr:       cli.cidr.join(" "),
            custom:     cli.custom.join(" "),
            interface:  cli.interface,
            active:     cli.active,
            quick:      cli.quick,
            report_fmt: cli.report_format(),
            results:    Vec::new(),
            selected:   None,
            status:     "idle".to_string(),
            scanning:   false,
            dark:       load_dark(),
            server_port: port,
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.status = "scanning…".to_string();
        self.results.clear();
        self.selected = None;

        let remote = self.remote.clone();
        let cidr = self.cidr.clone();
        let custom = self.custom.clone();
        let interface = self.interface;
        let active = self.active;
        let quick = self.quick;
        let tx = self.tx.clone();
        let shared = Arc::clone(&self.shared);
        let ctx = ctx.clone();

        let job = self.rt.spawn(async move {
            let mut targets = vec![];
            for tok in split_tokens(&remote) {
                targets.extend(scan::resolve_host(&tok).await);
            }
            for tok in split_tokens(&cidr) {
                if let Ok(v) = scan::expand_cidr(&tok) {
                    targets.extend(v);
                }
            }
            if interface {
                targets.extend(scan::local_subnet_hosts());
            }
            if quick && targets.len() > 256 {
                targets.truncate(256);
            }

            let in_cluster = scan::detect_in_cluster();
            let sa_token = in_cluster.as_ref().map(|(_, _, t)| t.clone());

            let cfg = ScanConfig {
                targets,
                interface,
                active,
                sa_token,
                custom: split_tokens(&custom),
                ports: None,
                port_timeout: Duration::from_millis(1500),
                in_cluster,
            };

            let msg = match scan::run_scan(cfg).await {
                Ok(findings) => {
                    if let Ok(mut s) = shared.lock() {
                        s.findings = findings.clone();
                        s.status = format!("{} finding(s)", findings.len());
                    }
                    ScanMsg::Done(findings)
                }
                Err(e) => ScanMsg::Error(e.to_string()),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
        self.job = Some(job);
    }

    fn stop_scan(&mut self) {
        if let Some(job) = self.job.take() {
            job.abort();
        }
        self.scanning = false;
        self.status = "stopped".to_string();
    }

    fn export(&self) {
        let (ext, contents) = match self.report_fmt {
            Format::Json     => ("json", crate::report::json::render(&self.results).unwrap_or_default()),
            Format::Yaml     => ("yaml", crate::report::yaml::render(&self.results).unwrap_or_default()),
            Format::Sarif    => ("sarif", crate::report::sarif::render(&self.results).unwrap_or_default()),
            Format::Markdown => ("md", crate::report::markdown::render(&self.results)),
            Format::Plain    => ("csv", server::export_csv(&self.results)),
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("kube-hunter-report.{ext}"))
            .save_file()
        {
            let _ = std::fs::write(path, contents);
        }
    }

    fn copy_selected(&self) {
        if let Some(i) = self.selected {
            if let Some(f) = self.results.get(i) {
                let text = format!(
                    "{} {} [{}] {} @ {}{}\n{}\n{}",
                    f.vid,
                    f.cve.clone().unwrap_or_default(),
                    f.severity,
                    f.name,
                    f.host,
                    f.port.map(|p| format!(":{p}")).unwrap_or_default(),
                    f.description,
                    f.evidence.clone().unwrap_or_default(),
                );
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(text);
                }
            }
        }
    }
}

impl eframe::App for KubeHunterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(if self.dark { egui::Visuals::dark() } else { egui::Visuals::light() });

        // Drain worker messages.
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                ScanMsg::Done(findings) => {
                    self.results = findings;
                    self.results.sort_by(|a, b| b.severity.rank().cmp(&a.severity.rank()));
                    self.scanning = false;
                    self.status = format!("{} finding(s)", self.results.len());
                }
                ScanMsg::Error(e) => {
                    self.scanning = false;
                    self.status = format!("error: {e}");
                }
            }
        }

        // Ingest targets pushed in via the integration server.
        if let Ok(mut s) = self.shared.lock() {
            if !s.imported.is_empty() {
                for t in s.imported.drain(..) {
                    if !self.remote.is_empty() { self.remote.push(' '); }
                    self.remote.push_str(&t);
                }
            }
        }

        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        self.menu_bar(ctx);
        self.left_panel(ctx);
        self.right_panel(ctx);
        self.status_bar(ctx);
        self.central_panel(ctx);
    }
}

impl KubeHunterApp {
    fn menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Export report…").clicked() {
                        self.export();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Run scan").clicked() {
                        self.start_scan(ctx);
                    }
                    if ui.button("Stop").clicked() {
                        self.stop_scan();
                    }
                    if ui.button("Copy selected finding").clicked() {
                        self.copy_selected();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    if ui.checkbox(&mut self.dark, "Dark theme").changed() {
                        save_dark(self.dark);
                    }
                });
                ui.menu_button("Help", |ui| {
                    ui.label("lancer-kube-hunter");
                    ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));
                    ui.label("Kubernetes attack-surface scanner");
                    ui.hyperlink("https://github.com/NHTanvir/lancer-kube-hunter");
                });
            });
        });
    }

    fn left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("inputs")
            .resizable(true)
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.heading("Scope");
                ui.add_space(4.0);
                ui.label("Remote hosts / IPs (space-separated):");
                ui.text_edit_multiline(&mut self.remote);
                ui.add_space(4.0);
                ui.label("CIDR ranges:");
                ui.text_edit_singleline(&mut self.cidr);
                ui.add_space(4.0);
                ui.label("Custom hunters (optional):");
                ui.text_edit_singleline(&mut self.custom);

                ui.separator();
                ui.checkbox(&mut self.interface, "Scan local interface");
                ui.checkbox(&mut self.active, "Active mode (exploit) ⚠");
                ui.checkbox(&mut self.quick, "Quick (/24 cap)");

                ui.separator();
                egui::ComboBox::from_label("Report format")
                    .selected_text(format!("{:?}", self.report_fmt))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.report_fmt, Format::Plain, "plain/csv");
                        ui.selectable_value(&mut self.report_fmt, Format::Json, "json");
                        ui.selectable_value(&mut self.report_fmt, Format::Yaml, "yaml");
                        ui.selectable_value(&mut self.report_fmt, Format::Sarif, "sarif");
                        ui.selectable_value(&mut self.report_fmt, Format::Markdown, "markdown");
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.scanning, egui::Button::new("▶ Run")).clicked() {
                        self.start_scan(ctx);
                    }
                    if ui.add_enabled(self.scanning, egui::Button::new("■ Stop")).clicked() {
                        self.stop_scan();
                    }
                    if ui.add_enabled(!self.results.is_empty(), egui::Button::new("Export")).clicked() {
                        self.export();
                    }
                });

                ui.separator();
                ui.heading("Summary");
                self.severity_summary(ui);
            });
    }

    fn severity_summary(&self, ui: &mut egui::Ui) {
        let sevs = [
            (Severity::Critical, Color32::from_rgb(220, 50, 50)),
            (Severity::High,     Color32::from_rgb(230, 110, 40)),
            (Severity::Medium,   Color32::from_rgb(220, 190, 40)),
            (Severity::Low,      Color32::from_rgb(80, 160, 220)),
            (Severity::Info,     Color32::GRAY),
        ];
        let total = self.results.len().max(1) as f32;
        for (sev, color) in sevs {
            let count = self.results.iter().filter(|f| f.severity == sev).count();
            ui.horizontal(|ui| {
                ui.colored_label(color, format!("{sev:<8}"));
                ui.add(
                    egui::ProgressBar::new(count as f32 / total)
                        .desired_width(140.0)
                        .text(format!("{count}")),
                );
            });
        }
    }

    fn right_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.heading("Detail");
                ui.separator();
                match self.selected.and_then(|i| self.results.get(i)) {
                    Some(f) => {
                        ui.label(RichText::new(f.name.as_str()).heading());
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("{}  [{}]", f.vid, f.severity)).strong());
                        if let Some(cve) = &f.cve {
                            ui.label(format!("CVE: {cve}"));
                        }
                        ui.label(format!("MITRE ATT&CK: {}", f.category));
                        ui.label(format!("Hunter: {}", f.hunter));
                        let loc = f.port.map(|p| format!("{}:{}", f.host, p)).unwrap_or_else(|| f.host.clone());
                        ui.label(format!("Location: {loc}"));
                        ui.separator();
                        ui.label(f.description.as_str());
                        if let Some(ev) = &f.evidence {
                            ui.add_space(6.0);
                            ui.label(RichText::new("Evidence:").strong());
                            ui.code(ev.as_str());
                        }
                        ui.add_space(8.0);
                        if ui.button("Copy to clipboard").clicked() {
                            self.copy_selected();
                        }
                    }
                    None => {
                        ui.label("Select a finding to see details.");
                    }
                }
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.scanning {
                    ui.spinner();
                }
                ui.label(format!("Status: {}", self.status));
                ui.separator();
                ui.label(format!("Findings: {}", self.results.len()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.server_port != 0 {
                        ui.label(format!("integration: 127.0.0.1:{}", self.server_port));
                    }
                });
            });
        });
    }

    fn central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Findings");
            ui.separator();
            if self.results.is_empty() {
                ui.label(if self.scanning { "Scanning…" } else { "No findings yet. Set a scope and press Run." });
                return;
            }

            let mut clicked: Option<usize> = None;
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .column(Column::auto())          // ID
                .column(Column::auto())          // Severity
                .column(Column::auto())          // Category
                .column(Column::remainder())     // Name
                .column(Column::auto())          // Location
                .header(22.0, |mut header| {
                    header.col(|ui| { ui.strong("ID"); });
                    header.col(|ui| { ui.strong("Severity"); });
                    header.col(|ui| { ui.strong("Category"); });
                    header.col(|ui| { ui.strong("Name"); });
                    header.col(|ui| { ui.strong("Location"); });
                })
                .body(|mut body| {
                    for (i, f) in self.results.iter().enumerate() {
                        body.row(20.0, |mut row| {
                            row.col(|ui| {
                                let id = if f.vid != "None" { f.vid.clone() } else { f.cve.clone().unwrap_or_default() };
                                if ui.selectable_label(self.selected == Some(i), id).clicked() {
                                    clicked = Some(i);
                                }
                            });
                            row.col(|ui| { ui.colored_label(severity_color(f.severity), f.severity.to_string()); });
                            row.col(|ui| { ui.label(f.category.as_str()); });
                            row.col(|ui| {
                                if ui.selectable_label(self.selected == Some(i), f.name.as_str()).clicked() {
                                    clicked = Some(i);
                                }
                            });
                            row.col(|ui| {
                                let loc = f.port.map(|p| format!("{}:{}", f.host, p)).unwrap_or_else(|| f.host.clone());
                                ui.label(loc);
                            });
                        });
                    }
                });
            if clicked.is_some() {
                self.selected = clicked;
            }
        });
    }
}

fn severity_color(sev: Severity) -> Color32 {
    match sev {
        Severity::Critical => Color32::from_rgb(220, 50, 50),
        Severity::High     => Color32::from_rgb(230, 110, 40),
        Severity::Medium   => Color32::from_rgb(220, 190, 40),
        Severity::Low      => Color32::from_rgb(80, 160, 220),
        Severity::Info     => Color32::GRAY,
    }
}

fn split_tokens(s: &str) -> Vec<String> {
    s.split(|c: char| c == ' ' || c == ',' || c == '\n' || c == '\t')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

// ── theme persistence ─────────────────────────────────────────────────────────

fn config_file() -> Option<PathBuf> {
    directories::ProjectDirs::from("io", "Lancer", "lancer-kube-hunter")
        .map(|d| d.config_dir().join("lancer-kube-hunter-config.json"))
}

fn load_dark() -> bool {
    config_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["dark"].as_bool())
        .unwrap_or(true)
}

fn save_dark(dark: bool) {
    if let Some(path) = config_file() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, serde_json::json!({ "dark": dark }).to_string());
    }
}
