#![windows_subsystem = "windows"]

mod fw;

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui::{self, Color32, RichText};
use fw::{BlockReport, BlockedProgram, RemoveReport};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Folder,
    Exe,
    Blocked,
}

enum Msg {
    Scanned { files: Vec<PathBuf>, already: usize, errors: Vec<String> },
    Progress(usize, usize),
    Blocked(BlockReport),
    Listed(Result<Vec<BlockedProgram>, String>),
    Removed(RemoveReport),
    Failed(String),
}

struct App {
    tab: Tab,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: Option<String>,
    progress: Option<(usize, usize)>,

    // block folder
    folder: Option<PathBuf>,
    scan_files: Vec<PathBuf>,
    scan_already: usize,
    folder_log: Vec<(bool, String)>,

    // block exe
    exes: Vec<PathBuf>,
    exe_log: Vec<(bool, String)>,

    // blocked list
    blocked: Vec<BlockedProgram>,
    selected: std::collections::HashSet<String>,
    filter: String,
    loaded: bool,
    list_msg: Option<(bool, String)>,
    confirm_all: bool,
}

fn is_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Relaunches this exe elevated (UAC prompt). Returns true if the new process was started.
fn relaunch_elevated() -> bool {
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let Ok(exe) = std::env::current_exe() else { return false };
    let r = unsafe {
        ShellExecuteW(None, w!("runas"), &HSTRING::from(exe.as_os_str()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL)
    };
    r.0 as isize > 32
}

fn main() -> eframe::Result<()> {
    if !is_elevated() && !relaunch_elevated() {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Warning)
            .set_title("Administrator required")
            .set_description("Firewall Manager needs administrator rights to manage Windows Firewall rules.")
            .show();
        return Ok(());
    }
    if !is_elevated() {
        return Ok(()); // the elevated copy took over
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([940.0, 620.0])
            .with_min_inner_size([760.0, 480.0])
            .with_title("Firewall Manager")
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native("Firewall Manager", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (tx, rx) = channel();
        let mut app = App {
            tab: Tab::Folder,
            tx,
            rx,
            busy: None,
            progress: None,
            folder: None,
            scan_files: vec![],
            scan_already: 0,
            folder_log: vec![],
            exes: vec![],
            exe_log: vec![],
            blocked: vec![],
            selected: Default::default(),
            filter: String::new(),
            loaded: false,
            list_msg: None,
            confirm_all: false,
        };
        // Prefetch so the list is ready by the time the tab is opened.
        app.spawn("Loading rules...", &cc.egui_ctx, |tx| {
            let _ = tx.send(Msg::Listed(fw::list_blocked()));
        });
        app
    }

    fn spawn(&mut self, label: &str, ctx: &egui::Context, f: impl FnOnce(&Sender<Msg>) + Send + 'static) {
        self.busy = Some(label.to_string());
        self.progress = None;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            f(&tx);
            ctx.request_repaint();
        });
    }

    fn reload(&mut self, ctx: &egui::Context) {
        self.spawn("Loading rules...", ctx, |tx| {
            let _ = tx.send(Msg::Listed(fw::list_blocked()));
        });
    }

    fn scan(&mut self, ctx: &egui::Context, dir: PathBuf) {
        self.folder = Some(dir.clone());
        self.scan_files.clear();
        self.folder_log.clear();
        self.spawn("Scanning folder...", ctx, move |tx| {
            let (files, errors) = fw::scan_exes(&dir);
            let have = fw::blocked_set().unwrap_or_default();
            let already = files.iter().filter(|f| have.contains(&fw::path_key(&f.to_string_lossy()))).count();
            let _ = tx.send(Msg::Scanned { files, already, errors });
        });
    }

    fn block(&mut self, ctx: &egui::Context, files: Vec<PathBuf>) {
        let c = ctx.clone();
        self.spawn("Blocking...", ctx, move |tx| {
            let r = fw::block_files(&files, |d, t| {
                let _ = tx.send(Msg::Progress(d, t));
                if d % 8 == 0 {
                    c.request_repaint();
                }
            });
            let _ = tx.send(match r {
                Ok(rep) => Msg::Blocked(rep),
                Err(e) => Msg::Failed(e),
            });
        });
    }

    fn remove(&mut self, ctx: &egui::Context, paths: Option<Vec<String>>) {
        self.spawn("Removing rules...", ctx, move |tx| {
            let r = match paths {
                Some(p) => fw::remove_paths(&p),
                None => fw::remove_all(),
            };
            let _ = tx.send(match r {
                Ok(rep) => Msg::Removed(rep),
                Err(e) => Msg::Failed(e),
            });
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Progress(d, t) => self.progress = Some((d, t)),
                Msg::Scanned { files, already, errors } => {
                    self.busy = None;
                    self.scan_already = already;
                    self.scan_files = files;
                    self.folder_log.extend(errors.into_iter().map(|e| (false, e)));
                }
                Msg::Blocked(rep) => {
                    self.busy = None;
                    let mut log = vec![];
                    for e in &rep.errors {
                        log.push((false, e.clone()));
                    }
                    log.push((
                        rep.errors.is_empty(),
                        format!("{} blocked, {} already blocked, {} failed", rep.blocked, rep.skipped, rep.errors.len()),
                    ));
                    self.loaded = false;
                    if self.tab == Tab::Folder {
                        if let Some(d) = self.folder.clone() {
                            self.scan(ctx, d); // refreshes "already blocked"
                        }
                        self.folder_log = log;
                    } else {
                        self.exe_log = log;
                        self.exes.clear();
                    }
                }
                Msg::Listed(r) => {
                    self.busy = None;
                    match r {
                        Ok(v) => {
                            let keep: std::collections::HashSet<_> = v.iter().map(|p| fw::path_key(&p.path)).collect();
                            self.selected.retain(|s| keep.contains(s));
                            self.blocked = v;
                            self.loaded = true;
                        }
                        Err(e) => self.list_msg = Some((false, e)),
                    }
                }
                Msg::Removed(rep) => {
                    self.busy = None;
                    self.selected.clear();
                    self.list_msg = Some((
                        rep.errors.is_empty(),
                        if rep.errors.is_empty() {
                            format!("Removed {} rule(s)", rep.removed)
                        } else {
                            format!("Removed {}, {} failed: {}", rep.removed, rep.errors.len(), rep.errors[0])
                        },
                    ));
                    self.reload(ctx);
                }
                Msg::Failed(e) => {
                    self.busy = None;
                    let l = vec![(false, e)];
                    match self.tab {
                        Tab::Folder => self.folder_log = l,
                        Tab::Exe => self.exe_log = l,
                        Tab::Blocked => self.list_msg = Some((false, l[0].1.clone())),
                    }
                }
            }
        }
    }
}

fn log_view(ui: &mut egui::Ui, log: &[(bool, String)]) {
    egui::ScrollArea::vertical().id_salt("log").max_height(110.0).show(ui, |ui| {
        for (ok, line) in log {
            let c = if *ok { Color32::from_rgb(80, 200, 120) } else { Color32::from_rgb(235, 90, 90) };
            ui.label(RichText::new(line).color(c).monospace().size(12.0));
        }
    });
}

fn badge(ui: &mut egui::Ui, on: bool, yes: &str, no: &str) {
    let (t, c) = if on {
        (yes, Color32::from_rgb(80, 200, 120))
    } else {
        (no, Color32::from_rgb(140, 140, 140))
    };
    ui.label(RichText::new(t).color(c));
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        let idle = self.busy.is_none();

        // Drag & drop: folder -> scan, exe files -> block list.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if idle && !dropped.is_empty() {
            if dropped.len() == 1 && dropped[0].is_dir() {
                self.tab = Tab::Folder;
                self.scan(ctx, dropped[0].clone());
            } else {
                let exes: Vec<PathBuf> = dropped
                    .into_iter()
                    .filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false))
                    .collect();
                if !exes.is_empty() {
                    self.tab = Tab::Exe;
                    self.exes = exes;
                    self.exe_log.clear();
                }
            }
        }

        egui::SidePanel::left("nav").exact_width(170.0).show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("Firewall Manager");
            ui.add_space(14.0);
            let mut tab = self.tab;
            for (t, label) in [(Tab::Folder, "Block Folder"), (Tab::Exe, "Block EXE"), (Tab::Blocked, "Blocked Programs")] {
                let text = if t == Tab::Blocked && self.loaded {
                    format!("{label} ({})", self.blocked.len())
                } else {
                    label.to_string()
                };
                if ui.selectable_label(tab == t, RichText::new(text).size(15.0)).clicked() {
                    tab = t;
                }
                ui.add_space(2.0);
            }
            if tab != self.tab {
                self.tab = tab;
                if tab == Tab::Blocked && !self.loaded && idle {
                    self.reload(ctx);
                }
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| match (&self.busy, self.progress) {
                (Some(l), Some((d, t))) => {
                    ui.spinner();
                    ui.label(format!("{l} {d}/{t}"));
                    ui.add(egui::ProgressBar::new(d as f32 / t.max(1) as f32).desired_width(240.0));
                }
                (Some(l), None) => {
                    ui.spinner();
                    ui.label(l);
                }
                _ => {
                    ui.label("Ready  ·  tip: drop a folder or .exe files onto the window");
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(idle, |ui| match self.tab {
                Tab::Folder => self.folder_ui(ui, ctx),
                Tab::Exe => self.exe_ui(ui, ctx),
                Tab::Blocked => self.blocked_ui(ui, ctx),
            });
        });
    }
}

impl App {
    fn folder_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Block Folder");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(match &self.folder {
                Some(p) => RichText::new(p.display().to_string()).monospace(),
                None => RichText::new("No folder selected").weak(),
            });
            if ui.button("Browse...").clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.scan(ctx, d);
                }
            }
        });
        if self.folder.is_some() && !self.scan_files.is_empty() {
            let new = self.scan_files.len() - self.scan_already;
            ui.add_space(6.0);
            ui.label(format!(
                "{} .exe file(s) found, {} already blocked, {} new",
                self.scan_files.len(),
                self.scan_already,
                new
            ));
            ui.horizontal(|ui| {
                if ui.add_enabled(new > 0, egui::Button::new(RichText::new(format!("Block {new} new")).color(Color32::WHITE)).fill(Color32::from_rgb(170, 50, 50))).clicked() {
                    let files = self.scan_files.clone();
                    self.block(ctx, files);
                }
                if ui.button("Rescan").clicked() {
                    if let Some(d) = self.folder.clone() {
                        self.scan(ctx, d);
                    }
                }
            });
            ui.add_space(6.0);
            let h = (ui.available_height() - 130.0).max(80.0);
            egui::ScrollArea::vertical().id_salt("scanlist").max_height(h).show(ui, |ui| {
                let root = self.folder.clone().unwrap_or_default();
                for f in &self.scan_files {
                    let rel = f.strip_prefix(&root).unwrap_or(f);
                    ui.label(RichText::new(rel.display().to_string()).monospace().size(12.0));
                }
            });
        } else if self.folder.is_some() && self.busy.is_none() && self.folder_log.is_empty() {
            ui.add_space(6.0);
            ui.label("No .exe files found in the selected folder.");
        }
        ui.add_space(6.0);
        log_view(ui, &self.folder_log);
    }

    fn exe_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Block EXE");
        ui.add_space(8.0);
        if ui.button("Browse...").clicked() {
            if let Some(f) = rfd::FileDialog::new().add_filter("Executables", &["exe"]).pick_files() {
                self.exes = f;
                self.exe_log.clear();
            }
        }
        ui.add_space(6.0);
        if self.exes.is_empty() {
            ui.label(RichText::new("No file selected").weak());
        }
        for p in &self.exes {
            ui.label(RichText::new(p.display().to_string()).monospace().size(12.0));
        }
        ui.add_space(6.0);
        if ui
            .add_enabled(!self.exes.is_empty(), egui::Button::new(format!("Block {}", self.exes.len())))
            .clicked()
        {
            let f = self.exes.clone();
            self.block(ctx, f);
        }
        ui.add_space(6.0);
        log_view(ui, &self.exe_log);
    }

    fn blocked_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Blocked Programs");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(220.0));
            if ui.button("Refresh").clicked() {
                self.reload(ctx);
            }
        });
        let f = self.filter.to_lowercase();
        let shown: Vec<usize> = (0..self.blocked.len())
            .filter(|&i| {
                let b = &self.blocked[i];
                f.is_empty() || b.name.to_lowercase().contains(&f) || b.path.to_lowercase().contains(&f)
            })
            .collect();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Select shown").clicked() {
                for &i in &shown {
                    self.selected.insert(fw::path_key(&self.blocked[i].path));
                }
            }
            if ui.button("Select none").clicked() {
                self.selected.clear();
            }
            let missing = self.blocked.iter().filter(|b| !b.exists).count();
            if ui.add_enabled(missing > 0, egui::Button::new(format!("Select missing ({missing})"))).clicked() {
                self.selected = self.blocked.iter().filter(|b| !b.exists).map(|b| fw::path_key(&b.path)).collect();
            }
            let n = self.selected.len();
            if ui.add_enabled(n > 0, egui::Button::new(format!("Remove selected ({n})"))).clicked() {
                let paths: Vec<String> = self
                    .blocked
                    .iter()
                    .filter(|b| self.selected.contains(&fw::path_key(&b.path)))
                    .map(|b| b.path.clone())
                    .collect();
                self.remove(ctx, Some(paths));
            }
            if ui.add_enabled(!self.blocked.is_empty(), egui::Button::new("Remove all")).clicked() {
                self.confirm_all = true;
            }
        });
        if self.confirm_all {
            egui::Window::new("Remove all rules?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Remove ALL firewall rules created by this tool?");
                    ui.horizontal(|ui| {
                        if ui.button("Remove all").clicked() {
                            self.confirm_all = false;
                            self.remove(ctx, None);
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_all = false;
                        }
                    });
                });
        }
        if let Some((ok, m)) = &self.list_msg {
            let c = if *ok { Color32::from_rgb(80, 200, 120) } else { Color32::from_rgb(235, 90, 90) };
            ui.label(RichText::new(m).color(c));
        }
        ui.add_space(4.0);
        if self.blocked.is_empty() {
            ui.label(RichText::new(if self.loaded { "No rules created by this tool." } else { "Loading..." }).weak());
            return;
        }
        // Virtualised table: only visible rows are laid out, so thousands of rules stay smooth.
        let row_h = 22.0;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, shown.len(), |ui, range| {
            egui::Grid::new("blocked").striped(true).num_columns(6).min_row_height(row_h).show(ui, |ui| {
                for &i in &shown[range] {
                    let b = &self.blocked[i];
                    let key = fw::path_key(&b.path);
                    let mut sel = self.selected.contains(&key);
                    if ui.checkbox(&mut sel, "").changed() {
                        if sel {
                            self.selected.insert(key);
                        } else {
                            self.selected.remove(&key);
                        }
                    }
                    ui.label(RichText::new(&b.name).strong());
                    badge(ui, b.inbound, "In", "–");
                    badge(ui, b.outbound, "Out", "–");
                    badge(ui, b.enabled, "Active", "Inactive");
                    let mut path = RichText::new(&b.path).monospace().size(11.0);
                    if !b.exists {
                        path = path.color(Color32::from_rgb(230, 170, 60));
                    }
                    ui.label(path).on_hover_text(if b.exists { &b.path } else { "File no longer exists" });
                    ui.end_row();
                }
            });
        });
    }
}
