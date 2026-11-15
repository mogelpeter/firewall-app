#![windows_subsystem = "windows"]

mod fw;
mod update;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui::{self, Color32, RichText};
use fw::{BlockReport, BlockedProgram, RemoveReport};

// ---- palette ---------------------------------------------------------------
const BG: Color32 = Color32::from_rgb(8, 6, 13);
const PANEL: Color32 = Color32::from_rgb(14, 10, 22);
const CARD: Color32 = Color32::from_rgb(21, 16, 33);
const CARD_HI: Color32 = Color32::from_rgb(34, 25, 52);
const LINE: Color32 = Color32::from_rgb(48, 36, 74);
const ACCENT: Color32 = Color32::from_rgb(139, 92, 246);
const INFO: Color32 = Color32::from_rgb(196, 181, 253);
const OK: Color32 = Color32::from_rgb(74, 201, 120);
const WARN: Color32 = Color32::from_rgb(235, 170, 60);
const BAD: Color32 = Color32::from_rgb(240, 100, 100);
const TEXT: Color32 = Color32::from_rgb(250, 248, 255);
const MUTED: Color32 = Color32::from_rgb(166, 154, 196);

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Folder,
    Exe,
    Blocked,
}

enum Upd {
    Checking,
    UpToDate,
    Available(update::Update),
    Installing(String),
    Failed(String),
}

enum Msg {
    Scanned { files: Vec<PathBuf>, already: usize, errors: Vec<String> },
    Progress(usize, usize),
    Blocked(BlockReport),
    Listed(Result<Vec<BlockedProgram>, String>),
    Removed(RemoveReport),
    Failed(String),
    UpdateChecked(Result<Option<update::Update>, String>),
    UpdateProgress(String),
    UpdateFailed(String),
    UpdateStarted,
}

struct App {
    tab: Tab,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: Option<String>,
    progress: Option<(usize, usize)>,
    icon: Option<egui::TextureHandle>,
    upd: Upd,

    folder: Option<PathBuf>,
    scan_files: Vec<PathBuf>,
    scan_already: usize,
    folder_log: Vec<(bool, String)>,

    exes: Vec<PathBuf>,
    exe_log: Vec<(bool, String)>,

    blocked: Vec<BlockedProgram>,
    selected: HashSet<String>,
    filter: String,
    loaded: bool,
    list_msg: Option<(bool, String)>,
    confirm_all: bool,
}

fn is_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Relaunches this exe elevated (one UAC prompt). Returns true if the new process was started.
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
    if !is_elevated() {
        if !relaunch_elevated() {
            rfd::MessageDialog::new()
                .set_level(rfd::MessageLevel::Warning)
                .set_title("Administrator required")
                .set_description("Firewall Manager needs administrator rights to manage Windows Firewall rules.")
                .show();
        }
        return Ok(()); // the elevated copy (if any) took over
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 660.0])
            .with_min_inner_size([820.0, 520.0])
            .with_title("Firewall Manager")
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/icon.rgba").to_vec(),
                width: 64,
                height: 64,
            })
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native("Firewall Manager", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

/// JetBrains Mono (SIL OFL, see assets/fonts) for everything; a separate "bold" family for emphasis.
fn setup_fonts(ctx: &egui::Context) {
    use egui::{FontData, FontFamily};
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("jbm".into(), std::sync::Arc::new(FontData::from_static(include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf"))));
    fonts.font_data.insert("jbm-bold".into(), std::sync::Arc::new(FontData::from_static(include_bytes!("../assets/fonts/JetBrainsMono-Bold.ttf"))));
    for fam in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts.families.entry(fam).or_default().insert(0, "jbm".into());
    }
    fonts.families.insert(FontFamily::Name("bold".into()), vec!["jbm-bold".into(), "jbm".into()]);
    ctx.set_fonts(fonts);
}

/// Bold JetBrains Mono text.
fn bold(t: impl Into<String>, size: f32) -> RichText {
    RichText::new(t.into()).font(egui::FontId::new(size, egui::FontFamily::Name("bold".into())))
}

fn setup_style(ctx: &egui::Context) {
    setup_fonts(ctx);
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = Color32::from_rgb(4, 3, 8);
    v.faint_bg_color = Color32::from_rgb(17, 12, 27);
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = ACCENT.linear_multiply(0.55);
    v.window_corner_radius = 12.into();
    v.menu_corner_radius = 8.into();
    v.window_stroke = egui::Stroke::new(1.0_f32, LINE);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active] {
        w.corner_radius = 8.into();
    }
    v.widgets.inactive.bg_fill = CARD_HI;
    v.widgets.inactive.weak_bg_fill = CARD_HI;
    v.widgets.hovered.bg_fill = Color32::from_rgb(52, 38, 82);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(52, 38, 82);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(10.0, 10.0);
        s.spacing.button_padding = egui::vec2(14.0, 7.0);
        s.spacing.interact_size.y = 30.0;
        s.spacing.scroll.bar_width = 8.0;
        use egui::{FontFamily::Proportional, FontId, TextStyle::*};
        s.text_styles.insert(Heading, FontId::new(19.0, Proportional));
        s.text_styles.insert(Body, FontId::new(12.5, Proportional));
        s.text_styles.insert(Button, FontId::new(12.5, Proportional));
        s.text_styles.insert(Small, FontId::new(10.5, Proportional));
    });
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_style(&cc.egui_ctx);
        let icon = {
            let img = egui::ColorImage::from_rgba_unmultiplied([64, 64], include_bytes!("../assets/icon.rgba"));
            Some(cc.egui_ctx.load_texture("icon", img, egui::TextureOptions::LINEAR))
        };
        let (tx, rx) = channel();
        let mut app = App {
            tab: Tab::Folder,
            tx,
            rx,
            busy: None,
            progress: None,
            icon,
            upd: Upd::Checking,
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
        app.reload(&cc.egui_ctx);
        app.check_update(&cc.egui_ctx);
        app
    }

    fn check_update(&mut self, ctx: &egui::Context) {
        self.upd = Upd::Checking;
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            update::cleanup();
            let _ = tx.send(Msg::UpdateChecked(update::check()));
            ctx.request_repaint();
        });
    }

    fn start_update(&mut self, ctx: &egui::Context, u: update::Update) {
        self.upd = Upd::Installing("Downloading...".into());
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let t2 = tx.clone();
            let c2 = ctx.clone();
            let r = update::install(&u, move |d, t| {
                let pct = if t > 0 { format!("Downloading... {}%", d * 100 / t) } else { "Downloading...".into() };
                let _ = t2.send(Msg::UpdateProgress(pct));
                c2.request_repaint();
            });
            let _ = tx.send(match r {
                Ok(()) => Msg::UpdateStarted,
                Err(e) => Msg::UpdateFailed(e),
            });
            ctx.request_repaint();
        });
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
                Msg::UpdateChecked(r) => {
                    self.upd = match r {
                        Ok(Some(u)) => Upd::Available(u),
                        Ok(None) => Upd::UpToDate,
                        Err(e) => Upd::Failed(e),
                    }
                }
                Msg::UpdateProgress(s) => self.upd = Upd::Installing(s),
                Msg::UpdateFailed(e) => self.upd = Upd::Failed(e),
                Msg::UpdateStarted => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close); // the installer takes over
                }
                Msg::Progress(d, t) => self.progress = Some((d, t)),
                Msg::Scanned { files, already, errors } => {
                    self.busy = None;
                    self.scan_already = already;
                    self.scan_files = files;
                    self.folder_log.extend(errors.into_iter().map(|e| (false, e)));
                }
                Msg::Blocked(rep) => {
                    self.busy = None;
                    let mut log: Vec<(bool, String)> = rep.errors.iter().map(|e| (false, e.clone())).collect();
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
                            let keep: HashSet<_> = v.iter().map(|p| fw::path_key(&p.path)).collect();
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
                    match self.tab {
                        Tab::Folder => self.folder_log = vec![(false, e)],
                        Tab::Exe => self.exe_log = vec![(false, e)],
                        Tab::Blocked => self.list_msg = Some((false, e)),
                    }
                }
            }
        }
    }
}

// ---- small widgets ----------------------------------------------------------

fn card<R>(ui: &mut egui::Ui, fill: Color32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(fill)
        .corner_radius(12)
        .inner_margin(egui::Margin::same(16))
        .stroke(egui::Stroke::new(1.0_f32, LINE))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Explanation box shown at the top of the block pages.
fn info_box(ui: &mut egui::Ui, title: &str, lines: &[&str]) {
    egui::Frame::new()
        .fill(Color32::from_rgb(27, 19, 48))
        .corner_radius(12)
        .inner_margin(egui::Margin::same(14))
        .stroke(egui::Stroke::new(1.0_f32, ACCENT.linear_multiply(0.55)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(bold("i", 13.0).color(INFO));
                ui.label(bold(title, 12.5).color(INFO));
            });
            for l in lines {
                ui.label(RichText::new(format!("•  {l}")).color(TEXT));
            }
        });
}

fn page_header(ui: &mut egui::Ui, title: &str, sub: &str) {
    ui.label(bold(title, 20.0));
    ui.label(RichText::new(sub).color(MUTED));
    ui.add_space(4.0);
}

fn primary(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(bold(text, 12.5).color(Color32::WHITE)).fill(ACCENT)
}

fn chip(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.linear_multiply(0.18))
        .corner_radius(20)
        .inner_margin(egui::Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.label(bold(text, 11.0).color(color));
        });
}

fn log_view(ui: &mut egui::Ui, log: &[(bool, String)]) {
    if log.is_empty() {
        return;
    }
    card(ui, PANEL, |ui| {
        egui::ScrollArea::vertical().id_salt("log").max_height(100.0).show(ui, |ui| {
            for (ok, line) in log {
                ui.label(RichText::new(line).color(if *ok { OK } else { BAD }).monospace().size(11.0));
            }
        });
    });
}

fn path_label(p: &str) -> RichText {
    RichText::new(p).monospace().size(11.5)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        let idle = self.busy.is_none();

        // Drag & drop: a folder starts a scan, .exe files go to the Block EXE page.
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

        self.sidebar(ctx, idle);
        self.statusbar(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(26, 20)))
            .show(ctx, |ui| {
                self.update_banner(ui, ctx);
                ui.add_enabled_ui(idle, |ui| match self.tab {
                    Tab::Folder => self.folder_ui(ui, ctx),
                    Tab::Exe => self.exe_ui(ui, ctx),
                    Tab::Blocked => self.blocked_ui(ui, ctx),
                });
            });
    }
}

impl App {
    fn sidebar(&mut self, ctx: &egui::Context, idle: bool) {
        egui::SidePanel::left("nav")
            .exact_width(210.0)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(16)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(t) = &self.icon {
                        ui.image((t.id(), egui::vec2(34.0, 34.0)));
                    }
                    ui.vertical(|ui| {
                        ui.add_space(-2.0);
                        ui.label(bold("Firewall", 14.0));
                        ui.label(bold("Manager", 14.0));
                    });
                });
                ui.add_space(18.0);
                let items = [
                    (Tab::Folder, "Block Folder".to_string()),
                    (Tab::Exe, "Block EXE".to_string()),
                    (
                        Tab::Blocked,
                        if self.loaded { format!("Blocked Programs  ({})", self.blocked.len()) } else { "Blocked Programs".into() },
                    ),
                ];
                let mut next = self.tab;
                for (t, label) in items {
                    let sel = self.tab == t;
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
                    let fill = if sel {
                        ACCENT.linear_multiply(0.22)
                    } else if resp.hovered() {
                        CARD
                    } else {
                        Color32::TRANSPARENT
                    };
                    ui.painter().rect_filled(rect, 8.0, fill);
                    if sel {
                        let bar = egui::Rect::from_min_size(rect.left_top() + egui::vec2(0.0, 8.0), egui::vec2(3.0, 22.0));
                        ui.painter().rect_filled(bar, 2.0, ACCENT);
                    }
                    ui.painter().text(
                        rect.left_center() + egui::vec2(14.0, 0.0),
                        egui::Align2::LEFT_CENTER,
                        label,
                        egui::FontId::proportional(12.5),
                        if sel { Color32::WHITE } else { TEXT },
                    );
                    if resp.clicked() {
                        next = t;
                    }
                }
                if next != self.tab {
                    self.tab = next;
                    if next == Tab::Blocked && !self.loaded && idle {
                        self.reload(ctx);
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(RichText::new(format!("v{}", update::CURRENT)).color(MUTED).size(10.5));
                    let txt = match &self.upd {
                        Upd::Checking => "Checking for updates...".to_string(),
                        Upd::UpToDate => "Up to date".to_string(),
                        Upd::Available(u) => format!("Update {} available", u.version),
                        Upd::Installing(s) => s.clone(),
                        Upd::Failed(_) => "Update check failed".to_string(),
                    };
                    let r = ui.label(RichText::new(txt).color(MUTED).size(10.5));
                    if let Upd::Failed(e) = &self.upd {
                        r.on_hover_text(e);
                    }
                });
            });
    }

    fn statusbar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(16, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| match (&self.busy, self.progress) {
                    (Some(l), Some((d, t))) => {
                        ui.spinner();
                        ui.label(format!("{l} {d}/{t}"));
                        ui.add(egui::ProgressBar::new(d as f32 / t.max(1) as f32).desired_width(260.0).fill(ACCENT));
                    }
                    (Some(l), None) => {
                        ui.spinner();
                        ui.label(l);
                    }
                    _ => {
                        ui.label(RichText::new("Ready   ·   drop a folder or .exe files onto the window").color(MUTED).size(11.0));
                    }
                });
            });
    }

    fn update_banner(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Upd::Available(u) = &self.upd {
            let u = u.clone();
            egui::Frame::new()
                .fill(OK.linear_multiply(0.12))
                .corner_radius(12)
                .inner_margin(egui::Margin::same(12))
                .stroke(egui::Stroke::new(1.0_f32, OK.linear_multiply(0.5)))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(bold(format!("Version {} is available (you have {}).", u.version, update::CURRENT), 12.0).color(OK));
                        if ui.add(primary("Update now")).clicked() {
                            self.start_update(ctx, u.clone());
                        }
                        if !u.notes_url.is_empty() {
                            ui.hyperlink_to("What's new", &u.notes_url);
                        }
                    });
                });
            ui.add_space(6.0);
        }
    }

    fn folder_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        page_header(ui, "Block Folder", "Cut off every program in a folder from the network in one go.");
        info_box(
            ui,
            "What this does",
            &[
                "Scans the chosen folder and all of its subfolders for .exe files.",
                "Creates two Windows Firewall block rules per program: one for incoming and one for outgoing connections.",
                "Programs that are already blocked are skipped, so nothing is created twice.",
                "No file is changed or deleted. You can undo it any time under Blocked Programs.",
            ],
        );
        ui.horizontal(|ui| {
            if ui.add(primary("Choose folder...")).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.scan(ctx, d);
                }
            }
            match &self.folder {
                Some(p) => ui.label(path_label(&p.display().to_string())),
                None => ui.label(RichText::new("or drop a folder onto the window").color(MUTED)),
            };
        });

        if self.folder.is_some() && !self.scan_files.is_empty() {
            let total = self.scan_files.len();
            let new = total - self.scan_already;
            ui.horizontal(|ui| {
                chip(ui, &format!("{total} found"), INFO);
                chip(ui, &format!("{} already blocked", self.scan_already), MUTED);
                chip(ui, &format!("{new} new"), if new > 0 { WARN } else { MUTED });
            });
            card(ui, PANEL, |ui| {
                let h = (ui.available_height() - 150.0).max(90.0);
                egui::ScrollArea::vertical().id_salt("scanlist").max_height(h).auto_shrink([false, true]).show(ui, |ui| {
                    let root = self.folder.clone().unwrap_or_default();
                    for f in &self.scan_files {
                        let rel = f.strip_prefix(&root).unwrap_or(f);
                        ui.label(path_label(&rel.display().to_string()));
                    }
                });
            });
            ui.horizontal(|ui| {
                if ui.add_enabled(new > 0, primary(format!("Block {new} new program(s)"))).clicked() {
                    let files = self.scan_files.clone();
                    self.block(ctx, files);
                }
                if ui.button("Rescan").clicked() {
                    if let Some(d) = self.folder.clone() {
                        self.scan(ctx, d);
                    }
                }
            });
        } else if self.folder.is_some() && self.busy.is_none() && self.folder_log.is_empty() {
            ui.label(RichText::new("No .exe files found in this folder.").color(WARN));
        }
        log_view(ui, &self.folder_log);
    }

    fn exe_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        page_header(ui, "Block EXE", "Cut off individual programs from the network.");
        info_box(
            ui,
            "What this does",
            &[
                "Creates an incoming and an outgoing Windows Firewall block rule for each chosen program.",
                "Only that exact file is blocked. A copy or another version of the program in a different folder is not.",
                "Already blocked programs are skipped. No file is changed. Undo any time under Blocked Programs.",
            ],
        );
        ui.horizontal(|ui| {
            if ui.add(primary("Choose .exe files...")).clicked() {
                if let Some(f) = rfd::FileDialog::new().add_filter("Executables", &["exe"]).pick_files() {
                    self.exes = f;
                    self.exe_log.clear();
                }
            }
            if self.exes.is_empty() {
                ui.label(RichText::new("or drop .exe files onto the window").color(MUTED));
            }
        });
        if !self.exes.is_empty() {
            card(ui, PANEL, |ui| {
                egui::ScrollArea::vertical().id_salt("exelist").max_height(220.0).auto_shrink([false, true]).show(ui, |ui| {
                    for p in &self.exes {
                        ui.label(path_label(&p.display().to_string()));
                    }
                });
            });
            ui.horizontal(|ui| {
                if ui.add(primary(format!("Block {} program(s)", self.exes.len()))).clicked() {
                    let f = self.exes.clone();
                    self.block(ctx, f);
                }
                if ui.button("Clear").clicked() {
                    self.exes.clear();
                }
            });
        }
        log_view(ui, &self.exe_log);
    }

    fn blocked_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        page_header(ui, "Blocked Programs", "Everything this app has blocked. Rules live in Windows Firewall.");

        let f = self.filter.to_lowercase();
        let shown: Vec<usize> = (0..self.blocked.len())
            .filter(|&i| {
                let b = &self.blocked[i];
                f.is_empty() || b.name.to_lowercase().contains(&f) || b.path.to_lowercase().contains(&f)
            })
            .collect();
        let lost = self.blocked.iter().filter(|b| !b.active_rules).count();
        let missing = self.blocked.iter().filter(|b| !b.exists).count();

        card(ui, PANEL, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Search name or path...").desired_width(260.0));
                if ui.button("Refresh").clicked() {
                    self.reload(ctx);
                }
                if lost > 0 && ui.button(format!("Restore {lost} missing")).clicked() {
                    self.spawn("Restoring rules...", ctx, |tx| {
                        let _ = fw::restore_missing();
                        let _ = tx.send(Msg::Listed(fw::list_blocked()));
                    });
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!self.blocked.is_empty(), egui::Button::new("Remove all")).clicked() {
                        self.confirm_all = true;
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Select shown").clicked() {
                    for &i in &shown {
                        self.selected.insert(fw::path_key(&self.blocked[i].path));
                    }
                }
                if ui.button("Select none").clicked() {
                    self.selected.clear();
                }
                if ui.add_enabled(missing > 0, egui::Button::new(format!("Select deleted files ({missing})"))).clicked() {
                    self.selected = self.blocked.iter().filter(|b| !b.exists).map(|b| fw::path_key(&b.path)).collect();
                }
                ui.add_space(12.0);
                let n = self.selected.len();
                if ui.add_enabled(n > 0, primary(format!("Remove selected ({n})"))).clicked() {
                    let paths: Vec<String> = self
                        .blocked
                        .iter()
                        .filter(|b| self.selected.contains(&fw::path_key(&b.path)))
                        .map(|b| b.path.clone())
                        .collect();
                    self.remove(ctx, Some(paths));
                }
            });
            if let Some((ok, m)) = &self.list_msg {
                ui.label(RichText::new(m).color(if *ok { OK } else { BAD }));
            }
        });

        if self.confirm_all {
            egui::Window::new("Remove all rules?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("This removes every firewall rule created by Firewall Manager.\nThe blocked programs will be able to use the network again.");
                    ui.horizontal(|ui| {
                        if ui.add(primary("Remove all")).clicked() {
                            self.confirm_all = false;
                            self.remove(ctx, None);
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_all = false;
                        }
                    });
                });
        }

        if self.blocked.is_empty() {
            ui.add_space(20.0);
            ui.label(RichText::new(if self.loaded { "Nothing is blocked yet." } else { "Loading..." }).color(MUTED));
            return;
        }

        // Column header (same widths as the rows below)
        ui.horizontal(|ui| {
            ui.add_space(42.0);
            for (w, t) in [(204.0, "PROGRAM"), (104.0, "DIRECTION"), (104.0, "STATE")] {
                ui.scope(|ui| {
                    ui.set_width(w);
                    ui.label(bold(t, 10.5).color(MUTED));
                });
            }
            ui.label(bold("PATH", 10.5).color(MUTED));
        });

        let row_h = 34.0;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, shown.len(), |ui, range| {
            for &i in &shown[range] {
                let b = &self.blocked[i];
                let key = fw::path_key(&b.path);
                let sel = self.selected.contains(&key);
                let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), row_h - 4.0), egui::Sense::click());
                let fill = if sel {
                    ACCENT.linear_multiply(0.16)
                } else if resp.hovered() {
                    CARD_HI
                } else {
                    CARD
                };
                ui.painter().rect_filled(rect, 8.0, fill);
                if resp.clicked() {
                    if sel {
                        self.selected.remove(&key);
                    } else {
                        self.selected.insert(key);
                    }
                }
                let mut rui = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(rect.shrink2(egui::vec2(10.0, 0.0)))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                let mut c = sel;
                rui.add_enabled(false, egui::Checkbox::without_text(&mut c));
                rui.add_space(6.0);
                rui.scope(|ui| {
                    ui.set_width(204.0);
                    ui.add(egui::Label::new(bold(b.name.clone(), 12.0)).truncate());
                });
                let dir = match (b.inbound, b.outbound) {
                    (true, true) => ("In + Out", OK),
                    (true, false) => ("In only", WARN),
                    (false, true) => ("Out only", WARN),
                    _ => ("none", MUTED),
                };
                rui.scope(|ui| {
                    ui.set_width(104.0);
                    chip(ui, dir.0, dir.1);
                });
                rui.scope(|ui| {
                    ui.set_width(104.0);
                    if !b.active_rules {
                        chip(ui, "Not in firewall", WARN);
                    } else if b.enabled {
                        chip(ui, "Active", OK);
                    } else {
                        chip(ui, "Disabled", MUTED);
                    }
                });
                let mut path = RichText::new(&b.path).monospace().size(10.5).color(if b.exists { MUTED } else { WARN });
                if !b.exists {
                    path = path.strikethrough();
                }
                rui.add(egui::Label::new(path).truncate())
                    .on_hover_text(if b.exists { b.path.as_str() } else { "File no longer exists" });
            }
        });
    }
}
