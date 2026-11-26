//! "Close to tray": the setting, the tray icon, hiding/showing the window and the single-instance
//! signal (starting the app again opens the window of the running one).

use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::core::{w, BOOL};
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, WAIT_OBJECT_0};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_CLOAK, DWMWA_TEXT_COLOR,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{ITaskbarList, TaskbarList};
use windows::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, IsIconic, SetForegroundWindow, ShowWindowAsync, ASFW_ANY, SW_MINIMIZE, SW_RESTORE,
};

const SETTING: &str = "close_to_tray=1";

fn settings_file() -> Option<std::path::PathBuf> {
    Some(crate::fw::secure_dir()?.join("settings.txt"))
}

pub fn load_close_to_tray() -> bool {
    settings_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .is_some_and(|t| t.lines().any(|l| l.trim() == SETTING))
}

pub fn save_close_to_tray(on: bool) -> Result<(), String> {
    let f = settings_file().ok_or("data folder not available")?;
    std::fs::write(f, if on { SETTING } else { "" }).map_err(|e| e.to_string())
}

/// The main window. In the tray it is cloaked, minimised and taken off the taskbar rather than
/// hidden: eframe spins a full CPU core on a window that is hidden and gets no paint messages.
#[derive(Clone, Copy)]
pub struct Window(isize);

impl Window {
    pub fn of(handle: &impl HasWindowHandle) -> Option<Self> {
        match handle.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(h) => Some(Window(h.hwnd.get())),
            _ => None,
        }
    }

    fn hwnd(self) -> HWND {
        HWND(self.0 as *mut _)
    }

    pub fn hide(self) {
        self.cloak(true);
        unsafe {
            // minimising hands the keyboard focus to the next window
            let _ = ShowWindowAsync(self.hwnd(), SW_MINIMIZE);
        }
        self.taskbar_button(false);
    }

    pub fn show(self) {
        self.cloak(false);
        self.taskbar_button(true);
        unsafe {
            if IsIconic(self.hwnd()).as_bool() {
                let _ = ShowWindowAsync(self.hwnd(), SW_RESTORE);
            }
            let _ = SetForegroundWindow(self.hwnd());
        }
    }

    /// Colours the native title bar like the app, so both read as one window (Windows 11; older
    /// versions keep their dark title bar).
    pub fn color_title_bar(self, background: egui::Color32, text: egui::Color32) {
        for (attribute, c) in [(DWMWA_CAPTION_COLOR, background), (DWMWA_BORDER_COLOR, background), (DWMWA_TEXT_COLOR, text)] {
            // COLORREF is 0x00BBGGRR
            let value = u32::from_le_bytes([c.r(), c.g(), c.b(), 0]);
            unsafe {
                let _ = DwmSetWindowAttribute(self.hwnd(), attribute, &value as *const _ as *const _, size_of::<u32>() as u32);
            }
        }
    }

    fn cloak(self, on: bool) {
        let value = BOOL::from(on);
        unsafe {
            let _ = DwmSetWindowAttribute(self.hwnd(), DWMWA_CLOAK, &value as *const _ as *const _, size_of::<BOOL>() as u32);
        }
    }

    fn taskbar_button(self, on: bool) {
        let _com = crate::fw::ComGuard::new();
        unsafe {
            let Ok(list) = CoCreateInstance::<_, ITaskbarList>(&TaskbarList, None, CLSCTX_INPROC_SERVER) else { return };
            if list.HrInit().is_ok() {
                let _ = if on { list.AddTab(self.hwnd()) } else { list.DeleteTab(self.hwnd()) };
            }
        }
    }
}

/// Event that marks this app as running; setting it asks the running copy to show itself.
#[derive(Clone, Copy)]
pub struct Instance(isize);

/// `None` when the app is already running; that copy has then been asked to show its window.
pub fn claim_instance() -> Option<Instance> {
    unsafe {
        let Ok(event) = CreateEventW(None, false, false, w!("Local\\FirewallManager.Show")) else {
            return Some(Instance(0));
        };
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = AllowSetForegroundWindow(ASFW_ANY);
            let _ = SetEvent(event);
            return None;
        }
        Some(Instance(event.0 as isize))
    }
}

/// Shows the window whenever a second start, a tray click or the tray menu asks for it.
/// "Quit" sets `quit` so the close that follows is not turned into hiding. Call once.
pub fn listen(instance: Instance, window: Window, ctx: egui::Context, quit: Arc<AtomicBool>) {
    let c = ctx.clone();
    std::thread::spawn(move || {
        while unsafe { WaitForSingleObject(HANDLE(instance.0 as *mut _), INFINITE) } == WAIT_OBJECT_0 {
            window.show();
            c.request_repaint();
        }
    });
    let c = ctx.clone();
    TrayIconEvent::set_event_handler(Some(move |e| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
            window.show();
            c.request_repaint();
        }
    }));
    MenuEvent::set_event_handler(Some(Arc::new(move |e: MenuEvent| {
        window.show();
        if e.id() == "quit" {
            quit.store(true, Ordering::SeqCst);
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint();
    })));
}

/// The tray icon; dropping it removes it. Must be created on the UI thread.
pub fn icon() -> Result<TrayIcon, String> {
    let open = MenuItem::with_id("open", "Open Firewall Manager", true, None);
    let quit = MenuItem::with_id("quit", "Quit", true, None);
    let menu = Menu::with_items(&[&open, &quit]).map_err(|e| e.to_string())?;
    let image = Icon::from_rgba(include_bytes!("../assets/icon.rgba").to_vec(), 64, 64).map_err(|e| e.to_string())?;
    TrayIconBuilder::new()
        .with_tooltip("Firewall Manager")
        .with_icon(image)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()
        .map_err(|e| e.to_string())
}
