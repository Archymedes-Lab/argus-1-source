//! JARVIS desktop: an always-open window, tray and notifications over the
//! local daemon (docs/architecture/DESKTOP-APP.md).
//!
//! The app is a client, never the monitor. `jarvis serve` collects, scores
//! and responds whether or not this is running; nothing here observes the
//! machine or acts on it. The window shows the daemon's own dashboard, and
//! the tray reads the daemon's pulse stream.
//!
//! Trust boundary:
//! * The page is the daemon's (http://127.0.0.1:8787). It gets no Tauri IPC:
//!   there are no capabilities, `withGlobalTauri` is off, and the window may
//!   only navigate to the daemon or to the bundled fallback page.
//! * Every action the page offers still goes through the daemon's own local
//!   API checks (loopback, Host, same-origin). The app adds no new route in.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod pulse;
mod watch;

use std::thread;
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;
use watch::{Level, View, Watch};

const MAIN: &str = "main";
const POLL_WHEN_REFUSED: Duration = Duration::from_secs(15);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct Tray {
    icon: TrayIcon<Wry>,
    status: MenuItem<Wry>,
}

/// The only pages this window may show: the daemon, and the bundled
/// fallback (served from tauri://localhost or http(s)://tauri.localhost).
fn allowed(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("");
    match url.scheme() {
        "http" if host == "127.0.0.1" || host == "localhost" => {
            url.port_or_known_default() == Some(pulse::port())
        }
        "http" | "https" => host == "tauri.localhost",
        "tauri" => host == "localhost",
        _ => false,
    }
}

fn on_dashboard(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"))
        && url.port_or_known_default() == Some(pulse::port())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// A 32x32 tray dot in the level's colour, drawn in code (no image assets).
fn dot(level: Level) -> Image<'static> {
    let (r, g, b) = match level {
        Level::Good => (34, 197, 94),
        Level::Attention => (245, 158, 11),
        Level::Alarm => (239, 68, 68),
        Level::Unknown => (100, 116, 139),
    };
    const N: usize = 32;
    let mut px = vec![0u8; N * N * 4];
    let c = N as f32 / 2.0;
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 + 0.5 - c).powi(2) + (y as f32 + 0.5 - c).powi(2)).sqrt();
            let a = (13.5 - d).clamp(0.0, 1.0);
            let i = (y * N + x) * 4;
            px[i..i + 4].copy_from_slice(&[r, g, b, (a * 255.0) as u8]);
        }
    }
    Image::new_owned(px, N as u32, N as u32)
}

fn apply(app: &AppHandle, view: View, last: &mut Option<Level>) {
    if let Some(tray) = app.try_state::<Tray>() {
        // Windows caps tray tooltips at 127 characters.
        let tip: String = view.line.chars().take(120).collect();
        let _ = tray.icon.set_tooltip(Some(&tip));
        let _ = tray.status.set_text(&tip);
        if *last != Some(view.level) {
            let _ = tray.icon.set_icon(Some(dot(view.level)));
            *last = Some(view.level);
        }
    }
    for t in view.toasts {
        let _ = app.notification().builder().title(&t.title).body(&t.body).show();
    }
}

/// Leave the fallback page for the dashboard once the daemon answers.
fn ensure_dashboard(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        if !w.url().map(|u| on_dashboard(&u)).unwrap_or(false) {
            if let Ok(u) = pulse::dashboard_url().parse() {
                let _ = w.navigate(u);
            }
        }
    }
}

fn pulse_loop(app: AppHandle) {
    let mut watch = Watch::default();
    let mut last = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut got = false;
        let end = pulse::stream(&mut |p| {
            if !got {
                got = true;
                ensure_dashboard(&app);
            }
            apply(&app, watch.pulse(&p), &mut last);
        });
        match end {
            pulse::End::Refused => {
                // Up, but every stream slot is taken (or we were refused):
                // poll the same summary instead of going dark.
                match pulse::poll() {
                    Ok(p) => apply(&app, watch.pulse(&p), &mut last),
                    Err(_) => apply(&app, watch.unreachable(Instant::now()), &mut last),
                }
                thread::sleep(POLL_WHEN_REFUSED);
            }
            _ if got => backoff = Duration::from_secs(1), // stream ended normally
            _ => {
                apply(&app, watch.unreachable(Instant::now()), &mut last);
                thread::sleep(backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "JARVIS — connecting", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open JARVIS", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Close this app (monitoring continues)", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &sep, &open, &quit])?;
    let icon = TrayIconBuilder::with_id("jarvis")
        .icon(dot(Level::Unknown))
        .tooltip("JARVIS — connecting")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(Tray { icon, status });
    Ok(())
}

fn main() {
    // `--hidden`: start in the tray (used by the logon task).
    let hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .setup(move |app| {
            build_tray(app)?;
            let first = if pulse::reachable() {
                WebviewUrl::External(pulse::dashboard_url().parse().expect("static URL"))
            } else {
                WebviewUrl::App("index.html".into())
            };
            WebviewWindowBuilder::new(app, MAIN, first)
                .title("JARVIS")
                .inner_size(1440.0, 920.0)
                .min_inner_size(720.0, 480.0)
                .visible(!hidden)
                .on_navigation(allowed)
                .build()?;
            let handle = app.handle().clone();
            thread::Builder::new()
                .name("jarvis-pulse".into())
                .spawn(move || pulse_loop(handle))?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to the tray: "always open" is the point, and the
            // tray menu is the explicit way out.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == MAIN {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("JARVIS desktop failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        s.parse().unwrap()
    }

    #[test]
    fn navigation_is_pinned_to_the_daemon_and_the_fallback() {
        assert!(allowed(&u("http://127.0.0.1:8787/")));
        assert!(allowed(&u("http://localhost:8787/geo")));
        assert!(allowed(&u("http://tauri.localhost/index.html")));
        assert!(allowed(&u("tauri://localhost/index.html")));
        assert!(!allowed(&u("http://127.0.0.1:8788/")));
        assert!(!allowed(&u("http://127.0.0.1/")));
        assert!(!allowed(&u("https://127.0.0.1:8787/")));
        assert!(!allowed(&u("https://example.com/")));
        assert!(!allowed(&u("http://127.0.0.1.evil.example:8787/")));
        assert!(!allowed(&u("file:///C:/Windows/")));
        assert!(!allowed(&u("javascript:alert(1)")));
    }

    #[test]
    fn dashboard_detection() {
        assert!(on_dashboard(&u("http://127.0.0.1:8787/")));
        assert!(!on_dashboard(&u("http://tauri.localhost/index.html")));
    }
}
