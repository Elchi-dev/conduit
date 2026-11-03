//! Thin native shell around the Conduit daemon.
//!
//! Desktop: the shell starts the bundled `conduitd` sidecar (or attaches to a
//! daemon already listening on 127.0.0.1:7600), then shows the web app the
//! daemon serves. It adds what a browser tab can't: a tray icon that lights up
//! when something needs you, native notifications, start at login, and signed
//! updates of the whole app (shell and daemon together).
//!
//! Mobile: the same web app runs from the bundled files and reaches a daemon
//! over the LAN or through a hub relay (see web/src/lib/connection.ts).
//!
//! All product logic lives in the Go daemon and the web app; this crate only
//! owns native surfaces. The web app calls the commands below through
//! `window.__TAURI__` (web/src/lib/native.ts).

use serde::Serialize;
use tauri::Manager;

#[cfg(desktop)]
mod desktop {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use tauri::image::Image;
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
    use tauri::{AppHandle, Emitter, Manager, Wry};
    use tauri_plugin_shell::process::{CommandChild, CommandEvent};
    use tauri_plugin_shell::ShellExt;

    pub const DAEMON_ADDR: &str = "127.0.0.1:7600";

    #[derive(Default)]
    pub struct Shell {
        pub sidecar: Mutex<Option<CommandChild>>,
        pub managed: Mutex<bool>,
        pub tray: Mutex<Option<TrayIcon<Wry>>>,
        pub approvals: Mutex<Option<MenuItem<Wry>>>,
    }

    /// GET /healthz with a plain socket, so the shell needs no HTTP client.
    pub fn healthy(addr: &str) -> bool {
        let Some(sock) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
            return false;
        };
        let Ok(mut s) = TcpStream::connect_timeout(&sock, Duration::from_millis(400)) else {
            return false;
        };
        let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
        if s.write_all(format!("GET /healthz HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
            .is_err()
        {
            return false;
        }
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).contains(" 200 ")
    }

    fn start_sidecar(app: &AppHandle) -> Result<(), String> {
        let data = app
            .path()
            .app_data_dir()
            .map_err(|e| e.to_string())?
            .join("daemon");
        std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
        let cmd = app
            .shell()
            .sidecar("conduitd")
            .map_err(|e| format!("the bundled daemon is missing: {e}"))?
            .args(["-listen", DAEMON_ADDR, "-data"])
            .arg(data.to_string_lossy().to_string())
            // The app updates the daemon with itself; the daemon must not
            // replace its own binary inside the bundle.
            .env("CONDUIT_MANAGED", "desktop");
        let (mut rx, child) = cmd
            .spawn()
            .map_err(|e| format!("couldn't start the daemon: {e}"))?;
        let state = app.state::<Shell>();
        *state.sidecar.lock().unwrap() = Some(child);
        *state.managed.lock().unwrap() = true;
        tauri::async_runtime::spawn(async move {
            while let Some(ev) = rx.recv().await {
                match ev {
                    CommandEvent::Stdout(l) | CommandEvent::Stderr(l) => {
                        eprintln!("conduitd: {}", String::from_utf8_lossy(&l).trim_end())
                    }
                    CommandEvent::Terminated(t) => {
                        eprintln!("conduitd exited: {:?}", t.code);
                        break;
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }

    /// Start or find the daemon, then show its UI in the main window.
    pub fn boot(app: AppHandle) {
        std::thread::spawn(move || {
            let mut err = None;
            if !healthy(DAEMON_ADDR) {
                if let Err(e) = start_sidecar(&app) {
                    err = Some(e);
                }
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while err.is_none() && !healthy(DAEMON_ADDR) {
                if Instant::now() > deadline {
                    err = Some(format!(
                        "The daemon didn't answer on {DAEMON_ADDR}. Another program may be using that port."
                    ));
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            let Some(win) = app.get_webview_window("main") else {
                return;
            };
            match err {
                None => {
                    let url = format!("http://{DAEMON_ADDR}/").parse().unwrap();
                    let _ = win.navigate(url);
                }
                Some(e) => {
                    let msg = serde_json::to_string(&e).unwrap_or_default();
                    let _ = win.eval(format!(
                        "window.conduitStartFailed && window.conduitStartFailed({msg})"
                    ));
                }
            }
        });
    }

    pub fn show_main(app: &AppHandle) {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
        }
    }

    pub fn tray(app: &AppHandle) -> tauri::Result<()> {
        let open = MenuItem::with_id(app, "open", "Open Conduit", true, None::<&str>)?;
        let approvals = MenuItem::with_id(
            app,
            "approvals",
            "Nothing waiting for you",
            true,
            None::<&str>,
        )?;
        let panic = MenuItem::with_id(app, "panic", "Emergency stop", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "Quit Conduit", true, None::<&str>)?;
        let menu = Menu::with_items(
            app,
            &[
                &open,
                &PredefinedMenuItem::separator(app)?,
                &approvals,
                &panic,
                &PredefinedMenuItem::separator(app)?,
                &quit,
            ],
        )?;
        let icon = Image::from_bytes(include_bytes!("../icons/tray.png"))?;
        let tray = TrayIconBuilder::with_id("main")
            .icon(icon)
            .tooltip("Conduit")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, ev| match ev.id().as_ref() {
                "open" => show_main(app),
                "approvals" => {
                    show_main(app);
                    let _ = app.emit("conduit://navigate", "/approvals");
                }
                "panic" => {
                    show_main(app);
                    // The page holds the session; it confirms nothing and
                    // stops at once, as the button in the app does.
                    let _ = app.emit("conduit://panic", ());
                }
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
        let state = app.state::<Shell>();
        *state.tray.lock().unwrap() = Some(tray);
        *state.approvals.lock().unwrap() = Some(approvals);
        Ok(())
    }

    /// Light the tray when approvals wait or the emergency stop is on.
    pub fn set_attention(app: &AppHandle, waiting: u32, frozen: bool) {
        let state = app.state::<Shell>();
        let label = match waiting {
            0 => "Nothing waiting for you".to_string(),
            1 => "1 approval waiting for you".to_string(),
            n => format!("{n} approvals waiting for you"),
        };
        if let Some(item) = state.approvals.lock().unwrap().as_ref() {
            let _ = item.set_text(&label);
        };
        if let Some(tray) = state.tray.lock().unwrap().as_ref() {
            let lit = waiting > 0 || frozen;
            let bytes: &[u8] = if lit {
                include_bytes!("../icons/tray-attention.png")
            } else {
                include_bytes!("../icons/tray.png")
            };
            if let Ok(img) = Image::from_bytes(bytes) {
                let _ = tray.set_icon(Some(img));
            }
            let tip = if frozen {
                "Conduit: emergency stop is on".to_string()
            } else if waiting > 0 {
                format!("Conduit: {label}")
            } else {
                "Conduit".to_string()
            };
            let _ = tray.set_tooltip(Some(tip));
        };
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellInfo {
    version: String,
    platform: &'static str,
    /// The app started the daemon itself (as opposed to attaching to one).
    managed_daemon: bool,
    updates: bool,
    autostart: bool,
    /// A tray icon is showing (some Linux desktops have none).
    tray: bool,
}

#[tauri::command]
fn shell_info(app: tauri::AppHandle) -> ShellInfo {
    #[cfg(desktop)]
    {
        use tauri_plugin_autostart::ManagerExt;
        let state = app.state::<desktop::Shell>();
        let managed = *state.managed.lock().unwrap();
        let tray = state.tray.lock().unwrap().is_some();
        ShellInfo {
            version: app.package_info().version.to_string(),
            platform: std::env::consts::OS,
            managed_daemon: managed,
            updates: true,
            autostart: app.autolaunch().is_enabled().unwrap_or(false),
            tray,
        }
    }
    #[cfg(mobile)]
    {
        ShellInfo {
            version: app.package_info().version.to_string(),
            platform: std::env::consts::OS,
            managed_daemon: false,
            updates: false,
            autostart: false,
            tray: false,
        }
    }
}

#[tauri::command]
fn set_attention(app: tauri::AppHandle, waiting: u32, frozen: bool) {
    #[cfg(desktop)]
    desktop::set_attention(&app, waiting, frozen);
    #[cfg(mobile)]
    let _ = (app, waiting, frozen);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInfo {
    version: String,
    current: String,
    notes: Option<String>,
    date: Option<String>,
}

/// Ask the update feed whether a newer signed release exists.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_updater::UpdaterExt;
        let update = app
            .updater()
            .map_err(|e| e.to_string())?
            .check()
            .await
            .map_err(|e| e.to_string())?;
        Ok(update.map(|u| UpdateInfo {
            version: u.version.clone(),
            current: u.current_version.clone(),
            notes: u.body.clone(),
            date: u.date.map(|d| d.to_string()),
        }))
    }
    #[cfg(mobile)]
    {
        let _ = app;
        Err("updates on Android come from the in-app updater".into())
    }
}

/// Download, verify (the updater checks the minisign signature against the
/// key in tauri.conf.json), install and restart.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_updater::UpdaterExt;
        let Some(update) = app
            .updater()
            .map_err(|e| e.to_string())?
            .check()
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("Already up to date.".into());
        };
        update
            .download_and_install(|_, _| {}, || {})
            .await
            .map_err(|e| e.to_string())?;
        stop_sidecar(&app);
        app.restart();
    }
    #[cfg(mobile)]
    {
        let _ = app;
        Err("updates on Android come from the in-app updater".into())
    }
}

#[tauri::command]
fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<bool, String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_autostart::ManagerExt;
        let al = app.autolaunch();
        if enabled {
            al.enable().map_err(|e| e.to_string())?;
        } else {
            al.disable().map_err(|e| e.to_string())?;
        }
        al.is_enabled().map_err(|e| e.to_string())
    }
    #[cfg(mobile)]
    {
        let _ = (app, enabled);
        Err("not available on this device".into())
    }
}

#[cfg(desktop)]
fn stop_sidecar(app: &tauri::AppHandle) {
    if let Some(child) = app.state::<desktop::Shell>().sidecar.lock().unwrap().take() {
        let _ = child.kill();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(desktop)]
    let builder = builder
        // A second launch focuses the running app instead of starting
        // another daemon.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            desktop::show_main(app)
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .manage(desktop::Shell::default());

    let app = builder
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            shell_info,
            set_attention,
            check_update,
            install_update,
            set_autostart
        ])
        .setup(|app| {
            #[cfg(desktop)]
            {
                // Some Linux desktops lack an app-indicator library, and
                // loading it panics. Without a tray, closing the window quits.
                let handle = app.handle().clone();
                let tray = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    desktop::tray(&handle)
                }));
                if !matches!(tray, Ok(Ok(()))) {
                    eprintln!(
                        "conduit: no system tray on this desktop; closing the window will quit"
                    );
                }
                desktop::boot(app.handle().clone());
                // Started at login: stay in the tray until asked.
                if std::env::args().any(|a| a == "--background") {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.hide();
                    }
                }
            }
            #[cfg(mobile)]
            let _ = app;
            Ok(())
        })
        .on_window_event(|win, ev| {
            // Closing the window keeps Conduit running in the tray.
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = ev {
                let has_tray = win.state::<desktop::Shell>().tray.lock().unwrap().is_some();
                if win.label() == "main" && has_tray {
                    api.prevent_close();
                    let _ = win.hide();
                }
            }
            #[cfg(mobile)]
            let _ = (win, ev);
        })
        .build(tauri::generate_context!())
        .expect("error while building Conduit");

    app.run(|handle, ev| {
        #[cfg(desktop)]
        if let tauri::RunEvent::Exit = ev {
            stop_sidecar(handle);
        }
        #[cfg(mobile)]
        let _ = (handle, ev);
    });
}
