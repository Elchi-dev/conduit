//! Thin native shell around the Conduit daemon.
//!
//! On desktop the shell starts the bundled `conduitd` sidecar (unless a remote
//! daemon is configured) and shows the UI the daemon serves. All logic lives in
//! the Go daemon; this crate only owns the window, tray, notifications and the
//! native updater.

use tauri::Manager;

#[cfg(desktop)]
fn start_sidecar(app: &tauri::AppHandle) {
    use tauri_plugin_shell::ShellExt;
    match app.shell().sidecar("conduitd") {
        Ok(cmd) => {
            if let Err(e) = cmd.spawn() {
                eprintln!("conduit: failed to start daemon: {e}");
            }
        }
        Err(e) => eprintln!("conduit: daemon sidecar missing: {e}"),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            #[cfg(desktop)]
            start_sidecar(app.handle());
            let _ = app.get_webview_window("main");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Conduit");
}
