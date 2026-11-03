fn main() {
    // App commands the web app may call. The daemon's own page (a remote
    // origin, http://127.0.0.1) gets them through capabilities/daemon.json.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "shell_info",
            "set_attention",
            "check_update",
            "install_update",
            "set_autostart",
        ]),
    ))
    .expect("failed to run tauri-build");
}
