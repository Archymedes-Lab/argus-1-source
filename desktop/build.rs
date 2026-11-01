// Only these commands exist for the interface, and capabilities/main.json
// grants them to the main window alone. Anything not listed here cannot be
// invoked, whatever the page does.
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "daemon_state",
            "daemon_status",
            "run_collector",
            "answer_question",
            "ask_jarvis",
            "score_coach",
            "decide_fix",
            "billing_status",
            "billing_checkout",
            "autopilot_status",
            "autopilot_decide",
            "autopilot_policy",
            "get_settings",
            "set_settings",
            "pause_monitoring",
            "resume_monitoring",
            "protection_status",
            "protection_scan",
        ]),
    ))
    .expect("tauri build");
}
