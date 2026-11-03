//! The daemon's lifecycle as the app manages it: detect, start, recover, report.
//!
//! The app is still only a client. It never monitors anything itself. What it
//! owns is making sure the monitoring program is running and telling the truth
//! about it:
//!
//! * **Start.** When nothing answers on the daemon's port, start it through the
//!   installer's supported mechanism (the logon scheduled task) and only if that
//!   task does not exist, directly. Never both: that would race two daemons for
//!   one port. A port that already answers is never "started" again.
//! * **Recover.** A daemon that stopped is restarted, within a budget
//!   (`Governor`): a daemon that dies again and again is reported as failing,
//!   with its reason, instead of being restarted in a loop forever.
//! * **Report.** `Status` is what the person sees. It is derived from facts
//!   (can the program be found, does it answer, did the pulse say healthy, are
//!   collectors blind). "Monitoring" is shown only when all of them hold.

use serde::Serialize;
use serde_json::Value;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pulse;

/// How long a freshly started daemon gets to open its port. A first start on a
/// slow disk verifies its own code before it listens.
const START_WAIT: Duration = Duration::from_secs(45);
/// At most this many starts per window; after that the failure is reported.
const MAX_STARTS: usize = 3;
const WINDOW: Duration = Duration::from_secs(600);
const TASK_NAME: &str = "jarvis native service";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Looking, or waiting for a start to finish.
    Starting,
    /// Answering, healthy, no collector blind.
    Live,
    /// Answering, but the daemon itself says something is not working.
    Degraded,
    /// Not installed on this computer.
    NotInstalled,
    /// Installed, answering, but this app is not authorised.
    NotAuthorised,
    /// Installed but not answering, and starting it did not work.
    Stopped,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    /// One plain sentence for the person.
    pub message: String,
    /// What to do or what was found, when there is more to say.
    pub detail: String,
}

impl Status {
    fn new(phase: Phase, message: &str, detail: impl Into<String>) -> Self {
        Status { phase, message: message.into(), detail: detail.into() }
    }
}

/// Why a collector is blind, from what the daemon reports about it. An explicit
/// `reason` wins; otherwise the failure flags are put in plain words.
fn blind_reason(b: &Value) -> String {
    if let Some(r) = b.get("reason").and_then(Value::as_str).filter(|r| !r.is_empty()) {
        return r.to_string();
    }
    if b.get("error").and_then(Value::as_bool) == Some(true) {
        return "it failed the last time it ran".into();
    }
    match b.get("freshness").and_then(Value::as_str) {
        Some("STALE") => "it has not reported recently".into(),
        _ => "no reason reported".into(),
    }
}

/// What a pulse from the daemon means for the person. `blind` lists collectors
/// that cannot run; each is named so the limitation is explained, not hidden.
pub fn classify_pulse(p: &Value) -> Status {
    if p.get("ok").and_then(Value::as_bool) != Some(true) {
        return Status::new(Phase::Degraded, "ARGUS-1 is running but did not report its state", "Its last report was incomplete.");
    }
    let blind: Vec<String> = p
        .get("blind")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|b| {
                    let name = b.get("label").or_else(|| b.get("job")).and_then(Value::as_str).unwrap_or("a collector");
                    format!("{name}: {}", blind_reason(b))
                })
                .collect()
        })
        .unwrap_or_default();
    if p.get("healthy").and_then(Value::as_bool) != Some(true) {
        return Status::new(Phase::Degraded, "ARGUS-1 is running but reports a problem with itself", blind.join("; "));
    }
    if !blind.is_empty() {
        let n = blind.len();
        let msg = format!("Monitoring is partial: {n} area{} cannot be fully watched", if n == 1 { "" } else { "s" });
        return Status::new(Phase::Degraded, &msg, blind.join("; "));
    }
    Status::new(Phase::Live, "Monitoring is active", "")
}

/// Restart budget: at most `MAX_STARTS` starts per `WINDOW`.
#[derive(Debug, Default)]
pub struct Governor {
    starts: Vec<Instant>,
}

impl Governor {
    pub fn allow(&mut self, now: Instant) -> bool {
        self.starts.retain(|t| now.duration_since(*t) < WINDOW);
        if self.starts.len() >= MAX_STARTS {
            return false;
        }
        self.starts.push(now);
        true
    }
}

/// Where the daemon's runtime is installed. Injectable for tests.
pub fn runtime_home(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(py) = env("JARVIS_PYTHON").filter(|p| !p.is_empty()) {
        return Path::new(&py).parent().map(Path::to_path_buf);
    }
    if cfg!(windows) {
        return env("JARVIS_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| env("LOCALAPPDATA").map(|l| Path::new(&l).join("Programs").join("Jarvis")));
    }
    None
}

/// The packaged program (a compiled `jarvis.exe` that is both the CLI and the
/// daemon) when the installer put one in `home`.
pub fn packaged_exe(home: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let exe = home.join("jarvis.exe");
    exists(&exe).then_some(exe)
}

pub fn installed(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> bool {
    if env("JARVIS_PYTHON").filter(|p| !p.is_empty()).is_some() {
        return true;
    }
    if cfg!(windows) {
        return runtime_home(env).is_some_and(|h| packaged_exe(&h, exists).is_some() || exists(&h.join("python").join("python.exe")));
    }
    ["/usr/local/bin/jarvis-svc", "/usr/bin/jarvis-svc"].iter().any(|p| exists(Path::new(p)))
}

/// True when something accepts connections on the daemon's loopback port.
pub fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)).is_ok()
}

#[cfg(windows)]
fn hidden(c: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    c.creation_flags(0x0800_0000) // CREATE_NO_WINDOW
}
#[cfg(not(windows))]
fn hidden(c: &mut Command) -> &mut Command {
    c
}

/// Ask the installer's scheduled task to start the daemon. Ok(true): the task
/// exists and was started; Ok(false): there is no such task.
fn start_task() -> Result<bool, String> {
    if !cfg!(windows) {
        return Ok(false);
    }
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = Path::new(&sys).join("System32").join("schtasks.exe");
    let mut q = Command::new(&exe);
    q.args(["/Query", "/TN", TASK_NAME]).stdout(Stdio::null()).stderr(Stdio::null());
    if !hidden(&mut q).status().map(|s| s.success()).unwrap_or(false) {
        return Ok(false);
    }
    let mut r = Command::new(&exe);
    r.args(["/Run", "/TN", TASK_NAME]).stdout(Stdio::null()).stderr(Stdio::null());
    match hidden(&mut r).status() {
        Ok(s) if s.success() => Ok(true),
        _ => Err("Windows would not start the ARGUS-1 background task".into()),
    }
}

/// Start the daemon directly, detached from this app (closing the app must not
/// stop monitoring). Only used when the installer's task does not exist.
fn start_direct(env: &dyn Fn(&str) -> Option<String>, port: u16) -> Result<(), String> {
    let home = runtime_home(env).ok_or("ARGUS-1's monitoring program was not found")?;
    let port_s = port.to_string();
    let mut c = match (env("JARVIS_PYTHON").filter(|p| !p.is_empty()), packaged_exe(&home, &|p| p.exists())) {
        (Some(py), _) => {
            let mut c = Command::new(py);
            c.args(["-m", "jarvis", "serve", "--port", &port_s]);
            c
        }
        (None, Some(exe)) => {
            let mut c = Command::new(exe);
            c.args(["serve", "--port", &port_s]).current_dir(&home);
            c
        }
        (None, None) => {
            let mut c = Command::new(home.join("python").join("python.exe"));
            c.args(["-m", "jarvis", "serve", "--port", &port_s]);
            c
        }
    };
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(app) = env("JARVIS_APP_DIR").filter(|p| !p.is_empty()).map(PathBuf::from).or_else(|| Some(home.join("app")).filter(|p| p.is_dir())) {
        c.current_dir(app);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000 | 0x0000_0008); // no window, detached from this app
    }
    c.spawn().map(|_| ()).map_err(|e| format!("could not start ARGUS-1 ({e})"))
}

/// Make sure the daemon answers, starting it when it does not. Returns the
/// status to show: `Live`-class statuses are decided by the pulse, not here,
/// so this returns `Starting` once the port is open.
pub fn ensure_running(governor: &mut Governor, port: u16) -> Status {
    let env = |k: &str| std::env::var(k).ok();
    if !installed(&env, &|p| p.exists()) {
        return Status::new(
            Phase::NotInstalled,
            "ARGUS-1's monitoring program is not installed on this computer",
            "Run the ARGUS-1 installer to add it. Nothing is being monitored until then.",
        );
    }
    if listening(port) {
        return Status::new(Phase::Starting, "Connecting to ARGUS-1", "");
    }
    if !governor.allow(Instant::now()) {
        return Status::new(
            Phase::Stopped,
            "ARGUS-1 monitoring has stopped and could not be restarted",
            "It was restarted several times in the last ten minutes and stopped each time. Nothing is being monitored. Restart the computer, or reinstall ARGUS-1 if this continues.",
        );
    }
    let started = match start_task() {
        Ok(true) => Ok(()),
        Ok(false) => start_direct(&env, port),
        Err(e) => Err(e),
    };
    if let Err(e) = started {
        return Status::new(Phase::Stopped, "ARGUS-1 monitoring is not running and could not be started", e);
    }
    let end = Instant::now() + START_WAIT;
    while Instant::now() < end {
        if listening(port) {
            return Status::new(Phase::Starting, "ARGUS-1 started; connecting", "");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Status::new(
        Phase::Stopped,
        "ARGUS-1 was started but is not answering",
        format!("It did not open its local port within {} seconds.", START_WAIT.as_secs()),
    )
}

/// The last status, for the interface to read.
static CURRENT: Mutex<Option<Status>> = Mutex::new(None);

pub fn set(s: Status) {
    if let Ok(mut g) = CURRENT.lock() {
        *g = Some(s);
    }
}

pub fn current() -> Status {
    CURRENT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| Status::new(Phase::Starting, "Starting ARGUS-1", ""))
}

/// The status after a failed token fetch or refused request.
pub fn from_error(e: &str) -> Status {
    if e.contains("not paired") || e.contains("refused this app") {
        Status::new(Phase::NotAuthorised, "This app is not authorised to talk to ARGUS-1", e)
    } else {
        Status::new(Phase::Stopped, "ARGUS-1 is not reachable", e)
    }
}

/// Used by `--check`: Ok when the daemon answers after at most one start.
pub fn ensure_for_check() -> Status {
    ensure_running(&mut Governor::default(), pulse::port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn healthy_and_nothing_blind_is_the_only_live() {
        let p = json!({"ok": true, "healthy": true, "blind": [], "score": 95});
        assert_eq!(classify_pulse(&p).phase, Phase::Live);
    }

    #[test]
    fn a_blind_collector_is_degraded_and_named_with_its_reason() {
        let p = json!({"ok": true, "healthy": true,
            "blind": [{"job": "sysmon", "label": "Windows event log", "reason": "needs administrator rights"}]});
        let s = classify_pulse(&p);
        assert_eq!(s.phase, Phase::Degraded);
        assert!(s.message.contains("1 area cannot be fully watched"), "{}", s.message);
        assert!(s.detail.contains("Windows event log") && s.detail.contains("needs administrator rights"));
    }

    #[test]
    fn blind_collectors_are_explained_from_the_daemons_flags() {
        let p = json!({"ok": true, "healthy": true, "blind": [
            {"job": "scan", "label": "Processes", "freshness": "STALE", "error": false},
            {"job": "net", "label": "Network", "freshness": "FRESH", "error": true},
            {"job": "x"}]});
        let s = classify_pulse(&p);
        assert!(s.message.contains("3 areas"));
        assert!(s.detail.contains("Processes: it has not reported recently"));
        assert!(s.detail.contains("Network: it failed the last time it ran"));
        assert!(s.detail.contains("x: no reason reported"));
    }

    #[test]
    fn unhealthy_or_incomplete_pulses_are_never_live() {
        for p in [json!({"ok": true, "healthy": false}), json!({"ok": true}), json!({"ok": false}), json!({}), json!(null)] {
            assert_eq!(classify_pulse(&p).phase, Phase::Degraded, "{p}");
        }
    }

    #[test]
    fn the_governor_stops_a_restart_loop_and_forgives_after_the_window() {
        let mut g = Governor::default();
        let t0 = Instant::now();
        assert!(g.allow(t0) && g.allow(t0) && g.allow(t0));
        assert!(!g.allow(t0), "a fourth start inside ten minutes is refused");
        assert!(g.allow(t0 + WINDOW + Duration::from_secs(1)), "and allowed again afterwards");
    }

    #[test]
    fn not_installed_is_said_plainly_and_nothing_is_started() {
        let none = |_: &str| None;
        if cfg!(windows) {
            let env = |k: &str| (k == "LOCALAPPDATA").then(|| "C:\\Users\\nobody\\AppData\\Local".to_string());
            assert!(!installed(&env, &|_| false));
        } else {
            assert!(!installed(&none, &|_| false));
        }
        assert!(installed(&|k: &str| (k == "JARVIS_PYTHON").then(|| "x".to_string()), &|_| false));
    }

    #[test]
    fn errors_map_to_a_reason_the_person_can_act_on() {
        assert_eq!(from_error("ARGUS-1 is not paired with this app. ...").phase, Phase::NotAuthorised);
        assert_eq!(from_error("could not reach ARGUS-1").phase, Phase::Stopped);
    }

    #[test]
    fn listening_sees_a_real_socket_and_a_closed_one() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(listening(port));
        drop(l);
        assert!(!listening(port));
    }
}
