//! The typed bridge between the bundled interface and the daemon.
//!
//! The interface is a page from `tauri://localhost`; it is cross-origin to
//! the daemon on purpose and has no network permission of its own. Every
//! request it needs goes through one of the commands below, which run here,
//! validate their arguments against the daemon's own formats, and make one
//! bounded loopback request. The page never sees the API token.
//!
//! Every request carries the app's paired client token (pairing.rs): the
//! daemon requires a credential on every route but liveness, and it no longer
//! hands its dashboard cookie to a peer whose account it cannot identify,
//! which from Windows across WSL it never can. Unpaired, every command fails
//! with the steps to pair.

use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::{pairing, pulse};

/// The state document is about 0.5 MB on a busy machine; 8 MB bounds a
/// misbehaving peer without truncating a real one.
pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_HEADER_LINE: u64 = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// A loaded machine has taken 9 s to build the state document.
const STATE_TIMEOUT: Duration = Duration::from_secs(45);
const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
/// The assistant may consult the local model.
const ASK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Parse a complete HTTP/1.x response: status, headers, body bounded by
/// Content-Length (or by EOF under `Connection: close`) and by MAX_BODY.
pub fn parse_response<R: BufRead>(r: &mut R) -> io::Result<Response> {
    let mut line = String::new();
    read_bounded_line(r, &mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| bad("bad status line"))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if read_bounded_line(r, &mut line)? == 0 {
            return Err(bad("headers ended early"));
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(bad("too many headers"));
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut resp = Response { status, headers, body: Vec::new() };
    if resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        return Err(bad("chunked bodies are not expected from the daemon"));
    }
    match resp.header("content-length").map(|v| v.parse::<usize>()) {
        Some(Ok(n)) if n > MAX_BODY => return Err(bad("body too large")),
        Some(Ok(n)) => {
            resp.body = vec![0; n];
            r.read_exact(&mut resp.body)?;
        }
        Some(Err(_)) => return Err(bad("bad content-length")),
        None => {
            r.by_ref().take(MAX_BODY as u64 + 1).read_to_end(&mut resp.body)?;
            if resp.body.len() > MAX_BODY {
                return Err(bad("body too large"));
            }
        }
    }
    Ok(resp)
}

fn read_bounded_line<R: BufRead>(r: &mut R, line: &mut String) -> io::Result<usize> {
    let n = r.by_ref().take(MAX_HEADER_LINE).read_line(line)?;
    if n as u64 == MAX_HEADER_LINE && !line.ends_with('\n') {
        return Err(bad("header line too long"));
    }
    Ok(n)
}

fn request(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Response> {
    request_to(pulse::port(), method, path, token, body, timeout)
}

/// The same request to an explicit loopback port (tests aim it at a fake daemon).
fn request_to(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Response> {
    let sock = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), pulse::CONNECT_TIMEOUT)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(pulse::CONNECT_TIMEOUT))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: jarvis-desktop\r\n\
         Accept: application/json\r\nConnection: close\r\n"
    );
    if let Some(t) = token {
        head.push_str(&format!("X-JARVIS-Token: {t}\r\n"));
    }
    if let Some(b) = body {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    head.push_str("\r\n");
    (&sock).write_all(head.as_bytes())?;
    if let Some(b) = body {
        (&sock).write_all(b)?;
    }
    parse_response(&mut BufReader::new(sock))
}

fn unreachable(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "ARGUS-1 is not running (nothing answers on the loopback port)".into(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "ARGUS-1 did not answer in time".into(),
        _ => format!("could not reach ARGUS-1: {e}"),
    }
}

fn json_of(r: &Response) -> Result<Value, String> {
    serde_json::from_slice(&r.body).map_err(|_| format!("ARGUS-1 answered HTTP {} with a body that is not JSON", r.status))
}

/// A 403 that names the token: the pairing was revoked or never made.
fn refused_token(r: &Response, v: &Value) -> bool {
    r.status == 403 && v.get("error").and_then(Value::as_str).is_some_and(|m| m.contains("token"))
}

fn get_json(path: &str, timeout: Duration) -> Result<Value, String> {
    let t = pairing::client_token()?;
    let r = request("GET", path, Some(&t), None, timeout).map_err(|e| unreachable(&e))?;
    if r.status != 200 {
        let v = json_of(&r).unwrap_or(Value::Null);
        if refused_token(&r, &v) {
            return Err(REVOKED.into());
        }
        return Err(format!("ARGUS-1 answered HTTP {}", r.status));
    }
    json_of(&r)
}

const REVOKED: &str = "ARGUS-1 refused this app's pairing (revoked, or from another install). \
                       Pair again: `jarvis desktop pair --name desktop`, then replace client.token.";

/// A state-changing call with the paired client token.
fn post_json(path: &str, body: &Value, timeout: Duration) -> Result<Value, String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let t = pairing::client_token()?;
    let r = request("POST", path, Some(&t), Some(&bytes), timeout).map_err(|e| unreachable(&e))?;
    let v = json_of(&r).unwrap_or(Value::Null);
    if refused_token(&r, &v) {
        return Err(REVOKED.into());
    }
    if (200..300).contains(&r.status) {
        return Ok(v);
    }
    let msg = v.get("message").or_else(|| v.get("error")).and_then(Value::as_str).unwrap_or("refused");
    Err(format!("ARGUS-1 refused: {msg} (HTTP {})", r.status))
}

// ---- argument formats, mirrored from the daemon ---------------------------

/// Scheduler job names: lower-case letters and underscores.
pub fn valid_job(job: &str) -> bool {
    (1..=32).contains(&job.len()) && job.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Question ids (jarvis/response/questions.py): short and alphanumeric.
pub fn valid_question_id(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fix proposal ids: `fx-` and eight hex digits, as the daemon checks.
pub fn valid_fix_id(id: &str) -> bool {
    id.len() == 11
        && id.starts_with("fx-")
        && id[3..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The app records intent only. Authorising a patch stays a deliberate step
/// outside it (the dashboard or `jarvis fix`), so it is not offered here.
pub fn valid_fix_decision(d: &str) -> bool {
    matches!(d, "approve" | "retry" | "reject")
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| format!("worker failed: {e}"))?
}

// ---- commands ----------------------------------------------------------------

#[tauri::command]
pub async fn daemon_state() -> Result<Value, String> {
    blocking(|| get_json("/api/state", STATE_TIMEOUT)).await
}

/// Cheap liveness for the sidebar: the pulse summary, or why it is missing.
#[tauri::command]
pub async fn daemon_status() -> Result<Value, String> {
    blocking(|| get_json("/api/pulse", ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn run_collector(job: String) -> Result<Value, String> {
    if !valid_job(&job) {
        return Err("unknown collector name".into());
    }
    blocking(move || post_json(&format!("/api/run?job={job}"), &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn answer_question(id: String, choice: String) -> Result<Value, String> {
    if !valid_question_id(&id) || !matches!(choice.as_str(), "yes" | "no") {
        return Err("invalid answer".into());
    }
    blocking(move || post_json("/api/answer", &json!({ "id": id, "choice": choice }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn ask_jarvis(question: String) -> Result<Value, String> {
    let q: String = question.trim().chars().take(4000).collect();
    if q.is_empty() {
        return Err("ask a question first".into());
    }
    blocking(move || post_json("/api/ask", &json!({ "question": q }), ASK_TIMEOUT)).await
}

#[tauri::command]
pub async fn score_coach() -> Result<Value, String> {
    blocking(|| post_json("/api/score-coach", &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn decide_fix(id: String, decision: String, reason: Option<String>) -> Result<Value, String> {
    if !valid_fix_id(&id) || !valid_fix_decision(&decision) {
        return Err("invalid fix decision".into());
    }
    let reason: String = reason.unwrap_or_default().chars().take(300).collect();
    blocking(move || {
        post_json(&format!("/api/fix/{decision}"), &json!({ "id": id, "reason": reason }), ACTION_TIMEOUT)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &str) -> io::Result<Response> {
        parse_response(&mut Cursor::new(raw.as_bytes().to_vec()))
    }

    #[test]
    fn response_with_length_and_cookie() {
        let r = parse(
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: jarvis_token=\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; Path=/; SameSite=Strict\r\n\
             Content-Length: 5\r\n\r\nhello trailing",
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert!(r.header("set-cookie").is_some());
    }

    #[test]
    fn body_to_eof_without_length() {
        let r = parse("HTTP/1.0 404 Not Found\r\n\r\n{\"error\": \"not found\"}").unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(json_of(&r).unwrap()["error"], "not found");
    }

    #[test]
    fn hostile_responses_are_errors() {
        assert!(parse("garbage\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").is_err());
        let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(20_000));
        assert!(parse(&long).is_err());
        let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: y\r\n".repeat(80));
        assert!(parse(&many).is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nX: y\r\n").is_err(), "headers must end");
    }

    #[test]
    fn oversized_body_without_length_is_refused() {
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{}", "x".repeat(MAX_BODY + 10));
        assert!(parse(&raw).is_err());
    }

    // ---- against a fake daemon on a real socket --------------------------------

    use std::net::TcpListener;
    use std::thread;

    /// Serve one connection: capture the request, answer with `reply`, then
    /// optionally keep the socket open (to model a stalled peer).
    fn fake_daemon(reply: Vec<u8>, hold: Duration) -> (u16, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let _ = sock.write_all(&reply);
            thread::sleep(hold);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (port, h)
    }

    #[test]
    fn a_real_round_trip_sends_loopback_host_and_token_only_when_asked() {
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n{\"ok\": true}".to_vec(), Duration::ZERO);
        let r = request_to(port, "POST", "/api/answer", Some(&"ab".repeat(32)), Some(b"{}"), Duration::from_secs(5)).unwrap();
        assert_eq!(json_of(&r).unwrap()["ok"], true);
        let sent = h.join().unwrap();
        assert!(sent.starts_with("POST /api/answer HTTP/1.1\r\n"));
        assert!(sent.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
        assert!(sent.contains("X-JARVIS-Token: "));
        assert!(sent.contains("Content-Length: 2\r\n"));
        assert!(!sent.contains("Origin:"), "no Origin: the daemon treats the app as a local client");

        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(), Duration::ZERO);
        request_to(port, "GET", "/api/state", None, None, Duration::from_secs(5)).unwrap();
        assert!(!h.join().unwrap().contains("X-JARVIS-Token"), "no token unless the caller passes one");
    }

    #[test]
    fn a_stalled_daemon_times_out_instead_of_hanging() {
        // Headers promise 100 bytes, five arrive, then silence.
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nhello".to_vec(), Duration::from_secs(3));
        let started = std::time::Instant::now();
        let r = request_to(port, "GET", "/api/state", None, None, Duration::from_millis(500));
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(3), "bounded by the read timeout");
        h.join().unwrap();
    }

    #[test]
    fn a_daemon_that_hangs_up_mid_headers_is_an_error() {
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Ty".to_vec(), Duration::ZERO);
        assert!(request_to(port, "GET", "/", None, None, Duration::from_secs(5)).is_err());
        h.join().unwrap();
    }

    #[test]
    fn an_oversized_answer_is_refused_before_it_is_read() {
        let reply = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).into_bytes();
        let (port, h) = fake_daemon(reply, Duration::ZERO);
        let err = request_to(port, "GET", "/api/state", None, None, Duration::from_secs(5)).unwrap_err();
        assert!(err.to_string().contains("too large"));
        h.join().unwrap();
    }

    #[test]
    fn nothing_listening_reads_as_not_running() {
        let port = { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }; // bound, then freed
        let err = request_to(port, "GET", "/api/state", None, None, Duration::from_secs(2)).unwrap_err();
        assert!(unreachable(&err).contains("not running") || unreachable(&err).contains("could not reach"));
    }

    #[test]
    fn arguments_match_the_daemons_formats() {
        assert!(valid_job("scan") && valid_job("history_verify") && valid_job("sysmon_linux"));
        for bad in ["", "Scan", "scan;rm", "scan&job=x", "../x", "a b", &"x".repeat(33)] {
            assert!(!valid_job(bad), "{bad}");
        }
        assert!(valid_question_id("25ccafca"));
        assert!(!valid_question_id("") && !valid_question_id("a/b") && !valid_question_id(&"a".repeat(33)));
        assert!(valid_fix_id("fx-bc6b4886"));
        for bad in ["fx-BC6B4886", "fx-bc6b488", "fx-bc6b48861", "xx-bc6b4886", "fx-bc6b488g"] {
            assert!(!valid_fix_id(bad), "{bad}");
        }
        assert!(valid_fix_decision("approve") && valid_fix_decision("retry") && valid_fix_decision("reject"));
        assert!(!valid_fix_decision("authorize"), "authorising a patch is not offered by the app");
    }
}
