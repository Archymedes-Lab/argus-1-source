//! JARVIS Runtime prototype (Phase 4, surgical).
//!
//! Python remains JARVIS Intelligence (policies, incidents, reasoning,
//! Forge, self-fix, models). This crate owns only the hot path:
//!
//! * event ingestion + validation (mirrors `jarvis.core.event.validate`)
//! * buffering + segment sealing with gzip compression
//! * integrity/hash chains over sealed segment headers
//! * live resource metrics (loadavg + meminfo, no subprocesses)
//! * resource governance (Tier 0 never defers; Tier 1/2 yield)
//!
//! Pure where it matters, bounded everywhere, no model calls, no IO in
//! the library core except the explicit metrics probe.

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::AsRawFd;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const SEAL_EVENTS: usize = 20_000;
pub const SEAL_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_SEGMENT_BYTES: usize = SEAL_BYTES + MAX_EVENT_BYTES + 1;
pub const CPU_PRESSURE_PCT: f64 = 75.0;

const CATEGORIES: &[&str] = &[
    "process",
    "network",
    "file",
    "registry",
    "driver",
    "ipc",
    "wmi",
    "malware",
    "protection",
    "task",
    "sensor",
    "unknown",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentHeader {
    pub v: u32,
    pub segment: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: usize,
    pub payload_sha256: String,
    pub payload_bytes: usize,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoreState {
    pub root: PathBuf,
    pub sealed_through: u64,
    pub previous_hash: String,
    pub next_segment: u64,
    pub segments: u64,
}

struct StoreLock {
    file: File,
}

impl StoreLock {
    fn exclusive(root: &Path) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|e| format!("cannot create runtime store: {e}"))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(root.join("writer.lock"))
            .map_err(|e| format!("cannot open runtime store lock: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot protect runtime store lock: {e}"))?;
            // SAFETY: flock only observes the valid descriptor owned by `file`.
            // StoreLock retains that File until the critical section ends.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(format!(
                    "cannot lock runtime store: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: the descriptor remains valid until this Drop returns.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn segment_path(root: &Path, segment: u64) -> PathBuf {
    root.join("segments").join(format!("{segment:012}.jrs"))
}

fn read_envelope(path: &Path) -> Result<(SegmentHeader, Vec<u8>), String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let split = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| format!("segment {} has no header", path.display()))?;
    let header = serde_json::from_slice::<SegmentHeader>(&bytes[..split])
        .map_err(|e| format!("invalid segment header: {e}"))?;
    Ok((header, bytes[split + 1..].to_vec()))
}

fn append_chain(root: &Path, header: &SegmentHeader) -> Result<(), String> {
    let path = root.join("chain.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open chain: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect chain: {e}"))?;
    }
    let line =
        serde_json::to_vec(header).map_err(|e| format!("cannot encode chain header: {e}"))?;
    file.write_all(&line)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot commit chain: {e}"))
}

/// Open and fully verify a persistent Rust segment store. A segment renamed
/// into place immediately before a crash is adopted only after verification.
fn open_store_unlocked(root: &Path) -> Result<StoreState, String> {
    fs::create_dir_all(root.join("segments"))
        .map_err(|e| format!("cannot create runtime store: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot protect runtime store: {e}"))?;
    }
    let chain_path = root.join("chain.jsonl");
    let mut previous = GENESIS.to_string();
    let mut sealed_through = 0u64;
    let mut next_segment = 1u64;
    let mut segments = 0u64;
    if chain_path.exists() {
        let file = File::open(&chain_path).map_err(|e| format!("cannot read chain: {e}"))?;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| format!("cannot read chain: {e}"))?;
            if line.trim().is_empty() {
                return Err("blank line in segment chain".to_string());
            }
            let header: SegmentHeader =
                serde_json::from_str(&line).map_err(|e| format!("invalid chain header: {e}"))?;
            if header.segment != next_segment
                || sealed_through.checked_add(1) != Some(header.first_seq)
            {
                return Err("segment chain sequence is not contiguous".to_string());
            }
            let (stored, compressed) = read_envelope(&segment_path(root, next_segment))?;
            if stored != header {
                return Err("segment header disagrees with chain".to_string());
            }
            Ingest::verify_segment(&header, &compressed, &previous)?;
            previous = header.hash.clone();
            sealed_through = header.last_seq;
            next_segment = next_segment
                .checked_add(1)
                .ok_or_else(|| "segment number exhausted".to_string())?;
            segments += 1;
        }
    }
    // Adopt verified orphan(s) left by a crash between atomic segment rename
    // and the durable chain append.
    while segment_path(root, next_segment).exists() {
        let (header, compressed) = read_envelope(&segment_path(root, next_segment))?;
        if header.segment != next_segment || sealed_through.checked_add(1) != Some(header.first_seq)
        {
            return Err("orphan segment is not contiguous".to_string());
        }
        Ingest::verify_segment(&header, &compressed, &previous)?;
        append_chain(root, &header)?;
        previous = header.hash.clone();
        sealed_through = header.last_seq;
        next_segment = next_segment
            .checked_add(1)
            .ok_or_else(|| "segment number exhausted".to_string())?;
        segments += 1;
    }
    Ok(StoreState {
        root: root.to_path_buf(),
        sealed_through,
        previous_hash: previous,
        next_segment,
        segments,
    })
}

pub fn open_store(root: &Path) -> Result<StoreState, String> {
    let _lock = StoreLock::exclusive(root)?;
    open_store_unlocked(root)
}

/// Atomically persist one verified segment, then durably extend the chain.
pub fn persist_segment(
    root: &Path,
    header: &SegmentHeader,
    compressed: &[u8],
) -> Result<(), String> {
    let _lock = StoreLock::exclusive(root)?;
    let state = open_store_unlocked(root)?;
    if header.segment != state.next_segment
        || header.previous_hash != state.previous_hash
        || state.sealed_through.checked_add(1) != Some(header.first_seq)
    {
        return Err("segment does not extend the durable store".to_string());
    }
    Ingest::verify_segment(header, compressed, &state.previous_hash)?;
    let final_path = segment_path(root, header.segment);
    if final_path.exists() {
        return Err("segment already exists".to_string());
    }
    let temp = final_path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| format!("cannot create segment: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect segment: {e}"))?;
    }
    let line =
        serde_json::to_vec(header).map_err(|e| format!("cannot encode segment header: {e}"))?;
    let write_result = file
        .write_all(&line)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.write_all(compressed))
        .and_then(|_| file.sync_all());
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp);
        return Err(format!("cannot commit segment: {error}"));
    }
    fs::rename(&temp, &final_path).map_err(|e| format!("cannot install segment: {e}"))?;
    File::open(root.join("segments"))
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("cannot sync segment directory: {e}"))?;
    append_chain(root, header)
}

fn canonical_json(value: &serde_json::Value) -> String {
    // serde_json BTreeMap-backed objects already serialize with sorted keys
    // when constructed from BTreeMap; for header hashing we rebuild the
    // map without `hash` so key order is deterministic.
    serde_json::to_string(value).unwrap_or_default()
}

pub fn header_hash(body: &BTreeMap<String, serde_json::Value>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json(&serde_json::Value::Object(
        body.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    )));
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Append-only ingest buffer. Assigns global sequence numbers in ingest
/// order; source clocks are never trusted for ordering.
pub struct Ingest {
    pub next_seq: u64,
    pub previous_hash: String,
    pub segment_no: u64,
    buffered: Vec<serde_json::Value>,
    buffered_bytes: usize,
}

impl Ingest {
    pub fn new(sealed_through: u64, previous_hash: &str, next_segment: u64) -> Self {
        Self {
            next_seq: sealed_through,
            previous_hash: previous_hash.to_string(),
            segment_no: next_segment,
            buffered: Vec::new(),
            buffered_bytes: 0,
        }
    }

    /// Validate + sequence one event. Returns the assigned seq.
    pub fn push(&mut self, mut ev: serde_json::Value) -> Result<u64, String> {
        let obj = ev.as_object_mut().ok_or("event must be an object")?;
        if obj.get("v").and_then(|v| v.as_u64()) != Some(1) {
            return Err("unsupported event schema".to_string());
        }
        for k in [
            "id",
            "host",
            "sensor",
            "channel",
            "generation",
            "time",
            "source",
            "category",
            "action",
        ] {
            match obj.get(k).and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => {}
                _ => return Err(format!("event field {k} missing")),
            }
        }
        let category = obj.get("category").and_then(|v| v.as_str()).unwrap_or("");
        if !CATEGORIES.contains(&category) {
            return Err("unknown event category".to_string());
        }
        if obj.get("record").and_then(|v| v.as_u64()).is_none() {
            return Err("event record ID missing".to_string());
        }
        for k in ["process", "parent", "target"] {
            if let Some(value) = obj.get(k) {
                if !value.is_null() && !value.is_object() {
                    return Err(format!("event {k} must be an object"));
                }
            }
        }
        let next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| "event sequence exhausted".to_string())?;
        obj.insert("seq".to_string(), serde_json::json!(next_seq));
        let line =
            serde_json::to_string(&ev).map_err(|e| format!("event is not serializable: {e}"))?;
        if line.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds {MAX_EVENT_BYTES} byte limit"));
        }
        self.next_seq = next_seq;
        self.buffered_bytes = self
            .buffered_bytes
            .checked_add(line.len() + 1)
            .ok_or_else(|| "ingest buffer size exhausted".to_string())?;
        self.buffered.push(ev);
        Ok(self.next_seq)
    }

    pub fn due(&self) -> bool {
        self.buffered.len() >= SEAL_EVENTS || self.buffered_bytes >= SEAL_BYTES
    }

    /// Seal the buffer: gzip the exact bytes, hash the payload, chain.
    /// Returns the header; the caller persists header + compressed bytes.
    pub fn seal(&mut self) -> Result<Option<(SegmentHeader, Vec<u8>)>, String> {
        // Prototype seals on demand; production decides when to call this
        // using due(). An empty buffer has nothing to seal.
        if self.buffered.is_empty() {
            return Ok(None);
        }
        let mut payload = String::new();
        for ev in &self.buffered {
            payload.push_str(
                &serde_json::to_string(ev)
                    .map_err(|e| format!("event is not serializable: {e}"))?,
            );
            payload.push('\n');
        }
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload.as_bytes())
            .map_err(|e| format!("segment compression failed: {e}"))?;
        let compressed = enc
            .finish()
            .map_err(|e| format!("segment compression failed: {e}"))?;
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        let payload_sha256 = hex(&h.finalize());
        let first = self
            .buffered
            .first()
            .and_then(|v| v.get("seq"))
            .and_then(|v| v.as_u64())
            .unwrap_or(self.next_seq);
        let last = self.next_seq;
        let count = self.buffered.len();
        let mut body = BTreeMap::new();
        body.insert("v".to_string(), serde_json::json!(1));
        body.insert("segment".to_string(), serde_json::json!(self.segment_no));
        body.insert("first_seq".to_string(), serde_json::json!(first));
        body.insert("last_seq".to_string(), serde_json::json!(last));
        body.insert("count".to_string(), serde_json::json!(count));
        body.insert(
            "payload_sha256".to_string(),
            serde_json::json!(payload_sha256),
        );
        body.insert(
            "payload_bytes".to_string(),
            serde_json::json!(payload.len()),
        );
        body.insert(
            "previous_hash".to_string(),
            serde_json::json!(self.previous_hash),
        );
        let hash = header_hash(&body);
        let header = SegmentHeader {
            v: 1,
            segment: self.segment_no,
            first_seq: first,
            last_seq: last,
            count,
            payload_sha256,
            payload_bytes: payload.len(),
            previous_hash: self.previous_hash.clone(),
            hash: hash.clone(),
        };
        let next_segment = self
            .segment_no
            .checked_add(1)
            .ok_or_else(|| "segment number exhausted".to_string())?;
        self.previous_hash = hash;
        self.segment_no = next_segment;
        self.buffered.clear();
        self.buffered_bytes = 0;
        Ok(Some((header, compressed)))
    }

    /// Verify one sealed segment: decompress, rehash payload, check link.
    pub fn verify_segment(
        header: &SegmentHeader,
        compressed: &[u8],
        expected_prev: &str,
    ) -> Result<(), String> {
        if header.v != 1 {
            return Err("unsupported segment schema".to_string());
        }
        if header.previous_hash != expected_prev {
            return Err("segment does not link to the previous segment".to_string());
        }
        let dec = GzDecoder::new(compressed);
        let mut payload_bytes = Vec::new();
        dec.take((MAX_SEGMENT_BYTES + 1) as u64)
            .read_to_end(&mut payload_bytes)
            .map_err(|e| format!("unreadable segment: {e}"))?;
        if payload_bytes.len() > MAX_SEGMENT_BYTES {
            return Err("segment expands beyond the verification limit".to_string());
        }
        let payload = String::from_utf8(payload_bytes)
            .map_err(|_| "segment payload is not UTF-8".to_string())?;
        if payload.len() != header.payload_bytes {
            return Err("payload byte count does not match header".to_string());
        }
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        if hex(&h.finalize()) != header.payload_sha256 {
            return Err("payload altered".to_string());
        }
        let mut body = BTreeMap::new();
        body.insert("v".to_string(), serde_json::json!(header.v));
        body.insert("segment".to_string(), serde_json::json!(header.segment));
        body.insert("first_seq".to_string(), serde_json::json!(header.first_seq));
        body.insert("last_seq".to_string(), serde_json::json!(header.last_seq));
        body.insert("count".to_string(), serde_json::json!(header.count));
        body.insert(
            "payload_sha256".to_string(),
            serde_json::json!(header.payload_sha256),
        );
        body.insert(
            "payload_bytes".to_string(),
            serde_json::json!(header.payload_bytes),
        );
        body.insert(
            "previous_hash".to_string(),
            serde_json::json!(header.previous_hash),
        );
        if header_hash(&body) != header.hash {
            return Err("header altered".to_string());
        }
        let mut count = 0usize;
        let mut first_seq: Option<u64> = None;
        let mut last_seq: Option<u64> = None;
        for line in payload.lines() {
            let event: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| format!("invalid event JSON in segment: {e}"))?;
            let seq = event
                .get("seq")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "segment event sequence missing".to_string())?;
            if let Some(previous) = last_seq {
                if previous.checked_add(1) != Some(seq) {
                    return Err("segment event sequences are not contiguous".to_string());
                }
            } else {
                first_seq = Some(seq);
            }
            last_seq = Some(seq);
            count += 1;
        }
        if count != header.count
            || first_seq != Some(header.first_seq)
            || last_seq != Some(header.last_seq)
        {
            return Err("segment sequence metadata does not match payload".to_string());
        }
        Ok(())
    }
}

// -- live resource metrics (no subprocesses) -------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub cpu_pct: f64,
    pub mem_available_pct: f64,
    pub pressured: bool,
    pub reason: String,
}

pub fn live_metrics() -> Metrics {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    let load1: f64 = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|t| t.split_whitespace().next().unwrap_or("0").parse().ok())
        .unwrap_or(0.0);
    let cpu_pct = load1 / cpu_count.max(1.0) * 100.0;
    let mut total = 0u64;
    let mut avail = 0u64;
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            let mut it = line.split(':');
            let name = it.next().unwrap_or("").trim();
            let val: u64 = it
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            if name == "MemTotal" {
                total = val;
            } else if name == "MemAvailable" {
                avail = val;
            }
        }
    }
    let mem_pct = if total > 0 {
        avail as f64 / total as f64 * 100.0
    } else {
        100.0
    };
    let pressured = cpu_pct >= CPU_PRESSURE_PCT || (total > 0 && mem_pct < 10.0);
    let reason = if pressured {
        format!("host pressured (CPU {cpu_pct:.0}%, mem avail {mem_pct:.1}%); Tier 0 only")
    } else {
        "nominal load; all tiers permitted".to_string()
    };
    Metrics {
        cpu_pct,
        mem_available_pct: mem_pct,
        pressured,
        reason,
    }
}

// -- resource governance ----------------------------------------------------

/// Scheduler job names the governor may defer. Tier 0 protection,
/// ingestion and freshness supervision always run.
pub fn governed_jobs() -> Vec<&'static str> {
    vec![
        "intel",
        "feeds",
        "secrets",
        "memscan",
        "spy",
        "posture",
        "toolchain",
        "webshell",
        "hunt",
        "gaps",
        "attackmap",
        "arena",
        "model",
        "geo",
        "pixel",
        "intrusion",
    ]
}

pub fn should_defer(job: &str, pressured: bool) -> bool {
    pressured && governed_jobs().contains(&job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ev(seq_host: &str) -> serde_json::Value {
        serde_json::json!({
            "v": 1, "id": "event-id", "host": seq_host, "sensor": "s",
            "channel": "c", "generation": "g", "source": "test",
            "time": "2026-09-20T10:00:00Z", "category": "process",
            "action": "start", "record": 1
        })
    }

    fn temp_store(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "jarvis-runtime-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn rejects_events_with_missing_fields() {
        let mut ing = Ingest::new(0, GENESIS, 1);
        assert!(ing.push(serde_json::json!({"host": "w"})).is_err());
    }

    #[test]
    fn sequences_in_ingest_order_and_seals_with_chain() {
        let mut ing = Ingest::new(0, GENESIS, 1);
        let a = ing.push(ev("w")).unwrap();
        let b = ing.push(ev("w")).unwrap();
        assert_eq!((a, b), (1, 2));
        let (h, bytes) = ing.seal().expect("seal result").expect("segment");
        assert_eq!((h.first_seq, h.last_seq, h.count), (1, 2, 2));
        assert!(Ingest::verify_segment(&h, &bytes, GENESIS).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let mut ing = Ingest::new(0, GENESIS, 1);
        ing.push(ev("w")).unwrap();
        let (h, mut bytes) = ing.seal().expect("seal result").expect("segment");
        if !bytes.is_empty() {
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0xFF;
        }
        assert!(Ingest::verify_segment(&h, &bytes, GENESIS).is_err());
    }

    #[test]
    fn wrong_previous_link_fails() {
        let mut ing = Ingest::new(0, GENESIS, 1);
        ing.push(ev("w")).unwrap();
        let (h, bytes) = ing.seal().expect("seal result").expect("segment");
        assert!(Ingest::verify_segment(&h, &bytes, "ff").is_err());
    }

    #[test]
    fn altered_sequence_metadata_fails_even_with_rehashed_header() {
        let mut ing = Ingest::new(0, GENESIS, 1);
        ing.push(ev("w")).unwrap();
        let (mut h, bytes) = ing.seal().expect("seal result").expect("segment");
        h.count = 2;
        let mut body = BTreeMap::new();
        body.insert("v".to_string(), serde_json::json!(h.v));
        body.insert("segment".to_string(), serde_json::json!(h.segment));
        body.insert("first_seq".to_string(), serde_json::json!(h.first_seq));
        body.insert("last_seq".to_string(), serde_json::json!(h.last_seq));
        body.insert("count".to_string(), serde_json::json!(h.count));
        body.insert(
            "payload_sha256".to_string(),
            serde_json::json!(h.payload_sha256),
        );
        body.insert(
            "payload_bytes".to_string(),
            serde_json::json!(h.payload_bytes),
        );
        body.insert(
            "previous_hash".to_string(),
            serde_json::json!(h.previous_hash),
        );
        h.hash = header_hash(&body);
        assert!(Ingest::verify_segment(&h, &bytes, GENESIS).is_err());
    }

    #[test]
    fn sequence_overflow_is_rejected_without_mutating_the_buffer() {
        let mut ing = Ingest::new(u64::MAX, GENESIS, 1);
        assert!(ing.push(ev("w")).is_err());
        assert!(ing.seal().expect("seal result").is_none());
    }

    #[test]
    fn persistent_store_reopens_and_verifies() {
        let root = temp_store("persistent");
        let state = open_store(&root).expect("open empty store");
        let mut ing = Ingest::new(
            state.sealed_through,
            &state.previous_hash,
            state.next_segment,
        );
        ing.push(ev("w")).unwrap();
        let (header, compressed) = ing.seal().unwrap().unwrap();
        persist_segment(&root, &header, &compressed).expect("persist segment");
        let reopened = open_store(&root).expect("reopen store");
        assert_eq!(reopened.segments, 1);
        assert_eq!(reopened.sealed_through, 1);
        assert_eq!(reopened.previous_hash, header.hash);
        fs::remove_dir_all(&root).expect("remove test store");
    }

    #[test]
    fn persistent_store_rejects_tampered_bytes() {
        let root = temp_store("tamper");
        let state = open_store(&root).expect("open empty store");
        let mut ing = Ingest::new(0, &state.previous_hash, 1);
        ing.push(ev("w")).unwrap();
        let (header, compressed) = ing.seal().unwrap().unwrap();
        persist_segment(&root, &header, &compressed).expect("persist segment");
        let path = segment_path(&root, 1);
        let mut bytes = fs::read(&path).expect("read segment");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, bytes).expect("tamper segment");
        assert!(open_store(&root).is_err());
        fs::remove_dir_all(&root).expect("remove test store");
    }

    #[test]
    fn persistent_store_serializes_competing_writers() {
        let root = temp_store("concurrent");
        let state = open_store(&root).expect("open empty store");
        let mut first = Ingest::new(0, &state.previous_hash, 1);
        let mut second = Ingest::new(0, &state.previous_hash, 1);
        first.push(ev("first")).unwrap();
        second.push(ev("second")).unwrap();
        let (first_header, first_bytes) = first.seal().unwrap().unwrap();
        let (second_header, second_bytes) = second.seal().unwrap().unwrap();
        let root_a = root.clone();
        let root_b = root.clone();
        let a = std::thread::spawn(move || persist_segment(&root_a, &first_header, &first_bytes));
        let b = std::thread::spawn(move || persist_segment(&root_b, &second_header, &second_bytes));
        let outcomes = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        let reopened = open_store(&root).expect("winning segment remains valid");
        assert_eq!(reopened.segments, 1);
        assert_eq!(reopened.sealed_through, 1);
        fs::remove_dir_all(&root).expect("remove test store");
    }

    #[test]
    fn tier0_never_defers() {
        assert!(!should_defer("scan", true));
        assert!(!should_defer("native", true));
        assert!(should_defer("intel", true));
        assert!(!should_defer("intel", false));
    }

    #[test]
    fn metrics_never_panic() {
        let m = live_metrics();
        assert!(m.cpu_pct >= 0.0 && m.mem_available_pct >= 0.0);
        assert!(!m.reason.is_empty());
    }
}
