"""The SQLite schema. Applied idempotently by Store() on every open."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS procs (
    fp          TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    name        TEXT,
    exe         TEXT,
    script      TEXT,
    cmdline     TEXT,
    user        TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    approved    INTEGER NOT NULL DEFAULT 0,
    note        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS peers (
    key         TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    fp          TEXT NOT NULL,
    remote_ip   TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    rdns        TEXT DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    approved    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    host        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    fp          TEXT,
    pid         INTEGER,
    name        TEXT,
    exe         TEXT,
    cmdline     TEXT,
    user        TEXT,
    reasons     TEXT,
    remotes     TEXT,
    acked       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_peers_fp ON peers(fp);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);

-- Every alert ever emailed, and what became of it.
--
-- alert.py keeps a live state map in meta, but it *deletes* an entry the moment
-- the finding stops being reported, because that map exists to decide what to
-- send next -- not to remember. So the question "what did JARVIS tell me about
-- that I never actually dealt with?" had no answer anywhere: a finding that was
-- mailed, ignored for three weeks, and then silently cleared left no trace at
-- all, and one that was fixed and came back looked identical to one seen for
-- the first time.
--
-- This table is append-and-update only. Rows are never deleted on clear; they
-- are marked cleared, so a reappearance can be recognised as a reappearance.
-- That distinction is the point: an alert that comes back after being resolved
-- means the remediation did not hold, or the persistence re-established itself,
-- and that is a different and worse fact than a new finding.
CREATE TABLE IF NOT EXISTS alert_ledger (
    key         TEXT PRIMARY KEY,   -- alert.py's dedupe key
    category    TEXT DEFAULT '',
    title       TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    locus       TEXT DEFAULT '',    -- the finding's "where" ("where" is SQL)
    host        TEXT DEFAULT '',
    job         TEXT DEFAULT '',
    severity    TEXT DEFAULT '',    -- severity at the most recent send
    worst_sev   TEXT DEFAULT '',    -- worst it has ever been
    fix         TEXT DEFAULT '',    -- remediation, captured when mailed
    first_sent  INTEGER NOT NULL,
    last_sent   INTEGER NOT NULL,
    sent_count  INTEGER NOT NULL DEFAULT 1,
    cleared_at  INTEGER NOT NULL DEFAULT 0,
    clear_count INTEGER NOT NULL DEFAULT 0,
    reopened    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ledger_open
    ON alert_ledger(cleared_at, last_sent);

-- Latest result per audit, so the dashboard always has something to draw even
-- while a slow collector is mid-run.
CREATE TABLE IF NOT EXISTS snapshots (
    kind       TEXT PRIMARY KEY,
    ts         INTEGER NOT NULL,
    duration   REAL NOT NULL DEFAULT 0,
    error      TEXT DEFAULT '',
    payload    TEXT NOT NULL
);

-- Severity counts over time, for the trend strip.
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    critical   INTEGER NOT NULL DEFAULT 0,
    high       INTEGER NOT NULL DEFAULT 0,
    medium     INTEGER NOT NULL DEFAULT 0,
    low        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts DESC);

-- Collector receipts and incident memory are independent of email delivery
-- and the replaceable dashboard snapshots. A receipt and all of its incident
-- transitions are committed together before the response layer is invoked.
CREATE TABLE IF NOT EXISTS defender_runs (
    sequence     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL UNIQUE,
    job          TEXT NOT NULL,
    observed_at  REAL NOT NULL,
    coverage     TEXT NOT NULL CHECK(coverage IN ('complete','partial','unavailable')),
    error        TEXT NOT NULL,
    digest       TEXT NOT NULL,
    finding_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_defender_runs_job ON defender_runs(job, sequence DESC);
CREATE INDEX IF NOT EXISTS idx_defender_runs_time ON defender_runs(observed_at);

CREATE TABLE IF NOT EXISTS defender_incidents (
    id           TEXT PRIMARY KEY,
    job          TEXT NOT NULL,
    host         TEXT NOT NULL,
    category     TEXT NOT NULL,
    title        TEXT NOT NULL,
    locus        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    worst_severity TEXT NOT NULL,
    state        TEXT NOT NULL CHECK(state IN ('active','unobserved','not_observed')),
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    updated_at   REAL NOT NULL,
    seen_count   INTEGER NOT NULL,
    recurrences  INTEGER NOT NULL DEFAULT 0,
    last_run_id  TEXT NOT NULL,
    evidence     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_defender_incidents_job ON defender_incidents(job, state);

CREATE TABLE IF NOT EXISTS defender_transitions (
    sequence     INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    observed_at  REAL NOT NULL,
    previous_state TEXT NOT NULL,
    state        TEXT NOT NULL,
    reason       TEXT NOT NULL,
    evidence     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_defender_transitions_incident
    ON defender_transitions(incident_id, sequence DESC);
CREATE INDEX IF NOT EXISTS idx_defender_transitions_run ON defender_transitions(run_id);

-- ── Threat intelligence ────────────────────────────────────────────────
-- Fetched security writeups. Text is kept only long enough to extract from;
-- what persists is the extraction, not the article.
CREATE TABLE IF NOT EXISTS intel_docs (
    url        TEXT PRIMARY KEY,
    title      TEXT DEFAULT '',
    published  TEXT DEFAULT '',
    topic      TEXT DEFAULT '',
    query      TEXT DEFAULT '',
    fetched_at INTEGER NOT NULL,
    text_len   INTEGER NOT NULL DEFAULT 0,
    n_indicators INTEGER NOT NULL DEFAULT 0
);

-- One observable extracted from a writeup. Never authoritative on its own:
-- an indicator can only ever raise suspicion, never clear it.
CREATE TABLE IF NOT EXISTS indicators (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    norm       TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    topic      TEXT DEFAULT '',
    context    TEXT DEFAULT '',
    source_url TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    doc_count  INTEGER NOT NULL DEFAULT 1,
    status     TEXT NOT NULL DEFAULT 'active',
    source     TEXT NOT NULL DEFAULT 'exa',
    malware    TEXT DEFAULT '',
    UNIQUE(kind, norm)
);

CREATE INDEX IF NOT EXISTS idx_ind_kind ON indicators(kind, status);

-- The ATT&CK catalogue, so a technique id can be shown with its real name and
-- gap analysis can talk about behaviour instead of numbers.
CREATE TABLE IF NOT EXISTS attack_techniques (
    tid       TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    tactics   TEXT DEFAULT '',
    platforms TEXT DEFAULT '',
    updated   INTEGER NOT NULL
);

-- Continuous network state. Sampled on a short interval and kept, because
-- the question "when did the wifi drop, and was anything else happening then?"
-- can only ever be answered from history that was already being recorded.
CREATE TABLE IF NOT EXISTS net_samples (
    ts        INTEGER NOT NULL,
    iface     TEXT NOT NULL,
    state     TEXT DEFAULT '',
    ssid      TEXT DEFAULT '',
    bssid     TEXT DEFAULT '',
    channel   INTEGER DEFAULT 0,
    band      TEXT DEFAULT '',
    auth      TEXT DEFAULT '',
    cipher    TEXT DEFAULT '',
    signal    INTEGER DEFAULT 0,
    ipv4      TEXT DEFAULT '',
    gateway   TEXT DEFAULT '',
    gw_mac    TEXT DEFAULT '',
    dns       TEXT DEFAULT '',
    PRIMARY KEY (ts, iface)
);

CREATE INDEX IF NOT EXISTS idx_net_ts ON net_samples(ts DESC);

-- A transition worth remembering: a drop, a disable, an access point swap.
CREATE TABLE IF NOT EXISTS net_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    iface    TEXT DEFAULT '',
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail   TEXT DEFAULT '',
    prev     TEXT DEFAULT '',
    curr     TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_netev_ts ON net_events(ts DESC);

-- Access points this machine has associated with, so a familiar SSID
-- appearing on unfamiliar hardware is visible as such.
CREATE TABLE IF NOT EXISTS known_aps (
    ssid       TEXT NOT NULL,
    bssid      TEXT NOT NULL,
    auth       TEXT DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ssid, bssid)
);

-- Synthetic input. Only injected events are stored, never real keystrokes and
-- never what was typed — see jarvis/win/inputhook.ps1 for why.
CREATE TABLE IF NOT EXISTS input_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    lower_il INTEGER NOT NULL DEFAULT 0,
    class    TEXT DEFAULT '',
    fg       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_input_ts ON input_events(ts DESC);

-- Heartbeats, so a dead hook and a quiet keyboard are distinguishable.
-- Control activations: volume, media and launch keys, and the state changes
-- they should explain. A row with keyed=0 is a control that moved with no key
-- behind it, which is the shape of software driving the machine as if it were
-- the person at the keyboard.
CREATE TABLE IF NOT EXISTS control_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,       -- 'control-key' | 'control-state'
    control    TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    injected   INTEGER NOT NULL DEFAULT 0,
    lower_il   INTEGER NOT NULL DEFAULT 0,
    keyed      INTEGER NOT NULL DEFAULT -1,   -- -1 = not applicable
    key_gap_ms INTEGER NOT NULL DEFAULT -1,
    fg         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_control_events_ts ON control_events(ts DESC);

CREATE TABLE IF NOT EXISTS input_beats (
    ts             INTEGER PRIMARY KEY,
    real_keys      INTEGER NOT NULL DEFAULT 0,
    injected_keys  INTEGER NOT NULL DEFAULT 0,
    real_clicks    INTEGER NOT NULL DEFAULT 0,
    injected_clicks INTEGER NOT NULL DEFAULT 0,
    real_moves     INTEGER NOT NULL DEFAULT 0,
    injected_moves INTEGER NOT NULL DEFAULT 0,
    injected_keyups     INTEGER NOT NULL DEFAULT 0,
    injected_move_bursts INTEGER NOT NULL DEFAULT 0,
    real_key_gaps  INTEGER NOT NULL DEFAULT 0,
    real_key_sub20 INTEGER NOT NULL DEFAULT 0,
    real_key_sub8  INTEGER NOT NULL DEFAULT 0,
    cad_run_max    INTEGER NOT NULL DEFAULT 0,
    lat_avg_ms     INTEGER NOT NULL DEFAULT 0,
    lat_max_ms     INTEGER NOT NULL DEFAULT 0,
    lat_over50     INTEGER NOT NULL DEFAULT 0,
    lat_samples    INTEGER NOT NULL DEFAULT 0
);

-- Privacy-safe typing history. One row describes a one-minute window; there
-- are no free-form characters, window titles, clipboard values or command
-- lines. Watched families (=/+, /?, ./ >, digits) are counted in aggregate
-- here; individual digit/punct presses are timestamped separately in
-- input_events. Enough for cadence and volume anomaly detection without a
-- full keylog. Raw windows are retained for 90 days.
CREATE TABLE IF NOT EXISTS input_typing_windows (
    ts             INTEGER PRIMARY KEY,
    real_keys      INTEGER NOT NULL DEFAULT 0,
    injected_keys  INTEGER NOT NULL DEFAULT 0,
    real_key_gaps  INTEGER NOT NULL DEFAULT 0,
    real_key_sub20 INTEGER NOT NULL DEFAULT 0,
    real_key_sub8  INTEGER NOT NULL DEFAULT 0,
    cad_run_max    INTEGER NOT NULL DEFAULT 0,
    equals_keys    INTEGER NOT NULL DEFAULT 0,
    slash_keys     INTEGER NOT NULL DEFAULT 0,
    period_keys    INTEGER NOT NULL DEFAULT 0,
    digit_keys     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_input_typing_ts
    ON input_typing_windows(ts DESC);

-- Sysmon findings, kept because the collector reads incrementally. Each run
-- only sees events since the last one, so without this a critical detection
-- would live in exactly one snapshot and then be replaced by the next run's
-- "nothing new" — an optimisation that silently loses findings is not one.
CREATE TABLE IF NOT EXISTS sysmon_hits (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT DEFAULT '',
    where_   TEXT DEFAULT '',
    UNIQUE(category, title, where_)
);

CREATE INDEX IF NOT EXISTS idx_sysmon_ts ON sysmon_hits(ts DESC);

-- Per-feed bookkeeping: when it last ran, how big it was, whether it worked.
CREATE TABLE IF NOT EXISTS feed_runs (
    name      TEXT PRIMARY KEY,
    last_run  INTEGER NOT NULL,
    rows      INTEGER NOT NULL DEFAULT 0,
    kept      INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0,
    error     TEXT DEFAULT ''
);

-- A live match of an indicator against this machine.
CREATE TABLE IF NOT EXISTS hunt_hits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL,
    host      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    evidence  TEXT DEFAULT '',
    source_url TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hits_ts ON hunt_hits(ts DESC);

-- Cache of file hashes so a hunt does not re-read every binary each pass.
CREATE TABLE IF NOT EXISTS file_hashes (
    path    TEXT PRIMARY KEY,
    sha256  TEXT NOT NULL,
    size    INTEGER NOT NULL,
    mtime   INTEGER NOT NULL,
    hashed_at INTEGER NOT NULL
);
"""
