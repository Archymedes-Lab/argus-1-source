//! What the tray shows and when to interrupt, decided from the daemon's pulse.
//!
//! Pure logic (no Tauri types) so every rule is unit-tested:
//!
//! * Unknown is never green. No pulse, a failed pulse, an unhealthy daemon or
//!   a blind collector can only make the tray more cautious, never calmer.
//! * Notify on change, not on state. The first pulse after start seeds what is
//!   already known (except criticals, which are always announced once); later
//!   pulses notify only for findings, blind collectors or a score crossing
//!   that were not there before. Owner-acknowledged findings never notify.
//! * Bounded. At most MAX_TOASTS per pulse; the rest are summarised.

use serde_json::Value;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub const GATE: i64 = 90;
pub const OUTAGE_AFTER: Duration = Duration::from_secs(60);
pub const MAX_TOASTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Unknown,
    Good,
    Attention,
    Alarm,
}

/// What a notification is about, so the owner's preferences can mute a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Finding,
    Collector,
    Score,
    Outage,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Toast {
    pub kind: Kind,
    pub title: String,
    pub body: String,
}

#[derive(Debug)]
pub struct View {
    pub level: Level,
    pub line: String,
    pub toasts: Vec<Toast>,
}

#[derive(Default)]
pub struct Watch {
    seeded: bool,
    seen: HashSet<String>,
    blind: HashSet<String>,
    below_gate: bool,
    down_since: Option<Instant>,
    outage_announced: bool,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

impl Watch {
    pub fn pulse(&mut self, p: &Value) -> View {
        let mut toasts = Vec::new();
        if self.outage_announced {
            toasts.push(Toast {
                kind: Kind::Outage,
                title: "ARGUS-1 daemon reachable again".into(),
                body: "Live insight resumed.".into(),
            });
        }
        self.down_since = None;
        self.outage_announced = false;

        if p.get("ok").and_then(Value::as_bool) != Some(true) {
            return View {
                level: Level::Unknown,
                line: format!("ARGUS-1 could not build its summary ({})", s(p, "error")),
                toasts,
            };
        }

        let score = p.get("score").and_then(Value::as_i64);
        let open: Vec<&Value> = p
            .get("urgent")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|u| u.get("acknowledged") != Some(&Value::Bool(true))).collect())
            .unwrap_or_default();
        let critical = open.iter().any(|u| s(u, "severity") == "critical");
        let blind: Vec<&Value> = p.get("blind").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
        let healthy = p.get("healthy").and_then(Value::as_bool);

        let level = if critical {
            Level::Alarm
        } else if score.is_none() || healthy != Some(true) {
            Level::Unknown
        } else if !open.is_empty() || !blind.is_empty() || score.unwrap_or(0) < GATE {
            Level::Attention
        } else {
            Level::Good
        };

        let mut line = match score {
            Some(n) => format!("ARGUS-1 {n} · {}", s(p, "grade")),
            None => "ARGUS-1 score unknown".to_string(),
        };
        if !open.is_empty() {
            line += &format!(" · {} need you", open.len());
        }
        if !blind.is_empty() {
            line += &format!(" · {} blind", blind.len());
        }
        if healthy == Some(false) {
            line += " · daemon unhealthy";
        }

        // New serious findings.
        let mut fresh: Vec<&Value> = Vec::new();
        for u in &open {
            let id = s(u, "id").to_string();
            if id.is_empty() || self.seen.contains(&id) {
                continue;
            }
            if self.seeded || s(u, "severity") == "critical" {
                fresh.push(u);
            }
            self.seen.insert(id);
        }
        for u in fresh.iter().take(MAX_TOASTS) {
            toasts.push(Toast {
                kind: Kind::Finding,
                title: format!("ARGUS-1: {} finding", s(u, "severity")),
                body: crate::brand::brand(s(u, "title")).chars().take(180).collect(),
            });
        }
        if fresh.len() > MAX_TOASTS {
            toasts.push(Toast {
                kind: Kind::Finding,
                title: "ARGUS-1: more findings".into(),
                body: format!("{} more need you — open ARGUS-1.", fresh.len() - MAX_TOASTS),
            });
        }

        // Newly blind collectors.
        let now_blind: HashSet<String> = blind.iter().map(|b| s(b, "job").to_string()).collect();
        if self.seeded {
            let mut gone: Vec<&Value> = blind.iter().copied().filter(|b| !self.blind.contains(s(b, "job"))).collect();
            gone.sort_by_key(|b| s(b, "job").to_string());
            if !gone.is_empty() {
                let names: Vec<&str> = gone.iter().map(|b| s(b, "label")).collect();
                toasts.push(Toast {
                kind: Kind::Collector,
                    title: "ARGUS-1: collector blind".into(),
                    body: format!("Not reporting: {}. Unobserved is not clean.", names.join(", ")),
                });
            }
        }
        self.blind = now_blind;

        // The score crossing the release gate, either way, once per crossing.
        if let Some(n) = score {
            let below = n < GATE;
            if self.seeded && below && !self.below_gate {
                toasts.push(Toast {
                kind: Kind::Score,
                    title: format!("ARGUS-1 score fell to {n}"),
                    body: format!("Below {GATE}. Open ARGUS-1 to see what changed."),
                });
            }
            self.below_gate = below;
        }

        self.seeded = true;
        View { level, line, toasts }
    }

    /// The daemon did not answer. Announce an outage once it has lasted
    /// OUTAGE_AFTER, because a silent tray would read as "all quiet".
    pub fn unreachable(&mut self, now: Instant) -> View {
        let since = *self.down_since.get_or_insert(now);
        let mut toasts = Vec::new();
        if !self.outage_announced && now.duration_since(since) >= OUTAGE_AFTER {
            self.outage_announced = true;
            toasts.push(Toast {
                kind: Kind::Outage,
                title: "ARGUS-1 daemon unreachable".into(),
                body: "No live insight: monitoring may be down. Check `jarvis serve`.".into(),
            });
        }
        View { level: Level::Unknown, line: "ARGUS-1 daemon unreachable — retrying".into(), toasts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pulse(score: i64, urgent: Value, blind: Value) -> Value {
        json!({"ok": true, "score": score, "grade": "secure", "healthy": true,
               "urgent": urgent, "blind": blind})
    }

    #[test]
    fn clean_is_good_and_quiet() {
        let v = Watch::default().pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(v.level, Level::Good);
        assert!(v.toasts.is_empty());
        assert_eq!(v.line, "ARGUS-1 91 · secure");
    }

    #[test]
    fn unknown_is_never_green() {
        let mut w = Watch::default();
        assert_eq!(w.pulse(&json!({"ok": false, "error": "OSError"})).level, Level::Unknown);
        let mut p = pulse(95, json!([]), json!([]));
        p["healthy"] = Value::Null;
        assert_eq!(w.pulse(&p).level, Level::Unknown);
        p["healthy"] = json!(false);
        assert_eq!(w.pulse(&p).level, Level::Unknown);
        assert_eq!(w.unreachable(Instant::now()).level, Level::Unknown);
    }

    #[test]
    fn blind_collector_or_low_score_needs_attention() {
        let mut w = Watch::default();
        let blind = json!([{"job": "scan", "label": "Processes"}]);
        assert_eq!(w.pulse(&pulse(95, json!([]), blind)).level, Level::Attention);
        assert_eq!(w.pulse(&pulse(89, json!([]), json!([]))).level, Level::Attention);
    }

    #[test]
    fn first_pulse_seeds_highs_but_announces_criticals() {
        let mut w = Watch::default();
        let urgent = json!([
            {"id": "c1", "severity": "critical", "title": "ransom note"},
            {"id": "h1", "severity": "high", "title": "odd listener"}]);
        let v = w.pulse(&pulse(80, urgent.clone(), json!([])));
        assert_eq!(v.level, Level::Alarm);
        assert_eq!(v.toasts.len(), 1);
        assert_eq!(v.toasts[0].body, "ransom note");
        // Same findings again: nothing new to say.
        assert!(w.pulse(&pulse(80, urgent, json!([]))).toasts.is_empty());
    }

    #[test]
    fn new_finding_after_seed_notifies_once() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let urgent = json!([{"id": "h2", "severity": "high", "title": "new peer"}]);
        assert_eq!(w.pulse(&pulse(91, urgent.clone(), json!([]))).toasts.len(), 1);
        assert!(w.pulse(&pulse(91, urgent, json!([]))).toasts.is_empty());
    }

    #[test]
    fn acknowledged_findings_never_notify_or_alarm() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let urgent = json!([{"id": "c9", "severity": "critical", "title": "x", "acknowledged": true}]);
        let v = w.pulse(&pulse(91, urgent, json!([])));
        assert!(v.toasts.is_empty());
        assert_eq!(v.level, Level::Good);
    }

    #[test]
    fn toasts_are_bounded() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let many: Vec<Value> = (0..10)
            .map(|i| json!({"id": format!("h{i}"), "severity": "high", "title": "t"}))
            .collect();
        let v = w.pulse(&pulse(91, Value::Array(many), json!([])));
        assert_eq!(v.toasts.len(), MAX_TOASTS + 1);
        assert!(v.toasts.last().unwrap().body.starts_with("7 more"));
    }

    #[test]
    fn newly_blind_collector_notifies() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let blind = json!([{"job": "sysmon", "label": "Sysmon"}]);
        let v = w.pulse(&pulse(91, json!([]), blind.clone()));
        assert_eq!(v.toasts.len(), 1);
        assert!(v.toasts[0].body.contains("Sysmon"));
        assert!(w.pulse(&pulse(91, json!([]), blind)).toasts.is_empty());
    }

    #[test]
    fn gate_crossing_notifies_once_per_crossing() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(w.pulse(&pulse(89, json!([]), json!([]))).toasts.len(), 1);
        assert!(w.pulse(&pulse(88, json!([]), json!([]))).toasts.is_empty());
        assert!(w.pulse(&pulse(92, json!([]), json!([]))).toasts.is_empty());
        assert_eq!(w.pulse(&pulse(85, json!([]), json!([]))).toasts.len(), 1);
    }

    #[test]
    fn outage_announced_after_a_minute_then_recovery() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let t0 = Instant::now();
        assert!(w.unreachable(t0).toasts.is_empty());
        assert!(w.unreachable(t0 + Duration::from_secs(30)).toasts.is_empty());
        assert_eq!(w.unreachable(t0 + OUTAGE_AFTER).toasts.len(), 1);
        assert!(w.unreachable(t0 + OUTAGE_AFTER * 2).toasts.is_empty());
        let v = w.pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(v.toasts[0].title, "ARGUS-1 daemon reachable again");
    }
}
