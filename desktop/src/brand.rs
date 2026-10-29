//! Display-time re-branding: server text may still say JARVIS (finding titles keep
//! their identity for acknowledgements and history); what a person reads says
//! ARGUS-1. The same rule as jarvis/web/static/dashboard.html and
//! desktop/ui/src/lib/brand.ts; tests/test_ui_brand.py keeps the KEEP list equal.
//! Real Windows objects keep their spelling (`JARVIS input hook`), lowercase
//! commands are never touched, and a name already followed by `-1` is left alone.

const BRAND: &str = "ARGUS-1";
/// Words after JARVIS that name a real object, so the spelling stays.
const KEEP: [&str; 5] = [" input hook", " independent health monitor", " connectivity guard", " native sensor", " Jarvis"];

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

pub fn brand(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let mut before: Option<char> = None;
    while let Some(i) = rest.find("JARVIS") {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let prev = head.chars().last().or(before);
        let after = &tail["JARVIS".len()..];
        let boundary = !is_word(prev) && !is_word(after.chars().next());
        let keep = after.starts_with("-1") || KEEP.iter().any(|k| after.starts_with(k));
        out.push_str(if boundary && !keep { BRAND } else { "JARVIS" });
        before = Some('S');
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::brand;

    #[test]
    fn matches_the_web_rule_cases() {
        let cases = [
            ("JARVIS is up", "ARGUS-1 is up"),
            ("JARVIS's view of JARVIS", "ARGUS-1's view of ARGUS-1"),
            ("JARVIS input hook", "JARVIS input hook"),
            ("JARVIS independent health monitor stalled", "JARVIS independent health monitor stalled"),
            ("JARVIS connectivity guard", "JARVIS connectivity guard"),
            ("JARVIS native sensor", "JARVIS native sensor"),
            ("JARVIS JarvisSensorDefender collector", "JARVIS JarvisSensorDefender collector"),
            ("restart jarvis.service", "restart jarvis.service"),
            (r"C:\ProgramData\Jarvis\Broker", r"C:\ProgramData\Jarvis\Broker"),
            ("JARVIS_NET_DIR", "JARVIS_NET_DIR"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(brand(input), want, "{input}");
        }
    }

    #[test]
    fn is_idempotent() {
        for s in ["JARVIS is up", "ARGUS-1 is up", "JARVIS input hook", "JARVIS-1 x"] {
            assert_eq!(brand(&brand(s)), brand(s));
        }
    }
}
