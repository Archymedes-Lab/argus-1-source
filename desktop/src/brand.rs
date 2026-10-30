//! The product is ARGUS-1. Daemon text can still say JARVIS (finding titles
//! keep their identity for acknowledgements and history), so text shown in a
//! native toast is re-branded here. Real Windows object names, lowercase
//! commands and paths keep their spelling. Same rule as the web pages and
//! ui/src/lib/brand.ts; tests/test_ui_brand.py keeps them in step.

/// The name as it appears in this tree (the Argus build renames it).
const NAME: &str = "JARVIS";
const KEEP: [&str; 5] = [" input hook", " independent health monitor", " connectivity guard",
                         " native sensor", " Jarvis"];

fn word_char(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

pub fn brand(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(NAME) {
        let (before, tail) = rest.split_at(i);
        out.push_str(before);
        let after = &tail[NAME.len()..];
        let whole = !word_char(out.chars().last()) && !word_char(after.chars().next());
        // Idempotent: a name already followed by -1 is left alone.
        if whole && !after.starts_with("-1") && !KEEP.iter().any(|k| after.starts_with(k)) {
            out.push_str("ARGUS-1");
        } else {
            out.push_str(NAME);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::brand;

    #[test]
    fn product_prose_reads_argus() {
        assert_eq!(brand("JARVIS is up"), "ARGUS-1 is up");
        assert_eq!(brand("JARVIS's view of JARVIS"), "ARGUS-1's view of ARGUS-1");
        assert_eq!(brand("(JARVIS)"), "(ARGUS-1)");
    }

    #[test]
    fn real_objects_commands_paths_and_variables_keep_their_spelling() {
        for s in ["JARVIS input hook", "JARVIS independent health monitor",
                  "JARVIS connectivity guard", "JARVIS native sensor",
                  "JARVIS JarvisSensorDefender collector", "jarvis.service",
                  r"C:\ProgramData\Jarvis\Broker", "JARVIS_DESKTOP_PORT", "XJARVIS", ""] {
            assert_eq!(brand(s), s);
        }
    }

    #[test]
    fn idempotent_never_argus_1_1() {
        for s in ["JARVIS is up", "ARGUS-1 is up", "JARVIS input hook", "x JARVIS-1 y"] {
            assert_eq!(brand(&brand(s)), brand(s));
        }
        assert_eq!(brand("JARVIS-1"), "JARVIS-1");
    }

    #[test]
    fn multibyte_text_is_safe() {
        assert_eq!(brand("é JARVIS — ✓"), "é ARGUS-1 — ✓");
    }
}
