#!/usr/bin/env bash
# Compile the dashboard design system and inline it into the page.
#
#   scripts/dev/build_ui.sh            build jarvis/web/styles/dashboard.css into
#                                      the <style id="ui"> block of dashboard.html
#   scripts/dev/build_ui.sh --check    exit 1 if the page is not up to date
#
# Development-only: the Tailwind standalone CLI (v4.3.3, verified against the
# release's sha256sums.txt) lives in ~/.cache/jarvis-ui-tools, outside the
# repository and outside every release. The product ships the compiled CSS.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
TW_VERSION=v4.3.3
TOOLS="${JARVIS_UI_TOOLS:-$HOME/.cache/jarvis-ui-tools}"
TW="$TOOLS/tailwindcss-linux-x64"
SRC=jarvis/web/styles/dashboard.css
PAGE=jarvis/web/static/dashboard.html

if [ ! -x "$TW" ]; then
  mkdir -p "$TOOLS"
  base="https://github.com/tailwindlabs/tailwindcss/releases/download/$TW_VERSION"
  curl -fsSL -o "$TOOLS/sha256sums.txt" "$base/sha256sums.txt"
  curl -fsSL -o "$TW" "$base/tailwindcss-linux-x64"
  (cd "$TOOLS" && grep " *tailwindcss-linux-x64$" sha256sums.txt | sha256sum -c -)
  chmod 755 "$TW"
fi

out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
"$TW" -i "$SRC" -o "$out/ui.css" --minify >/dev/null 2>&1

python3 - "$PAGE" "$out/ui.css" "${1:-}" <<'PY'
import re, sys, pathlib
page, css, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]).read_text(), sys.argv[3]
html = page.read_text()
banner = "/* compiled from jarvis/web/styles/dashboard.css by scripts/dev/build_ui.sh; do not edit here */\n"
new = re.sub(r'(<style id="ui">)(.*?)(</style>)', lambda m: m.group(1) + "\n" + banner + css.strip() + "\n" + m.group(3),
             html, count=1, flags=re.S)
if new == html and '<style id="ui">' not in html:
    sys.exit("dashboard.html has no <style id=\"ui\"> block")
if mode == "--check":
    sys.exit(0 if new == html else "dashboard.html is out of date: run scripts/dev/build_ui.sh")
page.write_text(new)
print(f"inlined {len(css):,} bytes of CSS into {page}")
PY
