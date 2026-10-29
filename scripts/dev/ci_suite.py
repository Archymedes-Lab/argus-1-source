#!/usr/bin/env python3
"""Run the unit suite in CI against the reviewed quarantine list.

    python3 scripts/dev/ci_suite.py [--write]

tests/ci-quarantine.txt names tests known to fail on a clean Linux runner
because they assume the owner's WSL host (Windows jobs registered, /mnt/c,
interop). CI fails when any other test fails, and also when a quarantined test
passes, so the list only shrinks: remove a line when its test is fixed.
--write rewrites the list from this run (review the diff before committing).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUARANTINE = ROOT / "tests" / "ci-quarantine.txt"


def test_id(test):
    return test.id() if hasattr(test, "id") else str(test)


def main():
    sys.path.insert(0, str(ROOT))
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=1, buffer=True).run(suite)
    failed = sorted({test_id(t) for t, _ in result.failures + result.errors + result.unexpectedSuccesses})
    if "--write" in sys.argv:
        QUARANTINE.write_text("# Tests that fail on a clean Linux CI runner; see scripts/dev/ci_suite.py.\n"
                              + "".join(f"{t}\n" for t in failed))
        print(f"wrote {len(failed)} entries to {QUARANTINE}")
        return 0
    known = {line.strip() for line in QUARANTINE.read_text().splitlines()
             if line.strip() and not line.startswith("#")} if QUARANTINE.exists() else set()
    new = [t for t in failed if t not in known]
    fixed = sorted(known - set(failed))
    print(f"\nran {result.testsRun}: {len(failed)} failing, {len(known)} quarantined, "
          f"{len(new)} new failures, {len(fixed)} quarantined tests now passing")
    for t in new:
        print(f"NEW FAILURE  {t}")
    for t in fixed:
        print(f"NOW PASSING  {t}  (remove it from tests/ci-quarantine.txt)")
    return 1 if new or fixed else 0


if __name__ == "__main__":
    sys.exit(main())
