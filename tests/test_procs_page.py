"""The /procs page rules, run in Node against the real modules.

procs-model.js decides what is alarm, notice or calm; procs-state.js turns
feed frames into the live table and the change list. These tests drive both
with recorded frames: births, resynchronising snapshots after a gap, verdicts
arriving after their row, short-lived starts and watched processes going
missing only while the feed is live."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "jarvis" / "web" / "static"
NOW = 2_000_000_000


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class NodeCase(unittest.TestCase):
    def run_js(self, body):
        script = (f"import * as m from {json.dumps((STATIC / 'procs-model.js').as_uri())};\n"
                  f"import * as s from {json.dumps((STATIC / 'procs-state.js').as_uri())};\n{body}")
        r = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)


class ModelTests(NodeCase):
    def test_name_classes(self):
        out = self.run_js(f"""
          const b = {{ ok: true, recent_s: 86400, watch: {{ win: ['msmpeng.exe'] }},
            hosts: {{ win: {{ rows: 2, names: {{ 'msmpeng.exe': [{NOW - 999999}, {NOW}, 9, 1], 'fresh.exe': [{NOW - 60}, {NOW}, 1, 0],
                                              'old.exe': [{NOW - 999999}, {NOW}, 9, 0] }} }},
                      lin: {{ rows: 0, names: {{}} }} }} }};
          console.log(JSON.stringify([
            m.classify(b, 'win', 'MsMpEng.exe', {NOW}), m.classify(b, 'win', 'fresh.exe', {NOW}),
            m.classify(b, 'win', 'old.exe', {NOW}), m.classify(b, 'win', 'evil.exe', {NOW}),
            m.classify(b, 'lin', 'anything', {NOW}), m.classify(null, 'win', 'evil.exe', {NOW}),
            m.classify({{ ok: false, hosts: {{}} }}, 'win', 'evil.exe', {NOW}),
            m.norm('Relay(46877)'), m.norm(' WSLHost.EXE '), m.norm('init-systemd(Ub')]));""")
        self.assertEqual(out, ["approved", "recent", "known", "new", "unknown", "unknown", "unknown",
                               "relay(#)", "wslhost.exe", "init-systemd(ub"])

    def test_verdict_levels_and_their_order(self):
        out = self.run_js("""
          const v = (c, i) => { const r = m.verdict(c, i); return r.level + ':' + r.reason; };
          console.log(JSON.stringify([
            v('known', ['system', 'same', 'known']),
            v('known', ['temp', 'moved', 'known']),
            v('approved', ['user', 'moved', 'known']),
            v('known', ['fileless', 'moved', 'unknown']),
            v('new', ['user', 'new', 'new']),
            v('known', ['deleted', 'same', 'unknown']),
            v('recent', ['user', 'new', 'recent']),
            v('known', ['program', 'same', 'recent']),
            v('known', ['program', 'same', 'pending']),
            v('unknown', null),
            v('known', null),
            v('unknown', ['unknown', 'unknown', 'unknown'])]));""")
        self.assertEqual(out, [
            "calm:null", "alarm:moved", "alarm:moved", "alarm:fileless", "alarm:new-name",
            "notice:deleted", "notice:recent-name", "notice:new-binary", "calm:null",
            "unknown:null", "calm:null", "calm:null"])

    def test_short_lived_starts_are_judged_by_place_not_by_name(self):
        out = self.run_js("""
          const v = (i) => { const r = m.startVerdict(i); return r.level + ':' + r.reason; };
          console.log(JSON.stringify([
            v(['system', 'same', 'unknown']),    // a container health check: started here for weeks
            v(['other', 'moved', 'unknown']),    // runc re-executing as /runc inside a container
            v(['temp', 'moved', 'unknown']),     // a system name from /tmp
            v(['user', 'moved', 'known']),
            v(['temp', 'new', 'unknown']),
            v(['fileless', 'unknown', 'unknown']),
            v(['program', 'same', 'new']),
            v(null),
            v(['system', 'new', 'unknown']),     // started here for the first time (mature history)
            v(['temp', 'same', 'known']),        // a program that has run from /tmp for weeks
            v(['temp', 'unknown', 'unknown'])]));""")
        self.assertEqual(out, ["calm:null", "calm:null", "alarm:moved", "alarm:moved", "notice:first-run",
                               "alarm:fileless", "notice:new-binary", "unknown:null",
                               "notice:first-run", "calm:null", "notice:temp"])

    def test_missing_only_after_being_seen_and_only_watched_names(self):
        out = self.run_js("""
          const b = { ok: true, watch: { win: ['msmpeng.exe', 'sysmon64.exe'] }, hosts: {} };
          console.log(JSON.stringify([
            m.missing(b, 'win', new Set(['sysmon64.exe']), new Set(['msmpeng.exe', 'sysmon64.exe'])),
            m.missing(b, 'win', new Set([]), new Set([])),
            m.missing(b, 'win', new Set(['msmpeng.exe', 'sysmon64.exe']), new Set(['msmpeng.exe'])),
            m.missing(null, 'win', new Set(), new Set(['msmpeng.exe']))]));""")
        self.assertEqual(out, [["msmpeng.exe"], [], [], []])

    def test_routine_events_stay_out_of_the_change_list(self):
        out = self.run_js("""
          console.log(JSON.stringify([
            m.changeLine('start', 'calm', false), m.changeLine('exit', 'calm', false),
            m.changeLine('start', 'unknown', false), m.changeLine('start', 'alarm', false),
            m.changeLine('exit', 'alarm', false), m.changeLine('short', 'notice', false),
            m.changeLine('short', 'calm', false), m.changeLine('exit', 'calm', true),
            m.changeLine('missing', null, true), m.changeLine('back', null, true)]));""")
        self.assertEqual(out, [None, None, None, "alarm-start", "alarm-exit", "notice-short", None,
                               "watched-exit", "missing", "back"])

    def test_every_reason_and_change_has_text(self):
        out = self.run_js("""
          const reasons = ['fileless', 'moved', 'new-name', 'deleted', 'recent-name', 'new-binary', 'temp',
                           'first-run'];
          const lines = ['alarm-start', 'notice-start', 'alarm-exit', 'notice-exit', 'alarm-short',
                         'notice-short', 'watched-exit', 'missing', 'back'];
          console.log(JSON.stringify([reasons.filter((r) => !m.REASONS[r]), lines.filter((l) => !m.CHANGE_TEXT[l]),
            m.describeIdent('win', ['temp', 'moved', 'new']), m.describeIdent('lin', null)]));""")
        self.assertEqual(out[0], [])
        self.assertEqual(out[1], [])
        self.assertEqual(out[2], [["Runs from", "a temporary or download folder · never from here before"],
                                  ["Binary", "never seen before"]])
        self.assertEqual(out[3], [["Image", "not checked yet"]])


STATE_PRELUDE = f"""
  let wall = {NOW} * 1000, mono = 0;
  const st = new s.ProcState({{ wallMs: () => wall, monoMs: () => mono }});
  const live = (h) => st.apply({{ k: 'status', sources: {{ [h]: {{ state: 'live' }} }} }});
  const row = (key, pid, name, created, ident = null) => [key, pid, 1, name, created, 0, 1024, 1, ident];
  const baseline = {{ ok: true, recent_s: 86400, watch: {{ win: ['msmpeng.exe'] }},
    hosts: {{ win: {{ rows: 2, names: {{ 'svchost.exe': [{NOW - 999999}, {NOW}, 9, 0],
                                         'msmpeng.exe': [{NOW - 999999}, {NOW}, 9, 0] }} }} }} }};
  st.setBaseline(baseline);
  live('win');
  const kinds = () => st.changes.map((c) => c.k + ':' + c.name).reverse();
"""


class StateTests(NodeCase):
    def state(self, body):
        return self.run_js(STATE_PRELUDE + body)

    def test_the_first_snapshot_is_the_present_not_a_burst_of_starts(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [row('1:1', 1, 'evil.exe', wall - 5000), row('2:1', 2, 'svchost.exe', wall)] });
          const evil = st.procs.get('win|1:1');
          console.log(JSON.stringify([kinds(), evil.level, evil.born, st.tally().alarm]));""")
        self.assertEqual(out, [[], "alarm", 0, 1])

    def test_a_delta_birth_is_listed_once_its_verdict_is_known(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [] });
          st.apply({ k: 'd', h: 'win', t: wall, a: [row('5:9', 5, 'svchost.exe', wall)], x: [], u: [] });
          const before = kinds();
          st.apply({ k: 'i', h: 'win', t: wall, i: [['5:9', ['temp', 'moved', 'pending']]] });
          st.apply({ k: 'i', h: 'win', t: wall, i: [['5:9', ['temp', 'moved', 'known']]] });
          st.apply({ k: 'd', h: 'win', t: wall, a: [], x: ['5:9'], u: [] });
          console.log(JSON.stringify([before, kinds(), st.changes[1].reason]));""")
        self.assertEqual(out, [[], ["alarm-start:svchost.exe", "alarm-exit:svchost.exe"], "moved"])

    def test_a_notice_that_becomes_an_alarm_is_listed_again(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [] });
          st.apply({ k: 'd', h: 'win', t: wall, a: [row('6:9', 6, 'svchost.exe', wall, ['program', 'same', 'recent'])], x: [], u: [] });
          st.apply({ k: 'i', h: 'win', t: wall, i: [['6:9', ['program', 'moved', 'recent']]] });
          console.log(JSON.stringify(kinds()));""")
        self.assertEqual(out, ["notice-start:svchost.exe", "alarm-start:svchost.exe"])

    def test_a_start_during_a_gap_is_a_start_after_the_resync(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [row('2:1', 2, 'svchost.exe', wall - 9000)] });
          const lastLive = wall;
          wall += 10000;   // the helper was replaced or the stream reconnected
          st.apply({ k: 'snap', h: 'win', t: wall, p: [row('2:1', 2, 'svchost.exe', wall - 19000),
                     row('7:1', 7, 'dropper.exe', lastLive + 4000), row('8:1', 8, 'old.exe', lastLive - 60000)] });
          console.log(JSON.stringify([kinds(), !!st.procs.get('win|7:1').born, !!st.procs.get('win|8:1').born]));""")
        self.assertEqual(out, [["alarm-start:dropper.exe"], True, False])

    def test_a_sysmon_start_never_sampled_becomes_a_ghost_listed_only_when_it_matters(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [row('3:1', 3, 'svchost.exe', wall - 9000)] });
          st.apply({ k: 'ev', h: 'win', t: wall, pid: 40, ppid: 3, name: 'svchost.exe', i: ['temp', 'moved', 'new'] });
          st.apply({ k: 'ev', h: 'win', t: wall, pid: 41, ppid: 3, name: 'svchost.exe', i: ['system', 'same', 'known'] });
          st.apply({ k: 'ev', h: 'lin', t: wall, pid: 42, ppid: 1, name: 'pg_isready', i: ['system', 'same', 'unknown'] });
          st.apply({ k: 'd', h: 'win', t: wall, a: [row('41:1', 41, 'svchost.exe', wall)], x: [], u: [] });
          mono += 1000; st.settleStarts(mono);
          const early = st.shortLived.win + st.shortLived.lin;
          mono += 500; st.settleStarts(mono);
          console.log(JSON.stringify([early, st.shortLived, kinds(), st.ghosts.map((g) => [g.h, g.level, g.parent && g.parent.pid])]));""")
        self.assertEqual(out, [0, {"win": 1, "lin": 1}, ["alarm-short:svchost.exe"],
                               [["win", "alarm", 3], ["lin", "calm", None]]])

    def test_a_late_start_for_a_process_already_sampled_and_gone_is_not_a_ghost(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'lin', t: wall, p: [] });
          st.apply({ k: 'd', h: 'lin', t: wall, a: [row('50:1', 50, 'job', wall)], x: [], u: [] });
          mono += 600; st.apply({ k: 'd', h: 'lin', t: wall, a: [], x: ['50:1'], u: [] });
          mono += 2000;    // Sysmon for Linux delivered the start after the exit
          st.apply({ k: 'ev', h: 'lin', t: wall, pid: 50, ppid: 1, name: 'job', i: ['temp', 'new', 'unknown'] });
          mono += 1500; st.settleStarts(mono);
          const settled = st.shortLived.lin;
          for (const q of [...st.procs.values()]) if (q.dying) st.remove(q.id);   // the scene, after the fade
          mono += 61000;
          st.apply({ k: 'ev', h: 'lin', t: wall, pid: 50, ppid: 1, name: 'job', i: ['temp', 'new', 'unknown'] });
          mono += 1500; st.settleStarts(mono);
          console.log(JSON.stringify([settled, st.shortLived.lin]));""")
        self.assertEqual(out, [0, 1], "a pid exited a minute ago may be a new run")

    def test_a_repeating_change_is_one_line_with_a_count(self):
        out = self.state("""
          for (let i = 0; i < 50; i++) {
            st.apply({ k: 'ev', h: 'lin', t: wall, pid: 100 + i, ppid: 1, name: 'loader', i: ['temp', 'new', 'unknown'] });
            mono += 2000; wall += 2000; st.settleStarts(mono);
          }
          const one = st.changes.map((c) => [c.k, c.count]);
          wall += 11 * 60 * 1000;
          st.apply({ k: 'ev', h: 'lin', t: wall, pid: 999, ppid: 1, name: 'loader', i: ['temp', 'new', 'unknown'] });
          mono += 2000; st.settleStarts(mono);
          console.log(JSON.stringify([one, st.changes.map((c) => c.count)]));""")
        self.assertEqual(out, [[["notice-short", 50]], [1, 50]])

    def test_missing_needs_a_live_feed_and_comes_back(self):
        out = self.state("""
          st.apply({ k: 'snap', h: 'win', t: wall, p: [row('9:1', 9, 'MsMpEng.exe', wall - 9000)] });
          st.tally();
          st.apply({ k: 'd', h: 'win', t: wall, a: [], x: ['9:1'], u: [] });
          for (const p of st.procs.values()) if (p.dying) st.remove(p.id);
          st.apply({ k: 'status', sources: { win: { state: 'stale' } } });
          const stale = st.tally().missing;
          live('win');
          const gone = st.tally().missing;
          st.apply({ k: 'd', h: 'win', t: wall, a: [row('10:2', 10, 'MsMpEng.exe', wall)], x: [], u: [] });
          const back = st.tally().missing;
          console.log(JSON.stringify([stale, gone, back, kinds()]));""")
        self.assertEqual(out, [0, 1, 0, ["watched-exit:MsMpEng.exe", "missing:msmpeng.exe", "back:msmpeng.exe"]])

    def test_a_baseline_arriving_late_reclassifies_without_listing_old_processes(self):
        out = self.run_js(f"""
          let wall = {NOW} * 1000;
          const st = new s.ProcState({{ wallMs: () => wall, monoMs: () => 0 }});
          st.apply({{ k: 'snap', h: 'win', t: wall, p: [['1:1', 1, 0, 'evil.exe', wall, 0, 1, 1, null]] }});
          const before = st.procs.get('win|1:1').level;
          st.setBaseline({{ ok: true, hosts: {{ win: {{ rows: 1, names: {{ 'svchost.exe': [1, 1, 1, 0] }} }} }}, watch: {{}} }});
          console.log(JSON.stringify([before, st.procs.get('win|1:1').level, st.changes.length]));""")
        self.assertEqual(out, ["unknown", "alarm", 0])

    def test_unknown_frames_and_malformed_rows_do_not_break_the_table(self):
        out = self.state("""
          st.apply(null); st.apply('x'); st.apply({ k: 'exec', cmd: 'calc' });
          st.apply({ k: 'i', h: 'win', i: [['nope', ['temp', 'moved', 'new']]] });
          st.apply({ k: 'd', h: 'win', t: wall, x: ['nope'], u: [['nope', 50, 1]] });
          console.log(JSON.stringify([st.procs.size, kinds()]));""")
        self.assertEqual(out, [0, []])


class WiringTests(unittest.TestCase):
    def test_every_page_module_is_served_and_imported_by_absolute_path(self):
        from jarvis.web import server
        for name in ("procs.js", "procs-model.js", "procs-state.js", "procs-scene.js"):
            self.assertIn(f"/static/{name}", server.COVERAGE_ASSETS)
        page = (STATIC / "procs.js").read_text()
        for name in ("procs-model.js", "procs-state.js", "procs-scene.js"):
            self.assertIn(f"from '/static/{name}'", page)

    def test_the_page_never_names_a_path_or_hash_field(self):
        for name in ("procs.js", "procs-state.js", "procs-scene.js", "procs-model.js"):
            text = (STATIC / name).read_text()
            for field in ("sha256", ".path", "cmdline", "CommandLine"):
                self.assertNotIn(field, text, f"{name} mentions {field}")


if __name__ == "__main__":
    unittest.main()
