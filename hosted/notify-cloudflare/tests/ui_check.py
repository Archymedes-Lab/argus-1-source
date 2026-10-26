"""Drive the phone app in Chromium at a phone viewport against `wrangler dev`:
pairing through the real UI, an alert in the inbox, the detail view, settings.
Records console errors and CSP violations; writes screenshots to OUT.

    HOME=$(mktemp -d) uv run --with playwright==1.55.0 python tests/ui_check.py OUT
"""
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "..", "..")))
from playwright.sync_api import sync_playwright  # noqa: E402

from jarvis.response.notify import channel, crypto, devices, relay  # noqa: E402

PORT = 9467
BASE = f"http://127.0.0.1:{PORT}"
CONF = {"notify_url": BASE, "notify_label": "web-1"}
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/argus-ui"


def main():
    os.makedirs(OUT, exist_ok=True)
    srv = subprocess.Popen(["./node_modules/.bin/wrangler", "dev", "--ip", "127.0.0.1", "--port", str(PORT), "--local",
                            "--log-level", "warn"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    problems = []
    try:
        for _ in range(120):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        time.sleep(1)
        ident = crypto.Identity.load(create=True)
        code = crypto.pairing_code()
        relay.call(CONF, ident, "PUT", f"/v1/pair/{code}",
                   {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub), "s_enc": crypto.b64u(ident.enc_pub),
                    "label": "web-1", "expires": int(time.time()) + 600})
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--disable-dev-shm-usage"])
            ctx = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2,
                                      is_mobile=True, has_touch=True, color_scheme="dark",
                                      user_agent="Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36")
            page = ctx.new_page()
            page.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
            page.goto(BASE + "/#/")
            page.wait_for_selector("text=No servers yet")
            page.screenshot(path=f"{OUT}/1-empty.png")
            page.click("text=Add a server")
            page.fill("#code", crypto.format_code(code).lower())
            page.screenshot(path=f"{OUT}/2-add.png")
            page.click("button[type=submit]")
            page.wait_for_selector(".sas", timeout=20000)
            shown = page.inner_text(".sas").replace(" ", "")
            page.screenshot(path=f"{OUT}/3-compare.png")
            claims = []
            for _ in range(20):
                claims = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code}")
                if claims:
                    break
                time.sleep(0.3)
            c = claims[0]
            ours = crypto.sas(ident.sig_pub, ident.enc_pub, crypto.unb64u(c["d_sig"]), crypto.unb64u(c["d_enc"]))
            print("SAS page", shown, "server", ours, "MATCH" if shown == ours else "MISMATCH")
            if shown != ours:
                problems.append("SAS mismatch")
            devices.add({"dev": c["dev"], "d_sig": c["d_sig"], "d_enc": c["d_enc"], "name": c["name"]})
            relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{c['dev']}/activate", {"code": code})
            page.wait_for_selector("text=Paired", timeout=20000)
            page.screenshot(path=f"{OUT}/4-paired.png")
            for sev, title in (("critical", "web-1: known-exploited vulnerability fixed but not installed: openssh"),
                               ("medium", "web-1: 22 packages have security fixes not installed"),
                               ("low", "web-1: no off-box heartbeat")):
                err = channel.send(CONF, title, "CVE-2024-6387 (CISA KEV) affect openssh 1:9.6p1-3ubuntu13.4; "
                                   "USN-6859-1 fixed it in 1:9.6p1-3ubuntu13.5. Install the update and restart sshd.\n"
                                   "<img src=x onerror=alert(1)> stays text.", severity=sev)
                if err:
                    problems.append(f"send: {err}")
            page.goto(BASE + "/#/")
            try:
                page.wait_for_selector(".row", timeout=20000)
            except Exception:
                diag = page.evaluate("""async () => {
                  const m = await import('/lib/store.js'); const s = await import('/lib/sync.js');
                  const servers = (await m.servers.all()).map(x => ({mb: x.mb, dev: x.dev, err: x.lastError, sync: x.lastSync,
                     keyType: x.keys && x.keys.sigPriv && x.keys.sigPriv.constructor.name}));
                  let r; try { r = await s.syncAll(); r = {fresh: r.fresh.length, dropped: r.dropped}; } catch (e) { r = String(e); }
                  const src = await (await fetch('/app.js', {cache: 'no-store'})).text();
                  return {servers, sync: r, after: (await m.servers.all()).map(x => x.lastError),
                          status: document.getElementById('status').textContent, href: location.href,
                          view: document.getElementById('view').innerText.slice(0, 120),
                          servedHasSync: src.includes('async function sync()'),
                          swControlled: !!navigator.serviceWorker.controller};
                }""")
                print("DIAG", diag)
                raise
            page.wait_for_timeout(500)
            page.screenshot(path=f"{OUT}/5-inbox.png")
            rows = page.locator(".row").count()
            page.locator(".row").first.click()
            page.wait_for_selector(".detail")
            if page.locator(".detail img").count():
                problems.append("alert text was parsed as HTML")
            page.screenshot(path=f"{OUT}/6-detail.png", full_page=True)
            page.click("text=Settings")
            page.wait_for_selector("text=Show alert titles on the lock screen")
            page.screenshot(path=f"{OUT}/7-settings.png")
            ctx_light = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, color_scheme="light")
            lp = ctx_light.new_page()
            lp.goto(BASE + "/#/")
            lp.wait_for_selector("text=No servers yet")
            lp.screenshot(path=f"{OUT}/8-light-empty.png")
            sw = page.evaluate("navigator.serviceWorker.getRegistration().then(r => !!(r && (r.active || r.installing || r.waiting)))")
            print(f"rows {rows}; service worker registered: {sw}")
            browser.close()
    finally:
        srv.terminate()
        srv.wait(10)
    real = [p for p in problems if "favicon" not in p]
    print("problems:", real or "none")
    sys.exit(1 if real else 0)


if __name__ == "__main__":
    main()
