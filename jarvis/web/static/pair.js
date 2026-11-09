// Pairs this browser with the daemon: posts a client token once to /api/session,
// which answers with an HttpOnly cookie. The token is never stored by this script.
'use strict';

// Only a same-origin path may follow pairing: never another site, never "//host".
function safeNext(raw) {
  const value = String(raw || '');
  return /^\/(?![/\\])[A-Za-z0-9/_\-.]*$/.test(value) ? value : '/';
}

async function pair(token, fetchImpl) {
  const res = await fetchImpl('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: String(token || '').trim() }),
  });
  if (res.ok) return { ok: true };
  let message = 'ARGUS-INSTINCT refused this token.';
  try { const body = await res.json(); if (body && body.error) message = String(body.error); } catch (e) { /* not JSON */ }
  return { ok: false, message };
}

// A link opened from the ARGUS-INSTINCT app carries a one-time code after the "#"
// (so it is never sent to a server or in a Referer). Trade it for the browser cookie.
function linkCode(hash) {
  const m = /^#code=([A-Za-z0-9_-]{32,64})$/.exec(String(hash || ''));
  return m ? m[1] : '';
}

async function pairWithCode(code, fetchImpl) {
  const res = await fetchImpl('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (res.ok) return { ok: true };
  let message = 'This link has expired. Open it again from the ARGUS-INSTINCT app.';
  try { const body = await res.json(); if (body && body.error) message = String(body.error); } catch (e) { /* not JSON */ }
  return { ok: false, message };
}

if (typeof document !== 'undefined' && document.getElementById('pair')) {
  const form = document.getElementById('pair');
  const out = document.getElementById('result');
  const code = linkCode(location.hash);
  if (code) {
    history.replaceState(null, '', location.pathname + location.search);   // the code is spent: drop it
    const manual = document.getElementById('manual');
    if (manual) manual.hidden = true;
    out.textContent = 'Connecting…';
    pairWithCode(code, fetch.bind(window)).then((result) => {
      if (result.ok) {
        out.textContent = 'Connected. Opening ARGUS-INSTINCT…';
        location.replace(safeNext(new URLSearchParams(location.search).get('next')));
      } else {
        out.className = 'bad';
        out.textContent = result.message;
        if (manual) manual.hidden = false;
      }
    }).catch(() => {
      out.className = 'bad';
      out.textContent = 'ARGUS-INSTINCT did not answer.';
      if (manual) manual.hidden = false;
    });
  }
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const input = document.getElementById('token');
    out.className = '';
    out.textContent = 'Pairing…';
    try {
      const result = await pair(input.value, fetch.bind(window));
      input.value = '';
      if (result.ok) {
        out.textContent = 'Paired. Opening ARGUS-INSTINCT…';
        location.replace(safeNext(new URLSearchParams(location.search).get('next')));
      } else {
        out.className = 'bad';
        out.textContent = result.message;
      }
    } catch (e) {
      out.className = 'bad';
      out.textContent = 'ARGUS-INSTINCT did not answer.';
    }
  });
}

if (typeof globalThis !== 'undefined') globalThis.__pair = { pair, safeNext, linkCode, pairWithCode };
