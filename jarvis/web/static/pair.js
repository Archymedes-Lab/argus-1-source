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
  let message = 'ARGUS-1 refused this token.';
  try { const body = await res.json(); if (body && body.error) message = String(body.error); } catch (e) { /* not JSON */ }
  return { ok: false, message };
}

if (typeof document !== 'undefined' && document.getElementById('pair')) {
  const form = document.getElementById('pair');
  const out = document.getElementById('result');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const input = document.getElementById('token');
    out.className = '';
    out.textContent = 'Pairing…';
    try {
      const result = await pair(input.value, fetch.bind(window));
      input.value = '';
      if (result.ok) {
        out.textContent = 'Paired. Opening ARGUS-1…';
        location.replace(safeNext(new URLSearchParams(location.search).get('next')));
      } else {
        out.className = 'bad';
        out.textContent = result.message;
      }
    } catch (e) {
      out.className = 'bad';
      out.textContent = 'ARGUS-1 did not answer.';
    }
  });
}

if (typeof globalThis !== 'undefined') globalThis.__pair = { pair, safeNext };
