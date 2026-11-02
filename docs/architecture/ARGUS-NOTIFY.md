# Notifications to a phone: the sealed relay (v1)

Status: building, 2026-10-25. Supersedes the transport and crypto choices of MESSAGING.md
(2026-09-16) for its phase 1; the goals and threat model there still apply.

Owner decisions 2026-10-25: hosted at `argus.archymedes.xyz` (Cloudflare Worker + Durable
Objects); no accounts, a phone is a set of device keys; first release is one-way push, inbox and
pairing (no replies); the server uses `python3-cryptography` from the distribution.

## Shape

```
 server (Argus, never listens)      argus.archymedes.xyz                 phone (PWA)
 ─────────────────────────────      ──────────────────────               ───────────
 alert.deliver ─► notify channel    Worker ─ Mailbox DO (per server)     service worker
   seal per device (X25519,         stores ciphertext envelopes,         ◄─ Web Push (empty)
   HKDF-SHA256, AES-256-GCM),       device push subscriptions;           fetches its inbox,
   sign (Ed25519) ─HTTPS POST──►    sends an empty Web Push  ──────►     verifies, decrypts,
                                    PairSlot DO (per code, 10 min)       shows the notification
```

The relay stores and forwards ciphertext. The push service (Apple, Google, Mozilla) receives
an empty wake-up. Only the phone can read an alert, and only alerts signed by its paired
server are shown.

## Invariants

- **N1 Nothing listens on the server.** Argus only makes outbound HTTPS requests.
- **N2 The relay cannot read.** It sees mailbox and device ids, sizes, times and push
  endpoints; never titles, severities or text.
- **N3 The relay cannot impersonate.** Mailbox and device ids are hashes of their own Ed25519
  keys (self-certifying); every envelope is signed by the server key the phone pinned at pairing;
  a device becomes active only after the owner confirms a 6-digit code on the server that the
  phone also shows, derived from both sides' keys.
- **N4 Bounded.** Envelope ≤ 8 KiB, ≤ 500 pending per device, ≤ 20 devices per mailbox, 7-day
  expiry, pairing codes single-use for 10 minutes with ≤ 10 attempts; request timestamps within
  300 s, replayed request signatures refused.
- **N5 Visible delivery.** The channel's outcome is recorded per send; it counts as a channel
  that can reach the owner only while at least one device is active and the last send worked.
- **N6 Nothing to steal on the relay.** No accounts, no emails, no passwords.
- **N7 Revocable.** `notify revoke` removes a device locally and on the relay; the phone can
  remove a server.

## Identifiers and keys

`b64u` = base64url without padding. `H(x)` = SHA-256.

| who | keys | id |
| --- | --- | --- |
| server (mailbox) | Ed25519 `S_sig`, X25519 `S_enc` (kept 0600 beside the store) | `mb = b64u(H(S_sig_pub))[:22]` |
| phone (device) | Ed25519 `D_sig`, X25519 `D_enc` (WebCrypto, non-extractable, IndexedDB) | `dev = b64u(H(D_sig_pub))[:22]` |

Public keys travel as b64u of their 32 raw bytes.

## Signed requests

Server → relay and phone → relay requests carry:

```
X-Notify-Key: b64u(sig_pub)            (the id must equal b64u(H(key))[:22])
X-Notify-Time: unix seconds
X-Notify-Nonce: b64u(16 random bytes)  (Ed25519 is deterministic: without it two identical
                                        requests in one second would share a signature)
X-Notify-Sig: b64u(Ed25519(sig_priv, "notify-req/1\n" + METHOD + "\n" + PATH + "\n" + TIME
                                     + "\n" + NONCE + "\n" + hex(H(body))))
```

The relay checks the id, the window (±300 s) and that the signature was not seen in the window.

## Pairing

1. Server: `notify pair --label NAME` creates a code (10 symbols of Crockford base32, 50 bits),
   and `PUT /v1/pair/{code}` (signed by `S_sig`) with
   `{mb, s_sig, s_enc, label, expires}`.
2. Phone: the owner types the code; `GET /v1/pair/{code}` returns that offer; the phone checks
   `mb == b64u(H(s_sig))[:22]`, makes its keys and push subscription, and
   `POST /v1/pair/{code}/claim` (signed by `D_sig`) with `{dev, d_sig, d_enc, push, name}`.
3. Both compute `SAS = int(H("notify-sas/1" | s_sig | s_enc | d_sig | d_enc)[:4]) mod 10^6`,
   shown as `123 456`. The server polls `GET /v1/mailbox/{mb}/claims` (signed), shows the
   device name and code; the owner answers yes only if the phone shows the same code.
4. Yes: the server records the device (`dev, d_sig, d_enc, name, paired_at`) and
   `POST /v1/mailbox/{mb}/devices/{dev}/activate` (signed). The phone polls the slot until
   active, then stores `{mb, label, s_sig, s_enc}`.

Robustness (2026-11-02): the server retries the activation 5 times over 30 s; if the relay
still does not confirm, the device stays recorded with `relay_pending: true`, `notify devices`
and `notify status` say so, and the Link Plane reports it (pair again to fix). The phone
stores the pending pairing (server, code, its keys, the 10-minute deadline) in IndexedDB
*before* claiming, so a reload or an app switch mid-pairing resumes the "compare this code"
screen with the same keys instead of losing them; Servers shows "pairing in progress" with a
cancel, and the entry is cleared on success, expiry or cancel.

## Envelopes

Per message and device, the server makes an ephemeral X25519 key `E`:

```
shared = X25519(E_priv, D_enc_pub)
key    = HKDF-SHA256(ikm=shared, salt=id_bytes, info="notify-seal/1", 32 bytes)
iv     = 12 random bytes
aad    = canonical JSON of {v, id, mb, dev, sent, expires, epk}
ct     = AES-256-GCM(key, iv, payload, aad)
sig    = Ed25519(S_sig, "notify-env/1\n" + aad + "\n" + b64u(iv) + "\n" + b64u(ct))
envelope = {v: 1, id, mb, dev, sent, expires, epk, iv, ct, sig}
```

`id` is 16 random bytes (b64u). Canonical JSON: keys sorted, no whitespace, UTF-8.
Payload (JSON, ≤ 4 KiB): `{kind: "alert"|"test", title, body, severity, finding?, host, at}`.

Server → relay: `POST /v1/mailbox/{mb}/envelopes` (signed) with `[envelope, ...]`.
Server ← relay: `GET /v1/mailbox/{mb}/devices` (signed) returns
`[{dev, name, state, added, last_seen, push}]`: liveness metadata only (`last_seen` is the
device's last inbox fetch, `push` whether a subscription is stored). The server's Link Plane
(`jarvis/service/links.py`) uses it to say "this phone has not checked in for 48 h" or
"this phone has no push subscription"; nothing it returns can read or forge an alert (N2, N3).
Phone ← relay: `GET /v1/device/{dev}/inbox` (signed by `D_sig`), then
`POST /v1/device/{dev}/ack` with the ids it stored. The relay deletes acked and expired ones.

The phone shows a message only if `sig` verifies with the pinned `s_sig` of `mb` and decryption
succeeds; anything else is dropped and counted.

## Push

The relay holds a VAPID key (Worker secret). After storing envelopes for a device it sends one
Web Push with no payload and TTL 7 days. The service worker, on `push`, fetches the inbox,
verifies, decrypts, stores and shows one notification per message (or a summary for more than 3).
iOS delivers Web Push only to a PWA added to the home screen (16.4+).

## Server side

`jarvis/response/notify/`: `crypto.py` (keys, seal, sign, SAS), `relay.py` (signed HTTPS client,
bounded), `devices.py` (local registry), `channel.py` (`send(subject, text, severity)` used by
`alert.deliver`). CLI: `notify pair | devices | revoke | test | status`. The relay URL defaults to
`https://argus.archymedes.xyz` and is set by `notify_url` in the alert config.
