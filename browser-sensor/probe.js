// Main-world probe. Never retain an event object or payload; only increment
// fixed allowlisted counters. A hostile page cannot ask it to perform actions.
(() => {
  const listeners = Object.create(null), surfaces = Object.create(null), transports = Object.create(null);
  const listenerNames = new Set(["mousemove", "pointermove", "scroll", "input", "keydown"]);
  const origins = new Set();
  const inc = (map, name) => { map[name] = Math.min(10000, (map[name] || 0) + 1); };
  const noteUrl = (value) => { try { const u = new URL(value, location.href); if (/^https?:$/.test(u.protocol)) origins.add(u.origin); } catch (_) {} };
  const originalAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, ...rest) {
    if (listenerNames.has(type)) inc(listeners, type);
    return originalAdd.call(this, type, ...rest);
  };
  const wrap = (object, method, surface) => {
    if (!object || !object[method]) return;
    const original = object[method];
    object[method] = function(...args) { inc(surfaces, surface); return original.apply(this, args); };
  };
  wrap(HTMLCanvasElement.prototype, "toDataURL", "canvas");
  wrap(HTMLCanvasElement.prototype, "getContext", "canvas");
  const originalBeacon = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
  if (originalBeacon) navigator.sendBeacon = (url, ...rest) => { inc(transports, "beacon"); noteUrl(url); return originalBeacon(url, ...rest); };
  const originalFetch = window.fetch;
  if (originalFetch) window.fetch = (input, ...rest) => { inc(transports, "fetch"); noteUrl(typeof input === "string" ? input : input.url); return originalFetch(input, ...rest); };
  const open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) { inc(transports, "xhr"); noteUrl(url); return open.call(this, method, url, ...rest); };
  for (const name of ["WebGLRenderingContext", "WebGL2RenderingContext"]) if (window[name]) inc(surfaces, "webgl");
  if (navigator.gpu) inc(surfaces, "webgpu");
  if (navigator.mediaDevices) inc(surfaces, "media_devices");
  if (navigator.storage && navigator.storage.getDirectory) inc(surfaces, "opfs");
  const send = () => window.postMessage({channel: "jarvis-veil", payload: {
    top_origin: location.origin, egress_origins: [...origins].slice(0, 16), listeners, surfaces, transports
  }}, location.origin);
  setInterval(send, 20000);
  addEventListener("pagehide", send, {once: true});
})();
