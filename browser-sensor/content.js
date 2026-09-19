// This runs in the isolated extension world. It only forwards a bounded summary
// emitted by probe.js; it never reads page text, form values, cookies, pointer
// positions, keystroke timing, resource paths, query strings, or request bodies.
const probe = document.createElement("script");
probe.src = chrome.runtime.getURL("probe.js");
probe.dataset.jarvisVeil = "1";
(document.head || document.documentElement).appendChild(probe);
probe.remove();

let last = 0;
window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data || event.data.channel !== "jarvis-veil") return;
  const now = Date.now();
  if (now - last < 15000) return; // coarse periodic evidence, not a session replay
  last = now;
  chrome.runtime.sendMessage({kind: "veil-report", payload: event.data.payload});
});
