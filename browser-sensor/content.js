// This runs in the isolated extension world. It only forwards a bounded summary
// emitted by probe.js (a MAIN-world content script); it never reads page text,
// form values, cookies, pointer positions, keystroke timing, resource paths,
// query strings, or request bodies.
let last = 0;
window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data || event.data.channel !== "jarvis-veil") return;
  const now = Date.now();
  if (now - last < 15000) return; // coarse periodic evidence, not a session replay
  last = now;
  chrome.runtime.sendMessage({kind: "veil-report", payload: event.data.payload});
});
