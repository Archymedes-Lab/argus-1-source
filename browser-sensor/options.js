const input = document.querySelector("#token");
chrome.storage.local.get("pairToken", ({pairToken}) => { input.value = pairToken || ""; });
document.querySelector("#save").onclick = () => chrome.storage.local.set({pairToken: input.value.trim()});
