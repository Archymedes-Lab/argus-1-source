<script lang="ts">
  import Search from "@lucide/svelte/icons/search";
  import RotateCw from "@lucide/svelte/icons/rotate-cw";
  import IconButton from "./IconButton.svelte";
  import { app, refresh } from "../lib/store.svelte";
  import { NAV } from "../lib/nav";
  import { scoreTone } from "../lib/model";

  const sec = $derived(app.data?.security);
  const tone = $derived(scoreTone(sec?.score));
  const title = $derived(NAV.find((n) => n.view === app.view)?.label ?? "");

  function onKey(e: KeyboardEvent) {
    const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
    if ((e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !typing)) {
      e.preventDefault(); app.palette = true;
    }
  }
</script>

<svelte:window onkeydown={onKey} />

<header class="material sticky top-0 z-10 flex h-13 items-center gap-3 border-b border-gray-300 px-6">
  <h1 class="text-heading-16">{title}</h1>
  {#if sec}
    <span class="pill {tone === 'red' ? 'pill-critical' : tone === 'amber' ? 'pill-high' : 'pill-ok'}">
      Score {sec.score}{sec.state === "verifying" ? " · re-checking" : ""}
    </span>
  {/if}
  <div class="ml-auto flex items-center gap-1.5">
    <button class="input flex w-[280px] cursor-default items-center gap-2 text-gray-700" onclick={() => (app.palette = true)} aria-label="Search">
      <Search size={14} /><span class="flex-1 text-left">Search or jump to…</span><span class="kbd">Ctrl K</span>
    </button>
    <IconButton label="Refresh now" onclick={refresh} disabled={app.loading}>
      <RotateCw size={15} class={app.loading ? "animate-spin" : ""} />
    </IconButton>
  </div>
</header>
