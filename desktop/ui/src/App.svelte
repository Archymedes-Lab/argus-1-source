<script lang="ts">
  import Sidebar from "./components/Sidebar.svelte";
  import Toolbar from "./components/Toolbar.svelte";
  import SimpleOverview from "./views/SimpleOverview.svelte";
  import Overview from "./views/Overview.svelte";
  import Findings from "./views/Findings.svelte";
  import Collectors from "./views/Collectors.svelte";
  import Review from "./views/Review.svelte";
  import Assistant from "./views/Assistant.svelte";
  import Pricing from "./views/Pricing.svelte";
  import Settings from "./views/Settings.svelte";
  import CommandPalette from "./components/CommandPalette.svelte";
  import { Tooltip } from "bits-ui";
  import { app } from "./lib/store.svelte";
  import { tr } from "./lib/i18n";

  const views = { overview: Overview, findings: Findings, collectors: Collectors, review: Review, assistant: Assistant, pricing: Pricing, settings: Settings };
  const Current = $derived(app.view === "overview" && app.mode === "simple" ? SimpleOverview : views[app.view]);
</script>

<Tooltip.Provider>
<div class="flex h-full">
  <Sidebar />
  <div class="flex min-w-0 flex-1 flex-col">
    <Toolbar />
    <main class="flex-1 overflow-y-auto">
      {#if (app.data?.paused_until ?? 0) * 1000 > Date.now()}
        <div class="mx-auto mt-6 max-w-[1200px] px-8">
          <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900">
            <span class="dot dot-warn"></span>{tr("ARGUS-1 is taking a break and is not checking your computer. It starts again by itself at {time}.", { time: new Date(app.data.paused_until * 1000).toLocaleTimeString(app.lang, { hour: "2-digit", minute: "2-digit" }) })}
          </div>
        </div>
      {/if}
      {#if app.daemon === "down" && app.data}
        <div class="mx-auto mt-6 max-w-[1200px] px-8">
          <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900">
            <span class="dot dot-warn"></span>{tr("ARGUS-1 is not answering right now. Showing the last state it reported; monitoring may still be running.")}
          </div>
        </div>
      {/if}
      <div class="mx-auto max-w-[1200px] px-8 py-8">
        {#key app.view}<div class="anim-rise"><Current /></div>{/key}
      </div>
    </main>
  </div>
</div>
<CommandPalette />
</Tooltip.Provider>

<div class="pointer-events-none fixed right-4 bottom-4 z-40 flex w-[360px] flex-col gap-2">
  {#each app.toasts as t (t.id)}
    <div class="pointer-events-auto flex items-start gap-2.5 rounded-lg bg-bg-100 px-4 py-3 text-copy-13 shadow-pop anim-rise" role="status">
      <span class="dot mt-1.5 {t.tone === 'ok' ? 'dot-ok' : t.tone === 'bad' ? 'dot-bad' : 'dot-run'}"></span><span>{t.text}</span>
    </div>
  {/each}
</div>
