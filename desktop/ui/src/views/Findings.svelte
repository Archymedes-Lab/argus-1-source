<script lang="ts">
  import { Dialog } from "bits-ui";
  import X from "@lucide/svelte/icons/x";
  import Search from "@lucide/svelte/icons/search";
  import Pill from "../components/Pill.svelte";
  import Segmented from "../components/Segmented.svelte";
  import Select from "../components/Select.svelte";
  import { app } from "../lib/store.svelte";
  import { filterFindings, sentence, severityCounts, SEVERITIES, type Finding } from "../lib/model";

  const all = $derived((app.data?.findings ?? []) as Finding[]);
  const counts = $derived(severityCounts(all));
  const rows = $derived(filterFindings(all, { query: app.query, severity: app.severity, host: app.host, job: app.job }));
  const jobs = $derived([...new Set(all.map((f) => f.job))].sort());
  let limit = $state(150);
  $effect(() => { app.query; app.severity; app.host; app.job; limit = 150; });
  const filtered = $derived(!!(app.query || app.severity || app.host || app.job));
  function clear() { app.query = ""; app.severity = null; app.host = ""; app.job = ""; }
  // The toggle group's empty value means "all severities".
  let sev = $state(app.severity ?? "");
  $effect(() => { sev = app.severity ?? ""; });
  $effect(() => { app.severity = sev || null; });
  const sevItems = $derived([{ value: "", label: "All", count: all.length },
    ...SEVERITIES.map((s) => ({ value: s, label: sentence(s), count: counts[s], tone: s === "critical" && counts[s] ? "text-red-900" : undefined }))]);
  const hostItems = [{ value: "", label: "Both hosts" }, { value: "win", label: "Windows" }, { value: "wsl", label: "WSL" }];
  const jobItems = $derived([{ value: "", label: "All collectors" }, ...jobs.map((j) => ({ value: j, label: j }))]);
  let detailOpen = $state(false);
  $effect(() => { detailOpen = !!app.selected; });
</script>

<div class="flex flex-col gap-4">
  <div class="flex flex-wrap items-center gap-2">
    <label class="relative w-64">
      <Search size={14} class="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-gray-700" />
      <input class="input pl-8" bind:value={app.query} placeholder="Filter findings" aria-label="Filter findings" />
    </label>
    <Segmented items={sevItems} bind:value={sev} label="Severity" />
    <Select items={hostItems} bind:value={app.host} label="Host" width="w-36" />
    <Select items={jobItems} bind:value={app.job} label="Collector" />
    {#if filtered}<button class="btn btn-ghost btn-sm" onclick={clear}>Clear filters</button>{/if}
    <span class="ml-auto text-copy-13 text-gray-900 tabular">{rows.length} of {all.length}</span>
  </div>

  <div class="card overflow-hidden">
    {#if !rows.length}
      <div class="empty">{all.length ? "Nothing matches these filters." : app.error || "No findings."}</div>
    {:else}
      <div class="divide">
        {#each rows.slice(0, limit) as f, i (i)}
          <button class="row row-click w-full items-start text-left {app.selected === f ? 'bg-gray-100' : ''}" onclick={() => (app.selected = f)}>
            <span class="w-[76px] shrink-0 pt-px"><Pill severity={f.severity} /></span>
            <span class="min-w-0 flex-1">
              <span class="block truncate text-label-13">{f.title}</span>
              <span class="block truncate text-copy-13 text-gray-900">{f.detail}</span>
            </span>
            <span class="flex shrink-0 items-center gap-1.5 pt-px"><span class="tag">{f.job}</span><span class="tag">{f.host}</span></span>
          </button>
        {/each}
      </div>
      {#if rows.length > limit}
        <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (limit += 150)}>Show {Math.min(150, rows.length - limit)} more</button></div>
      {/if}
    {/if}
  </div>
</div>

<Dialog.Root bind:open={detailOpen} onOpenChange={(o) => { if (!o) app.selected = null; }}>
  <Dialog.Portal>
    <Dialog.Overlay class="overlay" />
    <Dialog.Content class="popover fixed top-2 right-2 bottom-2 z-50 flex w-[440px] max-w-[calc(100vw-16px)] flex-col overflow-hidden p-0 anim-slide">
      {#if app.selected}
        {@const f = app.selected}
        <div class="flex items-start gap-3 border-b border-gray-300 p-5">
          <div class="min-w-0 flex-1">
            <Pill severity={f.severity} />
            <Dialog.Title class="selectable mt-2 text-heading-20">{f.title}</Dialog.Title>
          </div>
          <Dialog.Close class="btn btn-ghost w-8 justify-center px-0" aria-label="Close"><X size={16} /></Dialog.Close>
        </div>
        <div class="selectable flex-1 overflow-auto p-5">
          <Dialog.Description class="text-copy-14 text-gray-1000">{f.detail}</Dialog.Description>
          <dl class="mt-5 grid grid-cols-[96px_1fr] gap-x-4 gap-y-2.5 text-copy-13">
            <dt class="text-gray-900">Collector</dt><dd><span class="tag">{f.job}</span></dd>
            <dt class="text-gray-900">Host</dt><dd>{f.host === "win" ? "Windows" : f.host === "wsl" ? "WSL" : f.host}</dd>
            <dt class="text-gray-900">Category</dt><dd>{f.category ?? "—"}</dd>
            <dt class="text-gray-900">Location</dt><dd class="font-mono text-[12.5px] break-all">{f.where || "—"}</dd>
          </dl>
          {#if f.forensics?.length}
            <h3 class="mt-6 mb-2 text-label-13 text-gray-900">Forensics</h3>
            <pre class="rounded-lg bg-gray-100 p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-all">{f.forensics.join("\n")}</pre>
          {/if}
        </div>
      {/if}
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
