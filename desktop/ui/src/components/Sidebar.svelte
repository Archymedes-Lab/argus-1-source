<script lang="ts">
  import Shield from "@lucide/svelte/icons/shield";
  import { app, go, type View } from "../lib/store.svelte";
  import { NAV } from "../lib/nav";
  import { collectorSummary, groupQuestions, problemCounts } from "../lib/model";

  const counts = $derived(app.data ? problemCounts(app.data.findings ?? []) : null);
  const coll = $derived(app.data ? collectorSummary(app.data.jobs ?? []) : null);
  const review = $derived(app.data ? groupQuestions(app.data.questions ?? []).length + (app.data.fix ?? []).length : 0);

  function badge(v: View): { n: number; tone: string } | null {
    if (v === "findings" && counts?.critical) return { n: counts.critical, tone: "text-red-900" };
    if (v === "collectors" && coll && coll.stale + coll.error) return { n: coll.stale + coll.error, tone: "text-amber-900" };
    if (v === "review" && review) return { n: review, tone: "text-blue-900" };
    return null;
  }
</script>

{#snippet item(n: (typeof NAV)[number])}
  {@const b = badge(n.view)}
  <button class="nav-item" aria-current={app.view === n.view ? "page" : undefined} onclick={() => go(n.view)}>
    <n.icon size={16} strokeWidth={1.75} />
    <span>{n.label}</span>
    {#if b}<span class="ml-auto tabular text-label-12 {b.tone}">{b.n}</span>{/if}
  </button>
{/snippet}

<aside class="flex w-[232px] shrink-0 flex-col border-r border-gray-300 bg-bg-200">
  <div class="flex h-13 items-center gap-2.5 px-4">
    <span class="grid size-6 place-items-center rounded-md bg-gray-1000 text-bg-100"><Shield size={14} strokeWidth={2} /></span>
    <span class="text-heading-16">ARGUS-1</span>
  </div>
  <nav class="flex flex-col gap-0.5 px-2 pt-2" aria-label="Sections">
    {#each NAV.slice(0, 5) as n (n.view)}{@render item(n)}{/each}
  </nav>
  <div class="mt-auto flex flex-col gap-0.5 px-2 pb-2">
    {#each NAV.slice(5) as n (n.view)}{@render item(n)}{/each}
    <div class="mt-2 flex items-center gap-2 px-2.5 py-2 text-label-12 text-gray-900">
      <span class="dot {app.daemon === 'live' ? 'dot-ok' : app.daemon === 'down' ? 'dot-bad' : 'dot-run'}"></span>
      {app.daemon === "live" ? "Monitoring" : app.daemon === "down" ? "ARGUS-1 unreachable" : "Connecting"}
    </div>
  </div>
</aside>
