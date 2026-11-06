<script lang="ts">
  import Download from "@lucide/svelte/icons/download";
  import { api } from "../lib/api";
  import { app, go, type View } from "../lib/store.svelte";
  import { EXPERT_ONLY, NAV, type NavGroup } from "../lib/nav";
  import { t, type Key } from "../lib/words";
  import { tr } from "../lib/i18n";
  import { collectorSummary, groupQuestions, problemCounts } from "../lib/model";
  import { LEVELS, summarize } from "../lib/coverage";

  const counts = $derived(app.data ? problemCounts(app.data.findings ?? []) : null);
  const coll = $derived(app.data ? collectorSummary(app.data.jobs ?? []) : null);
  // Same count as the home page: questions, fix proposals and grouped cases.
  const review = $derived(app.data ? groupQuestions(app.data.questions ?? []).length + (app.data.fix ?? []).length + app.casesWaiting : 0);
  const cov = $derived(summarize(app.coverage));
  const simple = $derived(app.mode === "simple");
  const LEVEL_NAME = $derived((simple
    ? { validated: tr("Working"), claimed: tr("Should work"), blind: tr("Cannot see yet"), regressed: tr("Stopped working") }
    : { validated: tr("Proven"), claimed: tr("Expected"), blind: tr("Blind spot"), regressed: tr("Got worse") }) as Record<string, string>);
  const TONE: Record<string, string> = { validated: "var(--green-700)", claimed: "var(--blue-700)", blind: "var(--amber-700)", regressed: "var(--red-700)" };

  function badge(v: View): { n: number; tone: string } | null {
    if (v === "findings" && counts?.critical) return { n: counts.critical, tone: "text-amber-900" };
    if (v === "collectors" && coll && coll.stale + coll.error) return { n: coll.stale + coll.error, tone: "text-amber-900" };
    if (v === "review" && review) return { n: review, tone: "text-blue-900" };
    return null;
  }
  const shown = (g: NavGroup) => NAV.filter((n) => n.group === g && (app.mode === "expert" || !EXPERT_ONLY.includes(n.view)));
  const live = $derived(app.status.phase === "live");
  const paused = $derived(live && (app.data?.paused_until ?? 0) * 1000 > Date.now());
</script>

{#snippet item(n: (typeof NAV)[number])}
  {@const b = badge(n.view)}
  <button class="nav-item" aria-current={app.view === n.view ? "page" : undefined} onclick={() => go(n.view)}>
    <span class="truncate">{t(`nav.${n.view}` as Key)}</span>
    {#if b}<span class="ml-auto tabular text-label-12 {b.tone}">{b.n}</span>{/if}
  </button>
{/snippet}

<aside class="flex w-[232px] shrink-0 flex-col overflow-y-auto border-r border-gray-300 bg-bg-200">
  <div class="flex h-13 shrink-0 items-center px-5">
    <span class="text-label-13 font-bold tracking-[0.06em]">ARGUS-INSTINCT</span>
  </div>

  <nav class="side-section flex flex-col" aria-label={tr("Sections")}>
    {#each shown("main") as n (n.view)}{@render item(n)}{/each}
  </nav>

  <!-- Coverage, always in view: what the daemon reports, expected never added to proven. -->
  <button class="side-section group relative w-full cursor-default px-5 text-left" onclick={() => go("coverage")}
          aria-current={app.view === "coverage" ? "page" : undefined}>
    {#if app.view === "coverage"}<i class="absolute top-3 bottom-2 left-0 w-0.5 bg-gray-1000"></i>{/if}
    <span class="block pb-2 text-eyebrow {app.view === 'coverage' ? 'text-gray-1000' : 'text-gray-700 group-hover:text-gray-1000'}">{t("nav.coverage")}</span>
    {#if cov}
      <span class="flex h-1 overflow-hidden bg-gray-300" role="img"
            aria-label={LEVELS.map((l) => `${LEVEL_NAME[l]} ${cov.counts[l]}`).join(", ")}>
        {#each LEVELS as l}<i style:width="{cov.shares[l] * 100}%" style:background={TONE[l]}></i>{/each}
      </span>
      <span class="mt-2.5 grid grid-cols-[1fr_auto] gap-y-1 text-label-12">
        {#each LEVELS as l}
          {#if l !== "regressed" || cov.counts.regressed}
            <span class="flex items-center gap-2 text-gray-900"><i class="size-1.5" style:background={TONE[l]}></i>{LEVEL_NAME[l]}</span>
            <span class="tabular text-right {l === 'regressed' ? 'text-red-900' : 'text-gray-1000'}">{cov.counts[l]}</span>
          {/if}
        {/each}
        {#if cov.watched !== null}
          <span class="col-span-2 mt-1 text-gray-700">{tr("Watched {n}% of the last 24 hours", { n: cov.watched })}</span>
        {/if}
      </span>
    {:else}
      <span class="block text-copy-13 text-gray-700">{tr("Reading ARGUS-INSTINCT…")}</span>
    {/if}
  </button>

  <nav class="side-section flex flex-col" aria-label={tr("Explore")}>
    <p class="side-label">{tr("Explore")}</p>
    {#each shown("explore").filter((n) => n.view !== "coverage") as n (n.view)}{@render item(n)}{/each}
  </nav>

  <div class="mt-auto">
    {#if app.update?.newer}
      <div class="side-section flex items-center gap-2 px-5" role="status">
        <span class="min-w-0 flex-1 truncate text-label-12">{tr("Version {v} is ready to download.", { v: app.update.latest ?? "" })}</span>
        <button class="btn btn-sm btn-accent shrink-0" onclick={() => api.openDownloadPage().catch(() => {})} aria-label={tr("Get the update")}>
          <Download size={13} />
        </button>
      </div>
    {/if}
    <nav class="side-section flex flex-col" aria-label={tr("Account")}>
      {#each shown("bottom") as n (n.view)}{@render item(n)}{/each}
    </nav>
    <div class="flex items-center gap-2 border-t border-gray-300 px-5 py-3 text-label-12 text-gray-900">
      <span class="dot {live ? (paused ? 'dot-warn' : 'dot-ok') : app.status.phase === 'degraded' ? 'dot-warn' : app.status.phase === 'starting' ? 'dot-run' : 'dot-bad'}"></span>
      <span class="truncate" title={app.status.detail}>{live ? (paused ? tr("On a break") : tr("Watching")) : tr(app.status.message)}</span>
    </div>
  </div>
</aside>
