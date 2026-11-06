<script lang="ts">
  import { onMount } from "svelte";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import Eye from "@lucide/svelte/icons/eye";
  import MessageCircle from "@lucide/svelte/icons/message-circle";
  import ListChecks from "@lucide/svelte/icons/list-checks";
  import Sparkles from "@lucide/svelte/icons/sparkles";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import Smartphone from "@lucide/svelte/icons/smartphone";
  import Pill from "../components/Pill.svelte";
  import ProtectionCard from "../components/ProtectionCard.svelte";
  import { api, type Autopilot } from "../lib/api";
  import { app, go } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";
  import { collectorSummary, distinct, groupQuestions, isReminder, problemCounts, type Finding } from "../lib/model";
  import { hasGuide, headline, plainFinding } from "../lib/plain";

  let ap = $state<(Autopilot & { health?: { okay: string; monitoring_line: string } }) | null>(null);
  let phones = $state<number | null>(null);
  onMount(async () => { try { ap = await api.autopilot(); } catch { ap = null; } });
  onMount(async () => { try { phones = (await api.phoneStatus()).devices; } catch { phones = null; } });

  const d = $derived(app.data);
  const findings = $derived((d?.findings ?? []) as Finding[]);
  const counts = $derived(problemCounts(findings));
  const coll = $derived(collectorSummary(d?.jobs ?? []));
  const look = $derived(counts.critical + counts.high);
  const h = $derived(headline(d?.security?.score, counts.critical, counts.high, coll.stale + coll.error));
  const top = $derived(distinct(findings.filter((f) => !isReminder(f) && (f.severity === "critical" || f.severity === "high")), 3));
  const waiting = $derived(groupQuestions(d?.questions ?? []).length + (d?.fix ?? []).length + (ap?.needs_me?.length ?? 0));
  const score = $derived(d?.security?.score as number | undefined);
  const C = 2 * Math.PI * 52;
  const hue = $derived({ ok: "var(--green-700)", warn: "var(--amber-700)", bad: "var(--amber-700)", unknown: "var(--gray-600)" }[h.tone]);
  const soft = $derived({ ok: "var(--green-100)", warn: "var(--amber-100)", bad: "var(--amber-100)", unknown: "var(--gray-100)" }[h.tone]);
</script>

{#if !d}
  <div class="empty">{app.error || tr("Reading ARGUS-INSTINCT…")}</div>
{:else}
  <div class="mx-auto flex max-w-[820px] flex-col gap-6">
    <!-- hero -->
    <section class="card relative overflow-hidden p-0 anim-rise">
      <div class="pointer-events-none absolute -top-24 -right-16 size-72 rounded-full opacity-70 blur-3xl" style:background={soft}></div>
      <div class="pointer-events-none absolute -bottom-28 -left-10 size-64 rounded-full opacity-40 blur-3xl" style:background="var(--blue-100)"></div>
      <div class="relative flex items-center gap-8 p-8 max-sm:flex-col max-sm:items-start">
        <div class="relative shrink-0">
          <svg width="136" height="136" viewBox="0 0 120 120" class="-rotate-90" role="img" aria-label={tr("Health {n} out of 100", { n: score ?? "?" })}>
            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--gray-200)" stroke-width="8" />
            <circle cx="60" cy="60" r="52" fill="none" stroke={hue} stroke-width="8" stroke-linecap="round"
                    stroke-dasharray={C} stroke-dashoffset={C * (1 - Math.max(0, Math.min(100, score ?? 0)) / 100)} class="ring-fill" />
          </svg>
          <div class="absolute inset-0 grid place-items-center" style:color={hue}>
            {#if h.tone === "ok"}<ShieldCheck size={44} strokeWidth={1.5} />{:else}<ShieldAlert size={44} strokeWidth={1.5} />{/if}
          </div>
        </div>
        <div class="min-w-0">
          <h2 class="text-heading-32">{tr(h.title, h.vars)}</h2>
          <p class="mt-2 text-copy-14 text-gray-900">{tr(h.body, h.vars)}</p>
          {#if h.partial}<p class="mt-1 text-copy-14 text-amber-900">{tr(h.partial)}</p>{/if}
        </div>
      </div>
    </section>

    <!-- three friendly tiles -->
    <section class="grid grid-cols-3 gap-3 max-sm:grid-cols-1">
      <button class="card flex flex-col gap-1 p-5 text-left transition-transform hover:-translate-y-0.5" onclick={() => go("findings", { severity: null, query: "" })}>
        <span class="grid size-9 place-items-center rounded-xl bg-amber-100 text-amber-900"><ListChecks size={18} /></span>
        <span class="mt-2 text-display text-[30px] leading-[34px]">{look}</span>
        <span class="text-copy-13 text-gray-900">{look === 1 ? tr("thing worth a look") : tr("things worth a look")}</span>
      </button>
      <button class="card flex flex-col gap-1 p-5 text-left transition-transform hover:-translate-y-0.5" onclick={() => go("collectors")}>
        <span class="grid size-9 place-items-center rounded-xl bg-green-100 text-green-900"><Eye size={18} /></span>
        <span class="mt-2 text-display text-[30px] leading-[34px]">{coll.ok}<span class="text-heading-16 text-gray-700"> / {coll.total}</span></span>
        <span class="text-copy-13 text-gray-900">{tr("checks are up to date")}</span>
      </button>
      <button class="card flex flex-col gap-1 p-5 text-left transition-transform hover:-translate-y-0.5" onclick={() => go("review")}>
        <span class="grid size-9 place-items-center rounded-xl bg-blue-100 text-blue-900"><MessageCircle size={18} /></span>
        <span class="mt-2 text-display text-[30px] leading-[34px]">{waiting}</span>
        <span class="text-copy-13 text-gray-900">{waiting === 1 ? tr("question is waiting for you") : tr("questions are waiting for you")}</span>
      </button>
    </section>

    {#if top.length}
      <section>
        <h3 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Worth a look first")}</h3>
        <div class="flex flex-col gap-2">
          {#each top as f, i}
            <button class="card row-click flex w-full items-start gap-4 p-4 text-left transition-transform hover:-translate-y-0.5 anim-rise"
                    style:animation-delay="{i * 60}ms"
                    onclick={() => { go("findings", { query: "", severity: null }); app.selected = f; }}>
              <Pill severity={f.severity} />
              <span class="min-w-0 flex-1">
                {#if hasGuide(f)}
                  <span class="block text-label-14">{tr(plainFinding(f).means)}</span>
                  <span class="mt-0.5 block text-copy-13 text-gray-900">{tr(plainFinding(f).next)}</span>
                {:else}
                  <span class="block text-label-14">{f.title}</span>
                {/if}
              </span>
              <ChevronRight size={16} class="mt-1 shrink-0 text-gray-700" />
            </button>
          {/each}
        </div>
      </section>
    {/if}

    <ProtectionCard />

    {#if phones !== null}
      <button class="card flex items-center gap-4 p-5 text-left transition-colors hover:bg-gray-100" onclick={() => go("phone")}>
        <span class="grid size-10 place-items-center rounded-xl {phones ? 'bg-green-100 text-green-900' : 'bg-blue-100 text-blue-900'}"><Smartphone size={20} /></span>
        <span class="flex-1">
          <span class="block text-label-14">{phones ? (phones === 1 ? tr("Your phone gets alerts") : tr("{n} phones get alerts", { n: phones })) : tr("Get alerts on your phone")}</span>
        </span>
        <ChevronRight size={16} class="text-gray-700" />
      </button>
    {/if}

    <button class="card flex items-center gap-4 p-5 text-left transition-colors hover:bg-gray-100" onclick={() => go("assistant")}>
      <span class="grid size-10 place-items-center rounded-xl bg-blue-100 text-blue-900"><Sparkles size={20} /></span>
      <span class="flex-1">
        <span class="block text-label-14">{tr("Not sure what something means?")}</span>
      </span>
      <ChevronRight size={16} class="text-gray-700" />
    </button>
  </div>
{/if}
