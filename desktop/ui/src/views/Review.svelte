<script lang="ts">
  import Pill from "../components/Pill.svelte";
  import { api } from "../lib/api";
  import { app, refresh, toast } from "../lib/store.svelte";
  import { groupQuestions } from "../lib/model";

  const groups = $derived(groupQuestions(app.data?.questions ?? []));
  const fixes = $derived((app.data?.fix ?? []) as any[]);
  let busy = $state(false);
  // A grouped question answers every item in it, so a multi-item answer asks
  // once more before it is sent. Neither answer is styled as the default.
  let pending = $state<{ prompt: string; choice: "yes" | "no" } | null>(null);
  function choose(g: { prompt: string; ids: { id: string }[] }, choice: "yes" | "no") {
    if (g.ids.length > 1 && !(pending?.prompt === g.prompt && pending.choice === choice)) { pending = { prompt: g.prompt, choice }; return; }
    pending = null; answer(g.ids, choice);
  }

  async function answer(ids: { id: string }[], choice: "yes" | "no") {
    busy = true;
    try {
      for (const q of ids) await api.answer(q.id, choice);
      toast(ids.length > 1 ? `Answer recorded for ${ids.length} questions` : "Answer recorded", "ok");
      await refresh();
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  async function decide(id: string, d: "approve" | "retry" | "reject") {
    busy = true;
    try { const r = await api.decideFix(id, d); toast(r.message ?? "Decision recorded", "ok"); await refresh(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

<div class="flex flex-col gap-8">
  <section>
    <h2 class="mb-1 text-heading-20">Questions</h2>
    <p class="mb-4 text-copy-13 text-gray-900">Your answer tells ARGUS-1 whether something is expected on this machine. It records intent; it changes nothing on the system.</p>
    {#if !groups.length}
      <div class="card empty">No questions are waiting.</div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each groups as g (g.prompt)}
          {@const q = g.ids[0]}
          <div class="card p-5">
            <div class="flex items-center gap-2"><Pill severity={g.severity ?? "low"} />
              {#if g.ids.length > 1}<span class="text-copy-13 text-gray-900">asked about {g.ids.length} items</span>{/if}</div>
            <p class="selectable mt-2.5 text-label-14">{g.prompt}</p>
            {#if pending?.prompt === g.prompt}
              <div class="mt-4 flex flex-wrap items-center gap-2 rounded-lg bg-gray-100 px-3 py-2">
                <span class="text-copy-13">Answer <b>{pending.choice}</b> for all {g.ids.length} items?</span>
                <button class="btn btn-sm ml-auto" disabled={busy} onclick={() => choose(g, pending!.choice)}>Answer {pending.choice} for {g.ids.length}</button>
                <button class="btn btn-ghost btn-sm" onclick={() => (pending = null)}>Cancel</button>
              </div>
            {:else}
              <div class="mt-4 flex flex-wrap gap-2">
                <button class="btn" disabled={busy} onclick={() => choose(g, "yes")}>Yes{q.yes ? ` · ${q.yes}` : ""}</button>
                <button class="btn" disabled={busy} onclick={() => choose(g, "no")}>No{q.no ? ` · ${q.no}` : ""}</button>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </section>

  <section>
    <h2 class="mb-1 text-heading-20">Fix proposals</h2>
    <p class="mb-4 text-copy-13 text-gray-900">Approving starts an investigation that drafts a patch for review. Applying a patch is never done from this app.</p>
    {#if !fixes.length}
      <div class="card empty">No fix proposals.</div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each fixes as f (f.id)}
          <div class="card p-5">
            <div class="flex items-center gap-2"><span class="pill pill-info">{f.status}</span><span class="tag">{f.id}</span></div>
            <p class="selectable mt-2.5 text-label-14">{f.title}</p>
            {#if f.problem}<p class="selectable mt-1 text-copy-13 text-gray-900">{f.problem}</p>{/if}
            {#if f.generation_error}<p class="mt-1 text-copy-13 text-red-900">Draft failed: {f.generation_error}</p>{/if}
            <div class="mt-4 flex flex-wrap gap-2">
              {#if f.status === "proposed"}<button class="btn btn-primary" disabled={busy} onclick={() => decide(f.id, "approve")}>Approve investigation</button>{/if}
              {#if f.status === "draft_failed"}<button class="btn btn-primary" disabled={busy} onclick={() => decide(f.id, "retry")}>Retry draft</button>{/if}
              <button class="btn" disabled={busy} onclick={() => decide(f.id, "reject")}>Reject</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
