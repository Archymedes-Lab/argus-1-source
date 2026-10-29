<script lang="ts">
  import { api } from "../lib/api";
  import { toast } from "../lib/store.svelte";

  let q = $state("");
  let answer = $state("");
  let source = $state("");
  let busy = $state(false);
  const prompts = ["What needs me?", "What's my score?", "What changed today?"];

  async function ask(text = q) {
    if (!text.trim() || busy) return;
    busy = true; answer = ""; source = "";
    try { const r = await api.ask(text); answer = r.answer ?? r.message ?? ""; source = r.source ?? ""; }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  async function coach() {
    busy = true; answer = ""; source = "";
    try { const r = await api.scoreCoach(); answer = r.answer ?? ""; source = "score plan · deterministic"; }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

<div class="mx-auto flex max-w-[760px] flex-col gap-4">
  <div>
    <h2 class="text-heading-24">Ask ARGUS-1</h2>
    <p class="mt-1 text-copy-14 text-gray-900">Answers come from ARGUS-1's own data and a local model. It reads; it never acts on what it says.</p>
  </div>
  <form class="card flex items-center gap-2 p-2" onsubmit={(e) => { e.preventDefault(); ask(); }}>
    <input class="input input-bare h-10 flex-1 text-copy-14" bind:value={q} maxlength="4000" placeholder="Ask anything about this machine" aria-label="Question" />
    <button class="btn btn-primary h-10 px-4" disabled={busy || !q.trim()}>Ask</button>
  </form>
  <div class="flex flex-wrap gap-2">
    {#each prompts as p}<button class="btn btn-sm" disabled={busy} onclick={() => { q = p; ask(p); }}>{p}</button>{/each}
    <button class="btn btn-sm" disabled={busy} onclick={coach}>How do I raise my score?</button>
  </div>
  {#if busy}
    <div class="card p-5 text-copy-14 text-gray-900"><span class="dot dot-run mr-2"></span>Thinking…</div>
  {:else if answer}
    <div class="card selectable anim-rise p-5">
      <p class="text-copy-14 whitespace-pre-wrap">{answer}</p>
      {#if source}<p class="mt-3 text-label-12 text-gray-700">{source}</p>{/if}
    </div>
  {/if}
</div>
