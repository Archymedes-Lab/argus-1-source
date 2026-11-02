<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { api, type Billing } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  let b = $state<Billing | null>(null);
  let err = $state("");
  let busy = $state(false);
  let waiting = $state(false);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    try { b = await api.billingStatus(); err = ""; if (b.licensed) stopWaiting(); }
    catch (e) { err = String((e as Error).message ?? e); }
  }
  function stopWaiting() { waiting = false; clearInterval(timer); }

  async function subscribe() {
    busy = true;
    try {
      await api.billingCheckout();
      toast(tr("Checkout opened in your browser"), "ok");
      // The browser tab confirms the payment with Stripe; this window just watches for the licence.
      waiting = true; clearInterval(timer);
      let n = 0; timer = setInterval(() => { load(); if (++n > 120) stopWaiting(); }, 5000);
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  onMount(load);
  onDestroy(() => clearInterval(timer));
  const until = $derived(b?.expires ? new Date(b.expires * 1000).toLocaleDateString(app.lang) : "");
  const price = $derived(b?.price_usd ?? 79);
</script>

<div class="mx-auto flex max-w-[760px] flex-col gap-6">
  <div>
    <h2 class="text-heading-24">{tr("Pricing")}</h2>
    <p class="mt-1 text-copy-14 text-gray-900">{tr("One plan. Your data stays on this computer; the licence only unlocks ARGUS-INSTINCT.")}</p>
  </div>

  <div class="card p-6">
    <div class="flex items-center gap-2">
      <h3 class="text-heading-20">{tr("ARGUS-INSTINCT Yearly")}</h3>
      {#if b?.licensed}<span class="pill pill-ok">{tr("Licensed")}</span>{:else if b}<span class="pill pill-low">{tr("Not licensed")}</span>{/if}
    </div>
    <p class="mt-3 text-heading-32 tabular">${price}<span class="ml-1.5 text-copy-14 text-gray-900">{tr("per year")}</span></p>
    <ul class="mt-4 flex flex-col gap-1.5 text-copy-14">
      <li>{tr("Continuous monitoring of this computer")}</li>
      <li>{tr("Plain-language assistant")}</li>
      <li>{tr("Investigate any finding with one click")}</li>
      <li>{tr("Approvals, reports and daily briefing")}</li>
      <li>{tr("Cancel any time; renews yearly")}</li>
    </ul>

    <div class="mt-6">
      {#if err}
        <p class="text-copy-13 text-amber-900">{err}</p>
      {:else if b?.licensed}
        <p class="text-copy-14">{tr("Active")}{b.email ? ` · ${b.email}` : ""}{until ? ` · ${tr("until {date}", { date: until })}` : ""}</p>
      {:else if b && !b.can_purchase}
        {#if app.mode === "simple"}
          <p class="text-copy-14 text-gray-900">{tr("Buying a licence is not switched on yet. It will be available here soon.")}</p>
        {:else}
          <p class="text-copy-13 text-gray-900">{tr("Stripe is not configured on this computer. Add STRIPE_SECRET_KEY to ~/.jarvis/billing.env (see docs/STRIPE-HANDOFF.md).")} <button class="link" onclick={load}>{tr("Check again")}</button></p>
        {/if}
      {:else}
        <button class="btn btn-primary h-10 px-5" disabled={busy || !b} onclick={subscribe}>{tr("Subscribe — ${price}/year", { price })}</button>
        {#if waiting}<p class="mt-3 text-copy-13 text-gray-900" role="status"><span class="dot dot-run mr-2"></span>{tr("Waiting for payment to complete in your browser…")} <button class="link" onclick={load}>{tr("I have paid, check now")}</button></p>{/if}
      {/if}
    </div>
  </div>

  <p class="text-copy-13 text-gray-900">{tr("Payment is handled by Stripe in your browser. ARGUS-INSTINCT never sees or stores your card details.")}</p>
  {#if b?.required && !b.licensed}<p class="text-copy-13 text-amber-900">{tr("This build asks for a licence before the assistant and checks can be used.")}</p>{/if}
</div>
