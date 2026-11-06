<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { api, type Billing } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  let b = $state<Billing | null>(null);
  let err = $state("");
  let busy = $state<"" | "month" | "year">("");
  let waiting = $state(false);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    try { b = await api.billingStatus(); err = ""; if (b.licensed) stopWaiting(); }
    catch (e) { err = String((e as Error).message ?? e); }
  }
  function stopWaiting() { waiting = false; clearInterval(timer); }

  async function subscribe(plan: "month" | "year") {
    busy = plan;
    try {
      await api.billingCheckout(plan);
      toast(tr("Checkout opened in your browser"), "ok");
      // The browser tab confirms the payment with Stripe; this window just watches for the licence.
      waiting = true; clearInterval(timer);
      let n = 0; timer = setInterval(() => { load(); if (++n > 120) stopWaiting(); }, 5000);
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = ""; }
  }
  onMount(load);
  onDestroy(() => clearInterval(timer));
  const until = $derived(b?.expires ? new Date(b.expires * 1000).toLocaleDateString(app.lang) : "");
  const monthly = $derived(b?.plans?.month ?? 15);
  const yearly = $derived(b?.plans?.year ?? b?.price_usd ?? 79);
  const saving = $derived(monthly * 12 - yearly);
  const features = [
    "Continuous monitoring of this computer",
    "Plain-language assistant",
    "Investigate any finding with one click",
    "Approvals, reports and daily briefing",
  ];
</script>

<div class="mx-auto flex max-w-[760px] flex-col gap-6">
  <div>
    <h2 class="text-heading-24">{tr("Pricing")}</h2>
    <p class="mt-1 text-copy-14 text-gray-900">{tr("Pay monthly or save with a year. Your data stays on this computer, and protection works the same with or without a licence.")}</p>
  </div>

  {#if err}
    <p class="text-copy-13 text-amber-900">{err}</p>
  {:else if b?.licensed}
    <div class="card p-6">
      <div class="flex items-center gap-2">
        <h3 class="text-heading-20">{b.plan === "month" ? tr("ARGUS-INSTINCT Monthly") : tr("ARGUS-INSTINCT Yearly")}</h3>
        <span class="pill pill-ok">{tr("Licensed")}</span>
      </div>
      <p class="mt-3 text-copy-14">{tr("Active")}{b.email ? ` · ${b.email}` : ""}{until ? ` · ${tr("until {date}", { date: until })}` : ""}</p>
    </div>
  {:else}
    <div class="grid grid-cols-2 gap-4 max-md:grid-cols-1">
      {#each [["month", monthly, tr("per month"), tr("Subscribe — ${price}/month", { price: monthly }), false], ["year", yearly, tr("per year"), tr("Subscribe — ${price}/year", { price: yearly }), true]] as [plan, amount, per, label, best] (plan)}
        <div class="card flex flex-col p-6 {best ? 'ring-2 ring-blue-700' : ''}">
          <div class="flex items-center gap-2">
            <h3 class="text-heading-20">{plan === "month" ? tr("ARGUS-INSTINCT Monthly") : tr("ARGUS-INSTINCT Yearly")}</h3>
            {#if best}<span class="pill pill-ok">{tr("Best value")}</span>{/if}
          </div>
          <p class="mt-3 text-heading-32 tabular">${amount}<span class="ml-1.5 text-copy-14 text-gray-900">{per}</span></p>
          <p class="mt-1 h-5 text-copy-13 text-gray-900">{best && saving > 0 ? tr("Save ${amount} a year compared with paying monthly", { amount: saving }) : ""}</p>
          <ul class="mt-4 flex flex-col gap-1.5 text-copy-14">
            {#each features as f}<li>{tr(f)}</li>{/each}
            <li>{plan === "month" ? tr("Cancel any time; renews monthly") : tr("Cancel any time; renews yearly")}</li>
          </ul>
          <div class="mt-auto pt-6">
            {#if b && !b.can_purchase}
              {#if app.mode === "simple"}
                <p class="text-copy-14 text-gray-900">{tr("Buying a licence is not switched on yet. It will be available here soon.")}</p>
              {:else}
                <p class="text-copy-13 text-gray-900">{tr("Stripe is not configured on this computer. Add STRIPE_SECRET_KEY to ~/.jarvis/billing.env (see docs/STRIPE-HANDOFF.md).")} <button class="link" onclick={load}>{tr("Check again")}</button></p>
              {/if}
            {:else}
              <button class="btn {best ? 'btn-primary' : ''} h-10 px-5" disabled={!!busy || !b} onclick={() => subscribe(plan as "month" | "year")}>{label}</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
    {#if waiting}<p class="text-copy-13 text-gray-900" role="status"><span class="dot dot-run mr-2"></span>{tr("Waiting for payment to complete in your browser…")} <button class="link" onclick={load}>{tr("I have paid, check now")}</button></p>{/if}
  {/if}

  <p class="text-copy-13 text-gray-900">{tr("Payment is handled by Stripe in your browser. ARGUS-INSTINCT never sees or stores your card details.")}</p>
</div>
