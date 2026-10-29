<script lang="ts">
  import Segmented from "../components/Segmented.svelte";
  import { app, setTheme, type Theme } from "../lib/store.svelte";
  const themes: [Theme, string][] = [["auto", "Automatic"], ["light", "Light"], ["dark", "Dark"]];
</script>

<div class="mx-auto flex max-w-[680px] flex-col gap-6">
  {#snippet group(title: string, rows: [string, string][])}
    <section>
      <h2 class="mb-2 px-1 text-label-13 text-gray-900">{title}</h2>
      <div class="card divide">
        {#each rows as [k, v]}<div class="row justify-between"><span class="text-label-13">{k}</span><span class="selectable text-copy-13 text-gray-900">{v}</span></div>{/each}
      </div>
    </section>
  {/snippet}

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">Appearance</h2>
    <div class="card row justify-between">
      <span class="text-label-13">Theme</span>
      <Segmented items={themes.map(([t, l]) => ({ value: t, label: l }))}
                 label="Theme" bind:value={() => app.theme, (v) => setTheme((v || app.theme) as Theme)} />
    </div>
  </section>

  {@render group("Notifications", [
    ["Critical findings", "Native notification when one appears"],
    ["Monitoring outages", "Native notification when ARGUS-1 stops answering"],
    ["Tray", "Coloured dot: green, amber, red; grey when unreachable"],
  ])}
  {@render group("How this app works", [
    ["Monitoring", "Done by the ARGUS-1 service, with or without this window"],
    ["Closing the window", "Hides it to the tray; monitoring continues"],
    ["Connection", "127.0.0.1 only, through the app's own commands"],
    ["Actions offered", "Run a collector, answer, ask, approve or reject a fix"],
  ])}
  {@render group("Shortcuts", [["Search", "Ctrl K  or  /"], ["Close a panel", "Esc"]])}
</div>
