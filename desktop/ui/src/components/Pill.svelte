<script lang="ts">
  import { sev } from "../lib/i18n";
  let { severity }: { severity: string } = $props();
  const known = ["critical", "high", "medium", "low", "ok"];
</script>
<span class="pill pill-{known.includes(severity) ? severity : 'low'}">{sev(severity)}</span>
