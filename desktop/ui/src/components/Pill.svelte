<script lang="ts">
  import { sentence } from "../lib/model";
  let { severity }: { severity: string } = $props();
  const known = ["critical", "high", "medium", "low", "ok"];
</script>
<span class="pill pill-{known.includes(severity) ? severity : 'low'}">{sentence(severity)}</span>
