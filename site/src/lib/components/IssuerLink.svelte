<script lang="ts">
  import { resolve } from "$app/paths";

  let { spki, name }: { spki: string; name?: string } = $props();
</script>

<a href={resolve("/issuers/[spki]", { spki })}>{name || `${spki.slice(0, 16)}…`}</a>
