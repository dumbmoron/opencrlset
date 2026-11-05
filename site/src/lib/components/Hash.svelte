<script lang="ts">
  // A hash or serial, shortened unless `full`, with the whole value on hover.
  let { value, length = 16, full = false }: { value: string; length?: number; full?: boolean } = $props();
</script>

<span class="mono" title={value}>{full || value.length <= length ? value : `${value.slice(0, length)}…`}</span>
