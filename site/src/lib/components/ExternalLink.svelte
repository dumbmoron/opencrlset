<script lang="ts">
  import type { Snippet } from "svelte";
  import { Link } from "@imput/helium-prism";
  import { safeUrl } from "#lib/format.ts";

  // URLs from CAs: only http(s) becomes a link
  let { href, children }: { href: string; children?: Snippet } = $props();
  let url = $derived(safeUrl(href));
</script>

{#if url}
  <Link href={url}>
    {#if children}{@render children()}{:else}{href}{/if}
  </Link>
{:else if children}
  {@render children()}
{:else}
  {href}
{/if}
