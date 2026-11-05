<script lang="ts">
  import "@fontsource-variable/instrument-sans/wdth.css";
  import "@imput/helium-prism/styles.css";
  import "../app.css";

  import { resolve } from "$app/paths";
  import { REPOSITORY } from "#lib/data.ts";
  import { ago } from "#lib/format.ts";
  import type { LayoutProps } from "./$types";

  let { data, children }: LayoutProps = $props();
</script>

<svelte:head>
  <title>opencrlset</title>
</svelte:head>

<header>
  <a class="brand" href={resolve("/")}>opencrlset</a>
  <span class="muted">build {data.meta.sequence} · {ago(data.meta.snapshotTime)}</span>
  <a class="source" href={REPOSITORY}>source</a>
</header>

<main>
  {@render children()}
</main>

<style>
  header,
  main {
    max-width: 1100px;
    margin: 0 auto;
    padding: 16px;
  }

  header {
    display: flex;
    align-items: baseline;
    gap: 12px;
  }

  .brand {
    font-size: 17px;
    font-weight: 600;
    color: var(--primary);
    text-decoration: none;
  }

  .source {
    margin-left: auto;
  }
</style>
