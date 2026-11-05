<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import { Button, Input, Spinner } from "@imput/helium-prism";
  import { buildUrl } from "#lib/data.ts";
  import { TIERS, reasonName, tierStatus } from "#lib/explain.ts";
  import { bytes, date, epoch, num } from "#lib/format.ts";
  import { lookup } from "#lib/lookup.ts";
  import ExternalLink from "#lib/components/ExternalLink.svelte";
  import Hash from "#lib/components/Hash.svelte";
  import IssuerLink from "#lib/components/IssuerLink.svelte";
  import type { PageProps } from "./$types";

  let { data }: PageProps = $props();
  let meta = $derived(data.meta);

  // a serial goes in the URL (#/?q=…); a pasted certificate stays on the page
  let urlQuery = $derived(new URLSearchParams(page.url.hash.split("?")[1] ?? "").get("q") ?? "");
  let pasted = $state<string | null>(null);
  let query = $derived(pasted ?? urlQuery);

  // svelte-ignore state_referenced_locally
  let input = $state(urlQuery);
  let result = $derived(query ? lookup(meta, query) : undefined);

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const value = input.trim();

    if (value.includes("BEGIN CERTIFICATE")) {
      pasted = value;
    } else {
      pasted = null;
      goto(resolve(`/?q=${encodeURIComponent(value)}`));
    }
  }
</script>

<form onsubmit={submit}>
  <Input bind:value={input} aria-label="Serial or PEM certificate" placeholder="Serial (hex) or PEM certificate" />
  <Button primary type="submit">Look up</Button>
</form>

{#if result}
  {#await result}
    <Spinner size={20} />
  {:then { serial, matches, candidates }}
    {#if candidates && !candidates.length}
      <p class="error">Issuer not in the CCADB data, so this can't be checked.</p>
    {:else if !matches.length}
      <p>Serial <span class="mono">{serial}</span> isn't on any fetched CRL or in Google's CRLSet.</p>
    {:else}
      <div class="table">
        <table>
          <thead>
            <tr>
              <th>Issuer</th>
              <th>Reason</th>
              <th>Revoked</th>
              <th>Source</th>
              {#each TIERS as tier (tier)}<th>{tier}</th>{/each}
              <th>Google</th>
            </tr>
          </thead>
          <tbody>
            {#each matches as { record, summary, detail } (`${record.issuer}/${record.serial}`)}
              {@const crl = record.crl >= 0 ? detail?.crls[record.crl] : undefined}
              <tr>
                <td>
                  {#if summary}<IssuerLink spki={summary.spki} name={summary.name} />{:else}<Hash value={String(record.issuer)} />{/if}
                  <div class="muted">{record.ca ? "CA certificate" : "leaf"}</div>
                  {#if summary && meta.blockedKeys.some((key) => key.issuer === summary.spki && key.serial === record.serial)}
                    <div class="error">its key is blocked in every tier</div>
                  {/if}
                </td>
                <td>{record.googleOnly ? "–" : reasonName(record.reason)}</td>
                <td>{epoch(record.revoked)}</td>
                <td>
                  {#if crl}
                    {#each crl.sources as source (source.url)}<div><ExternalLink href={source.url} /></div>{/each}
                    <div class="muted">
                      issued {date(crl.sources[0]?.thisUpdate)}{#if crl.sources[0]?.crlNumber}, #{crl.sources[0].crlNumber}{/if}
                    </div>
                  {:else if record.googleOnly}
                    <span class="muted">no fetched CRL</span>
                  {:else}
                    <span class="muted">CCADB only</span>
                  {/if}
                </td>
                {#each TIERS as tier (tier)}
                  {@const status = tierStatus(tier, record, detail?.inScope ?? false, meta)}
                  <td>
                    {#if status.included}<span class="yes">yes</span>{:else}<span class="muted">{status.why ?? "no"}</span>{/if}
                    {#if status.disagrees}<div class="error">build disagrees</div>{/if}
                  </td>
                {/each}
                <td>{#if record.google}<span class="yes">yes</span>{:else}<span class="muted">no</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {:catch error}
    <p class="error">{error.message}</p>
  {/await}
{/if}

<h2>Downloads</h2>
<div class="table">
  <table>
    <thead>
      <tr><th>Tier</th><th class="num">Serials</th><th class="num">Issuers</th><th class="num">Size</th><th>Files</th></tr>
    </thead>
    <tbody>
      {#each TIERS as tier (tier)}
        <tr>
          <td>{tier}</td>
          <td class="num">{num(meta.tiers[tier].serials)}</td>
          <td class="num">{num(meta.tiers[tier].parents)}</td>
          <td class="num">{bytes(meta.tiers[tier].bytes)}</td>
          <td>
            <a href={buildUrl(meta.sequence, `crlset/${tier}/crl-set`)}>crl-set</a>
            <a href={buildUrl(meta.sequence, `crlset/${tier}/manifest.json`)}>manifest.json</a>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
<p class="files">
  <a href={buildUrl(meta.sequence, "revocations.ndjson.zst")}>revocations.ndjson.zst</a>
  <a href={buildUrl(meta.sequence, "report.json")}>report.json</a>
  <a href={buildUrl(meta.sequence, "snapshot.tar.zst")}>snapshot.tar.zst</a>
  <a href={buildUrl(meta.sequence, "SHA256SUMS")}>SHA256SUMS</a>
</p>

<style>
  form {
    display: flex;
    gap: 8px;
  }

  form :global(.input-field) {
    flex: 1;
  }

  form :global(button) {
    white-space: nowrap;
  }

  td a + a {
    margin-left: 12px;
  }

  .files {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
  }

  td {
    white-space: nowrap;
  }

  .yes {
    color: var(--good);
  }
</style>
