<script lang="ts">
  import { resolve } from "$app/paths";
  import { reasonName } from "#lib/explain.ts";
  import { crtsh, date, num } from "#lib/format.ts";
  import ExternalLink from "#lib/components/ExternalLink.svelte";
  import Hash from "#lib/components/Hash.svelte";
  import IssuerLink from "#lib/components/IssuerLink.svelte";
  import type { PageProps } from "./$types";

  let { data }: PageProps = $props();
  let detail = $derived(data.detail);
  let sources = $derived(detail.crls.flatMap((crl) => crl.sources.map((source) => ({ crl, source }))));
</script>

<svelte:head>
  <title>{data.summary?.name ?? "Issuer"} · opencrlset</title>
</svelte:head>

<h1>{data.summary?.name ?? "Issuer"}</h1>
<p class="muted">
  {data.summary?.owner} · trusted by {detail.trustedBy.join(", ") || "nobody"} · {detail.inScope ? "in" : "out of"}
  {data.meta.store} scope{detail.root ? " · root key" : ""}
</p>
<p>
  <Hash value={detail.spkiSha256} full /><br />
  {num(detail.revocations)} revocations · standard {num(detail.tiers.standard)} · priority {num(detail.tiers.priority)} ·
  all {num(detail.tiers.all)} · Google {num(detail.google)}
</p>
{#if data.blocked}
  {@const blocked = data.blocked}
  <p class="error">
    Key blocked in every tier: <IssuerLink spki={blocked.issuer} name={data.blockedBy?.name} /> revoked
    <a class="mono" href={resolve(`/?q=${blocked.serial}`)}>{blocked.serial}</a> for {reasonName(blocked.reason)}
  </p>
{/if}

<h2>Certificates</h2>
<div class="table">
  <table>
    <thead><tr><th>Name</th><th>Type</th><th>Trusted by</th><th>Revocation</th><th>Valid to</th></tr></thead>
    <tbody>
      {#each detail.certificates as certificate (certificate.fingerprint)}
        <tr>
          <td><ExternalLink href={crtsh(certificate.fingerprint)}>{certificate.name}</ExternalLink></td>
          <td>{certificate.type}</td>
          <td>{certificate.trustedBy.join(", ") || "–"}</td>
          <td>{certificate.revocationStatus || "–"}</td>
          <td>{certificate.validTo}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<h2>CRLs</h2>
<div class="table">
  <table>
    <thead><tr><th>URL</th><th>Issued</th><th>Next update</th><th class="num">Entries</th><th>Problem</th></tr></thead>
    <tbody>
      {#each sources as { source } (source.url)}
        <tr>
          <td><ExternalLink href={source.url} /></td>
          <td>{date(source.thisUpdate)}</td>
          <td>{date(source.nextUpdate)}</td>
          <td class="num">{num(source.entries)}</td>
          <td class="muted">{source.warnings.join(", ")}</td>
        </tr>
      {/each}
      {#each detail.failedCrls as source (source.url)}
        <tr>
          <td><ExternalLink href={source.url} /></td>
          <td>–</td>
          <td>–</td>
          <td class="num">–</td>
          <td class="error">{source.error}</td>
        </tr>
      {:else}
        {#if !sources.length}<tr><td colspan="5" class="muted">none</td></tr>{/if}
      {/each}
    </tbody>
  </table>
</div>

{#if detail.caCertificates.length}
  <h2>CA certificates it issued</h2>
  <div class="table">
    <table>
      <thead><tr><th>Serial</th><th>Name</th><th>Revocation</th></tr></thead>
      <tbody>
        {#each detail.caCertificates as certificate (certificate.serial)}
          <tr>
            <td><a class="mono" href={resolve(`/?q=${certificate.serial}`)}>{certificate.serial}</a></td>
            <td><ExternalLink href={crtsh(certificate.fingerprint)}>{certificate.name}</ExternalLink></td>
            <td>{certificate.revocationStatus || "–"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
