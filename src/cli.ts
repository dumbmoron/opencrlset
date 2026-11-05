#!/usr/bin/env node
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { parseArgs } from "node:util";
import { build } from "./build.ts";
import { STORES } from "./ccadb.ts";
import { componentId, crlSetArchive, packageTier, type ComponentIndex } from "./component.ts";
import { verifyCrx } from "./crx.ts";
import { checkSerial, parseCrlSet } from "./crlset.ts";
import { fetchGoogleCrlSet } from "./google.ts";
import { fetchText } from "./net.ts";
import { TIERS } from "./policy.ts";
import { errorMessage, snapshot } from "./snapshot.ts";
import { cupKey, serve } from "./update-server.ts";
import { sha256, sha256Hex } from "./x509.ts";

const DEFAULT_OVERRIDES = join(import.meta.dirname, "..", "policy", "overrides.json");

const USAGE = `usage: opencrlset <command> [options]

  snapshot <dir> [--concurrency N] [--per-host N]
      fetch CCADB reports and every disclosed CRL into <dir>
  build <snapshot-dir> <out-dir> [--google crl-set] [--previous crl-set] [--overrides file] [--store chrome]
      validate the snapshot and write CRLSets, the dataset, reports and explorer data
      (offline, deterministic; --previous only adds report.json's changes and explorer/ flags)
  fetch-google <dir> [--lowmem]
      download the official CRLSet for comparison
  dump <crl-set> [--json]
      print a CRLSet's header and parents
  check <crl-set> <issuer-spki-sha256> <serial-hex>
      look up one serial, like CRLSet::CheckSerial
  compare <a> <b>
      diff two CRLSet files
  checksums <dir>
      write <dir>/SHA256SUMS for every file below <dir>, except explorer/
  history <report.json> <previous-history-url>
      print history.json: the previous builds' summaries plus this one
  index <dir>
      print latest.json for a finished build directory (after checksums)
  gate <report.json> <previous-report-url> [--max-drop 0.25]
      fail if the standard tier shrank suspiciously compared to the last build

  crx <build-dir> <out-dir> --key key.pem [--tier T]... [--previous-crx dir] [--puffin path]
      package each tier as a signed CRX3 for the CRLSet component, with an index
      (<tier>.json) and, given puffin, patches from the <tier>.crx3 files below --previous-crx
  crx-id <key.pem>
      print the component ID and kCrlSetPublicKeySHA256 for a signing key
  crx-verify <file.crx3> [--key-hash hex] [--files <build-dir>/crlset/<tier>]
      check a CRX's signatures, and with --files that it holds exactly those files
  serve <public-url> [--tier standard] [--port 8080] [--cup-key version=key.pem]...
      reference update server for the CRLSet component, answering from the
      newest build's crx/<tier>.json; with CUP keys (ML-DSA-44 or ECDSA P-256),
      it signs responses to requests that ask

See docs/integration.md.
`;

const log = (message: string) => console.error(message);

// one build's line in history.json
interface HistoryEntry {
  sequence: number;
  snapshotTime: string;
  standard: number;
  priority: number;
  all: number;
  crlsValid: number;
  crlsDisclosed: number;
  googleSequence?: number;
  googleSerials?: number;
  googleShared?: number;
}

async function main(argv: string[]) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      concurrency: { type: "string", default: "48" },
      "per-host": { type: "string", default: "6" },
      google: { type: "string" },
      previous: { type: "string" },
      overrides: { type: "string", default: DEFAULT_OVERRIDES },
      store: { type: "string", default: "chrome" },
      lowmem: { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      "max-drop": { type: "string", default: "0.25" },
      key: { type: "string" },
      tier: { type: "string", multiple: true },
      "previous-crx": { type: "string" },
      puffin: { type: "string" },
      "key-hash": { type: "string" },
      files: { type: "string" },
      port: { type: "string", default: "8080" },
      "cup-key": { type: "string", multiple: true },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  const [command, ...args] = positionals;

  const need = (count: number) => {
    if (args.length !== count) throw new UsageError();

    return args;
  };

  if (values.help || !command) {
    console.log(USAGE);

    return;
  }

  switch (command) {
    case "snapshot": {
      const [dir] = need(1);
      await snapshot(dir!, {
        concurrency: Number(values.concurrency),
        perHost: Number(values["per-host"]),
        log,
      });
      break;
    }

    case "build": {
      const [snapshotDir, outDir] = need(2);

      const store = STORES.find((name) => name === values.store);

      if (!store) throw new Error(`unknown store ${values.store}`);

      const report = await build(snapshotDir!, outDir!, {
        google: values.google,
        previous: values.previous,
        overrides: values.overrides,
        store,
        log,
      });

      const { google, ...summary } = report;
      console.log(
        JSON.stringify(
          {
            ...summary,
            crlErrors: undefined,
            google: google && { ...google, perIssuer: undefined, unknownIssuers: undefined },
          },
          null,
          2,
        ),
      );
      break;
    }

    case "fetch-google": {
      const [dir] = need(1);
      const result = await fetchGoogleCrlSet(dir!, values.lowmem);
      console.log(`version ${result.version} (${result.sha256})`);
      break;
    }

    case "dump": {
      const [path] = need(1);
      const set = parseCrlSet(await readFile(path!));
      // the header as written, not just the fields Chromium reads
      const header = JSON.parse(set.json);

      if (values.json) {
        console.log(JSON.stringify({ header, parents: Object.fromEntries(set.parents) }, null, 1));
        break;
      }

      console.log(JSON.stringify(header, null, 2));

      for (const [spki, serials] of set.parents) {
        console.log(`${spki} ${serials.length}`);
      }

      break;
    }

    case "check": {
      const [path, spki, serial] = need(3);
      const set = parseCrlSet(await readFile(path!));
      console.log(
        checkSerial(set, spki!.toLowerCase(), Buffer.from(serial!.replace(/[:\s]/g, ""), "hex")),
      );
      break;
    }

    case "compare": {
      const [a, b] = need(2);
      const left = parseCrlSet(await readFile(a!));
      const right = parseCrlSet(await readFile(b!));
      let shared = 0;
      let leftOnly = 0;
      let rightOnly = 0;
      const parents = new Set([...left.parents.keys(), ...right.parents.keys()]);
      const rows: string[] = [];

      for (const spki of [...parents].sort()) {
        const l = new Set(left.parents.get(spki) ?? []);
        const r = new Set(right.parents.get(spki) ?? []);
        let both = 0;

        for (const serial of l) if (r.has(serial)) both++;
        shared += both;
        leftOnly += l.size - both;
        rightOnly += r.size - both;

        if (l.size !== both || r.size !== both)
          rows.push(`${spki} shared=${both} a-only=${l.size - both} b-only=${r.size - both}`);
      }

      console.log(rows.join("\n"));
      console.log(
        `parents: a=${left.parents.size} b=${right.parents.size}; serials: shared=${shared} a-only=${leftOnly} b-only=${rightOnly}`,
      );
      break;
    }

    case "checksums": {
      const [dir] = need(1);

      const files = (await readdir(dir!, { recursive: true, withFileTypes: true }))
        .filter((entry) => entry.isFile())
        .map((entry) => relative(dir!, join(entry.parentPath, entry.name)))
        // explorer/ is derived, regenerated for every build, and not archived
        .filter((path) => path !== "SHA256SUMS" && !path.startsWith("explorer/"))
        .sort();

      const lines: string[] = [];

      for (const path of files)
        lines.push(`${sha256Hex(await readFile(join(dir!, path)))}  ${path}\n`);
      await writeFile(join(dir!, "SHA256SUMS"), lines.join(""));
      break;
    }

    case "index": {
      const [dir] = need(1);
      const report = JSON.parse(await readFile(join(dir!, "report.json"), "utf8"));
      const files: Record<string, string> = {};

      for (const line of (await readFile(join(dir!, "SHA256SUMS"), "utf8")).trim().split("\n")) {
        const [hash, path] = line.split("  ");
        files[path!] = hash!;
      }

      const index = {
        sequence: report.sequence,
        snapshotTime: report.snapshotTime,
        notAfter: report.notAfter,
        path: `builds/${report.sequence}/`,
        sha256sums: sha256Hex(await readFile(join(dir!, "SHA256SUMS"))),
        tiers: report.tiers,
        files,
      };

      console.log(JSON.stringify(index, null, 1));
      break;
    }

    case "history": {
      const [reportPath, previousUrl] = need(2);
      const report = JSON.parse(await readFile(reportPath!, "utf8"));
      let history: HistoryEntry[] = [];

      try {
        history = JSON.parse(await fetchText(previousUrl!));
      } catch (error) {
        log(`no previous history (${errorMessage(error)}), starting a new one`);
      }

      history = history.filter((b) => b.sequence !== report.sequence);
      history.push({
        sequence: report.sequence,
        snapshotTime: report.snapshotTime,
        standard: report.tiers.standard.serials,
        priority: report.tiers.priority.serials,
        all: report.tiers.all.serials,
        crlsValid: report.crls.valid,
        crlsDisclosed: report.crls.disclosed,
        googleSequence: report.google?.sequence,
        googleSerials: report.google?.serials,
        googleShared: report.google?.shared,
      });
      console.log(JSON.stringify(history.slice(-1000)));
      break;
    }

    case "gate": {
      const [reportPath, previousUrl] = need(2);
      const current = JSON.parse(await readFile(reportPath!, "utf8"));
      let previous;

      try {
        previous = JSON.parse(await fetchText(previousUrl!));
      } catch (error) {
        log(`no previous report (${errorMessage(error)}), skipping gate`);
        break;
      }

      const maxDrop = Number(values["max-drop"]);

      for (const key of ["parents", "serials"] as const) {
        const before = previous.tiers?.standard?.[key] ?? 0;
        const after = current.tiers.standard[key];
        log(`standard ${key}: ${before} -> ${after}`);

        if (before > 0 && after < before * (1 - maxDrop)) {
          throw new Error(`standard tier ${key} dropped from ${before} to ${after}`);
        }
      }

      break;
    }

    case "crx": {
      const [buildDir, outDir] = need(2);

      if (!values.key) throw new UsageError();
      const key = createPrivateKey(await readFile(values.key));
      const tiers = values.tier ?? [...TIERS];

      const previous = values["previous-crx"]
        ? (await readdir(values["previous-crx"], { recursive: true, withFileTypes: true })).filter(
            (entry) => entry.isFile(),
          )
        : [];

      for (const tier of tiers) {
        const earlier = await Promise.all(
          previous
            .filter((entry) => entry.name === `${tier}.crx3`)
            .map((entry) => readFile(join(entry.parentPath, entry.name))),
        );

        const index = await packageTier(join(buildDir!, "crlset", tier), tier, outDir!, {
          key,
          previous: earlier,
          puffin: values.puffin,
          log,
        });

        log(
          `${tier}: ${index.appid} ${index.version}, ${index.crx.size} bytes, ${Object.keys(index.patches).length} patches`,
        );
      }

      break;
    }

    case "crx-id": {
      const [keyPath] = need(1);
      const key = createPrivateKey(await readFile(keyPath!));
      const spki = createPublicKey(key).export({ type: "spki", format: "der" });
      const bytes = [...sha256(spki)].map((b) => `0x${b.toString(16).padStart(2, "0")}`);
      console.log(`component ID: ${componentId(key)}`);
      console.log(
        `kCrlSetPublicKeySHA256 = {\n    ${bytes.slice(0, 11).join(", ")},\n    ${bytes.slice(11, 22).join(", ")},\n    ${bytes.slice(22).join(", ")},\n};`,
      );
      break;
    }

    case "crx-verify": {
      const [path] = need(1);
      const required = values["key-hash"] ? [Buffer.from(values["key-hash"], "hex")] : [];
      const { id, archive } = verifyCrx(await readFile(path!), required);

      if (values.files && !(await crlSetArchive(values.files)).archive.equals(archive)) {
        throw new Error(`${path}: archive differs from the one ${values.files} packages to`);
      }

      console.log(`${id} ok${values.files ? ", archive matches" : ""}`);
      break;
    }

    case "serve": {
      const [publicUrl] = need(1);
      const root = new URL(publicUrl!.endsWith("/") ? publicUrl! : `${publicUrl}/`);
      const tier = values.tier?.[0] ?? "standard";
      const cupKeys: Record<string, CryptoKey> = {};

      for (const entry of values["cup-key"] ?? []) {
        const [version, path] = entry.split(/=(.*)/s);

        if (!version || !path || !/^\d+$/.test(version))
          throw new Error(`--cup-key ${entry}: expected <version>=<key.pem>`);
        const [keyId, key] = cupKey(Number(version), createPrivateKey(await readFile(path)));
        cupKeys[keyId] = key;
      }

      serve({
        load: async () => {
          // latest.json points to the newest build, whose files never change
          const latest: { path?: unknown } = JSON.parse(
            await fetchText(new URL("latest.json", root).href),
          );

          if (typeof latest.path !== "string") throw new Error("latest.json has no path");

          const base = new URL(`${latest.path}crx/${tier}.json`, root);
          const index: ComponentIndex = JSON.parse(await fetchText(base.href));

          if (index.format !== 1) throw new Error(`${base.href}: unsupported format`);

          return new Map([[index.appid, { index, base }]]);
        },
        cupKeys,
        port: Number(values.port),
        log,
      });

      return;
    }

    default:
      throw new UsageError();
  }
}

class UsageError extends Error {}

main(process.argv.slice(2)).catch((error) => {
  if (error instanceof UsageError) {
    console.error(USAGE);
    process.exit(2);
  }

  console.error(error);
  process.exit(1);
});
