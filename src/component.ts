// Packages a build's CRLSets as signed CRX3 files for Chromium's component
// updater, with Puffin patches from earlier CRXs and an index an update
// server answers from. See docs/integration.md.
//
// Our CI and integrators run the same code, so the same build and key give
// the same CRX bytes. With another key, only the CRX header differs.

import { execFile } from "node:child_process";
import { createPublicKey, type KeyObject } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { availableParallelism, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { zipSync } from "fflate";
import { crxId, packCrx, verifyCrx } from "./crx.ts";
import { Semaphore } from "./net.ts";
import { sha256Hex } from "./x509.ts";

const run = promisify(execFile);

export interface Download {
  // relative to the index file
  url: string;
  sha256: string;
  size: number;
}

// <tier>.json: what an update server needs to answer for one tier
export interface ComponentIndex {
  format: 1;
  appid: string;
  version: string;
  crx: Download;
  // patches that turn an earlier CRX into this one, by that CRX's SHA-256
  patches: Record<string, Download>;
}

// Stored, not deflated: CRLSets barely compress (they're mostly random
// serials), and patches between CRXs work on the raw bytes. The date is given
// as local fields, so the zip's DOS timestamp is the same in every time zone.
const ZIP_ENTRY = { level: 0, mtime: new Date(1980, 0, 1) } as const;

// The CRX archive for one tier: its crl-set and manifest.json, from
// <build>/crlset/<tier>/.
export async function crlSetArchive(
  tierDir: string,
): Promise<{ archive: Buffer; version: string }> {
  const [crlSet, manifest] = await Promise.all([
    readFile(join(tierDir, "crl-set")),
    readFile(join(tierDir, "manifest.json")),
  ]);

  const { version }: { version?: unknown } = JSON.parse(manifest.toString("utf8"));

  if (typeof version !== "string" || !/^\d+(\.\d+)*$/.test(version))
    throw new Error(`${tierDir}: bad manifest version`);

  const archive = zipSync({
    "crl-set": [crlSet, ZIP_ENTRY],
    "manifest.json": [manifest, ZIP_ENTRY],
  });

  return { archive: Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength), version };
}

export const componentId = (key: KeyObject) =>
  crxId(createPublicKey(key).export({ type: "spki", format: "der" }));

// Makes a patch with Chromium's puffin (third_party/puffin), and applies it
// again to check it gives exactly `to`.
export async function puffDiff(puffin: string, from: Buffer, to: Buffer): Promise<Buffer> {
  const dir = await mkdtemp(join(tmpdir(), "opencrlset-puff-"));

  try {
    const a = join(dir, "from.crx3");
    const b = join(dir, "to.crx3");
    const patch = join(dir, "patch.puff");
    const check = join(dir, "check.crx3");

    await Promise.all([writeFile(a, from), writeFile(b, to)]);
    // puffin writes puffin.log into its working directory
    const options = { cwd: dir, maxBuffer: 64 * 1024 * 1024 };
    await run(resolve(puffin), ["-puffdiff", a, b, patch], options);
    await run(resolve(puffin), ["-puffpatch", a, check, patch], options);

    if (!(await readFile(check)).equals(to))
      throw new Error("puffin patch does not reproduce the CRX");

    return await readFile(patch);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export interface PackageOptions {
  key: KeyObject;
  // earlier CRXs of this tier to make patches from
  previous?: Buffer[];
  // path to Chromium's puffin binary; without it, no patches
  puffin?: string;
  // patches made at once; each takes about 13 times the CRX's size in memory
  jobs?: number;
  log?: (message: string) => void;
}

// Writes <outDir>/<tier>.crx3, <outDir>/<tier>/<from-sha256>.puff and
// <outDir>/<tier>.json.
export async function packageTier(
  tierDir: string,
  tier: string,
  outDir: string,
  options: PackageOptions,
): Promise<ComponentIndex> {
  const { archive, version } = await crlSetArchive(tierDir);
  const crx = packCrx(archive, options.key);
  const appid = verifyCrx(crx).id;
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, `${tier}.crx3`), crx);

  const patches: ComponentIndex["patches"] = {};

  if (options.puffin) {
    const puffin = options.puffin;
    // only patch from CRXs this key signed: nothing else is in the browser's cache
    const sources = new Map<string, Buffer>();

    for (const from of options.previous ?? []) {
      let previousId: string;

      try {
        previousId = verifyCrx(from).id;
      } catch {
        continue;
      }

      if (previousId === appid && !from.equals(crx)) sources.set(sha256Hex(from), from);
    }

    if (sources.size) await mkdir(join(outDir, tier), { recursive: true });
    const limit = new Semaphore(options.jobs ?? Math.min(availableParallelism(), 4));
    await Promise.all(
      [...sources].map(([fromSha, from]) =>
        limit.run(async () => {
          options.log?.(`  ${tier}: patch from ${fromSha.slice(0, 12)}`);
          const patch = await puffDiff(puffin, from, crx);
          await writeFile(join(outDir, tier, `${fromSha}.puff`), patch);
          patches[fromSha] = {
            url: `${tier}/${fromSha}.puff`,
            sha256: sha256Hex(patch),
            size: patch.length,
          };
        }),
      ),
    );
  }

  const index: ComponentIndex = {
    format: 1,
    appid,
    version,
    crx: { url: `${tier}.crx3`, sha256: sha256Hex(crx), size: crx.length },
    patches: Object.fromEntries(Object.entries(patches).sort(([a], [b]) => (a < b ? -1 : 1))),
  };

  await writeFile(join(outDir, `${tier}.json`), JSON.stringify(index, null, 1) + "\n");

  return index;
}
