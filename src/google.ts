import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { unzipSync } from "fflate";
import { verifyCrx } from "./crx.ts";
import { download, fetchText } from "./net.ts";

export const CRLSET_COMPONENT_ID = "hfnkpimlhhgieaddgfemjhofmfblmnib";

// kCrlSetPublicKeySHA256 in chrome/browser/component_updater/crl_set_component_installer.cc
export const CRLSET_PUBLIC_KEY_SHA256 = Buffer.from(
  "75daf8cb77684033654c97e5c51bcd817b1eeb112ce1a4338cf5725eedb84397",
  "hex",
);

// The same legacy update protocol query agl/crlset-tools uses. Without
// `tag=force_full` the server answers with the smaller "androidlowmem" set.
export function updateUrl(lowmem = false) {
  const x = encodeURIComponent(`id=${CRLSET_COMPONENT_ID}&v=&uc&acceptformat=crx3`);

  return `https://clients2.google.com/service/update2/crx?x=${x}${lowmem ? "" : "&tag=force_full"}`;
}

export interface GoogleCrlSet {
  version: string;
  crx: string;
  sha256: string;
}

export async function fetchGoogleCrlSet(dir: string, lowmem = false): Promise<GoogleCrlSet> {
  await mkdir(dir, { recursive: true });
  const response = await fetchText(updateUrl(lowmem));
  const updatecheck = response.match(/<updatecheck\b[^>]*>/)?.[0] ?? "";
  const attribute = (name: string) => updatecheck.match(new RegExp(`\\s${name}="([^"]+)"`))?.[1];
  const codebase = attribute("codebase");
  const expected = attribute("hash_sha256");
  const version = attribute("version");

  if (!codebase || !expected || !version) {
    throw new Error(`unexpected update response: ${response.slice(0, 500)}`);
  }

  const result = await download(codebase.replace(/^http:/, "https:"), dir, { suffix: ".crx3" });

  if (result.sha256 !== expected.toLowerCase()) {
    throw new Error(`CRX hash mismatch: expected ${expected}, got ${result.sha256}`);
  }

  const crxPath = join(dir, `${CRLSET_COMPONENT_ID}_${version}.crx3`);
  await rename(result.path, crxPath);

  // signed with the key Chrome requires for this component
  const { archive } = verifyCrx(await readFile(crxPath), [CRLSET_PUBLIC_KEY_SHA256]);

  const files = unzipSync(archive, {
    filter: (file) => file.name === "crl-set" || file.name === "manifest.json",
  });

  if (!files["crl-set"]) throw new Error("CRX has no crl-set");
  await writeFile(join(dir, "crl-set"), files["crl-set"]);

  if (files["manifest.json"]) await writeFile(join(dir, "manifest.json"), files["manifest.json"]);
  await writeFile(
    join(dir, "source.json"),
    JSON.stringify({ version, codebase, sha256: result.sha256, lowmem }, null, 2) + "\n",
  );

  return { version, crx: crxPath, sha256: result.sha256 };
}
