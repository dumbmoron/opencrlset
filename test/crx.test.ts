import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { componentId, crlSetArchive, packageTier, type ComponentIndex } from "../src/component.ts";
import { crxIdFromHash, packCrx, parseCrx, verifyCrx } from "../src/crx.ts";
import { encodeCrlSet } from "../src/crlset.ts";
import { CRLSET_COMPONENT_ID, CRLSET_PUBLIC_KEY_SHA256 } from "../src/google.ts";
import { cupKey, updateHandler, updateResponse, type Component } from "../src/update-server.ts";
import { sha256, sha256Hex } from "../src/x509.ts";

const work = mkdtempSync(join(tmpdir(), "opencrlset-crx-"));
const { privateKey: key, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const keyHash = sha256(publicKey.export({ type: "spki", format: "der" }));

const tierDir = (name: string, sequence: number, serials: string[]) => {
  const dir = join(work, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "crl-set"),
    encodeCrlSet({ Sequence: sequence }, new Map([["11".repeat(32), serials]])),
  );
  writeFileSync(
    join(dir, "manifest.json"),
    JSON.stringify({
      manifest_version: 2,
      name: `crl-set-${sequence}.data`,
      version: String(sequence),
    }),
  );

  return dir;
};

test("derives component IDs like Chromium", () => {
  assert.equal(crxIdFromHash(CRLSET_PUBLIC_KEY_SHA256), CRLSET_COMPONENT_ID);
});

test("signs and verifies CRX3 files deterministically", async () => {
  const { archive } = await crlSetArchive(tierDir("v1", 100, ["01"]));
  const crx = packCrx(archive, key);
  assert.deepEqual(packCrx(archive, key), crx);
  const verified = verifyCrx(crx, [keyHash]);
  assert.equal(verified.id, componentId(key));
  assert.deepEqual(verified.archive, archive);

  assert.throws(() => verifyCrx(crx, [Buffer.alloc(32)]), /required key/);
  const tampered = Buffer.from(crx);
  tampered[tampered.length - 30]! ^= 1;
  assert.throws(() => verifyCrx(tampered), /signature/);
  const { privateKey: ec } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  assert.throws(() => packCrx(archive, ec), /RSA/);
});

test("writes the same zip in every time zone, readable by another implementation", async () => {
  const dir = tierDir("tz", 100, ["01", "02"]);

  const hashes = ["UTC", "America/Los_Angeles", "Pacific/Kiritimati", "Asia/Kathmandu"].map((tz) =>
    execFileSync(
      process.execPath,
      [
        "-e",
        `import("${join(import.meta.dirname, "../src/component.ts")}").then(async (m) => process.stdout.write((await m.crlSetArchive(${JSON.stringify(dir)})).archive.toString("hex")))`,
      ],
      {
        env: { ...process.env, TZ: tz },
      },
    ).toString(),
  );

  assert.equal(new Set(hashes).size, 1);

  const { archive } = await crlSetArchive(dir);
  const zip = join(work, "tz.zip");
  writeFileSync(zip, archive);

  const python = spawnSync("python3", [
    "-I",
    "-c",
    "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); z.testzip(); print(' '.join(f'{i.filename}:{i.compress_type}:{i.date_time[0]}' for i in z.infolist()))",
    zip,
  ]);

  if (python.error) return; // no python3 here
  assert.equal(python.stdout.toString().trim(), "crl-set:0:1980 manifest.json:0:1980");
});

// Chrome's own packer (`--pack-extension`, as Brave uses) is an independent
// implementation: re-signing its archive must give back its exact file.
test(
  "matches the CRX3 files Chrome packs",
  { skip: !existsSync("/usr/bin/google-chrome") && "no google-chrome" },
  () => {
    const extension = join(work, "extension");
    mkdirSync(extension, { recursive: true });
    writeFileSync(
      join(extension, "manifest.json"),
      JSON.stringify({ manifest_version: 3, name: "test", version: "1" }),
    );
    const keyPath = join(work, "extension.pem");
    writeFileSync(keyPath, key.export({ type: "pkcs8", format: "pem" }));
    execFileSync(
      "google-chrome",
      [
        "--headless=new",
        "--no-first-run",
        `--user-data-dir=${join(work, "chrome")}`,
        `--pack-extension=${extension}`,
        `--pack-extension-key=${keyPath}`,
      ],
      { stdio: "ignore" },
    );
    const chrome = readFileSync(`${extension}.crx`);
    assert.equal(verifyCrx(chrome, [keyHash]).id, componentId(key));
    assert.deepEqual(packCrx(parseCrx(chrome).archive, key), chrome);
  },
);

test("packages a tier with an index, and patches when puffin is available", async () => {
  const out = join(work, "crx");

  const v1 = await packageTier(tierDir("p1", 100, ["01"]), "standard", join(work, "crx-v1"), {
    key,
  });

  const previous = readFileSync(join(work, "crx-v1", "standard.crx3"));
  const puffin = process.env.PUFFIN;

  const v2 = await packageTier(tierDir("p2", 200, ["01", "02"]), "standard", out, {
    key,
    previous: [previous],
    puffin,
  });

  const index: ComponentIndex = JSON.parse(readFileSync(join(out, "standard.json"), "utf8"));
  assert.deepEqual(index, v2);
  assert.equal(index.appid, componentId(key));
  assert.equal(index.version, "200");
  assert.equal(index.crx.sha256, sha256Hex(readFileSync(join(out, "standard.crx3"))));

  if (!puffin) return;
  const patch = index.patches[v1.crx.sha256];
  assert.ok(patch, "a patch from the previous CRX");
  assert.equal(sha256Hex(readFileSync(join(out, patch.url))), patch.sha256);
});

test("answers update checks", () => {
  const index: ComponentIndex = {
    format: 1,
    appid: "abc",
    version: "200",
    crx: { url: "standard.crx3", sha256: "c2", size: 10 },
    patches: { c1: { url: "standard/c1.puff", sha256: "p1", size: 2 } },
  };

  const components = new Map<string, Component>([
    ["abc", { index, base: new URL("https://cdn.test/builds/200/crx/standard.json") }],
  ]);

  const ask = (apps: unknown[]) => {
    const text = updateResponse(JSON.stringify({ request: { protocol: "4.0", apps } }), components);
    assert.ok(text.startsWith(")]}'"));

    return JSON.parse(text.slice(4)).response.apps;
  };

  assert.deepEqual(ask([{ appid: "abc", version: "200", updatecheck: {} }])[0].updatecheck, {
    status: "noupdate",
  });

  const [patched] = ask([
    { appid: "abc", version: "100", updatecheck: {}, cached_items: [{ sha256: "c1" }] },
  ]);

  assert.equal(patched.updatecheck.nextversion, "200");
  assert.deepEqual(
    patched.updatecheck.pipelines.map((p: { operations: { type: string }[] }) =>
      p.operations.map((o) => o.type).join(","),
    ),
    ["download,puff,crx3", "download,crx3"],
  );
  const [patchDownload, puff] = patched.updatecheck.pipelines[0].operations;
  assert.equal(patchDownload.urls[0].url, "https://cdn.test/builds/200/crx/standard/c1.puff");
  assert.deepEqual(puff, { type: "puff", previous: { sha256: "c1" }, out: { sha256: "c2" } });

  const [full] = ask([
    { appid: "abc", version: "100", updatecheck: {}, cached_items: [{ sha256: "other" }] },
  ]);

  assert.equal(full.updatecheck.pipelines.length, 1);
  assert.equal(
    full.updatecheck.pipelines[0].operations[0].urls[0].url,
    "https://cdn.test/builds/200/crx/standard.crx3",
  );

  assert.deepEqual(ask([{ appid: "widevine", version: "1", updatecheck: {} }]), [
    { appid: "widevine", status: "error-unknownApplication" },
  ]);
  assert.throws(() => updateResponse("{}", components), /protocol 4.0/);
});

// Checks proofs the way components/client_update_protocol/cup.cc does: over
// SHA-256(request) | SHA-256(response) | cup2key, ECDSA_SHA256 with a DER
// signature, or ML-DSA-44 over that hash itself.
test("signs responses with CUP when the browser asks", async () => {
  const index: ComponentIndex = {
    format: 1,
    appid: "abc",
    version: "200",
    crx: { url: "s.crx3", sha256: "c2", size: 1 },
    patches: {},
  };

  const ecdsa = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const mldsa = generateKeyPairSync("ml-dsa-44");

  const handle = updateHandler({
    load: async () => new Map([["abc", { index, base: new URL("https://cdn.test/") }]]),
    cupKeys: Object.fromEntries([cupKey(7, ecdsa.privateKey), cupKey(16, mldsa.privateKey)]),
    log: () => {},
  });

  const body = JSON.stringify({
    request: { protocol: "4.0", apps: [{ appid: "abc", version: "1", updatecheck: {} }] },
  });

  const hash = (data: string | Buffer) => createHash("sha256").update(data).digest();

  const post = (query: string) =>
    handle(new Request(`http://updates.test/?${query}`, { method: "POST", body }));

  const proof = async (cup2key: string) => {
    const response = await post(
      `cup2key=${encodeURIComponent(cup2key)}&cup2hreq=${hash(body).toString("hex")}`,
    );

    assert.equal(response.status, 200);
    const [signature, requestHash] = response.headers.get("x-cup-server-proof")!.split(":");
    assert.equal(requestHash, hash(body).toString("hex"));

    const inner = hash(
      Buffer.concat([hash(body), hash(await response.text()), Buffer.from(cup2key)]),
    );

    return { inner, signature: Buffer.from(signature!, "hex") };
  };

  const signedEcdsa = await proof("7:123456789");
  assert.ok(verify("sha256", signedEcdsa.inner, ecdsa.publicKey, signedEcdsa.signature));
  const signedMldsa = await proof("ML-DSA-44-16:123456789");
  assert.equal(signedMldsa.signature.length, 2420);
  assert.ok(verify(null, signedMldsa.inner, mldsa.publicKey, signedMldsa.signature));

  // browsers with CUP off don't ask, and get an unsigned answer
  const plain = await post("");
  assert.equal(plain.status, 200);
  assert.equal(plain.headers.get("x-cup-server-proof"), null);
  // unknown key IDs and a tampered request hash are refused
  assert.equal((await post("cup2key=8:1")).status, 400);
  assert.equal((await post("cup2key=ML-DSA-44-7:1")).status, 400);
  assert.equal((await post(`cup2key=7:1&cup2hreq=${"00".repeat(32)}`)).status, 400);

  assert.throws(
    () => cupKey(1, generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey),
    /P-256 or ML-DSA-44/,
  );
});
