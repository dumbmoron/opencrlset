import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";
import { gunzipSync, zstdDecompressSync } from "node:zlib";
import { build } from "../src/build.ts";
import { encodeCrlSet, parseCrlSet } from "../src/crlset.ts";
import type { CrlSource } from "../src/snapshot.ts";
import { FLAG, shardOf } from "../src/explorer.ts";
import { parseCertificate, sha256Hex } from "../src/x509.ts";
import { crossSign, makeCrl, makeIntermediate, makeRoot, type Ca } from "./pki.ts";

const work = mkdtempSync(join(tmpdir(), "opencrlset-build-"));
const snapshotDir = join(work, "snapshot");

mkdirSync(join(snapshotDir, "ccadb"), { recursive: true });

mkdirSync(join(snapshotDir, "crls"), { recursive: true });

const root = makeRoot(join(work, "root"), "Chrome Root");

const revokedIntermediate = makeIntermediate(
  join(work, "revoked"),
  "Revoked Intermediate",
  root,
  "1001",
);

const ccadbRevoked = makeIntermediate(
  join(work, "ccadb-revoked"),
  "CCADB-only Revoked",
  root,
  "1002",
);

const sub = makeIntermediate(join(work, "sub"), "Issuing CA", root, "1003");
const mozillaRoot = makeRoot(join(work, "mozilla"), "Mozilla Only Root", "ec");

const mozillaSub = makeIntermediate(
  join(work, "mozilla-sub"),
  "Mozilla Only CA",
  mozillaRoot,
  "2001",
);

const stranger = makeRoot(join(work, "stranger"), "Chrome Root");
// also cross-signed by the Mozilla-only root, which hasn't revoked it: the
// root revoking its own certificate for this key can't block it
const crossed = makeIntermediate(join(work, "crossed"), "Cross-signed CA", root, "1004");
const crossedByMozilla = crossSign(
  join(work, "crossed-mozilla"),
  crossed,
  "Cross-signed CA",
  mozillaRoot,
  "2002",
);
// a root no store trusts any more, and its revoked cross-sign from the Chrome
// root: nothing vouches for its key, so every tier blocks it
const distrusted = makeRoot(join(work, "distrusted"), "Distrusted Root");
const distrustedByRoot = crossSign(
  join(work, "distrusted-root"),
  distrusted,
  "Distrusted Root",
  root,
  "1005",
);

const spki = (ca: Ca) => parseCertificate(ca.der).spkiSha256;
const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64");
const fingerprint = (ca: Ca) => sha256Hex(ca.der).toUpperCase();

const crls = new Map<string, Buffer>([
  [
    "http://crl.test/root.crl",
    makeCrl(root, [
      // a leaked CA key: every tier blocks the key, not just this certificate
      { serial: "1001", reason: "CACompromise" },
      { serial: "1004", reason: "keyCompromise" },
      { serial: "1005", reason: "keyCompromise" },
      // a sub-CA CCADB doesn't know about; roots only issue CA certificates
      { serial: "0C", reason: "superseded" },
      // CA certificates on hold are only suspended
      { serial: "0D", reason: "certificateHold" },
    ]),
  ],
  [
    "http://crl.test/sub/1.crl",
    makeCrl(
      sub,
      [
        { serial: "01", reason: "keyCompromise" },
        { serial: "02", reason: "cessationOfOperation" },
        { serial: "03", reason: "superseded" },
        { serial: "04", reason: "certificateHold" },
        // revoked over 398 days before the snapshot, so certainly expired
        { serial: "07", reason: "keyCompromise", date: "250901000000Z" },
        { serial: "AA", reason: "keyCompromise" },
      ],
      { idp: "http://crl.test/sub/1.crl" },
    ),
  ],
  // the revoked intermediate's own CRL still counts, its key may be certified elsewhere
  [
    "http://crl.test/revoked.crl",
    makeCrl(revokedIntermediate, [{ serial: "0B", reason: "keyCompromise" }]),
  ],
  ["http://crl.test/mozilla.crl", makeCrl(mozillaSub, [{ serial: "05", reason: "keyCompromise" }])],
  // served from a URL the root disclosed, but signed by someone else
  ["http://crl.test/forged.crl", makeCrl(stranger, [{ serial: "06", reason: "keyCompromise" }])],
]);

const csv = (rows: Record<string, string>[]) => {
  const columns = Object.keys(rows[0]!);
  const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;

  return (
    [
      columns.map(quote).join(","),
      ...rows.map((row) => columns.map((c) => quote(row[c] ?? "")).join(",")),
    ].join("\n") + "\n"
  );
};

const record = (
  ca: Ca,
  name: string,
  options: {
    parent?: Ca;
    chrome: string;
    mozilla?: string;
    revoked?: boolean;
    full?: string[];
    partitioned?: string[];
  },
) => ({
  "CA Owner": "Test",
  "Certificate Name": name,
  "Certificate Record Type": options.parent ? "Intermediate Certificate" : "Root Certificate",
  "Apple Status": "Not Included",
  "Chrome Status": options.chrome,
  "Microsoft Status": "Not Included",
  "Mozilla Status": options.mozilla ?? "Not Included",
  "Revocation Status": options.revoked ? "Revoked" : options.parent ? "Not Revoked" : "",
  "SHA-256 Fingerprint": fingerprint(ca),
  "Parent SHA-256 Fingerprint": options.parent ? fingerprint(options.parent) : "",
  "Valid To (GMT)": "2099.01.01",
  "JSON Array of All Full CRL URLs": options.full ? JSON.stringify(options.full) : "",
  "JSON Array of Partitioned CRLs": options.partitioned ? JSON.stringify(options.partitioned) : "",
});

writeFileSync(
  join(snapshotDir, "ccadb", "records.csv"),
  csv([
    record(root, "Chrome Root", {
      chrome: "Included",
      full: [
        "http://crl.test/root.crl",
        "http://crl.test/forged.crl",
        "http://crl.test/missing.crl",
      ],
    }),
    record(revokedIntermediate, "Revoked Intermediate", {
      parent: root,
      chrome: "Not Trusted",
      revoked: true,
      full: ["http://crl.test/revoked.crl"],
    }),
    record(ccadbRevoked, "CCADB-only Revoked", {
      parent: root,
      chrome: "Not Trusted",
      revoked: true,
    }),
    record(sub, "Issuing CA", {
      parent: root,
      chrome: "Trusted",
      partitioned: ["http://crl.test/sub/1.crl"],
    }),
    record(mozillaRoot, "Mozilla Only Root", { chrome: "Not Included", mozilla: "Included" }),
    record(mozillaSub, "Mozilla Only CA", {
      parent: mozillaRoot,
      chrome: "Not Trusted",
      mozilla: "Trusted",
      full: ["http://crl.test/mozilla.crl"],
    }),
    record(crossed, "Cross-signed CA", { parent: root, chrome: "Not Trusted" }),
    record(crossedByMozilla, "Cross-signed CA", {
      parent: mozillaRoot,
      chrome: "Not Trusted",
      mozilla: "Trusted",
    }),
    record(distrusted, "Distrusted Root", { chrome: "Removed" }),
    record(distrustedByRoot, "Distrusted Root", { parent: root, chrome: "Not Trusted" }),
  ]),
);

writeFileSync(
  join(snapshotDir, "ccadb", "pems.csv"),
  csv(
    [
      root,
      revokedIntermediate,
      ccadbRevoked,
      sub,
      mozillaRoot,
      mozillaSub,
      crossed,
      crossedByMozilla,
      distrusted,
      distrustedByRoot,
    ].map((ca) => ({
      "SHA-256 Fingerprint": fingerprint(ca),
      "X.509 Certificate (PEM)": readFileSync(ca.pem, "utf8"),
    })),
  ),
);

const sources: CrlSource[] = [...crls].map(([url, der]) => {
  const sha256 = sha256Hex(der);
  writeFileSync(join(snapshotDir, "crls", `${sha256}.crl`), der);

  const issuer = url.includes("mozilla")
    ? mozillaSub
    : url.includes("sub")
      ? sub
      : url.includes("revoked")
        ? revokedIntermediate
        : root;

  return {
    url,
    issuers: [fingerprint(issuer)],
    partitioned: url.includes("sub"),
    status: 200,
    sha256,
    size: der.length,
  };
});

sources.push({
  url: "http://crl.test/missing.crl",
  issuers: [fingerprint(root)],
  partitioned: false,
  error: "HTTP 404",
});

writeFileSync(
  join(snapshotDir, "manifest.json"),
  JSON.stringify({
    format: 1,
    snapshotTime: "2026-10-20T12:00:00.000Z",
    tool: { node: "test" },
    ccadb: [
      { name: "records", url: "test:", file: "ccadb/records.csv", sha256: "", size: 0 },
      { name: "pems", url: "test:", file: "ccadb/pems.csv", sha256: "", size: 0 },
    ],
    crls: sources.sort((a, b) => (a.url < b.url ? -1 : 1)),
  }),
);

const googlePath = join(work, "google-crl-set");

writeFileSync(
  googlePath,
  encodeCrlSet(
    { Sequence: 10000, BlockedSPKIs: [b64(spki(revokedIntermediate)), b64("ff".repeat(32))] },
    new Map([
      [spki(sub), ["01", "03", "99"]],
      ["ee".repeat(32), ["01"]],
    ]),
  ),
);

const quiet = () => {};

test("builds tiers, dataset and reports from a snapshot", async () => {
  const out = join(work, "out");
  const report = await build(snapshotDir, out, { google: googlePath, log: quiet });

  const tier = (name: string) => parseCrlSet(readFileSync(join(out, "crlset", name, "crl-set")));
  const standard = tier("standard");
  assert.equal(standard.header.Sequence, Math.floor(Date.parse("2026-10-20T12:00:00Z") / 60000));
  assert.deepEqual(Object.fromEntries(standard.parents), {
    [spki(root)]: ["0c", "1001", "1002", "1004", "1005"],
    [spki(sub)]: ["01", "aa"],
    [spki(revokedIntermediate)]: ["0b"],
  });
  assert.deepEqual([...standard.parents.keys()], [...standard.parents.keys()].sort());

  for (const name of ["standard", "priority", "all"]) {
    assert.deepEqual(
      tier(name).header.BlockedSPKIs,
      [b64(spki(revokedIntermediate)), b64(spki(distrusted))].sort(),
    );
  }

  assert.deepEqual(
    report.blockedKeys,
    [
      { spkiSha256: spki(revokedIntermediate), issuer: spki(root), serial: "1001", reason: 2 },
      { spkiSha256: spki(distrusted), issuer: spki(root), serial: "1005", reason: 1 },
    ].sort((a, b) => (a.spkiSha256 < b.spkiSha256 ? -1 : 1)),
  );
  assert.deepEqual(report.contestedKeys, [
    {
      spkiSha256: spki(crossed),
      issuer: spki(root),
      serial: "1004",
      reason: 1,
      vouching: [fingerprint(crossedByMozilla)],
    },
  ]);
  assert.deepEqual(tier("priority").parents.get(spki(sub)), ["01", "02", "aa"]);
  assert.deepEqual(tier("all").parents.get(spki(sub)), ["01", "02", "03", "aa"]);
  assert.deepEqual(tier("all").parents.get(spki(root)), ["0c", "1001", "1002", "1004", "1005"]);
  assert.equal(tier("all").parents.has(spki(mozillaSub)), false);

  const manifest = JSON.parse(
    readFileSync(join(out, "crlset", "standard", "manifest.json"), "utf8"),
  );

  assert.equal(manifest.version, String(standard.header.Sequence));

  const lines = zstdDecompressSync(readFileSync(join(out, "revocations.ndjson.zst")))
    .toString()
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  const find = (issuer: Ca, serial: string) =>
    lines.find((l) => l.issuer === spki(issuer) && l.serial === serial);

  assert.deepEqual(find(mozillaSub, "05"), {
    issuer: spki(mozillaSub),
    serial: "05",
    reason: 1,
    revoked: "2026-01-01T00:00:00Z",
    ca: false,
    crl: sha256Hex(crls.get("http://crl.test/mozilla.crl")!),
  });
  assert.equal(find(sub, "04").reason, 6);
  assert.equal(find(sub, "07").revoked, "2025-09-01T00:00:00Z");
  assert.equal(find(root, "1001").ca, true);
  assert.equal(find(root, "0c").ca, true);
  assert.equal(find(root, "0d").reason, 6);
  assert.deepEqual(find(root, "1002"), {
    issuer: spki(root),
    serial: "1002",
    reason: null,
    revoked: null,
    ca: true,
    crl: null,
  });
  assert.equal(find(root, "06"), undefined);

  const results = JSON.parse(readFileSync(join(out, "sources.json"), "utf8"));

  const status = Object.fromEntries(
    results.map((s: { url: string; status: string }) => [s.url, s.status]),
  );

  assert.deepEqual(status, {
    "http://crl.test/forged.crl": "failed",
    "http://crl.test/missing.crl": "not-fetched",
    "http://crl.test/mozilla.crl": "ok",
    "http://crl.test/revoked.crl": "ok",
    "http://crl.test/root.crl": "ok",
    "http://crl.test/sub/1.crl": "ok",
  });

  assert.equal(report.google!.shared, 1);
  assert.equal(report.google!.googleOnly.issuerKnownButNotInDataset, 1);
  assert.deepEqual(report.google!.googleOnly.inDatasetWithOtherReason, { "4": 1 });
  assert.equal(report.google!.googleOnly.unknownIssuer, 1);
  assert.equal(report.google!.blockedSPKIs, 2);
  assert.equal(report.google!.blockedSPKIsShared, 1);

  const explorer = (path: string) => readFileSync(join(out, "explorer", path), "utf8");
  const meta = JSON.parse(explorer("meta.json"));
  assert.equal(meta.sequence, standard.header.Sequence);
  assert.deepEqual(meta.policy.leafReasons.standard, [1, 9]);
  const index: { spki: string; inScope: boolean }[] = JSON.parse(explorer("issuers.json"));

  const shard = (serial: string) =>
    gunzipSync(readFileSync(join(out, "explorer", "revocations", `${shardOf(serial)}.ndjson.gz`)))
      .toString()
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .filter((r) => r[1] === serial);

  const issuerOf = (r: unknown[]) => (typeof r[0] === "number" ? index[r[0]]!.spki : r[0]);

  const [aa] = shard("aa");
  assert.equal(issuerOf(aa), spki(sub));
  assert.equal(aa[5], FLAG.standard | FLAG.priority | FLAG.all);
  const subFile = JSON.parse(explorer(`issuers/${spki(sub)}.json`));
  assert.equal(subFile.crls[aa[4]].sources[0].url, "http://crl.test/sub/1.crl");
  assert.equal(subFile.inScope, true);

  const ones = shard("01");
  assert.equal(ones.find((r) => issuerOf(r) === spki(sub))[5] & FLAG.google, FLAG.google);
  assert.equal(ones.find((r) => issuerOf(r) === "ee".repeat(32))[5], FLAG.google | FLAG.googleOnly);
  assert.equal(shard("99")[0][5], FLAG.google | FLAG.googleOnly);
  assert.equal(shard("0c")[0][5] & FLAG.caByRoot, FLAG.caByRoot);
  assert.equal(shard("1001")[0][5] & FLAG.caDisclosed, FLAG.caDisclosed);
  // out of chrome's scope: in the dataset, in no tier
  assert.equal(shard("05")[0][5], 0);

  const revokedFile = JSON.parse(explorer(`issuers/${spki(revokedIntermediate)}.json`));
  assert.equal(revokedFile.inScope, true);
  assert.deepEqual(revokedFile.trustedBy, []);
  const rootFile = JSON.parse(explorer(`issuers/${spki(root)}.json`));
  assert.deepEqual(
    rootFile.caCertificates.map((c: { serial: string }) => c.serial),
    ["1001", "1002", "1003", "1004", "1005"],
  );
  assert.equal(rootFile.failedCrls.length, 2);
});

test("explains what changed since a previous build", async () => {
  const previousPath = join(work, "previous-crl-set");
  writeFileSync(
    previousPath,
    encodeCrlSet({ Sequence: 1 }, new Map([[spki(sub), ["01", "03", "bb"]]])),
  );

  // without Google's set and the explorer too, which once reported every
  // previous issuer as having no data
  for (const [name, options] of [
    ["with-previous", { google: googlePath }],
    ["with-previous-only", { explorer: false }],
  ] as const) {
    const out = join(work, name);
    await build(snapshotDir, out, { ...options, previous: previousPath, log: quiet });
    const { changes } = JSON.parse(readFileSync(join(out, "report.json"), "utf8"));
    assert.equal(changes.previous, 1);
    assert.deepEqual(
      changes.removed.map((r: { serial: string; why: string }) => [r.serial, r.why]),
      [
        ["03", "excluded: reason"],
        ["bb", "no longer on any fetched CRL"],
      ],
      name,
    );
    // aa under sub, 0b, 0c, 1001, 1002, 1004, 1005 are new; 01 was there before
    assert.equal(changes.added, 7);
  }
});

test("is deterministic", async () => {
  const files = async (out: string) => {
    await build(snapshotDir, out, { google: googlePath, log: quiet });

    const listing = readdirSync(out, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => join(e.parentPath, e.name));

    return Object.fromEntries(
      listing.map((path) => [relative(out, path), sha256Hex(readFileSync(path))]),
    );
  };

  assert.deepEqual(await files(join(work, "a")), await files(join(work, "b")));
});
