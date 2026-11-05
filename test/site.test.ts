import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FLAG, nameHash, shardOf, subjectKeyId } from "../src/explorer.ts";
import { POLICY } from "../src/policy.ts";
import { parseCertificate as parseCertificateTs } from "../src/x509.ts";
// the site's own modules, as the browser runs them
import { parseCertificate, pemToDer, sha256Hex } from "../site/src/lib/cert.ts";
import { canonicalSerial, decodeRecord, tierStatus, verdictFor } from "../site/src/lib/explain.ts";
import { makeIntermediate, makeRoot } from "./pki.ts";

const meta = { policy: POLICY, snapshotTime: "2026-10-20T12:00:00Z", store: "chrome" };
const now = Date.parse(meta.snapshotTime) / 1000;

test("explains records the way the build decided them", () => {
  const leaf = decodeRecord(
    [0, "01", 1, now - 86400, 0, FLAG.standard | FLAG.priority | FLAG.all | FLAG.google],
    FLAG,
  );

  assert.equal(leaf.google, true);
  assert.equal(verdictFor("standard", leaf, true, meta), "included");
  assert.equal(verdictFor("standard", leaf, false, meta), "scope");
  assert.deepEqual(tierStatus("standard", leaf, true, meta), {
    included: true,
    why: undefined,
    disagrees: false,
  });

  const ca = decodeRecord(
    [0, "02", 4, now - 1000 * 86400, 0, FLAG.caByRoot | FLAG.standard | FLAG.priority | FLAG.all],
    FLAG,
  );

  assert.equal(verdictFor("standard", ca, false, meta), "included");

  const old = decodeRecord([0, "04", 1, now - 1000 * 86400, 0, 0], FLAG);
  assert.deepEqual(tierStatus("all", old, true, meta), {
    included: false,
    why: "expired",
    disagrees: false,
  });

  const googleOnly = decodeRecord([0, "03", null, null, -1, FLAG.google | FLAG.googleOnly], FLAG);
  assert.equal(verdictFor("all", googleOnly, true, meta), "missing");
  assert.equal(tierStatus("all", googleOnly, true, meta).disagrees, false);
});

test("flags disagreement with the build", () => {
  // superseded is not a standard-tier reason, but the flags say included
  const wrong = decodeRecord([0, "01", 4, now - 86400, 0, FLAG.standard], FLAG);
  assert.equal(tierStatus("standard", wrong, true, meta).disagrees, true);
});

test("normalizes serials like the build", () => {
  assert.equal(canonicalSerial("00:A1:b2"), "a1b2");
  assert.equal(canonicalSerial("0x3"), "03");
  assert.equal(canonicalSerial("00"), "00");
  assert.equal(canonicalSerial("zz"), undefined);
});

test("reads certificates like the build", async () => {
  const work = mkdtempSync(join(tmpdir(), "opencrlset-site-"));
  const root = makeRoot(join(work, "root"), "Site Root");

  const intermediate = makeIntermediate(
    join(work, "intermediate"),
    "Site Intermediate",
    root,
    "00F003",
  );

  const parsed = parseCertificate(pemToDer(readFileSync(intermediate.pem, "utf8"))!);
  const rootTs = parseCertificateTs(root.der);
  assert.equal(parsed.serial, "f003");
  assert.equal(parsed.negativeSerial, false);
  assert.equal(parsed.authorityKeyId, subjectKeyId(rootTs));
  assert.equal((await sha256Hex(parsed.issuer)).slice(0, 16), nameHash(rootTs.subject));
  assert.equal((await sha256Hex("f003")).slice(0, 3), shardOf("f003"));
});
