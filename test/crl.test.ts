import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { REASON, crlEntries, parseCrl, verifyCrl } from "../src/crl.ts";
import { canonicalSerial } from "../src/der.ts";
import { parseCertificate, publicKeyOf, sha256Hex } from "../src/x509.ts";
import { makeCrl, makeRoot } from "./pki.ts";

const work = mkdtempSync(join(tmpdir(), "opencrlset-crl-"));

test("parses certificates like openssl does", () => {
  const ca = makeRoot(join(work, "cert"), "Cert Test CA");
  const certificate = parseCertificate(ca.der);
  assert.equal(certificate.sha256, sha256Hex(ca.der).toUpperCase());
  assert.equal(certificate.issuer.toString("hex"), certificate.subject.toString("hex"));
  // the hashed SPKI must be the certificate's own bytes, as Chromium hashes them
  assert.ok(ca.der.includes(certificate.spki));
  assert.equal(certificate.spki[0], 0x30);
});

for (const [type, pss] of [
  ["rsa", false],
  ["rsa", true],
  ["ec", false],
] as const) {
  test(`parses and verifies ${type}${pss ? "-pss" : ""} CRLs`, () => {
    const ca = makeRoot(join(work, `${type}-${pss}`), `${type} CA`, type);

    const der = makeCrl(
      ca,
      [
        { serial: "01", reason: "keyCompromise" },
        { serial: "00FF", reason: "cessationOfOperation" },
        { serial: "0A0B0C0D0E0F101112131415161718191A1B1C1D", reason: "certificateHold" },
        { serial: "02" },
      ],
      { pss },
    );

    const crl = parseCrl(der);
    const certificate = parseCertificate(ca.der);
    assert.ok(crl.issuer.equals(certificate.subject));
    assert.equal(crl.crlNumber, "1000");
    assert.equal(crl.isDelta, false);
    assert.ok(crl.nextUpdate! > crl.thisUpdate);
    assert.equal(verifyCrl(crl, publicKeyOf(certificate.spki)), true);

    const other = parseCertificate(makeRoot(join(work, `${type}-${pss}-other`), "Other", type).der);
    assert.equal(verifyCrl(crl, publicKeyOf(other.spki)), false);

    const entries = [...crlEntries(crl)].map(
      (e) => [canonicalSerial(e.serial).toString("hex"), e.reason] as const,
    );

    assert.deepEqual(
      new Map(entries),
      new Map([
        ["01", REASON.keyCompromise],
        ["ff", REASON.cessationOfOperation],
        ["0a0b0c0d0e0f101112131415161718191a1b1c1d", REASON.certificateHold],
        ["02", REASON.unspecified],
      ]),
    );
  });
}

test("reads issuing distribution points and PEM CRLs", () => {
  const ca = makeRoot(join(work, "idp"), "IDP CA");
  makeCrl(ca, [], { idp: "http://crl.example.test/7.crl" });
  const crl = parseCrl(readFileSync(join(ca.dir, "crl.pem")));
  assert.deepEqual(crl.idp?.uris, ["http://crl.example.test/7.crl"]);
  assert.equal(crl.idp?.indirectCRL, false);
  assert.equal(crl.revokedCertificates, undefined);
  assert.deepEqual([...crlEntries(crl)], []);
});

test("detects tampering", () => {
  const ca = makeRoot(join(work, "tamper"), "Tamper CA");
  const der = Buffer.from(makeCrl(ca, [{ serial: "1234", reason: "keyCompromise" }]));
  const index = der.indexOf(Buffer.from([0x02, 0x02, 0x12, 0x34]));
  der[index + 3] = 0x35;
  const certificate = parseCertificate(ca.der);
  assert.equal(verifyCrl(parseCrl(der), publicKeyOf(certificate.spki)), false);
});
