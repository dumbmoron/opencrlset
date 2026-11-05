import assert from "node:assert/strict";
import { test } from "node:test";
import { checkSerial, encodeCrlSet, encodeHeader, parseCrlSet } from "../src/crlset.ts";
import {
  kBlockedSPKICRLSet,
  kExpiredCRLSet,
  kGIACRLSet,
  kGIASPKISHA256,
} from "./chromium-vectors.ts";

const header = (json: string) => {
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16LE(Buffer.byteLength(json));

  return Buffer.concat([prefix, Buffer.from(json)]);
};

test("parses Chromium's GIA vector", () => {
  const set = parseCrlSet(kGIACRLSet);
  assert.equal(set.parents.size, 1);
  const serials = set.parents.get(kGIASPKISHA256.toString("hex"));
  assert.ok(serials);
  assert.equal(serials.length, 13);
  assert.equal(serials[0], "100d7f30000300002" + "3b0");
  assert.equal(serials[12], "646349d2000300001d77");

  const spki = kGIASPKISHA256.toString("hex");
  assert.equal(checkSerial(set, spki, Buffer.from("100d7f300003000023b0", "hex")), "revoked");
  assert.equal(checkSerial(set, spki, Buffer.from("00100d7f300003000023b0", "hex")), "revoked");
  assert.equal(checkSerial(set, spki, Buffer.from("01", "hex")), "good");
  assert.equal(checkSerial(set, spki, Buffer.from("ff", "hex")), "unknown");
  assert.equal(checkSerial(set, "00".repeat(32), Buffer.from("01", "hex")), "unknown");
});

test("parses Chromium's blocked SPKI and expired vectors", () => {
  assert.deepEqual(parseCrlSet(kBlockedSPKICRLSet).header.BlockedSPKIs, [
    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  ]);
  const expired = parseCrlSet(kExpiredCRLSet);
  assert.equal(expired.header.NotAfter, 1);
  assert.equal(expired.header.Sequence, 1);
});

test("round-trips through the encoder", () => {
  const parents = new Map([
    ["11".repeat(32), ["00", "01", "7f00ff"]],
    ["22".repeat(32), ["ab".repeat(20)]],
  ]);

  const encoded = encodeCrlSet(
    {
      Sequence: 29000000,
      NotAfter: 1800000000,
      BlockedSPKIs: ["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="],
    },
    parents,
  );

  const parsed = parseCrlSet(encoded);
  assert.deepEqual(parsed.parents, parents);
  assert.equal(parsed.header.Sequence, 29000000);
  assert.equal(JSON.parse(parsed.json).NumParents, 2);
  assert.equal(parsed.header.NotAfter, 1800000000);
  assert.deepEqual(
    encodeCrlSet(
      {
        Sequence: 29000000,
        NotAfter: 1800000000,
        BlockedSPKIs: ["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="],
      },
      parents,
    ),
    encoded,
  );
});

test("rejects what Chromium rejects", () => {
  const valid = '{"ContentType":"CRLSet","Version":0,"Sequence":1}';
  assert.doesNotThrow(() => parseCrlSet(header(valid)));
  const reject = (data: Buffer) => assert.throws(() => parseCrlSet(data));
  reject(Buffer.from([1]));
  reject(header('{"ContentType":"CRLSet","Version":1,"Sequence":1}'));
  reject(header('{"ContentType":"CRLSet","Version":0}'));
  reject(header('{"ContentType":"CRLSet","Version":0,"Sequence":1.5}'));
  reject(header('{"ContentType":"CRLSet","Version":0,"Sequence":1,"NotAfter":-1}'));
  reject(header('{"ContentType":"CRLSet","Version":0,"Sequence":1,"BlockedSPKIs":["not base64"]}'));
  reject(header('{"ContentType":"CRLSet","Version":0,"Sequence":1,"BlockedSPKIs":[1]}'));
  reject(header('{"ContentType":"Other","Version":0,"Sequence":1}'));
  reject(Buffer.concat([header(valid), Buffer.alloc(35)]));
  // one serial announced, none present
  reject(Buffer.concat([header(valid), Buffer.alloc(32), Buffer.from([1, 0, 0, 0])]));
});

test("refuses headers Chromium would drop", () => {
  assert.throws(() => encodeHeader({ Sequence: 0 }, 0));
  assert.throws(() => encodeHeader({ Sequence: 2 ** 31 }, 0));
  assert.throws(() =>
    encodeHeader({ Sequence: 1, BlockedSPKIs: Array(2000).fill("A".repeat(44)) }, 0),
  );
});
