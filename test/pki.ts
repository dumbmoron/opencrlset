// Builds throwaway CAs and CRLs with the openssl CLI, so the parsers are
// tested against an independent implementation.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type KeyType = "rsa" | "ec";

export interface Revoked {
  serial: string;
  reason?: string;
  date?: string;
}

export interface Ca {
  dir: string;
  key: string;
  pem: string;
  der: Buffer;
}

const openssl = (args: string[], cwd: string) =>
  execFileSync("openssl", args, { cwd, stdio: ["ignore", "pipe", "pipe"] });

const keyArgs = (type: KeyType) =>
  type === "ec"
    ? ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
    : ["-newkey", "rsa:2048"];

export function makeRoot(dir: string, name: string, type: KeyType = "rsa"): Ca {
  mkdirSync(dir, { recursive: true });
  openssl(
    [
      "req",
      "-x509",
      ...keyArgs(type),
      "-nodes",
      "-keyout",
      "ca.key",
      "-out",
      "ca.pem",
      "-subj",
      `/CN=${name}`,
      "-days",
      "30",
    ],
    dir,
  );

  return load(dir);
}

export function makeIntermediate(dir: string, name: string, parent: Ca, serial: string): Ca {
  mkdirSync(dir, { recursive: true });
  openssl(
    [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      "ca.key",
      "-out",
      "ca.csr",
      "-subj",
      `/CN=${name}`,
    ],
    dir,
  );
  writeFileSync(
    join(dir, "ext.cnf"),
    "basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n",
  );
  openssl(
    [
      "x509",
      "-req",
      "-in",
      "ca.csr",
      "-CA",
      parent.pem,
      "-CAkey",
      parent.key,
      "-set_serial",
      `0x${serial}`,
      "-days",
      "30",
      "-extfile",
      "ext.cnf",
      "-out",
      "ca.pem",
    ],
    dir,
  );

  return load(dir);
}

function load(dir: string): Ca {
  const pem = join(dir, "ca.pem");

  return {
    dir,
    key: join(dir, "ca.key"),
    pem,
    der: openssl(["x509", "-in", pem, "-outform", "DER"], dir),
  };
}

export function makeCrl(
  ca: Ca,
  revoked: Revoked[],
  options: { idp?: string; pss?: boolean; crlNumber?: string; out?: string } = {},
): Buffer {
  const index = revoked
    .map(({ serial, reason, date = "260101000000Z" }) =>
      [
        "R",
        "301231235959Z",
        reason ? `${date},${reason}` : date,
        serial.toUpperCase(),
        "unknown",
        `/CN=leaf-${serial}`,
      ].join("\t"),
    )
    .join("\n");

  writeFileSync(join(ca.dir, "index.txt"), index ? index + "\n" : "");
  writeFileSync(join(ca.dir, "crlnumber"), (options.crlNumber ?? "1000") + "\n");
  writeFileSync(
    join(ca.dir, "ca.cnf"),
    [
      "[ca]",
      "default_ca = ca_default",
      "[ca_default]",
      "database = index.txt",
      "crlnumber = crlnumber",
      "default_md = sha256",
      "default_crl_days = 7",
      "crl_extensions = crl_ext",
      "[crl_ext]",
      "authorityKeyIdentifier = keyid:always",
      ...(options.idp
        ? ["issuingDistributionPoint = critical, @idp", "[idp]", `fullname = URI:${options.idp}`]
        : []),
      "",
    ].join("\n"),
  );
  const out = options.out ?? join(ca.dir, "crl.der");

  const pss = options.pss
    ? ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
    : [];

  openssl(
    [
      "ca",
      "-gencrl",
      "-config",
      "ca.cnf",
      "-keyfile",
      ca.key,
      "-cert",
      ca.pem,
      ...pss,
      "-out",
      "crl.pem",
    ],
    ca.dir,
  );
  openssl(["crl", "-in", "crl.pem", "-outform", "DER", "-out", out], ca.dir);

  return readFileSync(out);
}
