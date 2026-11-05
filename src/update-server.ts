// A reference update server for the CRLSet component: answers Chromium's
// update protocol 4.0 (components/update_client) from the <tier>.json index
// `opencrlset crx` writes. See docs/integration.md.
//
// Given CUP keys, it signs responses to requests that ask for it, through
// @imput/cup2. Chromium asks for ML-DSA-44 by default (kPqcCupSigning), else
// ECDSA P-256. Without keys, the browser must have CUP turned off
// (ConfiguratorImpl::EnabledCupSigning).

import type { KeyObject } from "node:crypto";
import { createServer } from "node:http";
import { buffer } from "node:stream/consumers";
import { CupError, CupServer } from "@imput/cup2";
import type { ComponentIndex } from "./component.ts";

// One component: its index, and the URL the index's relative URLs resolve against.
export interface Component {
  index: ComponentIndex;
  base: URL;
}

interface RequestApp {
  appid?: unknown;
  version?: unknown;
  updatecheck?: unknown;
  cached_items?: unknown;
}

// The request isn't one this server can answer: a 400, not a 500.
export class BadRequestError extends Error {}

// base::Version ordering: dotted numbers, compared part by part
export function compareVersions(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);

  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);

    if (d) return Math.sign(d);
  }

  return 0;
}

const download = (base: URL, file: { url: string; sha256: string; size: number }) => ({
  type: "download",
  urls: [{ url: new URL(file.url, base).href }],
  size: file.size,
  out: { sha256: file.sha256 },
});

// The updatecheck for one app: noupdate when it's current, else a patch from
// a CRX it has cached (when there is one), then the full CRX as a fallback.
export function updateCheck(component: Component, version: string, cached: string[]) {
  const { index, base } = component;

  if (compareVersions(version, index.version) >= 0) return { status: "noupdate" };
  const install = { type: "crx3", in: { sha256: index.crx.sha256 } };
  const pipelines = [];
  const from = cached.find((sha256) => index.patches[sha256]);

  if (from) {
    pipelines.push({
      pipeline_id: `puff_${from.slice(0, 8)}`,
      operations: [
        download(base, index.patches[from]!),
        { type: "puff", previous: { sha256: from }, out: { sha256: index.crx.sha256 } },
        install,
      ],
    });
  }

  pipelines.push({ pipeline_id: "full", operations: [download(base, index.crx), install] });

  return { status: "ok", nextversion: index.version, pipelines };
}

// Answers a request body. Apps it doesn't know get error-unknownApplication;
// a server that also serves other components answers those itself.
export function updateResponse(body: string, components: Map<string, Component>): string {
  let apps: RequestApp[];

  try {
    const { request }: { request?: { protocol?: unknown; apps?: unknown } } = JSON.parse(body);

    if (request?.protocol !== "4.0" || !Array.isArray(request.apps)) throw new Error();
    // JSON objects; anything else in the list isn't an app
    apps = request.apps.filter((app) => app instanceof Object);
  } catch {
    throw new BadRequestError("not an update protocol 4.0 request");
  }

  const response = {
    response: {
      protocol: "4.0",
      apps: apps.map((app) => {
        const appid = String(app.appid ?? "");
        const component = components.get(appid);

        if (!component) return { appid, status: "error-unknownApplication" };

        if (app.updatecheck === undefined) return { appid, status: "ok" };

        const cached = Array.isArray(app.cached_items)
          ? app.cached_items.map((item) => String(item?.sha256 ?? ""))
          : [];

        return {
          appid,
          status: "ok",
          updatecheck: updateCheck(component, String(app.version ?? "0"), cached),
        };
      }),
    },
  };

  // the prefix Chromium requires against cross-site script inclusion
  return ")]}'\n" + JSON.stringify(response);
}

export interface ServeOptions {
  // loads the components to answer for; called at most once a minute
  load: () => Promise<Map<string, Component>>;
  // CUP signing keys by the ID the browser asks for, as cupKey() names them
  cupKeys?: Record<string, CryptoKey>;
  log: (message: string) => void;
}

// A CUP signing key of a key version, named the way the browser asks for it:
// "8" for ECDSA P-256, "ML-DSA-44-8" for ML-DSA-44.
export function cupKey(version: number, key: KeyObject): [string, CryptoKey] {
  if (key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1") {
    return [
      String(version),
      key.toCryptoKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]),
    ];
  }

  if (key.asymmetricKeyType === "ml-dsa-44") {
    return [`ML-DSA-44-${version}`, key.toCryptoKey({ name: "ML-DSA-44" }, false, ["sign"])];
  }

  throw new Error(`CUP keys are ECDSA P-256 or ML-DSA-44, not ${key.asymmetricKeyType}`);
}

// A fetch-style handler, for any server that speaks Request and Response.
export function updateHandler(options: ServeOptions): (request: Request) => Promise<Response> {
  let cache: { at: number; components: Promise<Map<string, Component>> } | undefined;

  const components = () => {
    if (!cache || Date.now() - cache.at > 60_000)
      cache = { at: Date.now(), components: options.load() };

    return cache.components;
  };

  const cup =
    options.cupKeys && Object.keys(options.cupKeys).length
      ? new CupServer(options.cupKeys)
      : undefined;

  return async (request) => {
    if (request.method !== "POST") return new Response(null, { status: 405 });

    try {
      // sign when the browser asks; browsers with CUP off don't send cup2key
      const ticket =
        cup && new URL(request.url).searchParams.has("cup2key")
          ? await cup.makeTicket(request)
          : undefined;

      const body = updateResponse(await request.text(), await components());
      const response = new Response(body, { headers: { "content-type": "application/json" } });

      return ticket ? await cup!.sign(response, ticket) : response;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      options.log(`bad request: ${message}`);

      return new Response(null, {
        status: error instanceof CupError || error instanceof BadRequestError ? 400 : 500,
      });
    }
  };
}

// Serves updateHandler with node:http.
export function serve(options: ServeOptions & { port: number }) {
  const handle = updateHandler(options);

  const server = createServer(async (incoming, outgoing) => {
    const body = await buffer(incoming);
    const headers = new Headers();

    for (const [name, value] of Object.entries(incoming.headers))
      if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);

    const request = new Request(
      new URL(incoming.url ?? "/", `http://${incoming.headers.host ?? "localhost"}`),
      {
        method: incoming.method,
        headers,
        body: incoming.method === "GET" || incoming.method === "HEAD" ? undefined : body,
      },
    );

    const response = await handle(request);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  });

  server.listen(options.port, () => options.log(`listening on :${options.port}`));

  return server;
}
