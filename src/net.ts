import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";

export const USER_AGENT = "opencrlset/0.1 (+https://github.com/imputnet/opencrlset)";

export class Semaphore {
  #available: number;
  #waiting: (() => void)[] = [];

  constructor(count: number) {
    this.#available = count;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#available > 0) {
      this.#available--;
    } else {
      await new Promise<void>((resolve) => this.#waiting.push(resolve));
    }

    try {
      return await task();
    } finally {
      const next = this.#waiting.shift();

      if (next) next();
      else this.#available++;
    }
  }
}

export interface Download {
  status: number;
  finalUrl: string;
  sha256: string;
  size: number;
  path: string;
}

export class HttpError extends Error {
  status: number;
  constructor(status: number, url: string) {
    super(`HTTP ${status} for ${url}`);
    this.status = status;
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Node's TLS verification failures (incomplete chains, unknown roots, ...)
function isCertificateError(error: unknown): boolean {
  const cause = error instanceof Error ? error.cause : undefined;
  const code = cause instanceof Error && "code" in cause ? String(cause.code) : "";

  return /CERT|SELF_SIGNED|UNABLE_TO_(VERIFY|GET)|ALTNAME/.test(code);
}

const retryable = (error: unknown) =>
  !(error instanceof HttpError) || error.status === 429 || error.status >= 500;

// Streams a URL into `dir/<sha256><suffix>`, hashing as it goes.
export async function download(
  url: string,
  dir: string,
  options: {
    suffix?: string;
    maxBytes?: number;
    timeoutMs?: number;
    attempts?: number;
    httpFallback?: boolean;
  } = {},
): Promise<Download & { attempts: number }> {
  const {
    suffix = "",
    maxBytes = 512 * 1024 * 1024,
    timeoutMs = 5 * 60_000,
    attempts = 3,
  } = options;

  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return { ...(await downloadOnce(url, dir, suffix, maxBytes, timeoutMs)), attempts: attempt };
    } catch (error) {
      lastError = error;

      if (options.httpFallback && url.startsWith("https://") && isCertificateError(error)) {
        return download(url.replace(/^https:/, "http:"), dir, { ...options, httpFallback: false });
      }

      if (!retryable(error) || attempt === attempts) break;
      await sleep(2000 * 4 ** (attempt - 1));
    }
  }

  throw lastError;
}

async function downloadOnce(
  url: string,
  dir: string,
  suffix: string,
  maxBytes: number,
  timeoutMs: number,
): Promise<Download> {
  const response = await fetch(url, {
    headers: { "user-agent": USER_AGENT },
    redirect: "follow",
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new HttpError(response.status, url);
  }

  const declared = Number(response.headers.get("content-length"));

  if (declared > maxBytes) {
    await response.body.cancel();
    throw new Error(`response too large (${declared} bytes)`);
  }

  const hash = createHash("sha256");
  let size = 0;

  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      size += chunk.length;

      if (size > maxBytes) {
        callback(new Error(`response exceeds ${maxBytes} bytes`));

        return;
      }

      hash.update(chunk);
      callback(null, chunk);
    },
  });

  const temporary = join(dir, `.partial-${process.pid}-${Math.random().toString(36).slice(2)}`);

  try {
    await pipeline(Readable.fromWeb(response.body), meter, createWriteStream(temporary));
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }

  const sha256 = hash.digest("hex");
  const path = join(dir, `${sha256}${suffix}`);
  await rename(temporary, path);

  return { status: response.status, finalUrl: response.url, sha256, size, path };
}

export async function fetchText(url: string, timeoutMs = 60_000): Promise<string> {
  const response = await fetch(url, {
    headers: { "user-agent": USER_AGENT },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) throw new HttpError(response.status, url);

  return response.text();
}
