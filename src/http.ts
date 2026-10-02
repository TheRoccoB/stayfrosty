import { FrostyError, type ApiName } from "./errors.ts";

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export type Sleep = (ms: number) => Promise<void>;

export const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export interface RawResponse {
  status: number;
  headers: Headers;
  body: unknown;
}

const RETRYABLE = new Set([429, 502, 503, 504]);
const MAX_ATTEMPTS = 4;
const TIMEOUT_MS = 30_000;

// One HTTP call with a timeout, JSON in and out. Reads (GET) are retried on rate limits and
// gateway errors; writes are not, because a retried POST can create a duplicate.
export async function sendJson(opts: {
  api: ApiName;
  fetch: Fetch;
  sleep: Sleep;
  url: string;
  method: string;
  token: string;
  body?: unknown;
}): Promise<RawResponse> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
    Accept: "application/json",
  };
  let payload: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(opts.body);
  }
  const canRetry = opts.method === "GET";
  let attempt = 0;
  for (;;) {
    attempt += 1;
    let response: Response;
    try {
      const init: RequestInit = {
        method: opts.method,
        headers,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      };
      if (payload !== undefined) {
        init.body = payload;
      }
      response = await opts.fetch(opts.url, init);
    } catch (error) {
      if (canRetry && attempt < MAX_ATTEMPTS) {
        await opts.sleep(backoffMs(attempt, undefined));
        continue;
      }
      const label = opts.api === "hetzner" ? "Hetzner" : "Cloudflare";
      const reason = error instanceof Error ? error.message : String(error);
      throw new FrostyError(
        `Could not reach the ${label} API (${opts.method} ${pathOf(opts.url)}): ${reason}`,
        "Check your internet connection and run the command again.",
      );
    }
    if (canRetry && RETRYABLE.has(response.status) && attempt < MAX_ATTEMPTS) {
      await opts.sleep(backoffMs(attempt, response.headers.get("retry-after")));
      continue;
    }
    const text = await response.text();
    let body: unknown = undefined;
    if (text.length > 0) {
      try {
        body = JSON.parse(text);
      } catch {
        body = { nonJsonBody: text.slice(0, 500) };
      }
    }
    return { status: response.status, headers: response.headers, body };
  }
}

function backoffMs(attempt: number, retryAfter: string | null | undefined): number {
  if (retryAfter !== null && retryAfter !== undefined) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds, 60) * 1000;
    }
  }
  return 500 * 2 ** (attempt - 1);
}

export function pathOf(url: string): string {
  const parsed = new URL(url);
  return parsed.pathname + parsed.search;
}

export function withQuery(path: string, query: Record<string, string | number | boolean | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  if (qs.length === 0) {
    return path;
  }
  return `${path}${path.includes("?") ? "&" : "?"}${qs}`;
}
