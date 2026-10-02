import type { Fetch } from "../src/http.ts";

export interface Call {
  method: string;
  url: URL;
  body: unknown;
  authorization: string | null;
}

export interface FakeReply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

type Handler = (call: Call) => FakeReply;

interface Route {
  method: string;
  host: string;
  path: RegExp;
  handler: Handler;
}

// A tiny fake of both REST APIs: routes are matched by method, host and path regex, and a
// route added later wins, so a test can override one route of a shared setup.
// Every call is recorded, so tests can assert that a command only read.
export class FakeHttp {
  readonly calls: Call[] = [];
  private readonly routes: Route[] = [];

  // `host` is e.g. "api.hetzner.cloud"; `path` is a regex source for the pathname.
  on(method: string, host: string, path: string, handler: Handler | FakeReply): this {
    this.routes.push({
      method,
      host,
      path: new RegExp(`^${path}$`),
      handler: typeof handler === "function" ? handler : () => handler,
    });
    return this;
  }

  readonly fetch: Fetch = async (input, init) => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      body = JSON.parse(init.body);
    }
    const call: Call = { method, url, body, authorization: headers.get("authorization") };
    this.calls.push(call);
    for (const route of [...this.routes].reverse()) {
      if (route.method === method && route.host === url.host && route.path.test(url.pathname)) {
        const reply = route.handler(call);
        return new Response(reply.body === undefined ? null : JSON.stringify(reply.body), {
          status: reply.status ?? 200,
          headers: { "content-type": "application/json", ...reply.headers },
        });
      }
    }
    return new Response(JSON.stringify({ error: { code: "not_found", message: `no fake route for ${method} ${url.pathname}` } }), {
      status: 404,
    });
  };

  writes(): Call[] {
    return this.calls.filter((call) => call.method !== "GET");
  }
}

export const noSleep = async (): Promise<void> => {};

export function cfOk(result: unknown, resultInfo?: Record<string, unknown>): FakeReply {
  const body: Record<string, unknown> = { success: true, errors: [], messages: [], result };
  if (resultInfo !== undefined) {
    body["result_info"] = resultInfo;
  }
  return { body };
}

export function cfFail(status: number, code: number, message: string): FakeReply {
  return { status, body: { success: false, errors: [{ code, message }], messages: [], result: null } };
}

export function hzPage(key: string, items: unknown[], nextPage: number | null = null): FakeReply {
  return {
    body: {
      [key]: items,
      meta: { pagination: { page: 1, per_page: 50, previous_page: null, next_page: nextPage, last_page: 1, total_entries: items.length } },
    },
  };
}
