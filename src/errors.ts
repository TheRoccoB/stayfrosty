import { redact } from "./redact.ts";

// An error the user can act on. `hint` is the next thing to run or check.
export class FrostyError extends Error {
  readonly hint: string | undefined;

  constructor(message: string, hint?: string) {
    super(redact(message));
    this.name = "FrostyError";
    this.hint = hint === undefined ? undefined : redact(hint);
  }
}

export type ApiName = "hetzner" | "cloudflare" | "digitalocean";

export const API_LABELS: Record<ApiName, string> = { hetzner: "Hetzner", cloudflare: "Cloudflare", digitalocean: "DigitalOcean" };

export class ApiError extends FrostyError {
  readonly api: ApiName;
  readonly status: number;
  readonly code: string | undefined;
  readonly method: string;
  readonly path: string;

  constructor(opts: {
    api: ApiName;
    status: number;
    code?: string | undefined;
    message: string;
    method: string;
    path: string;
    hint?: string | undefined;
  }) {
    const label = API_LABELS[opts.api];
    const codePart = opts.code === undefined ? "" : ` (${opts.code})`;
    super(`${label} API ${opts.method} ${opts.path} failed with HTTP ${opts.status}${codePart}: ${opts.message}`, opts.hint);
    this.name = "ApiError";
    this.api = opts.api;
    this.status = opts.status;
    this.code = opts.code;
    this.method = opts.method;
    this.path = redact(opts.path);
  }
}
