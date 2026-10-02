import { ApiError, FrostyError } from "./errors.ts";
import { realSleep, sendJson, withQuery, type Fetch, type Sleep } from "./http.ts";
import { redact, registerSecret } from "./redact.ts";

export const CLOUDFLARE_BASE_URL = "https://api.cloudflare.com/client/v4";

// Names of everything frosty creates in Cloudflare start with this.
export const NAME_PREFIX = "stayfrosty-";

interface Envelope<T> {
  success: boolean;
  errors?: { code: number; message: string }[];
  result: T;
  result_info?: { page?: number; per_page?: number; total_pages?: number; count?: number; total_count?: number; cursor?: string };
}

export interface CfZone {
  id: string;
  name: string;
  status: string;
  account: { id: string; name: string };
}

export interface CfTunnel {
  id: string;
  name: string;
  status: string;
  created_at: string;
  deleted_at: string | null;
  config_src?: string;
  connections?: { colo_name?: string; client_version?: string; is_pending_reconnect?: boolean }[];
}

export interface CfIngressRule {
  hostname?: string;
  service: string;
}

export interface CfAccessRule {
  email?: { email: string };
  everyone?: Record<string, never>;
  [other: string]: unknown;
}

export interface CfAccessPolicy {
  id: string;
  name: string;
  decision: string;
  include: CfAccessRule[];
  exclude?: CfAccessRule[];
  require?: CfAccessRule[];
}

export interface CfAccessApp {
  id: string;
  name: string;
  domain?: string;
  type: string;
  session_duration?: string;
  policies?: { id: string; name?: string; decision?: string; precedence?: number; include?: CfAccessRule[] }[];
}

export interface CfNotificationPolicy {
  id: string;
  name: string;
  alert_type: string;
  enabled: boolean;
  filters?: Record<string, string[]>;
  mechanisms?: Record<string, { id: string }[]>;
}

export interface CfDnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  proxied?: boolean;
  comment?: string | null;
}

export interface CfTokenStatus {
  id: string;
  status: string;
  expires_on?: string;
}

const AUTH_HINT =
  "CLOUDFLARE_API_TOKEN was rejected. Check that it is the whole token, that it is active, and that any IP filtering on it allows this network. Run: frosty init";

export class Cloudflare {
  private readonly token: string;
  private readonly fetchImpl: Fetch;
  private readonly sleep: Sleep;
  private readonly baseUrl: string;

  constructor(opts: { token: string; fetch?: Fetch; sleep?: Sleep; baseUrl?: string }) {
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? realSleep;
    this.baseUrl = opts.baseUrl ?? CLOUDFLARE_BASE_URL;
  }

  async envelope<T>(method: string, path: string, body?: unknown): Promise<Envelope<T>> {
    const response = await sendJson({
      api: "cloudflare",
      fetch: this.fetchImpl,
      sleep: this.sleep,
      url: `${this.baseUrl}${path}`,
      method,
      token: this.token,
      body,
    });
    const env = response.body as Envelope<T> | undefined;
    if (response.status >= 200 && response.status < 300 && env?.success === true) {
      return env;
    }
    const first = env?.errors?.[0];
    const message = env?.errors !== undefined && env.errors.length > 0 ? env.errors.map((e) => `${e.code} ${e.message}`).join("; ") : "no error message in the response";
    let hint: string | undefined;
    if (response.status === 401) {
      hint = AUTH_HINT;
    } else if (response.status === 403) {
      hint = "The Cloudflare token is missing a permission for this call. Compare it with the list printed by: frosty init";
    }
    throw new ApiError({
      api: "cloudflare",
      status: response.status,
      code: first === undefined ? undefined : String(first.code),
      message: redact(message),
      method,
      path,
      hint,
    });
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const env = await this.envelope<T>(method, path, body);
    return env.result;
  }

  // Page-number pagination, following result_info.total_pages; also handles cursor-paginated lists.
  async listAll<T>(path: string, query: Record<string, string | number | boolean | undefined> = {}, perPage = 50): Promise<T[]> {
    const items: T[] = [];
    let page = 1;
    let cursor: string | undefined;
    for (;;) {
      const q: Record<string, string | number | boolean | undefined> = { ...query, per_page: perPage };
      if (cursor !== undefined) {
        q["cursor"] = cursor;
      } else {
        q["page"] = page;
      }
      const env = await this.envelope<T[]>("GET", withQuery(path, q));
      const batch = Array.isArray(env.result) ? env.result : [];
      items.push(...batch);
      const info = env.result_info;
      if (info?.cursor !== undefined && info.cursor !== "" && batch.length > 0) {
        cursor = info.cursor;
        continue;
      }
      const totalPages = info?.total_pages;
      if (typeof totalPages === "number" && page < totalPages && batch.length > 0) {
        page += 1;
        continue;
      }
      return items;
    }
  }

  // User-owned and account-owned tokens are verified at different paths. Newer tokens say
  // which they are by prefix (cfut_ user, cfat_ account); older ones get the user path first.
  async verifyToken(accountId?: string): Promise<CfTokenStatus> {
    const accountPath = accountId === undefined ? undefined : `/accounts/${encodeURIComponent(accountId)}/tokens/verify`;
    if (this.token.startsWith("cfat_")) {
      if (accountPath === undefined) {
        throw new FrostyError("This is an account-owned Cloudflare token, and verifying it needs the account ID.", "Run: frosty init");
      }
      return this.request<CfTokenStatus>("GET", accountPath);
    }
    if (this.token.startsWith("cfut_")) {
      return this.request<CfTokenStatus>("GET", "/user/tokens/verify");
    }
    try {
      return await this.request<CfTokenStatus>("GET", "/user/tokens/verify");
    } catch (error) {
      if (accountPath === undefined || !(error instanceof ApiError) || (error.status !== 401 && error.status !== 403 && error.status !== 400)) {
        throw error;
      }
      return this.request<CfTokenStatus>("GET", accountPath);
    }
  }

  async findZone(domain: string): Promise<CfZone | undefined> {
    const zones = await this.listAll<CfZone>("/zones", { name: domain });
    return zones.find((zone) => zone.name === domain);
  }

  // One page is enough to tell whether the token sees more than one zone.
  async firstZones(): Promise<{ zones: CfZone[]; total: number }> {
    const env = await this.envelope<CfZone[]>("GET", withQuery("/zones", { per_page: 5 }));
    const zones = Array.isArray(env.result) ? env.result : [];
    return { zones, total: env.result_info?.total_count ?? zones.length };
  }

  listTunnels(accountId: string, query: { name?: string; is_deleted?: boolean } = {}): Promise<CfTunnel[]> {
    return this.listAll<CfTunnel>(`/accounts/${encodeURIComponent(accountId)}/cfd_tunnel`, query);
  }

  listAccessApps(accountId: string): Promise<CfAccessApp[]> {
    return this.listAll<CfAccessApp>(`/accounts/${encodeURIComponent(accountId)}/access/apps`);
  }

  listNotificationPolicies(accountId: string): Promise<CfNotificationPolicy[]> {
    return this.request<CfNotificationPolicy[]>("GET", `/accounts/${encodeURIComponent(accountId)}/alerting/v3/policies`);
  }

  listDnsRecords(zoneId: string, query: Record<string, string | number | undefined> = {}): Promise<CfDnsRecord[]> {
    return this.listAll<CfDnsRecord>(`/zones/${encodeURIComponent(zoneId)}/dns_records`, query, 100);
  }

  // Tunnels.

  async createTunnel(accountId: string, name: string): Promise<CfTunnel> {
    return this.request<CfTunnel>("POST", `${acct(accountId)}/cfd_tunnel`, { name, config_src: "cloudflare" });
  }

  getTunnel(accountId: string, tunnelId: string): Promise<CfTunnel> {
    return this.request<CfTunnel>("GET", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}`);
  }

  // The token is registered for redaction before anything else can see it.
  async getTunnelToken(accountId: string, tunnelId: string): Promise<string> {
    const token = await this.request<string>("GET", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/token`);
    registerSecret(token);
    return token;
  }

  async putTunnelIngress(accountId: string, tunnelId: string, ingress: CfIngressRule[]): Promise<void> {
    await this.request<unknown>("PUT", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/configurations`, { config: { ingress } });
  }

  async getTunnelIngress(accountId: string, tunnelId: string): Promise<CfIngressRule[]> {
    const result = await this.request<{ config?: { ingress?: CfIngressRule[] } }>("GET", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/configurations`);
    return result.config?.ingress ?? [];
  }

  async deleteTunnel(accountId: string, tunnelId: string): Promise<void> {
    // A tunnel with live connections cannot be deleted; drop them first.
    await this.request<unknown>("DELETE", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/connections`);
    await this.request<unknown>("DELETE", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}`);
  }

  // DNS.

  createDnsRecord(zoneId: string, record: { type: string; name: string; content: string; proxied: boolean; comment: string }): Promise<CfDnsRecord> {
    return this.request<CfDnsRecord>("POST", `/zones/${encodeURIComponent(zoneId)}/dns_records`, { ...record, ttl: 1 });
  }

  async deleteDnsRecord(zoneId: string, recordId: string): Promise<void> {
    await this.request<unknown>("DELETE", `/zones/${encodeURIComponent(zoneId)}/dns_records/${encodeURIComponent(recordId)}`);
  }

  // Access.

  listAccessPolicies(accountId: string): Promise<CfAccessPolicy[]> {
    return this.listAll<CfAccessPolicy>(`${acct(accountId)}/access/policies`);
  }

  createAccessPolicy(accountId: string, policy: { name: string; decision: string; include: CfAccessRule[]; session_duration?: string }): Promise<CfAccessPolicy> {
    return this.request<CfAccessPolicy>("POST", `${acct(accountId)}/access/policies`, policy);
  }

  async deleteAccessPolicy(accountId: string, policyId: string): Promise<void> {
    await this.request<unknown>("DELETE", `${acct(accountId)}/access/policies/${encodeURIComponent(policyId)}`);
  }

  getAccessApp(accountId: string, appId: string): Promise<CfAccessApp> {
    return this.request<CfAccessApp>("GET", `${acct(accountId)}/access/apps/${encodeURIComponent(appId)}`);
  }

  createAccessApp(accountId: string, app: Record<string, unknown>): Promise<CfAccessApp> {
    return this.request<CfAccessApp>("POST", `${acct(accountId)}/access/apps`, app);
  }

  async deleteAccessApp(accountId: string, appId: string): Promise<void> {
    await this.request<unknown>("DELETE", `${acct(accountId)}/access/apps/${encodeURIComponent(appId)}`);
  }

  // Notifications.

  createNotificationPolicy(accountId: string, policy: Record<string, unknown>): Promise<{ id: string }> {
    return this.request<{ id: string }>("POST", `${acct(accountId)}/alerting/v3/policies`, policy);
  }

  async deleteNotificationPolicy(accountId: string, policyId: string): Promise<void> {
    await this.request<unknown>("DELETE", `${acct(accountId)}/alerting/v3/policies/${encodeURIComponent(policyId)}`);
  }

  async countDnsRecords(zoneId: string): Promise<number> {
    const env = await this.envelope<CfDnsRecord[]>("GET", withQuery(`/zones/${encodeURIComponent(zoneId)}/dns_records`, { per_page: 5 }));
    return env.result_info?.total_count ?? (Array.isArray(env.result) ? env.result.length : 0);
  }
}

function acct(accountId: string): string {
  return `/accounts/${encodeURIComponent(accountId)}`;
}
