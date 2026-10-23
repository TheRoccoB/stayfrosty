import { ApiError, FrostyError } from "./errors.ts";
import { logDone, summarize, type ChangeLog } from "./changelog.ts";
import { realSleep, sendJson, withQuery, type Fetch, type Sleep } from "./http.ts";
import { redact, registerSecret } from "./redact.ts";

export const CLOUDFLARE_BASE_URL = "https://api.cloudflare.com/client/v4";

// Names of everything frosty creates in Cloudflare start with this.
export const NAME_PREFIX = "stayfrosty-";
// And its DNS records carry this comment.
export const DNS_COMMENT_PREFIX = "stayfrosty box ";

// The token frosty uses can change any tunnel or Access app in the account. These guards keep
// it to frosty's own: every create, change and delete checks the name on the object itself.
function ours(kind: string, name: string | undefined): void {
  if (name === undefined || !name.startsWith(NAME_PREFIX) || name.length === NAME_PREFIX.length) {
    throw new FrostyError(`frosty refused to change the ${kind} "${name ?? "?"}": it only touches names starting with ${NAME_PREFIX}.`, "This is a bug in frosty. Please report it.");
  }
}

function emailOnly(rules: CfAccessRule[] | undefined): boolean {
  return (rules ?? []).length > 0 && (rules ?? []).every((r) => Object.keys(r).length === 1 && typeof r.email?.email === "string");
}

// frosty's own kind of policy: its name, allow, only email includes, no require or exclude.
export function isOurEmailPolicy(policy: { name?: string; decision?: string; include?: CfAccessRule[]; require?: CfAccessRule[]; exclude?: CfAccessRule[] }): boolean {
  return (
    policy.name !== undefined &&
    policy.name.startsWith(NAME_PREFIX) &&
    policy.name.length > NAME_PREFIX.length &&
    policy.decision === "allow" &&
    emailOnly(policy.include) &&
    (policy.require ?? []).length === 0 &&
    (policy.exclude ?? []).length === 0
  );
}

const BOX = /^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/;

// The box a frosty name belongs to, or a refusal.
function boxOf(kind: string, name: string | undefined): string {
  ours(kind, name);
  const box = (name as string).slice(NAME_PREFIX.length);
  if (!BOX.test(box)) {
    throw new FrostyError(`frosty refused to change the ${kind} "${name ?? "?"}": "${box}" is not a box name.`, "This is a bug in frosty. Please report it.");
  }
  return box;
}

// ssh-<box>.<some domain>, never a wildcard or the apex.
function isSshHostname(hostname: string | undefined, box: string): boolean {
  return hostname !== undefined && hostname.startsWith(`ssh-${box}.`) && /^ssh-[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(hostname);
}

// What a change log keeps of an object before it is changed.
function pick(o: { id: string; name: string }): { id: string; name: string } {
  return { id: o.id, name: o.name };
}

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

  private readonly changeLog: ChangeLog | undefined;

  constructor(opts: { token: string; fetch?: Fetch; sleep?: Sleep; baseUrl?: string; changeLog?: ChangeLog | undefined }) {
    this.token = opts.token;
    this.changeLog = opts.changeLog;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? realSleep;
    this.baseUrl = opts.baseUrl ?? CLOUDFLARE_BASE_URL;
  }

  // Private, so every write goes through a method below and its guard.
  private async envelope<T>(method: string, path: string, body?: unknown, before?: unknown): Promise<Envelope<T>> {
    const write = method !== "GET";
    if (write) {
      this.changeLog?.({ phase: "intent", action: `cloudflare ${method}`, target: path, before, request: body });
    }
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
    if (write) {
      logDone(this.changeLog, { phase: "done", action: `cloudflare ${method}`, target: path, before, result: summarize(response.status, env?.result) });
    }
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

  private async request<T>(method: string, path: string, body?: unknown, before?: unknown): Promise<T> {
    const env = await this.envelope<T>(method, path, body, before);
    return env.result;
  }

  // Page-number pagination, following result_info.total_pages; also handles cursor-paginated lists.
  private async listAll<T>(path: string, query: Record<string, string | number | boolean | undefined> = {}, perPage = 50): Promise<T[]> {
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

  async listNotificationPolicies(accountId: string): Promise<CfNotificationPolicy[]> {
    const env = await this.envelope<CfNotificationPolicy[]>("GET", `/accounts/${encodeURIComponent(accountId)}/alerting/v3/policies`);
    if ((env.result_info?.total_pages ?? 1) > 1) {
      throw new FrostyError("The account has more notification policies than one page, and frosty reads only one.", "This is a bug in frosty. Please report it.");
    }
    return Array.isArray(env.result) ? env.result : [];
  }

  listDnsRecords(zoneId: string, query: Record<string, string | number | undefined> = {}): Promise<CfDnsRecord[]> {
    return this.listAll<CfDnsRecord>(`/zones/${encodeURIComponent(zoneId)}/dns_records`, query, 100);
  }

  // Tunnels.

  async createTunnel(accountId: string, name: string): Promise<CfTunnel> {
    ours("tunnel", name);
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

  // Only frosty's own shape: its box's SSH hostname to the box's sshd, everything else 404.
  async putTunnelIngress(accountId: string, tunnel: { id: string; name: string }, ingress: CfIngressRule[]): Promise<void> {
    const live = await this.getTunnel(accountId, tunnel.id);
    const box = boxOf("tunnel", live.name);
    const [first, last, ...rest] = ingress;
    if (
      rest.length > 0 ||
      first === undefined ||
      last === undefined ||
      Object.keys(first).sort().join() !== "hostname,service" ||
      first.service !== "ssh://localhost:22" ||
      !isSshHostname(first.hostname, box) ||
      Object.keys(last).join() !== "service" ||
      last.service !== "http_status:404"
    ) {
      throw new FrostyError(`frosty refused to set ingress on tunnel ${live.name}: it only sets ssh-${box}.<domain> to ssh://localhost:22 and a 404 catch-all.`, "This is a bug in frosty. Please report it.");
    }
    await this.request<unknown>("PUT", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(live.id)}/configurations`, { config: { ingress } }, pick(live));
  }

  async getTunnelIngress(accountId: string, tunnelId: string): Promise<CfIngressRule[]> {
    const result = await this.request<{ config?: { ingress?: CfIngressRule[] } }>("GET", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/configurations`);
    return result.config?.ingress ?? [];
  }

  async deleteTunnel(accountId: string, tunnel: { id: string; name: string }): Promise<void> {
    const live = await this.getTunnel(accountId, tunnel.id);
    ours("tunnel", live.name);
    const tunnelId = live.id;
    // A tunnel with live connections cannot be deleted; drop them first.
    await this.request<unknown>("DELETE", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/connections`, undefined, pick(live));
    await this.request<unknown>("DELETE", `${acct(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}`, undefined, pick(live));
  }

  // DNS.

  async createDnsRecord(zoneId: string, record: { type: string; name: string; content: string; proxied: boolean; comment: string }): Promise<CfDnsRecord> {
    const box = record.comment.startsWith(DNS_COMMENT_PREFIX) ? record.comment.slice(DNS_COMMENT_PREFIX.length) : "";
    if (
      !BOX.test(box) ||
      record.type !== "CNAME" ||
      !record.proxied ||
      !isSshHostname(record.name, box) ||
      !/^[0-9a-f-]{36}\.cfargotunnel\.com$/.test(record.content)
    ) {
      throw new FrostyError(`frosty refused to create DNS record ${record.name}: it only creates proxied CNAMEs commented "${DNS_COMMENT_PREFIX}...".`, "This is a bug in frosty. Please report it.");
    }
    return this.request<CfDnsRecord>("POST", `/zones/${encodeURIComponent(zoneId)}/dns_records`, { ...record, ttl: 1 });
  }

  async deleteDnsRecord(zoneId: string, record: { id: string; name: string; comment?: string | null }): Promise<void> {
    const live = await this.request<CfDnsRecord>("GET", `/zones/${encodeURIComponent(zoneId)}/dns_records/${encodeURIComponent(record.id)}`);
    if (live.comment?.startsWith(DNS_COMMENT_PREFIX) !== true) {
      throw new FrostyError(`frosty refused to delete DNS record ${live.name}: it is not commented "${DNS_COMMENT_PREFIX}...".`, "This is a bug in frosty. Please report it.");
    }
    await this.request<unknown>("DELETE", `/zones/${encodeURIComponent(zoneId)}/dns_records/${encodeURIComponent(live.id)}`, undefined, live);
  }

  // Access.

  listAccessPolicies(accountId: string): Promise<CfAccessPolicy[]> {
    return this.listAll<CfAccessPolicy>(`${acct(accountId)}/access/policies`);
  }

  async createAccessPolicy(accountId: string, policy: { name: string; decision: string; include: CfAccessRule[]; session_duration?: string }): Promise<CfAccessPolicy> {
    // Only "allow these emails": never bypass, everyone, groups, IdP orgs, IP ranges or service tokens.
    if (!isOurEmailPolicy(policy) || Object.keys(policy).some((k) => !["name", "decision", "include", "session_duration"].includes(k))) {
      throw new FrostyError(`frosty refused to create Access policy ${policy.name}: it only creates allow policies of plain email rules.`, "This is a bug in frosty. Please report it.");
    }
    return this.request<CfAccessPolicy>("POST", `${acct(accountId)}/access/policies`, policy);
  }

  getAccessPolicy(accountId: string, policyId: string): Promise<CfAccessPolicy> {
    return this.request<CfAccessPolicy>("GET", `${acct(accountId)}/access/policies/${encodeURIComponent(policyId)}`);
  }

  async deleteAccessPolicy(accountId: string, policy: { id: string; name: string }): Promise<void> {
    const live = await this.getAccessPolicy(accountId, policy.id);
    ours("Access policy", live.name);
    await this.request<unknown>("DELETE", `${acct(accountId)}/access/policies/${encodeURIComponent(live.id)}`, undefined, live);
  }

  getAccessApp(accountId: string, appId: string): Promise<CfAccessApp> {
    return this.request<CfAccessApp>("GET", `${acct(accountId)}/access/apps/${encodeURIComponent(appId)}`);
  }

  // Only a self-hosted app for exactly its box's SSH hostname, with only frosty's own email
  // policies, each re-read and checked. Nothing else in the body: no inline policies, no
  // wildcard, no extra domains or destinations.
  async createAccessApp(
    accountId: string,
    app: { name: string; type: string; domain: string; session_duration: string; app_launcher_visible: boolean; policies: { id: string; precedence: number }[] },
  ): Promise<CfAccessApp> {
    const box = boxOf("Access application", app.name);
    const keysOk = Object.keys(app).sort().join() === "app_launcher_visible,domain,name,policies,session_duration,type";
    const policiesOk = app.policies.length > 0 && app.policies.every((p) => Object.keys(p).sort().join() === "id,precedence" && typeof p.id === "string");
    if (!keysOk || app.type !== "self_hosted" || !isSshHostname(app.domain, box) || !policiesOk || !/^\d+(m|h)$/.test(app.session_duration)) {
      throw new FrostyError(`frosty refused to create Access application ${app.name}: it only creates a self-hosted app for ssh-${box}.<domain> with frosty's policies.`, "This is a bug in frosty. Please report it.");
    }
    for (const ref of app.policies) {
      const live = await this.getAccessPolicy(accountId, ref.id);
      if (!isOurEmailPolicy(live)) {
        throw new FrostyError(`frosty refused to attach Access policy ${live.name} to ${app.name}: it is not one of frosty's allow-by-email policies.`, "Delete that policy in the Cloudflare dashboard if frosty did not make it, then run the command again.");
      }
    }
    return this.request<CfAccessApp>("POST", `${acct(accountId)}/access/apps`, app);
  }

  async deleteAccessApp(accountId: string, app: { id: string; name: string }): Promise<void> {
    const live = await this.getAccessApp(accountId, app.id);
    ours("Access application", live.name);
    await this.request<unknown>("DELETE", `${acct(accountId)}/access/apps/${encodeURIComponent(live.id)}`, undefined, live);
  }

  // Notifications.

  // Email only, to one address: no webhooks or other destinations.
  async createNotificationPolicy(
    accountId: string,
    policy: { name: string; description: string; alert_type: string; enabled: boolean; mechanisms: { email: { id: string }[] }; filters: Record<string, string[]> },
  ): Promise<{ id: string }> {
    ours("notification", policy.name);
    const emails = policy.mechanisms.email;
    if (Object.keys(policy.mechanisms).join() !== "email" || emails.length !== 1 || Object.keys(emails[0] ?? {}).join() !== "id" || !/^[^\s@]+@[^\s@]+$/.test(emails[0]?.id ?? "")) {
      throw new FrostyError(`frosty refused to create notification ${policy.name}: it only sends email to one address.`, "This is a bug in frosty. Please report it.");
    }
    return this.request<{ id: string }>("POST", `${acct(accountId)}/alerting/v3/policies`, policy);
  }

  async deleteNotificationPolicy(accountId: string, policy: { id: string; name: string }): Promise<void> {
    const live = await this.request<CfNotificationPolicy>("GET", `${acct(accountId)}/alerting/v3/policies/${encodeURIComponent(policy.id)}`);
    ours("notification", live.name);
    await this.request<unknown>("DELETE", `${acct(accountId)}/alerting/v3/policies/${encodeURIComponent(live.id)}`, undefined, live);
  }

  async countDnsRecords(zoneId: string): Promise<number> {
    const env = await this.envelope<CfDnsRecord[]>("GET", withQuery(`/zones/${encodeURIComponent(zoneId)}/dns_records`, { per_page: 5 }));
    return env.result_info?.total_count ?? (Array.isArray(env.result) ? env.result.length : 0);
  }
}

function acct(accountId: string): string {
  return `/accounts/${encodeURIComponent(accountId)}`;
}
