import { ApiError, FrostyError } from "./errors.ts";
import { realSleep, sendJson, withQuery, type Fetch, type Sleep } from "./http.ts";
import { redact } from "./redact.ts";

export const HETZNER_BASE_URL = "https://api.hetzner.cloud/v1";

// Labels that mark everything frosty created. Anything without them is never touched.
export const LABEL_MANAGED = "stayfrosty";
export const LABEL_BOX = "stayfrosty-box";
export const MANAGED_SELECTOR = `${LABEL_MANAGED}=1`;
// Firewall label set when a window opens, so its age survives across laptops.
export const LABEL_WINDOW_OPENED = "stayfrosty-window-opened";
export const WINDOW_DESCRIPTION = "stayfrosty window";

export interface HzServer {
  id: number;
  name: string;
  status: string;
  created: string;
  labels: Record<string, string>;
  server_type: { name: string };
  location?: { name: string };
  public_net: {
    ipv4: { ip: string } | null;
    ipv6: { ip: string } | null;
    firewalls?: { id: number; status: string }[];
  };
  outgoing_traffic?: number | null;
  included_traffic?: number | null;
}

export interface HzFirewallRule {
  direction: "in" | "out";
  protocol: string;
  port?: string | null;
  source_ips?: string[];
  destination_ips?: string[];
  description?: string | null;
}

export interface HzFirewall {
  id: number;
  name: string;
  labels: Record<string, string>;
  rules: HzFirewallRule[];
  applied_to: { type: string; server?: { id: number } }[];
}

export interface HzLocation {
  id: number;
  name: string;
  description: string;
  city: string;
  country: string;
  network_zone: string;
}

export interface HzPrice {
  location: string;
  price_monthly: { gross: string; net: string };
  included_traffic?: number;
  price_per_tb_traffic?: { gross: string; net: string };
}

export interface HzServerType {
  id: number;
  name: string;
  description: string;
  cores: number;
  memory: number;
  disk: number;
  architecture: string;
  cpu_type: string;
  // Top-level deprecation fields are going away; per-location `locations[].deprecation` replaces them.
  deprecated?: boolean | null;
  deprecation?: unknown;
  prices: HzPrice[];
  locations?: { id: number; name: string; available?: boolean; deprecation?: unknown }[];
}

export interface HzImage {
  id: number;
  name: string | null;
  description: string;
  type: string;
  status: string;
  os_flavor: string;
  os_version: string | null;
  architecture: string;
  // `deprecated` is removed on 2026-11-02 in favor of `deprecation`; read both.
  deprecated?: string | null;
  deprecation?: unknown;
}

export interface HzSshKey {
  id: number;
  name: string;
  fingerprint: string;
  public_key: string;
}

const READ_ONLY_HINT =
  "The Hetzner token looks read-only. Create a Read & Write token in the Hetzner Cloud Console (Security, API tokens) and set HCLOUD_TOKEN to it.";

export class Hetzner {
  private readonly token: string;
  private readonly fetchImpl: Fetch;
  private readonly sleep: Sleep;
  private readonly baseUrl: string;

  constructor(opts: { token: string; fetch?: Fetch; sleep?: Sleep; baseUrl?: string }) {
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? realSleep;
    this.baseUrl = opts.baseUrl ?? HETZNER_BASE_URL;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await sendJson({
      api: "hetzner",
      fetch: this.fetchImpl,
      sleep: this.sleep,
      url: `${this.baseUrl}${path}`,
      method,
      token: this.token,
      body,
    });
    if (response.status >= 200 && response.status < 300) {
      return response.body as T;
    }
    const error = (response.body as { error?: { code?: string; message?: string } } | undefined)?.error;
    const code = error?.code;
    let hint: string | undefined;
    if (response.status === 401) {
      hint = "HCLOUD_TOKEN was rejected. Check that it is the whole token and that it has not been deleted in the Hetzner Cloud Console.";
    } else if (code === "token_readonly" || (response.status === 403 && method !== "GET")) {
      hint = READ_ONLY_HINT;
    }
    throw new ApiError({
      api: "hetzner",
      status: response.status,
      code,
      message: redact(error?.message ?? "no error message in the response"),
      method,
      path,
      hint,
    });
  }

  // Follows meta.pagination.next_page until it runs out.
  async listAll<T>(path: string, key: string, query: Record<string, string | number | undefined> = {}): Promise<T[]> {
    const items: T[] = [];
    let page: number | null = 1;
    while (page !== null) {
      const body: Record<string, unknown> = await this.request<Record<string, unknown>>("GET", withQuery(path, { ...query, page, per_page: 50 }));
      const batch = body[key];
      if (Array.isArray(batch)) {
        items.push(...(batch as T[]));
      }
      const meta = body["meta"] as { pagination?: { next_page?: number | null } } | undefined;
      const next = meta?.pagination?.next_page;
      page = typeof next === "number" && next > (page ?? 0) ? next : null;
    }
    return items;
  }

  listServers(labelSelector?: string): Promise<HzServer[]> {
    return this.listAll<HzServer>("/servers", "servers", { label_selector: labelSelector });
  }

  listFirewalls(labelSelector?: string): Promise<HzFirewall[]> {
    return this.listAll<HzFirewall>("/firewalls", "firewalls", { label_selector: labelSelector });
  }

  listLocations(): Promise<HzLocation[]> {
    return this.listAll<HzLocation>("/locations", "locations");
  }

  listServerTypes(): Promise<HzServerType[]> {
    return this.listAll<HzServerType>("/server_types", "server_types");
  }

  listSystemImages(architecture?: string): Promise<HzImage[]> {
    return this.listAll<HzImage>("/images", "images", { type: "system", architecture, status: "available" });
  }

  listSshKeys(): Promise<HzSshKey[]> {
    return this.listAll<HzSshKey>("/ssh_keys", "ssh_keys");
  }

  async createSshKey(name: string, publicKey: string, labels: Record<string, string>): Promise<HzSshKey> {
    const body = await this.request<{ ssh_key: HzSshKey }>("POST", "/ssh_keys", { name, public_key: publicKey, labels });
    return body.ssh_key;
  }

  async createFirewall(name: string, labels: Record<string, string>, rules: HzFirewallRule[]): Promise<{ firewall: HzFirewall; actions: HzAction[] }> {
    return this.request<{ firewall: HzFirewall; actions: HzAction[] }>("POST", "/firewalls", { name, labels, rules });
  }

  async updateFirewallLabels(id: number, labels: Record<string, string>): Promise<HzFirewall> {
    const body = await this.request<{ firewall: HzFirewall }>("PUT", `/firewalls/${id}`, { labels });
    return body.firewall;
  }

  async setFirewallRules(id: number, rules: HzFirewallRule[]): Promise<HzAction[]> {
    const body = await this.request<{ actions: HzAction[] }>("POST", `/firewalls/${id}/actions/set_rules`, { rules });
    return body.actions;
  }

  async applyFirewall(id: number, serverId: number): Promise<HzAction[]> {
    const body = await this.request<{ actions: HzAction[] }>("POST", `/firewalls/${id}/actions/apply_to_resources`, {
      apply_to: [{ type: "server", server: { id: serverId } }],
    });
    return body.actions;
  }

  async deleteFirewall(id: number): Promise<void> {
    await this.request<unknown>("DELETE", `/firewalls/${id}`);
  }

  async createServer(input: CreateServerInput): Promise<{ server: HzServer; action: HzAction; next_actions: HzAction[] }> {
    return this.request<{ server: HzServer; action: HzAction; next_actions: HzAction[] }>("POST", "/servers", {
      name: input.name,
      server_type: input.serverType,
      image: input.image,
      location: input.location,
      ssh_keys: input.sshKeyIds,
      user_data: input.userData,
      labels: input.labels,
      firewalls: input.firewallIds.map((firewall) => ({ firewall })),
      public_net: { enable_ipv4: true, enable_ipv6: true },
      start_after_create: true,
    });
  }

  async getServer(id: number): Promise<HzServer> {
    const body = await this.request<{ server: HzServer }>("GET", `/servers/${id}`);
    return body.server;
  }

  async deleteServer(id: number): Promise<HzAction> {
    const body = await this.request<{ action: HzAction }>("DELETE", `/servers/${id}`);
    return body.action;
  }

  async getAction(id: number): Promise<HzAction> {
    const body = await this.request<{ action: HzAction }>("GET", `/actions/${id}`);
    return body.action;
  }

  // Polls GET /actions/{id} until the action leaves "running".
  async waitForAction(action: HzAction, timeoutMs = 300_000, now: () => number = Date.now): Promise<HzAction> {
    const deadline = now() + timeoutMs;
    let current = action;
    while (current.status === "running") {
      if (now() >= deadline) {
        throw new FrostyError(`Hetzner action ${current.command} (${current.id}) is still running after ${Math.round(timeoutMs / 1000)}s.`, "Run the command again; it resumes where it stopped.");
      }
      await this.sleep(2000);
      current = await this.getAction(current.id);
    }
    if (current.status === "error") {
      const reason = current.error === null ? "no reason given" : `${current.error.code}: ${current.error.message}`;
      throw new FrostyError(`Hetzner action ${current.command} failed: ${reason}.`, "Run the command again; it resumes where it stopped.");
    }
    return current;
  }
}

export interface HzAction {
  id: number;
  command: string;
  status: "running" | "success" | "error";
  progress: number;
  error: { code: string; message: string } | null;
}

export interface CreateServerInput {
  name: string;
  serverType: string;
  image: string;
  location: string;
  sshKeyIds: number[];
  userData: string;
  labels: Record<string, string>;
  firewallIds: number[];
}

export function boxLabels(box: string, extra: Record<string, string> = {}): Record<string, string> {
  return { [LABEL_MANAGED]: "1", [LABEL_BOX]: box, ...extra };
}

export function boxSelector(box: string): string {
  return `${MANAGED_SELECTOR},${LABEL_BOX}=${box}`;
}

export function serverLocation(server: HzServer): string {
  return server.location?.name ?? "?";
}
