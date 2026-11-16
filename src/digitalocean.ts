import { logDone, summarize, type ChangeLog } from "./changelog.ts";
import { ApiError, FrostyError } from "./errors.ts";
import { LABEL_BOX, LABEL_MANAGED, assertWindowRules, boxLabels, isUntouchable } from "./hetzner.ts";
import { realSleep, sendJson, withQuery, type Fetch, type Sleep } from "./http.ts";
import type { Action, CreateServerSpec, Firewall, FirewallId, FirewallRule, Provider, Server, SshKey } from "./provider.ts";
import { redact } from "./redact.ts";

// DigitalOcean, translated into frosty's provider model (provider.ts). The differences that matter:
// - Labels are tags. A label k=v is the tag "k:v"; frosty only ever adds tags to a droplet.
// - A cloud firewall has no labels, and its "tags" field is not a label: it applies the firewall to
//   every droplet with that tag. So frosty knows its firewall by its exact shape: the name
//   stayfrosty-<box>, applied by no tag but stayfrosty-box:<box>, and exactly frosty's outbound
//   rules. Anything else is someone else's, and frosty never writes to it.
// - A cloud firewall denies outbound traffic that no rule allows, unlike Hetzner's. frosty's always
//   carries allow-all outbound rules and never changes them; it only sets inbound rules.
// - The firewall is applied by the box's tag, so it covers the droplet from its creation, and also
//   by droplet id, so it stays on if someone removes the tag.
// - Droplets have no delete or rebuild protection. frosty never deletes a droplet tagged as adopted,
//   but nothing stops a person in the control panel. frosty doesn't adopt droplets (adopt.ts).

export const DIGITALOCEAN_BASE_URL = "https://api.digitalocean.com/v2";

const ANYWHERE = ["0.0.0.0/0", "::/0"];
// "0" is DigitalOcean's "all ports". ICMP rules have no ports.
export const OUTBOUND_RULES: DoRule[] = [
  { protocol: "tcp", ports: "0", destinations: { addresses: ANYWHERE } },
  { protocol: "udp", ports: "0", destinations: { addresses: ANYWHERE } },
  { protocol: "icmp", destinations: { addresses: ANYWHERE } },
];

const BOX = /^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/;
const TAG = /^[A-Za-z0-9:_-]{1,255}$/;

interface DoTargets {
  addresses?: string[];
  droplet_ids?: number[];
  load_balancer_uids?: string[];
  kubernetes_ids?: string[];
  tags?: string[];
}

export interface DoRule {
  protocol: string;
  // DigitalOcean returns "allow" on every rule it reads back; frosty never sends it.
  action?: string;
  ports?: string;
  sources?: DoTargets;
  destinations?: DoTargets;
}

export interface DoFirewall {
  id: string;
  name: string;
  status: string;
  created_at?: string;
  inbound_rules: DoRule[] | null;
  outbound_rules: DoRule[] | null;
  droplet_ids: number[] | null;
  tags: string[] | null;
  pending_changes?: { droplet_id: number; removing: boolean; status: string }[];
}

export interface DoDroplet {
  id: number;
  name: string;
  status: string;
  created_at: string;
  tags: string[] | null;
  size_slug: string;
  region?: { slug: string };
  networks?: { v4?: { ip_address: string; type: string }[]; v6?: { ip_address: string; type: string }[] };
}

interface DoAction {
  id: number;
  status: "in-progress" | "completed" | "errored";
  type: string;
}

// stayfrosty=1 -> "stayfrosty:1".
export function labelTag(key: string, value: string): string {
  const tag = `${key}:${value}`;
  if (key.includes(":") || !TAG.test(tag)) {
    throw new FrostyError(`frosty refused to use the DigitalOcean tag "${tag}": tags take letters, digits, colons, dashes and underscores.`, "This is a bug in frosty. Please report it.");
  }
  return tag;
}

export function labelsToTags(labels: Record<string, string>): string[] {
  return Object.entries(labels).map(([k, v]) => labelTag(k, v));
}

// Tags without a colon are not labels, and are left out.
export function tagsToLabels(tags: string[] | null | undefined): Record<string, string> {
  const labels: Record<string, string> = {};
  for (const tag of tags ?? []) {
    const at = tag.indexOf(":");
    if (at > 0) {
      labels[tag.slice(0, at)] = tag.slice(at + 1);
    }
  }
  return labels;
}

export function boxTag(box: string): string {
  return labelTag(LABEL_BOX, box);
}

// frosty's own selectors are only ever "k=v,k=v".
function parseSelector(selector: string | undefined): Record<string, string> {
  const wanted: Record<string, string> = {};
  if (selector === undefined) {
    return wanted;
  }
  for (const part of selector.split(",")) {
    const m = /^([A-Za-z0-9_-]+)=([A-Za-z0-9_-]+)$/.exec(part);
    if (m === null) {
      throw new FrostyError(`frosty can't select DigitalOcean resources by "${selector}".`, "This is a bug in frosty. Please report it.");
    }
    wanted[m[1] as string] = m[2] as string;
  }
  return wanted;
}

function selected(labels: Record<string, string>, wanted: Record<string, string>): boolean {
  return Object.entries(wanted).every(([k, v]) => labels[k] === v);
}

// Inbound rules name sources, outbound rules destinations; the other field is ignored.
function ruleKey(r: DoRule, direction: "in" | "out" = "in"): string {
  const ports = r.protocol === "icmp" ? "" : r.ports === undefined || r.ports === "" || r.ports === "all" ? "0" : r.ports;
  const t = (direction === "in" ? r.sources : r.destinations) ?? {};
  const others = [...(t.droplet_ids ?? []).map((d) => `droplet:${d}`), ...(t.load_balancer_uids ?? []).map((u) => `lb:${u}`), ...(t.kubernetes_ids ?? []).map((k) => `k8s:${k}`), ...(t.tags ?? []).map((g) => `tag:${g}`)];
  // Anything but an allow rule never matches one of frosty's (a window is always an allow).
  const protocol = r.action === undefined || r.action === "allow" ? r.protocol : `${r.action}:${r.protocol}`;
  return `${protocol}|${ports}|${[...(t.addresses ?? []).map(withPrefix), ...others].sort().join(",")}`;
}

function sameOutbound(a: DoRule[], b: DoRule[]): boolean {
  const ka = a.map((r) => ruleKey(r, "out")).sort();
  const kb = b.map((r) => ruleKey(r, "out")).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]);
}

// DigitalOcean may return a single address without its prefix length.
function withPrefix(address: string): string {
  const a = address.toLowerCase();
  if (a.includes("/")) {
    return a;
  }
  return a.includes(":") ? `${a}/128` : `${a}/32`;
}

type DropletTags = Map<number, string[]>;

// The box a firewall belongs to, if it has exactly frosty's shape (see the top of this file). Every
// droplet it is attached to by id must carry the box's tag too: a stranger attached by hand would
// otherwise get frosty's window, and lose its firewall on destroy. An id missing from
// `dropletTags` is a droplet that no longer exists (DigitalOcean drops it from the firewall a little
// after deleting it); every droplet that exists in the team is in the map.
export function frostyFirewallBox(fw: Pick<DoFirewall, "name" | "tags" | "outbound_rules" | "droplet_ids" | "inbound_rules">, dropletTags: DropletTags): string | undefined {
  const m = /^stayfrosty-(.+)$/.exec(fw.name);
  const box = m?.[1];
  if (box === undefined || !BOX.test(box)) {
    return undefined;
  }
  // frosty creates it applied by exactly the box's tag; a firewall made by hand has none.
  const tags = fw.tags ?? [];
  if (tags.length !== 1 || tags[0] !== boxTag(box)) {
    return undefined;
  }
  if (!sameOutbound(fw.outbound_rules ?? [], OUTBOUND_RULES)) {
    return undefined;
  }
  // Inbound: none, or frosty's window (TCP 22 from one address), at most one per family.
  const inbound = fw.inbound_rules ?? [];
  const windowRule = (r: DoRule): boolean => {
    const [protocol, ports, sources] = ruleKey(r, "in").split("|");
    return protocol === "tcp" && ports === "22" && /^(\d{1,3}(\.\d{1,3}){3}\/32|[0-9a-f:]+\/128)$/.test(sources ?? "");
  };
  if (inbound.length > 2 || !inbound.every(windowRule)) {
    return undefined;
  }
  const managed = labelTag(LABEL_MANAGED, "1");
  const stranger = (id: number): boolean => {
    const tags = dropletTags.get(id);
    return tags !== undefined && (!tags.includes(boxTag(box)) || !tags.includes(managed));
  };
  if ((fw.droplet_ids ?? []).some(stranger)) {
    return undefined;
  }
  return box;
}

// The inbound rules as frosty's model has them. Sources other than addresses are kept as
// "tag:..." etc., so a check sees them and assertWindowRules refuses them.
function toModelRule(r: DoRule): FirewallRule {
  const key = ruleKey(r, "in").split("|");
  return {
    direction: "in",
    protocol: r.protocol,
    port: r.protocol === "icmp" ? null : key[1] === "0" ? null : (key[1] as string),
    source_ips: (key[2] as string) === "" ? [] : (key[2] as string).split(","),
    description: null,
  };
}

function toDoInbound(r: FirewallRule): DoRule {
  return { protocol: r.protocol, ports: r.port ?? "0", sources: { addresses: [...(r.source_ips ?? [])] } };
}

function tagsOf(droplets: DoDroplet[]): DropletTags {
  return new Map(droplets.map((d) => [d.id, d.tags ?? []]));
}

function toModelFirewall(fw: DoFirewall, dropletTags: DropletTags): Firewall {
  const box = frostyFirewallBox(fw, dropletTags);
  return {
    id: fw.id,
    name: fw.name,
    labels: box === undefined ? {} : boxLabels(box),
    rules: (fw.inbound_rules ?? []).map(toModelRule),
    applied_to: [...(fw.droplet_ids ?? []).map((id) => ({ type: "server", server: { id } })), ...(fw.tags ?? []).map(() => ({ type: "label_selector" }))],
  };
}

const STATUS: Record<string, string> = { active: "running", new: "initializing", off: "off", archive: "archived" };

function attachment(fw: DoFirewall, droplet: DoDroplet): { id: FirewallId; status: string } | undefined {
  const byId = (fw.droplet_ids ?? []).includes(droplet.id);
  const byTag = (fw.tags ?? []).some((t) => (droplet.tags ?? []).includes(t));
  if (!byId && !byTag) {
    return undefined;
  }
  const pending = (fw.pending_changes ?? []).some((c) => c.droplet_id === droplet.id && c.status !== "done");
  return { id: fw.id, status: pending ? "pending" : fw.status === "succeeded" ? "applied" : fw.status };
}

function toModelServer(d: DoDroplet, firewalls: DoFirewall[]): Server {
  const v4 = d.networks?.v4?.find((n) => n.type === "public")?.ip_address;
  const v6 = d.networks?.v6?.find((n) => n.type === "public")?.ip_address;
  return {
    id: d.id,
    name: d.name,
    status: STATUS[d.status] ?? d.status,
    created: d.created_at,
    labels: tagsToLabels(d.tags),
    // DigitalOcean has no such protection; isUntouchable then rests on the adopted tag alone.
    protection: { delete: false, rebuild: false },
    server_type: { name: d.size_slug },
    location: { name: d.region?.slug ?? "?" },
    public_net: {
      ipv4: v4 === undefined ? null : { ip: v4 },
      ipv6: v6 === undefined ? null : { ip: v6 },
      firewalls: firewalls.map((f) => attachment(f, d)).filter((a): a is { id: FirewallId; status: string } => a !== undefined),
    },
    outgoing_traffic: null,
    included_traffic: null,
  };
}

function toModelAction(a: DoAction): Action {
  const status = a.status === "in-progress" ? "running" : a.status === "completed" ? "success" : "error";
  return { id: a.id, command: a.type, status, progress: status === "running" ? 0 : 100, error: status === "error" ? { code: "errored", message: "DigitalOcean reports the action errored" } : null };
}

const DONE = (command: string): Action => ({ id: 0, command, status: "success", progress: 100, error: null });

export class DigitalOcean implements Provider {
  readonly kind = "digitalocean" as const;
  readonly label = "DigitalOcean";
  readonly consoleName = "the DigitalOcean control panel";
  readonly accountName = "DigitalOcean account";
  readonly webConsoleName = "DigitalOcean Recovery Console";
  private readonly token: string;
  private readonly fetchImpl: Fetch;
  private readonly sleep: Sleep;
  private readonly baseUrl: string;
  private readonly changeLog: ChangeLog | undefined;
  private readonly backups: boolean;
  private readonly now: () => number;

  constructor(opts: { token: string; fetch?: Fetch; sleep?: Sleep; baseUrl?: string; changeLog?: ChangeLog | undefined; backups?: boolean; now?: () => number }) {
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? realSleep;
    this.baseUrl = opts.baseUrl ?? DIGITALOCEAN_BASE_URL;
    this.changeLog = opts.changeLog;
    this.backups = opts.backups === true;
    this.now = opts.now ?? Date.now;
  }

  // Private, so every write goes through a method below and its guard.
  private async request<T>(method: string, path: string, body?: unknown, before?: unknown): Promise<T> {
    const write = method !== "GET";
    if (write) {
      this.changeLog?.({ phase: "intent", action: `digitalocean ${method}`, target: path, before, request: body });
    }
    const response = await sendJson({ api: "digitalocean", fetch: this.fetchImpl, sleep: this.sleep, url: `${this.baseUrl}${path}`, method, token: this.token, body });
    if (write) {
      logDone(this.changeLog, { phase: "done", action: `digitalocean ${method}`, target: path, before, result: summarize(response.status, response.body) });
    }
    if (response.status >= 200 && response.status < 300) {
      return response.body as T;
    }
    const error = response.body as { id?: string; message?: string } | undefined;
    let hint: string | undefined;
    if (response.status === 401) {
      hint = "DIGITALOCEAN_TOKEN was rejected. Check that it is the whole token, and that it has not expired or been deleted (DigitalOcean control panel, API, Tokens).";
    } else if (response.status === 403) {
      hint = "The DigitalOcean token is missing a scope for this call. Compare its custom scopes with the list in frosty's README (Tokens).";
    }
    throw new ApiError({ api: "digitalocean", status: response.status, code: error?.id, message: redact(error?.message ?? "no error message in the response"), method, path, hint });
  }

  // Follows links.pages.next until it runs out.
  private async listAll<T>(path: string, key: string, query: Record<string, string | number | undefined> = {}): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; ; page++) {
      const body = await this.request<Record<string, unknown>>("GET", withQuery(path, { ...query, page, per_page: 200 }));
      const batch = Array.isArray(body[key]) ? (body[key] as T[]) : [];
      items.push(...batch);
      const next = (body["links"] as { pages?: { next?: unknown } } | undefined)?.pages?.next;
      if (typeof next !== "string" || batch.length === 0 || page >= 1000) {
        return items;
      }
    }
  }

  private listDoFirewalls(): Promise<DoFirewall[]> {
    return this.listAll<DoFirewall>("/firewalls", "firewalls");
  }

  private async getDoFirewall(id: FirewallId): Promise<DoFirewall> {
    const body = await this.request<{ firewall: DoFirewall }>("GET", `/firewalls/${encodeURIComponent(String(id))}`);
    return body.firewall;
  }

  // The tags of the droplets a firewall is attached to by id. One that is gone is left out.
  private async dropletTagsFor(fw: DoFirewall): Promise<DropletTags> {
    const tags: DropletTags = new Map();
    for (const id of fw.droplet_ids ?? []) {
      try {
        tags.set(id, (await this.getDroplet(id)).tags ?? []);
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 404)) {
          throw error;
        }
      }
    }
    return tags;
  }

  private async getDroplet(id: number): Promise<DoDroplet> {
    const body = await this.request<{ droplet: DoDroplet }>("GET", `/droplets/${id}`);
    return body.droplet;
  }

  async listServers(labelSelector?: string): Promise<Server[]> {
    const wanted = parseSelector(labelSelector);
    const first = Object.entries(wanted)[0];
    const [droplets, firewalls] = await Promise.all([
      this.listAll<DoDroplet>("/droplets", "droplets", first === undefined ? {} : { tag_name: labelTag(first[0], first[1]) }),
      this.listDoFirewalls(),
    ]);
    return droplets.map((d) => toModelServer(d, firewalls)).filter((s) => selected(s.labels, wanted));
  }

  async listFirewalls(labelSelector?: string): Promise<Firewall[]> {
    const wanted = parseSelector(labelSelector);
    const [firewalls, droplets] = await Promise.all([this.listDoFirewalls(), this.listAll<DoDroplet>("/droplets", "droplets")]);
    return firewalls.map((f) => toModelFirewall(f, tagsOf(droplets))).filter((f) => selected(f.labels, wanted));
  }

  async serversNamed(name: string): Promise<Server[]> {
    const [droplets, firewalls] = await Promise.all([this.listAll<DoDroplet>("/droplets", "droplets"), this.listDoFirewalls()]);
    return droplets.filter((d) => d.name === name).map((d) => toModelServer(d, firewalls));
  }

  async firewallsNamed(name: string): Promise<Firewall[]> {
    const [firewalls, droplets] = await Promise.all([this.listDoFirewalls(), this.listAll<DoDroplet>("/droplets", "droplets")]);
    return firewalls.filter((f) => f.name === name).map((f) => toModelFirewall(f, tagsOf(droplets)));
  }

  listSshKeys(): Promise<SshKey[]> {
    return this.listAll<SshKey>("/account/keys", "ssh_keys");
  }

  // DigitalOcean SSH keys have no labels.
  async createSshKey(name: string, publicKey: string): Promise<SshKey> {
    if (!/^stayfrosty-[0-9a-f]{12}$/.test(name)) {
      throw new FrostyError(`frosty refused to upload SSH key ${name}: it only uploads stayfrosty-<hash> keys.`, "This is a bug in frosty. Please report it.");
    }
    const body = await this.request<{ ssh_key: SshKey }>("POST", "/account/keys", { name, public_key: publicKey });
    return body.ssh_key;
  }

  // A tag must exist before a firewall can name it. Creating one that exists is harmless.
  private async ensureTag(tag: string): Promise<void> {
    if (!TAG.test(tag) || !tag.startsWith(`${LABEL_BOX}:`)) {
      throw new FrostyError(`frosty refused to create the DigitalOcean tag ${tag}.`, "This is a bug in frosty. Please report it.");
    }
    try {
      await this.request<unknown>("POST", "/tags", { name: tag });
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 422)) {
        throw error;
      }
    }
  }

  async createFirewall(name: string, labels: Record<string, string>, rules: FirewallRule[]): Promise<{ firewall: Firewall; actions: Action[] }> {
    const box = labels[LABEL_BOX] ?? "";
    if (labels[LABEL_MANAGED] !== "1" || !BOX.test(box) || name !== `stayfrosty-${box}`) {
      throw new FrostyError(`frosty refused to create firewall ${name}: it only creates stayfrosty-<box> firewalls for that box.`, "This is a bug in frosty. Please report it.");
    }
    assertWindowRules(name, rules);
    const tag = boxTag(box);
    await this.ensureTag(tag);
    const body = { name, inbound_rules: rules.map(toDoInbound), outbound_rules: OUTBOUND_RULES, tags: [tag], droplet_ids: [] };
    const created = await this.request<{ firewall: DoFirewall }>("POST", "/firewalls", body);
    return { firewall: toModelFirewall(created.firewall, new Map()), actions: [] };
  }

  async getFirewall(id: FirewallId): Promise<Firewall> {
    const fw = await this.getDoFirewall(id);
    return toModelFirewall(fw, await this.dropletTagsFor(fw));
  }

  // Every firewall write re-reads the firewall and acts only on frosty's own (by its shape).
  private async ourFirewall(id: FirewallId): Promise<DoFirewall & { box: string; dropletTags: DropletTags }> {
    const live = await this.getDoFirewall(id);
    const dropletTags = await this.dropletTagsFor(live);
    const box = frostyFirewallBox(live, dropletTags);
    if (box === undefined) {
      throw new FrostyError(
        `frosty refused to change firewall ${live.name} (id ${live.id}): it doesn't have the shape of frosty's (name stayfrosty-<box>, no tag but the box's, allow-all outbound, attached only to droplets tagged as the box).`,
        "If frosty made it, someone changed it in the DigitalOcean control panel. Delete it there, then run the command again.",
      );
    }
    return { ...live, box, dropletTags };
  }

  // DigitalOcean firewalls have no labels: this only checks that the caller keeps frosty's, and
  // drops the window's opening time (ls shows such a window as OPEN, without its age).
  async updateFirewallLabels(id: FirewallId, labels: Record<string, string>): Promise<Firewall> {
    const live = await this.ourFirewall(id);
    if (labels[LABEL_MANAGED] !== "1" || labels[LABEL_BOX] !== live.box) {
      throw new FrostyError(`frosty refused to relabel firewall ${live.name}: it keeps frosty's labels.`, "This is a bug in frosty. Please report it.");
    }
    return toModelFirewall(live, live.dropletTags);
  }

  // Inbound rules only, through the rules endpoints, so the outbound rules and the droplets the
  // firewall applies to are never rewritten. New rules go in before old ones come out.
  async setFirewallRules(id: FirewallId, rules: FirewallRule[]): Promise<Action[]> {
    const live = await this.ourFirewall(id);
    assertWindowRules(live.name, rules);
    const want = rules.map(toDoInbound);
    const have = live.inbound_rules ?? [];
    const key = (r: DoRule): string => ruleKey(r, "in");
    const haveKeys = new Set(have.map(key));
    const wantKeys = new Set(want.map(key));
    const add = want.filter((r) => !haveKeys.has(key(r)));
    const remove = have.filter((r) => !wantKeys.has(key(r)));
    const path = `/firewalls/${encodeURIComponent(live.id)}/rules`;
    if (add.length > 0) {
      await this.request<unknown>("POST", path, { inbound_rules: add }, { inbound_rules: have });
    }
    if (remove.length > 0) {
      await this.request<unknown>("DELETE", path, { inbound_rules: remove }, { inbound_rules: have });
    }
    return [];
  }

  // Only to the droplet tagged as the firewall's box.
  async applyFirewall(id: FirewallId, serverId: number): Promise<Action[]> {
    const live = await this.ourFirewall(id);
    const server = await this.getServer(serverId);
    if (server.labels[LABEL_MANAGED] !== "1" || server.labels[LABEL_BOX] !== live.box) {
      throw new FrostyError(`frosty refused to attach firewall ${live.name} to ${server.name}: that droplet is not box ${live.box}.`, "This is a bug in frosty. Please report it.");
    }
    await this.request<unknown>("POST", `/firewalls/${encodeURIComponent(live.id)}/droplets`, { droplet_ids: [serverId] });
    return [];
  }

  detachForeignFirewall(): Promise<Action[]> {
    throw new FrostyError("frosty detach-foreign works on Hetzner boxes only.", "Remove the other firewall in the DigitalOcean control panel (Networking, Firewalls).");
  }

  // DigitalOcean deletes a firewall that still covers droplets, which would leave them open on
  // every port. So frosty deletes it only once no droplet holds it by id or by its tag.
  async deleteFirewall(id: FirewallId): Promise<void> {
    const live = await this.ourFirewall(id);
    const tagged = await this.listAll<DoDroplet>("/droplets", "droplets", { tag_name: boxTag(live.box) });
    // live.dropletTags holds only droplets that still exist.
    const covered = [...live.dropletTags.keys(), ...tagged.map((d) => d.id)];
    if (covered.length > 0) {
      throw new FrostyError(
        `frosty refused to delete firewall ${live.name}: it still covers droplet(s) ${[...new Set(covered)].join(", ")}, which would be left with no firewall.`,
        "Delete those droplets first (frosty destroy deletes the box's own), or remove them from the firewall in the DigitalOcean control panel if they aren't frosty's.",
      );
    }
    await this.request<unknown>("DELETE", `/firewalls/${encodeURIComponent(live.id)}`, undefined, { name: live.name, inbound_rules: live.inbound_rules, droplet_ids: live.droplet_ids, tags: live.tags });
  }

  // Only a droplet named and tagged as one box, with frosty's own firewalls for that box, which
  // are attached by droplet id right after (they already cover it by its tag).
  async createServer(input: CreateServerSpec): Promise<{ server: Server; action: Action; next_actions: Action[] }> {
    const box = input.labels[LABEL_BOX] ?? "";
    if (!BOX.test(box) || input.name !== box || JSON.stringify(input.labels) !== JSON.stringify(boxLabels(box)) || input.firewallIds.length === 0) {
      throw new FrostyError(`frosty refused to create droplet ${input.name}: it only creates a droplet named and tagged as its box, behind that box's firewall.`, "This is a bug in frosty. Please report it.");
    }
    const firewalls = await Promise.all(input.firewallIds.map((id) => this.ourFirewall(id)));
    if (firewalls.some((f) => f.box !== box)) {
      throw new FrostyError(`frosty refused to create droplet ${input.name}: a firewall it was given belongs to another box.`, "This is a bug in frosty. Please report it.");
    }
    const body = {
      name: input.name,
      region: input.location,
      size: input.serverType,
      image: input.image,
      ssh_keys: input.sshKeyIds,
      user_data: input.userData,
      tags: labelsToTags(input.labels),
      ipv6: true,
      monitoring: false,
      with_droplet_agent: false,
      backups: this.backups,
    };
    const created = await this.request<{ droplet: DoDroplet; links?: { actions?: { id: number }[] } }>("POST", "/droplets", body);
    for (const fw of firewalls) {
      await this.request<unknown>("POST", `/firewalls/${encodeURIComponent(fw.id)}/droplets`, { droplet_ids: [created.droplet.id] });
    }
    const actionId = created.links?.actions?.[0]?.id;
    const action: Action = actionId === undefined ? DONE("create") : { id: actionId, command: "create", status: "running", progress: 0, error: null };
    return { server: toModelServer(created.droplet, []), action, next_actions: [] };
  }

  // frosty doesn't adopt droplets, so it never retags one.
  updateServerLabels(): Promise<Server> {
    throw new FrostyError("frosty never changes a DigitalOcean droplet's tags after creating it.", "This is a bug in frosty. Please report it.");
  }

  protectServer(): Promise<Action> {
    throw new FrostyError("DigitalOcean droplets have no delete or rebuild protection.", "This is a bug in frosty. Please report it.");
  }

  async getServer(id: number): Promise<Server> {
    const [droplet, firewalls] = await Promise.all([this.getDroplet(id), this.listDoFirewalls()]);
    return toModelServer(droplet, firewalls);
  }

  // Re-reads the droplet first: an adopted one is never deleted. Then waits until it is gone, since
  // DigitalOcean deletes without an action to follow.
  async deleteServer(id: number): Promise<Action> {
    const current = await this.getServer(id);
    if (isUntouchable(current) || current.labels[LABEL_MANAGED] !== "1") {
      throw new FrostyError(`frosty refused to delete ${current.name}: frosty didn't create it, or it is adopted.`, "Delete it yourself in the DigitalOcean control panel if you really mean to.");
    }
    await this.request<unknown>("DELETE", `/droplets/${id}`, undefined, { name: current.name, tags: Object.keys(current.labels) });
    const deadline = this.now() + 300_000;
    for (;;) {
      try {
        await this.getDroplet(id);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          return DONE("delete");
        }
        throw error;
      }
      if (this.now() >= deadline) {
        throw new FrostyError(`DigitalOcean still lists droplet ${current.name} 5 minutes after deleting it.`, "Run the command again; it resumes where it stopped.");
      }
      await this.sleep(3000);
    }
  }

  async getAction(id: number): Promise<Action> {
    const body = await this.request<{ action: DoAction }>("GET", `/actions/${id}`);
    return toModelAction(body.action);
  }

  async waitForAction(action: Action, timeoutMs = 300_000, now: () => number = this.now): Promise<Action> {
    const deadline = now() + timeoutMs;
    let current = action;
    while (current.status === "running") {
      if (now() >= deadline) {
        throw new FrostyError(`DigitalOcean action ${current.command} (${current.id}) is still running after ${Math.round(timeoutMs / 1000)}s.`, "Run the command again; it resumes where it stopped.");
      }
      await this.sleep(2000);
      current = await this.getAction(current.id);
    }
    if (current.status === "error") {
      throw new FrostyError(`DigitalOcean action ${current.command} failed.`, "Run the command again; it resumes where it stopped.");
    }
    return current;
  }
}
