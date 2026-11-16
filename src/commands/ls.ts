import { Cloudflare, NAME_PREFIX, type CfTunnel, BYPASS_POLICY_NAME } from "../cloudflare.ts";
import { loadConfig, providerKindFor, type Env } from "../config.ts";
import { DigitalOcean } from "../digitalocean.ts";
import { Hetzner, LABEL_BOX, LABEL_WINDOW_OPENED, MANAGED_SELECTOR, serverLocation } from "../hetzner.ts";
import type { Firewall, Provider, ProviderKind } from "../provider.ts";
import type { Fetch, Sleep } from "../http.ts";
import { table, yellow, type Io } from "../io.ts";
import { DIGITALOCEAN_TOKEN_ENV, HETZNER_TOKEN_ENV, loadProviderTokens } from "../tokens.ts";

export interface LsDeps {
  io: Io;
  env?: Env;
  fetch?: Fetch;
  sleep?: Sleep;
  now?: () => Date;
}

export async function runLs(deps: LsDeps): Promise<number> {
  const env = deps.env ?? process.env;
  const io = deps.io;
  const now = deps.now ?? (() => new Date());
  const tokens = loadProviderTokens(env);
  const config = await loadConfig(env, (line) => io.err(line));
  // Each provider whose token is set; the others are named, and nothing of theirs counts as a leftover.
  const providers: Provider[] = [];
  const skipped: { kind: ProviderKind; label: string; envVar: string }[] = [];
  if (tokens.hetzner !== undefined) {
    providers.push(new Hetzner({ token: tokens.hetzner, fetch: deps.fetch, sleep: deps.sleep }));
  } else {
    skipped.push({ kind: "hetzner", label: "Hetzner", envVar: HETZNER_TOKEN_ENV });
  }
  if (config.digitalocean !== undefined) {
    if (tokens.digitalocean !== undefined) {
      providers.push(new DigitalOcean({ token: tokens.digitalocean, fetch: deps.fetch, sleep: deps.sleep }));
    } else {
      skipped.push({ kind: "digitalocean", label: "DigitalOcean", envVar: DIGITALOCEAN_TOKEN_ENV });
    }
  }
  for (const s of skipped) {
    io.out(yellow(`${s.label} boxes not listed: ${s.envVar} is not set.`));
  }
  const cloudflare = new Cloudflare({ token: tokens.cloudflare, fetch: deps.fetch, sleep: deps.sleep });

  const [clouds, tunnels, apps, policies, alerts, records] = await Promise.all([
    Promise.all(
      providers.map(async (provider) => {
        const [servers, firewalls] = await Promise.all([provider.listServers(MANAGED_SELECTOR), provider.listFirewalls(MANAGED_SELECTOR)]);
        return { provider, servers, firewalls };
      }),
    ),
    cloudflare.listTunnels(config.accountId, { is_deleted: false }),
    cloudflare.listAccessApps(config.accountId),
    cloudflare.listAccessPolicies(config.accountId),
    cloudflare.listNotificationPolicies(config.accountId),
    cloudflare.listDnsRecords(config.zoneId, { "comment.startswith": "stayfrosty box " }),
  ]);
  const ourTunnels = tunnels.filter((tunnel) => tunnel.name.startsWith(NAME_PREFIX));

  const boxNames = new Set<string>();
  const rows: string[][] = [["BOX", "STATUS", "TYPE", "LOCATION", "IPV4", "TUNNEL", "WINDOW"]];
  const servers = clouds.flatMap((c) => c.servers.map((server) => ({ server, firewalls: c.firewalls })));
  for (const { server, firewalls } of [...servers].sort((a, b) => boxName(a.server.labels, a.server.name).localeCompare(boxName(b.server.labels, b.server.name)))) {
    const box = boxName(server.labels, server.name);
    boxNames.add(box);
    const firewall = firewalls.find((fw) => fw.labels[LABEL_BOX] === box);
    const tunnel = ourTunnels.find((t) => t.name === `${NAME_PREFIX}${box}`);
    rows.push([
      box,
      server.status,
      server.server_type.name,
      serverLocation(server),
      server.public_net.ipv4?.ip ?? "-",
      tunnelState(tunnel),
      windowState(firewall, now()),
    ]);
  }

  if (servers.length === 0) {
    io.out(skipped.length === 0 ? "No boxes. Create one with: frosty new <box>" : `No boxes on ${providers.map((p) => p.label).join(" or ") || "any provider frosty could list"}.`);
  } else {
    for (const line of table(rows)) {
      io.out(line);
    }
  }

  // Things frosty created whose box is gone. destroy should leave none.
  const leftovers: string[] = [];
  for (const { provider, firewalls } of clouds) {
    for (const firewall of firewalls) {
      const box = firewall.labels[LABEL_BOX];
      if (box === undefined || !boxNames.has(box)) {
        leftovers.push(`${provider.label} firewall ${firewall.name}`);
      }
    }
  }
  // stayfrosty-<box>, or a route app stayfrosty-<box>:<route>[:public]. The shared bypass policy
  // belongs to no box.
  // A box on a skipped provider wasn't listed, so its Cloudflare side is never called a leftover.
  const unseen = (box: string): boolean => !boxNames.has(box) && !skipped.some((p) => p.kind === providerKindFor(config, box));
  const orphan = (name: string): boolean => name.startsWith(NAME_PREFIX) && name !== BYPASS_POLICY_NAME && unseen(name.slice(NAME_PREFIX.length).split(":")[0] as string);
  for (const tunnel of tunnels.filter((t) => orphan(t.name))) {
    leftovers.push(`Cloudflare tunnel ${tunnel.name}`);
  }
  for (const app of apps.filter((a) => orphan(a.name))) {
    leftovers.push(`Cloudflare Access application ${app.name}`);
  }
  for (const policy of policies.filter((p) => orphan(p.name))) {
    leftovers.push(`Cloudflare Access policy ${policy.name}`);
  }
  for (const alert of alerts.filter((a) => orphan(a.name))) {
    leftovers.push(`Cloudflare notification ${alert.name}`);
  }
  for (const record of records.filter((r) => unseen((r.comment ?? "").slice("stayfrosty box ".length)))) {
    leftovers.push(`Cloudflare DNS record ${record.type} ${record.name}`);
  }
  if (leftovers.length > 0) {
    io.out("");
    io.out(yellow("Leftovers with no box (remove them with: frosty destroy <box>):"));
    for (const item of leftovers) {
      io.out(`  ${item}`);
    }
  }
  return 0;
}

function boxName(labels: Record<string, string>, fallback: string): string {
  return labels[LABEL_BOX] ?? fallback;
}

function tunnelState(tunnel: CfTunnel | undefined): string {
  if (tunnel === undefined) {
    return "none";
  }
  return tunnel.status;
}

export function windowState(firewall: Firewall | undefined, now: Date): string {
  if (firewall === undefined) {
    return yellow("no firewall");
  }
  const inbound = firewall.rules.filter((rule) => rule.direction === "in");
  if (inbound.length === 0) {
    return "closed";
  }
  const opened = firewall.labels[LABEL_WINDOW_OPENED];
  const seconds = opened === undefined ? NaN : Number(opened);
  if (!Number.isFinite(seconds)) {
    return yellow("OPEN");
  }
  return yellow(`OPEN ${formatAge(now.getTime() - seconds * 1000)}`);
}

export function formatAge(ms: number): string {
  const minutes = Math.max(0, Math.floor(ms / 60_000));
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    return `${hours}h${minutes % 60 === 0 ? "" : `${minutes % 60}m`}`;
  }
  return `${Math.floor(hours / 24)}d`;
}
