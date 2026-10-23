import { BYPASS_POLICY_NAME, DNS_COMMENT_PREFIX, NAME_PREFIX, isOurBypassPolicy, isOurEmailPolicy, type CfAccessApp, type CfAccessPolicy, type CfDnsRecord, type CfIngressRule, type CfNotificationPolicy, type CfTunnel, type IngressSpec } from "./cloudflare.ts";
import { accessUri, boxIngress, bypassPaths, frostyProtected, inZones, isRouteAppOf, publicAppName, routeAppName, sameIngressRules, type IngressRule, type Route } from "./routes.ts";
import { runOrFail, type SshTarget } from "./box.ts";
import { sshHostname, type Context } from "./context.ts";
import { FrostyError } from "./errors.ts";

// The Cloudflare side of a box. Cloudflare has no labels, so frosty's resources are found by
// name (stayfrosty-<box>) and the DNS record by its comment.

export function edgeName(box: string): string {
  return `${NAME_PREFIX}${box}`;
}

export function dnsComment(box: string): string {
  return `${DNS_COMMENT_PREFIX}${box}`;
}

export function expectedIngress(hostname: string): CfIngressRule[] {
  return [{ hostname, service: "ssh://localhost:22" }, { service: "http_status:404" }];
}

export function boxRoutes(ctx: Context, box: string): Route[] {
  return ctx.config.routes?.[box] ?? [];
}

// The Access apps a route needs: frosty's (protected prefixes), frosty's public one (bypasses), and
// any external app named in externalAccess. Missing ones are undefined.
export interface RouteApps {
  route: Route;
  app: CfAccessApp | undefined;
  publicApp: CfAccessApp | undefined;
  external: Record<string, CfAccessApp | undefined>;
}

export function routeApps(apps: CfAccessApp[], box: string, route: Route): RouteApps {
  const byName = (name: string): CfAccessApp | undefined => apps.find((a) => a.name === name);
  return {
    route,
    app: byName(routeAppName(box, route)),
    publicApp: byName(publicAppName(box, route)),
    external: Object.fromEntries(Object.entries(route.externalAccess ?? {}).map(([p, name]) => [p, byName(name)])),
  };
}

// The Access audience cloudflared checks for each protected prefix, or undefined while any app the
// route needs is missing (then the route stays out of the ingress: its paths 404).
export function routeAuds(r: RouteApps): Record<string, string[]> | undefined {
  const auds: Record<string, string[]> = {};
  for (const prefix of r.route.protected) {
    const app = r.route.externalAccess?.[prefix] !== undefined ? r.external[prefix] : r.app;
    if (app?.aud === undefined) {
      return undefined;
    }
    auds[prefix] = [app.aud];
  }
  if (bypassPaths(r.route).length > 0 && r.publicApp === undefined) {
    return undefined;
  }
  return auds;
}

export function ingressSpec(ctx: Context, box: string, apps: CfAccessApp[]): IngressSpec {
  const routes: IngressSpec["routes"] = [];
  for (const route of boxRoutes(ctx, box)) {
    const auds = routeAuds(routeApps(apps, box, route));
    if (auds !== undefined) {
      routes.push({ route, auds });
    }
  }
  return { sshHostname: sshHostname(ctx, box), teamName: ctx.config.accessTeam ?? "", appZones: ctx.config.appZones ?? [], routes };
}

export function specIngress(spec: IngressSpec): IngressRule[] {
  return boxIngress(spec.sshHostname, spec.routes.map(({ route, auds }) => ({ route, audFor: (p: string) => auds[p] ?? [] })), spec.teamName);
}

export interface Edge {
  tunnel: CfTunnel | undefined;
  dns: CfDnsRecord[];
  foreignDns: CfDnsRecord[];
  app: CfAccessApp | undefined;
  // stayfrosty-<box>:<route>[:public]: Access apps of the box's app routes.
  routeApps: CfAccessApp[];
  policy: CfAccessPolicy | undefined;
  alert: CfNotificationPolicy | undefined;
}

export async function findEdge(ctx: Context, box: string): Promise<Edge> {
  const { cloudflare, config } = ctx;
  const name = edgeName(box);
  const hostname = sshHostname(ctx, box);
  const [tunnels, records, apps, policies, alerts] = await Promise.all([
    cloudflare.listTunnels(config.accountId, { name, is_deleted: false }),
    cloudflare.listDnsRecords(config.zoneId, { name: hostname }),
    cloudflare.listAccessApps(config.accountId),
    cloudflare.listAccessPolicies(config.accountId),
    cloudflare.listNotificationPolicies(config.accountId),
  ]);
  return {
    tunnel: tunnels.find((t) => t.name === name),
    dns: records.filter((r) => r.comment === dnsComment(box)),
    foreignDns: records.filter((r) => r.comment !== dnsComment(box)),
    app: apps.find((a) => a.name === name),
    routeApps: apps.filter((a) => isRouteAppOf(box, a.name)),
    policy: policies.find((p) => p.name === name),
    alert: alerts.find((a) => a.name === name),
  };
}

export function edgeIsEmpty(edge: Edge): boolean {
  return edge.tunnel === undefined && edge.dns.length === 0 && edge.app === undefined && edge.routeApps.length === 0 && edge.policy === undefined && edge.alert === undefined;
}

// Step 7: the tunnel and its ingress, managed from Cloudflare.
export async function ensureTunnel(ctx: Context, box: string, existing: CfTunnel | undefined): Promise<CfTunnel> {
  const { cloudflare, config, io } = ctx;
  let tunnel = existing;
  if (tunnel === undefined) {
    io.out(`Creating tunnel ${edgeName(box)}.`);
    tunnel = await cloudflare.createTunnel(config.accountId, edgeName(box));
  }
  await ensureIngress(ctx, box, tunnel);
  return tunnel;
}

// SSH, plus every configured route whose Access apps exist, plus the 404s. Idempotent.
export async function ensureIngress(ctx: Context, box: string, tunnel: CfTunnel): Promise<void> {
  const { cloudflare, config, io } = ctx;
  const spec = boxRoutes(ctx, box).length === 0 ? ingressSpec(ctx, box, []) : ingressSpec(ctx, box, await cloudflare.listAccessApps(config.accountId));
  const have = await cloudflare.getTunnelIngress(config.accountId, tunnel.id);
  // Rules frosty could have written: the SSH host, app hosts in appZones (current or removed
  // routes), and the catch-all. Anything else came from someone else, and frosty won't overwrite it.
  const foreign = have.filter((r) => r.hostname !== undefined && r.hostname !== spec.sshHostname && !inZones(r.hostname, spec.appZones));
  if (foreign.length > 0) {
    throw new FrostyError(
      `Tunnel ${tunnel.name} routes ${[...new Set(foreign.map((r) => r.hostname))].join(", ")}, which frosty didn't set up.`,
      "Remove those rules in the Cloudflare dashboard (Zero Trust, Networks, Tunnels), or add the hostname to appZones and routes, then run the command again.",
    );
  }
  if (!sameIngressRules(have, specIngress(spec))) {
    const routes = spec.routes.map((r) => `${r.route.hostname} (${[...r.route.public, ...r.route.protected].length} paths)`);
    io.out(`Setting the tunnel's ingress: ${sshHostname(ctx, box)} to ssh://localhost:22${routes.length > 0 ? `, ${routes.join(", ")}` : ""}, everything else 404.`);
    await cloudflare.putTunnelIngress(config.accountId, tunnel, spec);
  }
}

export function sameIngress(a: CfIngressRule[], b: CfIngressRule[]): boolean {
  return sameIngressRules(a, b as IngressRule[]);
}

// frosty route sync: each route's Access apps first, then the ingress that routes their paths, then
// remove apps of routes no longer in config (their paths already left the ingress).
export async function syncRoutes(ctx: Context, box: string, tunnel: CfTunnel): Promise<void> {
  const { cloudflare, config, io } = ctx;
  const routes = boxRoutes(ctx, box);
  const [apps, policies] = await Promise.all([cloudflare.listAccessApps(config.accountId), cloudflare.listAccessPolicies(config.accountId)]);
  const emailPolicy = policies.find((p) => p.name === edgeName(box));
  if (routes.length > 0 && (emailPolicy === undefined || !isOurEmailPolicy(emailPolicy) || !sameEmails(emailPolicy.include.map((r) => r.email?.email ?? ""), config.accessEmails))) {
    throw new FrostyError(`Access policy ${edgeName(box)} is missing or not an allow policy for exactly ${config.accessEmails.join(", ")}.`, `Run: frosty verify ${box}, and fix the box's own Access first.`);
  }
  let bypass = policies.find((p) => p.name === BYPASS_POLICY_NAME);
  if (bypass !== undefined && !isOurBypassPolicy(bypass)) {
    throw new FrostyError(`Access policy ${BYPASS_POLICY_NAME} is not frosty's bypass shape (decision bypass, include everyone, nothing else).`, "Delete it in the Cloudflare dashboard, then run the command again.");
  }
  const base = { box, appZones: config.appZones ?? [], domain: config.domain, sessionDuration: config.accessSessionDuration };
  for (const route of routes) {
    const have = routeApps(apps, box, route);
    for (const [prefix, name] of Object.entries(route.externalAccess ?? {})) {
      const listedExt = have.external[prefix];
      const ext = listedExt === undefined ? undefined : await cloudflare.getAccessApp(config.accountId, listedExt.id);
      if (ext === undefined || !appCovers(ext, accessUri(route.hostname, prefix))) {
        throw new FrostyError(`Access app ${name} must exist and cover ${accessUri(route.hostname, prefix)} (externalAccess for ${route.name}).`, "frosty doesn't change that app. Fix it in the Cloudflare dashboard, or take the path out of externalAccess.");
      }
      const bad = externalPolicyProblems(ext);
      if (bad.length > 0) {
        throw new FrostyError(`Access app ${name} doesn't only let identified people in: ${bad.join("; ")}.`, "frosty doesn't change that app. Fix its policies in the Cloudflare dashboard, or take the path out of externalAccess.");
      }
      io.out(`Access app ${name} (not frosty's) covers ${accessUri(route.hostname, prefix)} and lets in ${describeIncludes(ext)}.`);
    }
    if (frostyProtected(route).length > 0) {
      const want = frostyProtected(route).map((p) => accessUri(route.hostname, p));
      if (have.app === undefined || !appMatches(await cloudflare.getAccessApp(config.accountId, have.app.id), want, [(emailPolicy as CfAccessPolicy).id])) {
        io.out(`${have.app === undefined ? "Creating" : "Updating"} Access application ${routeAppName(box, route)} for ${want.join(", ")}.`);
        await cloudflare.putRouteAccessApp(config.accountId, { ...base, route, kind: "protected", policyIds: [(emailPolicy as CfAccessPolicy).id] }, have.app?.id);
      }
    }
    if (bypassPaths(route).length > 0) {
      if (bypass === undefined) {
        io.out(`Creating Access policy ${BYPASS_POLICY_NAME} (for public paths under a protected prefix only).`);
        bypass = await cloudflare.createBypassPolicy(config.accountId);
      }
      const want = bypassPaths(route).map((p) => accessUri(route.hostname, p));
      if (have.publicApp === undefined || !appMatches(await cloudflare.getAccessApp(config.accountId, have.publicApp.id), want, [bypass.id])) {
        io.out(`${have.publicApp === undefined ? "Creating" : "Updating"} Access application ${publicAppName(box, route)} (bypass) for ${want.join(", ")}.`);
        await cloudflare.putRouteAccessApp(config.accountId, { ...base, route, kind: "public", policyIds: [bypass.id] }, have.publicApp?.id);
      }
    }
  }
  await ensureIngress(ctx, box, tunnel);
  const wanted = new Set(routes.flatMap((r) => [...(frostyProtected(r).length > 0 ? [routeAppName(box, r)] : []), ...(bypassPaths(r).length > 0 ? [publicAppName(box, r)] : [])]));
  for (const app of apps.filter((a) => isRouteAppOf(box, a.name) && !wanted.has(a.name))) {
    io.out(`Deleting Access application ${app.name}: its route is no longer in config.`);
    await cloudflare.deleteAccessApp(config.accountId, app);
  }
}

function appUris(app: CfAccessApp): string[] {
  const uris = (app.destinations ?? []).map((d) => d.uri).filter((u): u is string => u !== undefined);
  return uris.length > 0 ? uris : app.domain === undefined ? [] : [app.domain];
}

// What's wrong with an external app's policies for guarding a protected path: frosty doesn't own
// it, but it must still only let identified people in (allow, no everyone, IP ranges or tokens).
export function externalPolicyProblems(app: CfAccessApp): string[] {
  const problems: string[] = [];
  const policies = app.policies ?? [];
  if (policies.length === 0) {
    problems.push(`${app.name} has no policies`);
  }
  for (const p of policies) {
    if (p.decision !== "allow") {
      problems.push(`${app.name} policy ${p.name ?? p.id} decides ${p.decision ?? "?"}`);
    }
    for (const rule of p.include ?? []) {
      const kind = Object.keys(rule).join("/");
      if (!["email", "email_domain", "github-organization", "group", "gsuite", "okta", "azureAD", "saml", "oidc"].includes(kind)) {
        problems.push(`${app.name} policy ${p.name ?? p.id} includes a ${kind} rule`);
      }
    }
  }
  return problems;
}

// "email: 2, github-organization: 1": what an external app lets in, for verify and plan.
export function describeIncludes(app: CfAccessApp): string {
  const counts = new Map<string, number>();
  for (const p of app.policies ?? []) {
    for (const rule of p.include ?? []) {
      const kind = Object.keys(rule).join("/");
      counts.set(kind, (counts.get(kind) ?? 0) + 1);
    }
  }
  return [...counts].map(([k, n]) => `${k}: ${n}`).join(", ") || "nobody";
}

// An app covers a URI if one of its destinations is that URI or a path prefix of it.
export function appCovers(app: CfAccessApp, uri: string): boolean {
  return appUris(app).some((u) => uri === u || uri.startsWith(`${u}/`));
}

export function appMatches(app: CfAccessApp, uris: string[], policyIds: string[]): boolean {
  const same = (a: string[], b: string[]): boolean => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);
  return app.type === "self_hosted" && same(appUris(app), uris) && same((app.policies ?? []).map((p) => p.id), policyIds);
}

// Step 8: the token goes over SSH on stdin into a root-only file. systemd hands it to
// cloudflared as a credential, so it is never on a command line or in an environment.
export async function installConnector(ctx: Context, target: SshTarget, tunnelId: string): Promise<string> {
  const token = await ctx.cloudflare.getTunnelToken(ctx.config.accountId, tunnelId);
  ctx.io.out("Installing the tunnel token on the box (root-only file, sent over SSH on stdin).");
  await runOrFail(
    ctx.ssh,
    target,
    "sudo install -d -m 0700 -o root -g root /etc/cloudflared && sudo sh -c 'umask 077; cat > /etc/cloudflared/token.new && mv /etc/cloudflared/token.new /etc/cloudflared/token'",
    "Writing the tunnel token",
    { stdin: token },
  );
  await runOrFail(ctx.ssh, target, "sudo systemctl daemon-reload && sudo systemctl enable cloudflared.service && sudo systemctl restart cloudflared.service", "Starting cloudflared");
  return token;
}

// Step 9: a proxied CNAME to the tunnel. Never an A record with the box's IP.
export async function ensureDns(ctx: Context, box: string, tunnelId: string, edge: Edge): Promise<CfDnsRecord> {
  const { cloudflare, config, io } = ctx;
  const hostname = sshHostname(ctx, box);
  if (edge.foreignDns.length > 0) {
    throw new FrostyError(
      `${hostname} already has a DNS record that frosty did not create (${edge.foreignDns.map((r) => r.type).join(", ")}).`,
      "Delete it in the Cloudflare dashboard if it is not needed, or pick another box name. frosty never touches what it did not create.",
    );
  }
  const content = `${tunnelId}.cfargotunnel.com`;
  const good = edge.dns.find((r) => r.type === "CNAME" && r.content === content && r.proxied === true);
  for (const stale of edge.dns.filter((r) => r !== good)) {
    io.out(`Removing stale DNS record ${stale.type} ${stale.name}.`);
    await cloudflare.deleteDnsRecord(config.zoneId, stale);
  }
  if (good !== undefined) {
    return good;
  }
  io.out(`Creating DNS record ${hostname}: proxied CNAME to the tunnel.`);
  return cloudflare.createDnsRecord(config.zoneId, { type: "CNAME", name: hostname, content, proxied: true, comment: dnsComment(box) });
}

// Step 10: a reusable allow policy for the configured emails, and a self-hosted app for the
// SSH hostname that uses it.
export async function ensureAccess(ctx: Context, box: string, edge: Edge): Promise<{ app: CfAccessApp; policy: CfAccessPolicy }> {
  const { cloudflare, config, io } = ctx;
  let policy = edge.policy;
  // A policy with frosty's name is reused only if it is still frosty's kind: allow, emails only.
  if (policy !== undefined && (!isOurEmailPolicy(policy) || !sameEmails(policy.include.map((r) => r.email?.email ?? ""), config.accessEmails))) {
    throw new FrostyError(
      `Access policy ${policy.name} is not an allow policy for exactly ${config.accessEmails.join(", ")}, so frosty will not attach it.`,
      "Delete it in the Cloudflare dashboard (Access, Policies), then run the command again with --resume. frosty creates a fresh one.",
    );
  }
  if (policy === undefined) {
    io.out(`Creating Access policy ${edgeName(box)}: allow ${config.accessEmails.join(", ")}.`);
    policy = await cloudflare.createAccessPolicy(config.accountId, {
      name: edgeName(box),
      decision: "allow",
      include: config.accessEmails.map((email) => ({ email: { email } })),
    });
  }
  let app = edge.app;
  if (app === undefined) {
    io.out(`Creating Access application ${edgeName(box)} for ${sshHostname(ctx, box)}.`);
    app = await cloudflare.createAccessApp(config.accountId, {
      name: edgeName(box),
      type: "self_hosted",
      domain: sshHostname(ctx, box),
      session_duration: config.accessSessionDuration,
      app_launcher_visible: false,
      policies: [{ id: policy.id, precedence: 1 }],
    });
  }
  return { app, policy };
}

// Step 11: email when the tunnel's health changes.
export async function ensureAlert(ctx: Context, box: string, tunnelId: string, edge: Edge): Promise<void> {
  if (edge.alert !== undefined) {
    return;
  }
  ctx.io.out(`Creating notification ${edgeName(box)}: email ${ctx.config.alertEmail} when the tunnel's health changes.`);
  await ctx.cloudflare.createNotificationPolicy(ctx.config.accountId, {
    name: edgeName(box),
    description: `stayfrosty: tunnel health for box ${box}`,
    alert_type: "tunnel_health_event",
    enabled: true,
    mechanisms: { email: [{ id: ctx.config.alertEmail }] },
    filters: { tunnel_id: [tunnelId] },
  });
}

// Step 12.
export async function waitForHealthyTunnel(ctx: Context, tunnelId: string, timeoutMs = 3 * 60_000): Promise<void> {
  const deadline = ctx.now() + timeoutMs;
  for (;;) {
    const tunnel = await ctx.cloudflare.getTunnel(ctx.config.accountId, tunnelId);
    if (tunnel.status === "healthy") {
      return;
    }
    if (ctx.now() >= deadline) {
      throw new FrostyError(
        `The tunnel is still ${tunnel.status} after ${Math.round(timeoutMs / 60_000)} minutes.`,
        "cloudflared on the box may not be running. The window is still open, so look with: ssh to the box's IP, then sudo journalctl -u cloudflared -n 50. Then run frosty new <box> --resume.",
      );
    }
    await ctx.sleep(5000);
  }
}

// For destroy: the alert first, so deleting the box does not email a tunnel-down alert.
export async function removeEdge(ctx: Context, edge: Edge): Promise<void> {
  const { cloudflare, config, io } = ctx;
  if (edge.alert !== undefined) {
    io.out(`Deleting notification ${edge.alert.name}.`);
    await cloudflare.deleteNotificationPolicy(config.accountId, edge.alert);
  }
  if (edge.app !== undefined) {
    io.out(`Deleting Access application ${edge.app.name}.`);
    await cloudflare.deleteAccessApp(config.accountId, edge.app);
  }
  for (const app of edge.routeApps) {
    io.out(`Deleting Access application ${app.name}.`);
    await cloudflare.deleteAccessApp(config.accountId, app);
  }
  if (edge.policy !== undefined) {
    io.out(`Deleting Access policy ${edge.policy.name}.`);
    await cloudflare.deleteAccessPolicy(config.accountId, edge.policy);
  }
  for (const record of edge.dns) {
    io.out(`Deleting DNS record ${record.type} ${record.name}.`);
    await cloudflare.deleteDnsRecord(config.zoneId, record);
  }
}

export async function removeTunnel(ctx: Context, edge: Edge): Promise<void> {
  if (edge.tunnel !== undefined) {
    ctx.io.out(`Deleting tunnel ${edge.tunnel.name}.`);
    await ctx.cloudflare.deleteTunnel(ctx.config.accountId, edge.tunnel);
  }
}

export function describeEdge(edge: Edge): string[] {
  const lines: string[] = [];
  if (edge.tunnel !== undefined) {
    lines.push(`Cloudflare tunnel ${edge.tunnel.name} (${edge.tunnel.status})`);
  }
  for (const record of edge.dns) {
    lines.push(`Cloudflare DNS record ${record.type} ${record.name}`);
  }
  if (edge.app !== undefined) {
    lines.push(`Cloudflare Access application ${edge.app.name}`);
  }
  for (const app of edge.routeApps) {
    lines.push(`Cloudflare Access application ${app.name}`);
  }
  if (edge.policy !== undefined) {
    lines.push(`Cloudflare Access policy ${edge.policy.name}`);
  }
  if (edge.alert !== undefined) {
    lines.push(`Cloudflare notification ${edge.alert.name}`);
  }
  return lines;
}

// A lookup before the record is live gets "no such host", and resolvers (macOS's included)
// cache that for the zone's negative TTL, 30 minutes on Cloudflare. So nothing on the laptop
// looks the name up until the zone's own nameservers answer for it.
export async function waitForDns(ctx: Context, hostname: string): Promise<void> {
  const deadline = ctx.now() + 2 * 60_000;
  while (!(await ctx.authoritativeResolves(hostname, ctx.config.domain))) {
    if (ctx.now() >= deadline) {
      throw new FrostyError(`Cloudflare's nameservers still do not answer for ${hostname} after 2 minutes.`, "Run the command again with --resume.");
    }
    await ctx.sleep(3000);
  }
  const systemDeadline = ctx.now() + 60_000;
  while (!(await ctx.systemResolves(hostname))) {
    if (ctx.now() >= systemDeadline) {
      throw new FrostyError(
        `${hostname} is live, but this laptop still cannot resolve it: an earlier "no such host" answer is cached. The window is still open.`,
        "Flush the cache (macOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder), or wait up to 30 minutes. Then run: frosty new <box> --resume",
      );
    }
    await ctx.sleep(5000);
  }
}

export function sameEmails(a: string[], b: string[]): boolean {
  const norm = (list: string[]): string => [...new Set(list.map((e) => e.toLowerCase()))].sort().join(",");
  return norm(a) === norm(b);
}
