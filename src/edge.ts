import { NAME_PREFIX, type CfAccessApp, type CfAccessPolicy, type CfDnsRecord, type CfIngressRule, type CfNotificationPolicy, type CfTunnel } from "./cloudflare.ts";
import { runOrFail, type SshTarget } from "./box.ts";
import { sshHostname, type Context } from "./context.ts";
import { FrostyError } from "./errors.ts";

// The Cloudflare side of a box. Cloudflare has no labels, so frosty's resources are found by
// name (stayfrosty-<box>) and the DNS record by its comment.

export function edgeName(box: string): string {
  return `${NAME_PREFIX}${box}`;
}

export function dnsComment(box: string): string {
  return `stayfrosty box ${box}`;
}

export function expectedIngress(hostname: string): CfIngressRule[] {
  return [{ hostname, service: "ssh://localhost:22" }, { service: "http_status:404" }];
}

export interface Edge {
  tunnel: CfTunnel | undefined;
  dns: CfDnsRecord[];
  foreignDns: CfDnsRecord[];
  app: CfAccessApp | undefined;
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
    policy: policies.find((p) => p.name === name),
    alert: alerts.find((a) => a.name === name),
  };
}

export function edgeIsEmpty(edge: Edge): boolean {
  return edge.tunnel === undefined && edge.dns.length === 0 && edge.app === undefined && edge.policy === undefined && edge.alert === undefined;
}

// Step 7: the tunnel and its ingress, managed from Cloudflare.
export async function ensureTunnel(ctx: Context, box: string, existing: CfTunnel | undefined): Promise<CfTunnel> {
  const { cloudflare, config, io } = ctx;
  let tunnel = existing;
  if (tunnel === undefined) {
    io.out(`Creating tunnel ${edgeName(box)}.`);
    tunnel = await cloudflare.createTunnel(config.accountId, edgeName(box));
  }
  const want = expectedIngress(sshHostname(ctx, box));
  const have = await cloudflare.getTunnelIngress(config.accountId, tunnel.id);
  if (!sameIngress(have, want)) {
    io.out(`Setting the tunnel's ingress: ${sshHostname(ctx, box)} to ssh://localhost:22, everything else 404.`);
    await cloudflare.putTunnelIngress(config.accountId, tunnel.id, want);
  }
  return tunnel;
}

export function sameIngress(a: CfIngressRule[], b: CfIngressRule[]): boolean {
  const key = (r: CfIngressRule): string => `${r.hostname ?? ""}|${r.service}`;
  return a.length === b.length && a.every((r, i) => key(r) === key(b[i] as CfIngressRule));
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
    await cloudflare.deleteDnsRecord(config.zoneId, stale.id);
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
    await cloudflare.deleteNotificationPolicy(config.accountId, edge.alert.id);
  }
  if (edge.app !== undefined) {
    io.out(`Deleting Access application ${edge.app.name}.`);
    await cloudflare.deleteAccessApp(config.accountId, edge.app.id);
  }
  if (edge.policy !== undefined) {
    io.out(`Deleting Access policy ${edge.policy.name}.`);
    await cloudflare.deleteAccessPolicy(config.accountId, edge.policy.id);
  }
  for (const record of edge.dns) {
    io.out(`Deleting DNS record ${record.type} ${record.name}.`);
    await cloudflare.deleteDnsRecord(config.zoneId, record.id);
  }
}

export async function removeTunnel(ctx: Context, edge: Edge): Promise<void> {
  if (edge.tunnel !== undefined) {
    ctx.io.out(`Deleting tunnel ${edge.tunnel.name}.`);
    await ctx.cloudflare.deleteTunnel(ctx.config.accountId, edge.tunnel.id);
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
