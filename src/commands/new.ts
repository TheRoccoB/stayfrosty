import { createHash } from "node:crypto";
import { FRESH_CONNECTION, hostKeyAlias, knownHostsPath, lastLines, runOrFail, waitForSsh, type SshTarget } from "../box.ts";
import { checkOnlyPublickey, checkRootRefused } from "../checks/login.ts";
import { runOnBoxChecks } from "../checks/onbox.ts";
import type { CheckResult } from "../checks/types.ts";
import { loadTemplate, renderCloudInit } from "../cloudinit.ts";
import { rebootTimeFor } from "../config.ts";
import { assertBoxName, buildContext, directTarget, requireCloudflared, sshHostname, tunnelTarget, type Context, type Deps } from "../context.ts";
import { checkAccess, checkAccessLogin, checkAlert, checkDns, checkOnlyOurFirewall, checkProtected, checkTunnel, checkWindowClosed } from "../checks/edge.ts";
import { checkTokenNotExposed } from "../checks/token.ts";
import { checkRouteAccess, checkRouteMissing, checkRouteOutside, checkRoutePorts } from "../checks/routes.ts";
import { boxRoutes, edgeName, ensureAccess, ensureAlert, ensureDns, ensureTunnel, findEdge, ingressSpec, installConnector, specIngress, waitForDns, waitForHealthyTunnel } from "../edge.ts";
import { tildify, writeSshConfig, type SshConfigEntry } from "../sshconfig.ts";
import { FrostyError } from "../errors.ts";
import {
  LABEL_ADOPTED,
  LABEL_BOX,
  LABEL_MANAGED,
  MANAGED_SELECTOR,
  LABEL_WINDOW_OPENED,
  WINDOW_DESCRIPTION,
  boxLabels,
  boxSelector,
  isUntouchable,
  type HzFirewall,
  type HzFirewallRule,
  type HzServer,
} from "../hetzner.ts";
import { green, red, table } from "../io.ts";
import { windowSource } from "../ip.ts";
import { hasPassword, setConsolePassword } from "../password.ts";

export interface NewOptions {
  box: string | undefined;
  resume: boolean;
  dryRun: boolean;
  serverType?: string | undefined;
  location?: string | undefined;
}

const SSH_UP_TIMEOUT = 5 * 60_000;
const CLOUD_INIT_TIMEOUT = 25 * 60_000;

export function firewallName(box: string): string {
  return `stayfrosty-${box}`;
}

export function windowRule(cidr: string): HzFirewallRule {
  return { direction: "in", protocol: "tcp", port: "22", source_ips: [cidr], description: WINDOW_DESCRIPTION };
}

export function sameRules(a: HzFirewallRule[], b: HzFirewallRule[]): boolean {
  const key = (r: HzFirewallRule): string => `${r.direction}|${r.protocol}|${r.port ?? ""}|${[...(r.source_ips ?? [])].sort().join(",")}`;
  return a.length === b.length && a.map(key).sort().join(";") === b.map(key).sort().join(";");
}

export async function runNew(deps: Deps, opts: NewOptions): Promise<number> {
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  const { io, hetzner, config } = ctx;
  const serverType = opts.serverType ?? config.serverType;
  const location = opts.location ?? config.location;

  // 1. Preflight.
  requireCloudflared(ctx);
  const userData = renderCloudInit(loadTemplate(), { adminUser: config.adminUser, sshPublicKey: ctx.publicKey, rebootTime: rebootTimeFor(config, box) });
  const laptop = await ctx.laptopIp();
  const source = windowSource(laptop);
  const [servers, firewalls] = await Promise.all([hetzner.listServers(boxSelector(box)), hetzner.listFirewalls(boxSelector(box))]);
  let server = servers[0];
  let firewall = firewalls[0];
  await refuseForeign(ctx, box, server, firewall);
  if (server !== undefined && isUntouchable(server)) {
    throw new FrostyError(`${box} is an adopted or protected server, which frosty new never touches.`, `Re-apply its setup with: frosty adopt ${box} --ip ${server.public_net.ipv4?.ip ?? "<ip>"} --resume`);
  }
  if ((server !== undefined || firewall !== undefined) && !opts.resume) {
    throw new FrostyError(
      `Box ${box} already exists (${[server === undefined ? undefined : "server", firewall === undefined ? undefined : "firewall"].filter(Boolean).join(" and ")}).`,
      `To finish setting it up, run: frosty new ${box} --resume\nTo remove it, run: frosty destroy ${box}`,
    );
  }

  io.out(`${opts.dryRun ? "Would create" : "Creating"} box ${box}: ${serverType} in ${location}, ${config.image}, admin user ${config.adminUser}.`);
  io.out(`  Hetzner firewall ${firewallName(box)}: ${firewall === undefined ? "create" : "keep"}, inbound only TCP 22 from this laptop (${source.cidr}).`);
  io.out(`  Hetzner server ${box}: ${server === undefined ? "create with the firewall attached and cloud-init.yaml as user data" : `keep (${server.status})`}.`);
  io.out("  Then wait for cloud-init and set the console password.");
  io.out(`  Cloudflare: tunnel ${firewallName(box)}, proxied CNAME ssh-${box}.${config.domain}, Access app and policy for ${config.accessEmails.join(", ")}, tunnel alert to ${config.alertEmail}.`);
  io.out(`  ~/.ssh/stayfrosty.conf gets a "Host ${box}" block, then the window closes and everything is checked through the tunnel.`);
  if (opts.dryRun) {
    io.out("Dry run: nothing was changed.");
    return 0;
  }

  // The public key is uploaded once and shared by every box.
  const sshKeyId = await ensureSshKey(ctx);

  // 2. Box firewall with only the window, before the server exists.
  const rules = [windowRule(source.cidr)];
  const windowLabels = boxLabels(box, { [LABEL_WINDOW_OPENED]: String(Math.floor(ctx.now() / 1000)) });
  if (firewall === undefined) {
    io.out(`Creating firewall ${firewallName(box)}.`);
    const created = await hetzner.createFirewall(firewallName(box), windowLabels, rules);
    for (const action of created.actions) {
      await hetzner.waitForAction(action);
    }
    firewall = created.firewall;
  } else if (!sameRules(firewall.rules, rules)) {
    io.out(`Setting firewall ${firewall.name} to admit only ${source.cidr} on TCP 22.`);
    for (const action of await hetzner.setFirewallRules(firewall.id, rules)) {
      await hetzner.waitForAction(action);
    }
    await hetzner.updateFirewallLabels(firewall.id, { ...firewall.labels, ...windowLabels });
  }

  // 3. Server, with the firewall attached at creation.
  if (server === undefined) {
    io.out(`Creating server ${box}.`);
    const created = await hetzner.createServer({
      name: box,
      serverType,
      image: config.image,
      location,
      sshKeyIds: [sshKeyId],
      userData,
      labels: boxLabels(box),
      firewallIds: [firewall.id],
    });
    await hetzner.waitForAction(created.action);
    for (const action of created.next_actions) {
      await hetzner.waitForAction(action);
    }
    server = await hetzner.getServer(created.server.id);
    // A new box has a new host key; forget the pin of any earlier box with this name.
    await ctx.forgetHost(hostKeyAlias(box));
  } else if (!(server.public_net.firewalls ?? []).some((f) => f.id === firewall.id)) {
    io.out(`Attaching firewall ${firewall.name} to ${box}.`);
    for (const action of await hetzner.applyFirewall(firewall.id, server.id)) {
      await hetzner.waitForAction(action);
    }
  }
  const target = directTarget(ctx, box, server, source.family);

  // 5. Wait for SSH through the window, then for cloud-init.
  io.out(`Waiting for SSH on ${target.host} (up to 5 minutes).`);
  await waitForSsh({ ssh: ctx.ssh, target, timeoutMs: SSH_UP_TIMEOUT, sleep: ctx.sleep, now: ctx.now });
  io.out("Waiting for cloud-init to finish (it installs updates, usually a few minutes).");
  await waitForCloudInit(ctx, target);
  await rebootIfRequired(ctx, target);

  return finishBox(ctx, { box, server, firewall, target, resume: opts.resume });
}

export interface FinishInput {
  box: string;
  server: HzServer;
  firewall: HzFirewall;
  // The box's IP during the window, as the admin user.
  target: SshTarget;
  resume: boolean;
}

// Steps 6 to 16, shared by new and adopt: console password, tunnel, DNS, Access, alert, SSH
// config, the real ssh through Access, closing the window, then every check.
export async function finishBox(ctx: Context, input: FinishInput): Promise<number> {
  const { io, config } = ctx;
  const { box, server, firewall, target } = input;
  const opts = { resume: input.resume };
  // 6. Console password, unless a resumed run already set one.
  if (opts.resume && (await hasPassword(ctx.ssh, target, config.adminUser))) {
    io.out(`Console password for ${config.adminUser} is already set; leaving it. Rotate it with: frosty console-password ${box}`);
  } else {
    await setConsolePassword(ctx, { box, target, user: config.adminUser, passwordCommand: config.passwordCommand });
  }

  // 7 to 12: tunnel, token, DNS, Access, alert, then wait until Cloudflare sees it healthy.
  const edge = await findEdge(ctx, box);
  const tunnel = await ensureTunnel(ctx, box, edge.tunnel);
  const token = await installConnector(ctx, target, tunnel.id);
  // Access before DNS: the hostname must never resolve to the tunnel without Access in front.
  await ensureAccess(ctx, box, edge);
  await ensureDns(ctx, box, tunnel.id, edge);
  await ensureAlert(ctx, box, tunnel.id, edge);
  io.out("Waiting for the tunnel to report healthy.");
  await waitForHealthyTunnel(ctx, tunnel.id);

  // 13. SSH config for every box frosty manages.
  const written = await writeSshConfig(ctx.env, await sshConfigEntries(ctx), ctx.now);
  io.out(`Wrote ${tildify(written.path, ctx.env)}.`);
  if (written.includeAdded) {
    io.out(`Added "Include stayfrosty.conf" to the top of ~/.ssh/config${written.backup === undefined ? "" : ` (the old file is at ${tildify(written.backup, ctx.env)})`}.`);
  }

  // 14. The real path: ssh <box>, through Access. The first login opens a browser.
  const hostname = sshHostname(ctx, box);
  io.out(`Waiting for ${hostname} to resolve.`);
  await waitForDns(ctx, hostname);
  if (!(await ctx.hasAccessToken(hostname))) {
    io.out("");
    io.out(`A browser window opens for the Cloudflare Access login to ${hostname}. Log in there to continue.`);
    io.out("(This click is the human in the loop. frosty waits up to 15 minutes.)");
  }
  // Long enough for someone called away from the screen; the window stays open meanwhile, for
  // this laptop's IP only.
  const viaTunnel = await ctx.userSsh(box, "true", (line) => io.err(`  ${line}`), 15 * 60_000);
  if (viaTunnel.code !== 0) {
    throw new FrostyError(
      `ssh ${box} through the tunnel failed (exit ${viaTunnel.code}). The window is still open, so nothing is locked out.`,
      `If the Access login timed out, run the same command again with --resume.`,
    );
  }
  io.out(`ssh ${box} works through Cloudflare Access.`);

  // 15. Every check except the window's, through the tunnel. The window closes only if they pass,
  // so a box that is not right yet stays reachable (from this laptop's IP only) to fix.
  const before = await checkBox(ctx, box, tunnelTarget(ctx, box), server, { tunnel: true, token, window: false });
  const beforeFailed = before.filter((r) => !r.ok);
  if (beforeFailed.length > 0) {
    printResults(ctx, before);
    io.out("");
    io.err(`${beforeFailed.length} check(s) failed on ${box}, so the window stays open for this laptop's IP only. Fix them (see above), then run the same command again with --resume.`);
    return 1;
  }

  // 16. Close the window: no rules on frosty's firewall, which stays attached, so the box denies
  // all inbound. Then check the window and the firewall again.
  await closeWindow(ctx, firewall);
  io.out(`Closed the window. The box firewall now admits nothing.`);
  const after = await windowChecks(ctx, box, await ctx.hetzner.getServer(server.id));
  const results = [...before, ...after];
  printResults(ctx, results);
  const failed = results.filter((r) => !r.ok);
  io.out("");
  if (failed.length > 0) {
    io.err(`${failed.length} check(s) failed on ${box}. The fixes are listed above.`);
    return 1;
  }
  io.out(`Box ${box} is ready. Log in with: ssh ${box}`);
  return 0;
}

async function closeWindow(ctx: Context, firewall: HzFirewall): Promise<void> {
  for (const action of await ctx.hetzner.setFirewallRules(firewall.id, [])) {
    await ctx.hetzner.waitForAction(action);
  }
  const current = (await ctx.hetzner.listFirewalls(boxSelector(firewall.labels[LABEL_BOX] ?? ""))).find((f) => f.id === firewall.id) ?? firewall;
  const labels = { ...current.labels };
  delete labels[LABEL_WINDOW_OPENED];
  await ctx.hetzner.updateFirewallLabels(firewall.id, labels);
}

// One Host block per labeled server. The API is the source of truth, not the file.
export async function sshConfigEntries(ctx: Context): Promise<SshConfigEntry[]> {
  const cloudflared = requireCloudflared(ctx);
  const servers = await ctx.hetzner.listServers(MANAGED_SELECTOR);
  return servers
    .map((s) => s.labels[LABEL_BOX])
    .filter((b): b is string => b !== undefined)
    .map((b) => ({
      box: b,
      hostname: sshHostname(ctx, b),
      user: ctx.config.adminUser,
      identityFile: ctx.config.sshKey,
      cloudflared,
      knownHosts: tildify(knownHostsPath(ctx.env), ctx.env),
      hostKeyAlias: hostKeyAlias(b),
    }));
}

// A server or firewall with frosty's name but without its labels belongs to someone else.
async function refuseForeign(ctx: Context, box: string, server: HzServer | undefined, firewall: HzFirewall | undefined): Promise<void> {
  if (server === undefined) {
    const named = (await ctx.hetzner.listAll<HzServer>("/servers", "servers", { name: box }))[0];
    if (named !== undefined && named.labels[LABEL_MANAGED] !== "1") {
      throw new FrostyError(`A server named ${box} already exists in this Hetzner project, and frosty did not create it.`, "Pick another box name. frosty never touches what it did not create.");
    }
  }
  if (firewall === undefined) {
    const named = (await ctx.hetzner.listAll<HzFirewall>("/firewalls", "firewalls", { name: firewallName(box) }))[0];
    if (named !== undefined && named.labels[LABEL_MANAGED] !== "1") {
      throw new FrostyError(`A firewall named ${firewallName(box)} already exists, and frosty did not create it.`, "Rename or delete it in the Hetzner Cloud Console, or pick another box name.");
    }
  }
}

function keyBody(publicKey: string): string {
  return publicKey.split(/\s+/).slice(0, 2).join(" ");
}

async function ensureSshKey(ctx: Context): Promise<number> {
  const body = keyBody(ctx.publicKey);
  const existing = (await ctx.hetzner.listSshKeys()).find((k) => keyBody(k.public_key) === body);
  if (existing !== undefined) {
    return existing.id;
  }
  const name = `stayfrosty-${createHash("sha256").update(body).digest("hex").slice(0, 12)}`;
  ctx.io.out(`Uploading your SSH public key to Hetzner as ${name}.`);
  const created = await ctx.hetzner.createSshKey(name, body, { [LABEL_MANAGED]: "1" });
  return created.id;
}

async function waitForCloudInit(ctx: Context, target: SshTarget): Promise<void> {
  const result = await ctx.ssh(target, "sudo cloud-init status --wait --long", { timeoutMs: CLOUD_INIT_TIMEOUT });
  if (result.code === 0) {
    return;
  }
  const log = await ctx.ssh(target, "sudo cat /var/log/cloud-init-output.log", { timeoutMs: 30_000 });
  throw new FrostyError(
    `cloud-init did not finish cleanly (exit ${result.code}).\n${lastLines(result.stdout, 15)}\n--- /var/log/cloud-init-output.log, before the first failure ---\n${failureExcerpt(log.stdout)}`,
    "This means cloud-init.yaml or a package mirror failed. Fix the cause in the repo, then rebuild: frosty destroy <box> && frosty new <box>",
  );
}

// cloud-init prints host keys after a failed module, so the log's last lines hide the cause.
// Show the lines leading up to the first failure marker instead.
export function failureExcerpt(log: string, before = 25): string {
  const lines = log.split("\n");
  const marker = /stayfrosty-harden: failed|Failed to run module|Traceback \(most recent call last\)|^E: /;
  const at = lines.findIndex((line) => marker.test(line));
  if (at === -1) {
    return lines.slice(-40).join("\n");
  }
  return lines.slice(Math.max(0, at - before), at + 1).join("\n");
}

// A first-boot upgrade often brings a new kernel. Reboot now rather than at the nightly window,
// and tell the reboot apart from the old boot by its boot ID.
export async function rebootIfRequired(ctx: Context, target: SshTarget): Promise<void> {
  const probe = await ctx.ssh(target, "test -f /var/run/reboot-required && cat /proc/sys/kernel/random/boot_id || true", { timeoutMs: 30_000 });
  const bootId = probe.stdout.trim();
  if (bootId.length === 0) {
    return;
  }
  ctx.io.out("The updates need a reboot. Rebooting now and waiting for SSH.");
  await ctx.ssh(target, "sudo systemctl reboot", { timeoutMs: 30_000 });
  await ctx.closeSsh(target);
  const deadline = ctx.now() + SSH_UP_TIMEOUT;
  for (;;) {
    // Slower than UFW's limit of 6 new connections per 30 seconds.
    await ctx.sleep(10_000);
    const now = await ctx.ssh(target, "cat /proc/sys/kernel/random/boot_id", { timeoutMs: 20_000, extraOptions: FRESH_CONNECTION });
    if (now.code === 0 && now.stdout.trim() !== bootId) {
      return;
    }
    if (ctx.now() >= deadline) {
      throw new FrostyError("The box did not come back from its reboot within 5 minutes.", "Check it in the Hetzner Cloud Console (Console tab), then run the command again with --resume.");
    }
  }
}

// The checks of section 6 that exist so far. With `tunnel`, also the Cloudflare side and the
// closed window; with `token`, a search of the box for the tunnel token.
// The checks that close (or would catch an open) front door on the Hetzner side.
async function windowChecks(ctx: Context, box: string, server: HzServer): Promise<CheckResult[]> {
  const firewalls = await ctx.hetzner.listFirewalls(boxSelector(box));
  return [checkWindowClosed(box, firewalls[0], ctx.now()), checkOnlyOurFirewall(box, server, firewalls[0])];
}

export async function checkBox(
  ctx: Context,
  box: string,
  target: SshTarget,
  server: HzServer,
  opts: { tunnel: boolean; token?: string; window?: boolean },
): Promise<CheckResult[]> {
  const login = [await checkRootRefused(ctx.ssh, target, box), await checkOnlyPublickey(ctx.ssh, target, box)];
  // For an adopted server, its life under frosty starts at adoption, not at its creation.
  const created = Date.parse(server.created);
  const adopted = Number(server.labels[LABEL_ADOPTED]);
  const born = Math.max(Number.isFinite(created) ? Math.floor(created / 1000) : 0, Number.isFinite(adopted) ? adopted : 0);
  const createdAt = born > 0 ? born : undefined;
  const onBox = await runOnBoxChecks(ctx.ssh, target, { box, adminUser: ctx.config.adminUser, rebootTime: rebootTimeFor(ctx.config, box), createdAt, tunnel: opts.tunnel });
  if (!opts.tunnel) {
    return [...login, ...onBox];
  }
  const { config, cloudflare } = ctx;
  const hostname = sshHostname(ctx, box);
  const [edge, records] = await Promise.all([findEdge(ctx, box), cloudflare.listDnsRecords(config.zoneId)]);
  const ingress = edge.tunnel === undefined ? [] : await cloudflare.getTunnelIngress(config.accountId, edge.tunnel.id);
  const app = edge.app === undefined ? undefined : await cloudflare.getAccessApp(config.accountId, edge.app.id);
  const routes = boxRoutes(ctx, box);
  // Route apps re-read one by one: the list may leave out destinations and policies.
  const listed = routes.length === 0 ? [] : await cloudflare.listAccessApps(config.accountId);
  const apps = await Promise.all(listed.map((a) => (a.name.startsWith(`${edgeName(box)}:`) ? cloudflare.getAccessApp(config.accountId, a.id) : Promise.resolve(a))));
  const spec = ingressSpec(ctx, box, apps);
  const routeResults: CheckResult[] = [];
  if (routes.length > 0) {
    const policies = await cloudflare.listAccessPolicies(config.accountId);
    const ss = await runOrFail(ctx.ssh, target, "ss -tlnpH", "Listing listening sockets");
    routeResults.push(checkRoutePorts(routes, ss));
    for (const route of routes) {
      routeResults.push(spec.routes.some((r) => r.route === route) ? checkRouteAccess(box, route, apps, policies, edge.policy?.id) : checkRouteMissing(box, route));
      routeResults.push(await checkRouteOutside(ctx.rawGet, route, config.accessTeam ?? ""));
    }
  }
  const api = [
    ...(opts.window === false ? [] : await windowChecks(ctx, box, server)),
    ...[checkProtected(server)].filter((c): c is CheckResult => c !== undefined),
    checkTunnel(box, edge.tunnel, ingress, hostname, specIngress(spec), spec.routes.length),
    checkAccess(box, app, edge.policy, hostname, config.accessEmails),
    checkDns(box, records, hostname, edge.tunnel?.id, server.public_net.ipv4?.ip, server.public_net.ipv6?.ip),
    checkAlert(box, edge.alert, edge.tunnel?.id),
    await checkAccessLogin(ctx.fetch, hostname),
    ...routeResults,
  ];
  const tokenCheck = opts.token === undefined ? [] : [await checkTokenNotExposed(ctx.ssh, target, opts.token)];
  return [...login, ...onBox, ...tokenCheck, ...api];
}

export function printResults(ctx: Context, results: CheckResult[]): void {
  ctx.io.out("");
  for (const line of table(results.map((r) => [r.ok ? green("pass") : red("FAIL"), r.name, r.detail]))) {
    ctx.io.out(line);
  }
  for (const r of results.filter((x) => !x.ok && x.fix !== undefined)) {
    ctx.io.out("");
    ctx.io.out(`Fix for "${r.name}": ${r.fix}`);
  }
}
