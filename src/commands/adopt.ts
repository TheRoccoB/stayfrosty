import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { isIPv4 } from "node:net";
import { hardenScript, parseCloudInit, userScript } from "../adoptscript.ts";
import { FRESH_CONNECTION, fingerprintOf, hostKeyAlias, knownHostsPath, runOrFail, waitForSsh, type ScannedKey, type SshTarget } from "../box.ts";
import { loadTemplate, renderCloudInit } from "../cloudinit.ts";
import { assertBoxName, buildContext, requireCloudflared, type Context, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { LABEL_ADOPTED, LABEL_BOX, LABEL_MANAGED, LABEL_WINDOW_OPENED, boxLabels, boxSelector, type HzFirewall, type HzServer } from "../hetzner.ts";
import { windowSource } from "../ip.ts";
import { finishBox, firewallName, rebootIfRequired, sameRules, windowRule } from "./new.ts";

export interface AdoptOptions {
  box: string | undefined;
  ip: string | undefined;
  // The login that works on the box today, usually root.
  user: string;
  // SHA256 fingerprint of the box's host key, checked from a trusted place (the Hetzner web
  // console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).
  hostKey: string | undefined;
  trustFirstUse: boolean;
  resume: boolean;
  dryRun: boolean;
}

const HARDEN_TIMEOUT = 25 * 60_000;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const LOGIN_USER = /^[a-z_][a-z0-9_-]{0,31}$/;

// Brings a server that already exists under frosty: the same hardening as `new`, applied over
// SSH instead of cloud-init, then the same tunnel, Access and checks. For servers that cannot
// be recreated (a grandfathered price, a fixed IP). frosty turns on delete and rebuild
// protection and labels the server as adopted, and never deletes or rebuilds it afterwards.
export async function runAdopt(deps: Deps, opts: AdoptOptions): Promise<number> {
  const box = assertBoxName(opts.box);
  if (opts.ip === undefined || !isIPv4(opts.ip)) {
    throw new FrostyError(`--ip ${opts.ip ?? ""} is not an IPv4 address.`, `Pass the server's public IPv4: frosty adopt ${box} --ip 203.0.113.10`);
  }
  if (!LOGIN_USER.test(opts.user)) {
    throw new FrostyError(`--user ${opts.user} is not a valid user name.`, "Pass the user that can log in today, e.g. --user root");
  }
  if (opts.hostKey !== undefined && !FINGERPRINT.test(opts.hostKey)) {
    throw new FrostyError(`--host-key ${opts.hostKey} is not a SHA256 fingerprint.`, "Copy it from ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub, e.g. SHA256:abc...");
  }
  const ip = opts.ip;
  const ctx = await buildContext(deps);
  const { io, hetzner, config } = ctx;

  // 1. Preflight, all reads.
  requireCloudflared(ctx);
  // Parse the template first: a template adopt cannot read stops here, before any change.
  const values = { adminUser: config.adminUser, sshPublicKey: ctx.publicKey, rebootTime: config.rebootTime };
  const plan = parseCloudInit(renderCloudInit(loadTemplate(), values), values);
  const laptop = await ctx.laptopIp();
  if (laptop.ipv4 === undefined) {
    throw new FrostyError("This laptop has no public IPv4, and adopt reaches the server on its IPv4.", "Run adopt from a network with IPv4.");
  }
  const source = windowSource({ ipv4: laptop.ipv4, ipv6: undefined });
  const server = (await hetzner.listServers()).find((s) => s.public_net.ipv4?.ip === ip);
  if (server === undefined) {
    throw new FrostyError(`No server in this Hetzner project has the IPv4 ${ip}.`, "Check the IP, and that HCLOUD_TOKEN belongs to the server's project.");
  }
  refuseUnadoptable(box, server);
  const twins = (await hetzner.listServers(boxSelector(box))).filter((s) => s.id !== server.id);
  if (twins.length > 0) {
    throw new FrostyError(`Another server (${twins.map((t) => t.name).join(", ")}) is already labeled as box ${box}.`, "Fix the labels in the Hetzner Cloud Console.");
  }
  let firewall = (await hetzner.listFirewalls(boxSelector(box)))[0];
  await refuseForeignNamedFirewall(ctx, box, firewall);
  if (firewall !== undefined && firewall.applied_to.some((a) => a.type !== "server" || a.server?.id !== server.id)) {
    throw new FrostyError(`Firewall ${firewall.name} is applied to more than ${box}, so its window would open elsewhere too.`, "Remove its other targets in the Hetzner Cloud Console.");
  }
  if (!opts.resume && server.labels[LABEL_ADOPTED] !== undefined && firewall !== undefined) {
    throw new FrostyError(`${box} is already adopted.`, `To check it: frosty verify ${box}\nTo apply the setup again: frosty adopt ${box} --ip ${ip} --resume`);
  }
  const attached = server.public_net.firewalls ?? [];
  const ourAttached = firewall !== undefined && attached.some((f) => f.id === firewall?.id);
  const others = attached.filter((f) => f.id !== firewall?.id);
  const pin = pinnedKey(ctx, box);
  if (pin !== undefined && opts.hostKey !== undefined && (await fingerprintOf(pin)) !== opts.hostKey) {
    throw new FrostyError(
      `frosty already pinned a different host key for ${box} than --host-key ${opts.hostKey}.`,
      `Stop here unless you know why. If the box's key really changed, remove the line starting "${hostKeyAlias(box)} " from ${knownHostsPath(ctx.env)} and run adopt again with --host-key.`,
    );
  }
  const pinned = pin !== undefined;
  if (!pinned && opts.hostKey === undefined && !opts.trustFirstUse) {
    throw new FrostyError(
      `adopt needs the host key fingerprint of ${box}, to know it is talking to the real server.`,
      `In the Hetzner web console (Console tab), run: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub\nThen: frosty adopt ${box} --ip ${ip} --host-key SHA256:...\n(Or --trust-first-use to accept whatever key answers, which a man in the middle could fake.)`,
    );
  }
  // Read-only, so a wrong key stops adopt before it changes anything. When frosty's firewall is
  // already attached, port 22 may be closed, so the scan waits until the window is open.
  let hostKey = pinned || ourAttached ? undefined : await scanHostKey(ctx, ip, opts.hostKey);

  io.out(`${opts.dryRun ? "Would adopt" : "Adopting"} server ${server.name} (${ip}, ${server.server_type.name}) as box ${box}. Its type, disk and IP stay as they are.`);
  io.out("  Hetzner: turn on delete and rebuild protection, label it as adopted (frosty never deletes or rebuilds it).");
  io.out(`  Hetzner firewall ${firewallName(box)}: ${firewall === undefined ? "create and attach" : "keep"}, inbound only TCP 22 from this laptop (${source.cidr}).`);
  io.out(`  Over SSH as ${opts.user}: create ${config.adminUser} with your key and sudo. Then, as ${config.adminUser}: dist-upgrade, install ${plan.packages.join(", ")}, write ${plan.files.length} files, run the hardening.`);
  io.out(`  Then the same steps as new: console password, tunnel, ssh-${box}.${config.domain}, Access, alert, SSH config, every check, then close the window.`);
  io.out("  What this does to a running server:");
  io.out("    - all inbound traffic stops once the window closes, web ports included: only the tunnel reaches it");
  io.out("    - UFW is reset to deny incoming except SSH (existing UFW rules are dropped)");
  io.out(`    - SSH accepts only ${config.adminUser} with a key; root and every other user can no longer log in over SSH`);
  io.out("    - it may reboot once if the upgrade needs it");
  if (others.length > 0) {
    io.out(`  It has ${others.length} other firewall(s) (id ${others.map((f) => f.id).join(", ")}). adopt attaches frosty's first, then stops so you can detach those.`);
  }
  if (opts.dryRun) {
    io.out("Dry run: nothing was changed.");
    return 0;
  }

  // 2. Protection and labels first, so nothing frosty does later can delete or rebuild it.
  if (server.protection?.delete !== true || server.protection.rebuild !== true) {
    io.out(`Turning on delete and rebuild protection for ${box}.`);
    await hetzner.waitForAction(await hetzner.protectServer(server.id));
  }
  const labels = { ...server.labels, ...boxLabels(box), [LABEL_ADOPTED]: server.labels[LABEL_ADOPTED] ?? String(Math.floor(ctx.now() / 1000)) };
  if (JSON.stringify(labels) !== JSON.stringify(server.labels)) {
    await hetzner.updateServerLabels(server.id, labels);
  }

  // 3. The window. Until now the server may have had no firewall at all, so this narrows it.
  firewall = await openWindow(ctx, box, server, firewall, source.cidr);

  // Hetzner firewalls add up: another firewall's allow rules would open what frosty's closes.
  // frosty's is attached now, so detaching the others never leaves the server with none.
  if (others.length > 0) {
    throw new FrostyError(
      `${box} has ${others.length} firewall(s) frosty did not make (id ${others.map((f) => f.id).join(", ")}). Their allow rules would add to frosty's.`,
      `frosty's firewall ${firewall.name} is attached now. Detach the others in the Hetzner Cloud Console (Firewalls), never frosty's, then: frosty adopt ${box} --ip ${ip} --resume`,
    );
  }

  // 4. Pin the host key before the first login.
  if (!pinned && hostKey === undefined) {
    hostKey = await scanHostKey(ctx, ip, opts.hostKey);
  }
  if (hostKey !== undefined) {
    await pinHostKey(ctx, box, hostKey, opts.hostKey !== undefined);
  }

  // 5. The admin user, through the login that works today. On a resumed run the old login may
  // already be closed by the hardening, so try the admin user first.
  const admin: SshTarget = { host: ip, user: config.adminUser, keyPath: ctx.keyPath, hostKeyAlias: hostKeyAlias(box), pinned: true };
  const existing: SshTarget = { ...admin, user: opts.user };
  if (!(await works(ctx, admin))) {
    io.out(`Waiting for SSH as ${opts.user}@${ip}.`);
    await waitForSsh({ ssh: ctx.ssh, target: existing, timeoutMs: 2 * 60_000, sleep: ctx.sleep, now: ctx.now });
    io.out(`Creating ${config.adminUser} with your key and passwordless sudo.`);
    const out = await runOrFail(ctx.ssh, existing, opts.user === "root" ? "bash -s" : "sudo bash -s", "Creating the admin user", { stdin: userScript(config.adminUser, ctx.publicKey), timeoutMs: 60_000 });
    if (!out.includes("stayfrosty-user-ok")) {
      throw new FrostyError("Creating the admin user did not finish.", "Run the same command again with --resume.");
    }
    await ctx.closeSsh(existing);
    if (!(await works(ctx, admin))) {
      throw new FrostyError(
        `${config.adminUser}@${ip} cannot log in and sudo, so the hardening was not started. ${opts.user} still works as before.`,
        `Look at /home/${config.adminUser}/.ssh/authorized_keys and /etc/sudoers.d/90-stayfrosty as ${opts.user}, then run again with --resume.`,
      );
    }
  }

  // 6. The hardening, as the admin user. From here on root cannot log in over SSH.
  io.out("Applying the hardening (upgrades, cloudflared, sshd, UFW, unattended-upgrades). This takes a few minutes.");
  const out = await runOrFail(ctx.ssh, admin, "sudo bash -s", "Applying the hardening", { stdin: hardenScript(plan), timeoutMs: HARDEN_TIMEOUT });
  if (!out.includes("stayfrosty-harden-ok")) {
    throw new FrostyError("The hardening did not finish.", "Run the same command again with --resume; every step is safe to repeat.");
  }
  await rebootIfRequired(ctx, admin);

  // 7 to 16, the same as new.
  return finishBox(ctx, { box, server: await hetzner.getServer(server.id), firewall, target: admin, resume: opts.resume });
}

// frosty adopts only a server that is not already someone else's box.
export function refuseUnadoptable(box: string, server: HzServer): void {
  if (server.name !== box) {
    throw new FrostyError(`Hetzner calls the server at that IP "${server.name}", not "${box}".`, `Use the server's name as the box name: frosty adopt ${server.name} ...`);
  }
  if (server.labels[LABEL_MANAGED] === "1") {
    if (server.labels[LABEL_ADOPTED] === undefined) {
      throw new FrostyError(`${box} was created by frosty new, not adopted.`, `Finish it with: frosty new ${box} --resume`);
    }
    if (server.labels[LABEL_BOX] !== box) {
      throw new FrostyError(`${server.name} is labeled as frosty box ${server.labels[LABEL_BOX] ?? "?"}.`, "Fix its labels in the Hetzner Cloud Console.");
    }
  }
}

async function refuseForeignNamedFirewall(ctx: Context, box: string, firewall: HzFirewall | undefined): Promise<void> {
  if (firewall === undefined) {
    const named = (await ctx.hetzner.listAll<HzFirewall>("/firewalls", "firewalls", { name: firewallName(box) }))[0];
    if (named !== undefined) {
      throw new FrostyError(`A firewall named ${firewallName(box)} already exists, and frosty did not create it.`, "Rename or delete it in the Hetzner Cloud Console.");
    }
  }
}

async function openWindow(ctx: Context, box: string, server: HzServer, existing: HzFirewall | undefined, cidr: string): Promise<HzFirewall> {
  const { hetzner, io } = ctx;
  const rules = [windowRule(cidr)];
  const windowLabels = boxLabels(box, { [LABEL_WINDOW_OPENED]: String(Math.floor(ctx.now() / 1000)) });
  let firewall = existing;
  if (firewall === undefined) {
    io.out(`Creating firewall ${firewallName(box)}.`);
    const created = await hetzner.createFirewall(firewallName(box), windowLabels, rules);
    for (const action of created.actions) {
      await hetzner.waitForAction(action);
    }
    firewall = created.firewall;
  } else if (!sameRules(firewall.rules, rules)) {
    io.out(`Setting firewall ${firewall.name} to admit only ${cidr} on TCP 22.`);
    for (const action of await hetzner.setFirewallRules(firewall.id, rules)) {
      await hetzner.waitForAction(action);
    }
    await hetzner.updateFirewallLabels(firewall.id, { ...firewall.labels, ...windowLabels });
  }
  if (!(server.public_net.firewalls ?? []).some((f) => f.id === firewall.id)) {
    io.out(`Attaching firewall ${firewall.name} to ${box}.`);
    for (const action of await hetzner.applyFirewall(firewall.id, server.id)) {
      await hetzner.waitForAction(action);
    }
  }
  return firewall;
}

// The key frosty pinned for this box, as "type key", if any.
function pinnedKey(ctx: Context, box: string): string | undefined {
  try {
    const line = readFileSync(knownHostsPath(ctx.env), "utf8")
      .split("\n")
      .find((l) => l.startsWith(`${hostKeyAlias(box)} `));
    return line?.split(/\s+/).slice(1, 3).join(" ");
  } catch {
    return undefined;
  }
}

async function scanHostKey(ctx: Context, ip: string, expected: string | undefined): Promise<ScannedKey> {
  const keys = await ctx.keyScan(ip);
  const chosen = expected === undefined ? (keys.find((k) => k.type === "ssh-ed25519") ?? keys[0]) : keys.find((k) => k.fingerprint === expected);
  if (chosen === undefined) {
    throw new FrostyError(
      expected === undefined
        ? `${ip} did not present an SSH host key.`
        : `${ip} presents ${keys.map((k) => `${k.type} ${k.fingerprint}`).join(", ") || "no host key"}, not ${expected}.`,
      "Stop here if the fingerprint is wrong: something may be intercepting the connection. Check it again in the Hetzner web console.",
    );
  }
  return chosen;
}

async function pinHostKey(ctx: Context, box: string, chosen: ScannedKey, matched: boolean): Promise<void> {
  await ctx.forgetHost(hostKeyAlias(box));
  const path = knownHostsPath(ctx.env);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  appendFileSync(path, `${hostKeyAlias(box)} ${chosen.type} ${chosen.key}\n`, { mode: 0o600 });
  ctx.io.out(`Pinned ${box}'s host key ${chosen.type} ${chosen.fingerprint}${matched ? ", matching --host-key" : " (trusted on first use)"}.`);
}

async function works(ctx: Context, target: SshTarget): Promise<boolean> {
  const r = await ctx.ssh(target, "sudo -n true", { timeoutMs: 20_000, extraOptions: FRESH_CONNECTION });
  return r.code === 0;
}
