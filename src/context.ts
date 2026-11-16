import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { closeSshMaster, fingerprintOf, hostKeyAlias, keyScan, systemSsh, forgetHost, userSsh, type KeyScanner, type SshRunner, type SshTarget, type UserSsh } from "./box.ts";
import { isPublicKey } from "./cloudinit.ts";
import { fileChangeLog } from "./changelog.ts";
import { Cloudflare } from "./cloudflare.ts";
import { expandHome, loadConfig, providerKindFor, type Config, type Env } from "./config.ts";
import { DigitalOcean } from "./digitalocean.ts";
import { authoritativeResolves, systemResolves } from "./dns.ts";
import { FrostyError } from "./errors.ts";
import { Hetzner, LABEL_ADOPTED } from "./hetzner.ts";
import { realSleep, type Fetch, type Sleep } from "./http.ts";
import type { Io } from "./io.ts";
import { findLaptopIp, type LaptopIp } from "./ip.ts";
import { shellPasswordCommand, type PasswordCommandRunner } from "./password.ts";
import type { Provider, ProviderKind, Server, ServerSettings } from "./provider.ts";
import { DIGITALOCEAN_TOKEN_ENV, HETZNER_TOKEN_ENV, loadProviderTokens, missingDigitalOceanToken, missingHetznerToken } from "./tokens.ts";
import { rawGet, type RawGet } from "./rawget.ts";
import { findCommand, findStableCommand } from "./which.ts";

// Everything a command touches in the outside world, injectable for tests.
export interface Deps {
  io: Io;
  env?: Env;
  fetch?: Fetch;
  sleep?: Sleep;
  now?: () => number;
  ssh?: SshRunner;
  forgetHost?: (host: string) => Promise<void>;
  closeSsh?: (target: SshTarget) => Promise<void>;
  userSsh?: UserSsh;
  keyScan?: KeyScanner;
  fingerprintOf?: (publicKey: string) => Promise<string>;
  // Whether cloudflared on the laptop already holds an Access token for a hostname.
  hasAccessToken?: (hostname: string) => Promise<boolean>;
  authoritativeResolves?: (hostname: string, domain: string) => Promise<boolean>;
  systemResolves?: (hostname: string) => Promise<boolean>;
  laptopIp?: () => Promise<LaptopIp>;
  cloudflaredPath?: string | undefined;
  isTty?: boolean;
  runPasswordCommand?: PasswordCommandRunner;
  // HTTPS GET with the path sent exactly as written (verify's route checks).
  rawGet?: RawGet;
}

export interface Context {
  io: Io;
  env: Env;
  config: Config;
  // Each only when its token is set (and, for DigitalOcean, the config has its section). A box's
  // provider is reached through providerFor, which refuses when that provider's token is missing.
  hetzner: Hetzner | undefined;
  digitalocean: DigitalOcean | undefined;
  // Providers the config has but whose token isn't set: commands over every box say they skipped them.
  skipped: SkippedProvider[];
  cloudflare: Cloudflare;
  sleep: Sleep;
  now: () => number;
  ssh: SshRunner;
  forgetHost: (host: string) => Promise<void>;
  closeSsh: (target: SshTarget) => Promise<void>;
  userSsh: UserSsh;
  keyScan: KeyScanner;
  fingerprintOf: (publicKey: string) => Promise<string>;
  hasAccessToken: (hostname: string) => Promise<boolean>;
  authoritativeResolves: (hostname: string, domain: string) => Promise<boolean>;
  systemResolves: (hostname: string) => Promise<boolean>;
  fetch: Fetch;
  laptopIp: () => Promise<LaptopIp>;
  isTty: boolean;
  runPasswordCommand: PasswordCommandRunner;
  keyPath: string;
  publicKey: string;
  cloudflaredPath: string | undefined;
  rawGet: RawGet;
}

export async function buildContext(deps: Deps): Promise<Context> {
  const env = deps.env ?? process.env;
  const tokens = loadProviderTokens(env);
  const config = await loadConfig(env, (line) => deps.io.err(line));
  const sleep = deps.sleep ?? realSleep;
  const keyPath = expandHome(config.sshKey, env);
  let publicKey: string;
  try {
    publicKey = readFileSync(`${keyPath}.pub`, "utf8").trim();
  } catch {
    throw new FrostyError(`Cannot read ${keyPath}.pub.`, "Point sshKey at a key whose .pub sits next to it: frosty init");
  }
  if (!isPublicKey(publicKey)) {
    throw new FrostyError(`${keyPath}.pub is not a single OpenSSH public key line.`, "Point sshKey at a valid key: frosty init");
  }
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  const doToken = tokens.digitalocean;
  const digitalocean =
    config.digitalocean === undefined || doToken === undefined
      ? undefined
      : new DigitalOcean({
          token: doToken,
          fetch: fetchImpl,
          sleep,
          backups: config.digitalocean.backups,
          ...(deps.now === undefined ? {} : { now: deps.now }),
          changeLog: config.digitaloceanChangeLog === undefined ? undefined : fileChangeLog(config.digitaloceanChangeLog),
        });
  return {
    io: deps.io,
    env,
    config,
    hetzner:
      tokens.hetzner === undefined
        ? undefined
        : new Hetzner({ token: tokens.hetzner, fetch: fetchImpl, sleep, changeLog: config.hetznerChangeLog === undefined ? undefined : fileChangeLog(config.hetznerChangeLog) }),
    digitalocean,
    skipped: [
      ...(tokens.hetzner === undefined ? [{ kind: "hetzner" as const, label: "Hetzner", envVar: HETZNER_TOKEN_ENV }] : []),
      ...(config.digitalocean !== undefined && doToken === undefined ? [{ kind: "digitalocean" as const, label: "DigitalOcean", envVar: DIGITALOCEAN_TOKEN_ENV }] : []),
    ],
    cloudflare: new Cloudflare({ token: tokens.cloudflare, fetch: fetchImpl, sleep, changeLog: config.cloudflareChangeLog === undefined ? undefined : fileChangeLog(config.cloudflareChangeLog) }),
    sleep,
    now: deps.now ?? Date.now,
    ssh: deps.ssh ?? systemSsh(env),
    forgetHost: deps.forgetHost ?? ((host) => forgetHost(host, env)),
    closeSsh: deps.closeSsh ?? ((target) => closeSshMaster(target, env)),
    userSsh: deps.userSsh ?? userSsh,
    keyScan: deps.keyScan ?? keyScan,
    fingerprintOf: deps.fingerprintOf ?? fingerprintOf,
    hasAccessToken: deps.hasAccessToken ?? ((hostname) => cloudflaredHasToken(findCommand("cloudflared", env), hostname)),
    authoritativeResolves: deps.authoritativeResolves ?? authoritativeResolves,
    systemResolves: deps.systemResolves ?? systemResolves,
    fetch: fetchImpl,
    rawGet: deps.rawGet ?? rawGet,
    laptopIp: deps.laptopIp ?? (() => findLaptopIp(fetchImpl)),
    isTty: deps.isTty ?? (process.stdin.isTTY === true && process.stdout.isTTY === true),
    runPasswordCommand: deps.runPasswordCommand ?? shellPasswordCommand,
    keyPath,
    publicKey,
    cloudflaredPath: "cloudflaredPath" in deps ? deps.cloudflaredPath : findStableCommand("cloudflared", env),
  };
}

export interface SkippedProvider {
  kind: ProviderKind;
  label: string;
  envVar: string;
}

// The cloud a box lives on, from boxProviders (Hetzner unless listed). Fails closed: a box not
// listed as digitalocean is a Hetzner box and needs HCLOUD_TOKEN.
export function providerFor(ctx: Pick<Context, "config" | "hetzner" | "digitalocean">, box: string): Provider {
  if (providerKindFor(ctx.config, box) === "digitalocean") {
    if (ctx.config.digitalocean === undefined) {
      throw new FrostyError(`${box} is on digitalocean in boxProviders, but the config has no digitalocean section.`, "Add it (region, size, image), then run the command again.");
    }
    if (ctx.digitalocean === undefined) {
      throw missingDigitalOceanToken(box);
    }
    return ctx.digitalocean;
  }
  return requireHetzner(ctx, box);
}

export function requireHetzner(ctx: Pick<Context, "hetzner">, box: string): Hetzner {
  if (ctx.hetzner === undefined) {
    throw missingHetznerToken(box);
  }
  return ctx.hetzner;
}

// The clouds whose token is set: Hetzner, then DigitalOcean if the config has it. Commands over
// every box must say which ones they skipped (ctx.skipped), and never take a skipped provider's
// boxes for absent.
export function allProviders(ctx: Pick<Context, "hetzner" | "digitalocean">): Provider[] {
  return [ctx.hetzner, ctx.digitalocean].filter((p): p is Hetzner | DigitalOcean => p !== undefined);
}

export function skippedNote(ctx: Pick<Context, "skipped">): string | undefined {
  if (ctx.skipped.length === 0) {
    return undefined;
  }
  return `Skipped ${ctx.skipped.map((s) => `${s.label} boxes (${s.envVar} is not set)`).join(" and ")}: they were not listed, and nothing was assumed about them.`;
}

// What new creates a box with: its provider's settings.
export function serverSettings(config: Config, box: string): ServerSettings {
  if (providerKindFor(config, box) === "digitalocean" && config.digitalocean !== undefined) {
    return { serverType: config.digitalocean.size, location: config.digitalocean.region, image: config.digitalocean.image };
  }
  return { serverType: config.serverType, location: config.location, image: config.image };
}

// Box names become a Hetzner server name and the DNS label ssh-<box>.
const BOX_NAME = /^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/;

export function assertBoxName(box: string | undefined): string {
  // "bypass" is reserved: stayfrosty-bypass is the shared route bypass policy, not a box's.
  if (box === undefined || !BOX_NAME.test(box) || box === "bypass") {
    throw new FrostyError(
      `"${box ?? ""}" is not a valid box name.`,
      "Use 1 to 30 lowercase letters, digits and dashes, starting with a letter, e.g.: frosty new web1",
    );
  }
  return box;
}

// During a window frosty reaches the box directly on its public IP.
export function directTarget(ctx: Context, box: string, server: Server, family: 4 | 6): SshTarget {
  const host = family === 4 ? server.public_net.ipv4?.ip : ipv6Host(server.public_net.ipv6?.ip);
  if (host === undefined) {
    throw new FrostyError(`Box ${server.name} has no public IPv${family} address.`, "This is a bug in frosty. Please report it.");
  }
  // An adopted box's key was checked against a fingerprint, so it is never learned again.
  return { host, user: ctx.config.adminUser, keyPath: ctx.keyPath, hostKeyAlias: hostKeyAlias(box), pinned: server.labels[LABEL_ADOPTED] !== undefined };
}

export function sshHostname(ctx: Context, box: string): string {
  return `ssh-${box}.${ctx.config.domain}`;
}

// Through the tunnel and Access. cloudflared on the laptop carries the SSH connection.
export function tunnelTarget(ctx: Context, box: string): SshTarget {
  return {
    ...tunnelTargetBase(ctx, box),
    proxyCommand: `${requireCloudflared(ctx)} access ssh --hostname %h`,
  };
}

export function requireCloudflared(ctx: Context): string {
  if (ctx.cloudflaredPath === undefined) {
    throw new FrostyError(
      "cloudflared is not installed on this laptop, and SSH through the tunnel needs it.",
      "Install it (macOS: brew install cloudflared; others: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/), then run the command again.",
    );
  }
  return ctx.cloudflaredPath;
}

function tunnelTargetBase(ctx: Context, box: string): SshTarget {
  return {
    host: sshHostname(ctx, box),
    user: ctx.config.adminUser,
    keyPath: ctx.keyPath,
    hostKeyAlias: hostKeyAlias(box),
  };
}

// Hetzner reports the box's IPv6 as a /64 network; the box itself answers on ::1 within it.
export function ipv6Host(network: string | undefined): string | undefined {
  if (network === undefined) {
    return undefined;
  }
  return network.replace(/\/64$/, "").replace(/::$/, "::1");
}

// `cloudflared access token` prints a cached, unexpired token and never opens a browser.
function cloudflaredHasToken(cloudflared: string | undefined, hostname: string): Promise<boolean> {
  if (cloudflared === undefined) {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    const child = spawn(cloudflared, ["access", "token", `-app=https://${hostname}`], { stdio: "ignore" });
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
  });
}
