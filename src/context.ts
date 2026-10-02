import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { closeSshMaster, hostKeyAlias, systemSsh, forgetHost, userSsh, type SshRunner, type SshTarget, type UserSsh } from "./box.ts";
import { isPublicKey } from "./cloudinit.ts";
import { Cloudflare } from "./cloudflare.ts";
import { expandHome, loadConfig, type Config, type Env } from "./config.ts";
import { authoritativeResolves, systemResolves } from "./dns.ts";
import { FrostyError } from "./errors.ts";
import { Hetzner, type HzServer } from "./hetzner.ts";
import { realSleep, type Fetch, type Sleep } from "./http.ts";
import type { Io } from "./io.ts";
import { findLaptopIp, type LaptopIp } from "./ip.ts";
import { shellPasswordCommand, type PasswordCommandRunner } from "./password.ts";
import { loadTokens } from "./tokens.ts";
import { findCommand } from "./which.ts";

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
  // Whether cloudflared on the laptop already holds an Access token for a hostname.
  hasAccessToken?: (hostname: string) => Promise<boolean>;
  authoritativeResolves?: (hostname: string, domain: string) => Promise<boolean>;
  systemResolves?: (hostname: string) => Promise<boolean>;
  laptopIp?: () => Promise<LaptopIp>;
  cloudflaredPath?: string | undefined;
  isTty?: boolean;
  runPasswordCommand?: PasswordCommandRunner;
}

export interface Context {
  io: Io;
  env: Env;
  config: Config;
  hetzner: Hetzner;
  cloudflare: Cloudflare;
  sleep: Sleep;
  now: () => number;
  ssh: SshRunner;
  forgetHost: (host: string) => Promise<void>;
  closeSsh: (target: SshTarget) => Promise<void>;
  userSsh: UserSsh;
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
}

export async function buildContext(deps: Deps): Promise<Context> {
  const env = deps.env ?? process.env;
  const tokens = loadTokens(env);
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
  return {
    io: deps.io,
    env,
    config,
    hetzner: new Hetzner({ token: tokens.hetzner, fetch: fetchImpl, sleep }),
    cloudflare: new Cloudflare({ token: tokens.cloudflare, fetch: fetchImpl, sleep }),
    sleep,
    now: deps.now ?? Date.now,
    ssh: deps.ssh ?? systemSsh(env),
    forgetHost: deps.forgetHost ?? ((host) => forgetHost(host, env)),
    closeSsh: deps.closeSsh ?? ((target) => closeSshMaster(target, env)),
    userSsh: deps.userSsh ?? userSsh,
    hasAccessToken: deps.hasAccessToken ?? ((hostname) => cloudflaredHasToken(findCommand("cloudflared", env), hostname)),
    authoritativeResolves: deps.authoritativeResolves ?? authoritativeResolves,
    systemResolves: deps.systemResolves ?? systemResolves,
    fetch: fetchImpl,
    laptopIp: deps.laptopIp ?? (() => findLaptopIp(fetchImpl)),
    isTty: deps.isTty ?? (process.stdin.isTTY === true && process.stdout.isTTY === true),
    runPasswordCommand: deps.runPasswordCommand ?? shellPasswordCommand,
    keyPath,
    publicKey,
    cloudflaredPath: "cloudflaredPath" in deps ? deps.cloudflaredPath : findCommand("cloudflared", env),
  };
}

// Box names become a Hetzner server name and the DNS label ssh-<box>.
const BOX_NAME = /^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/;

export function assertBoxName(box: string | undefined): string {
  if (box === undefined || !BOX_NAME.test(box)) {
    throw new FrostyError(
      `"${box ?? ""}" is not a valid box name.`,
      "Use 1 to 30 lowercase letters, digits and dashes, starting with a letter, e.g.: frosty new web1",
    );
  }
  return box;
}

// During a window frosty reaches the box directly on its public IP.
export function directTarget(ctx: Context, box: string, server: HzServer, family: 4 | 6): SshTarget {
  const host = family === 4 ? server.public_net.ipv4?.ip : ipv6Host(server.public_net.ipv6?.ip);
  if (host === undefined) {
    throw new FrostyError(`Box ${server.name} has no public IPv${family} address.`, "This is a bug in frosty. Please report it.");
  }
  return { host, user: ctx.config.adminUser, keyPath: ctx.keyPath, hostKeyAlias: hostKeyAlias(box) };
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
