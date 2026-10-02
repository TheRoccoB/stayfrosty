import { readFileSync } from "node:fs";
import { closeSshMaster, systemSsh, forgetHost, type SshRunner, type SshTarget } from "./box.ts";
import { isPublicKey } from "./cloudinit.ts";
import { Cloudflare } from "./cloudflare.ts";
import { expandHome, loadConfig, type Config, type Env } from "./config.ts";
import { FrostyError } from "./errors.ts";
import { Hetzner, type HzServer } from "./hetzner.ts";
import { realSleep, type Fetch, type Sleep } from "./http.ts";
import type { Io } from "./io.ts";
import { findLaptopIp, type LaptopIp } from "./ip.ts";
import { shellPasswordCommand, type PasswordCommandRunner } from "./password.ts";
import { loadTokens } from "./tokens.ts";

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
  laptopIp?: () => Promise<LaptopIp>;
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
  laptopIp: () => Promise<LaptopIp>;
  isTty: boolean;
  runPasswordCommand: PasswordCommandRunner;
  keyPath: string;
  publicKey: string;
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
    laptopIp: deps.laptopIp ?? (() => findLaptopIp(fetchImpl)),
    isTty: deps.isTty ?? (process.stdin.isTTY === true && process.stdout.isTTY === true),
    runPasswordCommand: deps.runPasswordCommand ?? shellPasswordCommand,
    keyPath,
    publicKey,
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
export function directTarget(ctx: Context, server: HzServer, family: 4 | 6): SshTarget {
  const host = family === 4 ? server.public_net.ipv4?.ip : ipv6Host(server.public_net.ipv6?.ip);
  if (host === undefined) {
    throw new FrostyError(`Box ${server.name} has no public IPv${family} address.`, "This is a bug in frosty. Please report it.");
  }
  return { host, user: ctx.config.adminUser, keyPath: ctx.keyPath };
}

// Hetzner reports the box's IPv6 as a /64 network; the box itself answers on ::1 within it.
export function ipv6Host(network: string | undefined): string | undefined {
  if (network === undefined) {
    return undefined;
  }
  return network.replace(/\/64$/, "").replace(/::$/, "::1");
}
