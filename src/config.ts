import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { FrostyError } from "./errors.ts";
import { PROVIDER_KINDS, type ProviderKind } from "./provider.ts";
import { SERVICE_TOKEN_NAME, validateRouteHostnames, validateRoutes, type Route } from "./routes.ts";
import { validateRestrictedUsers, type RestrictedUser } from "./sshusers.ts";

export interface Config {
  domain: string;
  accountId: string;
  zoneId: string;
  accessEmails: string[];
  alertEmail: string;
  adminUser: string;
  sshKey: string;
  location: string;
  serverType: string;
  image: string;
  rebootTime: string;
  // Per-box reboot times (box local time, which is UTC on Hetzner's images), so boxes that depend on
  // each other never reboot together. Boxes not listed use rebootTime.
  rebootTimes?: Record<string, string>;
  accessSessionDuration: string;
  passwordCommand?: string;
  // Optional JSON-lines logs of every API write (see changelog.ts). Absolute paths.
  hetznerChangeLog?: string;
  cloudflareChangeLog?: string;
  // JSON-lines log of every on-box change frosty makes outside new and adopt (ssh-users sync).
  boxChangeLog?: string;
  // Web apps served through a box's tunnel (routes.ts), by box. Their hostnames must be in appZones.
  routes?: Record<string, Route[]>;
  appZones?: string[];
  // The Access team name (<team>.cloudflareaccess.com), for cloudflared's own token check.
  accessTeam?: string;
  // Extra forced-command-only SSH users (sshusers.ts), by box. Applied with frosty ssh-users sync.
  restrictedUsers?: Record<string, RestrictedUser[]>;
  // Names of existing Cloudflare Access service tokens allowed into a box's SSH, by box. Applied
  // with frosty service-tokens sync. A token opens exactly one box.
  serviceTokens?: Record<string, string[]>;
  // Boxes that live on another cloud than Hetzner, by box name. Boxes not listed are Hetzner's.
  boxProviders?: Record<string, ProviderKind>;
  // Settings for boxes on DigitalOcean. Needed once any box is on DigitalOcean.
  digitalocean?: DigitalOceanSettings;
  digitaloceanChangeLog?: string;
}

export interface DigitalOceanSettings {
  // Slugs, e.g. "fra1", "s-1vcpu-512mb-10gb", "ubuntu-24-04-x64".
  region: string;
  size: string;
  image: string;
  // DigitalOcean's weekly droplet backups (a paid add-on).
  backups?: boolean;
}

export const DEFAULTS = {
  adminUser: "ops",
  rebootTime: "04:00",
  accessSessionDuration: "24h",
} as const;

export type Env = Record<string, string | undefined>;

export function configPath(env: Env = process.env): string {
  const base = env["XDG_CONFIG_HOME"] !== undefined && env["XDG_CONFIG_HOME"] !== "" ? env["XDG_CONFIG_HOME"] : join(env["HOME"] ?? homedir(), ".config");
  return join(base, "stayfrosty", "config.json");
}

export function expandHome(path: string, env: Env = process.env): string {
  if (path === "~") {
    return env["HOME"] ?? homedir();
  }
  if (path.startsWith("~/")) {
    return join(env["HOME"] ?? homedir(), path.slice(2));
  }
  return path;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const DURATION = /^\d+(m|h)$/;

export function isEmail(value: string): boolean {
  return EMAIL.test(value);
}

export function isDomain(value: string): boolean {
  return DOMAIN.test(value);
}

export function isAdminUser(value: string): boolean {
  return USER.test(value) && value !== "root";
}

export function isRebootTime(value: string): boolean {
  return TIME.test(value);
}

export function isSessionDuration(value: string): boolean {
  return DURATION.test(value);
}

// Returns a list of problems, empty when the config is usable.
export function validateConfig(value: unknown): string[] {
  const problems: string[] = [];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return ["the file is not a JSON object"];
  }
  const c = value as Record<string, unknown>;
  const requireString = (key: string): string | undefined => {
    const v = c[key];
    if (typeof v !== "string" || v.length === 0) {
      problems.push(`${key} is missing`);
      return undefined;
    }
    return v;
  };
  const domain = requireString("domain");
  if (domain !== undefined && !isDomain(domain)) {
    problems.push(`domain "${domain}" is not a valid domain name`);
  }
  requireString("accountId");
  requireString("zoneId");
  const emails = c["accessEmails"];
  if (!Array.isArray(emails) || emails.length === 0) {
    problems.push("accessEmails needs at least one email");
  } else {
    for (const email of emails) {
      if (typeof email !== "string" || !isEmail(email)) {
        problems.push(`accessEmails has an invalid email: ${String(email)}`);
      }
    }
  }
  const alertEmail = requireString("alertEmail");
  if (alertEmail !== undefined && !isEmail(alertEmail)) {
    problems.push(`alertEmail "${alertEmail}" is not a valid email`);
  }
  const adminUser = requireString("adminUser");
  if (adminUser !== undefined && !isAdminUser(adminUser)) {
    problems.push(`adminUser "${adminUser}" must be a lowercase Linux user name and not root`);
  }
  requireString("sshKey");
  requireString("location");
  requireString("serverType");
  requireString("image");
  const rebootTime = requireString("rebootTime");
  if (rebootTime !== undefined && !isRebootTime(rebootTime)) {
    problems.push(`rebootTime "${rebootTime}" must look like 04:00`);
  }
  const rebootTimes = c["rebootTimes"];
  if (rebootTimes !== undefined) {
    if (rebootTimes === null || typeof rebootTimes !== "object" || Array.isArray(rebootTimes)) {
      problems.push("rebootTimes must be an object of box name to HH:MM");
    } else {
      for (const [box, time] of Object.entries(rebootTimes as Record<string, unknown>)) {
        if (!/^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/.test(box) || typeof time !== "string" || !isRebootTime(time)) {
          problems.push(`rebootTimes.${box} must be a box name mapped to a time like 04:00`);
        }
      }
    }
  }
  const duration = requireString("accessSessionDuration");
  if (duration !== undefined && !isSessionDuration(duration)) {
    problems.push(`accessSessionDuration "${duration}" must look like 24h or 30m`);
  }
  const passwordCommand = c["passwordCommand"];
  if (passwordCommand !== undefined && typeof passwordCommand !== "string") {
    problems.push("passwordCommand must be a string");
  }
  const appZones = c["appZones"];
  if (appZones !== undefined && (!Array.isArray(appZones) || appZones.some((z) => typeof z !== "string" || !isDomain(z) || z === domain))) {
    problems.push("appZones must be a list of domain names, not including domain");
  }
  const routes = c["routes"];
  if (routes !== undefined) {
    if (routes === null || typeof routes !== "object" || Array.isArray(routes)) {
      problems.push("routes must be an object of box name to a list of routes");
    } else {
      const zones = Array.isArray(appZones) ? appZones.filter((z): z is string => typeof z === "string") : [];
      const team = typeof c["accessTeam"] === "string" ? c["accessTeam"] : undefined;
      for (const [box, list] of Object.entries(routes as Record<string, unknown>)) {
        if (!/^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/.test(box)) {
          problems.push(`routes.${box}: not a box name`);
          continue;
        }
        problems.push(...validateRoutes(box, list, { domain: domain ?? "", appZones: zones, accessTeam: team }));
      }
      if (problems.length === 0) {
        problems.push(...validateRouteHostnames(routes as Record<string, Route[]>));
      }
      if (problems.length === 0) {
        problems.push(...validateTokenPlaces(c["serviceTokens"], routes as Record<string, Route[]>));
      }
    }
  }
  const restricted = c["restrictedUsers"];
  if (restricted !== undefined) {
    if (restricted === null || typeof restricted !== "object" || Array.isArray(restricted)) {
      problems.push("restrictedUsers must be an object of box name to a list of users");
    } else {
      for (const [box, list] of Object.entries(restricted as Record<string, unknown>)) {
        if (!/^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/.test(box)) {
          problems.push(`restrictedUsers.${box}: not a box name`);
          continue;
        }
        problems.push(...validateRestrictedUsers(box, list, adminUser ?? ""));
      }
    }
  }
  problems.push(...validateServiceTokens(c["serviceTokens"]));
  problems.push(...validateProviders(c["boxProviders"], c["digitalocean"]));
  for (const key of ["hetznerChangeLog", "cloudflareChangeLog", "boxChangeLog", "digitaloceanChangeLog"]) {
    const v = c[key];
    if (v !== undefined && (typeof v !== "string" || !v.startsWith("/"))) {
      problems.push(`${key} must be an absolute path`);
    }
  }
  return problems;
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function validateProviders(boxProviders: unknown, digitalocean: unknown): string[] {
  const problems: string[] = [];
  let usesDigitalOcean = false;
  if (boxProviders !== undefined) {
    if (boxProviders === null || typeof boxProviders !== "object" || Array.isArray(boxProviders)) {
      problems.push("boxProviders must be an object of box name to a provider (hetzner or digitalocean)");
    } else {
      for (const [box, kind] of Object.entries(boxProviders as Record<string, unknown>)) {
        if (!/^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/.test(box) || typeof kind !== "string" || !(PROVIDER_KINDS as readonly string[]).includes(kind)) {
          problems.push(`boxProviders.${box} must be a box name mapped to ${PROVIDER_KINDS.join(" or ")}`);
        }
        usesDigitalOcean ||= kind === "digitalocean";
      }
    }
  }
  if (digitalocean !== undefined) {
    if (digitalocean === null || typeof digitalocean !== "object" || Array.isArray(digitalocean)) {
      problems.push("digitalocean must be an object with region, size and image");
    } else {
      const d = digitalocean as Record<string, unknown>;
      for (const key of ["region", "size", "image"]) {
        if (typeof d[key] !== "string" || !SLUG.test(d[key] as string)) {
          problems.push(`digitalocean.${key} must be a DigitalOcean slug, e.g. ${key === "region" ? "fra1" : key === "size" ? "s-1vcpu-512mb-10gb" : "ubuntu-24-04-x64"}`);
        }
      }
      if (d["backups"] !== undefined && typeof d["backups"] !== "boolean") {
        problems.push("digitalocean.backups must be true or false");
      }
      const extra = Object.keys(d).filter((k) => !["region", "size", "image", "backups"].includes(k));
      if (extra.length > 0) {
        problems.push(`digitalocean has unknown setting(s): ${extra.join(", ")}`);
      }
    }
  } else if (usesDigitalOcean) {
    problems.push("a box is on digitalocean in boxProviders, so the config needs a digitalocean section (region, size, image)");
  }
  return problems;
}

export function validateServiceTokens(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return ["serviceTokens must be an object of box name to a list of service token names"];
  }
  const problems: string[] = [];
  const owner = new Map<string, string>();
  for (const [box, list] of Object.entries(value as Record<string, unknown>)) {
    if (!/^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$/.test(box)) {
      problems.push(`serviceTokens.${box}: not a box name`);
      continue;
    }
    if (!Array.isArray(list)) {
      problems.push(`serviceTokens.${box} must be a list of service token names`);
      continue;
    }
    const seen = new Set<string>();
    for (const name of list) {
      if (typeof name !== "string" || !SERVICE_TOKEN_NAME.test(name)) {
        problems.push(`serviceTokens.${box} has an invalid token name: ${JSON.stringify(name)} (letters, digits, dots, dashes and underscores, up to 64)`);
        continue;
      }
      if (seen.has(name)) {
        problems.push(`serviceTokens.${box} lists ${name} twice`);
        continue;
      }
      seen.add(name);
      const other = owner.get(name);
      if (other !== undefined) {
        problems.push(`service token ${name} is listed under both ${other} and ${box}: a service token opens exactly one box`);
        continue;
      }
      owner.set(name, box);
    }
  }
  return problems;
}

// A service token opens exactly one Access app: one box's SSH (serviceTokens) or one route. The
// same name under two boxes' SSH is validateServiceTokens's message; this catches the rest.
export function validateTokenPlaces(serviceTokens: unknown, routes: Record<string, Route[]>): string[] {
  const places = new Map<string, string>();
  if (serviceTokens !== null && typeof serviceTokens === "object" && !Array.isArray(serviceTokens)) {
    for (const [box, list] of Object.entries(serviceTokens as Record<string, unknown>)) {
      for (const name of Array.isArray(list) ? list : []) {
        if (typeof name === "string" && !places.has(name)) {
          places.set(name, `serviceTokens.${box}`);
        }
      }
    }
  }
  const problems: string[] = [];
  for (const [box, list] of Object.entries(routes)) {
    for (const route of list) {
      for (const name of new Set(route.serviceTokens ?? [])) {
        const here = `routes.${box}/${route.name}`;
        const other = places.get(name);
        if (other !== undefined) {
          problems.push(`service token ${name} is listed under both ${other} and ${here}: a service token opens exactly one box or route`);
          continue;
        }
        places.set(name, here);
      }
    }
  }
  return problems;
}

export async function readConfigFile(path: string): Promise<unknown | undefined> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new FrostyError(`${path} is not valid JSON.`, "Fix the file by hand, or delete it and run: frosty init");
  }
}

export async function loadConfig(env: Env = process.env, warn: (line: string) => void = () => {}): Promise<Config> {
  const path = configPath(env);
  const raw = await readConfigFile(path);
  if (raw === undefined) {
    throw new FrostyError(`No config found at ${path}.`, "Run: frosty init");
  }
  const problems = validateConfig(raw);
  if (problems.length > 0) {
    throw new FrostyError(`The config at ${path} has problems: ${problems.join("; ")}.`, "Run: frosty init");
  }
  const info = await stat(path);
  if ((info.mode & 0o077) !== 0) {
    warn(`${path} is readable by other users on this laptop. Fix it with: chmod 600 ${path}`);
  }
  return raw as Config;
}

// Writes atomically, 0600 file in a 0700 directory.
export async function saveConfig(config: Config, env: Env = process.env): Promise<string> {
  const path = configPath(env);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, path);
  return path;
}

export function restrictedUsersFor(config: Pick<Config, "restrictedUsers">, box: string): RestrictedUser[] {
  return config.restrictedUsers !== undefined && Object.hasOwn(config.restrictedUsers, box) ? (config.restrictedUsers[box] as RestrictedUser[]) : [];
}

export function serviceTokensFor(config: Pick<Config, "serviceTokens">, box: string): string[] {
  return config.serviceTokens !== undefined && Object.hasOwn(config.serviceTokens, box) ? (config.serviceTokens[box] as string[]) : [];
}

export function providerKindFor(config: Pick<Config, "boxProviders">, box: string): ProviderKind {
  return config.boxProviders !== undefined && Object.hasOwn(config.boxProviders, box) ? (config.boxProviders[box] as ProviderKind) : "hetzner";
}

export function rebootTimeFor(config: Pick<Config, "rebootTime" | "rebootTimes">, box: string): string {
  return config.rebootTimes !== undefined && Object.hasOwn(config.rebootTimes, box) ? (config.rebootTimes[box] as string) : config.rebootTime;
}
