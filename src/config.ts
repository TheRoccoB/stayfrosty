import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { FrostyError } from "./errors.ts";

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
  accessSessionDuration: string;
  passwordCommand?: string;
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
  const duration = requireString("accessSessionDuration");
  if (duration !== undefined && !isSessionDuration(duration)) {
    problems.push(`accessSessionDuration "${duration}" must look like 24h or 30m`);
  }
  const passwordCommand = c["passwordCommand"];
  if (passwordCommand !== undefined && typeof passwordCommand !== "string") {
    problems.push("passwordCommand must be a string");
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
