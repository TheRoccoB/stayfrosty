import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { Cloudflare, type CfTokenStatus, type CfZone } from "../cloudflare.ts";
import {
  DEFAULTS,
  configPath,
  expandHome,
  isAdminUser,
  isDomain,
  isEmail,
  isRebootTime,
  isSessionDuration,
  readConfigFile,
  saveConfig,
  validateConfig,
  type Config,
  type Env,
} from "../config.ts";
import { ApiError, FrostyError } from "../errors.ts";
import { Hetzner, LABEL_MANAGED, type HzImage, type HzLocation, type HzServerType } from "../hetzner.ts";
import type { Fetch, Sleep } from "../http.ts";
import { green, red, table, yellow, type Io } from "../io.ts";
import { redactJson } from "../redact.ts";
import { TOKEN_HELP, loadTokens } from "../tokens.ts";

export interface InitDeps {
  io: Io;
  dryRun: boolean;
  env?: Env;
  fetch?: Fetch;
  sleep?: Sleep;
}

interface Check {
  name: string;
  ok: boolean;
  warn?: boolean;
  detail: string;
}

const PREFERRED_LOCATION = "fsn1";
const MAX_TRIES = 5;

export async function runInit(deps: InitDeps): Promise<number> {
  const io = deps.io;
  const env = deps.env ?? process.env;
  const path = configPath(env);

  io.out("frosty init asks for your settings, checks both API tokens with read-only calls,");
  io.out(`and writes ${path}. It creates nothing in Hetzner or Cloudflare.`);
  io.out("");

  const tokens = loadTokens(env);
  const previous = await loadPrevious(path, io);
  const hetzner = new Hetzner({ token: tokens.hetzner, fetch: deps.fetch, sleep: deps.sleep });
  const cloudflare = new Cloudflare({ token: tokens.cloudflare, fetch: deps.fetch, sleep: deps.sleep });
  const checks: Check[] = [];

  // Hetzner first: everything after the domain question needs its read access.
  let foreignServers = 0;
  try {
    const servers = await hetzner.listServers();
    foreignServers = servers.filter((s) => s.labels[LABEL_MANAGED] !== "1").length;
    checks.push({ name: "Hetzner token can read the project", ok: true, detail: `${servers.length} server(s) in this project` });
  } catch (error) {
    throw tokenProblem("Hetzner", error);
  }
  if (foreignServers > 0) {
    checks.push({
      name: "Hetzner project used only for stayfrosty",
      ok: true,
      warn: true,
      detail: `${foreignServers} server(s) here were not made by frosty. A project of its own limits what a leaked token can touch.`,
    });
  }
  checks.push({
    name: "Hetzner token can write",
    ok: true,
    warn: true,
    detail: "Hetzner has no call that reports a token's permissions. Write access is confirmed the first time frosty creates something.",
  });

  // Domain, which also gives us the zone and account IDs.
  let zone: CfZone | undefined;
  let domain = "";
  for (let tries = 0; zone === undefined; tries += 1) {
    if (tries >= MAX_TRIES) {
      throw new FrostyError("No usable domain after several tries.", `Add the domain to Cloudflare and include it in the token's Zone resources, then run: frosty init`);
    }
    domain = (await askValid(io, "Cloudflare domain for SSH hostnames (ssh-<box>.<domain>)", previous?.domain, (v) => (isDomain(v.toLowerCase()) ? undefined : "Enter a domain like example.com."))).toLowerCase();
    try {
      zone = await cloudflare.findZone(domain);
    } catch (error) {
      throw tokenProblem("Cloudflare", error);
    }
    if (zone === undefined) {
      io.err(`The Cloudflare token cannot see a zone named ${domain}. Either it is not in your account, or the token's Zone resources do not include it.`);
    }
  }
  checks.push({ name: "Cloudflare Zone Read", ok: true, detail: `${zone.name} (${zone.status})` });
  const accountId = zone.account.id;

  const status = await verifyCloudflareToken(cloudflare, accountId);
  checks.push({ name: "Cloudflare token is active", ok: status.status === "active", detail: `status ${status.status}${status.expires_on === undefined ? "" : `, expires ${status.expires_on}`}` });

  const zoneScope = await cloudflare.firstZones();
  if (zoneScope.total > 1) {
    checks.push({
      name: "Cloudflare token limited to one zone",
      ok: true,
      warn: true,
      detail: `the token can see ${zoneScope.total} zones. Limit its Zone resources to ${domain} only.`,
    });
  } else {
    checks.push({ name: "Cloudflare token limited to one zone", ok: true, detail: "only this zone is visible" });
  }

  checks.push(await readCheck("Cloudflare DNS (Zone, DNS Write)", async () => `${await cloudflare.countDnsRecords(zone.id)} record(s) readable`));
  checks.push(await readCheck("Cloudflare Tunnel (Account, Cloudflare Tunnel Edit or Write)", async () => `${(await cloudflare.listTunnels(accountId, { is_deleted: false })).length} tunnel(s) readable`));
  checks.push(await readCheck("Cloudflare Access (Account, Access: Apps and Policies Edit or Write)", async () => `${(await cloudflare.listAccessApps(accountId)).length} Access app(s) readable`));
  checks.push(await readCheck("Cloudflare Notifications (Account, Notifications Edit or Write)", async () => `${(await cloudflare.listNotificationPolicies(accountId)).length} notification polic(ies) readable`));
  checks.push({
    name: "Cloudflare Edit/Write permissions",
    ok: true,
    warn: true,
    detail: "a token cannot list its own permissions, so read access is checked here and write access is confirmed on first use.",
  });

  // The rest of the settings.
  const accessEmails = parseEmails(
    await askValid(io, "Emails allowed through Cloudflare Access (comma separated)", previous?.accessEmails.join(", "), (v) =>
      parseEmails(v).length > 0 && parseEmails(v).every(isEmail) ? undefined : "Enter one or more emails, separated by commas.",
    ),
  );
  const alertEmail = await askValid(io, "Email for tunnel-down alerts", previous?.alertEmail ?? accessEmails[0], (v) => (isEmail(v) ? undefined : "Enter one email."));
  const adminUser = await askValid(io, "Admin user on every box", previous?.adminUser ?? DEFAULTS.adminUser, (v) =>
    isAdminUser(v) ? undefined : "Use a lowercase Linux user name (letters, digits, _ or -), not root.",
  );
  const sshKey = await askValid(io, "SSH private key (its .pub must sit next to it)", previous?.sshKey ?? defaultSshKey(env), (v) => sshKeyProblem(v, env));
  const publicKey = readFileSync(`${expandHome(sshKey, env)}.pub`, "utf8").trim();

  const locations = await hetzner.listLocations();
  io.out("");
  io.out("Hetzner locations (EU locations include far more traffic than US ones):");
  for (const line of table(locations.map((l) => [`  ${l.name}`, `${l.city}, ${l.country}`, l.network_zone]))) {
    io.out(line);
  }
  const location = await askValid(io, "Location", pickLocation(locations, previous?.location), (v) =>
    locations.some((l) => l.name === v) ? undefined : `Pick one of: ${locations.map((l) => l.name).join(", ")}.`,
  );

  const types = availableServerTypes(await hetzner.listServerTypes(), location);
  if (types.length === 0) {
    throw new FrostyError(`Hetzner offers no server types in ${location} right now.`, "Run frosty init again and pick another location.");
  }
  io.out("");
  io.out(`Server types in ${location}, cheapest first:`);
  const shown = types.slice(0, 10);
  for (const line of table([["  NAME", "ARCH", "CPU", "RAM", "DISK", "EUR/MONTH", "TRAFFIC"], ...shown.map((t) => serverTypeRow(t, location))])) {
    io.out(line);
  }
  const typeNames = types.map((t) => t.name);
  const serverTypeName = await askValid(io, "Server type", previous !== undefined && typeNames.includes(previous.serverType) ? previous.serverType : types[0]?.name, (v) =>
    typeNames.includes(v) ? undefined : `Pick an available type, e.g. ${typeNames.slice(0, 3).join(", ")}.`,
  );
  const serverType = types.find((t) => t.name === serverTypeName) as HzServerType;

  const images = ubuntuLtsImages(await hetzner.listSystemImages(serverType.architecture));
  if (images.length === 0) {
    throw new FrostyError(`Hetzner lists no Ubuntu LTS image for ${serverType.architecture}.`, "Run frosty init again and pick another server type.");
  }
  const imageNames = images.map((i) => i.name as string);
  const image = await askValid(io, `Image (Ubuntu LTS: ${imageNames.join(", ")})`, previous !== undefined && imageNames.includes(previous.image) ? previous.image : imageNames[0], (v) =>
    imageNames.includes(v) ? undefined : `Pick one of: ${imageNames.join(", ")}.`,
  );

  const rebootTime = await askValid(io, "Automatic reboot time, box local time (HH:MM)", previous?.rebootTime ?? DEFAULTS.rebootTime, (v) =>
    isRebootTime(v) ? undefined : "Use 24 hour HH:MM, like 04:00.",
  );
  const accessSessionDuration = await askValid(io, "Access session duration", previous?.accessSessionDuration ?? DEFAULTS.accessSessionDuration, (v) =>
    isSessionDuration(v) ? undefined : "Use minutes or hours, like 24h or 30m.",
  );
  if (commandExists("op", env)) {
    io.out("");
    io.out("1Password CLI found. passwordCommand can store each box's console password with it.");
  }
  io.out("passwordCommand (optional) receives the console password on stdin; {box} is replaced with the box name.");
  io.out("Leave it empty to have the password printed once instead.");
  const passwordCommandAnswer = await io.ask("passwordCommand", previous?.passwordCommand ?? "");

  const config: Config = {
    domain,
    accountId,
    zoneId: zone.id,
    accessEmails,
    alertEmail,
    adminUser,
    sshKey,
    location,
    serverType: serverType.name,
    image,
    rebootTime,
    accessSessionDuration,
  };
  if (passwordCommandAnswer.trim().length > 0) {
    config.passwordCommand = passwordCommandAnswer.trim();
  }

  const keys = await hetzner.listSshKeys();
  const keyBody = publicKey.split(/\s+/).slice(0, 2).join(" ");
  const uploaded = keys.find((k) => k.public_key.split(/\s+/).slice(0, 2).join(" ") === keyBody);
  checks.push({
    name: "SSH public key in Hetzner",
    ok: true,
    detail: uploaded === undefined ? "not uploaded yet; frosty new uploads it once" : `already uploaded as "${uploaded.name}"`,
  });

  io.out("");
  printChecks(io, checks);
  io.out("");

  const problems = validateConfig(config);
  if (problems.length > 0) {
    throw new FrostyError(`The settings are not valid: ${problems.join("; ")}.`, "Run: frosty init");
  }
  if (deps.dryRun) {
    io.out(`Dry run: would write ${path}:`);
    io.out(redactJson(config));
  } else {
    await saveConfig(config, env);
    io.out(`Wrote ${path} (mode 600).`);
  }
  io.out("Nothing was created in Hetzner or Cloudflare.");

  const failed = checks.filter((c) => !c.ok);
  if (failed.length > 0) {
    io.err("");
    io.err(`${failed.length} check(s) failed. Fix the token permissions listed above, then run: frosty init`);
    io.err("");
    io.err(TOKEN_HELP);
    return 1;
  }
  return 0;
}

async function loadPrevious(path: string, io: Io): Promise<Config | undefined> {
  const raw = await readConfigFile(path);
  if (raw === undefined) {
    return undefined;
  }
  if (validateConfig(raw).length > 0) {
    io.err(`Ignoring the existing ${path}: it has problems. Its values will not be offered as defaults.`);
    return undefined;
  }
  io.out(`Found ${path}. Press Enter to keep each current value.`);
  io.out("");
  return raw as Config;
}

async function verifyCloudflareToken(cloudflare: Cloudflare, accountId: string): Promise<CfTokenStatus> {
  try {
    return await cloudflare.verifyToken(accountId);
  } catch (error) {
    throw tokenProblem("Cloudflare", error);
  }
}

function tokenProblem(api: "Hetzner" | "Cloudflare", error: unknown): FrostyError {
  if (error instanceof FrostyError && !(error instanceof ApiError)) {
    return error;
  }
  const reason = error instanceof Error ? error.message : String(error);
  return new FrostyError(`The ${api} token check failed. ${reason}`, TOKEN_HELP);
}

async function readCheck(name: string, read: () => Promise<string>): Promise<Check> {
  try {
    return { name, ok: true, detail: await read() };
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      return { name, ok: false, detail: "the token cannot read this. Add the permission shown in the name." };
    }
    throw error;
  }
}

function printChecks(io: Io, checks: Check[]): void {
  const rows = checks.map((c) => [c.ok ? (c.warn === true ? yellow("note") : green("pass")) : red("FAIL"), c.name, c.detail]);
  for (const line of table(rows)) {
    io.out(line);
  }
}

async function askValid(io: Io, question: string, defaultValue: string | undefined, problem: (value: string) => string | undefined): Promise<string> {
  for (let tries = 0; tries < MAX_TRIES; tries += 1) {
    const answer = (await io.ask(question, defaultValue)).trim();
    const message = problem(answer);
    if (message === undefined) {
      return answer;
    }
    io.err(message);
  }
  throw new FrostyError(`No valid answer for "${question}" after ${MAX_TRIES} tries. Nothing was written.`, "Run: frosty init");
}

export function parseEmails(value: string): string[] {
  return value
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length > 0);
}

function defaultSshKey(env: Env): string | undefined {
  for (const name of ["id_ed25519", "id_ecdsa", "id_rsa"]) {
    if (existsSync(expandHome(`~/.ssh/${name}.pub`, env))) {
      return `~/.ssh/${name}`;
    }
  }
  return undefined;
}

function sshKeyProblem(value: string, env: Env): string | undefined {
  if (value.length === 0) {
    return "Enter the path to your SSH private key, e.g. ~/.ssh/id_ed25519. Create one with: ssh-keygen -t ed25519";
  }
  const path = expandHome(value, env);
  if (!existsSync(path)) {
    return `${path} does not exist. Create a key with: ssh-keygen -t ed25519`;
  }
  if (!existsSync(`${path}.pub`)) {
    return `${path}.pub does not exist. Recreate it with: ssh-keygen -y -f ${path} > ${path}.pub`;
  }
  const pub = readFileSync(`${path}.pub`, "utf8").trim();
  if (!/^(ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) /.test(pub)) {
    return `${path}.pub does not look like an OpenSSH public key.`;
  }
  return undefined;
}

export function pickLocation(locations: HzLocation[], previous: string | undefined): string | undefined {
  if (previous !== undefined && locations.some((l) => l.name === previous)) {
    return previous;
  }
  if (locations.some((l) => l.name === PREFERRED_LOCATION)) {
    return PREFERRED_LOCATION;
  }
  return locations.find((l) => l.network_zone.startsWith("eu-"))?.name ?? locations[0]?.name;
}

function isDeprecated(value: unknown): boolean {
  return value !== undefined && value !== null && value !== false;
}

// Server types orderable in the location, cheapest first.
export function availableServerTypes(types: HzServerType[], location: string): HzServerType[] {
  const priced = types.filter((t) => {
    if (isDeprecated(t.deprecated) || isDeprecated(t.deprecation)) {
      return false;
    }
    if (!t.prices.some((p) => p.location === location)) {
      return false;
    }
    if (t.locations !== undefined) {
      const here = t.locations.find((l) => l.name === location);
      if (here === undefined || here.available === false || isDeprecated(here.deprecation)) {
        return false;
      }
    }
    return true;
  });
  return priced.sort((a, b) => monthly(a, location) - monthly(b, location) || a.name.localeCompare(b.name));
}

function monthly(type: HzServerType, location: string): number {
  const price = type.prices.find((p) => p.location === location);
  return price === undefined ? Number.POSITIVE_INFINITY : Number(price.price_monthly.gross);
}

function serverTypeRow(type: HzServerType, location: string): string[] {
  const price = type.prices.find((p) => p.location === location);
  const traffic = price?.included_traffic === undefined ? "?" : `${Math.round(price.included_traffic / 1e12)} TB`;
  const cost = price === undefined ? "?" : `${Number(price.price_monthly.gross).toFixed(2)}`;
  return [`  ${type.name}`, type.architecture, `${type.cores} ${type.cpu_type}`, `${type.memory} GB`, `${type.disk} GB`, cost, traffic];
}

// Ubuntu LTS releases are YY.04 with an even YY. Newest first.
export function ubuntuLtsImages(images: HzImage[]): HzImage[] {
  return images
    .filter((i) => i.os_flavor === "ubuntu" && i.name !== null && !isDeprecated(i.deprecated) && !isDeprecated(i.deprecation) && i.status === "available")
    .filter((i) => {
      const match = /^(\d{2})\.04$/.exec(i.os_version ?? "");
      return match !== null && Number(match[1]) % 2 === 0;
    })
    .sort((a, b) => Number(b.os_version) - Number(a.os_version));
}

export function commandExists(name: string, env: Env): boolean {
  for (const dir of (env["PATH"] ?? "").split(delimiter)) {
    if (dir.length === 0) {
      continue;
    }
    try {
      accessSync(join(dir, name), constants.X_OK);
      return true;
    } catch {
      continue;
    }
  }
  return false;
}
