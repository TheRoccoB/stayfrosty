import { parseArgs } from "node:util";
import { FrostyError } from "./errors.ts";
import { terminalIo, type Io } from "./io.ts";
import { redact } from "./redact.ts";
import { runInit } from "./commands/init.ts";
import { runAdopt } from "./commands/adopt.ts";
import { runConsolePassword } from "./commands/console-password.ts";
import { runDestroy } from "./commands/destroy.ts";
import { runSshConfig } from "./commands/ssh-config.ts";
import { runDetachForeign } from "./commands/detach-foreign.ts";
import { runLs } from "./commands/ls.ts";
import { runNew } from "./commands/new.ts";
import { runVerify } from "./commands/verify.ts";
import { runRoute } from "./commands/route.ts";
import { runServiceTokens } from "./commands/service-tokens.ts";
import { runSshUsers } from "./commands/ssh-users.ts";
import { VERSION } from "./version.ts";

const USAGE = `frosty ${VERSION}: a VPS with no front door

Usage:
  frosty init                         write config, check tokens (creates nothing)
  frosty new <box> [--type T] [--location L] [--resume]
  frosty adopt <box> --ip <ip> [--user U] (--host-key SHA256:... | --trust-first-use) [--resume]
  frosty verify (<box> | --all)       check a box again, through the tunnel (changes nothing);
                                      exit 1 if a check failed, 3 if --all skipped a provider
  frosty detach-foreign <box>         detach other firewalls from an adopted box (keeps frosty's)
  frosty route (plan | sync) <box>    web apps through the box's tunnel (config: routes)
  frosty ssh-users (plan | sync) <box>  forced-command-only SSH users (config: restrictedUsers)
  frosty service-tokens (plan | sync) <box>  Access service tokens for the box's SSH (config: serviceTokens)
  frosty breakglass <box> [--minutes N | --close]
  frosty ls
  frosty ssh-config                   rewrite ~/.ssh/stayfrosty.conf from the APIs
  frosty destroy <box>                type the box name to confirm
  frosty console-password <box>       set a new password for the provider's web console

Flags:
  --dry-run    print what would change, change nothing (init, new, adopt, detach-foreign,
               ssh-config, destroy, console-password; route, ssh-users and service-tokens
               use plan instead)
  --help       show this help
  --version    show the version

A flag or word a command doesn't take is refused, and nothing runs.

Tokens come from HCLOUD_TOKEN and CLOUDFLARE_API_TOKEN, plus DIGITALOCEAN_TOKEN for boxes on
DigitalOcean. Run "frosty init" for details.`;

// Commands from later milestones, so nobody mistakes a missing command for a broken one.
const PLANNED: Record<string, string> = {
  breakglass: "M3",
};

// What each command takes besides --help and --version: its flags, and how many words it takes
// after its own name. Anything else is refused before the command runs, so a misspelt or misplaced
// flag (say --dry-run on a command that doesn't honour it) can't be silently ignored while the
// command goes ahead and changes things.
interface CommandShape {
  flags: string[];
  args: number;
}

const COMMANDS: Record<string, CommandShape> = {
  init: { flags: ["dry-run"], args: 0 },
  ls: { flags: [], args: 0 },
  new: { flags: ["dry-run", "resume", "type", "location"], args: 1 },
  adopt: { flags: ["dry-run", "resume", "ip", "user", "host-key", "trust-first-use"], args: 1 },
  verify: { flags: ["all"], args: 1 },
  route: { flags: [], args: 2 },
  "ssh-users": { flags: [], args: 2 },
  "service-tokens": { flags: [], args: 2 },
  "detach-foreign": { flags: ["dry-run"], args: 1 },
  "ssh-config": { flags: ["dry-run"], args: 0 },
  destroy: { flags: ["dry-run"], args: 1 },
  "console-password": { flags: ["dry-run", "direct"], args: 1 },
};

// Commands whose plan action is their dry run.
const PLAN_SYNC = new Set(["route", "ssh-users", "service-tokens"]);

const OPTIONS = {
  help: { type: "boolean", short: "h" },
  version: { type: "boolean" },
  "dry-run": { type: "boolean" },
  resume: { type: "boolean" },
  direct: { type: "boolean" },
  type: { type: "string" },
  location: { type: "string" },
  ip: { type: "string" },
  user: { type: "string" },
  "host-key": { type: "string" },
  "trust-first-use": { type: "boolean" },
  all: { type: "boolean" },
} as const;

// strict: an unknown flag, a value on a yes/no flag (--dry-run=false) or a flag missing its value
// is an error, not something to guess at.
function parse(argv: string[]) {
  return parseArgs({ args: argv, allowPositionals: true, strict: true, options: OPTIONS });
}

export async function main(argv: string[], io: Io): Promise<number> {
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(argv);
  } catch (error) {
    io.err(`${error instanceof Error ? error.message : String(error)}`);
    io.err("Nothing was changed. Run: frosty --help");
    return 2;
  }
  const { values, positionals } = parsed;
  const command = positionals[0];
  if (values["version"] === true) {
    io.out(VERSION);
    return 0;
  }
  if (command === undefined || values["help"] === true || command === "help") {
    io.out(USAGE);
    return 0;
  }
  const refused = shapeProblem(command, values, positionals);
  if (refused !== undefined) {
    io.err(refused);
    io.err("Nothing was changed. Run: frosty --help");
    return 2;
  }
  const dryRun = values["dry-run"] === true;
  switch (command) {
    case "init":
      return runInit({ io, dryRun });
    case "ls":
      return runLs({ io });
    case "new":
      return runNew({ io }, { box: positionals[1], resume: values["resume"] === true, dryRun, serverType: stringFlag(values["type"]), location: stringFlag(values["location"]) });
    case "adopt":
      return runAdopt(
        { io },
        {
          box: positionals[1],
          ip: stringFlag(values["ip"]),
          user: stringFlag(values["user"]) ?? "root",
          hostKey: stringFlag(values["host-key"]),
          trustFirstUse: values["trust-first-use"] === true,
          resume: values["resume"] === true,
          dryRun,
        },
      );
    case "verify":
      return runVerify({ io }, { box: positionals[1], all: values["all"] === true });
    case "route":
      return runRoute({ io }, { action: positionals[1], box: positionals[2] });
    case "ssh-users":
      return runSshUsers({ io }, { action: positionals[1], box: positionals[2] });
    case "service-tokens":
      return runServiceTokens({ io }, { action: positionals[1], box: positionals[2] });
    case "detach-foreign":
      return runDetachForeign({ io }, { box: positionals[1], dryRun });
    case "ssh-config":
      return runSshConfig({ io }, { dryRun });
    case "destroy":
      return runDestroy({ io }, { box: positionals[1], dryRun });
    case "console-password":
      return runConsolePassword({ io }, { box: positionals[1], dryRun, direct: values["direct"] === true });
    default: {
      const milestone = PLANNED[command];
      if (milestone !== undefined) {
        io.err(`"frosty ${command}" is planned for milestone ${milestone} and is not built yet. Nothing was changed.`);
        return 2;
      }
      io.err(`Unknown command "${command}". Run: frosty --help`);
      return 2;
    }
  }
}

// Why this command line is refused, or undefined. Unknown commands are left to main.
export function shapeProblem(command: string, values: Record<string, unknown>, positionals: string[]): string | undefined {
  const shape = COMMANDS[command];
  if (shape === undefined) {
    return undefined;
  }
  for (const flag of Object.keys(values)) {
    if (flag === "help" || flag === "version" || shape.flags.includes(flag)) {
      continue;
    }
    if (flag === "dry-run" && PLAN_SYNC.has(command)) {
      // plan already changes nothing; sync --dry-run would be a sync that changes things.
      if (positionals[1] === "plan") {
        continue;
      }
      return `frosty ${command} has no --dry-run. Use "frosty ${command} plan <box>": it shows what sync would change, and changes nothing.`;
    }
    return `frosty ${command} doesn't take --${flag}.`;
  }
  const extra = positionals.slice(1 + shape.args);
  if (extra.length > 0) {
    return `frosty ${command} doesn't take ${extra.map((x) => `"${x}"`).join(" ")}.`;
  }
  return undefined;
}

function stringFlag(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function reportError(error: unknown, io: Io): number {
  if (error instanceof FrostyError) {
    io.err(`Error: ${error.message}`);
    if (error.hint !== undefined) {
      io.err("");
      io.err(error.hint);
    }
    return 1;
  }
  const text = error instanceof Error ? (error.stack ?? error.message) : String(error);
  io.err(`Unexpected error: ${redact(text)}`);
  io.err("This is a bug in frosty. Nothing after the failing step ran. Please report it with the output above.");
  return 1;
}

export async function run(): Promise<void> {
  const io = terminalIo();
  let code: number;
  try {
    code = await main(process.argv.slice(2), io);
  } catch (error) {
    code = reportError(error, io);
  } finally {
    io.close();
  }
  process.exitCode = code;
}

