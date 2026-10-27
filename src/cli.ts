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
import { VERSION } from "./version.ts";

const USAGE = `frosty ${VERSION}: a VPS with no front door

Usage:
  frosty init                         write config, check tokens (creates nothing)
  frosty new <box> [--type T] [--location L] [--resume]
  frosty adopt <box> --ip <ip> [--user U] (--host-key SHA256:... | --trust-first-use) [--resume]
  frosty verify (<box> | --all)       check a box again, through the tunnel (changes nothing)
  frosty detach-foreign <box>         detach other firewalls from an adopted box (keeps frosty's)
  frosty route (plan | sync) <box>    web apps through the box's tunnel (config: routes)
  frosty breakglass <box> [--minutes N | --close]
  frosty ls
  frosty ssh-config                   rewrite ~/.ssh/stayfrosty.conf from the APIs
  frosty destroy <box>                type the box name to confirm
  frosty console-password <box>       set a new password for the Hetzner web console

Global flags:
  --dry-run    print what would change, change nothing
  --help       show this help
  --version    show the version

Tokens come from HCLOUD_TOKEN and CLOUDFLARE_API_TOKEN. Run "frosty init" for details.`;

// Commands from later milestones, so nobody mistakes a missing command for a broken one.
const PLANNED: Record<string, string> = {
  breakglass: "M3",
};

export async function main(argv: string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: {
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
    },
  });
  const command = positionals[0];
  if (values["version"] === true) {
    io.out(VERSION);
    return 0;
  }
  if (command === undefined || values["help"] === true || command === "help") {
    io.out(USAGE);
    return 0;
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

