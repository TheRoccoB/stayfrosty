import { parseArgs } from "node:util";
import { FrostyError } from "./errors.ts";
import { terminalIo, type Io } from "./io.ts";
import { redact } from "./redact.ts";
import { runInit } from "./commands/init.ts";
import { runLs } from "./commands/ls.ts";
import { VERSION } from "./version.ts";

const USAGE = `frosty ${VERSION}: a VPS with no front door

Usage:
  frosty init                         write config, check tokens (creates nothing)
  frosty new <box> [--type --location]
  frosty adopt <box> --ip <ip>
  frosty verify [<box> | --all] [--full]
  frosty breakglass <box> [--minutes N | --close]
  frosty ls
  frosty ssh-config                   rewrite ~/.ssh/stayfrosty.conf from the APIs
  frosty destroy <box>

Global flags:
  --dry-run    print what would change, change nothing
  --help       show this help
  --version    show the version

Tokens come from HCLOUD_TOKEN and CLOUDFLARE_API_TOKEN. Run "frosty init" for details.`;

// Commands from later milestones, so nobody mistakes a missing command for a broken one.
const PLANNED: Record<string, string> = {
  new: "M1",
  destroy: "M1",
  adopt: "M4",
  verify: "M3",
  breakglass: "M3",
  "ssh-config": "M3",
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

