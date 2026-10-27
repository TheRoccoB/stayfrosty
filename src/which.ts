import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";
import type { Env } from "./config.ts";

// The absolute path of a command on PATH, or undefined.
export function findCommand(name: string, env: Env): string | undefined {
  for (const dir of (env["PATH"] ?? "").split(delimiter)) {
    if (dir.length === 0) {
      continue;
    }
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  return undefined;
}

// Like findCommand, but a path that survives upgrades, for writing into files such as ssh_config.
// Version managers (mise, asdf) put one versioned directory per install on PATH; written into a
// file, that path keeps running the old version after an upgrade. Their shim picks the current one.
export function findStableCommand(name: string, env: Env): string | undefined {
  const found = findCommand(name, env);
  const install = found === undefined ? null : /^(.*)[\\/]installs[\\/][^\\/]+[\\/][^\\/]+[\\/]/.exec(found);
  if (install === null) {
    return found;
  }
  const shim = join(install[1]!, "shims", name);
  try {
    accessSync(shim, constants.X_OK);
    return shim;
  } catch {
    return found;
  }
}
