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
// file, that path keeps running the old version after an upgrade. mise keeps a `latest` symlink to
// the newest installed version, so use that. Not the shim: a shim picks the version (and even the
// source) from the directory ssh runs in, so any cloned repo could choose what runs.
export function findStableCommand(name: string, env: Env): string | undefined {
  const found = findCommand(name, env);
  if (found === undefined) {
    return undefined;
  }
  const sep = "[\\\\/]";
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const install = new RegExp(`^(.*${sep}installs${sep}${escaped}${sep})[^\\\\/]+(${sep}.*)$`).exec(found);
  if (install === null) {
    return found;
  }
  const latest = `${install[1]}latest${install[2]}`;
  try {
    accessSync(latest, constants.X_OK);
    return latest;
  } catch {
    return found;
  }
}
