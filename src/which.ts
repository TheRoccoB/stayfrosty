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
