import { appendFileSync, mkdirSync } from "node:fs";
import { hostname, userInfo } from "node:os";
import { dirname } from "node:path";
import { FrostyError } from "./errors.ts";
import { redact } from "./redact.ts";

// An optional JSON-lines record of every write frosty sends to an API: an "intent" line before
// the request (if it cannot be written, the request is not sent) and a "done" line after. Bodies
// are redacted; results keep only the status and ids, since responses can carry secrets.
export type ChangeLog = (entry: ChangeEntry) => void;

export interface ChangeEntry {
  phase: "intent" | "done";
  action: string;
  target: string;
  request?: unknown;
  result?: unknown;
}

export function fileChangeLog(path: string): ChangeLog {
  return (entry) => {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      who: `${safeUser()}@${hostname()}`,
      phase: entry.phase,
      action: entry.action,
      target: entry.target,
      before: null,
      request: entry.request === undefined ? null : JSON.parse(redact(JSON.stringify(entry.request))),
      result: entry.result ?? null,
    });
    try {
      mkdirSync(dirname(path), { recursive: true });
      appendFileSync(path, `${line}\n`);
    } catch (error) {
      throw new FrostyError(
        `Could not write the change log ${path}: ${error instanceof Error ? error.message : String(error)}.${entry.phase === "intent" ? " Nothing was sent." : " THE CHANGE WAS MADE but not logged."}`,
        "Fix the path in your config (hetznerChangeLog / cloudflareChangeLog), then run the command again.",
      );
    }
  };
}

function safeUser(): string {
  try {
    return userInfo().username;
  } catch {
    return "?";
  }
}

// What a response is allowed to put in the log: its status and any ids.
export function summarize(status: number, body: unknown): Record<string, unknown> {
  const ids: unknown[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (depth > 3 || v === null || typeof v !== "object") {
      return;
    }
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (k === "id" && (typeof x === "string" || typeof x === "number")) {
        ids.push(x);
      } else {
        walk(x, depth + 1);
      }
    }
  };
  walk(body, 0);
  return { status, ids };
}
