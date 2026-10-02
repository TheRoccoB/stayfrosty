import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { configPath, type Env } from "./config.ts";
import { FrostyError } from "./errors.ts";
import type { Sleep } from "./http.ts";
import { redact } from "./redact.ts";

// How frosty reaches a box over SSH. `host` is an IP during a window; later milestones add
// the tunnel hostname.
export interface SshTarget {
  host: string;
  user: string;
  keyPath: string;
}

export interface SshResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface SshRunOptions {
  stdin?: string;
  timeoutMs?: number;
  extraOptions?: string[];
}

export type SshRunner = (target: SshTarget, command: string, opts?: SshRunOptions) => Promise<SshResult>;

// frosty keeps its own known_hosts so it never edits ~/.ssh/known_hosts, and so a reused
// Hetzner IP can be forgotten without touching anything else.
export function knownHostsPath(env: Env = process.env): string {
  return join(dirname(configPath(env)), "known_hosts");
}

export function sshArgs(target: SshTarget, env: Env, extra: string[] = []): string[] {
  return [
    "-F",
    "/dev/null",
    "-i",
    target.keyPath,
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    `UserKnownHostsFile=${knownHostsPath(env)}`,
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=4",
    ...extra,
    "-l",
    target.user,
    target.host,
  ];
}

// Runs one command on the box with the system ssh. Secrets go on stdin, never in argv.
export function systemSsh(env: Env = process.env): SshRunner {
  return (target, command, opts = {}) =>
    new Promise((resolve, reject) => {
      mkdirSync(dirname(knownHostsPath(env)), { recursive: true, mode: 0o700 });
      const child = spawn("ssh", [...sshArgs(target, env, opts.extraOptions), "--", command], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGTERM");
      }, opts.timeoutMs ?? 120_000);
      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(new FrostyError(`Could not start ssh: ${error.message}`, "Install OpenSSH (it ships with macOS and most Linux distributions)."));
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (timedOut) {
          resolve({ code: 124, stdout, stderr: `${stderr}\nfrosty: ssh timed out` });
          return;
        }
        resolve({ code: code ?? 255, stdout, stderr });
      });
      child.stdin.on("error", () => {
        // The remote side may close stdin early; the exit code tells the story.
      });
      child.stdin.end(opts.stdin ?? "");
    });
}

// Forgets a host key, used when Hetzner hands a reused IP to a new box.
export function forgetHost(host: string, env: Env = process.env): Promise<void> {
  return new Promise((resolve) => {
    const child = spawn("ssh-keygen", ["-R", host, "-f", knownHostsPath(env)], { stdio: "ignore" });
    child.on("error", () => resolve());
    child.on("close", () => resolve());
  });
}

export async function runOrFail(ssh: SshRunner, target: SshTarget, command: string, what: string, opts?: SshRunOptions): Promise<string> {
  const result = await ssh(target, command, opts);
  if (result.code !== 0) {
    throw new FrostyError(
      `${what} failed on ${target.host} (exit ${result.code}): ${redact(lastLines(result.stderr || result.stdout, 15))}`,
      "Run the command again; every step checks before it acts, so it picks up where it stopped.",
    );
  }
  return result.stdout;
}

export function lastLines(text: string, n: number): string {
  return text.trimEnd().split("\n").slice(-n).join("\n");
}

// Polls until `ssh true` succeeds.
export async function waitForSsh(opts: {
  ssh: SshRunner;
  target: SshTarget;
  timeoutMs: number;
  sleep: Sleep;
  now: () => number;
  onWait?: (lastError: string) => void;
}): Promise<void> {
  const deadline = opts.now() + opts.timeoutMs;
  let last = "";
  for (;;) {
    const result = await opts.ssh(opts.target, "true", { timeoutMs: 20_000 });
    if (result.code === 0) {
      return;
    }
    last = lastLines(result.stderr, 3);
    if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(result.stderr)) {
      throw new FrostyError(
        `The SSH host key for ${opts.target.host} does not match the one frosty saw before.`,
        `If this IP belonged to a box you destroyed, forget it with: ssh-keygen -R ${opts.target.host} -f ${knownHostsPath()}  Otherwise stop: something may be intercepting the connection.`,
      );
    }
    if (opts.now() >= deadline) {
      throw new FrostyError(
        `SSH to ${opts.target.user}@${opts.target.host} did not come up in ${Math.round(opts.timeoutMs / 60_000)} minutes. Last error: ${last}`,
        "If your public IP changed, the window no longer admits you. Run the command again with --resume; it opens the window for your current IP.",
      );
    }
    opts.onWait?.(last);
    await opts.sleep(5000);
  }
}
