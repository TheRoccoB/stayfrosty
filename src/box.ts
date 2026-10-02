import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { configPath, type Env } from "./config.ts";
import { FrostyError } from "./errors.ts";
import type { Sleep } from "./http.ts";
import { redact } from "./redact.ts";

// How frosty reaches a box over SSH: its public IP during a window, or its SSH hostname
// through the tunnel (with a ProxyCommand).
export interface SshTarget {
  host: string;
  user: string;
  keyPath: string;
  // The box's host key is pinned under this name (stayfrosty-<box>), whatever the address.
  // The key learned through the window is the one the tunnel path must present.
  hostKeyAlias: string;
  proxyCommand?: string;
}

export function hostKeyAlias(box: string): string {
  return `stayfrosty-${box}`;
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

// Options that make one ssh call open its own connection instead of reusing the shared one.
export const FRESH_CONNECTION = ["-o", "ControlMaster=no", "-o", "ControlPath=none"];

// frosty keeps its own known_hosts so it never edits ~/.ssh/known_hosts, and so a reused
// Hetzner IP can be forgotten without touching anything else.
export function knownHostsPath(env: Env = process.env): string {
  return join(dirname(configPath(env)), "known_hosts");
}

// ssh keeps the first value it sees for an option, so `extra` goes first to override defaults.
// Commands share one connection per box (ControlMaster): UFW's `limit 22/tcp` rejects an IP
// after 6 new connections in 30 seconds, and frosty runs many short commands.
export function sshArgs(target: SshTarget, env: Env, extra: string[] = []): string[] {
  return [
    ...extra,
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
    // First contact is through the window, from one IP, to a box minutes old. After that the
    // key is pinned and the tunnel path must match it.
    `StrictHostKeyChecking=${target.proxyCommand === undefined ? "accept-new" : "yes"}`,
    "-o",
    `UserKnownHostsFile=${knownHostsPath(env)}`,
    "-o",
    `HostKeyAlias=${target.hostKeyAlias}`,
    ...(target.proxyCommand === undefined ? [] : ["-o", `ProxyCommand=${target.proxyCommand}`]),
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=4",
    "-o",
    "ControlMaster=auto",
    "-o",
    `ControlPath=${join(dirname(configPath(env)), "cm-%C")}`,
    "-o",
    "ControlPersist=60",
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

// Closes the shared connection, e.g. after a reboot killed the box end of it.
export function closeSshMaster(target: SshTarget, env: Env = process.env): Promise<void> {
  return new Promise((resolve) => {
    const child = spawn("ssh", [...sshArgs(target, env), "-O", "exit"], { stdio: "ignore" });
    child.on("error", () => resolve());
    child.on("close", () => resolve());
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
    const result = await opts.ssh(opts.target, "true", { timeoutMs: 20_000, extraOptions: FRESH_CONNECTION });
    if (result.code === 0) {
      return;
    }
    last = lastLines(result.stderr, 3);
    if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(result.stderr)) {
      throw new FrostyError(
        `The SSH host key of ${opts.target.host} does not match the one frosty pinned for this box (${opts.target.hostKeyAlias}).`,
        "Stop here: something may be intercepting the connection. If you rebuilt the box outside frosty, destroy it with frosty destroy and create it again.",
      );
    }
    if (opts.now() >= deadline) {
      throw new FrostyError(
        `SSH to ${opts.target.user}@${opts.target.host} did not come up in ${Math.round(opts.timeoutMs / 60_000)} minutes. Last error: ${last}`,
        "If your public IP changed, the window no longer admits you. Run the command again with --resume; it opens the window for your current IP.",
      );
    }
    opts.onWait?.(last);
    // Slower than UFW's limit of 6 new connections per 30 seconds, so polling cannot lock us out.
    await opts.sleep(10_000);
  }
}

export type UserSsh = (host: string, command: string, onStderr: (line: string) => void, timeoutMs: number) => Promise<SshResult>;

// `ssh <box> <command>` exactly as the user would type it, through ~/.ssh/config, the Include
// and the cloudflared ProxyCommand. The first time, cloudflared opens a browser for the
// Access login; its messages are passed through so the user sees what to do.
export const userSsh: UserSsh = (host, command, onStderr, timeoutMs) =>
  new Promise((resolve, reject) => {
    const child = spawn("ssh", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=30", host, command], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let partial = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      stderr += text;
      partial += text;
      const lines = partial.split("\n");
      partial = lines.pop() ?? "";
      for (const line of lines) {
        onStderr(line);
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(new FrostyError(`Could not start ssh: ${error.message}`, "Install OpenSSH."));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (partial.length > 0) {
        onStderr(partial);
      }
      resolve({ code: code ?? 255, stdout, stderr });
    });
  });
