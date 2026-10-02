import { spawn } from "node:child_process";
import { randomInt } from "node:crypto";
import { runOrFail, type SshRunner, type SshTarget } from "./box.ts";
import { FrostyError } from "./errors.ts";
import type { Io } from "./io.ts";

// Letters and digits only, without look-alikes: the Hetzner web console types it through a
// virtual keyboard, where symbols and layouts go wrong. 24 of 56 symbols is about 139 bits.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

export function generatePassword(length = 24): string {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += ALPHABET[randomInt(ALPHABET.length)];
  }
  return out;
}

export type PasswordCommandRunner = (command: string, password: string) => Promise<number>;

// Runs the configured command with the password on stdin, never in argv or the environment.
export const shellPasswordCommand: PasswordCommandRunner = (command, password) =>
  new Promise((resolve, reject) => {
    const child = spawn("sh", ["-c", command], { stdio: ["pipe", "inherit", "inherit"] });
    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
    child.stdin.end(`${password}\n`);
  });

export async function hasPassword(ssh: SshRunner, target: SshTarget, user: string): Promise<boolean> {
  const out = await runOrFail(ssh, target, `sudo passwd -S ${user}`, "Reading the console password state");
  // "ops P 2026-10-01 ..." means a usable password; L is locked, NP is none.
  return out.trim().split(/\s+/)[1] === "P";
}

async function setOnBox(ssh: SshRunner, target: SshTarget, user: string, password: string): Promise<void> {
  await runOrFail(ssh, target, "sudo chpasswd", "Setting the console password", { stdin: `${user}:${password}\n` });
}

export interface ConsolePasswordDeps {
  io: Io;
  ssh: SshRunner;
  isTty: boolean;
  runPasswordCommand: PasswordCommandRunner;
}

// Sets the admin user's password for the Hetzner web console. SSH stays key only. The
// password is never stored: it goes to passwordCommand, or to a person at a terminal.
// Returns false when there is nowhere safe to send it, and sets nothing.
export async function setConsolePassword(
  deps: ConsolePasswordDeps,
  opts: { box: string; target: SshTarget; user: string; passwordCommand: string | undefined },
): Promise<boolean> {
  const password = generatePassword();
  if (opts.passwordCommand !== undefined) {
    const command = opts.passwordCommand.replaceAll("{box}", opts.box);
    deps.io.out(`Storing the console password with passwordCommand.`);
    const code = await deps.runPasswordCommand(command, password);
    if (code !== 0) {
      throw new FrostyError(
        `passwordCommand exited with ${code}, so the console password was not set (the box is unchanged).`,
        `Fix passwordCommand in your config, then run: frosty console-password ${opts.box}`,
      );
    }
    await setOnBox(deps.ssh, opts.target, opts.user, password);
    deps.io.out(`Console password for ${opts.user} set and stored.`);
    return true;
  }
  if (!deps.isTty) {
    deps.io.err(`No terminal and no passwordCommand, so the console password was not set (the console login stays locked).`);
    deps.io.err(`From a terminal, run: frosty console-password ${opts.box}`);
    return false;
  }
  await setOnBox(deps.ssh, opts.target, opts.user, password);
  deps.io.out("");
  deps.io.out(`Console password for ${opts.user} on ${opts.box} (Hetzner web console only; SSH stays key only).`);
  deps.io.out("Save this in your password manager now. frosty does not keep it and cannot show it again:");
  deps.io.reveal(`    ${password}`);
  deps.io.out("");
  return true;
}
