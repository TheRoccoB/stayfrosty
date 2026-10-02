import { copyFile, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Env } from "./config.ts";

export interface SshConfigEntry {
  box: string;
  hostname: string;
  user: string;
  identityFile: string;
  cloudflared: string;
  knownHosts: string;
  hostKeyAlias: string;
}

const HEADER = `# Managed by stayfrosty. frosty rewrites this whole file from the Hetzner and Cloudflare
# APIs (frosty ssh-config), so edits here are lost. Put your own settings in ~/.ssh/config.
`;

export function sshDir(env: Env): string {
  return join(env["HOME"] ?? homedir(), ".ssh");
}

export function renderSshConfig(entries: SshConfigEntry[]): string {
  const blocks = [...entries]
    .sort((a, b) => a.box.localeCompare(b.box))
    .map((e) =>
      [
        `Host ${e.box}`,
        `  HostName ${e.hostname}`,
        `  User ${e.user}`,
        `  IdentityFile ${e.identityFile}`,
        "  IdentitiesOnly yes",
        `  ProxyCommand ${e.cloudflared} access ssh --hostname %h`,
        // The host key frosty pinned when it built the box, through the window.
        `  HostKeyAlias ${e.hostKeyAlias}`,
        `  UserKnownHostsFile ${e.knownHosts}`,
        "  StrictHostKeyChecking yes",
      ].join("\n"),
    );
  return `${HEADER}\n${blocks.join("\n\n")}${blocks.length > 0 ? "\n" : ""}`;
}

const INCLUDE = /^\s*Include\s+("?)(~\/\.ssh\/|.*\/\.ssh\/)?stayfrosty\.conf\1\s*$/im;

export function hasInclude(config: string): boolean {
  return INCLUDE.test(config);
}

// Include must come before any Host or Match block, or it only applies inside that block.
export function addInclude(config: string): string {
  return `# Added by stayfrosty: boxes managed by frosty.\nInclude stayfrosty.conf\n\n${config}`;
}

export interface SshConfigWrite {
  path: string;
  includeAdded: boolean;
  backup: string | undefined;
}

// Writes ~/.ssh/stayfrosty.conf and, once, the Include line at the top of ~/.ssh/config
// (after copying the old file aside).
export async function writeSshConfig(env: Env, entries: SshConfigEntry[], now: () => number): Promise<SshConfigWrite> {
  const dir = sshDir(env);
  const path = join(dir, "stayfrosty.conf");
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, renderSshConfig(entries), { mode: 0o600 });
  await rename(tmp, path);

  const mainPath = join(dir, "config");
  let main: string | undefined;
  try {
    main = await readFile(mainPath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
  if (main !== undefined && hasInclude(main)) {
    return { path, includeAdded: false, backup: undefined };
  }
  let backup: string | undefined;
  if (main !== undefined) {
    backup = `${mainPath}.stayfrosty-backup-${Math.floor(now() / 1000)}`;
    await copyFile(mainPath, backup);
  }
  await writeFile(mainPath, addInclude(main ?? ""), { mode: 0o600 });
  return { path, includeAdded: true, backup };
}

// Shows paths under the home directory with ~, which is how ssh_config users read them.
export function tildify(path: string, env: Env): string {
  const home = env["HOME"] ?? homedir();
  return path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path;
}
