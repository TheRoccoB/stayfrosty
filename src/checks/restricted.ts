import { DENIED_GROUPS, HOME_BASE, KEYS_DIR, RESTRICTED_SHELL, keyLinePrefix, restrictedSshdSettings, type RestrictedUser } from "../sshusers.ts";
import { parseSshdT } from "./sshd.ts";
import { fail, pass, type CheckResult } from "./types.ts";

// What restrictedGatherScript collected for one user.
export interface RestrictedState {
  sshdT: string;
  passwd: string;
  groups: string;
  status: string;
  keyDirStat: string;
  keyFileStat: string;
  keyFile: string;
  commandStat: string;
}

export function restrictedState(sections: Map<string, string>, user: string): RestrictedState {
  const get = (key: string): string => sections.get(key) ?? "";
  return {
    sshdT: get(`ru-sshd-${user}`),
    passwd: get(`ru-passwd-${user}`),
    groups: get(`ru-groups-${user}`),
    status: get(`ru-status-${user}`),
    keyDirStat: get("ru-keydir"),
    keyFileStat: get(`ru-keyfile-stat-${user}`),
    keyFile: get(`ru-keyfile-${user}`),
    commandStat: get(`ru-command-${user}`),
  };
}

// "owner group mode type" from stat; root-owned and writable by nobody but root.
function rootOnly(statLine: string, type: string): string | undefined {
  const [owner, group, mode, ...rest] = statLine.trim().split(/\s+/);
  if (owner === undefined || mode === undefined || !/^[0-7]{3,4}$/.test(mode)) {
    return `missing (${statLine.trim() || "no output"})`;
  }
  const kind = rest.join(" ");
  if (owner !== "root" || group !== "root") {
    return `owned by ${owner}:${group ?? "?"}, want root:root`;
  }
  if ((parseInt(mode, 8) & 0o022) !== 0) {
    return `mode ${mode} is group or world writable`;
  }
  if (!kind.startsWith(type)) {
    return `is a ${kind}, want a ${type}`;
  }
  return undefined;
}

// One restricted user, as configured: sshd forces its command and allows nothing else, the
// account has no password, no privileged groups and a real shell (for ForceCommand), and its keys
// sit in a root-owned file where every line carries the same restrictions.
export function checkRestrictedUser(state: RestrictedState, box: string, user: RestrictedUser): CheckResult {
  const name = `restricted user ${user.name}: forced command only`;
  const wrong: string[] = [];
  const values = parseSshdT(state.sshdT);
  if (values.size === 0) {
    wrong.push(`sshd -T -C user=${user.name} printed nothing`);
  } else {
    for (const [key, want] of restrictedSshdSettings(user)) {
      const got = values.get(key)?.[0];
      if (got !== want) {
        wrong.push(`${key} is ${got ?? "unset"}, want ${want}`);
      }
    }
  }
  const passwd = state.passwd.trim().split(":");
  if (passwd.length < 7 || passwd[0] !== user.name) {
    wrong.push("the user does not exist");
  } else {
    if (passwd[6] !== RESTRICTED_SHELL) {
      wrong.push(`shell is ${passwd[6] ?? ""}, want ${RESTRICTED_SHELL}`);
    }
    if (passwd[5] !== `${HOME_BASE}/${user.name}`) {
      wrong.push(`home is ${passwd[5] ?? ""}, want ${HOME_BASE}/${user.name}`);
    }
    if (passwd[2] === "0") {
      wrong.push("uid is 0");
    }
  }
  const [primary = "", all = ""] = state.groups.trim().split("\n").map((l) => l.trim());
  const supplementary = all.split(/\s+/).filter((g) => g.length > 0 && g !== primary);
  if (primary !== user.name) {
    wrong.push(`primary group is ${primary || "unknown"}, want ${user.name}`);
  }
  const sorted = (list: string[]): string => [...list].sort().join(" ");
  if (sorted(supplementary) !== sorted(user.groups)) {
    wrong.push(`groups are [${supplementary.join(" ")}], want [${user.groups.join(" ")}]`);
  }
  const privileged = [primary, ...supplementary].filter((g) => DENIED_GROUPS.includes(g));
  if (privileged.length > 0) {
    wrong.push(`is in privileged group(s) ${privileged.join(", ")}`);
  }
  if (state.status.trim().split(/\s+/)[1] !== "L") {
    wrong.push(`password is not locked (passwd -S: ${state.status.trim() || "no output"})`);
  }
  const dir = rootOnly(state.keyDirStat, "directory");
  if (dir !== undefined) {
    wrong.push(`${KEYS_DIR} ${dir}`);
  }
  const file = rootOnly(state.keyFileStat, "regular");
  if (file !== undefined) {
    wrong.push(`${KEYS_DIR}/${user.name} ${file}`);
  }
  const prefix = keyLinePrefix(user.command);
  const lines = state.keyFile.split("\n").filter((l) => l.trim().length > 0);
  const unrestricted = lines.filter((l) => !l.startsWith(prefix));
  if (unrestricted.length > 0) {
    wrong.push(`${unrestricted.length} key line(s) in ${KEYS_DIR}/${user.name} do not start with ${prefix.trim()}`);
  }
  const keys = lines.filter((l) => l.startsWith(prefix)).map((l) => l.slice(prefix.length));
  if (unrestricted.length === 0 && sorted(keys) !== sorted(user.keys)) {
    wrong.push(`the keys in ${KEYS_DIR}/${user.name} are not the configured ones (${keys.length} on the box, ${user.keys.length} in config)`);
  }
  // The command and every directory above it, one "path owner group mode type" line each. Not
  // installed yet is fine (the app that owns it installs it). Anything there must be changeable by
  // root only, and the command must not be a symlink, or whoever controls it chooses what runs.
  const statLines = state.commandStat.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  const missing = (l: string): boolean => /No such file or directory/.test(l);
  const notInstalled = statLines.length === 0 || missing(statLines[0] as string);
  const parents: string[] = [];
  for (let p = user.command; p !== "/"; ) {
    p = p.slice(0, p.lastIndexOf("/")) || "/";
    parents.push(p);
  }
  const byPath = new Map<string, string>();
  for (const line of statLines) {
    const space = line.indexOf(" ");
    if (!missing(line) && space > 0) {
      byPath.set(line.slice(0, space), line.slice(space + 1));
    }
  }
  if (!notInstalled) {
    const own = byPath.get(user.command);
    const problem = own === undefined ? "missing (no output)" : own.endsWith("symbolic link") ? "is a symbolic link" : rootOnly(own, "regular");
    if (problem !== undefined) {
      wrong.push(`forced command ${user.command} ${problem}`);
    }
  }
  for (const dir of parents) {
    const got = byPath.get(dir);
    if (got === undefined) {
      if (!notInstalled) {
        wrong.push(`directory ${dir} above the forced command was not checked`);
      }
      continue;
    }
    const problem = rootOnly(got, "directory");
    if (problem !== undefined) {
      wrong.push(`directory ${dir} above the forced command ${problem}`);
    }
  }
  if (wrong.length > 0) {
    return fail(name, wrong.join("; "), `frosty ssh-users sync ${box} (the forced command itself is installed by the app that owns it)`);
  }
  return pass(name, `runs only ${user.command}${notInstalled ? " (not installed yet)" : ""}, groups [${user.groups.join(" ")}], no tty or forwarding, root-owned keys`);
}
