import { isAdminUser } from "./config.ts";
import { FrostyError } from "./errors.ts";

// Restricted users: extra SSH logins on a box that can only run one forced command, e.g. a backup
// puller. They never get a shell, sudo, forwarding or a writable key file, so a bug in the forced
// command is that user's problem, not root's (the admin user has passwordless sudo).

export interface RestrictedUser {
  name: string;
  // Absolute path of the only program this user can run (ForceCommand and the key's command=).
  command: string;
  // Supplementary groups, exactly. Missing ones are created as empty system groups.
  groups: string[];
  // ed25519 or ecdsa public key lines, without options; frosty adds `restrict,command="..."`.
  keys: string[];
}

export const DROP_IN = "/etc/ssh/sshd_config.d/00-stayfrosty.conf";
// Root-owned and read through a Match block, so the user can never add a key of its own.
export const KEYS_DIR = "/etc/ssh/authorized_keys";
// A root-owned, empty home: sshd needs a directory to start in, the user can write nothing there.
export const HOME_BASE = "/var/lib/stayfrosty/users";
// sshd runs ForceCommand as `<shell> -c <command>`, so the shell must be a real one, not nologin.
export const RESTRICTED_SHELL = "/bin/sh";

const NAME = /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/;
const GROUP = /^[a-z][a-z0-9-]{0,31}$/;
const COMMAND = /^\/[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
// Only key types that need no hardware touch, no options before the type, a plain comment.
const KEY = /^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ([A-Za-z0-9+/]+={0,3})( [A-Za-z0-9._@:+=-]{1,100})?$/;
// Groups that give root, or root-equivalent reads, to whoever is in them.
export const DENIED_GROUPS = ["root", "sudo", "admin", "wheel", "docker", "adm", "lxd", "shadow", "disk", "systemd-journal"];

export function isRestrictedCommand(value: string): boolean {
  return COMMAND.test(value) && !value.split("/").some((part) => part === "." || part === "..");
}

// The key's own blob names its type; a mismatch means the line was pasted together wrong.
export function isRestrictedKey(value: string): boolean {
  const m = KEY.exec(value);
  if (m === null) {
    return false;
  }
  const blob = Buffer.from(m[2] as string, "base64");
  if (blob.length < 4) {
    return false;
  }
  const len = blob.readUInt32BE(0);
  return blob.subarray(4, 4 + len).toString("latin1") === m[1];
}

export function validateRestrictedUsers(box: string, list: unknown, adminUser: string): string[] {
  const where = `restrictedUsers.${box}`;
  if (!Array.isArray(list) || list.length === 0) {
    return [`${where} must be a non-empty list of users`];
  }
  const problems: string[] = [];
  const names = new Set<string>();
  list.forEach((entry, i) => {
    const at = `${where}[${i}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`${at} must be an object`);
      return;
    }
    const u = entry as Record<string, unknown>;
    const extra = Object.keys(u).filter((k) => !["name", "command", "groups", "keys"].includes(k));
    if (extra.length > 0) {
      problems.push(`${at} has unknown keys: ${extra.join(", ")}`);
    }
    const name = u["name"];
    if (typeof name !== "string" || !NAME.test(name) || !isAdminUser(name)) {
      problems.push(`${at}.name must be a lowercase Linux user name (letters, digits, dashes)`);
    } else if (name === adminUser || DENIED_GROUPS.includes(name)) {
      problems.push(`${at}.name "${name}" is the admin user or a privileged name`);
    } else if (names.has(name)) {
      problems.push(`${at}.name "${name}" is listed twice`);
    } else {
      names.add(name);
    }
    const command = u["command"];
    if (typeof command !== "string" || !isRestrictedCommand(command)) {
      problems.push(`${at}.command must be an absolute path of letters, digits, dots, dashes and underscores`);
    }
    const groups = u["groups"];
    if (!Array.isArray(groups)) {
      problems.push(`${at}.groups must be a list (it may be empty)`);
    } else {
      const seen = new Set<string>();
      for (const g of groups) {
        if (typeof g !== "string" || !GROUP.test(g)) {
          problems.push(`${at}.groups has an invalid group name: ${String(g)}`);
        } else if (DENIED_GROUPS.includes(g) || g === adminUser || g === name) {
          problems.push(`${at}.groups may not include ${g}`);
        } else if (seen.has(g)) {
          problems.push(`${at}.groups lists ${g} twice`);
        } else {
          seen.add(g);
        }
      }
    }
    const keys = u["keys"];
    if (!Array.isArray(keys) || keys.length === 0) {
      problems.push(`${at}.keys needs at least one public key`);
    } else {
      keys.forEach((k, j) => {
        if (typeof k !== "string" || !isRestrictedKey(k)) {
          problems.push(`${at}.keys[${j}] must be one ssh-ed25519 or ecdsa-sha2-nistp* public key line, without options`);
        }
      });
      if (new Set(keys).size !== keys.length) {
        problems.push(`${at}.keys lists a key twice`);
      }
    }
  });
  return problems;
}

function assertValid(adminUser: string, users: RestrictedUser[]): void {
  if (!isAdminUser(adminUser)) {
    throw new FrostyError(`Admin user "${adminUser}" is not a valid user name.`, "Fix adminUser with: frosty init");
  }
  if (users.length === 0) {
    return;
  }
  const problems = validateRestrictedUsers("box", users, adminUser);
  if (problems.length > 0) {
    throw new FrostyError(`Invalid restricted users: ${problems.join("; ")}.`, "Fix restrictedUsers in the config.");
  }
}

// The effective settings each restricted user must have, as `sshd -T -C user=<u>` prints them.
export function restrictedSshdSettings(user: RestrictedUser): [string, string][] {
  return [
    ["forcecommand", user.command],
    ["authorizedkeysfile", `${KEYS_DIR}/%u`],
    ["authenticationmethods", "publickey"],
    ["passwordauthentication", "no"],
    ["kbdinteractiveauthentication", "no"],
    ["permittty", "no"],
    ["allowtcpforwarding", "no"],
    ["allowstreamlocalforwarding", "no"],
    ["x11forwarding", "no"],
    ["allowagentforwarding", "no"],
    ["permittunnel", "no"],
    ["permituserrc", "no"],
  ];
}

// The sshd drop-in. With no restricted users it is exactly the one in cloud-init.yaml. Match
// blocks come last: every line after a Match belongs to it. The admin user's settings, including
// its ~/.ssh/authorized_keys, are untouched, because AuthorizedKeysFile is set only in the Match.
export function renderSshdDropIn(adminUser: string, users: RestrictedUser[]): string {
  assertValid(adminUser, users);
  const lines = [
    "# Managed by stayfrosty. Change it in the stayfrosty repo, not here.",
    "PermitRootLogin no",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "AuthenticationMethods publickey",
    `AllowUsers ${[adminUser, ...users.map((u) => u.name)].join(" ")}`,
  ];
  for (const u of users) {
    lines.push(
      "",
      `Match User ${u.name}`,
      `  AuthorizedKeysFile ${KEYS_DIR}/%u`,
      `  ForceCommand ${u.command}`,
      "  AuthenticationMethods publickey",
      "  PasswordAuthentication no",
      "  KbdInteractiveAuthentication no",
      "  PermitTTY no",
      "  AllowTcpForwarding no",
      "  AllowStreamLocalForwarding no",
      "  X11Forwarding no",
      "  AllowAgentForwarding no",
      "  PermitTunnel no",
      "  PermitUserRC no",
    );
  }
  return `${lines.join("\n")}\n`;
}

export function keyLinePrefix(command: string): string {
  return `restrict,command="${command}" `;
}

export function keyFileContent(user: RestrictedUser): string {
  return user.keys.map((k) => `${keyLinePrefix(user.command)}${k}\n`).join("");
}

const b64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");

// Same check as adopt's: without the Include, the drop-in would be silently ignored.
const PREFLIGHT = `[ -f ${DROP_IN} ] || { echo "stayfrosty-ssh-users: ${DROP_IN} is missing; this box is not hardened by stayfrosty" >&2; exit 1; }
grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/\\*\\.conf' /etc/ssh/sshd_config || { echo "stayfrosty-ssh-users: /etc/ssh/sshd_config does not include sshd_config.d" >&2; exit 1; }`;

// Makes the box's restricted users, their key files and the sshd drop-in match `users`, as root.
// With apply false it changes nothing and prints what it would do (the plan). Additions come
// before the drop-in, removals after it. The drop-in is checked with `sshd -t`, and the admin
// user's effective settings, before sshd is reloaded; on any failure the old file goes back.
// The previous drop-in is kept as 00-stayfrosty.conf.stayfrosty-prev (not *.conf, so sshd never
// reads it) until frosty has proven a fresh admin login.
export function sshUsersScript(adminUser: string, users: RestrictedUser[], apply: boolean): string {
  const dropIn = renderSshdDropIn(adminUser, users);
  const names = users.map((u) => u.name);
  const perUser = users
    .map((u) => {
      const home = `${HOME_BASE}/${u.name}`;
      const groups = [...u.groups].sort().join(" ");
      const missing = u.groups.map((g) => `getent group ${g} >/dev/null || change "create system group ${g}" groupadd --system ${g}`).join("\n");
      return `# --- ${u.name}
${missing}
[ -e ${u.command} ] || echo "warning: ${u.command} (the forced command for ${u.name}) does not exist yet"
ensure_dir ${HOME_BASE}
ensure_dir ${home}
if id -u ${u.name} >/dev/null 2>&1; then
  have_home=$(getent passwd ${u.name} | cut -d: -f6)
  if [ "$have_home" != ${home} ]; then
    echo "stayfrosty-ssh-users: a user ${u.name} already exists and frosty did not make it (home $have_home). Pick another name." >&2
    exit 1
  fi
  [ "$(id -gn ${u.name})" = ${u.name} ] || { echo "stayfrosty-ssh-users: ${u.name}'s primary group is $(id -gn ${u.name}), not ${u.name}" >&2; exit 1; }
  [ "$(getent passwd ${u.name} | cut -d: -f7)" = ${RESTRICTED_SHELL} ] || change "set ${u.name}'s shell to ${RESTRICTED_SHELL}" usermod -s ${RESTRICTED_SHELL} ${u.name}
  have_groups=$(id -Gn ${u.name} | tr ' ' '\\n' | { grep -vxF ${u.name} || true; } | sort | tr '\\n' ' ' | sed 's/ $//')
  [ "$have_groups" = "${groups}" ] || change "set ${u.name}'s groups to [${groups}] (were [$have_groups])" usermod -G "${u.groups.join(",")}" ${u.name}
  [ "$(passwd -S ${u.name} | awk '{print $2}')" = L ] || change "lock ${u.name}'s password" usermod -L ${u.name}
else
  change "create system user ${u.name} (home ${home}, shell ${RESTRICTED_SHELL}, groups [${groups}], password locked)" \\
    useradd --system --user-group --no-create-home --home-dir ${home} --shell ${RESTRICTED_SHELL}${u.groups.length === 0 ? "" : ` --groups ${u.groups.join(",")}`} ${u.name}
  if [ "$apply" = 1 ]; then usermod -L ${u.name}; fi
fi
put_file ${KEYS_DIR}/${u.name} '${b64(keyFileContent(u))}' "the keys of ${u.name}"`;
    })
    .join("\n");
  return `main() {
set -euo pipefail
trap 'echo "stayfrosty-ssh-users: failed at line $LINENO: $BASH_COMMAND" >&2' ERR
apply=${apply ? 1 : 0}
admin=${adminUser}
changes=0
${PREFLIGHT}
change() {
  local what=$1; shift
  changes=$((changes + 1))
  if [ "$apply" = 1 ]; then
    echo "changing: $what"
    "$@"
    logger -t stayfrosty "ssh-users: $what" || true
  else
    echo "would: $what"
  fi
}
ensure_dir() {
  if [ "$(stat -c '%U:%G %a %F' "$1" 2>/dev/null)" != "root:root 755 directory" ]; then
    change "make $1 a root:root 0755 directory" install -d -m 0755 -o root -g root "$1"
  fi
}
# put_file <path> <base64 content> <description>: root:root 0644, replaced atomically.
put_file() {
  local tmp
  tmp=$(mktemp)
  printf '%s' "$2" | base64 -d > "$tmp"
  if [ -f "$1" ] && cmp -s "$tmp" "$1" && [ "$(stat -c '%U:%G %a' "$1")" = "root:root 644" ]; then
    rm -f "$tmp"
    return 0
  fi
  echo "--- $3: $1"
  diff -u "$1" "$tmp" 2>/dev/null | tail -n +3 || true
  [ -f "$1" ] || sed 's/^/+/' "$tmp"
  change "write $1" install_file "$tmp" "$1"
  rm -f "$tmp"
}
install_file() {
  install -m 0644 -o root -g root "$1" "$2.stayfrosty-new"
  mv "$2.stayfrosty-new" "$2"
}
remove_user() {
  userdel "$1"
  rmdir "$2" 2>/dev/null || true
}
admin_ok() {
  local t
  t=$(sshd -T -C "user=$admin,host=x,addr=127.0.0.1")
  printf '%s\\n' "$t" | awk -v a="$admin" 'tolower($1)=="allowusers"{for(i=2;i<=NF;i++) if($i==a) f=1} END{exit !f}' &&
  printf '%s\\n' "$t" | awk 'tolower($1)=="forcecommand" && $2!="none"{bad=1} tolower($1)=="permitrootlogin" && $2!="no"{bad=1} END{exit bad}'
}
rm -f ${DROP_IN}.stayfrosty-prev
${users.length > 0 ? `ensure_dir ${KEYS_DIR}` : ""}
${perUser}
# --- the sshd drop-in
new_conf=$(mktemp)
printf '%s' '${b64(dropIn)}' | base64 -d > "$new_conf"
if ! cmp -s "$new_conf" ${DROP_IN}; then
  echo "--- sshd drop-in: ${DROP_IN}"
  diff -u ${DROP_IN} "$new_conf" | tail -n +3 || true
  changes=$((changes + 1))
  if [ "$apply" = 1 ]; then
    echo "changing: write ${DROP_IN}, check it with sshd -t, reload sshd"
    cp -p ${DROP_IN} ${DROP_IN}.stayfrosty-prev
    install -m 0644 -o root -g root "$new_conf" ${DROP_IN}.stayfrosty-new
    mv ${DROP_IN}.stayfrosty-new ${DROP_IN}
    install -d -m 0755 /run/sshd
    if ! sshd -t || ! admin_ok; then
      mv ${DROP_IN}.stayfrosty-prev ${DROP_IN}
      echo "stayfrosty-ssh-users: the new sshd config failed sshd -t or would change the admin login; the old one is back, sshd was not reloaded" >&2
      exit 1
    fi
    systemctl try-reload-or-restart ssh.service
    logger -t stayfrosty "ssh-users: wrote ${DROP_IN} and reloaded sshd" || true
  else
    echo "would: write ${DROP_IN}, check it with sshd -t, reload sshd"
  fi
fi
rm -f "$new_conf"
# --- users and key files no longer in config, removed once sshd no longer lets them in
keep=" ${names.join(" ")} "
for f in ${KEYS_DIR}/*; do
  [ -e "$f" ] || continue
  n=$(basename "$f")
  case $keep in *" $n "*) ;; *) change "remove $f (not in config)" rm -f "$f" ;; esac
done
while IFS=: read -r n _ _ _ _ home _; do
  case $home in ${HOME_BASE}/*) ;; *) continue ;; esac
  case $keep in *" $n "*) ;; *) change "remove user $n (not in config)" remove_user "$n" "$home" ;; esac
done < <(getent passwd)
echo "stayfrosty-ssh-users-changes $changes"
echo stayfrosty-ssh-users-ok
}
main </dev/null
`;
}

// Run as root after a fresh admin login was proven: drop the backup of the old drop-in.
export const SSH_USERS_CLEANUP = `rm -f ${DROP_IN}.stayfrosty-prev\necho stayfrosty-ssh-users-cleanup-ok\n`;

// Run as root over the still-open connection when a fresh admin login failed after a sync.
export const SSH_USERS_ROLLBACK = `set -eu
[ -f ${DROP_IN}.stayfrosty-prev ] || { echo "stayfrosty-ssh-users: no previous drop-in to restore" >&2; exit 1; }
mv ${DROP_IN}.stayfrosty-prev ${DROP_IN}
sshd -t
systemctl try-reload-or-restart ssh.service
echo stayfrosty-ssh-users-rollback-ok
`;

// verify's extra round trip, only for boxes with restricted users. Names and paths are validated
// against patterns without shell characters.
export function restrictedGatherScript(users: RestrictedUser[]): string {
  const parts = users.map((u) => {
    const n = u.name;
    return `section ru-sshd-${n}; sshd -T -C user=${n},host=x,addr=127.0.0.1 2>&1 || true
section ru-passwd-${n}; getent passwd ${n} || echo missing
section ru-groups-${n}; id -gn ${n} 2>&1 || true; id -Gn ${n} 2>&1 || true
section ru-status-${n}; passwd -S ${n} 2>&1 || true
section ru-keyfile-stat-${n}; stat -c '%U %G %a %F' ${KEYS_DIR}/${n} 2>&1 || true
section ru-keyfile-${n}; cat ${KEYS_DIR}/${n} 2>/dev/null || true
section ru-command-${n}; stat -L -c '%U %G %a %F' ${u.command} 2>&1 || true`;
  });
  return `set -u
section() { echo "### $1"; }
section ru-keydir; stat -c '%U %G %a %F' ${KEYS_DIR} 2>&1 || true
${parts.join("\n")}
section end
`;
}
