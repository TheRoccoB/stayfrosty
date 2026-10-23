import { isAdminUser } from "./config.ts";
import { FrostyError } from "./errors.ts";

// `adopt` applies cloud-init.yaml to a box that already exists. Hetzner's rebuild takes no user
// data and cloud-init only runs once per instance, so frosty turns the rendered file into shell
// scripts sent over SSH on stdin. This reads only the subset cloud-init.yaml uses (DECISIONS,
// M1: users, write_files, packages, runcmd) and refuses anything else, so a new key in the
// template cannot be silently skipped by adopt.

export interface WriteFile {
  path: string;
  owner: string;
  permissions: string;
  content: string;
}

export interface AdoptPlan {
  packages: string[];
  files: WriteFile[];
  runcmd: string[];
}

const KNOWN_TOP_LEVEL = new Set(["users", "disable_root", "ssh_pwauth", "package_update", "package_upgrade", "packages", "write_files", "runcmd"]);
// What adopt does for each top-level key, in shell, is fixed below. These must stay as they are.
const FIXED: Record<string, string> = { disable_root: "true", ssh_pwauth: "false", package_update: "true", package_upgrade: "true" };

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    const inner = v.slice(1, -1);
    if (/["\\]/.test(inner)) {
      throw new FrostyError(`cloud-init.yaml has an escaped string adopt cannot read: ${v}`, "This is a bug in frosty. Please report it.");
    }
    return inner;
  }
  if (/^["'|>&*!%@`]/.test(v)) {
    throw new FrostyError(`cloud-init.yaml has a value adopt cannot read: ${v}`, "This is a bug in frosty. Please report it.");
  }
  return v;
}

function bad(what: string, line: number): never {
  throw new FrostyError(`cloud-init.yaml line ${line + 1}: ${what}, which adopt cannot read.`, "This is a bug in frosty. Please report it.");
}

// The users block adopt reproduces with userScript. Anything else in it (another group, key,
// user or option) would be something new applies and adopt silently does not, so it must match.
export function expectedUsers(adminUser: string, sshPublicKey: string): string[] {
  return [
    `  - name: "${adminUser}"`,
    "    groups: [sudo]",
    "    shell: /bin/bash",
    "    # Access plus the SSH key is the gate. A sudo password would break unattended operation.",
    '    sudo: "ALL=(ALL) NOPASSWD:ALL"',
    "    lock_passwd: true",
    "    ssh_authorized_keys:",
    `      - "${sshPublicKey}"`,
  ];
}

// Parses the rendered cloud-init.yaml.
export function parseCloudInit(text: string, values: { adminUser: string; sshPublicKey: string }): AdoptPlan {
  const lines = text.split("\n");
  if (lines[0] !== "#cloud-config") {
    bad("the first line is not #cloud-config", 0);
  }
  const plan: AdoptPlan = { packages: [], files: [], runcmd: [] };
  const seen = new Set<string>();
  let i = 1;
  while (i < lines.length) {
    const line = lines[i] as string;
    if (line.includes("\t")) {
      bad("a tab", i);
    }
    if (line.trim() === "" || /^\s*#/.test(line)) {
      i += 1;
      continue;
    }
    const top = /^([a-z_]+):(.*)$/.exec(line);
    if (top === null) {
      bad(`unexpected line "${line}"`, i);
    }
    const [, key, rest] = top as unknown as [string, string, string];
    if (!KNOWN_TOP_LEVEL.has(key)) {
      bad(`the key ${key}`, i);
    }
    if (seen.has(key)) {
      bad(`a second ${key}`, i);
    }
    seen.add(key);
    i += 1;
    if (key in FIXED) {
      if (rest.trim() !== FIXED[key]) {
        bad(`${key} is ${rest.trim()}, not ${FIXED[key] as string}`, i - 1);
      }
      continue;
    }
    if (rest.trim() !== "") {
      bad(`${key} has an inline value`, i - 1);
    }
    // The block: every line up to the next top-level key.
    const start = i;
    while (i < lines.length && !/^[a-z_]+:/.test(lines[i] as string)) {
      i += 1;
    }
    const block = lines.slice(start, i);
    if (key === "packages") {
      plan.packages = listItems(block, start).map((p) => (/^[a-z0-9][a-z0-9.+-]*$/.test(p) ? p : bad(`package ${p}`, start)));
    } else if (key === "runcmd") {
      plan.runcmd = listItems(block, start).map((item) => {
        const m = /^\[([^\],"' ]+)\]$/.exec(item);
        if (m === null) {
          bad(`runcmd item ${item}`, start);
        }
        return m[1] as string;
      });
    } else if (key === "write_files") {
      plan.files = writeFiles(block, start);
    } else if (key === "users") {
      const got = block.filter((l) => l.trim() !== "");
      if (JSON.stringify(got) !== JSON.stringify(expectedUsers(values.adminUser, values.sshPublicKey))) {
        bad("a users block that is not the one adopt reproduces", start);
      }
    }
  }
  for (const key of ["users", "packages", "write_files", "runcmd"]) {
    if (!seen.has(key)) {
      throw new FrostyError(`cloud-init.yaml has no ${key}.`, "This is a bug in frosty. Please report it.");
    }
  }
  return plan;
}

function listItems(block: string[], offset: number): string[] {
  const items: string[] = [];
  block.forEach((line, n) => {
    if (line.trim() === "" || /^\s*#/.test(line)) {
      return;
    }
    const m = /^ {2}- (.+)$/.exec(line);
    if (m === null) {
      bad(`list line "${line}"`, offset + n);
    }
    items.push(unquote(m[1] as string));
  });
  return items;
}

function writeFiles(block: string[], offset: number): WriteFile[] {
  const files: WriteFile[] = [];
  let n = 0;
  const skipBlank = (): void => {
    while (n < block.length && ((block[n] as string).trim() === "" || /^ {2}#/.test(block[n] as string))) {
      n += 1;
    }
  };
  for (skipBlank(); n < block.length; skipBlank()) {
    const head = /^ {2}- path: (.+)$/.exec(block[n] as string);
    if (head === null) {
      bad(`write_files line "${block[n] as string}"`, offset + n);
    }
    const file: Partial<WriteFile> = { path: unquote(head[1] as string) };
    n += 1;
    while (n < block.length) {
      const field = /^ {4}(owner|permissions|content): ?(.*)$/.exec(block[n] as string);
      if (field === null) {
        break;
      }
      const [, name, value] = field as unknown as [string, "owner" | "permissions" | "content", string];
      if (file[name] !== undefined) {
        bad(`a second ${name}`, offset + n);
      }
      n += 1;
      if (name !== "content") {
        file[name] = unquote(value);
        continue;
      }
      if (value !== "|") {
        bad("content that is not a | block", offset + n - 1);
      }
      // A literal block: lines indented 6 spaces, blank lines kept, ending with one newline.
      const body: string[] = [];
      const first = block.slice(n).find((l) => l.trim() !== "");
      if (first !== undefined && /^ {7}/.test(first)) {
        bad("a content block indented more than 6 spaces", offset + n);
      }
      while (n < block.length && (/^ {6}/.test(block[n] as string) || (block[n] as string).trim() === "")) {
        body.push((block[n] as string).slice(6));
        n += 1;
      }
      while (body.length > 0 && body[body.length - 1] === "") {
        body.pop();
      }
      file.content = `${body.join("\n")}\n`;
    }
    if (file.owner === undefined || file.permissions === undefined || file.content === undefined) {
      bad(`write_files entry ${file.path ?? "?"} without owner, permissions or content`, offset + n);
    }
    if (!/^\/[A-Za-z0-9._/-]+$/.test(file.path as string) || (file.path as string).includes("..")) {
      bad(`write_files path ${file.path ?? ""}`, offset + n);
    }
    if (!/^[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*$/.test(file.owner) || !/^0[0-7]{3}$/.test(file.permissions)) {
      bad(`owner ${file.owner} or permissions ${file.permissions}`, offset + n);
    }
    files.push(file as WriteFile);
  }
  return files;
}

// Phase 1, run as the box's existing login (usually root): the admin user with the laptop's key
// and passwordless sudo, as cloud-init's `users` would make it. sshd is not touched yet, so if
// this goes wrong the existing login still works.
export function userScript(adminUser: string, publicKey: string): string {
  if (!isAdminUser(adminUser)) {
    throw new FrostyError(`Admin user "${adminUser}" is not a valid user name.`, "Fix adminUser with: frosty init");
  }
  // The key travels base64-encoded: a comment may hold any character.
  const b64 = Buffer.from(publicKey.trim(), "utf8").toString("base64");
  return `main() {
set -euo pipefail
. /etc/os-release
if [ "\${ID:-}" != ubuntu ] || ! dpkg --compare-versions "\${VERSION_ID:-0}" ge 24.04; then
  echo "stayfrosty-adopt: needs Ubuntu 24.04 or later, this is \${PRETTY_NAME:-unknown}" >&2
  exit 1
fi
grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/\\*\\.conf' /etc/ssh/sshd_config || { echo "stayfrosty-adopt: /etc/ssh/sshd_config does not include sshd_config.d" >&2; exit 1; }
u=${adminUser}
key=$(printf '%s' '${b64}' | base64 -d)
case $key in *$'\n'*|'') echo "stayfrosty-adopt: bad key" >&2; exit 1 ;; esac
if ! id "$u" >/dev/null 2>&1; then
  useradd -m -U -s /bin/bash -G sudo "$u"
  passwd -l "$u" >/dev/null
fi
usermod -aG sudo -s /bin/bash "$u"
g=$(id -gn "$u")
home=$(getent passwd "$u" | cut -d: -f6)
install -d -m 0700 -o "$u" -g "$g" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
grep -qxF -- "$key" "$home/.ssh/authorized_keys" || printf '%s\\n' "$key" >> "$home/.ssh/authorized_keys"
chown "$u:$g" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
printf '%s ALL=(ALL) NOPASSWD:ALL\\n' "$u" > /etc/sudoers.d/90-stayfrosty.new
chmod 0440 /etc/sudoers.d/90-stayfrosty.new
visudo -cqf /etc/sudoers.d/90-stayfrosty.new
mv /etc/sudoers.d/90-stayfrosty.new /etc/sudoers.d/90-stayfrosty
echo stayfrosty-user-ok
}
# Parsed whole before it runs, and nothing it starts can read the rest of it from stdin.
main </dev/null
`;
}

// Phase 2, run as the admin user with sudo: packages, files, then the hardening script, in
// cloud-init's order. File contents travel base64-encoded, so nothing in them is ever shell.
export function hardenScript(plan: AdoptPlan): string {
  const files = plan.files
    .map((f) => {
      const [owner, group] = f.owner.split(":") as [string, string];
      const b64 = Buffer.from(f.content, "utf8").toString("base64");
      return `install -d -m 0755 "$(dirname '${f.path}')"
printf '%s' '${b64}' | base64 -d > '${f.path}.stayfrosty-new'
chown ${owner}:${group} '${f.path}.stayfrosty-new'
chmod ${f.permissions} '${f.path}.stayfrosty-new'
mv '${f.path}.stayfrosty-new' '${f.path}'`;
    })
    .join("\n");
  const packages = plan.packages.map((p) => {
    if (!/^[a-z0-9][a-z0-9.+-]*$/.test(p)) {
      throw new FrostyError(`Package name ${p} in cloud-init.yaml is not a plain package name.`, "This is a bug in frosty. Please report it.");
    }
    return p;
  });
  const runcmd = plan.runcmd.map((c) => {
    if (!/^\/[A-Za-z0-9._/-]+$/.test(c)) {
      throw new FrostyError(`runcmd ${c} in cloud-init.yaml is not a plain path.`, "This is a bug in frosty. Please report it.");
    }
    return c;
  });
  return `main() {
set -euo pipefail
trap 'echo "stayfrosty-adopt: failed at line $LINENO: $BASH_COMMAND" >&2' ERR
export DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=a
# A long-lived box may be mid unattended-upgrade, or left half-configured by an earlier run.
apt_opts=(-y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
dpkg --configure -a
for i in 1 2 3 4 5; do apt-get -q -o DPkg::Lock::Timeout=600 update && break; [ "$i" = 5 ] && exit 1; sleep 30; done
# cloud-init's package_upgrade is a dist-upgrade, so new kernels come in too.
apt-get "\${apt_opts[@]}" dist-upgrade
apt-get "\${apt_opts[@]}" install ${packages.join(" ")}
${files}
${runcmd.join("\n")}
echo stayfrosty-harden-ok
}
main </dev/null
`;
}
