import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { parseCloudInit } from "../src/adoptscript.ts";
import { loadTemplate, renderCloudInit } from "../src/cloudinit.ts";
import { validateConfig } from "../src/config.ts";
import { isRestrictedCommand, isRestrictedKey, keyFileContent, renderSshdDropIn, restrictedGatherScript, sshUsersScript, SSH_USERS_ROLLBACK, type RestrictedUser } from "../src/sshusers.ts";
import { RESTRICTED_KEY, RESTRICTED_KEY_2 } from "./box-fixtures.ts";
import { sampleConfig } from "./fixtures.ts";

const ADMIN_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const USER: RestrictedUser = { name: "backupuser", command: "/usr/local/sbin/backup-gate", groups: ["backupread"], keys: [RESTRICTED_KEY] };

const problems = (users: unknown, extra: Record<string, unknown> = {}): string[] => validateConfig({ ...sampleConfig, restrictedUsers: { t1: users }, ...extra });

describe("restrictedUsers config", () => {
  it("accepts a forced-command user, and a config without any", () => {
    expect(validateConfig(sampleConfig)).toEqual([]);
    expect(problems([USER])).toEqual([]);
    expect(problems([{ ...USER, groups: [] }])).toEqual([]);
    expect(problems([{ ...USER, keys: [RESTRICTED_KEY, "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="] }])).toEqual([]);
  });

  it("refuses a bad shape", () => {
    for (const bad of [null, [], "x", [null], [{ ...USER, extra: 1 }]]) {
      expect(problems(bad).join(), JSON.stringify(bad)).toMatch(/restrictedUsers\.t1/);
    }
    expect(validateConfig({ ...sampleConfig, restrictedUsers: [] }).join()).toMatch(/restrictedUsers must be an object/);
    expect(validateConfig({ ...sampleConfig, restrictedUsers: { "Bad Box": [USER] } }).join()).toMatch(/not a box name/);
  });

  it("refuses root, the admin user, privileged and invalid names, and duplicates", () => {
    for (const name of ["root", "ops", "sudo", "docker", "staff", "kvm", "libvirt", "incus-admin", "BackupUser", "db backup", "db;x", "-db", "", "a".repeat(40)]) {
      expect(problems([{ ...USER, name }]).join(), name).toMatch(/name/);
    }
    expect(problems([USER, USER]).join()).toMatch(/listed twice/);
    expect(problems([{ ...USER, name: "deploy" }], { adminUser: "deploy" }).join()).toMatch(/admin user/);
  });

  it("refuses a command that is not a plain absolute path", () => {
    for (const command of ["backup-gate", "/usr/local/sbin/gate list", '/usr/bin/x"', "/usr/bin/x;id", "/usr/../bin/sh", "/usr/bin/$(id)", "/usr/bin/x\n", "/", "//x", "/usr/bin/x'", "/usr/bin/x`"]) {
      expect(isRestrictedCommand(command), command).toBe(false);
      expect(problems([{ ...USER, command }]).join(), command).toMatch(/command/);
    }
    expect(isRestrictedCommand("/usr/local/sbin/backup-gate")).toBe(true);
  });

  it("refuses privileged, admin, invalid and duplicate groups", () => {
    for (const g of ["sudo", "admin", "wheel", "docker", "adm", "lxd", "incus-admin", "libvirt", "kvm", "staff", "root", "shadow", "disk", "ops", "backupuser", "Backup", "a b", "x,y", 5]) {
      expect(problems([{ ...USER, groups: [g] }]).join(), String(g)).toMatch(/groups/);
    }
    expect(problems([{ ...USER, groups: ["backupread", "backupread"] }]).join()).toMatch(/twice/);
    expect(problems([{ ...USER, groups: "backupread" }]).join()).toMatch(/groups must be a list/);
  });

  it("refuses key lines with options, other types, broken blobs or odd comments", () => {
    const bad = [
      `restrict ${RESTRICTED_KEY}`,
      `command="/bin/sh" ${RESTRICTED_KEY}`,
      `no-pty,${RESTRICTED_KEY}`,
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x",
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t x",
      // An ecdsa blob labelled ed25519.
      "ssh-ed25519 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=",
      `${RESTRICTED_KEY}\nssh-ed25519 AAAA`,
      `${RESTRICTED_KEY} "quoted"`,
      "ssh-ed25519",
    ];
    for (const key of bad) {
      expect(isRestrictedKey(key), key).toBe(false);
      expect(problems([{ ...USER, keys: [key] }]).join(), key).toMatch(/keys\[0\]/);
    }
    expect(problems([{ ...USER, keys: [] }]).join()).toMatch(/at least one/);
    expect(problems([{ ...USER, keys: [RESTRICTED_KEY, RESTRICTED_KEY] }]).join()).toMatch(/twice/);
  });

  it("accepts boxChangeLog as an absolute path only", () => {
    expect(validateConfig({ ...sampleConfig, boxChangeLog: "/var/log/frosty-box.jsonl" })).toEqual([]);
    expect(validateConfig({ ...sampleConfig, boxChangeLog: "box.jsonl" }).join()).toMatch(/boxChangeLog/);
  });
});

describe("the sshd drop-in", () => {
  it("with no restricted users is byte-identical to the one in cloud-init.yaml", () => {
    const text = renderCloudInit(loadTemplate(), { adminUser: "ops", sshPublicKey: ADMIN_KEY, rebootTime: "04:00" });
    const plan = parseCloudInit(text, { adminUser: "ops", sshPublicKey: ADMIN_KEY });
    expect(plan.files.find((f) => f.path === "/etc/ssh/sshd_config.d/00-stayfrosty.conf")?.content).toBe(renderSshdDropIn("ops", []));
  });

  it("adds the user to AllowUsers and ends with its Match block", () => {
    expect(renderSshdDropIn("ops", [USER])).toBe(`# Managed by stayfrosty. Change it in the stayfrosty repo, not here.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers ops backupuser

Match User backupuser
  AuthorizedKeysFile /etc/ssh/authorized_keys/%u
  ForceCommand /usr/local/sbin/backup-gate
  AuthenticationMethods publickey
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  PermitTTY no
  AllowTcpForwarding no
  AllowStreamLocalForwarding no
  X11Forwarding no
  AllowAgentForwarding no
  PermitTunnel no
  PermitUserRC no
`);
  });

  it("refuses invalid users even when called directly", () => {
    expect(() => renderSshdDropIn("ops", [{ ...USER, command: "/bin/sh -c id" }])).toThrow(/Invalid restricted users/);
    expect(() => renderSshdDropIn("ops", [{ ...USER, name: "ops" }])).toThrow(/Invalid restricted users/);
    expect(() => renderSshdDropIn("root", [])).toThrow(/not a valid user name/);
  });

  it("writes every key with restrict and the forced command", () => {
    expect(keyFileContent({ ...USER, keys: [RESTRICTED_KEY, RESTRICTED_KEY_2] })).toBe(
      `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\nrestrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY_2}\n`,
    );
  });
});

describe("the on-box scripts", () => {
  const decoded = (script: string): string => [...script.matchAll(/'([A-Za-z0-9+/]{40,}={0,2})'/g)].map((m) => Buffer.from(m[1] as string, "base64").toString("utf8")).join("\n");

  it("are valid bash", () => {
    for (const script of [sshUsersScript("ops", [USER], true), sshUsersScript("ops", [USER], false), sshUsersScript("ops", [], true), restrictedGatherScript([USER]), SSH_USERS_ROLLBACK]) {
      const r = spawnSync("bash", ["-n"], { input: script });
      expect(r.status, r.stderr.toString()).toBe(0);
    }
  });

  it("carry the drop-in and key file base64-encoded, and check before reloading", () => {
    const script = sshUsersScript("ops", [USER], true);
    expect(decoded(script)).toContain(renderSshdDropIn("ops", [USER]));
    expect(decoded(script)).toContain(keyFileContent(USER));
    expect(script).toContain("useradd --system --user-group --no-create-home --home-dir /var/lib/stayfrosty/users/backupuser --shell /bin/sh --groups backupread backupuser");
    expect(script.indexOf("sshd -t")).toBeLessThan(script.indexOf("systemctl try-reload-or-restart ssh.service"));
    expect(script).toMatch(/if ! sshd -t \|\| ! admin_ok; then\n\s+mv \/etc\/ssh\/sshd_config.d\/00-stayfrosty.conf.stayfrosty-prev/);
    expect(script).not.toMatch(/sudo|docker/);
  });

  it("plan mode only describes", () => {
    expect(sshUsersScript("ops", [USER], false)).toContain("apply=0");
    expect(sshUsersScript("ops", [USER], true)).toContain("apply=1");
  });
});
