import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GATHER_SCRIPT } from "../src/checks/onbox.ts";
import { main } from "../src/cli.ts";
import { runSshUsers } from "../src/commands/ssh-users.ts";
import { saveConfig, type Config } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { renderSshdDropIn, SSH_USERS_CLEANUP, SSH_USERS_ROLLBACK, type RestrictedUser } from "../src/sshusers.ts";
import { COMMAND_STAT_GOOD, RESTRICTED_KEY, SSHD_T_GOOD, SSHD_T_RESTRICTED } from "./box-fixtures.ts";
import { FakeHetzner } from "./fake-hetzner.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { FakeBox, gatherOutput } from "./fake-ssh.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const USER: RestrictedUser = { name: "backupuser", command: "/usr/local/sbin/backup-gate", groups: ["backupread"], keys: [RESTRICTED_KEY] };

const RESTRICTED_GATHER = [
  "### ru-keydir", "root root 755 directory",
  "### ru-sshd-backupuser", SSHD_T_RESTRICTED,
  "### ru-passwd-backupuser", "backupuser:x:999:994::/var/lib/stayfrosty/users/backupuser:/bin/sh",
  "### ru-groups-backupuser", "backupuser\nbackupuser backupread",
  "### ru-status-backupuser", "backupuser L 2026-11-05 -1 -1 -1 -1",
  "### ru-keyfile-stat-backupuser", "root root 644 regular file",
  "### ru-keyfile-backupuser", `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}`,
  "### ru-command-backupuser", COMMAND_STAT_GOOD,
  "### end",
].join("\n");

describe("frosty ssh-users", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let box: FakeBox;
  let freshLoginWorks: boolean;

  const deps = (io: ScriptedIo): Deps => ({ io, env, fetch: http.fetch, sleep: noSleep, ssh: box.run, cloudflaredPath: "/usr/bin/cloudflared", isTty: false });
  const config = async (extra: Partial<Config>): Promise<void> => {
    await saveConfig({ ...sampleConfig, boxChangeLog: join(home, "box.jsonl"), ...extra }, env);
  };
  const scripts = (): string[] => box.calls.filter((c) => c.command === "sudo bash -s").map((c) => c.opts.stdin ?? "");

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-ssh-users-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await config({ restrictedUsers: { app1: [USER] } });
    http = new FakeHttp();
    const hz = new FakeHetzner(http);
    hz.servers.push({ id: 7, name: "app1", status: "running", created: "2025-03-01T00:00:00Z", labels: { stayfrosty: "1", "stayfrosty-box": "app1" }, public_net: { firewalls: [] } });
    box = new FakeBox();
    freshLoginWorks = true;
    box.on((call) => {
      const stdin = call.opts.stdin ?? "";
      if (call.command === "sudo bash -s" && stdin.includes("stayfrosty-ssh-users-ok")) {
        const apply = stdin.includes("apply=1");
        return { code: 0, stdout: `${apply ? "changing" : "would"}: write /etc/ssh/sshd_config.d/00-stayfrosty.conf, check it with sshd -t, reload sshd\nstayfrosty-ssh-users-changes 1\nstayfrosty-ssh-users-ok\n`, stderr: "" };
      }
      if (call.command === "sudo bash -s" && stdin === GATHER_SCRIPT) {
        const out = gatherOutput().replace(SSHD_T_GOOD, SSHD_T_GOOD.replace("allowusers ops\n", "allowusers ops\nallowusers backupuser\n")).replace("### ufw", "### sshd-match\nMatch User backupuser\n### ufw");
        return { code: 0, stdout: out, stderr: "" };
      }
      if (call.command === "sudo bash -s" && stdin.includes("section ru-keydir")) {
        return { code: 0, stdout: RESTRICTED_GATHER, stderr: "" };
      }
      if (call.command === "sudo -n true") {
        return freshLoginWorks ? { code: 0, stdout: "", stderr: "" } : { code: 255, stdout: "", stderr: "Permission denied (publickey)." };
      }
      return undefined;
    });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("plan runs the script in plan mode through the tunnel and changes nothing", async () => {
    const io = new ScriptedIo();
    expect(await runSshUsers(deps(io), { action: "plan", box: "app1" }), io.text()).toBe(0);
    expect(io.text()).toContain("would: write /etc/ssh/sshd_config.d/00-stayfrosty.conf");
    expect(io.text()).toContain("app1: 1 change(s). Apply them with: frosty ssh-users sync app1");
    expect(scripts()).toHaveLength(1);
    expect(scripts()[0]).toContain("apply=0");
    expect(box.calls[0]?.target).toMatchObject({ host: "ssh-app1.example.com", user: "ops", proxyCommand: "/usr/bin/cloudflared access ssh --hostname %h" });
    expect(http.writes()).toEqual([]);
    expect(() => readFileSync(join(home, "box.jsonl"))).toThrow();
  });

  it("sync applies, proves a fresh admin login, drops the backup, logs, then checks the users", async () => {
    const io = new ScriptedIo();
    expect(await runSshUsers(deps(io), { action: "sync", box: "app1" }), io.text()).toBe(0);
    const order = box.calls.map((c) => (c.command === "sudo bash -s" ? (c.opts.stdin?.includes("apply=1") === true ? "apply" : c.opts.stdin === SSH_USERS_CLEANUP ? "cleanup" : c.opts.stdin === GATHER_SCRIPT ? "gather" : "gather-restricted") : c.command));
    expect(order).toEqual(["apply", "sudo -n true", "cleanup", "gather", "gather-restricted"]);
    expect(box.calls[1]?.opts.extraOptions).toContain("ControlMaster=no");
    expect(io.text()).toMatch(/pass\s+sshd: keys only, no root, only the admin user/);
    expect(io.text()).toMatch(/pass\s+restricted user backupuser: forced command only/);
    const log = readFileSync(join(home, "box.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(log.map((l) => [l["phase"], l["action"], l["target"]])).toEqual([
      ["intent", "ssh-users.sync", "app1"],
      ["done", "ssh-users.sync", "app1"],
    ]);
    expect(log[0]?.["request"]).toEqual({ users: [{ name: "backupuser", command: "/usr/local/sbin/backup-gate", groups: ["backupread"], keys: 1 }] });
    expect(log[1]?.["result"]).toEqual({ changes: 1 });
  });

  it("rolls the drop-in back when a fresh admin login fails after the sync", async () => {
    freshLoginWorks = false;
    await expect(runSshUsers(deps(new ScriptedIo()), { action: "sync", box: "app1" })).rejects.toThrow(/fresh ops login to app1 failed\. The old sshd drop-in is back/);
    expect(scripts()).toContain(SSH_USERS_ROLLBACK);
    expect(scripts()).not.toContain(SSH_USERS_CLEANUP);
    const log = readFileSync(join(home, "box.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(log[1]?.["result"]).toEqual({ changes: 1, rolledBack: true });
  });

  it("with no restricted users in config, the script keeps none and writes the base drop-in", async () => {
    await config({});
    const io = new ScriptedIo();
    await runSshUsers(deps(io), { action: "plan", box: "app1" });
    expect(scripts()[0]).toContain('keep="  "');
    expect(scripts()[0]).toContain(`'${Buffer.from(renderSshdDropIn("ops", []), "utf8").toString("base64")}'`);
  });

  it("refuses an unknown action or box, and is wired into the CLI", async () => {
    await expect(runSshUsers(deps(new ScriptedIo()), { action: "apply", box: "app1" })).rejects.toThrow(/needs plan or sync/);
    await expect(runSshUsers(deps(new ScriptedIo()), { action: "plan", box: "nope" })).rejects.toThrow(/no box named nope/);
    const io = new ScriptedIo();
    expect(await main(["--help"], io)).toBe(0);
    expect(io.text()).toContain("frosty ssh-users (plan | sync) <box>");
  });
});
