import { describe, expect, it } from "vitest";
import { checkCloudflared, parsePolicy } from "../src/checks/cloudflared.ts";
import { parseOfferedMethods } from "../src/checks/login.ts";
import { checkListeners, parseSs } from "../src/checks/listeners.ts";
import { evaluateOnBox, parseSections } from "../src/checks/onbox.ts";
import { checkSshd } from "../src/checks/sshd.ts";
import { rebootTimeFor } from "../src/config.ts";
import { checkUfw } from "../src/checks/ufw.ts";
import { checkPendingReboot, checkUnattendedUpgrades } from "../src/checks/updates.ts";
import { checkRestrictedUser, type RestrictedState } from "../src/checks/restricted.ts";
import { APT_CONFIG_GOOD, COMMAND_STAT_GOOD, COMMAND_STAT_MISSING, POLICY_GOOD, RESTRICTED_KEY, RESTRICTED_KEY_2, SS_GOOD, SSHD_T_GOOD, SSHD_T_RESTRICTED, UFW_GOOD } from "./box-fixtures.ts";
import { gatherOutput } from "./fake-ssh.ts";

const NOW = 1_790_000_000;

describe("sshd check", () => {
  it("passes the hardened config", () => {
    expect(checkSshd(SSHD_T_GOOD, "t1", "ops").ok).toBe(true);
    expect(checkSshd(SSHD_T_GOOD, "t1", "ops", "\n").ok).toBe(true);
    const match = checkSshd(SSHD_T_GOOD, "t1", "ops", "Match Address 10.0.0.0/8\n");
    expect(match.ok).toBe(false);
    expect(match.detail).toContain("Match blocks (Match Address 10.0.0.0/8)");
  });

  it("names every wrong value", () => {
    const bad = SSHD_T_GOOD.replace("permitrootlogin no", "permitrootlogin prohibit-password").replace("allowusers ops", "allowusers ops root");
    const result = checkSshd(bad, "t1", "ops");
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("permitrootlogin is prohibit-password");
    expect(result.detail).toContain("allowusers is ops root");
    expect(result.fix).toContain("frosty destroy t1");
  });
});

describe("ufw check", () => {
  it("passes deny-by-default with only the 22 limit", () => {
    expect(checkUfw(UFW_GOOD, "t1").ok).toBe(true);
  });

  it("flags an extra rule like a leftover home IP or 8080", () => {
    const bad = UFW_GOOD.replace("22/tcp (v6)", "8080                       ALLOW IN    Anywhere\n22/tcp (v6)");
    const result = checkUfw(bad, "t1");
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("8080 ALLOW IN Anywhere");
  });

  it("flags inactive UFW", () => {
    expect(checkUfw("Status: inactive\n", "t1").detail).toBe("UFW is not active");
  });
});

describe("listeners check", () => {
  it("parses addresses with interfaces and brackets", () => {
    const parsed = parseSs(SS_GOOD);
    expect(parsed.find((l) => l.port === 68)).toMatchObject({ proto: "udp", address: "192.0.2.10", processes: ["systemd-network"] });
    expect(parsed.find((l) => l.address === "::" && l.port === 22)?.processes).toEqual(["sshd", "systemd"]);
  });

  it("passes sshd and DHCP, ignores loopback", () => {
    expect(checkListeners(SS_GOOD).ok).toBe(true);
  });

  it("allows cloudflared's QUIC sockets on ephemeral ports, nothing else of it", () => {
    // Captured from a live box: 4 QUIC connections to Cloudflare.
    const quic = `${SS_GOOD}udp UNCONN 0 0 *:58746 *:* users:(("cloudflared",pid=2743,fd=9))\nudp UNCONN 0 0 *:35496 *:* users:(("cloudflared",pid=2743,fd=7))\n`;
    expect(checkListeners(quic).ok).toBe(true);
    const metrics = `${SS_GOOD}tcp LISTEN 0 4096 0.0.0.0:20241 0.0.0.0:* users:(("cloudflared",pid=2743,fd=11))\n`;
    expect(checkListeners(metrics).ok).toBe(false);
  });

  it("reports a published Docker port by process", () => {
    const bad = `${SS_GOOD}tcp   LISTEN 0      4096         0.0.0.0:8080      0.0.0.0:*    users:(("docker-proxy",pid=1200,fd=4))\n`;
    const result = checkListeners(bad);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("tcp 0.0.0.0:8080 (docker-proxy)");
  });
});

describe("unattended-upgrades check", () => {
  const base = { enabled: "enabled", aptConfig: APT_CONFIG_GOOD, stamp: "none", createdAt: NOW - 3600, now: NOW };

  it("passes a new box that has not run yet", () => {
    expect(checkUnattendedUpgrades(base, "t1")).toMatchObject({ ok: true, detail: "not run yet (new box)" });
  });

  it("fails an old box that never ran, or ran long ago", () => {
    expect(checkUnattendedUpgrades({ ...base, createdAt: NOW - 5 * 86_400 }, "t1").ok).toBe(false);
    expect(checkUnattendedUpgrades({ ...base, createdAt: NOW - 10 * 86_400, stamp: String(NOW - 3 * 86_400) }, "t1").detail).toContain("last run 3d ago");
  });

  it("ignores a stamp baked into the image before the box existed", () => {
    expect(checkUnattendedUpgrades({ ...base, stamp: String(NOW - 5 * 86_400) }, "t1")).toMatchObject({ ok: true, detail: "not run yet (new box)" });
  });

  it("fails without the cloudflared origin or auto reboot", () => {
    const config = APT_CONFIG_GOOD.replace(/.*cloudflared.*\n/, "").replace('Automatic-Reboot "true"', 'Automatic-Reboot "false"');
    const result = checkUnattendedUpgrades({ ...base, aptConfig: config }, "t1");
    expect(result.detail).toContain("cloudflared origin");
    expect(result.detail).toContain("automatic reboot is off");
  });
});

describe("pending reboot check", () => {
  it("passes when none or recent, fails after 2 days", () => {
    expect(checkPendingReboot("none", NOW, "04:00").ok).toBe(true);
    expect(checkPendingReboot(String(NOW - 7200), NOW, "04:00").detail).toContain("reboots itself at 04:00");
    expect(checkPendingReboot(String(NOW - 3 * 86_400), NOW, "04:00").ok).toBe(false);
  });
});

describe("cloudflared check", () => {
  it("reads the installed version's sources", () => {
    expect(parsePolicy(POLICY_GOOD)).toEqual({
      installed: "2026.9.3",
      candidate: "2026.9.3",
      installedSources: ["https://pkg.cloudflare.com/cloudflared any/main amd64 Packages", "/var/lib/dpkg/status"],
    });
    expect(checkCloudflared(POLICY_GOOD, "t1").ok).toBe(true);
  });

  it("fails a .deb install that will never update", () => {
    const deb = `cloudflared:\n  Installed: 2025.1.0\n  Candidate: 2025.1.0\n  Version table:\n *** 2025.1.0 100\n        100 /var/lib/dpkg/status\n`;
    expect(checkCloudflared(deb, "t1").ok).toBe(false);
  });

  it("fails when missing", () => {
    expect(checkCloudflared("cloudflared:\n  Installed: (none)\n  Candidate: 2026.9.3\n", "t1").detail).toBe("cloudflared is not installed");
  });
});

describe("login checks", () => {
  it("reads the methods sshd offers", () => {
    expect(parseOfferedMethods("debug1: Authentications that can continue: publickey\n")).toEqual(["publickey"]);
    expect(parseOfferedMethods("debug1: Authentications that can continue: publickey,password\n")).toEqual(["publickey", "password"]);
    expect(parseOfferedMethods("nothing")).toBeUndefined();
  });
});

describe("on-box evaluation", () => {
  it("splits the gather output and runs every check", () => {
    const text = [
      "### sshd", SSHD_T_GOOD,
      "### ufw", UFW_GOOD,
      "### ss", SS_GOOD,
      "### uu-enabled", "enabled",
      "### apt-config", APT_CONFIG_GOOD,
      "### uu-stamp", "none",
      "### reboot-required", "none",
      "### cloudflared", POLICY_GOOD,
      "### now", String(NOW),
      "### end",
    ].join("\n");
    const results = evaluateOnBox(parseSections(text), { box: "t1", adminUser: "ops", rebootTime: "04:00", createdAt: NOW - 600, tunnel: false });
    expect(results.filter((r) => !r.ok)).toEqual([]);
    expect(results).toHaveLength(6);
  });
});

describe("tunnel token search", () => {
  it("passes when the token is only where it belongs", async () => {
    const { evaluateTokenSearch } = await import("../src/checks/token.ts");
    // Captured from a live box.
    const ok = "### ps\n0\n### environ\n0\n### files\n600 root root /etc/cloudflared/token\n440 root root /run/credentials/cloudflared.service/tunnel-token\n### end\n";
    expect(evaluateTokenSearch(ok).ok).toBe(true);
  });

  it("fails on ps, environment, a readable copy, or an unfinished search", async () => {
    const { evaluateTokenSearch } = await import("../src/checks/token.ts");
    const bad = "### ps\n1\n### environ\n1\n### files\n644 root root /etc/systemd/system/cloudflared.service\n644 root root /etc/cloudflared/token\n";
    const result = evaluateTokenSearch(bad);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("command line");
    expect(result.detail).toContain("environment");
    expect(result.detail).toContain("/etc/systemd/system/cloudflared.service (mode 644, root:root)");
    expect(result.detail).toContain("/etc/cloudflared/token (mode 644, root:root)");
    expect(result.detail).toContain("did not finish");
  });
});

describe("edge checks", () => {
  it("recognizes the Access login, by redirect or by 401", async () => {
    const { isAccessLogin } = await import("../src/checks/edge.ts");
    expect(isAccessLogin(302, "https://team.cloudflareaccess.com/cdn-cgi/access/login/ssh-t1.example.com?kid=x", null)).toBe(true);
    expect(isAccessLogin(401, null, "Bearer realm=x")).toBe(true);
    expect(isAccessLogin(302, "https://evil.example.com/cdn-cgi/access/login/x", null)).toBe(false);
    expect(isAccessLogin(200, null, null)).toBe(false);
  });

  it("finds the box's IP anywhere in the zone, including its IPv6 /64", async () => {
    const { checkDns } = await import("../src/checks/edge.ts");
    const records = [
      { id: "1", type: "CNAME", name: "ssh-t1.example.com", content: "tun.cfargotunnel.com", proxied: true },
      { id: "2", type: "AAAA", name: "old.example.com", content: "2a01:4f8:c012:766f::5", proxied: false },
    ];
    const result = checkDns("t1", records, "ssh-t1.example.com", "tun", "192.0.2.10", "2a01:4f8:c012:766f::/64");
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("AAAA old.example.com");
    expect(checkDns("t1", records.slice(0, 1), "ssh-t1.example.com", "tun", "192.0.2.10", "2a01:4f8:c012:766f::/64").ok).toBe(true);
  });

  it("flags an Everyone rule or a bypass decision in Access", async () => {
    const { checkAccess } = await import("../src/checks/edge.ts");
    const policy = { id: "p", name: "stayfrosty-t1", decision: "allow", include: [{ email: { email: "me@example.com" } }] };
    const app = { id: "a", name: "stayfrosty-t1", type: "self_hosted", domain: "ssh-t1.example.com", policies: [{ ...policy, precedence: 1 }] };
    expect(checkAccess("t1", app, policy, "ssh-t1.example.com", ["me@example.com"]).ok).toBe(true);
    const short = checkAccess("t1", app, policy, "ssh-t1.example.com", ["me@example.com", "two@example.com"]);
    expect(short.ok).toBe(false);
    expect(short.detail).toContain("does not include two@example.com");
    const open = { ...policy, decision: "bypass", include: [{ everyone: {} }] };
    const result = checkAccess("t1", { ...app, policies: [{ ...open, precedence: 1 }] }, open, "ssh-t1.example.com", ["me@example.com"]);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("decides bypass");
    expect(result.detail).toContain("an Everyone rule");
  });

  it("reports an open window with its age", async () => {
    const { checkWindowClosed } = await import("../src/checks/edge.ts");
    const firewall = { id: 1, name: "stayfrosty-t1", labels: { "stayfrosty-window-opened": "1790000000" }, rules: [{ direction: "in" as const, protocol: "tcp", port: "22", source_ips: ["198.51.100.7/32"] }], applied_to: [] };
    const result = checkWindowClosed("t1", firewall, 1_790_000_000_000 + 30 * 60_000);
    expect(result.detail).toContain("open for 30 minutes");
    expect(checkWindowClosed("t1", { ...firewall, rules: [] }, 0).ok).toBe(true);
  });
});

describe("per-box reboot times", () => {
  it("each box gets its own time, others the default, and the check wants the box's", () => {
    const cfg = { rebootTime: "04:00", rebootTimes: { app1: "10:00" } };
    expect(rebootTimeFor(cfg, "app1")).toBe("10:00");
    expect(rebootTimeFor(cfg, "svc1")).toBe("04:00");
    const input = { enabled: "enabled", aptConfig: APT_CONFIG_GOOD, stamp: "none", createdAt: 1, now: 2 };
    expect(checkUnattendedUpgrades({ ...input, rebootTime: "04:00" }, "t1").ok).toBe(true);
    const wrong = checkUnattendedUpgrades({ ...input, rebootTime: "10:00" }, "t1");
    expect(wrong.ok).toBe(false);
    expect(wrong.detail).toContain("reboot time is 04:00, want 10:00");
    const pacific = checkUnattendedUpgrades({ ...input, rebootTime: "04:00", timezone: "America/Los_Angeles\n" }, "t1");
    expect(pacific.ok).toBe(false);
    expect(pacific.detail).toContain("timezone is America/Los_Angeles, not UTC");
    expect(checkUnattendedUpgrades({ ...input, rebootTime: "04:00", timezone: "Etc/UTC\n" }, "t1").ok).toBe(true);
    // A key that is only in the prototype chain is not a box.
    expect(rebootTimeFor({ rebootTime: "04:00", rebootTimes: {} }, "constructor")).toBe("04:00");
  });
});

describe("restricted users", () => {
  const user = { name: "backupuser", command: "/usr/local/sbin/backup-gate", groups: ["backupread"], keys: [RESTRICTED_KEY] };
  const sshdT = SSHD_T_GOOD.replace("allowusers ops\n", "allowusers ops\nallowusers backupuser\n");
  const good = (): RestrictedState => ({
    sshdT: SSHD_T_RESTRICTED,
    passwd: "backupuser:x:999:994::/var/lib/stayfrosty/users/backupuser:/bin/sh\n",
    groups: "backupuser\nbackupuser backupread\n",
    status: "backupuser L 2026-11-05 -1 -1 -1 -1\n",
    keyDirStat: "root root 755 directory\n",
    keyFileStat: "root root 644 regular file\n",
    keyFile: `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\n`,
    commandStat: COMMAND_STAT_GOOD,
  });
  const fails = (change: Partial<RestrictedState>, detail: string | RegExp): void => {
    const result = checkRestrictedUser({ ...good(), ...change }, "t1", user);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(detail);
    expect(result.fix).toContain("frosty ssh-users sync t1");
  };
  const sshdSetting = (key: string, value: string): Partial<RestrictedState> => ({ sshdT: SSHD_T_RESTRICTED.replace(new RegExp(`^${key} .*$`, "m"), `${key} ${value}`) });

  it("passes AllowUsers of the admin plus the configured users, and their Match User lines", () => {
    expect(checkSshd(sshdT, "t1", "ops", "Match User backupuser\n", ["backupuser"]).ok).toBe(true);
    expect(checkSshd(sshdT, "t1", "ops", "  match user backupuser\n", ["backupuser"]).ok).toBe(true);
    expect(checkSshd(SSHD_T_GOOD.replace("allowusers ops", "allowusers ops backupuser"), "t1", "ops", "", ["backupuser"]).ok).toBe(true);
  });

  it("without restricted users in config, the same box is red as before", () => {
    const result = checkSshd(sshdT, "t1", "ops", "Match User backupuser\n");
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("allowusers is ops backupuser, want ops");
    expect(result.detail).toContain("Match blocks (Match User backupuser)");
  });

  it("fails AllowUsers with an extra user, or without a configured one", () => {
    expect(checkSshd(sshdT.replace("allowusers backupuser", "allowusers backupuser\nallowusers eve"), "t1", "ops", "", ["backupuser"]).detail).toContain("allowusers is ops backupuser eve, want ops backupuser");
    expect(checkSshd(SSHD_T_GOOD, "t1", "ops", "", ["backupuser"]).detail).toContain("allowusers is ops, want ops backupuser");
    expect(checkSshd(SSHD_T_GOOD, "t1", "ops", "", ["backupuser"]).fix).toContain("frosty ssh-users sync t1");
  });

  it("fails any other Match block", () => {
    for (const line of ["Match User eve", "Match User backupuser,ops", "Match User db*", "Match Address 10.0.0.0/8", "Match User backupuser Address 10.0.0.1", "Match Group backupread", "Match all"]) {
      const result = checkSshd(sshdT, "t1", "ops", `Match User backupuser\n${line}\n`, ["backupuser"]);
      expect(result.ok, line).toBe(false);
      expect(result.detail).toContain(`Match blocks (${line})`);
    }
  });

  it("passes the user frosty sets up (state captured from a test container)", () => {
    expect(checkRestrictedUser(good(), "t1", user)).toMatchObject({ ok: true, detail: expect.stringContaining("runs only /usr/local/sbin/backup-gate") });
  });

  it("passes while the forced command is not installed yet, and says so", () => {
    const result = checkRestrictedUser({ ...good(), commandStat: COMMAND_STAT_MISSING }, "t1", user);
    expect(result).toMatchObject({ ok: true, detail: expect.stringContaining("(not installed yet)") });
  });

  it("fails each effective sshd setting that is not locked down", () => {
    fails(sshdSetting("forcecommand", "none"), "forcecommand is none, want /usr/local/sbin/backup-gate");
    fails(sshdSetting("forcecommand", "/bin/sh"), "forcecommand is /bin/sh");
    fails(sshdSetting("permittty", "yes"), "permittty is yes, want no");
    fails(sshdSetting("allowtcpforwarding", "yes"), "allowtcpforwarding is yes, want no");
    fails(sshdSetting("allowtcpforwarding", "local"), "allowtcpforwarding is local, want no");
    fails(sshdSetting("allowstreamlocalforwarding", "yes"), "allowstreamlocalforwarding is yes, want no");
    fails(sshdSetting("x11forwarding", "yes"), "x11forwarding is yes, want no");
    fails(sshdSetting("allowagentforwarding", "yes"), "allowagentforwarding is yes, want no");
    fails(sshdSetting("permittunnel", "yes"), "permittunnel is yes, want no");
    fails(sshdSetting("permituserrc", "yes"), "permituserrc is yes, want no");
    fails(sshdSetting("authenticationmethods", "any"), "authenticationmethods is any, want publickey");
    fails(sshdSetting("passwordauthentication", "yes"), "passwordauthentication is yes, want no");
    fails(sshdSetting("kbdinteractiveauthentication", "yes"), "kbdinteractiveauthentication is yes, want no");
    fails(sshdSetting("authorizedkeysfile", ".ssh/authorized_keys /etc/ssh/authorized_keys/%u"), "authorizedkeysfile is .ssh/authorized_keys");
    fails({ sshdT: "" }, "printed nothing");
  });

  it("fails a missing user, a wrong shell or home, or uid 0", () => {
    fails({ passwd: "missing\n" }, "the user does not exist");
    fails({ passwd: "backupuser:x:999:994::/var/lib/stayfrosty/users/backupuser:/usr/sbin/nologin\n" }, "shell is /usr/sbin/nologin, want /bin/sh");
    fails({ passwd: "backupuser:x:999:994::/var/lib/stayfrosty/users/backupuser:/bin/bash\n" }, "shell is /bin/bash");
    fails({ passwd: "backupuser:x:999:994::/home/backupuser:/bin/sh\n" }, "home is /home/backupuser");
    fails({ passwd: "backupuser:x:0:994::/var/lib/stayfrosty/users/backupuser:/bin/sh\n" }, "uid is 0");
  });

  it("fails groups that are not exactly the configured ones, and privileged ones", () => {
    fails({ groups: "backupuser\nbackupuser\n" }, "groups are [], want [backupread]");
    fails({ groups: "backupuser\nbackupuser backupread other\n" }, "groups are [backupread other]");
    fails({ groups: "backupuser\nbackupuser backupread sudo\n" }, "privileged group(s) sudo");
    fails({ groups: "backupuser\nbackupuser backupread docker\n" }, "privileged group(s) docker");
    fails({ groups: "backupuser\nbackupuser backupread adm\n" }, "privileged group(s) adm");
    fails({ groups: "sudo\nsudo backupread\n" }, /primary group is sudo.*privileged group\(s\) sudo/);
  });

  it("fails a password that is not locked", () => {
    fails({ status: "backupuser P 2026-11-05 0 99999 7 -1\n" }, "password is not locked");
    fails({ status: "backupuser NP 2026-11-05 0 99999 7 -1\n" }, "password is not locked");
    fails({ status: "" }, "password is not locked");
  });

  it("fails a key directory that is not root-only", () => {
    fails({ keyDirStat: "backupuser root 755 directory\n" }, "/etc/ssh/authorized_keys owned by backupuser:root");
    fails({ keyDirStat: "root root 775 directory\n" }, "/etc/ssh/authorized_keys mode 775 is group or world writable");
    fails({ keyDirStat: "stat: cannot statx: No such file or directory\n" }, "/etc/ssh/authorized_keys missing");
  });

  it("fails a key file that is not root-only", () => {
    fails({ keyFileStat: "backupuser backupuser 644 regular file\n" }, "/etc/ssh/authorized_keys/backupuser owned by backupuser:backupuser");
    fails({ keyFileStat: "root backupuser 644 regular file\n" }, "owned by root:backupuser");
    fails({ keyFileStat: "root root 646 regular file\n" }, "mode 646 is group or world writable");
    fails({ keyFileStat: "root root 664 regular file\n" }, "mode 664 is group or world writable");
    fails({ keyFileStat: "root root 777 symbolic link\n" }, /writable|symbolic link/);
    fails({ keyFileStat: "root root 644 symbolic link\n" }, "is a symbolic link, want a regular");
    fails({ keyFileStat: "" }, "/etc/ssh/authorized_keys/backupuser missing");
  });

  it("fails key lines without restrict and the command, and keys that are not the configured ones", () => {
    fails({ keyFile: `${RESTRICTED_KEY}\n` }, '1 key line(s) in /etc/ssh/authorized_keys/backupuser do not start with restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate"');
    fails({ keyFile: `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\ncommand="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY_2}\n` }, "1 key line(s)");
    fails({ keyFile: `restrict,command="/bin/sh" ${RESTRICTED_KEY}\n` }, "do not start with");
    fails({ keyFile: `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate",port-forwarding ${RESTRICTED_KEY}\n` }, "do not start with");
    fails({ keyFile: `restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\nrestrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY_2}\n` }, "not the configured ones (2 on the box, 1 in config)");
    fails({ keyFile: "" }, "not the configured ones (0 on the box");
  });

  it("fails a forced command anyone but root can change", () => {
    const cmd = (line: string): Partial<RestrictedState> => ({ commandStat: COMMAND_STAT_GOOD.replace("/usr/local/sbin/backup-gate root root 755 regular file", `/usr/local/sbin/backup-gate ${line}`) });
    fails(cmd("backupuser root 755 regular file"), "forced command /usr/local/sbin/backup-gate owned by backupuser:root");
    fails(cmd("root backupread 775 regular file"), "forced command /usr/local/sbin/backup-gate owned by root:backupread");
    fails(cmd("root root 757 regular file"), "mode 757 is group or world writable");
    fails(cmd("root root 755 directory"), "is a directory");
    fails({ commandStat: COMMAND_STAT_GOOD.split("\n").slice(1).join("\n") }, "forced command /usr/local/sbin/backup-gate missing");
  });

  it("fails a forced command that is a symlink", () => {
    fails({ commandStat: COMMAND_STAT_GOOD.replace("root root 755 regular file", "root root 777 symbolic link") }, "forced command /usr/local/sbin/backup-gate is a symbolic link");
  });

  it("fails a directory above the forced command that is not root-only, like Debian's root:staff 2775 /usr/local", () => {
    fails({ commandStat: COMMAND_STAT_GOOD.replace("/usr/local root root 755 directory", "/usr/local root staff 2775 directory") }, "directory /usr/local above the forced command owned by root:staff");
    fails({ commandStat: COMMAND_STAT_GOOD.replace("/usr/local/sbin root root 755 directory", "/usr/local/sbin root root 775 directory") }, "directory /usr/local/sbin above the forced command mode 775 is group or world writable");
    fails({ commandStat: COMMAND_STAT_GOOD.replace("/usr root root 755 directory", "/usr backupuser root 755 directory") }, "directory /usr above the forced command owned by backupuser:root");
    fails({ commandStat: COMMAND_STAT_GOOD.replace("/ root root 755 directory\n", "/ root root 1777 directory\n") }, "directory / above the forced command mode 1777");
    fails({ commandStat: COMMAND_STAT_GOOD.replace("/usr/local/sbin root root 755 directory\n", "") }, "directory /usr/local/sbin above the forced command was not checked");
    // Not installed yet, but the directory it will land in is writable: still red.
    fails({ commandStat: COMMAND_STAT_MISSING.replace("/usr/local root root 755 directory", "/usr/local root staff 2775 directory") }, "directory /usr/local above the forced command owned by root:staff");
  });

  it("fails key lines without the loopback-only from= restriction", () => {
    fails({ keyFile: `restrict,command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\n` }, 'do not start with restrict,from="127.0.0.1,::1",command="/usr/local/sbin/backup-gate"');
    fails({ keyFile: `restrict,from="*",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\n` }, "do not start with");
    fails({ keyFile: `restrict,from="127.0.0.1,::1,203.0.113.0/24",command="/usr/local/sbin/backup-gate" ${RESTRICTED_KEY}\n` }, "do not start with");
  });

  it("evaluates restricted users only when the box has them in config", () => {
    const base = parseSections(gatherOutput());
    const want = { box: "t1", adminUser: "ops", rebootTime: "04:00", createdAt: NOW - 3600, tunnel: false };
    const plain = evaluateOnBox(base, want);
    expect(plain.map((r) => r.name)).not.toContain("restricted user backupuser: forced command only");
    expect(plain[0]?.ok).toBe(true);
    const sections = new Map(base);
    sections.set("sshd", sshdT);
    sections.set("sshd-match", "Match User backupuser\n");
    for (const [k, v] of Object.entries({
      "ru-keydir": good().keyDirStat,
      "ru-sshd-backupuser": good().sshdT,
      "ru-passwd-backupuser": good().passwd,
      "ru-groups-backupuser": good().groups,
      "ru-status-backupuser": good().status,
      "ru-keyfile-stat-backupuser": good().keyFileStat,
      "ru-keyfile-backupuser": good().keyFile,
      "ru-command-backupuser": good().commandStat,
    })) {
      sections.set(k, v);
    }
    const results = evaluateOnBox(sections, { ...want, restrictedUsers: [user] });
    expect(results.slice(0, 2).map((r) => [r.name, r.ok])).toEqual([
      ["sshd: keys only, no root, only the admin user", true],
      ["restricted user backupuser: forced command only", true],
    ]);
    // The same box checked with no restricted users in config is red.
    expect(evaluateOnBox(sections, want)[0]?.ok).toBe(false);
  });
});
