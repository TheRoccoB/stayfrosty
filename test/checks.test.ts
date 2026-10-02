import { describe, expect, it } from "vitest";
import { checkCloudflared, parsePolicy } from "../src/checks/cloudflared.ts";
import { parseOfferedMethods } from "../src/checks/login.ts";
import { checkListeners, parseSs } from "../src/checks/listeners.ts";
import { evaluateOnBox, parseSections } from "../src/checks/onbox.ts";
import { checkSshd } from "../src/checks/sshd.ts";
import { checkUfw } from "../src/checks/ufw.ts";
import { checkPendingReboot, checkUnattendedUpgrades } from "../src/checks/updates.ts";
import { APT_CONFIG_GOOD, POLICY_GOOD, SS_GOOD, SSHD_T_GOOD, UFW_GOOD } from "./box-fixtures.ts";

const NOW = 1_790_000_000;

describe("sshd check", () => {
  it("passes the hardened config", () => {
    expect(checkSshd(SSHD_T_GOOD, "t1", "ops").ok).toBe(true);
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
    const results = evaluateOnBox(parseSections(text), "t1", "ops", "04:00", NOW - 600);
    expect(results.filter((r) => !r.ok)).toEqual([]);
    expect(results).toHaveLength(6);
  });
});
