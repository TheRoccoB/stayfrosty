import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runDestroy } from "../src/commands/destroy.ts";
import { runNew } from "../src/commands/new.ts";
import { saveConfig } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeCloudflare, FAKE_TUNNEL_TOKEN } from "./fake-cloudflare.ts";
import { FakeHetzner } from "./fake-hetzner.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { FakeBox } from "./fake-ssh.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";

describe("frosty new and destroy", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let hz: FakeHetzner;
  let cf: FakeCloudflare;
  let box: FakeBox;
  let forgotten: string[];
  let events: string[];
  let userSshResult: { code: number; stdout: string; stderr: string };

  const deps = (io: ScriptedIo, extra: Partial<Deps> = {}): Deps => ({
    io,
    env,
    fetch: http.fetch,
    sleep: noSleep,
    now: () => 1_790_000_000_000,
    ssh: box.run,
    closeSsh: async () => {},
    forgetHost: async (host) => {
      forgotten.push(host);
    },
    userSsh: async (host, command) => {
      events.push(`user ssh ${host} ${command}`);
      return userSshResult;
    },
    hasAccessToken: async () => false,
    authoritativeResolves: async () => true,
    systemResolves: async () => true,
    cloudflaredPath: "/opt/homebrew/bin/cloudflared",
    laptopIp: async () => ({ ipv4: "198.51.100.7", ipv6: undefined }),
    isTty: true,
    ...extra,
  });

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-new-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    writeFileSync(join(home, ".ssh", "config"), "Host old\n  HostName old.example.com\n");
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await saveConfig(sampleConfig, env);
    http = new FakeHttp();
    hz = new FakeHetzner(http);
    cf = new FakeCloudflare(http);
    box = new FakeBox();
    forgotten = [];
    events = [];
    userSshResult = { code: 0, stdout: "", stderr: "" };
    // Record when the window opens and closes relative to the user's ssh.
    http.on("POST", "api.hetzner.cloud", "/v1/firewalls/\\d+/actions/set_rules", (call) => {
      const id = Number(call.url.pathname.split("/")[3]);
      const firewall = hz.firewalls.find((f) => f["id"] === id) as Record<string, unknown>;
      const rules = (call.body as { rules: unknown[] }).rules;
      firewall["rules"] = rules;
      events.push(rules.length === 0 ? "window closed" : "window opened");
      return { status: 201, body: { actions: [] } };
    });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  const hetznerWrites = (): string[] => http.writes().filter((c) => c.url.host === "api.hetzner.cloud").map((c) => `${c.method} ${c.url.pathname}`);

  it("creates the firewall with only the window, then the server with it attached", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(0);

    const firewall = hz.firewalls[0] as Record<string, unknown>;
    const fwId = firewall["id"] as number;
    expect(hetznerWrites()).toEqual(["POST /v1/ssh_keys", "POST /v1/firewalls", "POST /v1/servers", `POST /v1/firewalls/${fwId}/actions/set_rules`, `PUT /v1/firewalls/${fwId}`]);
    expect(firewall["name"]).toBe("stayfrosty-t1");
    const created = http.writes().find((c) => c.url.pathname === "/v1/firewalls")?.body as Record<string, unknown>;
    expect(created["rules"]).toEqual([{ direction: "in", protocol: "tcp", port: "22", source_ips: ["198.51.100.7/32"], description: "stayfrosty window" }]);
    expect(created["labels"]).toMatchObject({ stayfrosty: "1", "stayfrosty-box": "t1", "stayfrosty-window-opened": "1790000000" });

    const serverBody = http.writes().find((c) => c.url.pathname === "/v1/servers")?.body as Record<string, unknown>;
    expect(serverBody["firewalls"]).toEqual([{ firewall: fwId }]);
    expect(serverBody["labels"]).toEqual({ stayfrosty: "1", "stayfrosty-box": "t1" });
    expect(serverBody["user_data"]).toContain(PUBLIC_KEY);
    expect(serverBody["user_data"]).not.toMatch(/__[A-Z_]+__/);
    expect(forgotten).toEqual(["stayfrosty-t1"]);
    expect(box.commands()).toContain("sudo cloud-init status --wait --long");
  });

  it("sets up the tunnel, DNS, Access and alert, and closes the window only after ssh works through Access", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(0);

    const tunnel = cf.tunnels[0] as Record<string, unknown>;
    expect(tunnel["name"]).toBe("stayfrosty-t1");
    expect(cf.ingress.get(tunnel["id"] as string)).toEqual([{ hostname: "ssh-t1.example.com", service: "ssh://localhost:22" }, { service: "http_status:404" }]);
    expect(cf.dns).toEqual([
      expect.objectContaining({ type: "CNAME", name: "ssh-t1.example.com", content: `${tunnel["id"] as string}.cfargotunnel.com`, proxied: true, comment: "stayfrosty box t1" }),
    ]);
    expect(cf.policies).toEqual([expect.objectContaining({ name: "stayfrosty-t1", decision: "allow", include: [{ email: { email: "me@example.com" } }] })]);
    expect(cf.apps).toEqual([
      expect.objectContaining({ name: "stayfrosty-t1", type: "self_hosted", domain: "ssh-t1.example.com", session_duration: "24h", policies: [{ id: (cf.policies[0] as { id: string }).id, precedence: 1 }] }),
    ]);
    expect(cf.alerts).toEqual([
      expect.objectContaining({ name: "stayfrosty-t1", alert_type: "tunnel_health_event", mechanisms: { email: [{ id: "me@example.com" }] }, filters: { tunnel_id: [tunnel["id"]] } }),
    ]);

    expect(events).toEqual(["user ssh t1 true", "window closed"]);
    expect((hz.firewalls[0] as { labels: Record<string, string> }).labels["stayfrosty-window-opened"]).toBeUndefined();
    expect(io.text()).toContain("A browser window opens for the Cloudflare Access login");
    expect(io.text()).toContain("Box t1 is ready. Log in with: ssh t1");
  });

  it("sends the tunnel token only on stdin and never prints it", async () => {
    const io = new ScriptedIo();
    await runNew(deps(io), { box: "t1", resume: false, dryRun: false });
    const write = box.calls.find((c) => c.command.includes("/etc/cloudflared/token.new"));
    expect(write?.opts.stdin).toBe(FAKE_TUNNEL_TOKEN);
    expect(box.calls.every((c) => !c.command.includes(FAKE_TUNNEL_TOKEN))).toBe(true);
    expect(io.text()).not.toContain(FAKE_TUNNEL_TOKEN);
    expect(io.text()).toMatch(/pass\s+Tunnel token: not in ps, env or any readable file/);
  });

  it("writes ~/.ssh/stayfrosty.conf and includes it once, keeping a backup", async () => {
    await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false });
    const conf = readFileSync(join(home, ".ssh", "stayfrosty.conf"), "utf8");
    expect(conf).toContain("Host t1\n  HostName ssh-t1.example.com\n  User ops\n  IdentityFile ~/.ssh/id_ed25519");
    expect(conf).toContain("ProxyCommand /opt/homebrew/bin/cloudflared access ssh --hostname %h");
    expect(conf).toContain("HostKeyAlias stayfrosty-t1");
    expect(conf).toContain("StrictHostKeyChecking yes");
    const main = readFileSync(join(home, ".ssh", "config"), "utf8");
    expect(main.startsWith("# Added by stayfrosty")).toBe(true);
    expect(main).toContain("Include stayfrosty.conf\n\nHost old");
    expect(readFileSync(join(home, ".ssh", "config.stayfrosty-backup-1790000000"), "utf8")).toBe("Host old\n  HostName old.example.com\n");
  });

  it("keeps the window open when ssh through Access fails", async () => {
    userSshResult = { code: 255, stdout: "", stderr: "websocket: bad handshake" };
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/window is still open/);
    expect(events).toEqual(["user ssh t1 true"]);
    expect((hz.firewalls[0] as { rules: unknown[] }).rules).toHaveLength(1);
  });

  it("waits for the zone's nameservers before the laptop looks the name up, and explains a cached miss", async () => {
    let authoritativeAsks = 0;
    let clock = 1_790_000_000_000;
    const order: string[] = [];
    const io = new ScriptedIo();
    const run = runNew(
      deps(io, {
        now: () => {
          clock += 10_000;
          return clock;
        },
        authoritativeResolves: async () => {
          authoritativeAsks += 1;
          order.push("authoritative");
          return authoritativeAsks > 2;
        },
        systemResolves: async () => {
          order.push("system");
          return false;
        },
        hasAccessToken: async () => {
          order.push("cloudflared");
          return false;
        },
      }),
      { box: "t1", resume: false, dryRun: false },
    );
    await expect(run).rejects.toThrow(/cannot resolve it/);
    expect(order.slice(0, 4)).toEqual(["authoritative", "authoritative", "authoritative", "system"]);
    expect(order).not.toContain("cloudflared");
    expect(events).toEqual([]);
  });

  it("refuses a DNS record for the SSH hostname that it did not create", async () => {
    cf.dns.push({ id: "theirs", type: "A", name: "ssh-t1.example.com", content: "203.0.113.1", proxied: false, comment: null });
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/frosty did not create/);
    expect(cf.dns).toHaveLength(1);
  });

  it("sends the console password on stdin only", async () => {
    const io = new ScriptedIo();
    await runNew(deps(io), { box: "t1", resume: false, dryRun: false });
    const chpasswd = box.calls.find((c) => c.command === "sudo chpasswd");
    const password = io.revealed[0]?.trim() as string;
    expect(password).toMatch(/^[A-Za-z2-9]{24}$/);
    expect(chpasswd?.opts.stdin).toBe(`ops:${password}\n`);
    expect(box.calls.every((c) => !c.command.includes(password))).toBe(true);
    expect(io.text()).not.toContain(password);
  });

  it("does not set a console password without a terminal or passwordCommand", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io, { isTty: false }), { box: "t1", resume: false, dryRun: false })).toBe(0);
    expect(box.passwordState).toBe("L");
    expect(io.revealed).toEqual([]);
    expect(io.stderr.join("\n")).toContain("frosty console-password t1");
  });

  it("hands the password to passwordCommand on stdin", async () => {
    await saveConfig({ ...sampleConfig, passwordCommand: "store {box}" }, env);
    const received: { command: string; password: string }[] = [];
    const io = new ScriptedIo();
    await runNew(
      deps(io, {
        isTty: false,
        runPasswordCommand: async (command, password) => {
          received.push({ command, password });
          return 0;
        },
      }),
      { box: "t1", resume: false, dryRun: false },
    );
    expect(received).toHaveLength(1);
    expect(received[0]?.command).toBe("store t1");
    expect(box.passwordState).toBe("P");
    expect(io.revealed).toEqual([]);
  });

  it("reboots when the first upgrade needs it and waits for the new boot", async () => {
    box.rebootRequired = true;
    expect(await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).toBe(0);
    expect(box.commands()).toContain("sudo systemctl reboot");
    expect(box.bootId).toBe("boot-2");
  });

  it("fails with the cloud-init log when cloud-init did not finish clean", async () => {
    box.on((call) => (call.command === "sudo cloud-init status --wait --long" ? { code: 1, stdout: "status: error", stderr: "" } : undefined));
    box.on((call) => (call.command === "sudo cat /var/log/cloud-init-output.log" ? { code: 0, stdout: "ok\nE: Unable to locate package nope\nhost keys", stderr: "" } : undefined));
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/Unable to locate package nope/);
  });

  it("refuses an existing box without --resume, and resumes without duplicating anything", async () => {
    await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false });
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/already exists/);

    const io = new ScriptedIo();
    events = [];
    expect(await runNew(deps(io, { laptopIp: async () => ({ ipv4: "203.0.113.9", ipv6: undefined }) }), { box: "t1", resume: true, dryRun: false })).toBe(0);
    expect(events).toEqual(["window opened", "user ssh t1 true", "window closed"]);
    expect([hz.servers.length, cf.tunnels.length, cf.dns.length, cf.apps.length, cf.policies.length, cf.alerts.length]).toEqual([1, 1, 1, 1, 1, 1]);
    expect(io.text()).toContain("already set; leaving it");
  });

  it("never touches a server it did not create", async () => {
    hz.servers.push({ id: 1, name: "t1", status: "running", labels: {}, server_type: { name: "x" }, public_net: { ipv4: null, ipv6: null } });
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/frosty did not create it/);
    expect(http.writes()).toEqual([]);
  });

  it("dry run changes nothing", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: true })).toBe(0);
    expect(http.writes()).toEqual([]);
    expect(box.calls).toEqual([]);
  });

  it("needs cloudflared on the laptop before changing anything", async () => {
    await expect(runNew(deps(new ScriptedIo(), { cloudflaredPath: undefined }), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/cloudflared is not installed/);
    expect(http.writes()).toEqual([]);
  });

  it("rejects bad box names before calling anything", async () => {
    await expect(runNew(deps(new ScriptedIo()), { box: "Web_1", resume: false, dryRun: false })).rejects.toThrow(/not a valid box name/);
    expect(http.calls).toEqual([]);
  });

  it("reports failed checks with fixes and exit code 1", async () => {
    box.on((call) => (call.target.user === "root" ? { code: 0, stdout: "", stderr: "" } : undefined));
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(1);
    expect(io.text()).toMatch(/FAIL\s+root login is refused/);
    expect(io.text()).toContain("frosty destroy t1 && frosty new t1");
  });

  it("destroy needs the typed name, then deletes everything, the alert first", async () => {
    await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false });
    forgotten = [];

    expect(await runDestroy(deps(new ScriptedIo(["t2"])), { box: "t1", dryRun: false })).toBe(1);
    expect(hz.servers).toHaveLength(1);

    const before = http.writes().length;
    const io = new ScriptedIo(["t1"]);
    expect(await runDestroy(deps(io), { box: "t1", dryRun: false })).toBe(0);
    expect([hz.servers, hz.firewalls, cf.tunnels, cf.dns, cf.apps, cf.policies, cf.alerts]).toEqual([[], [], [], [], [], [], []]);
    const deletes = http.writes().slice(before).map((c) => c.url.pathname);
    expect(deletes[0]).toMatch(/alerting\/v3\/policies/);
    expect(deletes.findIndex((p) => p.includes("/access/apps/"))).toBeLessThan(deletes.findIndex((p) => p.includes("/access/policies/")));
    expect(deletes.findIndex((p) => p.startsWith("/v1/servers/"))).toBeLessThan(deletes.findIndex((p) => p.endsWith("/connections")));
    expect(forgotten).toEqual(["stayfrosty-t1"]);
    expect(readFileSync(join(home, ".ssh", "stayfrosty.conf"), "utf8")).not.toContain("Host t1");
    expect(io.text()).toContain("Box t1 is gone.");
  });

  it("destroy leaves unlabeled things alone and says when there is nothing", async () => {
    hz.servers.push({ id: 1, name: "t1", status: "running", labels: {}, server_type: { name: "x" }, public_net: { ipv4: null, ipv6: null } });
    cf.tunnels.push({ id: "theirs", name: "my-tunnel", status: "healthy" });
    const io = new ScriptedIo();
    expect(await runDestroy(deps(io), { box: "t1", dryRun: false })).toBe(0);
    expect(io.text()).toContain("nothing named t1");
    expect(hz.servers).toHaveLength(1);
    expect(cf.tunnels).toHaveLength(1);
  });
});
