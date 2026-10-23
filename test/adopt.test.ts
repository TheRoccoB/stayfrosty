import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { knownHostsPath } from "../src/box.ts";
import { runAdopt, type AdoptOptions } from "../src/commands/adopt.ts";
import { runDestroy } from "../src/commands/destroy.ts";
import { runNew } from "../src/commands/new.ts";
import { runVerify } from "../src/commands/verify.ts";
import { saveConfig } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHetzner } from "./fake-hetzner.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { FakeBox } from "./fake-ssh.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const HOST_FP = "SHA256:rC03+WKxJ6r3tjXgR+DoNWl8wJdQwqaWAASgZMSY+E4";
const OTHER_FP = "SHA256:AvIeAKW5ylXHzyFk7OpcweuSAKsPbJ3Y8ZuWGBI2HX8";
const IP = "192.0.2.20";
// The fake box reports the real clock, so the test runs on it too.
const NOW = Math.floor(Date.now() / 1000);

describe("frosty adopt", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let hz: FakeHetzner;
  let box: FakeBox;
  let scanned: string[];
  let adminExists: boolean;
  let hardened: boolean;

  const deps = (io: ScriptedIo, extra: Partial<Deps> = {}): Deps => ({
    io,
    env,
    fetch: http.fetch,
    sleep: noSleep,
    now: () => NOW * 1000,
    ssh: box.run,
    closeSsh: async () => {},
    forgetHost: async () => {},
    userSsh: async () => ({ code: 0, stdout: "", stderr: "" }),
    keyScan: async (host) => {
      scanned.push(host);
      return [
        { type: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIHostHostHostHostHostHostHostHostHostHost", fingerprint: HOST_FP },
        { type: "ecdsa-sha2-nistp256", key: "AAAAE2VjZHNh", fingerprint: "SHA256:ecdsaecdsaecdsaecdsaecdsaecdsaecdsaecdsaecd" },
      ];
    },
    hasAccessToken: async () => true,
    authoritativeResolves: async () => true,
    systemResolves: async () => true,
    cloudflaredPath: "/usr/bin/cloudflared",
    laptopIp: async () => ({ ipv4: "198.51.100.7", ipv6: undefined }),
    isTty: false,
    ...extra,
  });

  const opts = (extra: Partial<AdoptOptions> = {}): AdoptOptions => ({
    box: "app1",
    ip: IP,
    user: "root",
    hostKey: HOST_FP,
    trustFirstUse: false,
    resume: false,
    dryRun: false,
    ...extra,
  });

  const existingServer = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    id: 7,
    name: "app1",
    status: "running",
    created: "2025-03-01T00:00:00Z",
    labels: { owner: "rocco" },
    protection: { delete: false, rebuild: false },
    server_type: { name: "cpx21" },
    location: { name: "fsn1" },
    public_net: { ipv4: { ip: IP }, ipv6: { ip: "2001:db8:7::/64" }, firewalls: [] },
    ...extra,
  });

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-adopt-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await saveConfig(sampleConfig, env);
    http = new FakeHttp();
    hz = new FakeHetzner(http);
    new FakeCloudflare(http);
    hz.servers.push(existingServer());
    box = new FakeBox();
    scanned = [];
    adminExists = false;
    hardened = false;
    // Before adopt, root logs in and ops does not exist. The hardening closes root.
    box.on((call) => {
      const { user } = call.target;
      if (user === "root") {
        if (hardened) {
          return undefined;
        }
        if (call.command === "bash -s" && call.opts.stdin?.includes("useradd") === true) {
          adminExists = true;
          return { code: 0, stdout: "stayfrosty-user-ok\n", stderr: "" };
        }
        return { code: 0, stdout: "", stderr: "" };
      }
      if (call.command === "sudo -n true") {
        return adminExists ? { code: 0, stdout: "", stderr: "" } : { code: 255, stdout: "", stderr: "Permission denied (publickey)." };
      }
      if (call.command === "sudo bash -s" && call.opts.stdin?.includes("stayfrosty-harden-ok") === true) {
        hardened = true;
        return { code: 0, stdout: "...\nstayfrosty-harden-ok\n", stderr: "" };
      }
      return undefined;
    });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  const hetznerWrites = (): string[] => http.writes().filter((c) => c.url.host === "api.hetzner.cloud").map((c) => `${c.method} ${c.url.pathname}`);
  const server = (): Record<string, unknown> => hz.servers[0] as Record<string, unknown>;

  it("protects and labels the server, opens a window, hardens it in two phases, then closes the window", async () => {
    const io = new ScriptedIo();
    const code = await runAdopt(deps(io), opts());
    expect(code, io.text()).toBe(0);

    const fw = hz.firewalls[0] as Record<string, unknown>;
    expect(hetznerWrites()).toEqual([
      "POST /v1/servers/7/actions/change_protection",
      "PUT /v1/servers/7",
      "POST /v1/firewalls",
      `POST /v1/firewalls/${fw["id"] as number}/actions/apply_to_resources`,
      `POST /v1/firewalls/${fw["id"] as number}/actions/set_rules`,
      `PUT /v1/firewalls/${fw["id"] as number}`,
    ]);
    expect(server()["protection"]).toEqual({ delete: true, rebuild: true });
    expect(server()["labels"]).toEqual({ owner: "rocco", stayfrosty: "1", "stayfrosty-box": "app1", "stayfrosty-adopted": String(NOW) });
    expect(fw["rules"]).toEqual([]);

    // Phase 1 as root, then ops is proven, then phase 2 as ops.
    const steps = box.calls.map((c) => `${c.target.user} ${c.command}`).filter((s) => /bash -s|sudo -n true/.test(s));
    expect(steps.slice(0, 4)).toEqual(["ops sudo -n true", "root bash -s", "ops sudo -n true", "ops sudo bash -s"]);
    expect(box.calls.every((c) => c.target.pinned === true || c.target.proxyCommand !== undefined)).toBe(true);
    expect(readFileSync(knownHostsPath(env), "utf8")).toBe("stayfrosty-app1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostHostHostHostHostHostHostHostHostHost\n");
    expect(io.text()).toContain(`Pinned app1's host key ssh-ed25519 ${HOST_FP}, matching --host-key.`);
    expect(io.text()).toContain("Box app1 is ready.");
  });

  it("never creates, deletes, rebuilds or resizes a server", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    for (const w of hetznerWrites()) {
      expect(w).not.toMatch(/^POST \/v1\/servers$|^DELETE \/v1\/servers|rebuild|change_type|change_dns_ptr|reset|poweroff/);
    }
  });

  const refusesBeforeAnyChange = async (o: Partial<AdoptOptions>, what: RegExp, extra: Partial<Deps> = {}): Promise<void> => {
    await expect(runAdopt(deps(new ScriptedIo(), extra), opts(o))).rejects.toThrow(what);
    expect(hetznerWrites()).toEqual([]);
    expect(box.calls).toEqual([]);
  };

  it("refuses a host key that does not match, before changing anything", async () => {
    await refusesBeforeAnyChange({ hostKey: OTHER_FP }, /not SHA256:AvIe/);
  });

  it("needs --host-key or --trust-first-use", async () => {
    await refusesBeforeAnyChange({ hostKey: undefined }, /needs the host key fingerprint/);
    expect(scanned).toEqual([]);
  });

  it("with --trust-first-use pins the ed25519 key and says so", async () => {
    const io = new ScriptedIo();
    expect(await runAdopt(deps(io), opts({ hostKey: undefined, trustFirstUse: true }))).toBe(0);
    expect(io.text()).toContain(`Pinned app1's host key ssh-ed25519 ${HOST_FP} (trusted on first use).`);
  });

  it("with a foreign firewall attached, attaches frosty's first, stops, and resumes once it is detached", async () => {
    hz.servers[0] = existingServer({ public_net: { ipv4: { ip: IP }, ipv6: null, firewalls: [{ id: 99, status: "applied" }] } });
    await expect(runAdopt(deps(new ScriptedIo()), opts())).rejects.toThrow(/1 firewall\(s\) frosty did not make \(id 99\)/);
    const net = server()["public_net"] as { firewalls: { id: number }[] };
    const ours = (hz.firewalls[0] as { id: number }).id;
    expect(net.firewalls.map((f) => f.id)).toEqual([99, ours]);
    expect(box.calls).toEqual([]);
    net.firewalls = net.firewalls.filter((f) => f.id !== 99);
    const io = new ScriptedIo();
    expect(await runAdopt(deps(io), opts({ resume: true })), io.text()).toBe(0);
  });

  it("opens the window before scanning when frosty's firewall is already attached and closed", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    rmSync(knownHostsPath(env));
    const order: string[] = [];
    http.on("POST", "api.hetzner.cloud", "/v1/firewalls/\\d+/actions/set_rules", (call) => {
      const fw = hz.firewalls[0] as Record<string, unknown>;
      fw["rules"] = (call.body as { rules: unknown[] }).rules;
      order.push((call.body as { rules: unknown[] }).rules.length > 0 ? "open" : "close");
      return { status: 201, body: { actions: [] } };
    });
    const scan = deps(new ScriptedIo()).keyScan;
    const io = new ScriptedIo();
    const code = await runAdopt(deps(io, { keyScan: async (h) => (order.push("scan"), (scan as NonNullable<typeof scan>)(h)) }), opts({ resume: true }));
    expect(code, io.text()).toBe(0);
    expect(order).toEqual(["open", "scan", "close"]);
  });

  it("refuses --host-key that differs from the key it already pinned", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    const writes = hetznerWrites().length;
    await expect(runAdopt(deps(new ScriptedIo()), opts({ hostKey: OTHER_FP, resume: true }))).rejects.toThrow(/already pinned a different host key/);
    expect(hetznerWrites()).toHaveLength(writes);
  });

  it("refuses to run again on an adopted box without --resume", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    await expect(runAdopt(deps(new ScriptedIo()), opts())).rejects.toThrow(/already adopted/);
  });

  it("refuses a second server with the same box label, and a box firewall applied elsewhere", async () => {
    hz.servers.push({ ...existingServer({ id: 8, name: "other", labels: { stayfrosty: "1", "stayfrosty-box": "app1" } }) });
    await refusesBeforeAnyChange({}, /already labeled as box app1/);
    hz.servers.pop();
    hz.firewalls.push({ id: 50, name: "stayfrosty-app1", labels: { stayfrosty: "1", "stayfrosty-box": "app1" }, rules: [], applied_to: [{ type: "label_selector" }] });
    await refusesBeforeAnyChange({}, /applied to more than app1/);
  });

  it("refuses a name that is not the server's, an unknown IP, and a box frosty new made", async () => {
    await refusesBeforeAnyChange({ box: "web1" }, /calls the server at that IP "app1"/);
    await refusesBeforeAnyChange({ ip: "192.0.2.99" }, /No server .* 192.0.2.99/);
    await refusesBeforeAnyChange({ ip: "not-an-ip" }, /not an IPv4/);
    await refusesBeforeAnyChange({ user: "root; rm" }, /not a valid user name/);
    await refusesBeforeAnyChange({ hostKey: "md5:aa" }, /not a SHA256 fingerprint/);
    hz.servers[0] = existingServer({ labels: { stayfrosty: "1", "stayfrosty-box": "app1" } });
    await refusesBeforeAnyChange({}, /created by frosty new/);
  });

  it("dry run changes nothing", async () => {
    const io = new ScriptedIo();
    expect(await runAdopt(deps(io), opts({ dryRun: true }))).toBe(0);
    expect(hetznerWrites()).toEqual([]);
    expect(box.calls).toEqual([]);
    expect(io.text()).toContain("Dry run: nothing was changed.");
  });

  it("stops before the hardening if the admin user cannot log in", async () => {
    box.on((call) => (call.target.user === "ops" && call.command === "sudo -n true" ? { code: 255, stdout: "", stderr: "denied" } : undefined));
    await expect(runAdopt(deps(new ScriptedIo()), opts())).rejects.toThrow(/cannot log in and sudo, so the hardening was not started/);
    expect(box.calls.some((c) => c.opts.stdin?.includes("stayfrosty-harden-ok") === true)).toBe(false);
  });

  it("resumes as the admin user once root is closed, without pinning or creating the user again", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    const before = box.calls.length;
    scanned = [];
    expect(await runAdopt(deps(new ScriptedIo(), { laptopIp: async () => ({ ipv4: "203.0.113.9", ipv6: undefined }) }), opts({ hostKey: undefined, resume: true }))).toBe(0);
    const again = box.calls.slice(before);
    expect(again.some((c) => c.target.user === "root" && c.command === "bash -s")).toBe(false);
    expect(scanned).toEqual([]);
    expect(hz.firewalls).toHaveLength(1);
    expect(hetznerWrites().filter((w) => w.includes("change_protection"))).toHaveLength(1);
  });

  it("verify passes on an adopted box and catches a second firewall or protection turned off", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    const writesBefore = http.writes().length;
    let io = new ScriptedIo();
    expect(await runVerify(deps(io), { box: "app1", all: false }), io.text()).toBe(0);
    expect(io.text()).toMatch(/pass\s+Box firewall is the only one attached/);
    expect(io.text()).toMatch(/pass\s+Adopted server: delete and rebuild protection on/);
    expect(http.writes().length).toBe(writesBefore);

    const net = server()["public_net"] as { firewalls: { id: number; status: string }[] };
    net.firewalls.push({ id: 555, status: "applied" });
    server()["protection"] = { delete: true, rebuild: false };
    io = new ScriptedIo();
    expect(await runVerify(deps(io), { box: undefined, all: true })).toBe(1);
    expect(io.text()).toMatch(/FAIL\s+Box firewall is the only one attached\s+other firewall\(s\) attached: id 555/);
    expect(io.text()).toMatch(/FAIL\s+Adopted server: delete and rebuild protection on\s+delete true, rebuild false/);
    await expect(runVerify(deps(new ScriptedIo()), { box: "app1", all: true })).rejects.toThrow(/one box, or pass --all/);
    await expect(runVerify(deps(new ScriptedIo()), { box: "nope", all: false })).rejects.toThrow(/no box named nope/);
  });

  it("destroy refuses a protected server even without the adopted label, before touching Cloudflare", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    const labels = server()["labels"] as Record<string, string>;
    delete labels["stayfrosty-adopted"];
    const before = http.writes().length;
    await expect(runDestroy(deps(new ScriptedIo(["app1"])), { box: "app1", dryRun: false })).rejects.toThrow(/protected server/);
    expect(http.writes()).toHaveLength(before);
  });

  it("destroy and new both refuse an adopted server", async () => {
    await runAdopt(deps(new ScriptedIo()), opts());
    await expect(runDestroy(deps(new ScriptedIo(["app1"])), { box: "app1", dryRun: false })).rejects.toThrow(/never deletes a server it did not create/);
    await expect(runNew(deps(new ScriptedIo()), { box: "app1", resume: true, dryRun: false })).rejects.toThrow(/adopted or protected server/);
    expect(hz.servers).toHaveLength(1);
  });
});
