import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runAdopt } from "../src/commands/adopt.ts";
import { runDestroy } from "../src/commands/destroy.ts";
import { runDetachForeign } from "../src/commands/detach-foreign.ts";
import { runLs } from "../src/commands/ls.ts";
import { runNew } from "../src/commands/new.ts";
import { runVerify } from "../src/commands/verify.ts";
import { saveConfig, validateConfig, type Config } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { DigitalOcean, OUTBOUND_RULES, frostyFirewallBox, labelsToTags, tagsToLabels } from "../src/digitalocean.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { DO, FakeDigitalOcean } from "./fake-digitalocean.ts";
import { FakeHetzner } from "./fake-hetzner.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { FakeBox } from "./fake-ssh.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const DO_TOKEN = "do-token-0123456789abcdef";

const doConfig: Config = {
  ...sampleConfig,
  boxProviders: { mon1: "digitalocean" },
  digitalocean: { region: "fra1", size: "s-1vcpu-512mb-10gb", image: "ubuntu-24-04-x64" },
};

describe("DigitalOcean boxes", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let dig: FakeDigitalOcean;
  let hz: FakeHetzner;
  let cf: FakeCloudflare;
  let box: FakeBox;

  const deps = (io: ScriptedIo, extra: Partial<Deps> = {}): Deps => ({
    io,
    env,
    fetch: http.fetch,
    sleep: noSleep,
    now: () => 1_790_000_000_000,
    ssh: box.run,
    closeSsh: async () => {},
    forgetHost: async () => {},
    userSsh: async () => ({ code: 0, stdout: "", stderr: "" }),
    hasAccessToken: async () => true,
    authoritativeResolves: async () => true,
    systemResolves: async () => true,
    cloudflaredPath: "/opt/homebrew/bin/cloudflared",
    laptopIp: async () => ({ ipv4: "198.51.100.7", ipv6: undefined }),
    isTty: true,
    ...extra,
  });

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-do-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789", DIGITALOCEAN_TOKEN: DO_TOKEN };
    await saveConfig(doConfig, env);
    http = new FakeHttp();
    hz = new FakeHetzner(http);
    dig = new FakeDigitalOcean(http);
    cf = new FakeCloudflare(http);
    box = new FakeBox();
    for (const name of ["mon1", "web1"]) {
      http.on("GET", `ssh-${name}.example.com`, "/", { status: 302, headers: { location: `https://team.cloudflareaccess.com/cdn-cgi/access/login/ssh-${name}.example.com?kid=abc&redirect_url=%2F` } });
    }
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  const doWrites = (): string[] => http.writes().filter((c) => c.url.host === DO).map((c) => `${c.method} ${c.url.pathname}`);
  const hzWrites = (): string[] => http.writes().filter((c) => c.url.host === "api.hetzner.cloud").map((c) => `${c.method} ${c.url.pathname}`);
  const body = (method: string, path: string): Record<string, unknown> => http.writes().find((c) => c.url.host === DO && c.method === method && c.url.pathname === path)?.body as Record<string, unknown>;

  it("new makes a tagged droplet behind frosty's firewall, opens the window for this laptop only, then closes it", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "mon1", resume: false, dryRun: false }), io.text()).toBe(0);

    const fw = dig.firewalls[0] as { id: string; inbound_rules: unknown[]; droplet_ids: number[]; tags: string[] };
    const droplet = dig.droplets[0] as { id: number };
    expect(doWrites()).toEqual([
      "POST /v2/account/keys",
      "POST /v2/tags",
      "POST /v2/firewalls",
      "POST /v2/droplets",
      `POST /v2/firewalls/${fw.id}/droplets`,
      `DELETE /v2/firewalls/${fw.id}/rules`,
    ]);
    expect(hzWrites()).toEqual([]);
    expect(body("POST", "/v2/tags")).toEqual({ name: "stayfrosty-box:mon1" });
    expect(body("POST", "/v2/firewalls")).toEqual({
      name: "stayfrosty-mon1",
      inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.7/32"] } }],
      outbound_rules: OUTBOUND_RULES,
      tags: ["stayfrosty-box:mon1"],
      droplet_ids: [],
    });
    const create = body("POST", "/v2/droplets");
    expect(create).toMatchObject({
      name: "mon1",
      region: "fra1",
      size: "s-1vcpu-512mb-10gb",
      image: "ubuntu-24-04-x64",
      ssh_keys: [(dig.sshKeys[0] as { id: number }).id],
      tags: ["stayfrosty:1", "stayfrosty-box:mon1"],
      ipv6: true,
      monitoring: false,
      with_droplet_agent: false,
      backups: false,
    });
    expect(create["user_data"]).toContain(PUBLIC_KEY);
    expect(body("POST", `/v2/firewalls/${fw.id}/droplets`)).toEqual({ droplet_ids: [droplet.id] });
    // The window is closed, the firewall still applies by tag and by id, outbound stays open.
    expect(fw.inbound_rules).toEqual([]);
    expect(fw.droplet_ids).toEqual([droplet.id]);
    expect(fw.tags).toEqual(["stayfrosty-box:mon1"]);
    expect(io.text()).toContain("DigitalOcean firewall stayfrosty-mon1: create");
    expect(io.text()).toContain("DigitalOcean Recovery Console only");
    expect(io.text()).toContain("Box mon1 is ready.");
    expect(io.text()).not.toContain(DO_TOKEN);
    expect(http.calls.filter((c) => c.url.host === DO).every((c) => c.authorization === `Bearer ${DO_TOKEN}`)).toBe(true);
    // ssh config has the box.
    expect(readFileSync(join(home, ".ssh", "stayfrosty.conf"), "utf8")).toContain("Host mon1");
  });

  it("new waits until DigitalOcean reports the firewall applied before it connects to the droplet", async () => {
    let polls = 0;
    http.on("GET", DO, "/v2/firewalls", () => {
      if (dig.droplets.length > 0) {
        polls++;
      }
      const pending = dig.droplets.length > 0 && polls < 3;
      return { body: { firewalls: dig.firewalls.map((f) => ({ ...f, status: pending ? "waiting" : "succeeded", pending_changes: pending ? dig.droplets.map((d) => ({ droplet_id: d["id"], removing: false, status: "waiting" })) : [] })), links: {} } };
    });
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "mon1", resume: false, dryRun: false }), io.text()).toBe(0);
    const firstSsh = io.stdout.findIndex((l) => l.startsWith("Waiting for SSH"));
    const waited = io.stdout.findIndex((l) => l.startsWith("Waiting for DigitalOcean to apply firewall stayfrosty-mon1 (pending)"));
    expect(waited).toBeGreaterThan(-1);
    expect(waited).toBeLessThan(firstSsh);
  });

  it("a Hetzner box in the same config never writes to DigitalOcean, and ssh config lists both", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    const before = doWrites().length;
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "web1", resume: false, dryRun: false }), io.text()).toBe(0);
    expect(doWrites().length).toBe(before);
    expect(hz.servers).toHaveLength(1);
    const conf = readFileSync(join(home, ".ssh", "stayfrosty.conf"), "utf8");
    expect(conf).toContain("Host mon1");
    expect(conf).toContain("Host web1");
  });

  it("needs DIGITALOCEAN_TOKEN once the config has a digitalocean section", async () => {
    delete env["DIGITALOCEAN_TOKEN"];
    await expect(runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: true })).rejects.toThrow(/Missing DIGITALOCEAN_TOKEN/);
    expect(http.calls).toEqual([]);
  });

  it("refuses a firewall named like frosty's that does not have frosty's shape", async () => {
    dig.firewalls.push({ id: "00000000-0000-4000-8000-000000000001", name: "stayfrosty-mon1", status: "succeeded", inbound_rules: [], outbound_rules: [], droplet_ids: [], tags: [] });
    const io = new ScriptedIo();
    await expect(runNew(deps(io), { box: "mon1", resume: false, dryRun: false })).rejects.toThrow(/A firewall named stayfrosty-mon1 already exists, and frosty did not create it/);
    expect(doWrites()).toEqual([]);
  });

  it("verify passes on a fresh box and fails when another firewall applies to it by tag", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    expect(await runVerify(deps(new ScriptedIo()), { box: "mon1", all: false })).toBe(0);
    dig.firewalls.push({ id: "00000000-0000-4000-8000-000000000009", name: "web", status: "succeeded", inbound_rules: [{ protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0"] } }], outbound_rules: [], droplet_ids: [], tags: ["stayfrosty:1"] });
    const io = new ScriptedIo();
    expect(await runVerify(deps(io), { box: "mon1", all: false })).toBe(1);
    expect(io.text()).toContain("other firewall(s) attached: id 00000000-0000-4000-8000-000000000009");
    expect(io.text()).toContain("Detach the others in the DigitalOcean control panel");
  });

  it("verify --all checks boxes on both providers", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    await runNew(deps(new ScriptedIo()), { box: "web1", resume: false, dryRun: false });
    const io = new ScriptedIo();
    expect(await runVerify(deps(io), { box: undefined, all: true }), io.text()).toBe(0);
    expect(io.text()).toContain("All checks passed on 2 box(es).");
  });

  it("ls lists boxes from both providers and leftovers by provider", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    await runNew(deps(new ScriptedIo()), { box: "web1", resume: false, dryRun: false });
    // DigitalOcean takes a deleted droplet off its firewalls.
    dig.droplets = [];
    (dig.firewalls[0] as { droplet_ids: number[] }).droplet_ids = [];
    const io = new ScriptedIo();
    expect(await runLs({ io, env, fetch: http.fetch, sleep: noSleep })).toBe(0);
    expect(io.text()).toMatch(/web1 +running +cx23 +fsn1/);
    expect(io.text()).toContain("DigitalOcean firewall stayfrosty-mon1");
  });

  it("destroy deletes the droplet, waits for it to go, then the firewall, and keeps away from adopted droplets", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    const fw = dig.firewalls[0] as { id: string };
    const droplet = dig.droplets[0] as { id: number; tags: string[] };
    const before = doWrites().length;
    expect(await runDestroy(deps(new ScriptedIo(["mon1"])), { box: "mon1", dryRun: false })).toBe(0);
    expect(doWrites().slice(before)).toEqual([`DELETE /v2/droplets/${droplet.id}`, `DELETE /v2/firewalls/${fw.id}`]);
    expect(dig.droplets).toEqual([]);
    expect(dig.firewalls).toEqual([]);

    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    (dig.droplets[0] as { tags: string[] }).tags.push("stayfrosty-adopted:1700000000");
    const io = new ScriptedIo(["mon1"]);
    await expect(runDestroy(deps(io), { box: "mon1", dryRun: false })).rejects.toThrow(/frosty never deletes a server it did not create/);
    expect(dig.droplets).toHaveLength(1);
  });

  it("destroy never strips the firewall from a droplet whose tags were removed by hand", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    (dig.droplets[0] as { tags: string[] }).tags = [];
    await runDestroy(deps(new ScriptedIo(["mon1"])), { box: "mon1", dryRun: false }).catch(() => 1);
    expect(dig.firewalls).toHaveLength(1);
    expect(doWrites().filter((w) => w.startsWith("DELETE /v2/firewalls/") && !w.endsWith("/rules"))).toEqual([]);
    // And the client refuses outright while any droplet is still covered.
    const client = new DigitalOcean({ token: DO_TOKEN, fetch: http.fetch, sleep: noSleep });
    (dig.droplets[0] as { tags: string[] }).tags = ["stayfrosty:1", "stayfrosty-box:mon1"];
    await expect(client.deleteFirewall((dig.firewalls[0] as { id: string }).id)).rejects.toThrow(/still covers droplet/);
  });

  it("--resume attaches the firewall by droplet id when only the tag holds it", async () => {
    await runNew(deps(new ScriptedIo()), { box: "mon1", resume: false, dryRun: false });
    const fw = dig.firewalls[0] as { id: string; droplet_ids: number[]; inbound_rules: unknown[] };
    const droplet = dig.droplets[0] as { id: number };
    fw.droplet_ids = [];
    const before = doWrites().length;
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "mon1", resume: true, dryRun: false }), io.text()).toBe(0);
    expect(doWrites().slice(before)).toContain(`POST /v2/firewalls/${fw.id}/droplets`);
    expect(fw.droplet_ids).toEqual([droplet.id]);
  });

  it("adopt and detach-foreign refuse DigitalOcean boxes before any call", async () => {
    await expect(runAdopt(deps(new ScriptedIo()), { box: "mon1", ip: "203.0.113.40", user: "root", hostKey: undefined, trustFirstUse: true, resume: false, dryRun: false })).rejects.toThrow(
      /frosty adopt works on Hetzner servers only/,
    );
    await expect(runDetachForeign(deps(new ScriptedIo()), { box: "mon1", dryRun: false })).rejects.toThrow(/works on adopted Hetzner boxes only/);
    expect(http.calls).toEqual([]);
  });
});

describe("DigitalOcean client guards", () => {
  const FW = "00000000-0000-4000-8000-000000000042";
  const ours = () => ({ id: FW, name: "stayfrosty-mon1", status: "succeeded", inbound_rules: [], outbound_rules: OUTBOUND_RULES, droplet_ids: [], tags: ["stayfrosty-box:mon1"] });
  const setup = () => {
    const http = new FakeHttp();
    const fake = new FakeDigitalOcean(http);
    const client = new DigitalOcean({ token: DO_TOKEN, fetch: http.fetch, sleep: noSleep });
    return { http, fake, client };
  };
  const window = (cidr: string) => ({ direction: "in" as const, protocol: "tcp", port: "22", source_ips: [cidr], description: "stayfrosty window" });

  it("maps labels to tags and back", () => {
    expect(labelsToTags({ stayfrosty: "1", "stayfrosty-box": "mon1" })).toEqual(["stayfrosty:1", "stayfrosty-box:mon1"]);
    expect(tagsToLabels(["stayfrosty:1", "stayfrosty-box:mon1", "plain"])).toEqual({ stayfrosty: "1", "stayfrosty-box": "mon1" });
    expect(() => labelsToTags({ a: "b c" })).toThrow(/refused/);
  });

  it("knows its firewall only by its whole shape", () => {
    expect(frostyFirewallBox(ours(), new Map())).toBe("mon1");
    // A firewall made by hand with the control panel's default outbound rules and no tag is not frosty's.
    expect(frostyFirewallBox({ ...ours(), tags: [] }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), inbound_rules: [{ protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0", "::/0"] } }] }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.7"] } }] }, new Map())).toBe("mon1");
    expect(frostyFirewallBox({ ...ours(), tags: ["stayfrosty:1"] }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), tags: ["stayfrosty-box:other"] }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), outbound_rules: OUTBOUND_RULES.slice(0, 2) }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), name: "stayfrosty-Mon1" }, new Map())).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), name: "web" }, new Map())).toBeUndefined();
    // Every droplet attached by id must be tagged as the box; a missing one counts as a stranger.
    expect(frostyFirewallBox({ ...ours(), droplet_ids: [7] }, new Map([[7, ["stayfrosty:1", "stayfrosty-box:mon1"]]]))).toBe("mon1");
    expect(frostyFirewallBox({ ...ours(), droplet_ids: [7, 8] }, new Map([[7, ["stayfrosty:1", "stayfrosty-box:mon1"]], [8, ["db"]]]))).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), droplet_ids: [7] }, new Map([[7, ["stayfrosty-box:mon1"]]]))).toBeUndefined();
    expect(frostyFirewallBox({ ...ours(), droplet_ids: [9] }, new Map())).toBeUndefined();
    // DigitalOcean may say "all" or leave out ports and prefix lengths; the same rules either way.
    expect(frostyFirewallBox({ ...ours(), outbound_rules: [{ protocol: "icmp", ports: "0", destinations: { addresses: ["::/0", "0.0.0.0/0"] } }, ...OUTBOUND_RULES.slice(0, 2).map((r) => ({ ...r, ports: "all" }))] }, new Map())).toBe("mon1");
  });

  it("sets only inbound window rules, new before old, and never on a firewall that isn't frosty's", async () => {
    const { http, fake, client } = setup();
    fake.firewalls.push({ ...ours(), inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.7/32"] } }] });
    await client.setFirewallRules(FW, [window("198.51.100.8/32")]);
    expect(http.writes().map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`POST /v2/firewalls/${FW}/rules`, `DELETE /v2/firewalls/${FW}/rules`]);
    expect((fake.firewalls[0] as { inbound_rules: unknown[] }).inbound_rules).toEqual([{ protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.8/32"] } }]);
    await expect(client.setFirewallRules(FW, [{ ...window("0.0.0.0/0") }])).rejects.toThrow(/only ever sets none, or TCP 22 from one address/);
    fake.droplets.push({ id: 31, name: "db", status: "active", created_at: "2026-01-01T00:00:00Z", tags: ["db"], size_slug: "s", region: { slug: "fra1" } });
    (fake.firewalls[0] as { droplet_ids: number[] }).droplet_ids = [31];
    await expect(client.setFirewallRules(FW, [])).rejects.toThrow(/doesn't have the shape of frosty's/);
    (fake.firewalls[0] as { droplet_ids: number[] }).droplet_ids = [];
    (fake.firewalls[0] as { tags: string[] }).tags = ["stayfrosty:1"];
    await expect(client.setFirewallRules(FW, [])).rejects.toThrow(/doesn't have the shape of frosty's/);
    await expect(client.deleteFirewall(FW)).rejects.toThrow(/doesn't have the shape of frosty's/);
    expect(http.writes()).toHaveLength(2);
  });

  it("creates only a box's own firewall and droplet, and deletes only frosty's droplets", async () => {
    const { http, fake, client } = setup();
    await expect(client.createFirewall("web", { stayfrosty: "1", "stayfrosty-box": "mon1" }, [])).rejects.toThrow(/refused to create firewall/);
    await expect(client.createFirewall("stayfrosty-mon1", { stayfrosty: "1", "stayfrosty-box": "mon1" }, [{ ...window("198.51.100.7/32"), port: "443" }])).rejects.toThrow(/only ever sets/);
    fake.firewalls.push(ours(), { ...ours(), id: "00000000-0000-4000-8000-000000000043", name: "stayfrosty-other", tags: ["stayfrosty-box:other"] });
    const spec = { name: "mon1", serverType: "s", image: "i", location: "fra1", sshKeyIds: [1], userData: "#cloud-config", labels: { stayfrosty: "1", "stayfrosty-box": "mon1" }, firewallIds: [FW] };
    await expect(client.createServer({ ...spec, name: "other" })).rejects.toThrow(/refused to create droplet/);
    await expect(client.createServer({ ...spec, labels: { ...spec.labels, extra: "1" } })).rejects.toThrow(/refused to create droplet/);
    await expect(client.createServer({ ...spec, firewallIds: [] })).rejects.toThrow(/refused to create droplet/);
    await expect(client.createServer({ ...spec, firewallIds: ["00000000-0000-4000-8000-000000000043"] })).rejects.toThrow(/belongs to another box/);
    expect(http.writes()).toEqual([]);
    fake.droplets.push({ id: 9, name: "db", status: "active", created_at: "2026-01-01T00:00:00Z", tags: [], size_slug: "s", region: { slug: "fra1" } });
    await expect(client.deleteServer(9)).rejects.toThrow(/refused to delete db/);
    expect(http.writes()).toEqual([]);
    expect(() => client.protectServer()).toThrow(/no delete or rebuild protection/);
  });

  it("explains a missing scope", async () => {
    const http = new FakeHttp().on("GET", DO, "/v2/firewalls", { status: 403, body: { id: "Forbidden", message: "You are not authorized to perform this operation" } });
    const client = new DigitalOcean({ token: DO_TOKEN, fetch: http.fetch, sleep: noSleep });
    await expect(client.listFirewalls()).rejects.toMatchObject({ hint: expect.stringContaining("missing a scope") });
  });
});

describe("config for DigitalOcean", () => {
  it("accepts a digitalocean section and boxProviders", () => {
    expect(validateConfig(doConfig)).toEqual([]);
  });

  it("needs the digitalocean section when a box uses it, and checks its values", () => {
    expect(validateConfig({ ...sampleConfig, boxProviders: { mon1: "digitalocean" } })).toEqual([expect.stringContaining("needs a digitalocean section")]);
    expect(validateConfig({ ...sampleConfig, boxProviders: { mon1: "aws" } })).toEqual([expect.stringContaining("boxProviders.mon1")]);
    expect(validateConfig({ ...doConfig, digitalocean: { region: "FRA 1", size: "s", image: "i" } })).toEqual([expect.stringContaining("digitalocean.region")]);
    expect(validateConfig({ ...doConfig, digitalocean: { region: "fra1", size: "s", image: "i", monitoring: true } })).toEqual([expect.stringContaining("unknown setting(s): monitoring")]);
    expect(validateConfig({ ...doConfig, digitaloceanChangeLog: "relative.log" })).toEqual(["digitaloceanChangeLog must be an absolute path"]);
  });
});
