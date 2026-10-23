import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fileChangeLog } from "../src/changelog.ts";
import { Cloudflare } from "../src/cloudflare.ts";
import { Hetzner } from "../src/hetzner.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHetzner } from "./fake-hetzner.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";

describe("client guards", () => {
  let http: FakeHttp;
  let hz: FakeHetzner;
  let dir: string;

  beforeEach(() => {
    http = new FakeHttp();
    hz = new FakeHetzner(http);
    new FakeCloudflare(http);
    dir = mkdtempSync(join(tmpdir(), "frosty-guards-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const cf = (log?: string): Cloudflare => new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep, changeLog: log === undefined ? undefined : fileChangeLog(log) });
  const hetzner = (): Hetzner => new Hetzner({ token: "hz-token-0123456789", fetch: http.fetch, sleep: noSleep });

  it("Cloudflare: never touches a tunnel, app, policy or alert without frosty's prefix", async () => {
    const c = cf();
    const foreign = { id: "x", name: "other-tunnel" };
    await expect(c.createTunnel("acc", "other-tunnel")).rejects.toThrow(/only touches names starting with stayfrosty-/);
    await expect(c.createTunnel("acc", "stayfrosty-")).rejects.toThrow(/only touches/);
    await expect(c.deleteTunnel("acc", foreign)).rejects.toThrow(/only touches/);
    await expect(c.putTunnelIngress("acc", foreign, [])).rejects.toThrow(/only touches/);
    await expect(c.deleteAccessApp("acc", { id: "a", name: "*.example.com" })).rejects.toThrow(/only touches/);
    await expect(c.createAccessApp("acc", { name: "ssh-bigbox" })).rejects.toThrow(/only touches/);
    await expect(c.deleteAccessPolicy("acc", { id: "p", name: "gh-policy" })).rejects.toThrow(/only touches/);
    await expect(c.createNotificationPolicy("acc", { name: "other" })).rejects.toThrow(/only touches/);
    await expect(c.deleteNotificationPolicy("acc", { id: "n", name: "other" })).rejects.toThrow(/only touches/);
    expect(http.writes()).toEqual([]);
  });

  it("Cloudflare: Access policies are allow, plain email rules only", async () => {
    const c = cf();
    const make = (p: Record<string, unknown>) => c.createAccessPolicy("acc", { name: "stayfrosty-x", decision: "allow", include: [{ email: { email: "a@b.co" } }], ...p } as never);
    await expect(make({ decision: "bypass" })).rejects.toThrow(/plain email rules/);
    await expect(make({ include: [{ everyone: {} }] })).rejects.toThrow(/plain email rules/);
    await expect(make({ include: [{ "github-organization": { name: "example-org" } }] })).rejects.toThrow(/plain email rules/);
    await expect(make({ include: [{ email: { email: "a@b.co" }, ip: { ip: "0.0.0.0/0" } }] })).rejects.toThrow(/plain email rules/);
    await expect(make({ include: [] })).rejects.toThrow(/plain email rules/);
    await expect(make({ require: [{ email: { email: "a@b.co" } }] })).rejects.toThrow(/plain email rules/);
    expect(http.writes()).toEqual([]);
    await expect(make({})).resolves.toBeDefined();
  });

  it("Cloudflare: DNS writes only for frosty's commented, proxied CNAMEs", async () => {
    const c = cf();
    await expect(c.createDnsRecord("z", { type: "A", name: "ssh-x.example.com", content: "192.0.2.1", proxied: false, comment: "stayfrosty box x" })).rejects.toThrow(/only creates proxied CNAMEs/);
    await expect(c.createDnsRecord("z", { type: "CNAME", name: "x", content: "y", proxied: true, comment: "mine" })).rejects.toThrow(/only creates proxied CNAMEs/);
    await expect(c.deleteDnsRecord("z", { id: "r", name: "sshother.example.com", comment: null })).rejects.toThrow(/not commented/);
    expect(http.writes()).toEqual([]);
  });

  it("Hetzner: never deletes an adopted or protected server, never drops the adopted label", async () => {
    hz.servers.push(
      { id: 1, name: "a", labels: { "stayfrosty-adopted": "1" }, public_net: { ipv4: null, ipv6: null, firewalls: [] } },
      { id: 2, name: "b", labels: {}, protection: { delete: true, rebuild: false }, public_net: { ipv4: null, ipv6: null, firewalls: [] } },
      { id: 3, name: "c", labels: {}, protection: { delete: false, rebuild: true }, public_net: { ipv4: null, ipv6: null, firewalls: [] } },
    );
    const h = hetzner();
    for (const id of [1, 2, 3]) {
      await expect(h.deleteServer(id)).rejects.toThrow(/refused to delete/);
    }
    await expect(h.updateServerLabels(1, {})).rejects.toThrow(/refused to change the adopted label/);
    await expect(h.updateServerLabels(1, { "stayfrosty-adopted": "2" })).rejects.toThrow(/refused to change the adopted label/);
    expect(http.writes()).toEqual([]);
    await expect(h.updateServerLabels(1, { "stayfrosty-adopted": "1", x: "y" })).resolves.toBeDefined();
  });

  it("change log: an intent line before each write, a done line after, ids only, no secrets", async () => {
    const log = join(dir, "cf.log");
    await cf(log).createTunnel("acc", "stayfrosty-t1");
    const lines = readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.map((l) => l["phase"])).toEqual(["intent", "done"]);
    expect(lines[0]?.["action"]).toBe("cloudflare POST");
    expect(lines[0]?.["request"]).toEqual({ name: "stayfrosty-t1", config_src: "cloudflare" });
    expect(Object.keys(lines[1]?.["result"] as object).sort()).toEqual(["ids", "status"]);
    expect(readFileSync(log, "utf8")).not.toContain("cf-token-0123456789");
  });

  it("change log: if the intent line cannot be written, nothing is sent", async () => {
    await expect(cf(join(dir, "missing", "\0bad")).createTunnel("acc", "stayfrosty-t1")).rejects.toThrow(/Nothing was sent/);
    expect(http.writes()).toEqual([]);
  });
});
