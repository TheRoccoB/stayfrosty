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
  let fcf: FakeCloudflare;
  let dir: string;

  beforeEach(() => {
    http = new FakeHttp();
    hz = new FakeHetzner(http);
    fcf = new FakeCloudflare(http);
    dir = mkdtempSync(join(tmpdir(), "frosty-guards-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const cf = (log?: string): Cloudflare => new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep, changeLog: log === undefined ? undefined : fileChangeLog(log) });
  const hetzner = (): Hetzner => new Hetzner({ token: "hz-token-0123456789", fetch: http.fetch, sleep: noSleep });

  const seedForeign = (): void => {
    fcf.tunnels.push({ id: "11111111-1111-4111-8111-111111111111", name: "other-tunnel", status: "healthy" });
    fcf.apps.push({ id: "app-wild", name: "example ssh", domain: "*.example.com", type: "self_hosted", policies: [{ id: "pol-gh", precedence: 1 }] });
    fcf.policies.push({ id: "pol-gh", name: "gh-policy", decision: "allow", include: [{ email: { email: "a@b.co" } }, { "github-organization": { name: "example-org" } }] });
    fcf.policies.push({ id: "pol-bad", name: "stayfrosty-x", decision: "bypass", include: [{ everyone: {} }] });
    fcf.policies.push({ id: "pol-ok", name: "stayfrosty-x", decision: "allow", include: [{ email: { email: "a@b.co" } }] });
    fcf.alerts.push({ id: "al-1", name: "other alert" });
    fcf.dns.push({ id: "dns-1", name: "sshother.example.com", type: "CNAME", content: "x.cfargotunnel.com", proxied: true, comment: null });
  };

  it("Cloudflare: deletes and changes check the live object's name, not the caller's", async () => {
    seedForeign();
    const c = cf();
    // A frosty-looking name paired with a foreign id must not get through.
    await expect(c.deleteTunnel("acc", { id: "11111111-1111-4111-8111-111111111111", name: "stayfrosty-x" })).rejects.toThrow(/"other-tunnel"/);
    await expect(c.putTunnelIngress("acc", { id: "11111111-1111-4111-8111-111111111111", name: "stayfrosty-x" }, { sshHostname: "ssh-x.example.com", teamName: "team", appZones: [], routes: [] })).rejects.toThrow(/"other-tunnel"/);
    await expect(c.deleteAccessApp("acc", { id: "app-wild", name: "stayfrosty-x" })).rejects.toThrow(/"example ssh"/);
    await expect(c.deleteAccessPolicy("acc", { id: "pol-gh", name: "stayfrosty-x" })).rejects.toThrow(/"gh-policy"/);
    await expect(c.deleteNotificationPolicy("acc", { id: "al-1", name: "stayfrosty-x" })).rejects.toThrow(/"other alert"/);
    await expect(c.deleteDnsRecord("z", { id: "dns-1", name: "x", comment: "stayfrosty box x" })).rejects.toThrow(/not commented/);
    await expect(c.createTunnel("acc", "other-tunnel")).rejects.toThrow(/only touches names starting with stayfrosty-/);
    await expect(c.createTunnel("acc", "stayfrosty-")).rejects.toThrow(/only touches/);
    expect(http.writes()).toEqual([]);
  });

  it("Cloudflare: tunnel ingress is only the box's SSH hostname, its validated routes and 404s", async () => {
    const c = cf();
    const t = await c.createTunnel("acc", "stayfrosty-app1");
    const spec = { sshHostname: "ssh-app1.example.com", teamName: "team", appZones: ["example.net"], routes: [] };
    for (const host of ["*.example.com", "ssh-other.example.com", "app1.example.com"]) {
      await expect(c.putTunnelIngress("acc", t, { ...spec, sshHostname: host })).rejects.toThrow(/refused to set ingress/);
    }
    expect(await c.putTunnelIngress("acc", t, spec)).toEqual([{ hostname: "ssh-app1.example.com", service: "ssh://localhost:22" }, { service: "http_status:404" }]);
    expect(fcf.ingress.get(t.id)).toEqual([{ hostname: "ssh-app1.example.com", service: "ssh://localhost:22" }, { service: "http_status:404" }]);
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
    await expect(make({ name: "gh-policy" })).rejects.toThrow(/plain email rules/);
    expect(http.writes()).toEqual([]);
    await expect(make({})).resolves.toBeDefined();
  });

  it("Cloudflare: an Access app is self-hosted, for exactly ssh-<box>, with only frosty's email policies", async () => {
    seedForeign();
    const c = cf();
    const app = { name: "stayfrosty-x", type: "self_hosted", domain: "ssh-x.example.com", session_duration: "24h", app_launcher_visible: false, policies: [{ id: "pol-ok", precedence: 1 }] };
    const make = (p: Record<string, unknown>) => c.createAccessApp("acc", { ...app, ...p } as never);
    await expect(make({ policies: [{ decision: "bypass", include: [{ everyone: {} }] }] })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ policies: [{ id: "pol-ok", precedence: 1, decision: "bypass" }] })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ domain: "*.example.com" })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ domain: "ssh-other.example.com" })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ destinations: [{ uri: "sshother.example.com" }] })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ self_hosted_domains: ["sshother.example.com"] })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ type: "infrastructure" })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ policies: [] })).rejects.toThrow(/only creates a self-hosted app/);
    await expect(make({ policies: [{ id: "pol-gh", precedence: 1 }] })).rejects.toThrow(/refused to attach Access policy gh-policy/);
    await expect(make({ policies: [{ id: "pol-bad", precedence: 1 }] })).rejects.toThrow(/refused to attach Access policy stayfrosty-x/);
    expect(http.writes()).toEqual([]);
    await expect(make({})).resolves.toBeDefined();
  });

  it("Cloudflare: notifications only email one address", async () => {
    const c = cf();
    const alert = { name: "stayfrosty-x", description: "d", alert_type: "tunnel_health_event", enabled: true, mechanisms: { email: [{ id: "me@example.com" }] }, filters: { tunnel_id: ["t"] } };
    await expect(c.createNotificationPolicy("acc", { ...alert, mechanisms: { email: [{ id: "me@example.com" }], webhooks: [{ id: "w" }] } } as never)).rejects.toThrow(/only sends email/);
    await expect(c.createNotificationPolicy("acc", { ...alert, mechanisms: { email: [{ id: "a@b.co" }, { id: "c@d.co" }] } })).rejects.toThrow(/only sends email/);
    await expect(c.createNotificationPolicy("acc", { ...alert, name: "other" })).rejects.toThrow(/only touches/);
    expect(http.writes()).toEqual([]);
  });

  it("Cloudflare: DNS writes only for frosty's commented, proxied CNAMEs to a tunnel", async () => {
    seedForeign();
    const c = cf();
    const rec = { type: "CNAME", name: "ssh-x.example.com", content: "00000000-0000-4000-8000-000000000001.cfargotunnel.com", proxied: true, comment: "stayfrosty box x" };
    for (const bad of [{ type: "A", content: "192.0.2.1" }, { proxied: false }, { comment: "mine" }, { name: "example.com" }, { name: "*.example.com" }, { name: "ssh-y.example.com" }, { content: "evil.example.net" }]) {
      await expect(c.createDnsRecord("z", { ...rec, ...bad })).rejects.toThrow(/only creates proxied CNAMEs/);
    }
    await expect(c.deleteDnsRecord("z", { id: "dns-1", name: "sshother.example.com", comment: null })).rejects.toThrow(/not commented/);
    expect(http.writes()).toEqual([]);
    await expect(c.createDnsRecord("z", rec)).resolves.toBeDefined();
  });

  it("Hetzner: firewall writes only touch frosty's own firewall, with only window rules", async () => {
    hz.firewalls.push(
      { id: 60, name: "web", labels: {}, rules: [], applied_to: [] },
      { id: 61, name: "stayfrosty-app1", labels: { stayfrosty: "1", "stayfrosty-box": "app1" }, rules: [], applied_to: [] },
    );
    hz.servers.push(
      { id: 1, name: "app1", labels: { stayfrosty: "1", "stayfrosty-box": "app1" }, public_net: { ipv4: null, ipv6: null, firewalls: [] } },
      { id: 2, name: "web1", labels: {}, public_net: { ipv4: null, ipv6: null, firewalls: [] } },
    );
    const h = hetzner();
    const win = { direction: "in" as const, protocol: "tcp", port: "22", source_ips: ["198.51.100.7/32"], description: "stayfrosty window" };
    await expect(h.setFirewallRules(60, [])).rejects.toThrow(/frosty did not create it/);
    await expect(h.updateFirewallLabels(60, { stayfrosty: "1", "stayfrosty-box": "web" })).rejects.toThrow(/frosty did not create it/);
    await expect(h.deleteFirewall(60)).rejects.toThrow(/frosty did not create it/);
    await expect(h.applyFirewall(60, 1)).rejects.toThrow(/frosty did not create it/);
    await expect(h.applyFirewall(61, 2)).rejects.toThrow(/that server is not box app1/);
    for (const bad of [
      [{ ...win, source_ips: ["0.0.0.0/0"] }],
      [{ ...win, source_ips: ["198.51.100.0/24"] }],
      [{ ...win, port: "80" }],
      [{ ...win, port: "any" }],
      [{ ...win, description: "mine" }],
      [{ ...win, source_ips: ["198.51.100.7/32", "203.0.113.1/32"] }],
      [win, win, win],
    ]) {
      await expect(h.setFirewallRules(61, bad)).rejects.toThrow(/only ever sets none, or TCP 22 from one address/);
    }
    await expect(h.updateFirewallLabels(61, { stayfrosty: "1", "stayfrosty-box": "web1" })).rejects.toThrow(/keeps frosty's labels/);
    await expect(h.createFirewall("web", { stayfrosty: "1", "stayfrosty-box": "web1" }, [])).rejects.toThrow(/only creates stayfrosty-<box>/);
    expect(http.writes()).toEqual([]);
    await expect(h.setFirewallRules(61, [win])).resolves.toBeDefined();
    await expect(h.applyFirewall(61, 1)).resolves.toBeDefined();
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

  it("Hetzner: detaching a foreign firewall needs frosty's own attached and applied, and never detaches frosty's", async () => {
    const box = { stayfrosty: "1", "stayfrosty-box": "app1" };
    hz.firewalls.push(
      { id: 70, name: "stayfrosty-app1", labels: box, rules: [], applied_to: [{ type: "server", server: { id: 1 } }] },
      { id: 71, name: "ssh-only", labels: {}, rules: [], applied_to: [{ type: "server", server: { id: 1 } }, { type: "server", server: { id: 3 } }] },
      { id: 72, name: "by-label", labels: {}, rules: [], applied_to: [{ type: "label_selector" }] },
    );
    hz.servers.push(
      { id: 1, name: "app1", labels: box, public_net: { ipv4: null, ipv6: null, firewalls: [{ id: 70, status: "applied" }, { id: 71, status: "applied" }, { id: 72, status: "applied" }] } },
      { id: 2, name: "pending", labels: { stayfrosty: "1", "stayfrosty-box": "pending" }, public_net: { ipv4: null, ipv6: null, firewalls: [{ id: 71, status: "applied" }] } },
      { id: 3, name: "web1", labels: {}, public_net: { ipv4: null, ipv6: null, firewalls: [{ id: 71, status: "applied" }] } },
    );
    const h = hetzner();
    // Right name, wrong labels: not frosty's, so nothing is detached.
    (hz.firewalls[0] as { labels: Record<string, string> }).labels = { stayfrosty: "1", "stayfrosty-box": "other" };
    await expect(h.detachForeignFirewall(71, 1)).rejects.toThrow(/stayfrosty-app1 is not attached and applied/);
    (hz.firewalls[0] as { labels: Record<string, string> }).labels = box;
    await expect(h.detachForeignFirewall(70, 1)).rejects.toThrow(/that is frosty's own firewall/);
    await expect(h.detachForeignFirewall(72, 1)).rejects.toThrow(/label selector/);
    await expect(h.detachForeignFirewall(71, 3)).rejects.toThrow(/not a frosty box/);
    await expect(h.detachForeignFirewall(71, 2)).rejects.toThrow(/stayfrosty-pending is not attached and applied/);
    (hz.servers[0] as { public_net: { firewalls: { id: number; status: string }[] } }).public_net.firewalls[0]!.status = "pending";
    await expect(h.detachForeignFirewall(71, 1)).rejects.toThrow(/stayfrosty-app1 is not attached and applied/);
    expect(http.writes()).toEqual([]);
    (hz.servers[0] as { public_net: { firewalls: { id: number; status: string }[] } }).public_net.firewalls[0]!.status = "applied";
    await expect(h.detachForeignFirewall(71, 1)).resolves.toBeDefined();
    expect(http.writes().map((c) => c.url.pathname)).toEqual(["/v1/firewalls/71/actions/remove_from_resources"]);
  });

  it("change log: an intent line before each write, a done line after, ids only, no secrets", async () => {
    const log = join(dir, "cf.log");
    await cf(log).createTunnel("acc", "stayfrosty-t1");
    const lines = readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.map((l) => l["phase"])).toEqual(["intent", "done"]);
    expect(lines[0]?.["action"]).toBe("cloudflare POST");
    expect(lines[0]?.["request"]).toEqual({ name: "stayfrosty-t1", config_src: "cloudflare" });
    expect(lines[0]?.["before"]).toBeNull();
    expect(Object.keys(lines[1]?.["result"] as object).sort()).toEqual(["ids", "status"]);
    expect(readFileSync(log, "utf8")).not.toContain("cf-token-0123456789");
  });

  it("change log: if the intent line cannot be written, nothing is sent", async () => {
    await expect(cf(join(dir, "missing", "\0bad")).createTunnel("acc", "stayfrosty-t1")).rejects.toThrow(/Nothing was sent/);
    expect(http.writes()).toEqual([]);
  });
});
