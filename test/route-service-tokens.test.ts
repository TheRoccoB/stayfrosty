import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runRoute } from "../src/commands/route.ts";
import { saveConfig, type Config } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { checkRouteAccess, checkRouteServiceTokens, checkStrayRouteTokenPolicies } from "../src/checks/routes.ts";
import { Cloudflare, isOurTokenPolicy, tokenPolicyName } from "../src/cloudflare.ts";
import { validateConfig } from "../src/config.ts";
import type { Context } from "../src/context.ts";
import { describeEdge, edgeIsEmpty, findEdge, removeEdge, syncRoutes } from "../src/edge.ts";
import { isRouteTokenPolicyOf, routeTokenPolicyName, validateRoutes, type Route } from "../src/routes.ts";
import { planRouteTokens, tokensUsedElsewhere, type RouteTokenPlan } from "../src/servicetokens.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

// A monitoring hub behind Access: people log in, and agents on other machines get in with a
// service token sent as CF-Access-Client-Id and CF-Access-Client-Secret headers.
const hub: Route = {
  name: "hub",
  hostname: "monitor.example.net",
  service: "http://127.0.0.1:8090",
  protected: ["/"],
  public: [],
  serviceTokens: ["monitoring-agents"],
};
const opts = { domain: "example.com", appZones: ["example.net"], accessTeam: "team" };
const NOW = Date.parse("2026-11-06T12:00:00Z");
const DAY = 86_400_000;
const ID1 = "11111111-1111-4111-8111-111111111111";
const ID2 = "22222222-2222-4222-8222-222222222222";
const ID3 = "33333333-3333-4333-8333-333333333333";
const days = (n: number): string => new Date(NOW + n * DAY).toISOString();
const POLICY = "stayfrosty-mon1:hub:service-tokens";

const setup = (routes: Route[] = [hub]) => {
  const http = new FakeHttp();
  const fcf = new FakeCloudflare(http);
  const cloudflare = new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep });
  const config = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team", routes: { mon1: routes } };
  const io = new ScriptedIo();
  const ctx = { cloudflare, config, io, now: () => NOW } as unknown as Context;
  fcf.serviceTokens.push({ id: ID1, name: "monitoring-agents", expires_at: days(300) });
  fcf.serviceTokens.push({ id: ID2, name: "second-agent", expires_at: days(10) });
  return { http, fcf, cloudflare, config, io, ctx };
};
const seedBox = async (s: ReturnType<typeof setup>) => {
  const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-mon1");
  const policy = await s.cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-mon1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
  return { tunnel, policy };
};
const writes = (s: ReturnType<typeof setup>, from = 0): string[] =>
  s.http
    .writes()
    .slice(from)
    .map((w) => `${w.method} ${w.url.pathname.replace(/^.*\/accounts\/[^/]+/, "").replace(/(app|pol)-[^/]+$/, "$1")}`);
const appOf = (s: ReturnType<typeof setup>) => s.fcf.apps.find((a) => a["name"] === "stayfrosty-mon1:hub") as Record<string, unknown>;
const policyOf = (s: ReturnType<typeof setup>) => s.fcf.policies.find((p) => p["name"] === POLICY);

describe("route serviceTokens config", () => {
  const problems = (r: Record<string, unknown>): string[] => validateRoutes("mon1", [{ ...hub, ...r }], opts);

  it("accepts token names on a route with a protected path on frosty's own app", () => {
    expect(problems({})).toEqual([]);
    expect(problems({ serviceTokens: [] })).toEqual([]);
    expect(problems({ protected: ["/api"], public: ["/"], serviceTokens: ["a.b_c-1", "other"] })).toEqual([]);
  });

  it("refuses bad names, repeats, and a route with no app of frosty's to put them on", () => {
    for (const bad of ["x", [1], ["-a"], ["a b"], ["a".repeat(65)], null]) {
      expect(problems({ serviceTokens: bad }).join(), JSON.stringify(bad)).toMatch(/serviceTokens must be a list of service token names/);
    }
    expect(problems({ serviceTokens: ["a", "a"] })).toEqual([expect.stringMatching(/lists a twice/)]);
    expect(problems({ protected: [], public: ["/"] })).toEqual([expect.stringMatching(/needs a protected path on frosty's own Access app/)]);
    expect(problems({ protected: ["/admin"], public: ["/"], externalAccess: { "/admin": "other-app" } })).toEqual([expect.stringMatching(/needs a protected path on frosty's own Access app/)]);
  });

  it("refuses a token in two places: a box's SSH and a route, or two routes", () => {
    const base = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team" };
    expect(validateConfig({ ...base, routes: { mon1: [hub] } })).toEqual([]);
    expect(validateConfig({ ...base, routes: { mon1: [hub] }, serviceTokens: { box2: ["monitoring-agents"] } })).toEqual([
      "service token monitoring-agents is listed under both serviceTokens.box2 and routes.mon1/hub: a service token opens exactly one box or route",
    ]);
    expect(validateConfig({ ...base, routes: { mon1: [hub], box2: [{ ...hub, name: "other", hostname: "other.example.net" }] } })).toEqual([
      "service token monitoring-agents is listed under both routes.mon1/hub and routes.box2/other: a service token opens exactly one box or route",
    ]);
    // The SSH-only message is unchanged.
    expect(validateConfig({ ...base, serviceTokens: { box1: ["x"], box2: ["x"] } })).toEqual(["service token x is listed under both box1 and box2: a service token opens exactly one box"]);
  });
});

describe("route token policy names and shape", () => {
  const good = { name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] };

  it("names it after the route's app, with two colons, never the box's SSH policy", () => {
    expect(routeTokenPolicyName("mon1", hub)).toBe(POLICY);
    expect(tokenPolicyName("mon1", "hub")).toBe(POLICY);
    expect(tokenPolicyName("mon1")).toBe("stayfrosty-mon1:service-tokens");
    expect(isRouteTokenPolicyOf("mon1", POLICY)).toBe(true);
    expect(isRouteTokenPolicyOf("mon1", "stayfrosty-mon1:service-tokens")).toBe(false);
    expect(isRouteTokenPolicyOf("mon1", "stayfrosty-mon1x:hub:service-tokens")).toBe(false);
    expect(isRouteTokenPolicyOf("mon1", "stayfrosty-mon1:hub:public")).toBe(false);
    expect(isRouteTokenPolicyOf("mon1", "stayfrosty-mon1:a:b:service-tokens")).toBe(false);
  });

  it("accepts frosty's shape for that box and route only", () => {
    expect(isOurTokenPolicy(good, "mon1", "hub")).toBe(true);
    expect(isOurTokenPolicy(good, "mon1")).toBe(false);
    expect(isOurTokenPolicy(good, "mon1", "other")).toBe(false);
    expect(isOurTokenPolicy(good, "mon1", "Hub")).toBe(false);
    expect(isOurTokenPolicy({ ...good, name: "stayfrosty-mon1:service-tokens" }, "mon1", "hub")).toBe(false);
    expect(isOurTokenPolicy({ ...good, include: [{ any_valid_service_token: {} }] }, "mon1", "hub")).toBe(false);
    expect(isOurTokenPolicy({ ...good, decision: "allow" }, "mon1", "hub")).toBe(false);
  });
});

describe("route app guard with a token policy", () => {
  const base = { box: "mon1", route: hub, appZones: ["example.net"], domain: "example.com", sessionDuration: "24h" };

  it("takes the route's own token policy last, only for a route with serviceTokens", async () => {
    const s = setup();
    const { policy } = await seedBox(s);
    const token = await s.cloudflare.putTokenPolicy("acc123", "mon1", [ID1], undefined, "hub");
    expect(token).toMatchObject({ name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    const ssh = await s.cloudflare.putTokenPolicy("acc123", "mon1", [ID2]);
    const other = await s.cloudflare.putTokenPolicy("acc123", "mon1", [ID3], undefined, "other");
    const before = s.http.writes().length;
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [token.id] })).rejects.toThrow(/allow-by-email/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [token.id, policy.id] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [policy.id, ssh.id] })).rejects.toThrow(/is not stayfrosty-mon1:hub:service-tokens/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [policy.id, other.id] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: { ...hub, serviceTokens: [] }, kind: "protected", policyIds: [policy.id, token.id] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "public", policyIds: [token.id] })).rejects.toThrow(/refused/);
    expect(s.http.writes().length).toBe(before);
    const app = await s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [policy.id, token.id] });
    expect(app.policies).toEqual([
      { id: policy.id, precedence: 1 },
      { id: token.id, precedence: 2 },
    ]);
  });

  it("putTokenPolicy for a route refuses a policy of another name", async () => {
    const s = setup();
    const ssh = await s.cloudflare.putTokenPolicy("acc123", "mon1", [ID1]);
    await expect(s.cloudflare.putTokenPolicy("acc123", "mon1", [ID1], ssh.id, "hub")).rejects.toThrow(/is named stayfrosty-mon1:service-tokens/);
    await expect(s.cloudflare.putTokenPolicy("acc123", "mon1", [ID1], undefined, "Bad_Route")).rejects.toThrow(/wrong shape/);
  });
});

describe("route sync with service tokens", () => {
  it("writes the token policy before the app that uses it, is idempotent, and updates the token list", async () => {
    const s = setup();
    const { tunnel, policy } = await seedBox(s);
    const from = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(writes(s, from)).toEqual(["POST /access/policies", "POST /access/apps", `PUT /cfd_tunnel/${tunnel.id}/configurations`]);
    const token = policyOf(s) as Record<string, unknown>;
    expect(token).toMatchObject({ name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    expect(appOf(s)["policies"]).toEqual([
      { id: policy.id, precedence: 1 },
      { id: token["id"], precedence: 2 },
    ]);
    expect(s.io.text()).toContain("Service token monitoring-agents (route hub): expires 2027-09-02, in 300 days.");
    expect(s.io.text()).toContain(`Creating Access policy ${POLICY}: let in service tokens monitoring-agents.`);

    const again = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(s.http.writes().length).toBe(again);

    s.config.routes.mon1 = [{ ...hub, serviceTokens: ["monitoring-agents", "second-agent"] }];
    const upd = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(writes(s, upd)).toEqual(["PUT /access/policies/pol"]);
    expect(policyOf(s)?.["include"]).toEqual([{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID2 } }]);
    expect(s.io.text()).toContain("[expires within 30 days]");

    // A policy edited by hand to let in any token goes back to frosty's shape.
    (policyOf(s) as Record<string, unknown>)["include"] = [{ any_valid_service_token: {} }];
    const fix = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(writes(s, fix)).toEqual(["PUT /access/policies/pol"]);
  });

  it("taking the tokens out detaches the policy, then deletes it; removing the route deletes the app, then the policy", async () => {
    const s = setup();
    const { tunnel, policy } = await seedBox(s);
    await syncRoutes(s.ctx, "mon1", tunnel);
    s.config.routes.mon1 = [{ ...hub, serviceTokens: [] }];
    const from = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(writes(s, from)).toEqual(["PUT /access/apps/app", "DELETE /access/policies/pol"]);
    expect(appOf(s)["policies"]).toEqual([{ id: policy.id, precedence: 1 }]);
    expect(policyOf(s)).toBeUndefined();

    s.config.routes.mon1 = [hub];
    await syncRoutes(s.ctx, "mon1", tunnel);
    s.config.routes.mon1 = [];
    const rm = s.http.writes().length;
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(writes(s, rm)).toEqual([`PUT /cfd_tunnel/${tunnel.id}/configurations`, "DELETE /access/apps/app", "DELETE /access/policies/pol"]);
    expect(s.io.text()).toContain(`Deleting Access policy ${POLICY}: its route no longer lists service tokens.`);
  });

  it("refuses before any write: a missing or ambiguous token, or one that also opens something else", async () => {
    const s = setup([{ ...hub, serviceTokens: ["no-such-token"] }]);
    const { tunnel } = await seedBox(s);
    const from = s.http.writes().length;
    await expect(syncRoutes(s.ctx, "mon1", tunnel)).rejects.toThrow(/Cloudflare has no service token named no-such-token/);
    s.config.routes.mon1 = [hub];
    s.fcf.serviceTokens.push({ id: ID3, name: "monitoring-agents" });
    await expect(syncRoutes(s.ctx, "mon1", tunnel)).rejects.toThrow(/2 Cloudflare service tokens are named monitoring-agents/);
    s.fcf.serviceTokens.pop();
    // The box's SSH token policy names the same token.
    s.fcf.policies.push({ id: "pol-ssh-tok", name: "stayfrosty-mon1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    await expect(syncRoutes(s.ctx, "mon1", tunnel)).rejects.toThrow(/a token of mon1\/hub also opens: Access policy stayfrosty-mon1:service-tokens includes monitoring-agents/);
    s.fcf.policies.pop();
    // Another app lets in any valid service token.
    s.fcf.policies.push({ id: "pol-any", name: "any-token", decision: "non_identity", include: [{ any_valid_service_token: {} }] });
    s.fcf.apps.push({ id: "app-other", name: "other", type: "self_hosted", domain: "other.example.net", policies: [{ id: "pol-any", precedence: 1 }] });
    await expect(syncRoutes(s.ctx, "mon1", tunnel)).rejects.toThrow(/Access application other \(policy any-token\) lets in any valid service token/);
    expect(s.http.writes().length).toBe(from);
  });

  it("a route without serviceTokens reads no service tokens or groups", async () => {
    const s = setup([{ ...hub, serviceTokens: undefined }]);
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(s.http.calls.some((c) => /service_tokens|groups/.test(c.url.pathname))).toBe(false);
    expect(policyOf(s)).toBeUndefined();
  });
});

describe("the box's edge and destroy", () => {
  it("findEdge finds the route token policies, and removeEdge deletes them after the apps, before the email policy", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "mon1", tunnel);
    const ctx = { ...s.ctx, config: { ...s.config } } as unknown as Context;
    const edge = await findEdge(ctx, "mon1");
    expect(edge.routeTokenPolicies.map((p) => p.name)).toEqual([POLICY]);
    expect(edge.tokenPolicy).toBeUndefined();
    expect(describeEdge(edge)).toContain(`Cloudflare Access policy ${POLICY}`);
    const from = s.http.writes().length;
    await removeEdge(ctx, edge);
    expect(writes(s, from)).toEqual(["DELETE /access/apps/app", "DELETE /access/policies/pol", "DELETE /access/policies/pol"]);
    expect(s.fcf.policies.map((p) => p["name"])).toEqual([]);
    const left = await findEdge(ctx, "mon1");
    expect(edgeIsEmpty({ ...left, tunnel: undefined })).toBe(true);
  });
});

describe("one token, one place, from the SSH side", () => {
  it("a route token policy for another token doesn't trip the SSH check; one for the same token does", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "mon1", tunnel);
    expect(await tokensUsedElsewhere(s.ctx, "mon1", new Map([[ID2, "second-agent"]]), { appId: undefined, policyId: undefined })).toEqual([]);
    const hit = await tokensUsedElsewhere(s.ctx, "mon1", new Map([[ID1, "monitoring-agents"]]), { appId: undefined, policyId: undefined });
    expect(hit).toContain(`Access policy ${POLICY} includes monitoring-agents`);
    expect(hit).toContain(`Access application stayfrosty-mon1:hub (policy ${POLICY}) includes monitoring-agents`);
  });
});

describe("route verify with service tokens", () => {
  const plan = (extra: Partial<RouteTokenPlan> = {}): RouteTokenPlan => ({
    names: ["monitoring-agents"],
    tokens: [{ name: "monitoring-agents", token: { id: ID1, name: "monitoring-agents", expires_at: days(40) } }],
    problems: [],
    elsewhere: [],
    now: NOW,
    policyName: POLICY,
    policy: { id: "pt", name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] },
    ...extra,
  });

  it("passes the policy with exactly the configured tokens, listing days left", () => {
    const r = checkRouteServiceTokens("mon1", hub, plan());
    expect(r).toMatchObject({ ok: true, name: "Route hub: service tokens", detail: `${POLICY} lets in monitoring-agents (40 days left)` });
  });

  it("fails a missing or reshaped policy, extra or missing ids, expiry, unresolved names and tokens open elsewhere", () => {
    expect(checkRouteServiceTokens("mon1", hub, plan({ policy: undefined }))).toMatchObject({ ok: false, detail: `no Access policy ${POLICY}`, fix: "Run: frosty route sync mon1" });
    const shape = checkRouteServiceTokens("mon1", hub, plan({ policy: { id: "pt", name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }, { everyone: {} }] } }));
    expect(shape.detail).toContain("is not only service tokens");
    const extra = checkRouteServiceTokens("mon1", hub, plan({ policy: { id: "pt", name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID3 } }] } }));
    expect(extra.detail).toContain(`lets in token id(s) not in the route's serviceTokens: ${ID3}`);
    const missing = checkRouteServiceTokens("mon1", hub, plan({ policy: { id: "pt", name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID3 } }] } }));
    expect(missing.detail).toContain(`${POLICY} does not include monitoring-agents`);
    const expired = checkRouteServiceTokens("mon1", hub, plan({ tokens: [{ name: "monitoring-agents", token: { id: ID1, name: "monitoring-agents", expires_at: days(-2) } }] }));
    expect(expired.detail).toContain("service token monitoring-agents expired 2026-11-04, 2 days ago");
    expect(checkRouteServiceTokens("mon1", hub, plan({ problems: ["Cloudflare has no service token named x"] })).ok).toBe(false);
    expect(checkRouteServiceTokens("mon1", hub, plan({ elsewhere: ["Access policy p includes monitoring-agents"] })).detail).toContain("a token of mon1/hub also opens: Access policy p");
  });

  it("checkRouteAccess wants the email policy and the token policy on frosty's app", async () => {
    const s = setup();
    const { tunnel, policy } = await seedBox(s);
    await syncRoutes(s.ctx, "mon1", tunnel);
    const policies = await s.cloudflare.listAccessPolicies("acc123");
    const token = policies.find((p) => p.name === POLICY);
    expect(checkRouteAccess("mon1", hub, s.fcf.apps as never, policies, policy.id, token).ok).toBe(true);
    const r = checkRouteAccess("mon1", hub, s.fcf.apps as never, policies, policy.id, undefined);
    expect(r.ok).toBe(false);
    expect(r.detail).toContain(`with only frosty's email policy and ${POLICY}`);
    // Without serviceTokens in config, the token policy on the app is one policy too many.
    expect(checkRouteAccess("mon1", { ...hub, serviceTokens: undefined }, s.fcf.apps as never, policies, policy.id, token).ok).toBe(false);
  });

  it("planRouteTokens makes no calls for a route without tokens, and verify also counts the policy's own ids", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    expect(await planRouteTokens(s.ctx, "mon1", { ...hub, serviceTokens: [] }, undefined, undefined, true)).toBeUndefined();
    expect(s.http.calls.some((c) => /service_tokens|groups/.test(c.url.pathname))).toBe(false);
    await syncRoutes(s.ctx, "mon1", tunnel);
    // A hand-added id that also opens the box's SSH: verify sees it, sync's plan (configured ids only) doesn't.
    (policyOf(s) as Record<string, unknown>)["include"] = [{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID2 } }];
    s.fcf.policies.push({ id: "pol-ssh-tok", name: "stayfrosty-mon1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID2 } }] });
    const listed = s.fcf.policies.find((p) => p["name"] === POLICY) as never;
    const app = appOf(s)["id"] as string;
    const forVerify = await planRouteTokens(s.ctx, "mon1", hub, app, listed, true);
    expect(forVerify?.elsewhere).toEqual([`Access policy stayfrosty-mon1:service-tokens includes token id ${ID2}`]);
    const forSync = await planRouteTokens(s.ctx, "mon1", hub, app, listed, false);
    expect(forSync?.elsewhere).toEqual([]);
  });

  it("flags token policies no route wants", () => {
    expect(checkStrayRouteTokenPolicies("mon1", [])).toBeUndefined();
    expect(checkStrayRouteTokenPolicies("mon1", [{ id: "p", name: POLICY, decision: "non_identity", include: [] }])).toMatchObject({ ok: false, fix: "Run: frosty route sync mon1" });
  });
});

describe("frosty route plan with service tokens", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let fcf: FakeCloudflare;
  const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
  const deps = (io: ScriptedIo): Deps => ({ io, env, fetch: http.fetch, sleep: noSleep, now: () => NOW, cloudflaredPath: "/usr/bin/cloudflared", isTty: false });
  const config = async (routes: Route[], extra: Partial<Config> = {}): Promise<void> => {
    await saveConfig({ ...sampleConfig, appZones: ["example.net"], accessTeam: "team", routes: { mon1: routes }, ...extra }, env);
  };

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-route-tokens-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await config([hub]);
    http = new FakeHttp();
    fcf = new FakeCloudflare(http);
    fcf.tunnels.push({ id: "00000000-0000-4000-8000-000000000001", name: "stayfrosty-mon1", status: "healthy" });
    fcf.policies.push({ id: "pol-email", name: "stayfrosty-mon1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    fcf.serviceTokens.push({ id: ID1, name: "monitoring-agents", expires_at: days(10) });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("shows the token policy and expiry, changes nothing, and exits 1 where sync would refuse", async () => {
    const io = new ScriptedIo();
    expect(await runRoute(deps(io), { action: "plan", box: "mon1" }), io.text()).toBe(0);
    expect(io.text()).toContain(`Access ${POLICY} (service tokens, on stayfrosty-mon1:hub): monitoring-agents  [missing]`);
    expect(io.text()).toContain("service token monitoring-agents: expires 2026-11-16, in 10 days  [expires within 30 days]");
    expect(http.writes()).toEqual([]);

    await config([{ ...hub, serviceTokens: ["no-such-token"] }]);
    const bad = new ScriptedIo();
    expect(await runRoute(deps(bad), { action: "plan", box: "mon1" })).toBe(1);
    expect(bad.text()).toContain("[problem: Cloudflare has no service token named no-such-token]");
    expect(bad.text()).toContain("1 service token problem(s) above: sync would refuse.");

    await config([{ ...hub, serviceTokens: undefined }]);
    fcf.policies.push({ id: "pol-stray", name: POLICY, decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    const stray = new ScriptedIo();
    const callsBefore = http.calls.length;
    expect(await runRoute(deps(stray), { action: "plan", box: "mon1" })).toBe(0);
    expect(stray.text()).toContain(`Access policy ${POLICY}: no route lists service tokens for it; sync deletes it.`);
    // No route lists tokens, so no token or group reads.
    expect(http.calls.slice(callsBefore).some((c) => /service_tokens|groups/.test(c.url.pathname))).toBe(false);
    expect(http.writes()).toEqual([]);
  });

  it("sync creates the policy and the app, then plan shows both in place", async () => {
    const io = new ScriptedIo();
    expect(await runRoute(deps(io), { action: "sync", box: "mon1" }), io.text()).toBe(0);
    expect(fcf.policies.find((p) => p["name"] === POLICY)).toBeDefined();
    expect(io.text()).toContain(`Access ${POLICY} (service tokens, on stayfrosty-mon1:hub): monitoring-agents`);
    expect(io.text()).not.toContain("[missing]");
  });
});
