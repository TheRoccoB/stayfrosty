import { describe, expect, it } from "vitest";
import { checkRouteAccess, checkRouteEmails, checkStrayRouteEmailPolicies } from "../src/checks/routes.ts";
import { Cloudflare, isOurEmailPolicy } from "../src/cloudflare.ts";
import type { Context } from "../src/context.ts";
import { describeEdge, edgeIsEmpty, findEdge, removeEdge, syncRoutes } from "../src/edge.ts";
import { isRouteEmailPolicyOf, isRouteTokenPolicyOf, routeEmailPolicyName, validateRoutes, type Route } from "../src/routes.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

// A preview site shared with a few outside testers: its own email list, separate from the box's
// accessEmails, so the testers get into this one route and nothing else on the box.
const share: Route = {
  name: "share",
  hostname: "preview.example.net",
  service: "http://127.0.0.1:3000",
  protected: ["/"],
  public: [],
  emails: ["alice@example.org", "bob@example.org"],
};
const opts = { domain: "example.com", appZones: ["example.net"], accessTeam: "team" };
const POLICY = "stayfrosty-web1:share:emails";
const ID1 = "11111111-1111-4111-8111-111111111111";

const setup = (routes: Route[] = [share]) => {
  const http = new FakeHttp();
  const fcf = new FakeCloudflare(http);
  const cloudflare = new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep });
  const config = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team", routes: { web1: routes } };
  const io = new ScriptedIo();
  const ctx = { cloudflare, config, io, now: () => 0 } as unknown as Context;
  return { http, fcf, cloudflare, config, io, ctx };
};
type Setup = ReturnType<typeof setup>;
const seedBox = async (s: Setup) => {
  const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-web1");
  const policy = await s.cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-web1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
  return { tunnel, policy };
};
const writes = (s: Setup, from = 0): string[] =>
  s.http
    .writes()
    .slice(from)
    .map((w) => `${w.method} ${w.url.pathname.replace(/^.*\/accounts\/[^/]+/, "").replace(/(app|pol)-[^/]+$/, "$1")}`);
const appOf = (s: Setup) => s.fcf.apps.find((a) => a["name"] === "stayfrosty-web1:share") as Record<string, unknown>;
const policyOf = (s: Setup) => s.fcf.policies.find((p) => p["name"] === POLICY);

describe("route emails config", () => {
  it("accepts plain emails on a route with a protected path on frosty's own app", () => {
    expect(validateRoutes("web1", [share], opts)).toEqual([]);
  });

  it("refuses an empty list, non-emails, wildcards, repeats, and a route with no app of frosty's", () => {
    const bad = (emails: unknown, extra: Partial<Route> = {}) => validateRoutes("web1", [{ ...share, ...extra, emails }], opts).join("\n");
    expect(bad([])).toMatch(/emails must be a list of 1-50 plain email addresses/);
    expect(bad("alice@example.org")).toMatch(/emails must be a list/);
    expect(bad(["example.org"])).toMatch(/plain email addresses/);
    expect(bad(["*@example.org"])).toMatch(/plain email addresses/);
    expect(bad(["a@example.org,b@example.org"])).toMatch(/plain email addresses/);
    expect(bad(["alice@example.org", "Alice@Example.org"])).toMatch(/lists alice@example.org twice/);
    expect(bad(Array.from({ length: 51 }, (_, i) => `u${i}@example.org`))).toMatch(/1-50/);
    expect(bad(["alice@example.org"], { protected: [], public: ["/"] })).toMatch(/emails needs a protected path on frosty's own Access app/);
    expect(bad(["alice@example.org"], { protected: ["/admin"], public: ["/"], externalAccess: { "/admin": "Someone else's app" } })).toMatch(/emails needs a protected path on frosty's own Access app/);
  });
});

describe("route email policy names and writer", () => {
  it("names it after the route's app, never the box's policy or a token policy", () => {
    expect(routeEmailPolicyName("web1", share)).toBe(POLICY);
    expect(isRouteEmailPolicyOf("web1", POLICY)).toBe(true);
    expect(isRouteEmailPolicyOf("web1", "stayfrosty-web1")).toBe(false);
    expect(isRouteEmailPolicyOf("web1", "stayfrosty-web1-x:share:emails")).toBe(false);
    expect(isRouteEmailPolicyOf("web1", "stayfrosty-web1:Bad_Route:emails")).toBe(false);
    expect(isRouteTokenPolicyOf("web1", POLICY)).toBe(false);
  });

  it("writes exactly the route's emails as an allow policy, and replaces only a policy of that name", async () => {
    const s = setup();
    const { policy: boxPolicy } = await seedBox(s);
    const p = await s.cloudflare.putRouteEmailPolicy("acc123", "web1", share);
    expect(p).toMatchObject({ name: POLICY, decision: "allow", include: [{ email: { email: "alice@example.org" } }, { email: { email: "bob@example.org" } }] });
    expect(isOurEmailPolicy(p)).toBe(true);
    const before = s.http.writes().length;
    await expect(s.cloudflare.putRouteEmailPolicy("acc123", "web1", share, boxPolicy.id)).rejects.toThrow(/is named stayfrosty-web1/);
    await expect(s.cloudflare.putRouteEmailPolicy("acc123", "web1", { ...share, emails: [] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteEmailPolicy("acc123", "web1", { ...share, emails: ["*@example.org"] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteEmailPolicy("acc123", "web1", { ...share, emails: undefined })).rejects.toThrow(/refused/);
    expect(s.http.writes().length).toBe(before);
  });

  it("the route app takes the route's email policy first when it lists emails, the box's otherwise, and nothing else", async () => {
    const s = setup();
    const { policy: boxPolicy } = await seedBox(s);
    const own = await s.cloudflare.putRouteEmailPolicy("acc123", "web1", share);
    const other = await s.cloudflare.putRouteEmailPolicy("acc123", "web1", { ...share, name: "other" });
    const base = { box: "web1", appZones: ["example.net"], domain: "example.com", sessionDuration: "24h", kind: "protected" as const };
    const before = s.http.writes().length;
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: share, policyIds: [boxPolicy.id] })).rejects.toThrow(/is not the allow-by-email policy stayfrosty-web1:share:emails/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: share, policyIds: [other.id] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: share, policyIds: [own.id, boxPolicy.id] })).rejects.toThrow(/refused/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: { ...share, emails: undefined }, policyIds: [own.id] })).rejects.toThrow(/is not the allow-by-email policy stayfrosty-web1/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: share, policyIds: [own.id, own.id] })).rejects.toThrow(/wrong number of policies/);
    expect(s.http.writes().length).toBe(before);
    const app = await s.cloudflare.putRouteAccessApp("acc123", { ...base, route: share, policyIds: [own.id] });
    expect(app.policies).toEqual([{ id: own.id, precedence: 1 }]);
  });
});

describe("route sync with emails", () => {
  it("writes the email policy before the app, is idempotent, and follows changes to the list", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    const from = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(writes(s, from)).toEqual(["POST /access/policies", "POST /access/apps", `PUT /cfd_tunnel/${tunnel.id}/configurations`]);
    const policy = policyOf(s) as Record<string, unknown>;
    expect(appOf(s)["policies"]).toEqual([{ id: policy["id"], precedence: 1 }]);
    expect(s.io.text()).toContain(`Creating Access policy ${POLICY}: allow alice@example.org, bob@example.org.`);
    expect(s.io.text()).toContain(`with ${POLICY}.`);

    const again = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(s.http.writes().length).toBe(again);

    s.config.routes.web1 = [{ ...share, emails: ["alice@example.org", "carol@example.org"] }];
    const upd = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(writes(s, upd)).toEqual(["PUT /access/policies/pol"]);
    expect(policyOf(s)?.["include"]).toEqual([{ email: { email: "alice@example.org" } }, { email: { email: "carol@example.org" } }]);

    // A policy widened by hand goes back to exactly the list.
    (policyOf(s) as Record<string, unknown>)["include"] = [{ email: { email: "alice@example.org" } }, { email: { email: "carol@example.org" } }, { everyone: {} }];
    const fix = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(writes(s, fix)).toEqual(["PUT /access/policies/pol"]);
    expect(policyOf(s)?.["include"]).toEqual([{ email: { email: "alice@example.org" } }, { email: { email: "carol@example.org" } }]);
  });

  it("taking the emails out puts the box's policy back on the app first, then deletes the route's policy", async () => {
    const s = setup();
    const { tunnel, policy: boxPolicy } = await seedBox(s);
    await syncRoutes(s.ctx, "web1", tunnel);
    s.config.routes.web1 = [{ ...share, emails: undefined }];
    const from = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(writes(s, from)).toEqual(["PUT /access/apps/app", "DELETE /access/policies/pol"]);
    expect(appOf(s)["policies"]).toEqual([{ id: boxPolicy.id, precedence: 1 }]);
    expect(policyOf(s)).toBeUndefined();
    expect(s.io.text()).toContain(`Deleting Access policy ${POLICY}: its route no longer lists its own emails.`);

    // Removing the whole route: the app goes, then the policy.
    s.config.routes.web1 = [share];
    await syncRoutes(s.ctx, "web1", tunnel);
    s.config.routes.web1 = [];
    const rm = s.http.writes().length;
    await syncRoutes(s.ctx, "web1", tunnel);
    expect(writes(s, rm)).toEqual([`PUT /cfd_tunnel/${tunnel.id}/configurations`, "DELETE /access/apps/app", "DELETE /access/policies/pol"]);
  });

  it("works with service tokens: the email policy first, the token policy last", async () => {
    const s = setup([{ ...share, serviceTokens: ["preview-bot"] }]);
    s.fcf.serviceTokens.push({ id: ID1, name: "preview-bot", expires_at: "2027-06-01T00:00:00Z" });
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "web1", tunnel);
    const email = policyOf(s) as Record<string, unknown>;
    const token = s.fcf.policies.find((p) => p["name"] === "stayfrosty-web1:share:service-tokens") as Record<string, unknown>;
    expect(appOf(s)["policies"]).toEqual([
      { id: email["id"], precedence: 1 },
      { id: token["id"], precedence: 2 },
    ]);
  });

  it("refuses before any write when the route's email policy is on any other app", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "web1", tunnel);
    const policy = policyOf(s) as Record<string, unknown>;
    s.fcf.apps.push({ id: "app-other", name: "someone-elses-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: policy["id"], precedence: 1 }] });
    s.config.routes.web1 = [{ ...share, emails: ["alice@example.org"] }];
    const from = s.http.writes().length;
    await expect(syncRoutes(s.ctx, "web1", tunnel)).rejects.toThrow(/stayfrosty-web1:share:emails is attached to someone-elses-app/);
    expect(s.http.writes().length).toBe(from);
  });

  it("still needs the box's own email policy, so the box's Access is right before routes change", async () => {
    const s = setup();
    const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-web1");
    await expect(syncRoutes(s.ctx, "web1", tunnel)).rejects.toThrow(/Access policy stayfrosty-web1 is missing/);
  });
});

describe("the box's edge and destroy with route emails", () => {
  it("findEdge finds the route email policies, and removeEdge deletes them after the apps", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    await syncRoutes(s.ctx, "web1", tunnel);
    const edge = await findEdge(s.ctx, "web1");
    expect(edge.routeEmailPolicies.map((p) => p.name)).toEqual([POLICY]);
    expect(edge.policy?.name).toBe("stayfrosty-web1");
    expect(describeEdge(edge)).toContain(`Cloudflare Access policy ${POLICY}`);
    const from = s.http.writes().length;
    await removeEdge(s.ctx, edge);
    expect(writes(s, from)).toEqual(["DELETE /access/apps/app", "DELETE /access/policies/pol", "DELETE /access/policies/pol"]);
    expect(s.fcf.policies).toEqual([]);
    expect(edgeIsEmpty({ ...(await findEdge(s.ctx, "web1")), tunnel: undefined })).toBe(true);
  });
});

describe("route verify with emails", () => {
  const synced = async () => {
    const s = setup();
    const { tunnel, policy: boxPolicy } = await seedBox(s);
    await syncRoutes(s.ctx, "web1", tunnel);
    const policies = await s.cloudflare.listAccessPolicies("acc123");
    const emailPolicies = policies.filter((p) => isRouteEmailPolicyOf("web1", p.name));
    return { s, boxPolicy, policies, emailPolicies, policy: policies.find((p) => p.name === POLICY) };
  };

  it("passes exactly the list, on the route's app only, with every login method offered", async () => {
    const { s, policy, emailPolicies, policies, boxPolicy } = await synced();
    expect(checkRouteEmails("web1", share, policy, s.fcf.apps as never, emailPolicies)).toMatchObject({
      ok: true,
      name: "Route share: its own emails",
      detail: `${POLICY} lets in 2 email(s), on stayfrosty-web1:share only, every login method offered`,
    });
    expect(checkRouteAccess("web1", share, s.fcf.apps as never, policies, boxPolicy.id).ok).toBe(true);
    // The box's policy on that app instead is wrong.
    const r = checkRouteAccess("web1", { ...share, emails: undefined }, s.fcf.apps as never, policies, boxPolicy.id);
    expect(r).toMatchObject({ ok: false });
    expect(r.detail).toContain("with only frosty's email policy");
  });

  it("fails a missing or reshaped policy, extra or missing emails, another app using it, and limited login methods", async () => {
    const { s, policy, emailPolicies } = await synced();
    const apps = s.fcf.apps as never;
    expect(checkRouteEmails("web1", share, undefined, apps, emailPolicies)).toMatchObject({ ok: false, detail: `no Access policy ${POLICY}`, fix: "Run: frosty route sync web1" });
    const p = policy!;
    expect(checkRouteEmails("web1", share, { ...p, include: [...p.include, { everyone: {} }] }, apps, emailPolicies).detail).toContain("is not only emails");
    const diff = checkRouteEmails("web1", share, { ...p, include: [{ email: { email: "alice@example.org" } }, { email: { email: "eve@example.org" } }] }, apps, emailPolicies);
    expect(diff.detail).toContain("lets in eve@example.org too");
    expect(diff.detail).toContain("leaves out bob@example.org");
    // Case doesn't matter.
    expect(checkRouteEmails("web1", share, { ...p, include: [{ email: { email: "ALICE@example.org" } }, { email: { email: "bob@example.org" } }] }, apps, emailPolicies).ok).toBe(true);
    const elsewhere = [...s.fcf.apps, { id: "app-x", name: "stayfrosty-web1:other", type: "self_hosted", policies: [{ id: p.id }] }];
    expect(checkRouteEmails("web1", share, p, elsewhere as never, emailPolicies).detail).toContain(`${POLICY} is attached to stayfrosty-web1:other`);
    // A second app with the route app's own name is still elsewhere: it's matched by id.
    const twin = [...s.fcf.apps, { id: "app-twin", name: "stayfrosty-web1:share", type: "self_hosted", policies: [{ id: p.id }] }];
    expect(checkRouteEmails("web1", share, p, twin as never, emailPolicies).detail).toContain(`${POLICY} is attached to stayfrosty-web1:share`);
    appOf(s)["allowed_idps"] = ["idp-github"];
    expect(checkRouteEmails("web1", share, p, s.fcf.apps as never, emailPolicies).detail).toContain("offers only 1 login method(s) (allowed_idps)");
  });

  it("flags email policies no route wants", () => {
    expect(checkStrayRouteEmailPolicies("web1", [])).toBeUndefined();
    expect(checkStrayRouteEmailPolicies("web1", [{ id: "p", name: POLICY, decision: "allow", include: [] }])).toMatchObject({ ok: false, fix: "Run: frosty route sync web1" });
  });
});
