import { describe, expect, it } from "vitest";
import { BYPASS_POLICY_NAME, Cloudflare } from "../src/cloudflare.ts";
import { validateConfig } from "../src/config.ts";
import type { Context } from "../src/context.ts";
import { syncRoutes } from "../src/edge.ts";
import { checkRouteAccess, checkRouteOutside, checkRoutePorts, classify } from "../src/checks/routes.ts";
import { assertBoxName } from "../src/context.ts";
import type { RawGet } from "../src/rawget.ts";
import { SUSPICIOUS_PATH, boxIngress, bypassPaths, prefixRegex, routeIngress, validateRoutes, type Route } from "../src/routes.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

// The shape of the Listmonk route on a real box, on example names.
const listmonk: Route = {
  name: "listmonk",
  hostname: "news.example.net",
  service: "http://127.0.0.1:9000",
  protected: ["/admin", "/api"],
  public: ["/subscription/", "/link/", "/campaign/", "/archive", "/public/", "/uploads/", "/api/public/", "/webhooks/service/ses"],
  probe: "/public/static/logo.svg",
};
const opts = { domain: "example.com", appZones: ["example.net"], accessTeam: "team" };
const AUD = "a".repeat(64);

describe("route paths", () => {
  const matches = (prefix: string, path: string): boolean => new RegExp(prefixRegex(prefix)).test(path);

  it("matches a prefix and what's under it, never a longer name", () => {
    expect(matches("/archive", "/archive")).toBe(true);
    expect(matches("/archive", "/archive/2024")).toBe(true);
    expect(matches("/archive", "/archivex")).toBe(false);
    expect(matches("/webhooks/service/ses", "/webhooks/service/sesx")).toBe(false);
    expect(matches("/link/", "/link/abc")).toBe(true);
    expect(matches("/link/", "/link")).toBe(false);
    expect(matches("/link/", "/x/link/abc")).toBe(false);
    // Dots are literal.
    expect(matches("/a.b", "/aXb")).toBe(false);
    expect(matches("/a.b", "/a.b")).toBe(true);
  });

  it("flags every path trick", () => {
    const suspicious = new RegExp(SUSPICIOUS_PATH);
    for (const p of ["/api/public/../settings", "//api/settings", "/api\\settings", "/api;/settings", "/admin%2f..", "/api/public/%2e%2e/settings"]) {
      expect(suspicious.test(p), p).toBe(true);
    }
    for (const p of ["/api/public/subscription", "/link/abc-123/def", "/public/static/logo.svg"]) {
      expect(suspicious.test(p), p).toBe(false);
    }
  });

  it("finds the public paths that need an Access bypass", () => {
    expect(bypassPaths(listmonk)).toEqual(["/api/public/"]);
  });

  it("generates the trick 404 first, public before protected, Access checks on protected, and a host 404 last", () => {
    const rules = routeIngress(listmonk, "team", () => [AUD]);
    expect(rules[0]).toEqual({ hostname: "news.example.net", path: SUSPICIOUS_PATH, service: "http_status:404" });
    expect(rules.at(-1)).toEqual({ hostname: "news.example.net", service: "http_status:404" });
    const firstProtected = rules.findIndex((r) => r.originRequest !== undefined);
    expect(rules.findIndex((r) => r.path === prefixRegex("/api/public/"))).toBeLessThan(firstProtected);
    for (const r of rules.filter((x) => x.path === prefixRegex("/admin") || x.path === prefixRegex("/api"))) {
      expect(r.originRequest).toEqual({ access: { required: true, teamName: "team", audTag: [AUD] } });
    }
    expect(rules.filter((r) => r.originRequest !== undefined)).toHaveLength(2);
    // First match wins in cloudflared: simulate it over real paths.
    const route = (path: string): string => {
      const all = boxIngress("ssh-svc1.example.com", [{ route: listmonk, audFor: () => [AUD] }], "team");
      const hit = all.find((r) => (r.hostname === undefined || r.hostname === "news.example.net") && (r.path === undefined || new RegExp(r.path).test(path)));
      return hit === undefined ? "none" : hit.originRequest !== undefined ? "access" : hit.service === "http_status:404" ? "404" : "app";
    };
    expect(route("/api/public/subscription")).toBe("app");
    expect(route("/api/settings")).toBe("access");
    expect(route("/admin")).toBe("access");
    expect(route("/install")).toBe("404");
    expect(route("/api2")).toBe("404");
    expect(route("/API/settings")).toBe("404");
    for (const trick of ["/api/public/../settings", "//api/settings", "/api;/settings", "/admin%2f..", "/api/public/..%2fsettings"]) {
      expect(route(trick), trick).toBe("404");
    }
  });
});

describe("route config", () => {
  const problems = (r: Record<string, unknown>, o = opts): string[] => validateRoutes("svc1", [{ ...listmonk, ...r }], o);

  it("accepts the Listmonk route", () => {
    expect(problems({})).toEqual([]);
  });

  it("refuses hostnames, services and paths outside the allowed shapes", () => {
    for (const hostname of ["*.example.net", "news.example.com", "ssh-svc1.example.net", "news.example.org", "NEWS.example.net"]) {
      expect(problems({ hostname }), hostname).not.toEqual([]);
    }
    for (const service of ["http://localhost:9000", "https://127.0.0.1:9000", "http://10.0.0.1:9000", "ssh://127.0.0.1:22", "http://127.0.0.1:80", "http://127.0.0.1:9000/x", "unix:/run/x.sock"]) {
      expect(problems({ service }), service).not.toEqual([]);
    }
    for (const bad of [["/Admin"], ["admin"], ["/"], ["/a//b"], ["/a b"], ["/a", "/a"]]) {
      expect(problems({ protected: bad }), bad.join()).not.toEqual([]);
    }
    expect(problems({ public: [...listmonk.public, "/"], protected: ["/admin"] })).not.toEqual([]);
    expect(problems({ protected: ["/api/settings"], public: ["/api"], probe: undefined })).toEqual([expect.stringMatching(/protected \/api\/settings is under public \/api/)]);
    expect(problems({ externalAccess: { "/link/": "other-app" } })).not.toEqual([]);
    expect(problems({ externalAccess: { "/admin": "stayfrosty-x" } })).not.toEqual([]);
    expect(problems({ probe: "/admin/x" })).not.toEqual([]);
    expect(problems({ extra: 1 })).toEqual([expect.stringMatching(/unknown keys: extra/)]);
    expect(problems({}, { ...opts, accessTeam: undefined as never })).toEqual([expect.stringMatching(/accessTeam/)]);
  });

  it("refuses a hostname on two routes, and appZones including the frosty domain", () => {
    const base = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team" };
    expect(validateConfig({ ...base, routes: { svc1: [listmonk], app1: [{ ...listmonk, name: "other" }] } })).toEqual([expect.stringMatching(/news.example.net is used by svc1\/listmonk and app1\/other/)]);
    expect(validateConfig({ ...base, appZones: ["example.com"] })).toEqual([expect.stringMatching(/appZones/)]);
    expect(validateConfig({ ...base, routes: { svc1: [listmonk] } })).toEqual([]);
  });
});

describe("route guards and sync", () => {
  const setup = (routes: Route[] = [listmonk]) => {
    const http = new FakeHttp();
    const fcf = new FakeCloudflare(http);
    const cloudflare = new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep });
    const config = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team", routes: { svc1: routes } };
    const io = new ScriptedIo();
    const ctx = { cloudflare, config, io } as unknown as Context;
    return { http, fcf, cloudflare, config, io, ctx };
  };
  const seedBox = async (s: ReturnType<typeof setup>) => {
    const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-svc1");
    const policy = await s.cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-svc1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    return { tunnel, policy };
  };
  const base = { box: "svc1", route: listmonk, appZones: ["example.net"], domain: "example.com", sessionDuration: "24h" };

  it("route apps take only frosty's email policy (protected) or only the bypass policy (public)", async () => {
    const s = setup();
    const { policy } = await seedBox(s);
    const bypass = await s.cloudflare.createBypassPolicy("acc123");
    expect(bypass).toMatchObject({ name: BYPASS_POLICY_NAME, decision: "bypass" });
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [bypass.id] })).rejects.toThrow(/allow-by-email/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "public", policyIds: [policy.id] })).rejects.toThrow(/bypass policy/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "public", policyIds: [bypass.id, bypass.id] })).rejects.toThrow(/wrong number/);
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, route: { ...listmonk, hostname: "news.example.com" }, kind: "protected", policyIds: [policy.id] })).rejects.toThrow(/refused/);
    // The box's own SSH app never takes the bypass policy either.
    await expect(
      s.cloudflare.createAccessApp("acc123", { name: "stayfrosty-svc1", type: "self_hosted", domain: "ssh-svc1.example.com", session_duration: "24h", app_launcher_visible: false, policies: [{ id: bypass.id, precedence: 1 }] }),
    ).rejects.toThrow(/allow-by-email/);
    const app = await s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "public", policyIds: [bypass.id] });
    expect(app).toMatchObject({ name: "stayfrosty-svc1:listmonk:public", domain: "news.example.net/api/public", destinations: [{ type: "public", uri: "news.example.net/api/public" }], policies: [{ id: bypass.id, precedence: 1 }] });
    // An update re-reads the app and refuses one that isn't this route's.
    await expect(s.cloudflare.putRouteAccessApp("acc123", { ...base, kind: "protected", policyIds: [policy.id] }, app.id)).rejects.toThrow(/is named stayfrosty-svc1:listmonk:public/);
  });

  it("ingress for a protected path needs an Access audience", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    const spec = { sshHostname: "ssh-svc1.example.com", teamName: "team", appZones: ["example.net"], routes: [{ route: listmonk, auds: { "/admin": [AUD] } }] };
    await expect(s.cloudflare.putTunnelIngress("acc123", tunnel, spec)).rejects.toThrow(/news.example.net\/api has no Access audience/);
    await expect(s.cloudflare.putTunnelIngress("acc123", tunnel, { ...spec, routes: [{ route: { ...listmonk, service: "http://10.0.0.1:9000" }, auds: { "/admin": [AUD], "/api": [AUD] } }] })).rejects.toThrow(/service/);
    expect(s.http.writes().filter((w) => w.url.pathname.includes("configurations"))).toEqual([]);
  });

  it("sync creates Access before the ingress that routes its paths, is idempotent, and removes in reverse", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    const before = s.http.writes().length;
    await syncRoutes(s.ctx, "svc1", tunnel);
    const writes = s.http.writes().slice(before).map((w) => `${w.method} ${w.url.pathname.replace(/^.*\/accounts\/[^/]+/, "")}`);
    expect(writes).toEqual([
      "POST /access/apps",
      "POST /access/policies",
      "POST /access/apps",
      `PUT /cfd_tunnel/${tunnel.id}/configurations`,
    ]);
    const apps = s.fcf.apps.filter((a) => String(a["name"]).startsWith("stayfrosty-svc1:"));
    expect(apps.map((a) => [a["name"], (a["destinations"] as { uri: string }[]).map((d) => d.uri)])).toEqual([
      ["stayfrosty-svc1:listmonk", ["news.example.net/admin", "news.example.net/api"]],
      ["stayfrosty-svc1:listmonk:public", ["news.example.net/api/public"]],
    ]);
    const ingress = s.fcf.ingress.get(tunnel.id) as { originRequest?: { access: { audTag: string[] } } }[];
    const prot = apps.find((a) => a["name"] === "stayfrosty-svc1:listmonk") as Record<string, unknown>;
    expect(ingress.filter((r) => r.originRequest !== undefined).map((r) => r.originRequest?.access.audTag)).toEqual([[prot["aud"]], [prot["aud"]]]);

    const again = s.http.writes().length;
    await syncRoutes(s.ctx, "svc1", tunnel);
    expect(s.http.writes().length).toBe(again);

    // Route removed from config: the ingress drops its paths first, then its apps go.
    (s.config.routes as Record<string, Route[]>)["svc1"] = [];
    const removeFrom = s.http.writes().length;
    await syncRoutes(s.ctx, "svc1", tunnel);
    const removes = s.http.writes().slice(removeFrom).map((w) => `${w.method} ${w.url.pathname.replace(/^.*\/accounts\/[^/]+/, "").replace(/app-[^/]+$/, "app")}`);
    expect(removes).toEqual([`PUT /cfd_tunnel/${tunnel.id}/configurations`, "DELETE /access/apps/app", "DELETE /access/apps/app"]);
    expect(s.fcf.ingress.get(tunnel.id)).toEqual([{ hostname: "ssh-svc1.example.com", service: "ssh://localhost:22" }, { service: "http_status:404" }]);
  });

  it("an external Access app must exist and cover its path; frosty only reads it", async () => {
    const route = { ...listmonk, externalAccess: { "/admin": "other-app" } };
    const s = setup([route]);
    const { tunnel } = await seedBox(s);
    await expect(syncRoutes(s.ctx, "svc1", tunnel)).rejects.toThrow(/Access app other-app must exist and cover news.example.net\/admin/);
    s.fcf.policies.push({ id: "pol-other-app", name: "gh-policy", decision: "allow", include: [{ everyone: {} }] });
    s.fcf.apps.push({ id: "app-other-app", name: "other-app", aud: "b".repeat(64), type: "self_hosted", domain: "other.example.net", destinations: [{ type: "public", uri: "other.example.net" }, { type: "public", uri: "news.example.net/admin" }], policies: [{ id: "pol-other-app", precedence: 1 }] });
    // An external app that lets everyone in can't guard a protected path.
    await expect(syncRoutes(s.ctx, "svc1", tunnel)).rejects.toThrow(/includes a everyone rule/);
    (s.fcf.policies.find((p) => p["id"] === "pol-other-app") as Record<string, unknown>)["include"] = [{ email: { email: "a@b.co" } }, { "github-organization": { name: "example-org" } }];
    await syncRoutes(s.ctx, "svc1", tunnel);
    expect(s.io.text()).toContain("Access app other-app (not frosty's) covers news.example.net/admin and lets in email: 1, github-organization: 1.");
    const own = s.fcf.apps.find((a) => a["name"] === "stayfrosty-svc1:listmonk") as Record<string, unknown>;
    expect((own["destinations"] as { uri: string }[]).map((d) => d.uri)).toEqual(["news.example.net/api"]);
    const tags = (s.fcf.ingress.get(tunnel.id) as { path?: string; originRequest?: { access: { audTag: string[] } } }[]).filter((r) => r.originRequest !== undefined).map((r) => [r.path, r.originRequest?.access.audTag[0]]);
    expect(tags).toEqual([[prefixRegex("/admin"), "b".repeat(64)], [prefixRegex("/api"), own["aud"]]]);
    expect(s.http.writes().some((w) => w.url.pathname.includes("app-other-app"))).toBe(false);
  });

  it("refuses a look-alike bypass policy", async () => {
    const s = setup();
    const { tunnel } = await seedBox(s);
    s.fcf.policies.push({ id: "pol-evil", name: BYPASS_POLICY_NAME, decision: "bypass", include: [{ everyone: {} }, { email: { email: "x@y.z" } }] });
    await expect(syncRoutes(s.ctx, "svc1", tunnel)).rejects.toThrow(/not frosty's bypass shape/);
  });
});

describe("route verify checks", () => {
  const team = "team";
  const login = { status: 302, location: `https://${team}.cloudflareaccess.com/cdn-cgi/access/login/news.example.net?x=1`, body: "" };
  const tunnel404 = { status: 404, location: null, body: "" };
  // A correctly set-up route, simulated from the generated ingress (first match wins).
  const good: RawGet = async (_host, path) => {
    const rules = boxIngress("ssh-svc1.example.com", [{ route: listmonk, audFor: () => [AUD] }], team);
    const hit = rules.find((r) => (r.hostname === undefined || r.hostname === "news.example.net") && (r.path === undefined || new RegExp(r.path).test(path)));
    if (hit?.originRequest !== undefined) {
      // Access at the edge: protected paths, minus the bypass.
      return login;
    }
    if (hit?.service === "http_status:404") {
      return tunnel404;
    }
    return path === listmonk.probe ? { status: 200, location: null, body: "<svg/>" } : { status: 404, location: null, body: '{"message":"not found"}' };
  };

  it("passes a correct route and fails when a trick path reaches the app", async () => {
    const ok = await checkRouteOutside(good, listmonk, team);
    expect(ok.ok, ok.detail).toBe(true);
    const leaky: RawGet = async (host, path) => (path === "/api/public/..%2fsettings" ? { status: 401, location: null, body: '{"message":"auth"}' } : good(host, path));
    const bad = await checkRouteOutside(leaky, listmonk, team);
    expect(bad.ok).toBe(false);
    expect(bad.detail).toContain("/api/public/..%2fsettings got origin");
  });

  it("fails when Access is missing, the login is another team's, or the app doesn't answer the probe", async () => {
    const open: RawGet = async (host, path) => (path === "/admin" ? { status: 200, location: null, body: "<html>" } : good(host, path));
    expect((await checkRouteOutside(open, listmonk, team)).detail).toContain("/admin got origin");
    const otherTeam: RawGet = async (host, path) => {
      const r = await good(host, path);
      return r.status === 302 ? { ...r, location: "https://evil.cloudflareaccess.com/cdn-cgi/access/login/x" } : r;
    };
    expect((await checkRouteOutside(otherTeam, listmonk, team)).ok).toBe(false);
    const down: RawGet = async (host, path) => (path === listmonk.probe ? tunnel404 : good(host, path));
    expect((await checkRouteOutside(down, listmonk, team)).detail).toContain("want 200");
  });

  it("checks the app listens on 127.0.0.1 only, and nothing on 5432", () => {
    const ss = (lines: string[]): string => lines.map((l) => `tcp LISTEN 0 4096 ${l} 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))`).join("\n");
    expect(checkRoutePorts([listmonk], ss(["127.0.0.1:9000"])).ok).toBe(true);
    expect(checkRoutePorts([listmonk], ss(["127.0.0.1:9000", "[::]:9000"])).detail).toContain("also listens on ::");
    expect(checkRoutePorts([listmonk], ss(["0.0.0.0:9000"])).ok).toBe(false);
    expect(checkRoutePorts([listmonk], ss(["127.0.0.1:9000", "127.0.0.1:5432"])).detail).toContain("5432");
    expect(checkRoutePorts([listmonk], ss([])).detail).toContain("nothing listens");
  });

  it("checks the Access apps' exact shape and where the bypass policy is attached", async () => {
    const http = new FakeHttp();
    const fcf = new FakeCloudflare(http);
    const cloudflare = new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep });
    const ctx = { cloudflare, config: { ...sampleConfig, appZones: ["example.net"], accessTeam: team, routes: { svc1: [listmonk] } }, io: new ScriptedIo() } as unknown as Context;
    const tunnel = await cloudflare.createTunnel("acc123", "stayfrosty-svc1");
    const policy = await cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-svc1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    await syncRoutes(ctx, "svc1", tunnel);
    const policies = await cloudflare.listAccessPolicies("acc123");
    expect(checkRouteAccess("svc1", listmonk, fcf.apps as never, policies, policy.id).ok).toBe(true);
    const bypassId = policies.find((p) => p.name === BYPASS_POLICY_NAME)?.id as string;
    const tampered = [...fcf.apps, { id: "x", name: "other app", type: "self_hosted", policies: [{ id: bypassId }] }];
    expect(checkRouteAccess("svc1", listmonk, tampered as never, policies, policy.id).detail).toContain("attached to other app");
    const widened = fcf.apps.map((a) => (a["name"] === "stayfrosty-svc1:listmonk" ? { ...a, destinations: [{ uri: "news.example.net" }] } : a));
    expect(checkRouteAccess("svc1", listmonk, widened as never, policies, policy.id).ok).toBe(false);
  });
});

describe("route review fixes", () => {
  const setup = () => {
    const http = new FakeHttp();
    const fcf = new FakeCloudflare(http);
    const cloudflare = new Cloudflare({ token: "cf-token-0123456789", fetch: http.fetch, sleep: noSleep });
    const config = { ...sampleConfig, appZones: ["example.net"], accessTeam: "team", routes: { svc1: [listmonk] as Route[] } };
    const ctx = { cloudflare, config, io: new ScriptedIo() } as unknown as Context;
    return { http, fcf, cloudflare, config, ctx };
  };

  it("deletes a bypass app no longer needed, and keeps the protected one", async () => {
    const s = setup();
    const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-svc1");
    await s.cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-svc1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    await syncRoutes(s.ctx, "svc1", tunnel);
    s.config.routes.svc1 = [{ ...listmonk, public: listmonk.public.filter((p) => p !== "/api/public/") }];
    await syncRoutes(s.ctx, "svc1", tunnel);
    expect(s.fcf.apps.map((a) => a["name"]).filter((n) => String(n).startsWith("stayfrosty-svc1:"))).toEqual(["stayfrosty-svc1:listmonk"]);
  });

  it("won't overwrite tunnel rules for hosts frosty didn't set up", async () => {
    const s = setup();
    const tunnel = await s.cloudflare.createTunnel("acc123", "stayfrosty-svc1");
    await s.cloudflare.createAccessPolicy("acc123", { name: "stayfrosty-svc1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    s.fcf.ingress.set(tunnel.id, [{ hostname: "ssh-svc1.example.com", service: "ssh://localhost:22" }, { hostname: "grafana.example.org", service: "http://127.0.0.1:3000" }, { service: "http_status:404" }]);
    await expect(syncRoutes(s.ctx, "svc1", tunnel)).rejects.toThrow(/routes grafana.example.org, which frosty didn't set up/);
  });

  it("tells cloudflared's own 403 from the app's", () => {
    expect(classify({ status: 403, location: null, body: "Forbidden" }, "team")).toBe("tunnel-403");
    expect(classify({ status: 403, location: null, body: '{"message":"forbidden"}' }, "team")).toBe("origin");
    expect(classify({ status: 403, location: null, body: "<html>no</html>" }, "team")).toBe("origin");
    expect(classify({ status: 404, location: null, body: "" }, "team")).toBe("tunnel-404");
    expect(classify({ status: 302, location: "https://team.cloudflareaccess.com/cdn-cgi/access/login/x", body: "" }, "team")).toBe("access");
  });

  it("reserves the box name bypass, and rejects . and .. path segments", () => {
    expect(() => assertBoxName("bypass")).toThrow(/not a valid box name/);
    expect(validateRoutes("svc1", [{ ...listmonk, public: ["/a/../b"] }], opts)).not.toEqual([]);
    expect(validateRoutes("svc1", [{ ...listmonk, public: ["/."] }], opts)).not.toEqual([]);
    expect(validateRoutes("svc1", [{ ...listmonk, public: ["/public/static.v2/"] }], opts)).toEqual([expect.stringMatching(/probe/)]);
  });
});
