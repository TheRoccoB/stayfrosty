import { randomBytes } from "node:crypto";
import { BYPASS_POLICY_NAME, isOurBypassPolicy, isOurEmailPolicy, type CfAccessApp, type CfAccessPolicy } from "../cloudflare.ts";
import { appCovers, appMatches, describeIncludes, externalPolicyProblems, routeApps } from "../edge.ts";
import { accessUri, bypassPaths, frostyProtected, publicAppName, routeAppName, servicePort, type Route } from "../routes.ts";
import type { RawGet, RawResponse } from "../rawget.ts";
import { parseSs, type Listener } from "./listeners.ts";
import { fail, pass, type CheckResult } from "./types.ts";

// Checks of a box's app routes (routes.ts). The outside checks send each path exactly as written
// (no dot-segment cleanup, like curl --path-as-is), with no credentials.

type Answer = "access" | "tunnel-404" | "tunnel-403" | "origin";

export function classify(r: RawResponse, team: string): Answer {
  if (r.status >= 300 && r.status < 400 && r.location !== null) {
    try {
      const url = new URL(r.location);
      if (url.hostname === `${team}.cloudflareaccess.com` && url.pathname.startsWith("/cdn-cgi/access/login/")) {
        return "access";
      }
    } catch {
      // not a URL: falls through to origin
    }
  }
  // cloudflared's http_status:404 answers with an empty body, and its own Access check (a protected
  // rule reached without a token) with a 403 that isn't JSON or HTML. Anything else came from the app.
  if (r.status === 404 && r.body.trim() === "") {
    return "tunnel-404";
  }
  if (r.status === 403 && !/^\s*[{[<]/.test(r.body)) {
    return "tunnel-403";
  }
  return "origin";
}

// Paths that try to slip past Access or the ingress allowlist (the-bouncer's list).
const TRICKS = [
  "/api/public/../settings",
  "/api/public/%2e%2e/settings",
  "/api/public/..%2fsettings",
  "/api/public/%2e%2e%2fsettings",
  "//api/settings",
  "/api/./settings",
  "/API/settings",
  "/admin%2f..",
  "/api;/settings",
  // Not under /api to the edge, but cloudflared decodes it to /api/settings: its own check must stop it.
  "/api%2fsettings",
  // The bypass is /api/public/... only.
  "/api/public",
  "/api/publicx",
];

export async function checkRouteOutside(get: RawGet, route: Route, team: string): Promise<CheckResult> {
  const name = `Route ${route.name}: ${route.hostname} from outside`;
  const rand = randomBytes(6).toString("hex");
  const problems: string[] = [];
  const ask = async (path: string): Promise<Answer | string> => {
    try {
      return classify(await get(route.hostname, path), team);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return code === "ENOTFOUND" ? "no DNS record yet (add the CNAME from frosty route plan)" : `request failed (${error instanceof Error ? error.message : String(error)})`;
    }
  };
  const expect = async (path: string, ok: Answer[], why: string): Promise<void> => {
    const got = await ask(path);
    if (!ok.includes(got as Answer)) {
      problems.push(`${path} got ${got}, want ${ok.join(" or ")} (${why})`);
    }
  };
  for (const p of route.protected) {
    await expect(p, ["access"], "protected");
    await expect(`${p.replace(/\/$/, "")}/${rand}`, ["access"], "protected");
  }
  if (route.protected.includes("/api")) {
    await expect("/api/settings", ["access"], "protected");
  }
  for (const t of TRICKS) {
    await expect(t, ["access", "tunnel-404", "tunnel-403"], "path trick");
  }
  for (const p of [`/${rand}`, "/install", `${(route.protected[0] ?? route.public[0] ?? "/x").replace(/\/$/, "")}${rand}`]) {
    await expect(p, ["tunnel-404"], "not listed");
  }
  for (const p of route.public) {
    const path = p.endsWith("/") ? `${p}${rand}` : p;
    const got = await ask(path);
    if (got === "access") {
      problems.push(`${path} asks for the Access login, but it's public`);
    }
  }
  if (route.probe !== undefined) {
    try {
      const r = await get(route.hostname, route.probe);
      if (r.status !== 200) {
        problems.push(`${route.probe} got HTTP ${r.status}, want 200 from the app`);
      }
    } catch (error) {
      problems.push(`${route.probe} request failed (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), `A protected or unlisted path is reachable, or the app isn't answering. Run: frosty route sync <box>, then check the app on the box.`);
  }
  return pass(name, `protected paths get the Access login, ${TRICKS.length} path tricks are stopped, unlisted paths 404${route.probe === undefined ? "" : ", the app answers"}`);
}

// The route's Access apps are exactly frosty's shape, and the bypass policy is on no other app.
export function checkRouteAccess(box: string, route: Route, apps: CfAccessApp[], policies: CfAccessPolicy[], boxPolicyId: string | undefined): CheckResult {
  const name = `Route ${route.name}: Access apps`;
  const problems: string[] = [];
  const have = routeApps(apps, box, route);
  const emailPolicy = policies.find((p) => p.id === boxPolicyId);
  const bypass = policies.find((p) => p.name === BYPASS_POLICY_NAME);
  const prot = frostyProtected(route);
  if (prot.length > 0) {
    const want = prot.map((p) => accessUri(route.hostname, p));
    if (have.app === undefined || emailPolicy === undefined || !isOurEmailPolicy(emailPolicy) || !appMatches(have.app, want, [emailPolicy.id])) {
      problems.push(`${routeAppName(box, route)} should cover exactly ${want.join(", ")} with only frosty's email policy`);
    }
  } else if (have.app !== undefined) {
    problems.push(`${routeAppName(box, route)} exists but covers nothing`);
  }
  const externals: string[] = [];
  const bp = bypassPaths(route);
  if (bp.length > 0) {
    const want = bp.map((p) => accessUri(route.hostname, p));
    if (have.publicApp === undefined || bypass === undefined || !isOurBypassPolicy(bypass) || !appMatches(have.publicApp, want, [bypass.id])) {
      problems.push(`${publicAppName(box, route)} should cover exactly ${want.join(", ")} with only ${BYPASS_POLICY_NAME}`);
    }
  } else if (have.publicApp !== undefined) {
    problems.push(`${publicAppName(box, route)} exists but nothing needs a bypass`);
  }
  for (const [prefix, appName] of Object.entries(route.externalAccess ?? {})) {
    const ext = have.external[prefix];
    if (ext === undefined || !appCovers(ext, accessUri(route.hostname, prefix))) {
      problems.push(`external app ${appName} doesn't cover ${accessUri(route.hostname, prefix)}`);
    } else {
      problems.push(...externalPolicyProblems(ext));
      externals.push(`${appName} on ${prefix} lets in ${describeIncludes(ext)}`);
    }
  }
  if (bypass !== undefined) {
    const on = apps.filter((a) => (a.policies ?? []).some((p) => p.id === bypass.id)).map((a) => a.name);
    const wrong = on.filter((n) => !(n.startsWith("stayfrosty-") && n.endsWith(":public")));
    if (wrong.length > 0) {
      problems.push(`${BYPASS_POLICY_NAME} is attached to ${wrong.join(", ")}, which aren't route bypass apps`);
    }
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), `Run: frosty route sync ${box}`);
  }
  return pass(name, [`${[prot.length > 0 ? routeAppName(box, route) : "", bp.length > 0 ? publicAppName(box, route) : ""].filter((x) => x !== "").join(" and ") || "external apps only"} as configured`, ...externals].join("; "));
}

// On the box: the app's port listens on 127.0.0.1 only, and nothing listens on Postgres's port.
export function checkRoutePorts(routes: Route[], ssText: string): CheckResult {
  const name = "Route apps listen on 127.0.0.1 only; no Postgres port";
  const listeners: Listener[] = parseSs(ssText).filter((l) => l.proto === "tcp");
  const problems: string[] = [];
  for (const r of routes) {
    const port = servicePort(r.service);
    const on = listeners.filter((l) => l.port === port);
    if (on.length === 0) {
      problems.push(`nothing listens on ${r.service} (${r.name})`);
    }
    for (const l of on.filter((x) => x.address !== "127.0.0.1")) {
      problems.push(`${r.name}'s port ${String(port)} also listens on ${l.address}`);
    }
  }
  for (const l of listeners.filter((x) => x.port === 5432)) {
    problems.push(`Postgres's port 5432 is published on ${l.address}`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), "Bind the app to 127.0.0.1:<port> only, and remove any ports: mapping for Postgres (it stays on the Docker network).");
  }
  return pass(name, routes.map((r) => r.service).join(", "));
}

export function checkRouteMissing(box: string, route: Route): CheckResult {
  return fail(`Route ${route.name}: Access apps`, "an Access app the route needs is missing, so its paths are not in the ingress", `Run: frosty route sync ${box}`);
}
