import { randomBytes } from "node:crypto";
import { BYPASS_POLICY_NAME, isOurBypassPolicy, isOurEmailPolicy, isOurTokenPolicy, serviceTokenIds, type CfAccessApp, type CfAccessPolicy } from "../cloudflare.ts";
import { appCovers, appMatches, describeIncludes, externalPolicyProblems, routeApps, routeEmailPoliciesElsewhere, sameEmails } from "../edge.ts";
import { ROOT, accessUri, isUnder, bypassUris, exactPaths, frostyProtected, protectedUris, publicAppName, routeAppName, routeEmailPolicyName, routeServiceTokens, routeTokenPolicyName, servicePort, type Route } from "../routes.ts";
import type { RouteTokenPlan } from "../servicetokens.ts";
import { missingServiceTokenHint, SERVICE_TOKEN_ELSEWHERE_FIX, SERVICE_TOKEN_EXPIRED_FIX, tokenExpiry } from "./edge.ts";
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
  // A trick path must never reach the app inside a protected prefix. On a public "/" site, a trick that
  // only lands on public paths (read as an app might: case folded, /./ collapsed) may reach it.
  const lands = (path: string): string => path.toLowerCase().replace(/\/\.(?=\/|$)/g, "");
  for (const t of TRICKS) {
    const harmless = route.public.includes(ROOT) && !route.protected.some((q) => isUnder(lands(t), q));
    await expect(t, harmless ? ["access", "tunnel-404", "tunnel-403", "origin"] : ["access", "tunnel-404", "tunnel-403"], "path trick");
  }
  // Paths no prefix lists get the tunnel's 404, unless "/" is listed: then there are no unlisted paths,
  // and they must get the Access login (protected "/") or reach the app (public "/").
  const notListed: [Answer[], string] = route.protected.includes(ROOT)
    ? [["access"], "protected by /"]
    : route.public.includes(ROOT)
      ? [["origin"], "public by /"]
      : [["tunnel-404"], "not listed"];
  for (const p of [`/${rand}`, "/install", `${(route.protected[0] ?? route.public[0] ?? "/x").replace(/\/$/, "") || "/x"}${rand}`]) {
    await expect(p, ...notListed);
  }
  // An exact public path reaches the app through the tunnel (any answer from the app: it may well say
  // 401 without its own token), and nothing under or next to it does. Those get the login, or
  // cloudflared's own 403 when the edge lets them by (Access's path match is a prefix): both stop
  // short of the app.
  for (const e of exactPaths(route)) {
    await expect(e, ["origin"], "public, exact path");
    for (const near of [`${e}/`, `${e}/${rand}`, `${e}${rand}`, e.toUpperCase()]) {
      await expect(near, ["access", "tunnel-403"], `only ${e} itself is public`);
    }
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
  return pass(name, `protected paths get the Access login, ${TRICKS.length} path tricks are stopped, ${route.protected.includes(ROOT) ? "every other path asks for the login" : route.public.includes(ROOT) ? "every other path reaches the app" : "unlisted paths 404"}${route.probe === undefined ? "" : ", the app answers"}`);
}

// The route's Access apps are exactly frosty's shape, and the bypass policy is on no other app.
// With serviceTokens on the route, frosty's protected app carries the route's token policy too
// (`tokenPolicy`, checked in full by checkRouteServiceTokens).
export function checkRouteAccess(box: string, route: Route, apps: CfAccessApp[], policies: CfAccessPolicy[], boxPolicyId: string | undefined, tokenPolicy?: CfAccessPolicy): CheckResult {
  const name = `Route ${route.name}: Access apps`;
  const problems: string[] = [];
  const have = routeApps(apps, box, route);
  // A route with its own emails uses its own email policy instead of the box's (checkRouteEmails
  // checks that policy's contents).
  const emailPolicy = route.emails === undefined ? policies.find((p) => p.id === boxPolicyId) : policies.find((p) => p.name === routeEmailPolicyName(box, route));
  const emailLabel = route.emails === undefined ? "frosty's email policy" : routeEmailPolicyName(box, route);
  const bypass = policies.find((p) => p.name === BYPASS_POLICY_NAME);
  const prot = frostyProtected(route);
  if (prot.length > 0) {
    const want = protectedUris(route);
    const tokens = routeServiceTokens(route).length > 0;
    const ids = emailPolicy === undefined ? [] : [emailPolicy.id, ...(tokens && tokenPolicy !== undefined ? [tokenPolicy.id] : [])];
    if (have.app === undefined || emailPolicy === undefined || !isOurEmailPolicy(emailPolicy) || (tokens && tokenPolicy === undefined) || !appMatches(have.app, want, ids)) {
      problems.push(`${routeAppName(box, route)} should cover exactly ${want.join(", ")} with only ${emailLabel}${tokens ? ` and ${routeTokenPolicyName(box, route)}` : ""}`);
    }
  } else if (have.app !== undefined) {
    problems.push(`${routeAppName(box, route)} exists but covers nothing`);
  }
  const externals: string[] = [];
  const bp = bypassUris(route);
  if (bp.length > 0) {
    const want = bp;
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

// A route's own emails: its email policy lets in exactly the configured emails, frosty's shape (allow,
// emails only), it is on no app but the route's own, and that app offers every login method of the
// team (allowed_idps empty), so people without the other login can use the one-time PIN.
export function checkRouteEmails(box: string, route: Route, policy: CfAccessPolicy | undefined, apps: CfAccessApp[], allEmailPolicies: CfAccessPolicy[]): CheckResult {
  const policyName = routeEmailPolicyName(box, route);
  const name = `Route ${route.name}: its own emails`;
  const sync = `Run: frosty route sync ${box}`;
  const problems: string[] = [];
  const emails = route.emails ?? [];
  if (policy === undefined) {
    problems.push(`no Access policy ${policyName}`);
  } else {
    if (!isOurEmailPolicy(policy) || policy.name !== policyName) {
      problems.push(`${policyName} is not only emails (allow, email includes, no require or exclude)`);
    }
    const have = (policy.include ?? []).map((r) => r.email?.email ?? "");
    if (!sameEmails(have, emails)) {
      const want = new Set(emails.map((e) => e.toLowerCase()));
      const got = new Set(have.map((e) => e.toLowerCase()));
      const extra = [...got].filter((e) => !want.has(e));
      const missing = [...want].filter((e) => !got.has(e));
      problems.push(`${policyName} doesn't match the route's emails${extra.length > 0 ? `; lets in ${extra.join(", ")} too` : ""}${missing.length > 0 ? `; leaves out ${missing.join(", ")}` : ""}`);
    }
  }
  problems.push(...routeEmailPoliciesElsewhere(box, allEmailPolicies, apps).filter((p) => p.startsWith(`${policyName} `)));
  const app = routeApps(apps, box, route).app;
  const idps = app?.allowed_idps ?? [];
  if (idps.length > 0) {
    problems.push(`${routeAppName(box, route)} offers only ${idps.length} login method(s) (allowed_idps), not every one of the team`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), sync);
  }
  return pass(name, `${policyName} lets in ${emails.length} email(s), on ${routeAppName(box, route)} only, every login method offered`);
}

// Route email policies that no configured route wants: route sync deletes them.
export function checkStrayRouteEmailPolicies(box: string, strays: CfAccessPolicy[]): CheckResult | undefined {
  if (strays.length === 0) {
    return undefined;
  }
  return fail("Route email policies", `${strays.map((p) => p.name).join(", ")}: no route of ${box} lists its own emails for it`, `Run: frosty route sync ${box}`);
}

// A route's service tokens: its token policy lets in exactly the configured tokens and nothing else,
// none has expired, and none also opens another box, route or app.
export function checkRouteServiceTokens(box: string, route: Route, plan: RouteTokenPlan): CheckResult {
  const name = `Route ${route.name}: service tokens`;
  const problems: string[] = [];
  const fixes = new Set<string>();
  const sync = `Run: frosty route sync ${box}`;
  const add = (problem: string, fix: string): void => {
    problems.push(problem);
    fixes.add(fix);
  };
  const { policy, policyName } = plan;
  if (policy === undefined) {
    add(`no Access policy ${policyName}`, sync);
  } else {
    if (!isOurTokenPolicy(policy, box, route.name)) {
      add(`${policyName} is not only service tokens (non_identity, service_token includes, no require or exclude)`, sync);
    }
    const want = new Set(plan.tokens.map((t) => t.token.id));
    const have = new Set(serviceTokenIds(policy.include));
    const extra = [...have].filter((id) => !want.has(id));
    const missing = plan.tokens.filter((t) => !have.has(t.token.id)).map((t) => t.name);
    if (extra.length > 0) {
      add(`${policyName} lets in token id(s) not in the route's serviceTokens: ${extra.join(", ")}`, sync);
    }
    if (missing.length > 0) {
      add(`${policyName} does not include ${missing.join(", ")}`, sync);
    }
  }
  for (const problem of plan.problems) {
    add(problem, missingServiceTokenHint());
  }
  if (plan.elsewhere.length > 0) {
    add(`a token of ${box}/${route.name} also opens: ${plan.elsewhere.join("; ")}`, SERVICE_TOKEN_ELSEWHERE_FIX);
  }
  for (const t of plan.tokens) {
    const expiry = tokenExpiry(t.token, plan.now);
    if (expiry.expired) {
      add(`service token ${t.name} ${expiry.text}`, SERVICE_TOKEN_EXPIRED_FIX);
    }
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), [...fixes].join(" "));
  }
  const listing = plan.tokens.map((t) => {
    const e = tokenExpiry(t.token, plan.now);
    return `${t.name} (${e.days === undefined ? "no expiry" : `${e.days} days left${e.soon ? ", renew soon" : ""}`})`;
  });
  return pass(name, `${policyName} lets in ${listing.join(", ")}`);
}

// Route token policies that no configured route wants: route sync deletes them.
export function checkStrayRouteTokenPolicies(box: string, strays: CfAccessPolicy[]): CheckResult | undefined {
  if (strays.length === 0) {
    return undefined;
  }
  return fail("Route service token policies", `${strays.map((p) => p.name).join(", ")}: no route of ${box} lists service tokens for it`, `Run: frosty route sync ${box}`);
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
