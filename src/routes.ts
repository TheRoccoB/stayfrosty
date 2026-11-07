// App routes: a web app on a box, served through the box's tunnel (see DECISIONS.md, "App routes").
//
// Every path the app serves is listed in config as protected (behind Access) or public; "/" alone
// covers the whole site (a whole-site app behind Access, or a public site with protected parts). The tunnel's
// ingress is generated from that list and is itself an allowlist: unlisted paths, and any path with
// `..`, `//`, a backslash, `;` or `%`, get the tunnel's 404 and never reach the app. Protected rules
// also make cloudflared check the Access token itself, so a mistake at the edge can't open them.
// `publicExact` opens single paths inside a protected prefix, and nothing under or next to them: a
// public /api/feed leaves /api/feed/x, /api/feed/ and /api/feedx behind Access (exactUris).
// Pure: no I/O.

export interface Route {
  name: string;
  hostname: string;
  service: string;
  protected: string[];
  public: string[];
  // Exact public paths: each opens that one path, inside a protected prefix of frosty's own app.
  publicExact?: string[];
  // Protected prefixes covered by an Access app frosty doesn't own (read-only), by app name.
  externalAccess?: Record<string, string>;
  // A public path that must answer 200 from the app, so verify can tell the app from the tunnel's 404.
  probe?: string;
}

const ROUTE_NAME = /^[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// One or more /segments, each starting with a letter, digit, _ or - (so never . or ..), and an
// optional trailing slash. Linear: each segment starts at its own /. "/" alone is checked separately.
const PREFIX = /^(\/[a-z0-9_-][a-z0-9_.-]*)+\/?$/;
export const ROOT = "/";
const isPrefix = (p: unknown): p is string => typeof p === "string" && (p === ROOT || PREFIX.test(p));
const SERVICE = /^http:\/\/127\.0\.0\.1:(\d{4,5})$/;
const TEAM = /^[a-z0-9-]{1,63}$/;

// The first rule for every app hostname: 404 anything a path trick could hide in. cloudflared
// matches the decoded path, so `%` here only catches double encoding (%25..); encoded dots and
// slashes decode to `..` and `//`, which are caught as such. A `.` segment (/./) is caught too, rather
// than trusting the zone's URL normalization to collapse it.
export const SUSPICIOUS_PATH = String.raw`(\.\.|//|\\|;|%|/\.(/|$))`;

export function servicePort(service: string): number | undefined {
  const m = SERVICE.exec(service);
  const port = m === null ? NaN : Number(m[1]);
  return port >= 1024 && port <= 65535 ? port : undefined;
}

// Path `child` is inside prefix `parent`: "/api/public/" is under "/api"; "/apix" is not.
export function isUnder(child: string, parent: string): boolean {
  if (parent.endsWith("/")) {
    return child.startsWith(parent);
  }
  return child === parent || child.startsWith(`${parent}/`);
}

// "/archive" matches /archive and /archive/..., never /archivex. "/link/" matches /link/... only.
// Protected prefixes match case-insensitively (Go regexp's (?i), which cloudflared uses): /ADMIN gets
// the Access check too, instead of falling through to a public "/" (or the 404), whatever the app
// does with case. Public prefixes stay case-sensitive, so they never open more than listed.
export function prefixRegex(prefix: string, opts: { caseInsensitive?: boolean } = {}): string {
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
  const re = prefix.endsWith("/") ? `^${escaped}` : `^${escaped}(/|$)`;
  return opts.caseInsensitive === true ? `(?i)${re}` : re;
}

// Public paths inside a protected prefix: each needs an Access bypass, or Access would ask for a login.
export function bypassPaths(route: Route): string[] {
  return route.public.filter((p) => route.protected.some((q) => p !== q && isUnder(p, q)));
}

// Protected prefixes frosty's own Access app covers (the rest belong to an external app).
export function frostyProtected(route: Route): string[] {
  return route.protected.filter((p) => route.externalAccess?.[p] === undefined);
}

export function exactPaths(route: Route): string[] {
  return route.publicExact ?? [];
}

// An exact path matches itself only: no subpaths, no trailing slash, case-sensitive.
export function exactRegex(path: string): string {
  return `^${path.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&")}$`;
}

// The Access destinations of frosty's own app: each protected prefix, plus "<exact path>/*" for each
// exact public path. Access matches a destination's path and everything under it, so the bypass for an
// exact path also covers its subpaths; the more specific "/*" destination takes them back.
export function protectedUris(route: Route): string[] {
  return [
    ...frostyProtected(route).map((p) => accessUri(route.hostname, p)),
    ...exactPaths(route).map((e) => `${accessUri(route.hostname, e)}/*`),
  ];
}

// The bypass app's destinations: public prefixes inside protected ones, and the exact public paths.
export function bypassUris(route: Route): string[] {
  return [...bypassPaths(route), ...exactPaths(route)].map((p) => accessUri(route.hostname, p));
}

// stayfrosty-<box>:<route> and stayfrosty-<box>:<route>:public. The colon can't be in a box name,
// so a route app is never mistaken for another box's app (box "web1-x" vs route "x" of "web1").
export function routeAppName(box: string, route: Pick<Route, "name">): string {
  return `stayfrosty-${box}:${route.name}`;
}

export function publicAppName(box: string, route: Pick<Route, "name">): string {
  return `${routeAppName(box, route)}:public`;
}

export function isRouteAppOf(box: string, name: string): boolean {
  return name.startsWith(`stayfrosty-${box}:`);
}

// The Access destination for a prefix: "news.example.net/api" covers /api and everything under it.
export function accessUri(hostname: string, prefix: string): string {
  const path = prefix.replace(/\/$/, "");
  return path === "" ? hostname : `${hostname}${path}`;
}

export function inZones(hostname: string, zones: string[]): boolean {
  return zones.some((z) => hostname === z || hostname.endsWith(`.${z}`));
}

// Problems with a box's routes, given the rest of the config. Empty when usable.
export function validateRoutes(box: string, routes: unknown, opts: { domain: string; appZones: string[]; accessTeam: string | undefined }): string[] {
  const problems: string[] = [];
  const at = `routes.${box}`;
  if (!Array.isArray(routes)) {
    return [`${at} must be a list`];
  }
  if (routes.length > 0 && (opts.accessTeam === undefined || !TEAM.test(opts.accessTeam))) {
    problems.push("accessTeam (your Cloudflare Access team name, as in <team>.cloudflareaccess.com) is needed for routes");
  }
  const names = new Set<string>();
  for (const [i, raw] of routes.entries()) {
    const where = `${at}[${i}]`;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      problems.push(`${where} must be an object`);
      continue;
    }
    const r = raw as Record<string, unknown>;
    const extra = Object.keys(r).filter((k) => !["name", "hostname", "service", "protected", "public", "publicExact", "externalAccess", "probe"].includes(k));
    if (extra.length > 0) {
      problems.push(`${where} has unknown keys: ${extra.join(", ")}`);
    }
    if (typeof r["name"] !== "string" || !ROUTE_NAME.test(r["name"])) {
      problems.push(`${where}.name must be lowercase letters, digits and dashes (1-20)`);
    } else if (names.has(r["name"])) {
      problems.push(`${where}.name ${r["name"]} is used twice`);
    } else {
      names.add(r["name"]);
    }
    const hostname = r["hostname"];
    if (typeof hostname !== "string" || !HOSTNAME.test(hostname)) {
      problems.push(`${where}.hostname must be one exact host name (no wildcards)`);
    } else if (!inZones(hostname, opts.appZones) || inZones(hostname, [opts.domain]) || hostname.startsWith("ssh-")) {
      problems.push(`${where}.hostname ${hostname} must be in appZones, and never in ${opts.domain} or an ssh-* name`);
    }
    if (typeof r["service"] !== "string" || servicePort(r["service"]) === undefined) {
      problems.push(`${where}.service must be http://127.0.0.1:<port>, port 1024-65535`);
    }
    const lists: Record<string, string[]> = {};
    for (const key of ["protected", "public"]) {
      const list = r[key];
      if (!Array.isArray(list) || list.some((p) => !isPrefix(p) || /\/\//.test(p))) {
        problems.push(`${where}.${key} must be a list of paths like /, /admin or /link/ (lowercase letters, digits, _ . -)`);
        lists[key] = [];
      } else {
        lists[key] = list as string[];
      }
    }
    const prot = lists["protected"] ?? [];
    const pub = lists["public"] ?? [];
    if (prot.length + pub.length === 0) {
      problems.push(`${where} lists no paths`);
    }
    for (const p of [...prot, ...pub]) {
      if ([...prot, ...pub].filter((q) => q === p).length > 1) {
        problems.push(`${where} lists ${p} twice`);
      }
    }
    // A protected path under a public one would be public, except under a public "/": the ingress puts
    // every longer prefix before "/", so cloudflared still checks Access on it (a public site with
    // protected parts, like /admin).
    for (const q of prot) {
      for (const p of pub) {
        if (q !== p && p !== ROOT && isUnder(q, p)) {
          problems.push(`${where}: protected ${q} is under public ${p}, which would make it public`);
        }
      }
    }
    const exactRaw = r["publicExact"];
    let exact: string[] = [];
    if (exactRaw !== undefined) {
      if (!Array.isArray(exactRaw) || exactRaw.some((p) => !isPrefix(p) || p === ROOT || p.endsWith("/") || /\/\//.test(p))) {
        problems.push(`${where}.publicExact must be a list of exact paths like /api/feed (no trailing slash, not "/")`);
      } else {
        exact = exactRaw as string[];
      }
    }
    const externalMap = r["externalAccess"] !== null && typeof r["externalAccess"] === "object" && !Array.isArray(r["externalAccess"]) ? (r["externalAccess"] as Record<string, unknown>) : {};
    for (const e of exact) {
      if (exact.filter((x) => x === e).length > 1 || prot.includes(e) || pub.includes(e)) {
        problems.push(`${where} lists ${e} twice`);
        continue;
      }
      // It must sit inside a protected prefix of frosty's own app (which gets "<e>/*"), and no public
      // prefix may cover it already (that would make it public with its subpaths).
      if (!prot.some((q) => isUnder(e, q) && externalMap[q] === undefined)) {
        problems.push(`${where}.publicExact ${e} must be under a protected path of frosty's own Access app`);
      } else if (pub.some((p) => p !== ROOT && isUnder(e, p))) {
        problems.push(`${where}.publicExact ${e} is under public ${pub.find((p) => p !== ROOT && isUnder(e, p))}, which already makes it and its subpaths public`);
      }
    }
    const external = r["externalAccess"];
    if (external !== undefined) {
      if (external === null || typeof external !== "object" || Array.isArray(external)) {
        problems.push(`${where}.externalAccess must map protected paths to Access app names`);
      } else {
        for (const [p, app] of Object.entries(external as Record<string, unknown>)) {
          if (!prot.includes(p) || typeof app !== "string" || app.length === 0 || app.startsWith("stayfrosty-")) {
            problems.push(`${where}.externalAccess.${p} must be a protected path mapped to the name of an Access app frosty doesn't own`);
          } else if (p === ROOT) {
            problems.push(`${where}.externalAccess can't cover "/": a whole-site app gets frosty's own Access app`);
          }
        }
      }
    }
    // One Access app per hostname: all protected prefixes on frosty's app, or all on one external app.
    if (external !== null && typeof external === "object" && !Array.isArray(external)) {
      const apps = new Set(prot.map((p) => (external as Record<string, unknown>)[p] ?? "(frosty's own app)"));
      if (apps.size > 1) {
        problems.push(`${where}: protected paths must all use one Access app (two apps on one hostname share a login cookie and break apps that call their API from the browser)`);
      }
    }
    const probe = r["probe"];
    if (probe !== undefined && (typeof probe !== "string" || !isPrefix(probe) || !(exact.includes(probe) || pub.some((p) => isUnder(probe, p) && !prot.some((q) => isUnder(probe, q)))))) {
      problems.push(`${where}.probe must be a path under a public prefix that isn't protected`);
    }
  }
  return problems;
}

// Every hostname belongs to one route of one box.
export function validateRouteHostnames(all: Record<string, Route[]>): string[] {
  const seen = new Map<string, string>();
  const problems: string[] = [];
  for (const [box, routes] of Object.entries(all)) {
    for (const r of routes) {
      const owner = seen.get(r.hostname);
      if (owner !== undefined) {
        problems.push(`hostname ${r.hostname} is used by ${owner} and ${box}/${r.name}`);
      }
      seen.set(r.hostname, `${box}/${r.name}`);
    }
  }
  return problems;
}

export interface IngressRule {
  hostname?: string;
  path?: string;
  service: string;
  originRequest?: { access: { required: true; teamName: string; audTag: string[] } };
}

// The order cloudflared should try prefixes in (first match wins): the most specific first, so
// /api/public/ comes before /api, and every prefix before "/". Prefixes that don't nest can't both match
// a path, so length alone orders the ones that do; ties keep config order, public before protected.
function bySpecificity(a: string, b: string): number {
  if (a === ROOT || b === ROOT) {
    return a === b ? 0 : a === ROOT ? 1 : -1;
  }
  return b.length - a.length;
}

// One route's rules: the trick-path 404, the exact public paths (each matches one path, so order among
// them doesn't matter), then every listed prefix by specificity (protected ones with cloudflared's own
// Access check), then a 404 for everything else on the host.
export function routeIngress(route: Route, teamName: string, audFor: (prefix: string) => string[]): IngressRule[] {
  const { hostname, service } = route;
  const listed = [...route.public.map((p) => ({ p, protect: false })), ...route.protected.map((p) => ({ p, protect: true }))];
  const ordered = listed.map((x, i) => ({ ...x, i })).sort((a, b) => bySpecificity(a.p, b.p) || a.i - b.i);
  return [
    { hostname, path: SUSPICIOUS_PATH, service: "http_status:404" },
    ...exactPaths(route).map((e): IngressRule => ({ hostname, path: exactRegex(e), service })),
    ...ordered.map(({ p, protect }): IngressRule => (protect
      ? { hostname, path: prefixRegex(p, { caseInsensitive: true }), service, originRequest: { access: { required: true as const, teamName, audTag: audFor(p) } } }
      : { hostname, path: prefixRegex(p), service })),
    { hostname, service: "http_status:404" },
  ];
}

// The whole tunnel: SSH, each route, the catch-all 404.
export function boxIngress(sshHostname: string, routes: { route: Route; audFor: (prefix: string) => string[] }[], teamName: string): IngressRule[] {
  return [{ hostname: sshHostname, service: "ssh://localhost:22" }, ...routes.flatMap((r) => routeIngress(r.route, teamName, r.audFor)), { service: "http_status:404" }];
}

// Compares what matters, ignoring keys Cloudflare adds (an empty originRequest, and so on).
export function ingressKey(rule: { hostname?: string; path?: string; service: string; originRequest?: unknown }): string {
  const access = (rule.originRequest as { access?: { required?: boolean; teamName?: string; audTag?: string[] } } | undefined)?.access;
  const extraOrigin = Object.keys((rule.originRequest as object | undefined) ?? {}).filter((k) => k !== "access");
  return JSON.stringify([
    rule.hostname ?? "",
    rule.path ?? "",
    rule.service,
    access === undefined ? null : [access.required === true, access.teamName ?? "", [...(access.audTag ?? [])].sort()],
    extraOrigin.sort(),
  ]);
}

export function sameIngressRules(a: IngressRule[] | { hostname?: string; path?: string; service: string; originRequest?: unknown }[], b: IngressRule[]): boolean {
  return a.length === b.length && a.every((r, i) => ingressKey(r) === ingressKey(b[i] as IngressRule));
}
