// App routes: a web app on a box, served through the box's tunnel (see DECISIONS.md, "App routes").
//
// Every path the app serves is listed in config as protected (behind Access) or public. The tunnel's
// ingress is generated from that list and is itself an allowlist: unlisted paths, and any path with
// `..`, `//`, a backslash, `;` or `%`, get the tunnel's 404 and never reach the app. Protected rules
// also make cloudflared check the Access token itself, so a mistake at the edge can't open them.
// Pure: no I/O.

export interface Route {
  name: string;
  hostname: string;
  service: string;
  protected: string[];
  public: string[];
  // Protected prefixes covered by an Access app frosty doesn't own (read-only), by app name.
  externalAccess?: Record<string, string>;
  // A public path that must answer 200 from the app, so verify can tell the app from the tunnel's 404.
  probe?: string;
}

const ROUTE_NAME = /^[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// One or more /segments, each starting with a letter, digit, _ or - (so never . or ..), and an
// optional trailing slash. Linear: each segment starts at its own /.
const PREFIX = /^(\/[a-z0-9_-][a-z0-9_.-]*)+\/?$/;
const SERVICE = /^http:\/\/127\.0\.0\.1:(\d{4,5})$/;
const TEAM = /^[a-z0-9-]{1,63}$/;

// The first rule for every app hostname: 404 anything a path trick could hide in. cloudflared
// matches the decoded path, so `%` here only catches double encoding (%25..); encoded dots and
// slashes decode to `..` and `//`, which are caught as such.
export const SUSPICIOUS_PATH = String.raw`(\.\.|//|\\|;|%)`;

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
export function prefixRegex(prefix: string): string {
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
  return prefix.endsWith("/") ? `^${escaped}` : `^${escaped}(/|$)`;
}

// Public paths inside a protected prefix: each needs an Access bypass, or Access would ask for a login.
export function bypassPaths(route: Route): string[] {
  return route.public.filter((p) => route.protected.some((q) => p !== q && isUnder(p, q)));
}

// Protected prefixes frosty's own Access app covers (the rest belong to an external app).
export function frostyProtected(route: Route): string[] {
  return route.protected.filter((p) => route.externalAccess?.[p] === undefined);
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
    const extra = Object.keys(r).filter((k) => !["name", "hostname", "service", "protected", "public", "externalAccess", "probe"].includes(k));
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
      if (!Array.isArray(list) || list.some((p) => typeof p !== "string" || !PREFIX.test(p) || p === "/" || /\/\//.test(p))) {
        problems.push(`${where}.${key} must be a list of paths like /admin or /link/ (lowercase letters, digits, _ . -)`);
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
    for (const q of prot) {
      for (const p of pub) {
        if (q !== p && isUnder(q, p)) {
          problems.push(`${where}: protected ${q} is under public ${p}, which would make it public`);
        }
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
    if (probe !== undefined && (typeof probe !== "string" || !PREFIX.test(probe) || !pub.some((p) => isUnder(probe, p) && !prot.some((q) => isUnder(probe, q))))) {
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

// One route's rules: the trick-path 404, public prefixes (so /api/public/ wins over /api), protected
// prefixes with cloudflared's own Access check, then a 404 for everything else on the host.
export function routeIngress(route: Route, teamName: string, audFor: (prefix: string) => string[]): IngressRule[] {
  const { hostname, service } = route;
  return [
    { hostname, path: SUSPICIOUS_PATH, service: "http_status:404" },
    ...route.public.map((p) => ({ hostname, path: prefixRegex(p), service })),
    ...route.protected.map((p) => ({ hostname, path: prefixRegex(p), service, originRequest: { access: { required: true as const, teamName, audTag: audFor(p) } } })),
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
