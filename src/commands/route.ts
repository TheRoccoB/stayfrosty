import { assertBoxName, buildContext, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { boxRoutes, findEdge, routeApps, routeAuds, syncRoutes } from "../edge.ts";
import { accessUri, bypassPaths, frostyProtected, publicAppName, routeAppName } from "../routes.ts";

export interface RouteOptions {
  action: string | undefined;
  box: string | undefined;
}

// frosty route plan <box>: what the box's routes need (read-only).
// frosty route sync <box>: make Cloudflare match: Access apps first, then the ingress, then remove
// apps of routes taken out of config. DNS for the route hostnames isn't frosty's to write; the plan
// prints the records to add.
export async function runRoute(deps: Deps, opts: RouteOptions): Promise<number> {
  if (opts.action !== "plan" && opts.action !== "sync") {
    throw new FrostyError("frosty route needs plan or sync.", "frosty route plan <box>   or   frosty route sync <box>");
  }
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  const { io, cloudflare, config } = ctx;
  const edge = await findEdge(ctx, box);
  if (edge.tunnel === undefined) {
    throw new FrostyError(`${box} has no frosty tunnel.`, `Set the box up first: frosty new ${box}, or frosty adopt ${box}.`);
  }
  const routes = boxRoutes(ctx, box);
  if (opts.action === "sync") {
    await syncRoutes(ctx, box, edge.tunnel);
  }
  const apps = await cloudflare.listAccessApps(config.accountId);
  if (routes.length === 0) {
    io.out(`${box} has no routes in config.${opts.action === "sync" ? " Its tunnel carries SSH only." : ""}`);
    return 0;
  }
  for (const route of routes) {
    const have = routeApps(apps, box, route);
    io.out(`${route.name}: ${route.hostname} -> ${route.service}`);
    io.out(`  public: ${route.public.join(" ")}`);
    io.out(`  protected: ${route.protected.join(" ")}`);
    if (frostyProtected(route).length > 0) {
      io.out(`  Access ${routeAppName(box, route)} (your emails): ${frostyProtected(route).map((p) => accessUri(route.hostname, p)).join(", ")}${have.app === undefined ? "  [missing]" : ""}`);
    }
    if (bypassPaths(route).length > 0) {
      io.out(`  Access ${publicAppName(box, route)} (bypass): ${bypassPaths(route).map((p) => accessUri(route.hostname, p)).join(", ")}${have.publicApp === undefined ? "  [missing]" : ""}`);
    }
    for (const [prefix, name] of Object.entries(route.externalAccess ?? {})) {
      io.out(`  Access ${name} (not frosty's, read only): ${accessUri(route.hostname, prefix)}${have.external[prefix] === undefined ? "  [missing]" : ""}`);
    }
    io.out(`  In the tunnel's ingress: ${routeAuds(have) === undefined ? "no (an Access app is missing; run frosty route sync)" : "yes"}`);
    io.out(`  DNS (add it outside frosty): ${route.hostname} CNAME ${edge.tunnel.id}.cfargotunnel.com, proxied, comment "stayfrosty route ${box} ${route.name}"`);
  }
  io.out("");
  io.out(`Then check it: frosty verify ${box}`);
  return 0;
}
