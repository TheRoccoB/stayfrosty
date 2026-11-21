import { assertBoxName, buildContext, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { boxRoutes, checkExternalAccess, describeIncludes, findEdge, routeApps, routeAuds, syncRoutes, syncRun } from "../edge.ts";
import { tokenExpiry } from "../checks/edge.ts";
import { bypassUris, exactPaths, frostyProtected, isRouteEmailPolicyOf, isRouteTokenPolicyOf, protectedUris, publicAppName, routeAppName, routeEmailPolicyName, routeServiceTokens, routeTokenPolicyName } from "../routes.ts";
import { planRouteTokens } from "../servicetokens.ts";

export interface RouteOptions {
  action: string | undefined;
  box: string | undefined;
  dryRun?: boolean;
}

// frosty route plan <box>: what the box's routes need (read-only).
// frosty route sync <box>: make Cloudflare match: Access apps first, then the ingress, then remove
// apps of routes taken out of config. DNS for the route hostnames isn't frosty's to write; the plan
// prints the records to add.
// frosty route sync <box> --dry-run: the same checks and the same writes, in order, printed and not
// made. The Cloudflare client refuses writes for the whole run.
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
  // plan --dry-run is just plan: it changes nothing either way.
  if (opts.dryRun === true && opts.action === "sync") {
    cloudflare.refuseWrites();
    io.out(`Dry run of frosty route sync ${box}: nothing below is changed.`);
    const changes = await syncRoutes(ctx, box, edge.tunnel, syncRun(ctx, true));
    io.out("");
    io.out(changes === 0 ? "Dry run: sync would change nothing." : `Dry run: sync would make the ${changes} change(s) above, in that order. Nothing was changed.`);
    io.out("DNS for route hostnames isn't frosty's to write: frosty route plan prints the records.");
    return 0;
  }
  if (opts.action === "sync") {
    await syncRoutes(ctx, box, edge.tunnel);
  }
  const [apps, policies] = await Promise.all([cloudflare.listAccessApps(config.accountId), cloudflare.listAccessPolicies(config.accountId)]);
  // Token policies no route wants: sync deletes them.
  const wantedPolicies = new Set(routes.filter((r) => routeServiceTokens(r).length > 0).map((r) => routeTokenPolicyName(box, r)));
  const stray = policies.filter((p) => isRouteTokenPolicyOf(box, p.name) && !wantedPolicies.has(p.name));
  for (const p of stray) {
    io.out(`Access policy ${p.name}: no route lists service tokens for it${opts.action === "sync" ? "" : "; sync deletes it"}.`);
  }
  const wantedEmailPolicies = new Set(routes.filter((r) => r.emails !== undefined).map((r) => routeEmailPolicyName(box, r)));
  for (const p of policies.filter((x) => isRouteEmailPolicyOf(box, x.name) && !wantedEmailPolicies.has(x.name))) {
    io.out(`Access policy ${p.name}: no route lists its own emails for it${opts.action === "sync" ? "" : "; sync puts the box's emails back on its app, then deletes it"}.`);
  }
  if (routes.length === 0) {
    io.out(`${box} has no routes in config.${opts.action === "sync" ? " Its tunnel carries SSH only." : ""}`);
    return 0;
  }
  let problems = 0;
  let tokenProblems = 0;
  for (const route of routes) {
    const have = routeApps(apps, box, route);
    io.out(`${route.name}: ${route.hostname} -> ${route.service}`);
    io.out(`  public: ${route.public.join(" ")}`);
    io.out(`  protected: ${route.protected.join(" ")}`);
    if (exactPaths(route).length > 0) {
      io.out(`  public, exact path only: ${exactPaths(route).join(" ")}`);
    }
    if (frostyProtected(route).length > 0) {
      const who = route.emails === undefined ? "your emails" : `the route's own emails, via ${routeEmailPolicyName(box, route)}${policies.some((p) => p.name === routeEmailPolicyName(box, route)) ? "" : " [missing]"}: ${route.emails.join(", ")}`;
      io.out(`  Access ${routeAppName(box, route)} (${who}): ${protectedUris(route).join(", ")}${have.app === undefined ? "  [missing]" : ""}`);
    }
    // The same checks sync makes before any write, so a plan that looks fine never ends in a refused sync.
    const plan = await planRouteTokens(ctx, box, route, have.app?.id, policies.find((p) => p.name === routeTokenPolicyName(box, route)), false);
    if (plan !== undefined) {
      io.out(`  Access ${plan.policyName} (service tokens, on ${routeAppName(box, route)}): ${plan.names.join(", ")}${plan.policy === undefined ? "  [missing]" : ""}`);
      for (const t of plan.tokens) {
        const e = tokenExpiry(t.token, plan.now);
        io.out(`    service token ${t.name}: ${e.text}${e.expired ? "  [EXPIRED: refresh or rotate it in the Cloudflare dashboard]" : e.soon ? "  [expires within 30 days]" : ""}`);
      }
      for (const problem of [...plan.problems, ...plan.elsewhere.map((w) => `a token of this route also opens: ${w}`)]) {
        tokenProblems++;
        io.out(`    [problem: ${problem}]`);
      }
    }
    if (bypassUris(route).length > 0) {
      io.out(`  Access ${publicAppName(box, route)} (bypass): ${bypassUris(route).join(", ")}${have.publicApp === undefined ? "  [missing]" : ""}`);
    }
    // The same checks sync makes, so a plan that looks fine never ends in a refused sync.
    for (const c of await checkExternalAccess(ctx, route, have)) {
      if (c.problem !== undefined) {
        problems++;
        io.out(`  Access ${c.name} (not frosty's, read only): ${c.uri}  [problem: ${c.problem}]`);
      } else {
        io.out(`  Access ${c.name} (not frosty's, read only): ${c.uri}, lets in ${describeIncludes(c.app!)}`);
      }
    }
    io.out(`  In the tunnel's ingress: ${routeAuds(have) === undefined ? "no (an Access app is missing; run frosty route sync)" : "yes"}`);
    io.out(`  DNS (add it outside frosty): ${route.hostname} CNAME ${edge.tunnel.id}.cfargotunnel.com, proxied, comment "stayfrosty route ${box} ${route.name}"`);
  }
  io.out("");
  if (tokenProblems > 0) {
    io.out(`${tokenProblems} service token problem(s) above: sync would refuse. A service token opens exactly one box or route, and must exist under exactly that name.`);
  }
  if (problems > 0) {
    io.out(`${problems} externalAccess problem(s) above: sync would refuse. frosty doesn't change those apps; fix them in the Cloudflare dashboard, or take the paths out of externalAccess.`);
  }
  if (problems > 0 || tokenProblems > 0) {
    return 1;
  }
  io.out(`Then check it: frosty verify ${box}`);
  return 0;
}
