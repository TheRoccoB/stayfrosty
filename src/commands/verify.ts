import { assertBoxName, buildContext, requireCloudflared, tunnelTarget, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { LABEL_BOX, MANAGED_SELECTOR, boxSelector } from "../hetzner.ts";
import { checkBox, printResults } from "./new.ts";

export interface VerifyOptions {
  box: string | undefined;
  all: boolean;
}

// Every check from the end of new and adopt, again, through the tunnel: the box still has no
// front door, still patches itself, and Cloudflare still only lets your emails in. Changes nothing.
export async function runVerify(deps: Deps, opts: VerifyOptions): Promise<number> {
  if (opts.all === (opts.box !== undefined)) {
    throw new FrostyError("Name one box, or pass --all.", "frosty verify <box>   or   frosty verify --all");
  }
  const box = opts.box === undefined ? undefined : assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  requireCloudflared(ctx);
  const servers = await ctx.hetzner.listServers(box === undefined ? MANAGED_SELECTOR : boxSelector(box));
  if (servers.length === 0) {
    throw new FrostyError(box === undefined ? "frosty manages no boxes in this project." : `frosty has no box named ${box}.`, "See what exists with: frosty ls");
  }
  // A rebootTimes key that names no box would silently leave that box on the default time.
  if (box === undefined) {
    const names = new Set(servers.map((s) => s.labels[LABEL_BOX] ?? s.name));
    const unknown = Object.keys(ctx.config.rebootTimes ?? {}).filter((b) => !names.has(b));
    if (unknown.length > 0) {
      ctx.io.err(`Warning: rebootTimes names ${unknown.join(", ")}, which frosty does not manage. A typo? Those boxes use rebootTime.`);
    }
  }
  let failed = 0;
  for (const server of servers) {
    const name = server.labels[LABEL_BOX] ?? server.name;
    ctx.io.out(`${name}:`);
    const results = await checkBox(ctx, name, tunnelTarget(ctx, name), server, { tunnel: true });
    printResults(ctx, results);
    ctx.io.out("");
    failed += results.filter((r) => !r.ok).length;
  }
  if (failed > 0) {
    ctx.io.err(`${failed} check(s) failed. The fixes are listed above.`);
    return 1;
  }
  ctx.io.out(`All checks passed on ${servers.length} box(es).`);
  return 0;
}
