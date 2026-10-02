import { hostKeyAlias } from "../box.ts";
import { assertBoxName, buildContext, type Deps } from "../context.ts";
import { describeEdge, edgeIsEmpty, findEdge, removeEdge, removeTunnel } from "../edge.ts";
import { ApiError, FrostyError } from "../errors.ts";
import { boxSelector } from "../hetzner.ts";
import { tildify, writeSshConfig } from "../sshconfig.ts";
import { sshConfigEntries } from "./new.ts";

export interface DestroyOptions {
  box: string | undefined;
  dryRun: boolean;
}

// Deletes everything frosty created for one box: found by label in Hetzner and by name in
// Cloudflare. Never anything else.
export async function runDestroy(deps: Deps, opts: DestroyOptions): Promise<number> {
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  const { io, hetzner } = ctx;
  const [servers, firewalls, edge] = await Promise.all([hetzner.listServers(boxSelector(box)), hetzner.listFirewalls(boxSelector(box)), findEdge(ctx, box)]);
  if (servers.length === 0 && firewalls.length === 0 && edgeIsEmpty(edge)) {
    io.out(`frosty has nothing named ${box}. Nothing to destroy. See what exists with: frosty ls`);
    return 0;
  }

  io.out(`${opts.dryRun ? "Would delete" : "This deletes"}, permanently:`);
  for (const server of servers) {
    io.out(`  Hetzner server ${server.name} (id ${server.id}, ${server.public_net.ipv4?.ip ?? "no IPv4"}) and its disk`);
  }
  for (const firewall of firewalls) {
    io.out(`  Hetzner firewall ${firewall.name} (id ${firewall.id})`);
  }
  for (const line of describeEdge(edge)) {
    io.out(`  ${line}`);
  }
  if (opts.dryRun) {
    io.out("Dry run: nothing was deleted.");
    return 0;
  }
  const typed = await io.ask(`Type the box name (${box}) to destroy it`);
  if (typed.trim() !== box) {
    io.err("The name did not match. Nothing was deleted.");
    return 1;
  }

  // The alert goes first, so deleting the box does not send a tunnel-down email.
  await removeEdge(ctx, edge);
  for (const server of servers) {
    io.out(`Deleting server ${server.name}.`);
    await hetzner.waitForAction(await hetzner.deleteServer(server.id));
  }
  await ctx.forgetHost(hostKeyAlias(box));
  for (const firewall of firewalls) {
    io.out(`Deleting firewall ${firewall.name}.`);
    await deleteFirewallWhenFree(ctx.hetzner, firewall.id, ctx.sleep, ctx.now);
  }
  // The connector is gone with the server; now the tunnel can go.
  await removeTunnel(ctx, edge);

  if (ctx.cloudflaredPath !== undefined) {
    const written = await writeSshConfig(ctx.env, await sshConfigEntries(ctx), ctx.now);
    io.out(`Removed ${box} from ${tildify(written.path, ctx.env)}.`);
  }

  const [leftServers, leftFirewalls, leftEdge] = await Promise.all([hetzner.listServers(boxSelector(box)), hetzner.listFirewalls(boxSelector(box)), findEdge(ctx, box)]);
  if (leftServers.length > 0 || leftFirewalls.length > 0 || !edgeIsEmpty(leftEdge)) {
    throw new FrostyError(`Some of ${box} is still there after deleting: ${describeEdge(leftEdge).join(", ") || "Hetzner resources"}.`, `Run frosty destroy ${box} again, then: frosty ls`);
  }
  io.out(`Box ${box} is gone. Check with: frosty ls`);
  return 0;
}

// A firewall stays "in use" for a moment after its server is deleted.
async function deleteFirewallWhenFree(
  hetzner: { deleteFirewall(id: number): Promise<void> },
  id: number,
  sleep: (ms: number) => Promise<void>,
  now: () => number,
): Promise<void> {
  const deadline = now() + 120_000;
  for (;;) {
    try {
      await hetzner.deleteFirewall(id);
      return;
    } catch (error) {
      if (error instanceof ApiError && error.code === "resource_in_use" && now() < deadline) {
        await sleep(3000);
        continue;
      }
      throw error;
    }
  }
}
