import { assertBoxName, buildContext, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { boxSelector } from "../hetzner.ts";
import { firewallName } from "./new.ts";

export interface DetachForeignOptions {
  box: string | undefined;
  dryRun: boolean;
}

// For adopt: removes the firewalls frosty did not make from one box. Hetzner firewalls add up,
// so another firewall's allow rules would undo frosty's deny-all. Only from that one box, never
// frosty's own, and only while frosty's is attached and applied (checked again for every detach).
// The other firewalls themselves are left in place for the boxes that still use them.
export async function runDetachForeign(deps: Deps, opts: DetachForeignOptions): Promise<number> {
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  const { io, hetzner } = ctx;
  const servers = await hetzner.listServers(boxSelector(box));
  if (servers.length !== 1) {
    throw new FrostyError(servers.length === 0 ? `frosty has no box named ${box}.` : `More than one server is labeled as box ${box}.`, "See what exists with: frosty ls");
  }
  const server = servers[0]!;
  const ours = (await hetzner.listFirewalls(boxSelector(box))).find((f) => f.name === firewallName(box));
  const attached = server.public_net.firewalls ?? [];
  const oursApplied = ours !== undefined && attached.some((f) => f.id === ours.id && f.status === "applied");
  if (!oursApplied) {
    throw new FrostyError(`frosty's firewall ${firewallName(box)} is not attached and applied to ${box}, so nothing is detached.`, `Attach it first: frosty adopt ${box} --ip <ip> --resume`);
  }
  const others = attached.filter((f) => f.id !== ours.id);
  if (others.length === 0) {
    io.out(`${box} has only frosty's firewall. Nothing to detach.`);
    return 0;
  }
  for (const f of others) {
    const fw = await hetzner.getFirewall(f.id);
    const elsewhere = fw.applied_to.filter((t) => !(t.type === "server" && t.server?.id === server.id)).length;
    io.out(`${opts.dryRun ? "Would detach" : "Detaching"} firewall ${fw.name} (id ${fw.id}) from ${box}. It stays on ${elsewhere} other resource(s) and is not deleted.`);
    if (!opts.dryRun) {
      for (const action of await hetzner.detachForeignFirewall(fw.id, server.id)) {
        await hetzner.waitForAction(action);
      }
    }
  }
  if (opts.dryRun) {
    io.out("Dry run: nothing was changed.");
    return 0;
  }
  const after = await hetzner.getServer(server.id);
  const left = (after.public_net.firewalls ?? []).map((f) => `${f.id}=${f.status}`);
  io.out(`${box} now has: ${left.join(", ")} (frosty's is ${ours.id}).`);
  return 0;
}
