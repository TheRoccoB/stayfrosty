import { assertBoxName, buildContext, directTarget, tunnelTarget, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { boxSelector } from "../hetzner.ts";
import { windowSource } from "../ip.ts";
import { setConsolePassword } from "../password.ts";

// Sets a new console password for the admin user. Needs a terminal or passwordCommand.
export async function runConsolePassword(deps: Deps, opts: { box: string | undefined; dryRun: boolean; direct?: boolean }): Promise<number> {
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  const server = (await ctx.hetzner.listServers(boxSelector(box)))[0];
  if (server === undefined) {
    throw new FrostyError(`frosty has no box named ${box}.`, "See what exists with: frosty ls");
  }
  if (!ctx.isTty && ctx.config.passwordCommand === undefined) {
    throw new FrostyError(
      "There is no terminal to show the password on and no passwordCommand to send it to. Nothing was changed.",
      `Run it yourself in a terminal: frosty console-password ${box}`,
    );
  }
  ctx.io.out(`${opts.dryRun ? "Would set" : "Setting"} a new console password for ${ctx.config.adminUser} on ${box}, replacing any old one.`);
  if (opts.dryRun) {
    ctx.io.out("Dry run: nothing was changed.");
    return 0;
  }
  // Normally through the tunnel. --direct uses the box's IP, for an open break-glass window.
  const target = opts.direct === true ? directTarget(ctx, box, server, windowSource(await ctx.laptopIp()).family) : tunnelTarget(ctx, box);
  await setConsolePassword(ctx, { box, target, user: ctx.config.adminUser, passwordCommand: ctx.config.passwordCommand });
  return 0;
}
