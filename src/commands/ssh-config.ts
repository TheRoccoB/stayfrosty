import { buildContext, type Deps } from "../context.ts";
import { renderSshConfig, tildify, writeSshConfig } from "../sshconfig.ts";
import { sshConfigEntries } from "./new.ts";

export interface SshConfigOptions {
  dryRun: boolean;
}

// Rewrites ~/.ssh/stayfrosty.conf from the Hetzner API, for when it went stale: a box was made
// from another laptop, or cloudflared moved. Reads the APIs only; the one write is that file.
export async function runSshConfig(deps: Deps, opts: SshConfigOptions): Promise<number> {
  const ctx = await buildContext(deps);
  const { io } = ctx;
  const entries = await sshConfigEntries(ctx);
  if (opts.dryRun) {
    io.out(renderSshConfig(entries));
    io.out("Dry run: nothing was written.");
    return 0;
  }
  const written = await writeSshConfig(ctx.env, entries, ctx.now);
  io.out(`Wrote ${tildify(written.path, ctx.env)} (${entries.length} box${entries.length === 1 ? "" : "es"}).`);
  if (written.includeAdded) {
    io.out(`Added "Include stayfrosty.conf" to the top of ~/.ssh/config${written.backup === undefined ? "" : ` (the old file is at ${tildify(written.backup, ctx.env)})`}.`);
  }
  return 0;
}
