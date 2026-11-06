import { FRESH_CONNECTION, runOrFail, type SshTarget } from "../box.ts";
import { logDone, fileChangeLog, type ChangeLog } from "../changelog.ts";
import { runOnBoxChecks } from "../checks/onbox.ts";
import { rebootTimeFor, restrictedUsersFor } from "../config.ts";
import { assertBoxName, buildContext, requireCloudflared, tunnelTarget, type Context, type Deps } from "../context.ts";
import { FrostyError } from "../errors.ts";
import { boxSelector } from "../hetzner.ts";
import { SSH_USERS_CLEANUP, SSH_USERS_ROLLBACK, sshUsersScript } from "../sshusers.ts";
import { printResults } from "./new.ts";

export interface SshUsersOptions {
  action: string | undefined;
  box: string | undefined;
}

// frosty ssh-users plan <box>: what sync would change on the box (read-only).
// frosty ssh-users sync <box>: make the box's restricted users, key files and sshd drop-in match
// config.restrictedUsers, then check them like verify does.
export async function runSshUsers(deps: Deps, opts: SshUsersOptions): Promise<number> {
  if (opts.action !== "plan" && opts.action !== "sync") {
    throw new FrostyError("frosty ssh-users needs plan or sync.", "frosty ssh-users plan <box>   or   frosty ssh-users sync <box>");
  }
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  requireCloudflared(ctx);
  const servers = await ctx.hetzner.listServers(boxSelector(box));
  if (servers.length === 0) {
    throw new FrostyError(`frosty has no box named ${box}.`, "See what exists with: frosty ls");
  }
  const target = tunnelTarget(ctx, box);
  if (opts.action === "plan") {
    const changes = await planSshUsers(ctx, box, target);
    ctx.io.out(changes === 0 ? `${box}: the restricted users already match config. Nothing to change.` : `${box}: ${changes} change(s). Apply them with: frosty ssh-users sync ${box}`);
    return 0;
  }
  await syncSshUsers(ctx, box, target);
  const users = restrictedUsersFor(ctx.config, box);
  const results = (await runOnBoxChecks(ctx.ssh, target, { box, adminUser: ctx.config.adminUser, rebootTime: rebootTimeFor(ctx.config, box), createdAt: undefined, tunnel: false, restrictedUsers: users })).filter(
    (r) => r.name.startsWith("sshd:") || r.name.startsWith("restricted user "),
  );
  printResults(ctx, results);
  const failed = results.filter((r) => !r.ok);
  if (failed.length > 0) {
    ctx.io.err(`${failed.length} check(s) failed on ${box}. The fixes are listed above.`);
    return 1;
  }
  ctx.io.out(`Then check the whole box: frosty verify ${box}`);
  return 0;
}

function printScriptOutput(ctx: Context, out: string): number {
  let changes = 0;
  for (const line of out.trimEnd().split("\n")) {
    const m = /^stayfrosty-ssh-users-changes (\d+)$/.exec(line);
    if (m !== null) {
      changes = Number(m[1]);
    } else if (line !== "stayfrosty-ssh-users-ok" && line.length > 0) {
      ctx.io.out(`  ${line}`);
    }
  }
  return changes;
}

export async function planSshUsers(ctx: Context, box: string, target: SshTarget): Promise<number> {
  const script = sshUsersScript(ctx.config.adminUser, restrictedUsersFor(ctx.config, box), false);
  const out = await runOrFail(ctx.ssh, target, "sudo bash -s", "Planning the restricted users", { stdin: script, timeoutMs: 60_000 });
  if (!out.includes("stayfrosty-ssh-users-ok")) {
    throw new FrostyError("The restricted users plan did not finish.", `Run it again: frosty ssh-users plan ${box}`);
  }
  return printScriptOutput(ctx, out);
}

// Applies the box's restricted users. After a changed drop-in it proves a fresh admin login and,
// if that fails, puts the old drop-in back over the connection that is still open.
export async function syncSshUsers(ctx: Context, box: string, target: SshTarget): Promise<number> {
  const users = restrictedUsersFor(ctx.config, box);
  const log: ChangeLog | undefined = ctx.config.boxChangeLog === undefined ? undefined : fileChangeLog(ctx.config.boxChangeLog);
  const request = { users: users.map((u) => ({ name: u.name, command: u.command, groups: u.groups, keys: u.keys.length })) };
  log?.({ phase: "intent", action: "ssh-users.sync", target: box, request });
  ctx.io.out(`Syncing restricted SSH users on ${box}: ${users.length === 0 ? "none in config" : users.map((u) => u.name).join(", ")}.`);
  const out = await runOrFail(ctx.ssh, target, "sudo bash -s", "Syncing the restricted users", { stdin: sshUsersScript(ctx.config.adminUser, users, true), timeoutMs: 120_000 });
  if (!out.includes("stayfrosty-ssh-users-ok")) {
    throw new FrostyError("The restricted users sync did not finish.", `Run it again: frosty ssh-users sync ${box}`);
  }
  const changes = printScriptOutput(ctx, out);
  if (out.includes("changing: write /etc/ssh/sshd_config.d/00-stayfrosty.conf")) {
    const fresh = await ctx.ssh(target, "sudo -n true", { extraOptions: FRESH_CONNECTION, timeoutMs: 60_000 });
    if (fresh.code !== 0) {
      const back = await ctx.ssh(target, "sudo bash -s", { stdin: SSH_USERS_ROLLBACK, timeoutMs: 60_000 });
      logDone(log, { phase: "done", action: "ssh-users.sync", target: box, result: { changes, rolledBack: back.code === 0 } });
      throw new FrostyError(
        `After the sync, a fresh ${ctx.config.adminUser} login to ${box} failed. ${back.code === 0 ? "The old sshd drop-in is back and sshd was reloaded." : "PUTTING THE OLD DROP-IN BACK FAILED too."}`,
        back.code === 0 ? `Check that ssh ${box} works, then look at the sync output above.` : `Keep any open session to ${box}. Use the Hetzner web console (frosty console-password ${box}) to restore /etc/ssh/sshd_config.d/00-stayfrosty.conf.stayfrosty-prev.`,
      );
    }
    await runOrFail(ctx.ssh, target, "sudo bash -s", "Removing the old drop-in backup", { stdin: SSH_USERS_CLEANUP });
  }
  logDone(log, { phase: "done", action: "ssh-users.sync", target: box, result: { changes } });
  ctx.io.out(changes === 0 ? "Nothing to change." : `Made ${changes} change(s).`);
  return changes;
}
