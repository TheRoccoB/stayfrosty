import { checkAccess, SERVICE_TOKEN_ELSEWHERE_FIX, tokenExpiry, type ServiceTokenAccess } from "../checks/edge.ts";
import type { CheckResult } from "../checks/types.ts";
import { appFieldsFrostyWouldReset } from "../cloudflare.ts";
import { assertBoxName, buildContext, sshHostname, type Context, type Deps } from "../context.ts";
import { findEdge, type Edge } from "../edge.ts";
import { FrostyError } from "../errors.ts";
import { readTokenState, serviceTokenAccess, tokensUsedElsewhere, tokenSteps, type TokenState, type TokenStep } from "../servicetokens.ts";
import { printResults } from "./new.ts";

const APP_RESET_FIX = "Clear those settings in the Cloudflare dashboard (Zero Trust, Access, Applications) if you don't need them, then run the command again. frosty only writes its own app shape.";

export interface ServiceTokensOptions {
  action: string | undefined;
  box: string | undefined;
}

// frosty service-tokens plan <box>: what sync would change on the box's SSH Access app (read-only).
// frosty service-tokens sync <box>: make the box's service token policy and SSH app match
// config.serviceTokens, then check Access like verify does.
export async function runServiceTokens(deps: Deps, opts: ServiceTokensOptions): Promise<number> {
  if (opts.action !== "plan" && opts.action !== "sync") {
    throw new FrostyError("frosty service-tokens needs plan or sync.", "frosty service-tokens plan <box>   or   frosty service-tokens sync <box>");
  }
  const box = assertBoxName(opts.box);
  const ctx = await buildContext(deps);
  if (opts.action === "plan") {
    const { steps, elsewhere, reset } = await planServiceTokens(ctx, box);
    if (elsewhere.length > 0) {
      ctx.io.out(`${box}: sync would refuse. A service token opens exactly one box. ${SERVICE_TOKEN_ELSEWHERE_FIX}`);
      return 1;
    }
    if (reset.length > 0) {
      ctx.io.out(`${box}: sync would refuse. ${APP_RESET_FIX}`);
      return 1;
    }
    for (const step of steps) {
      ctx.io.out(`  would: ${step.describe}`);
    }
    ctx.io.out(steps.length === 0 ? `${box}: the service tokens already match config. Nothing to change.` : `${box}: ${steps.length} change(s). Apply them with: frosty service-tokens sync ${box}`);
    return 0;
  }
  await syncServiceTokens(ctx, box);
  const result = await accessCheck(ctx, box, await findEdge(ctx, box));
  printResults(ctx, [result]);
  if (!result.ok) {
    ctx.io.err(`The Access check failed on ${box}. The fix is listed above.`);
    return 1;
  }
  ctx.io.out(`Then check the whole box: frosty verify ${box}`);
  return 0;
}

function printTokens(ctx: Context, state: TokenState): void {
  for (const t of state.tokens) {
    const e = tokenExpiry(t.token, ctx.now());
    ctx.io.out(`  service token ${t.name}: ${e.text}${e.expired ? "  [EXPIRED: refresh or rotate it in the Cloudflare dashboard]" : e.soon ? "  [expires within 30 days]" : ""}`);
  }
}

// Every check sync makes, so a plan that looks fine never ends in a refused sync.
async function planServiceTokens(ctx: Context, box: string): Promise<{ state: TokenState; steps: TokenStep[]; elsewhere: string[]; reset: string[] }> {
  const state = await readTokenState(ctx, box);
  printTokens(ctx, state);
  const elsewhere = await tokensUsedElsewhere(ctx, box, new Map(state.tokens.map((t) => [t.token.id, t.name])), { appId: state.app.id, policyId: state.tokenPolicy?.id });
  for (const where of elsewhere) {
    ctx.io.out(`  [problem] a token of ${box} also opens: ${where}`);
  }
  const steps = tokenSteps(ctx, box, state);
  // Checked before any write too, so sync never creates a policy it then can't attach.
  const reset = steps.some((s) => s.app === true) ? appFieldsFrostyWouldReset(state.app as unknown as Record<string, unknown>) : [];
  if (reset.length > 0) {
    ctx.io.out(`  [problem] Access application ${state.app.name} has ${reset.join(", ")} set, and frosty's update would reset them`);
  }
  return { state, steps, elsewhere, reset };
}

// Applies config.serviceTokens to the box's SSH Access app. Refuses, before any write, a token
// that any other policy or app would also let in.
export async function syncServiceTokens(ctx: Context, box: string): Promise<number> {
  const { state, steps, elsewhere, reset } = await planServiceTokens(ctx, box);
  if (elsewhere.length > 0) {
    throw new FrostyError(`A service token opens exactly one box, but a token of ${box} also opens: ${elsewhere.join("; ")}.`, SERVICE_TOKEN_ELSEWHERE_FIX);
  }
  if (reset.length > 0) {
    throw new FrostyError(`Access application ${state.app.name} has ${reset.join(", ")} set, and frosty's update would reset them.`, APP_RESET_FIX);
  }
  ctx.io.out(`Syncing service tokens on ${box}: ${state.names.length === 0 ? "none in config" : state.names.join(", ")}.`);
  for (const step of steps) {
    ctx.io.out(`  changing: ${step.describe}`);
    await step.run();
  }
  ctx.io.out(steps.length === 0 ? "Nothing to change." : `Made ${steps.length} change(s).`);
  return steps.length;
}

// verify's Access check of the box's SSH app. The app and the token policy are re-read in full.
// With no serviceTokens for the box, service tokens are never listed.
export async function accessCheck(ctx: Context, box: string, edge: Edge): Promise<CheckResult> {
  const { cloudflare, config } = ctx;
  const [app, tokenPolicy] = await Promise.all([
    edge.app === undefined ? undefined : cloudflare.getAccessApp(config.accountId, edge.app.id),
    edge.tokenPolicy === undefined ? undefined : cloudflare.getAccessPolicy(config.accountId, edge.tokenPolicy.id),
  ]);
  const tokens: ServiceTokenAccess | undefined = await serviceTokenAccess(ctx, box, app?.id, tokenPolicy);
  return checkAccess(box, app, edge.policy, sshHostname(ctx, box), config.accessEmails, tokenPolicy, tokens);
}
