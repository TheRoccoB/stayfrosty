import { missingServiceTokenHint, type ServiceTokenAccess } from "./checks/edge.ts";
import { isOurEmailPolicy, isOurTokenPolicy, serviceTokenIds, tokenPolicyName, type CfAccessApp, type CfAccessPolicy, type CfAccessRule } from "./cloudflare.ts";
import { serviceTokensFor } from "./config.ts";
import type { Context } from "./context.ts";
import { edgeName, sameEmails } from "./edge.ts";
import { FrostyError } from "./errors.ts";

// Cloudflare Access service tokens on a box's SSH app (config.serviceTokens). The user makes the
// tokens in the dashboard; frosty only reads them, and writes one policy per box,
// stayfrosty-<box>:service-tokens, that lets exactly those tokens in. A token opens exactly one box.

// Resolves the configured names to tokens. With no names it makes no call, so a config without
// serviceTokens never needs the extra token permission.
export async function resolveServiceTokens(ctx: Context, names: string[]): Promise<Pick<ServiceTokenAccess, "tokens" | "problems">> {
  if (names.length === 0) {
    return { tokens: [], problems: [] };
  }
  const all = await ctx.cloudflare.listServiceTokens(ctx.config.accountId);
  const tokens: ServiceTokenAccess["tokens"] = [];
  const problems: string[] = [];
  for (const name of names) {
    const matches = all.filter((t) => t.name === name);
    if (matches.length === 0) {
      problems.push(`Cloudflare has no service token named ${name}`);
    } else if (matches.length > 1) {
      problems.push(`${matches.length} Cloudflare service tokens are named ${name}, so frosty can't tell which one is meant`);
    } else {
      tokens.push({ name, token: matches[0]! });
    }
  }
  return { tokens, problems };
}

function rulesNaming(rules: CfAccessRule[] | undefined, ids: Map<string, string>): string[] {
  return serviceTokenIds(rules)
    .filter((id) => ids.has(id))
    .map((id) => ids.get(id) as string);
}

function hasAnyToken(rules: CfAccessRule[] | undefined): boolean {
  return (rules ?? []).some((r) => "any_valid_service_token" in r);
}

// Every other Access policy and app that would also let one of these tokens in: a policy that
// names one, an app whose policies name one or take any valid service token, or an app that has
// the box's own token policy attached. The list of apps may leave out policy rules, so an app
// without them is read in full. `ids` maps token id to the name to print.
export async function tokensUsedElsewhere(ctx: Context, box: string, ids: Map<string, string>, own: { appId: string | undefined; policyId: string | undefined }): Promise<string[]> {
  if (ids.size === 0) {
    return [];
  }
  const { cloudflare, config } = ctx;
  const [policies, apps] = await Promise.all([cloudflare.listAccessPolicies(config.accountId), cloudflare.listAccessApps(config.accountId)]);
  const out: string[] = [];
  for (const p of policies) {
    if (p.id === own.policyId) {
      continue;
    }
    const named = [...rulesNaming(p.include, ids), ...rulesNaming(p.require, ids)];
    if (named.length > 0) {
      out.push(`Access policy ${p.name} includes ${[...new Set(named)].join(", ")}`);
    }
  }
  for (const listed of apps) {
    if (listed.id === own.appId) {
      continue;
    }
    const needsRead = listed.policies === undefined || listed.policies.some((p) => !Array.isArray(p.include));
    const app: CfAccessApp = needsRead ? await cloudflare.getAccessApp(config.accountId, listed.id) : listed;
    for (const p of app.policies ?? []) {
      const label = `Access application ${app.name} (policy ${p.name ?? p.id})`;
      if (own.policyId !== undefined && p.id === own.policyId) {
        out.push(`${label} is ${tokenPolicyName(box)} itself`);
        continue;
      }
      const named = [...rulesNaming(p.include, ids), ...rulesNaming(p.require, ids)];
      if (named.length > 0) {
        out.push(`${label} includes ${[...new Set(named)].join(", ")}`);
      }
      if (hasAnyToken(p.include)) {
        out.push(`${label} lets in any valid service token`);
      }
    }
  }
  return [...new Set(out)];
}

// What verify needs to judge a box's service tokens, or undefined (and no calls) when the box
// has none configured.
export async function serviceTokenAccess(ctx: Context, box: string, appId: string | undefined, tokenPolicy: CfAccessPolicy | undefined): Promise<ServiceTokenAccess | undefined> {
  const names = serviceTokensFor(ctx.config, box);
  if (names.length === 0) {
    return undefined;
  }
  const { tokens, problems } = await resolveServiceTokens(ctx, names);
  const ids = new Map<string, string>(serviceTokenIds(tokenPolicy?.include).map((id) => [id, `token id ${id}`]));
  for (const t of tokens) {
    ids.set(t.token.id, t.name);
  }
  const elsewhere = await tokensUsedElsewhere(ctx, box, ids, { appId, policyId: tokenPolicy?.id });
  return { names, tokens, problems, elsewhere, now: ctx.now() };
}

export interface TokenState {
  names: string[];
  // The box's SSH app, read in full, and its email policy.
  app: CfAccessApp;
  emailPolicy: CfAccessPolicy;
  tokenPolicy: CfAccessPolicy | undefined;
  tokens: ServiceTokenAccess["tokens"];
}

// The box's Access as it is, with the configured names resolved. Refuses a box without frosty's
// SSH app or email policy, and a name that matches no token or several.
export async function readTokenState(ctx: Context, box: string): Promise<TokenState> {
  const { cloudflare, config } = ctx;
  const [apps, policies] = await Promise.all([cloudflare.listAccessApps(config.accountId), cloudflare.listAccessPolicies(config.accountId)]);
  const listed = apps.find((a) => a.name === edgeName(box));
  if (listed === undefined) {
    throw new FrostyError(`${box} has no frosty Access application ${edgeName(box)}.`, `Set the box up first: frosty new ${box}, or frosty adopt ${box}.`);
  }
  const emailPolicy = policies.find((p) => p.name === edgeName(box));
  if (emailPolicy === undefined || !isOurEmailPolicy(emailPolicy) || !sameEmails(emailPolicy.include.map((r) => r.email?.email ?? ""), config.accessEmails)) {
    throw new FrostyError(`Access policy ${edgeName(box)} is missing or not an allow policy for exactly ${config.accessEmails.join(", ")}.`, `Run: frosty verify ${box}, and fix the box's own Access first.`);
  }
  const tokenListed = policies.find((p) => p.name === tokenPolicyName(box));
  const [app, tokenPolicy] = await Promise.all([cloudflare.getAccessApp(config.accountId, listed.id), tokenListed === undefined ? undefined : cloudflare.getAccessPolicy(config.accountId, tokenListed.id)]);
  const names = serviceTokensFor(config, box);
  const { tokens, problems } = await resolveServiceTokens(ctx, names);
  if (problems.length > 0) {
    throw new FrostyError(`serviceTokens.${box}: ${problems.join("; ")}.`, missingServiceTokenHint());
  }
  return { names, app, emailPolicy, tokenPolicy, tokens };
}

export interface TokenStep {
  describe: string;
  run: () => Promise<void>;
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// The writes that make the box's Access match config, in a safe order: a policy is written before
// it is attached, and detached before it is deleted.
export function tokenSteps(ctx: Context, box: string, state: TokenState): TokenStep[] {
  const { cloudflare, config } = ctx;
  const { app, emailPolicy, tokenPolicy, tokens } = state;
  const steps: TokenStep[] = [];
  const current = (app.policies ?? []).map((p) => p.id);
  const currentNames = (app.policies ?? []).map((p) => p.name ?? p.id).join(", ") || "none";
  // The ids are read when the step runs: a policy created by an earlier step has its id by then.
  const setPolicies = (ids: () => string[], names: string[]): TokenStep => ({
    describe: `set the policies of Access application ${app.name} to ${names.join(", ")} (now ${currentNames})`,
    run: async () => {
      await cloudflare.putSshAppPolicies(config.accountId, box, app.id, ids(), config.accessSessionDuration);
    },
  });
  if (tokens.length === 0) {
    if (!sameList(current, [emailPolicy.id])) {
      steps.push(setPolicies(() => [emailPolicy.id], [emailPolicy.name]));
    }
    if (tokenPolicy !== undefined) {
      steps.push({
        describe: `delete Access policy ${tokenPolicy.name}`,
        run: async () => {
          await cloudflare.deleteAccessPolicy(config.accountId, tokenPolicy);
        },
      });
    }
    return steps;
  }
  const want = tokens.map((t) => t.token.id).sort();
  const nameOf = new Map(tokens.map((t) => [t.token.id, t.name]));
  let policyId = tokenPolicy?.id;
  if (tokenPolicy === undefined) {
    steps.push({
      describe: `create Access policy ${tokenPolicyName(box)}: let in service tokens ${tokens.map((t) => t.name).join(", ")}`,
      run: async () => {
        policyId = (await cloudflare.putTokenPolicy(config.accountId, box, want)).id;
      },
    });
  } else {
    const have = [...new Set(serviceTokenIds(tokenPolicy.include))].sort();
    if (!isOurTokenPolicy(tokenPolicy, box) || !sameList(have, want)) {
      const added = want.filter((id) => !have.includes(id)).map((id) => nameOf.get(id) as string);
      const removed = have.filter((id) => !want.includes(id));
      const change = [...(added.length > 0 ? [`add ${added.join(", ")}`] : []), ...(removed.length > 0 ? [`remove token id(s) ${removed.join(", ")}`] : [])];
      steps.push({
        describe: `update Access policy ${tokenPolicy.name}: ${change.join(", ") || "back to frosty's shape"}`,
        run: async () => {
          await cloudflare.putTokenPolicy(config.accountId, box, want, tokenPolicy.id);
        },
      });
    }
  }
  if (tokenPolicy === undefined || !sameList(current, [emailPolicy.id, tokenPolicy.id])) {
    steps.push(setPolicies(() => [emailPolicy.id, policyId as string], [emailPolicy.name, tokenPolicyName(box)]));
  }
  return steps;
}
