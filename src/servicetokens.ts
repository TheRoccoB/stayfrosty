import { missingServiceTokenHint, type ServiceTokenAccess } from "./checks/edge.ts";
import { isOurEmailPolicy, isOurTokenPolicy, serviceTokenIds, tokenPolicyName, type CfAccessApp, type CfAccessGroup, type CfAccessPolicy, type CfAccessRule } from "./cloudflare.ts";
import { serviceTokensFor } from "./config.ts";
import type { Context } from "./context.ts";
import { edgeName, sameEmails } from "./edge.ts";
import { ApiError, FrostyError } from "./errors.ts";

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

// The permission the group check needs, named in its refusals.
export const GROUPS_PERMISSION = "Account · Access: Organizations, Identity Providers, and Groups · Read";

function groupRef(rule: CfAccessRule): string | undefined {
  const group = rule["group"] as { id?: unknown } | undefined;
  return group !== null && typeof group === "object" && typeof group.id === "string" ? group.id : undefined;
}

// What a set of rules lets in, as far as service tokens go: the configured tokens it names, and
// whether it takes any valid service token. Groups are resolved from the account's list; an
// unknown group fails closed. `nonIdentity` is true for a Service Auth policy's include, where any
// rule that isn't a specific service_token (everyone, an IP range...) lets any token in.
interface TokenReach {
  named: string[];
  any: boolean;
}

function reach(rules: CfAccessRule[], ids: Map<string, string>, groups: Map<string, CfAccessGroup>, nonIdentity: boolean, seen: Set<string> = new Set()): TokenReach {
  const named: string[] = [];
  let any = false;
  for (const rule of rules) {
    const tokenId = rule.service_token?.token_id;
    if (typeof tokenId === "string") {
      if (ids.has(tokenId)) {
        named.push(ids.get(tokenId) as string);
      }
      continue;
    }
    if ("any_valid_service_token" in rule) {
      any = true;
      continue;
    }
    const groupId = groupRef(rule);
    if (groupId !== undefined) {
      const group = groups.get(groupId);
      if (group === undefined) {
        throw new FrostyError(
          `frosty can't check Access group ${groupId}: a policy uses it, but it isn't in the account's list of groups.`,
          `A service token opens exactly one box, so frosty must see every group a policy uses. Give the Cloudflare API token "${GROUPS_PERMISSION}" (without it Cloudflare may return an empty list), then run the command again.`,
        );
      }
      if (seen.has(groupId)) {
        continue;
      }
      const inner = reach([...(group.include ?? []), ...(group.require ?? [])], ids, groups, nonIdentity, new Set([...seen, groupId]));
      named.push(...inner.named);
      any ||= inner.any;
      continue;
    }
    if (nonIdentity) {
      any = true;
    }
  }
  return { named, any };
}

function policyReach(p: { decision?: string; include?: CfAccessRule[]; require?: CfAccessRule[] }, ids: Map<string, string>, groups: Map<string, CfAccessGroup>): TokenReach {
  const nonIdentity = p.decision === "non_identity";
  const inc = reach(p.include ?? [], ids, groups, nonIdentity);
  // A require rule narrows, so only an explicit token rule or group in it counts, never everyone.
  const req = reach(p.require ?? [], ids, groups, false);
  return { named: [...new Set([...inc.named, ...req.named])], any: inc.any || req.any };
}

async function readGroups(ctx: Context): Promise<Map<string, CfAccessGroup>> {
  let groups: CfAccessGroup[];
  try {
    groups = await ctx.cloudflare.listAccessGroups(ctx.config.accountId);
  } catch (error) {
    if (error instanceof ApiError) {
      throw new FrostyError(`frosty can't check Access groups: Cloudflare said ${error.status} ${error.message}.`, `A service token opens exactly one box, so frosty must read every Access group. Give the Cloudflare API token "${GROUPS_PERMISSION}", then run the command again.`);
    }
    throw error;
  }
  return new Map(groups.map((g) => [g.id, g]));
}

// Every other Access policy and app that would also let one of these tokens in: a policy that
// names one (directly, in include or require, or through an Access group); a policy attached to
// another app that takes any valid service token (any_valid_service_token, or Service Auth with
// everyone); or an app that has the box's own token policy attached. Lists that leave out rules
// are read in full. `ids` maps token id to the name to print. Fails closed on groups it can't read.
export async function tokensUsedElsewhere(ctx: Context, box: string, ids: Map<string, string>, own: { appId: string | undefined; policyId: string | undefined }): Promise<string[]> {
  if (ids.size === 0) {
    return [];
  }
  const { cloudflare, config } = ctx;
  const [listedPolicies, listedApps, groups] = await Promise.all([cloudflare.listAccessPolicies(config.accountId), cloudflare.listAccessApps(config.accountId), readGroups(ctx)]);
  const policies = await Promise.all(listedPolicies.map((p) => (Array.isArray(p.include) ? p : cloudflare.getAccessPolicy(config.accountId, p.id))));
  const apps = await Promise.all(
    listedApps.filter((a) => a.id !== own.appId).map((a) => (a.policies === undefined || a.policies.some((p) => !Array.isArray(p.include)) ? cloudflare.getAccessApp(config.accountId, a.id) : a)),
  );
  const attachedElsewhere = new Map<string, string>();
  for (const app of apps) {
    for (const p of app.policies ?? []) {
      attachedElsewhere.set(p.id, app.name);
    }
  }
  const out: string[] = [];
  for (const p of policies) {
    if (p.id === own.policyId) {
      continue;
    }
    const r = policyReach(p, ids, groups);
    if (r.named.length > 0) {
      out.push(`Access policy ${p.name} includes ${r.named.join(", ")}`);
    }
    const on = attachedElsewhere.get(p.id);
    if (r.any && on !== undefined) {
      out.push(`Access policy ${p.name} (on ${on}) lets in any valid service token`);
    }
  }
  for (const app of apps) {
    for (const p of app.policies ?? []) {
      const label = `Access application ${app.name} (policy ${p.name ?? p.id})`;
      if (own.policyId !== undefined && p.id === own.policyId) {
        out.push(`${label} is ${tokenPolicyName(box)} itself`);
        continue;
      }
      const r = policyReach(p, ids, groups);
      if (r.named.length > 0) {
        out.push(`${label} includes ${r.named.join(", ")}`);
      }
      if (r.any) {
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
  // True for the step that rewrites the box's SSH app.
  app?: boolean;
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
    app: true,
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
