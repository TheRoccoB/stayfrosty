import { isOurTokenPolicy, serviceTokenIds, tokenPolicyName, type CfAccessApp, type CfAccessPolicy, type CfAccessRule, type CfDnsRecord, type CfIngressRule, type CfNotificationPolicy, type CfServiceToken, type CfTunnel } from "../cloudflare.ts";
import { sameIngress } from "../edge.ts";
import type { HzFirewall, HzServer } from "../hetzner.ts";
import { LABEL_ADOPTED, LABEL_WINDOW_OPENED } from "../hetzner.ts";
import type { Fetch } from "../http.ts";
import { fail, pass, type CheckResult } from "./types.ts";

// Checks of what the APIs say about a box. Pure: the caller fetches, these judge.

function rebuild(box: string): string {
  return `Run: frosty new ${box} --resume, or for an adopted box frosty adopt ${box} --ip <ip> --resume (each step checks and repairs its part)`;
}

export function checkWindowClosed(box: string, firewall: HzFirewall | undefined, now: number): CheckResult {
  const name = "Box firewall: no inbound rules";
  if (firewall === undefined) {
    return fail(name, "the box has no stayfrosty firewall", rebuild(box));
  }
  const inbound = firewall.rules.filter((r) => r.direction === "in");
  if (inbound.length > 0) {
    const opened = Number(firewall.labels[LABEL_WINDOW_OPENED]);
    const age = Number.isFinite(opened) && opened > 0 ? `, open for ${Math.max(0, Math.round((now / 1000 - opened) / 60))} minutes` : "";
    const sources = inbound.flatMap((r) => r.source_ips ?? []).join(", ");
    return fail(name, `a window is open (TCP ${inbound.map((r) => r.port ?? "any").join(", ")} from ${sources}${age})`, rebuild(box));
  }
  return pass(name, "deny all inbound");
}

// Hetzner firewalls add up, so a second firewall's allow rules would undo frosty's deny-all.
export function checkOnlyOurFirewall(box: string, server: HzServer, firewall: HzFirewall | undefined): CheckResult {
  const name = "Box firewall is the only one attached";
  const attached = server.public_net.firewalls ?? [];
  const ours = firewall !== undefined && attached.some((f) => f.id === firewall.id && f.status === "applied");
  const others = attached.filter((f) => f.id !== firewall?.id);
  if (!ours || others.length > 0) {
    const problems = [...(ours ? [] : ["frosty's firewall is not attached"]), ...(others.length > 0 ? [`other firewall(s) attached: id ${others.map((f) => f.id).join(", ")}`] : [])];
    return fail(name, problems.join("; "), `Detach the others in the Hetzner Cloud Console (Firewalls); attach frosty's with the same command that set up ${box} and --resume.`);
  }
  return pass(name, `only ${firewall.name}`);
}

// An adopted server cannot be recreated (that is why it was adopted), so it must stay protected.
export function checkProtected(server: HzServer): CheckResult | undefined {
  if (server.labels[LABEL_ADOPTED] === undefined) {
    return undefined;
  }
  const name = "Adopted server: delete and rebuild protection on";
  if (server.protection?.delete !== true || server.protection.rebuild !== true) {
    return fail(name, `delete ${String(server.protection?.delete ?? false)}, rebuild ${String(server.protection?.rebuild ?? false)}`, `Run: frosty adopt ${server.name} --ip ${server.public_net.ipv4?.ip ?? "<ip>"} --resume`);
  }
  return pass(name, "delete and rebuild protected");
}

export function checkTunnel(box: string, tunnel: CfTunnel | undefined, ingress: CfIngressRule[], hostname: string, expected: CfIngressRule[], routes = 0): CheckResult {
  const name = routes === 0 ? "Tunnel healthy, ingress exactly SSH" : "Tunnel healthy, ingress exactly SSH and the routes";
  if (tunnel === undefined) {
    return fail(name, "no tunnel", rebuild(box));
  }
  const problems: string[] = [];
  if (tunnel.status !== "healthy") {
    problems.push(`status is ${tunnel.status}`);
  }
  if (!sameIngress(ingress, expected)) {
    problems.push(`ingress is ${ingress.map((r) => `${r.hostname ?? "*"}${r.path === undefined ? "" : ` ${r.path}`} -> ${r.service}`).join(", ") || "empty"}`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), tunnel.status !== "healthy" ? `Look at cloudflared on the box: ssh ${box} sudo journalctl -u cloudflared -n 50` : rebuild(box));
  }
  return pass(name, `healthy; ${hostname} to ssh://localhost:22${routes === 0 ? "" : `, ${routes} route(s) as generated`}, everything else 404`);
}

function ruleProblems(rules: CfAccessRule[] | undefined, emails: string[]): string[] {
  const problems: string[] = [];
  for (const rule of rules ?? []) {
    if ("everyone" in rule) {
      problems.push("an Everyone rule");
    } else if (rule.email === undefined) {
      problems.push(`a ${Object.keys(rule).join("/")} rule`);
    } else if (!emails.includes(rule.email.email.toLowerCase())) {
      problems.push(`email ${rule.email.email} is not in accessEmails`);
    }
  }
  return problems;
}

// A box's configured service tokens, as verify and service-tokens sync found them.
export interface ServiceTokenAccess {
  // The names in serviceTokens.<box>, and the tokens they resolved to.
  names: string[];
  tokens: { name: string; token: CfServiceToken }[];
  // Names that matched no token, or more than one.
  problems: string[];
  // Other policies and apps that would also let one of these tokens in.
  elsewhere: string[];
  now: number;
}

const DAY = 86_400_000;

// "expires 2027-01-31, in 86 days", and whether the token has expired or expires within 30 days.
export function tokenExpiry(token: CfServiceToken, now: number): { text: string; days: number | undefined; expired: boolean; soon: boolean } {
  const at = token.expires_at === undefined ? NaN : Date.parse(token.expires_at);
  if (!Number.isFinite(at)) {
    return { text: "no expiry date", days: undefined, expired: false, soon: false };
  }
  const date = new Date(at).toISOString().slice(0, 10);
  if (at <= now) {
    const ago = Math.floor((now - at) / DAY);
    return { text: `expired ${date}, ${ago} days ago`, days: -ago, expired: true, soon: false };
  }
  const days = Math.floor((at - now) / DAY);
  return { text: `expires ${date}, in ${days} days`, days, expired: false, soon: days < 30 };
}

export const SERVICE_TOKEN_ELSEWHERE_FIX =
  "A service token opens exactly one box: take it out of those policies and apps in the Cloudflare dashboard, or give the other app its own token.";

export const SERVICE_TOKEN_EXPIRED_FIX = "Refresh or rotate the token in the Cloudflare dashboard (Zero Trust, Access, Service credentials), and give the client the new secret if it changed.";

export function checkAccess(
  box: string,
  app: CfAccessApp | undefined,
  policy: CfAccessPolicy | undefined,
  hostname: string,
  emails: string[],
  tokenPolicy?: CfAccessPolicy,
  tokens?: ServiceTokenAccess,
): CheckResult {
  const name = tokens === undefined ? "Access: only your emails, no bypass or everyone" : "Access: only your emails and this box's service tokens";
  if (app === undefined || policy === undefined) {
    return fail(name, app === undefined ? "no Access application" : "no Access policy", rebuild(box));
  }
  const problems: string[] = [];
  const fixes = new Set<string>();
  const generic = "Fix it in the Cloudflare dashboard to match, or destroy and recreate the box.";
  const sync = `Run: frosty service-tokens sync ${box}`;
  const add = (problem: string, fix: string): void => {
    problems.push(problem);
    fixes.add(fix);
  };
  if (app.domain !== hostname) {
    add(`the app covers ${app.domain ?? "nothing"}, not ${hostname}`, generic);
  }
  const appPolicies = app.policies ?? [];
  const ours = tokenPolicy !== undefined && isOurTokenPolicy(tokenPolicy, box);
  if (tokens === undefined) {
    if (appPolicies.length !== 1 || appPolicies[0]?.id !== policy.id) {
      if (tokenPolicy !== undefined && appPolicies.some((p) => p.id === tokenPolicy.id)) {
        add(`${tokenPolicyName(box)} is attached, but serviceTokens has no tokens for ${box}`, sync);
      } else {
        add(`the app has ${appPolicies.length} policies, want only ${policy.name}`, generic);
      }
    }
  } else {
    if (tokenPolicy === undefined) {
      add(`no Access policy ${tokenPolicyName(box)}`, sync);
    } else if (!ours) {
      add(`${tokenPolicy.name} is not only service tokens (non_identity, service_token includes, no require or exclude)`, sync);
    }
    if (appPolicies.length !== 2 || appPolicies[0]?.id !== policy.id || appPolicies[1]?.id !== tokenPolicy?.id) {
      add(`the app's policies are ${appPolicies.map((p) => p.name ?? p.id).join(", ") || "none"}, want ${policy.name}, ${tokenPolicyName(box)}`, sync);
    }
    if (tokenPolicy !== undefined) {
      const want = new Set(tokens.tokens.map((t) => t.token.id));
      const have = new Set(serviceTokenIds(tokenPolicy.include));
      const extra = [...have].filter((id) => !want.has(id));
      const missing = tokens.tokens.filter((t) => !have.has(t.token.id)).map((t) => t.name);
      if (extra.length > 0) {
        add(`${tokenPolicyName(box)} lets in token id(s) not in serviceTokens.${box}: ${extra.join(", ")}`, sync);
      }
      if (missing.length > 0) {
        add(`${tokenPolicyName(box)} does not include ${missing.join(", ")}`, sync);
      }
    }
    for (const problem of tokens.problems) {
      add(problem, missingServiceTokenHint());
    }
    if (tokens.elsewhere.length > 0) {
      add(`a token of ${box} also opens: ${tokens.elsewhere.join("; ")}`, SERVICE_TOKEN_ELSEWHERE_FIX);
    }
    for (const t of tokens.tokens) {
      const expiry = tokenExpiry(t.token, tokens.now);
      if (expiry.expired) {
        add(`service token ${t.name} ${expiry.text}`, SERVICE_TOKEN_EXPIRED_FIX);
      }
    }
  }
  for (const p of [policy, ...appPolicies]) {
    // frosty's own token policy is non_identity by design, and checked above.
    if (ours && p.id === tokenPolicy.id) {
      continue;
    }
    if (p.decision !== undefined && p.decision !== "allow") {
      add(`policy ${p.name ?? p.id} decides ${p.decision}`, generic);
    }
  }
  for (const problem of ruleProblems(policy.include, emails)) {
    add(problem, generic);
  }
  const listed = new Set((policy.include ?? []).map((r) => r.email?.email.toLowerCase()).filter((e): e is string => e !== undefined));
  const missing = emails.filter((e) => !listed.has(e.toLowerCase()));
  if (missing.length > 0) {
    add(`the policy does not include ${missing.join(", ")}`, generic);
  }
  if ((policy.include ?? []).length === 0) {
    add("the policy includes nobody", generic);
  }
  if (problems.length > 0) {
    return fail(name, [...new Set(problems)].join("; "), [...fixes].join(" "));
  }
  const allow = `allow ${policy.include.map((r) => r.email?.email).join(", ")}`;
  if (tokens === undefined) {
    return pass(name, allow);
  }
  const listing = tokens.tokens.map((t) => {
    const e = tokenExpiry(t.token, tokens.now);
    return `${t.name} (${e.days === undefined ? "no expiry" : `${e.days} days left${e.soon ? ", renew soon" : ""}`})`;
  });
  return pass(name, `${allow}; service tokens ${listing.join(", ")}`);
}

// Cloudflare returns an empty list, not an error, when the token lacks the permission to read them.
export function missingServiceTokenHint(): string {
  return 'Create the token in the Cloudflare dashboard (Zero Trust, Access, Service credentials), or fix its name in serviceTokens. If it exists, the Cloudflare API token may lack "Account · Access: Service Tokens · Read": without it Cloudflare returns an empty list, not an error.';
}

// Hetzner gives each box a /64; anything in it points at the box.
export function ipv6Prefix(network: string | undefined): string | undefined {
  return network?.replace(/::\/64$/, ":").replace(/\/64$/, "");
}

export function checkDns(box: string, records: CfDnsRecord[], hostname: string, tunnelId: string | undefined, ipv4: string | undefined, ipv6Network: string | undefined): CheckResult {
  const name = "DNS: proxied CNAME to the tunnel, no record has the box's IP";
  const problems: string[] = [];
  const ssh = records.filter((r) => r.name === hostname);
  const want = tunnelId === undefined ? undefined : `${tunnelId}.cfargotunnel.com`;
  if (ssh.length !== 1 || ssh[0]?.type !== "CNAME" || ssh[0].content !== want || ssh[0].proxied !== true) {
    problems.push(`${hostname} is ${ssh.map((r) => `${r.type} ${r.content}${r.proxied === true ? " (proxied)" : ""}`).join(", ") || "missing"}`);
  }
  const prefix = ipv6Prefix(ipv6Network);
  const leaks = records.filter((r) => (ipv4 !== undefined && r.content.includes(ipv4)) || (prefix !== undefined && r.content.toLowerCase().startsWith(prefix.toLowerCase())));
  if (leaks.length > 0) {
    problems.push(`the box's IP is in ${leaks.map((r) => `${r.type} ${r.name}`).join(", ")}`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), leaks.length > 0 ? "Delete those records in the Cloudflare dashboard: they reveal the origin. Then consider the IP burned: frosty destroy and new." : rebuild(box));
  }
  return pass(name, `${hostname} is a proxied CNAME; ${records.length} records hold no box IP`);
}

export function checkAlert(box: string, alert: CfNotificationPolicy | undefined, tunnelId: string | undefined): CheckResult {
  const name = "Tunnel-down alert";
  if (alert === undefined) {
    return fail(name, "no notification policy", rebuild(box));
  }
  const ids = alert.filters?.["tunnel_id"] ?? [];
  if (!alert.enabled || tunnelId === undefined || !ids.includes(tunnelId)) {
    return fail(name, alert.enabled ? "it does not watch this box's tunnel" : "it is disabled", rebuild(box));
  }
  const to = (alert.mechanisms?.["email"] ?? []).map((m) => m.id).join(", ");
  return pass(name, `emails ${to || "nobody"} on tunnel health changes`);
}

// Without an Access session the SSH hostname must answer with the Access login, never the origin.
export function isAccessLogin(status: number, location: string | null, wwwAuthenticate: string | null): boolean {
  if ((status === 301 || status === 302 || status === 303 || status === 307) && location !== null) {
    try {
      const url = new URL(location);
      return url.hostname.endsWith(".cloudflareaccess.com") && url.pathname.startsWith("/cdn-cgi/access/login/");
    } catch {
      return false;
    }
  }
  return status === 401 && wwwAuthenticate !== null;
}

export async function checkAccessLogin(fetchImpl: Fetch, hostname: string): Promise<CheckResult> {
  const name = "Unauthenticated request gets the Access login";
  let response: Response;
  try {
    response = await fetchImpl(`https://${hostname}/`, { redirect: "manual", signal: AbortSignal.timeout(15_000) });
  } catch (error) {
    return fail(name, `request failed: ${error instanceof Error ? error.message : String(error)}`, "Check DNS for the SSH hostname, then run the command again.");
  }
  if (isAccessLogin(response.status, response.headers.get("location"), response.headers.get("www-authenticate"))) {
    return pass(name, `HTTP ${response.status} to the Access login`);
  }
  return fail(name, `HTTP ${response.status}${response.headers.get("location") === null ? "" : ` to ${response.headers.get("location")}`}`, "The Access application is not in front of the hostname. Recreate it: frosty destroy and new.");
}
