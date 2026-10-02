import type { CfAccessApp, CfAccessPolicy, CfAccessRule, CfDnsRecord, CfIngressRule, CfNotificationPolicy, CfTunnel } from "../cloudflare.ts";
import { expectedIngress, sameIngress } from "../edge.ts";
import type { HzFirewall } from "../hetzner.ts";
import { LABEL_WINDOW_OPENED } from "../hetzner.ts";
import type { Fetch } from "../http.ts";
import { fail, pass, type CheckResult } from "./types.ts";

// Checks of what the APIs say about a box. Pure: the caller fetches, these judge.

function rebuild(box: string): string {
  return `Run: frosty new ${box} --resume (each step checks and repairs its part)`;
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
    return fail(name, `a window is open (TCP ${inbound.map((r) => r.port ?? "any").join(", ")} from ${sources}${age})`, `Close it with: frosty new ${box} --resume`);
  }
  return pass(name, "deny all inbound");
}

export function checkTunnel(box: string, tunnel: CfTunnel | undefined, ingress: CfIngressRule[], hostname: string): CheckResult {
  const name = "Tunnel healthy, ingress exactly SSH";
  if (tunnel === undefined) {
    return fail(name, "no tunnel", rebuild(box));
  }
  const problems: string[] = [];
  if (tunnel.status !== "healthy") {
    problems.push(`status is ${tunnel.status}`);
  }
  if (!sameIngress(ingress, expectedIngress(hostname))) {
    problems.push(`ingress is ${ingress.map((r) => `${r.hostname ?? "*"} -> ${r.service}`).join(", ") || "empty"}`);
  }
  if (problems.length > 0) {
    return fail(name, problems.join("; "), tunnel.status !== "healthy" ? `Look at cloudflared on the box: ssh ${box} sudo journalctl -u cloudflared -n 50` : rebuild(box));
  }
  return pass(name, `healthy; ${hostname} to ssh://localhost:22, everything else 404`);
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

export function checkAccess(box: string, app: CfAccessApp | undefined, policy: CfAccessPolicy | undefined, hostname: string, emails: string[]): CheckResult {
  const name = "Access: only your emails, no bypass or everyone";
  if (app === undefined || policy === undefined) {
    return fail(name, app === undefined ? "no Access application" : "no Access policy", rebuild(box));
  }
  const problems: string[] = [];
  if (app.domain !== hostname) {
    problems.push(`the app covers ${app.domain ?? "nothing"}, not ${hostname}`);
  }
  const appPolicies = app.policies ?? [];
  if (appPolicies.length !== 1 || appPolicies[0]?.id !== policy.id) {
    problems.push(`the app has ${appPolicies.length} policies, want only ${policy.name}`);
  }
  for (const p of [policy, ...appPolicies]) {
    if (p.decision !== undefined && p.decision !== "allow") {
      problems.push(`policy ${p.name ?? p.id} decides ${p.decision}`);
    }
  }
  problems.push(...ruleProblems(policy.include, emails));
  if ((policy.include ?? []).length === 0) {
    problems.push("the policy includes nobody");
  }
  if (problems.length > 0) {
    return fail(name, [...new Set(problems)].join("; "), "Fix it in the Cloudflare dashboard to match, or destroy and recreate the box.");
  }
  return pass(name, `allow ${policy.include.map((r) => r.email?.email).join(", ")}`);
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
