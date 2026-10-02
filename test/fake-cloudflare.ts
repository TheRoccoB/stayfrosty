import { cfOk, type Call, type FakeHttp } from "./fake-http.ts";

const CF = "api.cloudflare.com";
const ACCT = "/client/v4/accounts/[^/]+";
const ZONE = "/client/v4/zones/[^/]+";

type Item = Record<string, unknown>;

// An in-memory Cloudflare account and zone that remembers what frosty creates.
export class FakeCloudflare {
  tunnels: Item[] = [];
  ingress = new Map<string, unknown[]>();
  dns: Item[] = [];
  apps: Item[] = [];
  policies: Item[] = [];
  alerts: Item[] = [];
  tokenFetches = 0;
  private next = 1;

  constructor(http: FakeHttp, opts: { teamDomain?: string } = {}) {
    const team = opts.teamDomain ?? "team.cloudflareaccess.com";
    const lastId = (call: Call, fromEnd = 0): string => call.url.pathname.split("/").at(-1 - fromEnd) as string;
    const body = (call: Call): Item => call.body as Item;
    http
      .on("GET", CF, `${ACCT}/cfd_tunnel`, (call) => {
        const name = call.url.searchParams.get("name");
        return cfOk(this.tunnels.filter((t) => name === null || t["name"] === name), { total_pages: 1 });
      })
      .on("POST", CF, `${ACCT}/cfd_tunnel`, (call) => {
        const tunnel = { id: `tun-${this.id()}`, name: body(call)["name"], status: "inactive", created_at: "", deleted_at: null };
        this.tunnels.push(tunnel);
        return cfOk(tunnel);
      })
      .on("GET", CF, `${ACCT}/cfd_tunnel/[^/]+`, (call) => cfOk(this.tunnels.find((t) => t["id"] === lastId(call))))
      .on("GET", CF, `${ACCT}/cfd_tunnel/[^/]+/token`, (call) => {
        this.tokenFetches += 1;
        // The connector "starts" once the token is fetched.
        const tunnel = this.tunnels.find((t) => t["id"] === lastId(call, 1));
        if (tunnel !== undefined) {
          tunnel["status"] = "healthy";
        }
        return cfOk(FAKE_TUNNEL_TOKEN);
      })
      .on("GET", CF, `${ACCT}/cfd_tunnel/[^/]+/configurations`, (call) => cfOk({ config: { ingress: this.ingress.get(lastId(call, 1)) ?? [] } }))
      .on("PUT", CF, `${ACCT}/cfd_tunnel/[^/]+/configurations`, (call) => {
        this.ingress.set(lastId(call, 1), (body(call)["config"] as { ingress: unknown[] }).ingress);
        return cfOk({});
      })
      .on("DELETE", CF, `${ACCT}/cfd_tunnel/[^/]+/connections`, () => cfOk({}))
      .on("DELETE", CF, `${ACCT}/cfd_tunnel/[^/]+`, (call) => {
        this.tunnels = this.tunnels.filter((t) => t["id"] !== lastId(call));
        return cfOk({});
      })
      .on("GET", CF, `${ZONE}/dns_records`, (call) => {
        const name = call.url.searchParams.get("name");
        const commentPrefix = call.url.searchParams.get("comment.startswith");
        const records = this.dns.filter((r) => (name === null || r["name"] === name) && (commentPrefix === null || String(r["comment"] ?? "").startsWith(commentPrefix)));
        return cfOk(records, { total_pages: 1, total_count: records.length });
      })
      .on("POST", CF, `${ZONE}/dns_records`, (call) => {
        const record = { id: `dns-${this.id()}`, ...body(call) };
        this.dns.push(record);
        return cfOk(record);
      })
      .on("DELETE", CF, `${ZONE}/dns_records/[^/]+`, (call) => {
        this.dns = this.dns.filter((r) => r["id"] !== lastId(call));
        return cfOk({});
      })
      .on("GET", CF, `${ACCT}/access/policies`, () => cfOk(this.policies, { total_pages: 1 }))
      .on("POST", CF, `${ACCT}/access/policies`, (call) => {
        const policy = { id: `pol-${this.id()}`, ...body(call) };
        this.policies.push(policy);
        return cfOk(policy);
      })
      .on("DELETE", CF, `${ACCT}/access/policies/[^/]+`, (call) => {
        if (this.apps.some((a) => (a["policies"] as { id: string }[]).some((p) => p.id === lastId(call)))) {
          return { status: 409, body: { success: false, errors: [{ code: 12130, message: "policy is in use" }], result: null } };
        }
        this.policies = this.policies.filter((p) => p["id"] !== lastId(call));
        return cfOk({});
      })
      .on("GET", CF, `${ACCT}/access/apps`, () => cfOk(this.apps, { total_pages: 1 }))
      .on("POST", CF, `${ACCT}/access/apps`, (call) => {
        const app = { id: `app-${this.id()}`, ...body(call) };
        this.apps.push(app);
        return cfOk(app);
      })
      .on("GET", CF, `${ACCT}/access/apps/[^/]+`, (call) => {
        const app = this.apps.find((a) => a["id"] === lastId(call));
        if (app === undefined) {
          return { status: 404, body: { success: false, errors: [{ code: 404, message: "not found" }], result: null } };
        }
        // The API returns each policy expanded.
        const policies = (app["policies"] as { id: string; precedence: number }[]).map((ref) => ({ ...this.policies.find((p) => p["id"] === ref.id), precedence: ref.precedence }));
        return cfOk({ ...app, policies });
      })
      .on("DELETE", CF, `${ACCT}/access/apps/[^/]+`, (call) => {
        this.apps = this.apps.filter((a) => a["id"] !== lastId(call));
        return cfOk({});
      })
      .on("GET", CF, `${ACCT}/alerting/v3/policies`, () => cfOk(this.alerts))
      .on("POST", CF, `${ACCT}/alerting/v3/policies`, (call) => {
        const alert = { id: `alert-${this.id()}`, ...body(call) };
        this.alerts.push(alert);
        return cfOk({ id: alert.id });
      })
      .on("DELETE", CF, `${ACCT}/alerting/v3/policies/[^/]+`, (call) => {
        this.alerts = this.alerts.filter((a) => a["id"] !== lastId(call));
        return cfOk({});
      })
      // Any SSH hostname without a session: Access sends the browser to its login page.
      .on("GET", "ssh-t1.example.com", "/", () => ({
        status: 302,
        headers: { location: `https://${team}/cdn-cgi/access/login/ssh-t1.example.com?kid=abc&redirect_url=%2F` },
      }));
  }

  private id(): number {
    this.next += 1;
    return this.next;
  }
}

// Shaped like a real tunnel token so the redaction patterns apply to it.
export const FAKE_TUNNEL_TOKEN = Buffer.from(JSON.stringify({ a: "acc123", t: "tun-2", s: "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0" })).toString("base64");
