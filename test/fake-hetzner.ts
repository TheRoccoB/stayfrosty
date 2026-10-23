import { FakeHttp, hzPage, type Call } from "./fake-http.ts";

const HZ = "api.hetzner.cloud";

// An in-memory Hetzner project that remembers what frosty creates.
export class FakeHetzner {
  servers: Record<string, unknown>[] = [];
  firewalls: Record<string, unknown>[] = [];
  sshKeys: Record<string, unknown>[] = [];
  readonly http: FakeHttp;
  private nextId = 100;

  constructor(http: FakeHttp) {
    this.http = http;
    const done = (command: string) => ({ id: this.id(), command, status: "success", progress: 100, error: null });
    const matches = (labels: Record<string, string>, call: Call): boolean => {
      const selector = call.url.searchParams.get("label_selector");
      if (selector === null) {
        return true;
      }
      return selector.split(",").every((part) => {
        const [k, v] = part.split("=");
        return labels[k as string] === v;
      });
    };
    const byName = (items: Record<string, unknown>[], call: Call) => {
      const name = call.url.searchParams.get("name");
      return items.filter((i) => (name === null || i["name"] === name) && matches(i["labels"] as Record<string, string>, call));
    };
    this.http
      .on("GET", HZ, "/v1/servers", (call) => hzPage("servers", byName(this.servers, call)))
      .on("GET", HZ, "/v1/firewalls", (call) => hzPage("firewalls", byName(this.firewalls, call)))
      .on("GET", HZ, "/v1/ssh_keys", () => hzPage("ssh_keys", this.sshKeys))
      .on("POST", HZ, "/v1/ssh_keys", (call) => {
        const key = { id: this.id(), fingerprint: "x", ...(call.body as Record<string, unknown>) };
        this.sshKeys.push(key);
        return { status: 201, body: { ssh_key: key } };
      })
      .on("POST", HZ, "/v1/firewalls", (call) => {
        const body = call.body as Record<string, unknown>;
        const firewall = { id: this.id(), applied_to: [], ...body };
        this.firewalls.push(firewall);
        return { status: 201, body: { firewall, actions: [] } };
      })
      .on("POST", HZ, "/v1/servers", (call) => {
        const body = call.body as Record<string, unknown>;
        const id = this.id();
        const server = {
          id,
          name: body["name"],
          status: "running",
          created: new Date().toISOString(),
          labels: body["labels"],
          server_type: { name: body["server_type"] },
          location: { name: body["location"] },
          public_net: {
            ipv4: { ip: "192.0.2.10" },
            ipv6: { ip: "2001:db8:1::/64" },
            firewalls: (body["firewalls"] as { firewall: number }[]).map((f) => ({ id: f.firewall, status: "applied" })),
          },
          userData: body["user_data"],
        };
        this.servers.push(server);
        return { status: 201, body: { server, action: done("create_server"), next_actions: [done("start_server")], root_password: null } };
      })
      .on("GET", HZ, "/v1/servers/\\d+", (call) => {
        const id = Number(call.url.pathname.split("/").pop());
        return { body: { server: this.servers.find((s) => s["id"] === id) } };
      })
      .on("DELETE", HZ, "/v1/servers/\\d+", (call) => {
        const id = Number(call.url.pathname.split("/").pop());
        this.servers = this.servers.filter((s) => s["id"] !== id);
        return { body: { action: done("delete_server") } };
      })
      .on("DELETE", HZ, "/v1/firewalls/\\d+", (call) => {
        const id = Number(call.url.pathname.split("/").pop());
        this.firewalls = this.firewalls.filter((f) => f["id"] !== id);
        return { status: 204 };
      })
      .on("POST", HZ, "/v1/firewalls/\\d+/actions/set_rules", (call) => {
        const id = Number(call.url.pathname.split("/")[3]);
        const firewall = this.firewalls.find((f) => f["id"] === id) as Record<string, unknown>;
        firewall["rules"] = (call.body as { rules: unknown }).rules;
        return { status: 201, body: { actions: [done("set_firewall_rules")] } };
      })
      .on("PUT", HZ, "/v1/servers/\\d+", (call) => {
        const id = Number(call.url.pathname.split("/")[3]);
        const server = this.servers.find((x) => x["id"] === id) as Record<string, unknown>;
        server["labels"] = (call.body as { labels: unknown }).labels;
        return { body: { server } };
      })
      .on("POST", HZ, "/v1/servers/\\d+/actions/change_protection", (call) => {
        const id = Number(call.url.pathname.split("/")[3]);
        const server = this.servers.find((x) => x["id"] === id) as Record<string, unknown>;
        server["protection"] = call.body;
        return { status: 201, body: { action: done("change_protection") } };
      })
      .on("POST", HZ, "/v1/firewalls/\\d+/actions/apply_to_resources", (call) => {
        const id = Number(call.url.pathname.split("/")[3]);
        const body = call.body as { apply_to: { server: { id: number } }[] };
        for (const target of body.apply_to) {
          const server = this.servers.find((x) => x["id"] === target.server.id) as { public_net: { firewalls: unknown[] } };
          server.public_net.firewalls.push({ id, status: "applied" });
        }
        const firewall = this.firewalls.find((f) => f["id"] === id) as { applied_to: unknown[] };
        firewall.applied_to.push(...body.apply_to.map((t) => ({ type: "server", server: { id: t.server.id } })));
        return { status: 201, body: { actions: [done("apply_firewall")] } };
      })
      .on("PUT", HZ, "/v1/firewalls/\\d+", (call) => {
        const id = Number(call.url.pathname.split("/")[3]);
        const firewall = this.firewalls.find((f) => f["id"] === id) as Record<string, unknown>;
        firewall["labels"] = (call.body as { labels: unknown }).labels;
        return { body: { firewall } };
      });
  }

  private id(): number {
    this.nextId += 1;
    return this.nextId;
  }
}
