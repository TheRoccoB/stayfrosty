import type { FakeHttp } from "./fake-http.ts";

export const DO = "api.digitalocean.com";

type Obj = Record<string, unknown>;

// An in-memory DigitalOcean account that remembers what frosty creates. Firewalls apply to
// droplets by id and by tag, like the real thing.
export class FakeDigitalOcean {
  droplets: Obj[] = [];
  firewalls: Obj[] = [];
  sshKeys: Obj[] = [];
  tags: string[] = [];
  readonly http: FakeHttp;
  private nextId = 5000;

  constructor(http: FakeHttp) {
    this.http = http;
    const page = (key: string, items: unknown[]) => ({ body: { [key]: items, links: {}, meta: { total: items.length } } });
    const notFound = { status: 404, body: { id: "not_found", message: "The resource you were accessing could not be found." } };
    const dropletId = (path: string) => Number(path.split("/")[3]);
    const fwOf = (path: string) => this.firewalls.find((f) => f["id"] === path.split("/")[3]);
    const key = (r: unknown) => JSON.stringify(r);
    this.http
      .on("GET", DO, "/v2/droplets", (call) => {
        const tag = call.url.searchParams.get("tag_name");
        return page("droplets", this.droplets.filter((d) => tag === null || (d["tags"] as string[]).includes(tag)));
      })
      .on("GET", DO, "/v2/droplets/\\d+", (call) => {
        const droplet = this.droplets.find((d) => d["id"] === dropletId(call.url.pathname));
        return droplet === undefined ? notFound : { body: { droplet } };
      })
      .on("POST", DO, "/v2/droplets", (call) => {
        const body = call.body as Obj;
        const droplet = {
          id: this.id(),
          name: body["name"],
          status: "active",
          created_at: new Date().toISOString(),
          tags: body["tags"],
          size_slug: body["size"],
          region: { slug: body["region"] },
          networks: {
            v4: [
              { ip_address: "10.110.0.2", type: "private" },
              { ip_address: "203.0.113.40", type: "public" },
            ],
            v6: [{ ip_address: "2001:db8:40::2", type: "public" }],
          },
          userData: body["user_data"],
        };
        this.droplets.push(droplet);
        return { status: 202, body: { droplet, links: { actions: [{ id: 77, rel: "create", href: "x" }] } } };
      })
      .on("DELETE", DO, "/v2/droplets/\\d+", (call) => {
        const id = dropletId(call.url.pathname);
        this.droplets = this.droplets.filter((d) => d["id"] !== id);
        for (const f of this.firewalls) {
          f["droplet_ids"] = (f["droplet_ids"] as number[]).filter((x) => x !== id);
        }
        return { status: 204 };
      })
      .on("GET", DO, "/v2/actions/\\d+", (call) => ({ body: { action: { id: dropletId(call.url.pathname), status: "completed", type: "create" } } }))
      .on("GET", DO, "/v2/firewalls", () => page("firewalls", this.firewalls))
      .on("GET", DO, "/v2/firewalls/[0-9a-f-]+", (call) => {
        const firewall = fwOf(call.url.pathname);
        return firewall === undefined ? notFound : { body: { firewall } };
      })
      .on("POST", DO, "/v2/firewalls", (call) => {
        const body = call.body as Obj;
        const firewall = { id: `00000000-0000-4000-8000-${String(this.id()).padStart(12, "0")}`, status: "succeeded", pending_changes: [], ...body };
        this.firewalls.push(firewall);
        return { status: 202, body: { firewall } };
      })
      .on("POST", DO, "/v2/firewalls/[0-9a-f-]+/rules", (call) => {
        const firewall = fwOf(call.url.pathname) as Obj;
        firewall["inbound_rules"] = [...((firewall["inbound_rules"] as unknown[]) ?? []), ...((call.body as Obj)["inbound_rules"] as unknown[])];
        return { status: 204 };
      })
      .on("DELETE", DO, "/v2/firewalls/[0-9a-f-]+/rules", (call) => {
        const firewall = fwOf(call.url.pathname) as Obj;
        const gone = new Set(((call.body as Obj)["inbound_rules"] as unknown[]).map(key));
        firewall["inbound_rules"] = ((firewall["inbound_rules"] as unknown[]) ?? []).filter((r) => !gone.has(key(r)));
        return { status: 204 };
      })
      .on("POST", DO, "/v2/firewalls/[0-9a-f-]+/droplets", (call) => {
        const firewall = fwOf(call.url.pathname) as Obj;
        firewall["droplet_ids"] = [...new Set([...(firewall["droplet_ids"] as number[]), ...((call.body as Obj)["droplet_ids"] as number[])])];
        return { status: 204 };
      })
      .on("DELETE", DO, "/v2/firewalls/[0-9a-f-]+", (call) => {
        const id = call.url.pathname.split("/")[3];
        this.firewalls = this.firewalls.filter((f) => f["id"] !== id);
        return { status: 204 };
      })
      .on("GET", DO, "/v2/account/keys", () => page("ssh_keys", this.sshKeys))
      .on("POST", DO, "/v2/account/keys", (call) => {
        const sshKey = { id: this.id(), fingerprint: "aa:bb", ...(call.body as Obj) };
        this.sshKeys.push(sshKey);
        return { status: 201, body: { ssh_key: sshKey } };
      })
      .on("POST", DO, "/v2/tags", (call) => {
        const name = (call.body as { name: string }).name;
        if (this.tags.includes(name)) {
          return { status: 422, body: { id: "unprocessable_entity", message: "tag already exists" } };
        }
        this.tags.push(name);
        return { status: 201, body: { tag: { name } } };
      });
  }

  private id(): number {
    this.nextId += 1;
    return this.nextId;
  }
}
