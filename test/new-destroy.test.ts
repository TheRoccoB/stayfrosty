import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runDestroy } from "../src/commands/destroy.ts";
import { runNew } from "../src/commands/new.ts";
import { saveConfig } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeHttp, hzPage, noSleep, type Call } from "./fake-http.ts";
import { FakeBox } from "./fake-ssh.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const HZ = "api.hetzner.cloud";
const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";

// An in-memory Hetzner project that remembers what frosty creates.
class FakeHetzner {
  servers: Record<string, unknown>[] = [];
  firewalls: Record<string, unknown>[] = [];
  sshKeys: Record<string, unknown>[] = [];
  readonly http = new FakeHttp();
  private nextId = 100;

  constructor() {
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

describe("frosty new and destroy", () => {
  let home = "";
  let env: Record<string, string>;
  let hz: FakeHetzner;
  let box: FakeBox;
  let forgotten: string[];

  const deps = (io: ScriptedIo, extra: Partial<Deps> = {}): Deps => ({
    io,
    env,
    fetch: hz.http.fetch,
    sleep: noSleep,
    now: () => 1_790_000_000_000,
    ssh: box.run,
    closeSsh: async () => {},
    forgetHost: async (host) => {
      forgotten.push(host);
    },
    laptopIp: async () => ({ ipv4: "198.51.100.7", ipv6: undefined }),
    isTty: true,
    ...extra,
  });

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-new-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await saveConfig(sampleConfig, env);
    hz = new FakeHetzner();
    box = new FakeBox();
    forgotten = [];
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("creates the firewall first with only the window, then the server with it attached", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(0);

    const writes = hz.http.writes().map((c) => `${c.method} ${c.url.pathname}`);
    expect(writes).toEqual(["POST /v1/ssh_keys", "POST /v1/firewalls", "POST /v1/servers"]);
    const firewall = hz.firewalls[0] as Record<string, unknown>;
    expect(firewall["name"]).toBe("stayfrosty-t1");
    expect(firewall["rules"]).toEqual([
      { direction: "in", protocol: "tcp", port: "22", source_ips: ["198.51.100.7/32"], description: "stayfrosty window" },
    ]);
    expect(firewall["labels"]).toMatchObject({ stayfrosty: "1", "stayfrosty-box": "t1", "stayfrosty-window-opened": "1790000000" });

    const serverBody = hz.http.writes()[2]?.body as Record<string, unknown>;
    expect(serverBody["firewalls"]).toEqual([{ firewall: firewall["id"] }]);
    expect(serverBody["labels"]).toEqual({ stayfrosty: "1", "stayfrosty-box": "t1" });
    expect(serverBody["user_data"]).toContain(PUBLIC_KEY);
    expect(serverBody["user_data"]).not.toMatch(/__[A-Z_]+__/);
    expect(serverBody["ssh_keys"]).toEqual([(hz.sshKeys[0] as { id: number }).id]);

    expect(forgotten).toEqual(["192.0.2.10", "2001:db8:1::1"]);
    expect(box.commands()).toContain("sudo cloud-init status --wait --long");
    expect(box.passwordState).toBe("P");
    expect(io.revealed).toHaveLength(1);
    expect(io.revealed[0]?.trim()).toMatch(/^[A-Za-z2-9]{24}$/);
    expect(io.text()).not.toContain(io.revealed[0]?.trim());
    expect(io.text()).toContain("ssh -i ~/.ssh/id_ed25519 ops@192.0.2.10");
  });

  it("sends the console password on stdin only", async () => {
    const io = new ScriptedIo();
    await runNew(deps(io), { box: "t1", resume: false, dryRun: false });
    const chpasswd = box.calls.find((c) => c.command === "sudo chpasswd");
    const password = io.revealed[0]?.trim() as string;
    expect(chpasswd?.opts.stdin).toBe(`ops:${password}\n`);
    expect(box.calls.every((c) => !c.command.includes(password))).toBe(true);
  });

  it("does not set a console password without a terminal or passwordCommand", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io, { isTty: false }), { box: "t1", resume: false, dryRun: false })).toBe(0);
    expect(box.passwordState).toBe("L");
    expect(io.revealed).toEqual([]);
    expect(io.stderr.join("\n")).toContain("frosty console-password t1");
  });

  it("hands the password to passwordCommand on stdin", async () => {
    await saveConfig({ ...sampleConfig, passwordCommand: "store {box}" }, env);
    const received: { command: string; password: string }[] = [];
    const io = new ScriptedIo();
    await runNew(deps(io, { isTty: false, runPasswordCommand: async (command, password) => {
      received.push({ command, password });
      return 0;
    } }), { box: "t1", resume: false, dryRun: false });
    expect(received).toHaveLength(1);
    expect(received[0]?.command).toBe("store t1");
    expect(box.passwordState).toBe("P");
    expect(io.revealed).toEqual([]);
  });

  it("reboots when the first upgrade needs it and waits for the new boot", async () => {
    box.rebootRequired = true;
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(0);
    expect(box.commands()).toContain("sudo systemctl reboot");
    expect(box.bootId).toBe("boot-2");
  });

  it("fails with the cloud-init log when cloud-init did not finish clean", async () => {
    box.on((call) => (call.command === "sudo cloud-init status --wait --long" ? { code: 1, stdout: "status: error", stderr: "" } : undefined));
    box.on((call) => (call.command === "sudo cat /var/log/cloud-init-output.log" ? { code: 0, stdout: "ok\nE: Unable to locate package nope\nhost keys", stderr: "" } : undefined));
    const io = new ScriptedIo();
    await expect(runNew(deps(io), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/Unable to locate package nope/);
  });

  it("refuses an existing box without --resume, and resumes with it", async () => {
    await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false });
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/already exists/);

    const io = new ScriptedIo();
    const before = hz.http.writes().length;
    const laptopMoved = { laptopIp: async () => ({ ipv4: "203.0.113.9", ipv6: undefined }) };
    expect(await runNew(deps(io, laptopMoved), { box: "t1", resume: true, dryRun: false })).toBe(0);
    const resumedWrites = hz.http.writes().slice(before).map((c) => `${c.method} ${c.url.pathname}`);
    expect(resumedWrites).toEqual([`POST /v1/firewalls/${(hz.firewalls[0] as { id: number }).id}/actions/set_rules`, `PUT /v1/firewalls/${(hz.firewalls[0] as { id: number }).id}`]);
    expect(hz.servers).toHaveLength(1);
    expect(io.text()).toContain("already set; leaving it");
  });

  it("never touches a server it did not create", async () => {
    hz.servers.push({ id: 1, name: "t1", status: "running", labels: {}, server_type: { name: "x" }, public_net: { ipv4: null, ipv6: null } });
    await expect(runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false })).rejects.toThrow(/frosty did not create it/);
    expect(hz.http.writes()).toEqual([]);
  });

  it("dry run changes nothing", async () => {
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: true })).toBe(0);
    expect(hz.http.writes()).toEqual([]);
    expect(box.calls).toEqual([]);
  });

  it("rejects bad box names before calling anything", async () => {
    await expect(runNew(deps(new ScriptedIo()), { box: "Web_1", resume: false, dryRun: false })).rejects.toThrow(/not a valid box name/);
    expect(hz.http.calls).toEqual([]);
  });

  it("reports failed checks with fixes and exit code 1", async () => {
    box.on((call) => (call.target.user === "root" ? { code: 0, stdout: "", stderr: "" } : undefined));
    const io = new ScriptedIo();
    expect(await runNew(deps(io), { box: "t1", resume: false, dryRun: false })).toBe(1);
    expect(io.text()).toMatch(/FAIL\s+root login is refused/);
    expect(io.text()).toContain("frosty destroy t1 && frosty new t1");
  });

  it("destroy needs the typed name, then deletes server and firewall", async () => {
    await runNew(deps(new ScriptedIo()), { box: "t1", resume: false, dryRun: false });
    forgotten = [];

    expect(await runDestroy(deps(new ScriptedIo(["t2"])), { box: "t1", dryRun: false })).toBe(1);
    expect(hz.servers).toHaveLength(1);

    const io = new ScriptedIo(["t1"]);
    expect(await runDestroy(deps(io), { box: "t1", dryRun: false })).toBe(0);
    expect(hz.servers).toEqual([]);
    expect(hz.firewalls).toEqual([]);
    expect(forgotten).toEqual(["192.0.2.10", "2001:db8:1::1"]);
    expect(io.text()).toContain("Box t1 is gone.");
  });

  it("destroy leaves unlabeled things alone and says when there is nothing", async () => {
    hz.servers.push({ id: 1, name: "t1", status: "running", labels: {}, server_type: { name: "x" }, public_net: { ipv4: null, ipv6: null } });
    const io = new ScriptedIo();
    expect(await runDestroy(deps(io), { box: "t1", dryRun: false })).toBe(0);
    expect(io.text()).toContain("nothing named t1");
    expect(hz.servers).toHaveLength(1);
  });
});
