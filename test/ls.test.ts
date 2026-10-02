import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { formatAge, runLs } from "../src/commands/ls.ts";
import { saveConfig } from "../src/config.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeHttp, cfOk, hzPage, noSleep } from "./fake-http.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const HZ = "api.hetzner.cloud";
const CF = "api.cloudflare.com";

describe("frosty ls", () => {
  let home = "";
  let env: Record<string, string>;

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-ls-"));
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await saveConfig({ ...sampleConfig, accountId: "acc1" }, env);
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("says there are no boxes and only reads", async () => {
    const http = new FakeHttp()
      .on("GET", HZ, "/v1/servers", hzPage("servers", []))
      .on("GET", HZ, "/v1/firewalls", hzPage("firewalls", []))
      .on("GET", CF, "/client/v4/accounts/acc1/cfd_tunnel", cfOk([], { total_pages: 1 }));
    const io = new ScriptedIo();
    expect(await runLs({ io, env, fetch: http.fetch, sleep: noSleep })).toBe(0);
    expect(io.text()).toContain("No boxes.");
    expect(http.writes()).toEqual([]);
    const serverCall = http.calls.find((c) => c.url.pathname === "/v1/servers");
    expect(serverCall?.url.searchParams.get("label_selector")).toBe("stayfrosty=1");
  });

  it("shows boxes with tunnel health and an open window's age, and lists leftovers", async () => {
    const now = new Date("2026-10-01T12:00:00Z");
    const opened = Math.floor(now.getTime() / 1000) - 90 * 60;
    const http = new FakeHttp()
      .on("GET", HZ, "/v1/servers", hzPage("servers", [
        {
          id: 1,
          name: "web1",
          status: "running",
          created: "",
          labels: { stayfrosty: "1", "stayfrosty-box": "web1" },
          server_type: { name: "cx23" },
          location: { name: "fsn1" },
          public_net: { ipv4: { ip: "192.0.2.10" }, ipv6: null },
        },
      ]))
      .on("GET", HZ, "/v1/firewalls", hzPage("firewalls", [
        {
          id: 10,
          name: "stayfrosty-web1",
          labels: { stayfrosty: "1", "stayfrosty-box": "web1", "stayfrosty-window-opened": String(opened) },
          rules: [{ direction: "in", protocol: "tcp", port: "22", source_ips: ["198.51.100.7/32"] }],
          applied_to: [],
        },
        { id: 11, name: "stayfrosty-old", labels: { stayfrosty: "1", "stayfrosty-box": "old" }, rules: [], applied_to: [] },
      ]))
      .on("GET", CF, "/client/v4/accounts/acc1/cfd_tunnel", cfOk([
        { id: "t1", name: "stayfrosty-web1", status: "healthy", created_at: "", deleted_at: null },
        { id: "t2", name: "stayfrosty-gone", status: "down", created_at: "", deleted_at: null },
        { id: "t3", name: "someone-elses", status: "healthy", created_at: "", deleted_at: null },
      ], { total_pages: 1 }));
    const io = new ScriptedIo();
    await runLs({ io, env, fetch: http.fetch, sleep: noSleep, now: () => now });
    const text = io.text();
    expect(text).toMatch(/web1\s+running\s+cx23\s+fsn1\s+192\.0\.2\.10\s+healthy\s+OPEN 1h30m/);
    expect(text).toContain("Hetzner firewall stayfrosty-old");
    expect(text).toContain("Cloudflare tunnel stayfrosty-gone");
    expect(text).not.toContain("someone-elses");
  });

  it("formats ages", () => {
    expect(formatAge(5 * 60_000)).toBe("5m");
    expect(formatAge(120 * 60_000)).toBe("2h");
    expect(formatAge(72 * 3600_000)).toBe("3d");
  });
});
