import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { availableServerTypes, pickLocation, runInit, ubuntuLtsImages } from "../src/commands/init.ts";
import type { HzImage, HzServerType } from "../src/hetzner.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeHttp, cfFail, cfOk, hzPage, noSleep } from "./fake-http.ts";
import { ScriptedIo } from "./fixtures.ts";

const HZ = "api.hetzner.cloud";
const CF = "api.cloudflare.com";
const HCLOUD_TOKEN = "hzFAKEtoken0123456789abcdefghij";
const CLOUDFLARE_API_TOKEN = "cfFAKEtoken0123456789abcdefghij";

function serverType(name: string, monthly: string, extra: Partial<HzServerType> = {}): HzServerType {
  return {
    id: 1,
    name,
    description: name,
    cores: 2,
    memory: 4,
    disk: 40,
    architecture: "x86",
    cpu_type: "shared",
    prices: [{ location: "fsn1", price_monthly: { gross: monthly, net: monthly }, included_traffic: 20e12 }],
    locations: [{ id: 1, name: "fsn1", available: true, deprecation: null }],
    ...extra,
  };
}

function image(name: string, version: string, extra: Partial<HzImage> = {}): HzImage {
  return { id: 1, name, description: name, type: "system", status: "available", os_flavor: "ubuntu", os_version: version, architecture: "x86", deprecation: null, ...extra };
}

function fakeApis(): FakeHttp {
  return new FakeHttp()
    .on("GET", HZ, "/v1/servers", hzPage("servers", [{ id: 1, name: "other", labels: {} }]))
    .on("GET", HZ, "/v1/locations", hzPage("locations", [
      { id: 1, name: "fsn1", city: "Falkenstein", country: "DE", network_zone: "eu-central" },
      { id: 2, name: "ash", city: "Ashburn, VA", country: "US", network_zone: "us-east" },
    ]))
    .on("GET", HZ, "/v1/server_types", hzPage("server_types", [serverType("cx33", "6.00"), serverType("cx23", "4.00"), serverType("old", "1.00", { deprecated: true })]))
    .on("GET", HZ, "/v1/images", hzPage("images", [image("ubuntu-24.04", "24.04"), image("ubuntu-25.10", "25.10"), image("ubuntu-26.04", "26.04")]))
    .on("GET", HZ, "/v1/ssh_keys", hzPage("ssh_keys", []))
    .on("GET", CF, "/client/v4/zones", (call) => {
      if (call.url.searchParams.get("name") === "example.com") {
        return cfOk([{ id: "zone1", name: "example.com", status: "active", account: { id: "acc1", name: "acct" } }], { total_count: 1, total_pages: 1 });
      }
      if (call.url.searchParams.has("name")) {
        return cfOk([], { total_count: 0, total_pages: 1 });
      }
      return cfOk([{ id: "zone1", name: "example.com" }], { total_count: 1, total_pages: 1 });
    })
    .on("GET", CF, "/client/v4/user/tokens/verify", cfOk({ id: "tok", status: "active" }))
    .on("GET", CF, "/client/v4/zones/zone1/dns_records", cfOk([], { total_count: 3, total_pages: 1 }))
    .on("GET", CF, "/client/v4/accounts/acc1/cfd_tunnel", cfOk([], { total_pages: 1 }))
    .on("GET", CF, "/client/v4/accounts/acc1/access/apps", cfOk([], { total_pages: 1 }))
    .on("GET", CF, "/client/v4/accounts/acc1/alerting/v3/policies", cfOk([]));
}

// domain, emails, alert email, admin user, ssh key, location, server type, image, reboot, session, passwordCommand
const DEFAULT_ANSWERS = ["example.com", "Me@Example.com, you@example.com", "", "", "", "", "", "", "", "", ""];

describe("frosty init", () => {
  let home = "";
  let env: Record<string, string>;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "frosty-init-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE me@laptop\n");
    env = { HOME: home, PATH: "", HCLOUD_TOKEN, CLOUDFLARE_API_TOKEN };
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("writes the config with sensible defaults and makes only GET requests", async () => {
    const http = fakeApis();
    const io = new ScriptedIo(DEFAULT_ANSWERS);
    const code = await runInit({ io, dryRun: false, env, fetch: http.fetch, sleep: noSleep });
    expect(io.text()).not.toContain(HCLOUD_TOKEN);
    expect(io.text()).not.toContain(CLOUDFLARE_API_TOKEN);
    expect(code).toBe(0);
    expect(http.writes()).toEqual([]);
    const path = join(home, ".config", "stayfrosty", "config.json");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const config = JSON.parse(readFileSync(path, "utf8"));
    expect(config).toEqual({
      domain: "example.com",
      accountId: "acc1",
      zoneId: "zone1",
      accessEmails: ["me@example.com", "you@example.com"],
      alertEmail: "me@example.com",
      adminUser: "ops",
      sshKey: "~/.ssh/id_ed25519",
      location: "fsn1",
      serverType: "cx23",
      image: "ubuntu-26.04",
      rebootTime: "04:00",
      accessSessionDuration: "24h",
    });
    expect(io.text()).toContain("Nothing was created in Hetzner or Cloudflare.");
    expect(io.text()).toContain("not made by frosty");
  });

  it("dry run writes nothing", async () => {
    const http = fakeApis();
    const io = new ScriptedIo(DEFAULT_ANSWERS);
    await runInit({ io, dryRun: true, env, fetch: http.fetch, sleep: noSleep });
    expect(() => statSync(join(home, ".config", "stayfrosty", "config.json"))).toThrow();
    expect(io.text()).toContain("Dry run: would write");
  });

  it("re-asks for a domain the token cannot see", async () => {
    const http = fakeApis();
    const io = new ScriptedIo(["nope.com", ...DEFAULT_ANSWERS]);
    expect(await runInit({ io, dryRun: true, env, fetch: http.fetch, sleep: noSleep })).toBe(0);
    expect(io.stderr.join("\n")).toContain("cannot see a zone named nope.com");
  });

  it("fails a missing permission with a fix and exit code 1", async () => {
    const http = fakeApis().on("GET", CF, "/client/v4/accounts/acc1/access/apps", cfFail(403, 10000, "Authentication error"));
    const io = new ScriptedIo(DEFAULT_ANSWERS);
    const code = await runInit({ io, dryRun: true, env, fetch: http.fetch, sleep: noSleep });
    expect(code).toBe(1);
    expect(io.text()).toMatch(/FAIL\s+Cloudflare Access/);
    expect(io.text()).toContain("Access: Apps and Policies");
  });

  it("explains missing tokens without calling anything", async () => {
    const http = fakeApis();
    const io = new ScriptedIo([]);
    await expect(runInit({ io, dryRun: true, env: { HOME: home }, fetch: http.fetch, sleep: noSleep })).rejects.toThrow(/Missing HCLOUD_TOKEN and CLOUDFLARE_API_TOKEN/);
    expect(http.calls).toEqual([]);
  });

  it("turns a rejected Hetzner token into the token guide", async () => {
    const http = new FakeHttp().on("GET", HZ, "/v1/servers", { status: 401, body: { error: { code: "unauthorized", message: "unable to authenticate" } } });
    const io = new ScriptedIo([]);
    const error = (await runInit({ io, dryRun: true, env, fetch: http.fetch, sleep: noSleep }).catch((e: unknown) => e)) as { message: string; hint: string };
    expect(error.message).toContain("Hetzner token check failed");
    expect(error.hint).toContain("Read & Write");
  });
});

describe("init helpers", () => {
  it("prefers fsn1, then any EU location", () => {
    const loc = (name: string, zone: string) => ({ id: 1, name, description: "", city: "", country: "", network_zone: zone });
    expect(pickLocation([loc("ash", "us-east"), loc("fsn1", "eu-central")], undefined)).toBe("fsn1");
    expect(pickLocation([loc("ash", "us-east"), loc("hel1", "eu-central")], undefined)).toBe("hel1");
    expect(pickLocation([loc("ash", "us-east"), loc("hel1", "eu-central")], "ash")).toBe("ash");
  });

  it("drops deprecated and unavailable server types and sorts by price", () => {
    const types = [
      serverType("b", "5.00"),
      serverType("a", "3.00"),
      serverType("gone", "1.00", { locations: [{ id: 1, name: "fsn1", available: false }] }),
      serverType("dep", "1.00", { locations: [{ id: 1, name: "fsn1", deprecation: { announced: "2026-01-01" } }] }),
      serverType("elsewhere", "1.00", { prices: [{ location: "ash", price_monthly: { gross: "1", net: "1" } }] }),
    ];
    expect(availableServerTypes(types, "fsn1").map((t) => t.name)).toEqual(["a", "b"]);
  });

  it("keeps only Ubuntu LTS images, newest first", () => {
    const images = [image("ubuntu-22.04", "22.04"), image("ubuntu-25.04", "25.04"), image("ubuntu-24.04", "24.04"), image("ubuntu-20.04", "20.04", { deprecation: { unavailable_after: "x" } })];
    expect(ubuntuLtsImages(images).map((i) => i.name)).toEqual(["ubuntu-24.04", "ubuntu-22.04"]);
  });
});
