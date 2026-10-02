import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/errors.ts";
import { Hetzner } from "../src/hetzner.ts";
import { clearSecretsForTests, registerSecret } from "../src/redact.ts";
import { FakeHttp, hzPage, noSleep } from "./fake-http.ts";

const HOST = "api.hetzner.cloud";
const TOKEN = "hz-test-token-0123456789";

function client(http: FakeHttp): Hetzner {
  return new Hetzner({ token: TOKEN, fetch: http.fetch, sleep: noSleep });
}

afterEach(() => {
  clearSecretsForTests();
});

describe("Hetzner client", () => {
  it("sends the bearer token and the label selector", async () => {
    const http = new FakeHttp().on("GET", HOST, "/v1/servers", hzPage("servers", []));
    await client(http).listServers("stayfrosty=1");
    expect(http.calls[0]?.authorization).toBe(`Bearer ${TOKEN}`);
    expect(http.calls[0]?.url.searchParams.get("label_selector")).toBe("stayfrosty=1");
  });

  it("follows next_page", async () => {
    const http = new FakeHttp().on("GET", HOST, "/v1/locations", (call) => {
      const page = call.url.searchParams.get("page");
      if (page === "1") {
        return hzPage("locations", [{ name: "fsn1" }], 2);
      }
      return hzPage("locations", [{ name: "nbg1" }], null);
    });
    const locations = await client(http).listLocations();
    expect(locations.map((l) => l.name)).toEqual(["fsn1", "nbg1"]);
    expect(http.calls).toHaveLength(2);
  });

  it("retries a rate-limited read", async () => {
    let n = 0;
    const http = new FakeHttp().on("GET", HOST, "/v1/ssh_keys", () => {
      n += 1;
      return n === 1 ? { status: 429, body: { error: { code: "rate_limit_exceeded", message: "slow down" } } } : hzPage("ssh_keys", []);
    });
    await client(http).listSshKeys();
    expect(n).toBe(2);
  });

  it("does not retry a write", async () => {
    const http = new FakeHttp().on("POST", HOST, "/v1/firewalls", { status: 503, body: { error: { code: "unavailable", message: "try later" } } });
    await expect(client(http).request("POST", "/firewalls", { name: "x" })).rejects.toBeInstanceOf(ApiError);
    expect(http.calls).toHaveLength(1);
  });

  it("turns a 401 into a hint about the token", async () => {
    const http = new FakeHttp().on("GET", HOST, "/v1/servers", { status: 401, body: { error: { code: "unauthorized", message: "unable to authenticate" } } });
    const error = await client(http).listServers().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).hint).toContain("HCLOUD_TOKEN");
  });

  it("explains a read-only token on write", async () => {
    const http = new FakeHttp().on("POST", HOST, "/v1/servers", { status: 403, body: { error: { code: "token_readonly", message: "forbidden" } } });
    const error = await client(http).request("POST", "/servers", {}).catch((e: unknown) => e);
    expect((error as ApiError).hint).toContain("Read & Write");
  });

  it("never puts the token in an error message", async () => {
    registerSecret(TOKEN);
    const http = new FakeHttp().on("GET", HOST, "/v1/servers", { status: 400, body: { error: { code: "invalid_input", message: `bad token ${TOKEN}` } } });
    const error = (await client(http).listServers().catch((e: unknown) => e)) as Error;
    expect(error.message).not.toContain(TOKEN);
    expect(error.message).toContain("[redacted]");
  });
});
