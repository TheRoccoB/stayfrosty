import { describe, expect, it } from "vitest";
import { Cloudflare } from "../src/cloudflare.ts";
import { ApiError } from "../src/errors.ts";
import { FakeHttp, cfFail, cfOk, noSleep } from "./fake-http.ts";

const HOST = "api.cloudflare.com";

function client(http: FakeHttp): Cloudflare {
  return new Cloudflare({ token: "cf-test-token-0123456789", fetch: http.fetch, sleep: noSleep });
}

describe("Cloudflare client", () => {
  it("unwraps the result envelope", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/user/tokens/verify", cfOk({ id: "t1", status: "active" }));
    expect(await client(http).verifyToken()).toEqual({ id: "t1", status: "active" });
  });

  it("falls back to the account verify path for account-owned tokens", async () => {
    const http = new FakeHttp()
      .on("GET", HOST, "/client/v4/user/tokens/verify", cfFail(401, 1000, "Invalid API Token"))
      .on("GET", HOST, "/client/v4/accounts/acc1/tokens/verify", cfOk({ id: "t2", status: "active" }));
    expect((await client(http).verifyToken("acc1")).id).toBe("t2");
  });

  it("sends prefixed account tokens straight to the account verify path", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/accounts/acc1/tokens/verify", cfOk({ id: "t3", status: "active" }));
    const cf = new Cloudflare({ token: `${"cf" + "at_"}${"x".repeat(44)}`, fetch: http.fetch, sleep: noSleep });
    expect((await cf.verifyToken("acc1")).id).toBe("t3");
    expect(http.calls.map((c) => c.url.pathname)).toEqual(["/client/v4/accounts/acc1/tokens/verify"]);
  });

  it("raises success:false as an ApiError with codes", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/zones", cfFail(403, 9109, "Unauthorized to access requested resource"));
    const error = (await client(http).findZone("example.com").catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe("9109");
    expect(error.hint).toContain("frosty init");
  });

  it("follows total_pages", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/accounts/acc1/cfd_tunnel", (call) => {
      const page = Number(call.url.searchParams.get("page"));
      return cfOk([{ id: `t${page}`, name: `stayfrosty-b${page}` }], { page, per_page: 1, total_pages: 3 });
    });
    const tunnels = await client(http).listTunnels("acc1", { is_deleted: false });
    expect(tunnels.map((t) => t.id)).toEqual(["t1", "t2", "t3"]);
    expect(http.calls[0]?.url.searchParams.get("is_deleted")).toBe("false");
  });

  it("follows cursors", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/accounts/acc1/access/apps", (call) => {
      const cursor = call.url.searchParams.get("cursor");
      if (cursor === null) {
        return cfOk([{ id: "a1" }], { cursor: "next" });
      }
      return cfOk([{ id: "a2" }], { cursor: "" });
    });
    expect((await client(http).listAccessApps("acc1")).map((a) => a.id)).toEqual(["a1", "a2"]);
  });

  it("matches the zone name exactly", async () => {
    const http = new FakeHttp().on("GET", HOST, "/client/v4/zones", cfOk([{ id: "z1", name: "example.com", status: "active", account: { id: "acc1", name: "a" } }]));
    expect(await client(http).findZone("example.com")).toMatchObject({ id: "z1" });
    expect(await client(http).findZone("other.com")).toBeUndefined();
  });
});
