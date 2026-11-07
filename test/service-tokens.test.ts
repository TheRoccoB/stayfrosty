import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkAccess, type ServiceTokenAccess } from "../src/checks/edge.ts";
import { main } from "../src/cli.ts";
import { appFieldsFrostyWouldReset, Cloudflare, isOurTokenPolicy, tokenPolicyName, type CfAccessApp, type CfAccessPolicy, type CfServiceToken } from "../src/cloudflare.ts";
import { runServiceTokens } from "../src/commands/service-tokens.ts";
import { saveConfig, serviceTokensFor, validateConfig, type Config } from "../src/config.ts";
import type { Deps } from "../src/context.ts";
import { clearSecretsForTests } from "../src/redact.ts";
import { FakeCloudflare } from "./fake-cloudflare.ts";
import { FakeHttp, noSleep } from "./fake-http.ts";
import { ScriptedIo, sampleConfig } from "./fixtures.ts";

const PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake me@laptop";
const NOW = Date.parse("2026-11-06T12:00:00Z");
const DAY = 86_400_000;
const ID1 = "11111111-1111-4111-8111-111111111111";
const ID2 = "22222222-2222-4222-8222-222222222222";
const ID3 = "33333333-3333-4333-8333-333333333333";
const days = (n: number): string => new Date(NOW + n * DAY).toISOString();

describe("serviceTokens config", () => {
  it("accepts token names per box and refuses bad ones", () => {
    expect(validateConfig({ ...sampleConfig, serviceTokens: { box1: ["backup-puller-box1"], box2: ["a.b_c-1", "other"] } })).toEqual([]);
    expect(validateConfig({ ...sampleConfig, serviceTokens: { box1: [] } })).toEqual([]);
    for (const bad of [[], null, "x", { Box1: ["a"] }, { box1: "a" }, { box1: [1] }, { box1: ["-a"] }, { box1: ["a b"] }, { box1: ["a".repeat(65)] }, { box1: ["a", "a"] }]) {
      expect(validateConfig({ ...sampleConfig, serviceTokens: bad }).join(), JSON.stringify(bad)).toMatch(/serviceTokens/);
    }
  });

  it("refuses the same token under two boxes", () => {
    const problems = validateConfig({ ...sampleConfig, serviceTokens: { box1: ["backup-puller"], box2: ["backup-puller"] } });
    expect(problems).toEqual(["service token backup-puller is listed under both box1 and box2: a service token opens exactly one box"]);
  });

  it("serviceTokensFor gives the box's names, or none", () => {
    expect(serviceTokensFor({ serviceTokens: { box1: ["a"] } }, "box1")).toEqual(["a"]);
    expect(serviceTokensFor({ serviceTokens: { box1: ["a"] } }, "box2")).toEqual([]);
    expect(serviceTokensFor({}, "box1")).toEqual([]);
    expect(serviceTokensFor({ serviceTokens: { box1: ["a"] } }, "constructor")).toEqual([]);
  });
});

describe("isOurTokenPolicy", () => {
  const good = { name: "stayfrosty-box1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID2 } }] };

  it("accepts frosty's shape for its own box only", () => {
    expect(tokenPolicyName("box1")).toBe("stayfrosty-box1:service-tokens");
    expect(isOurTokenPolicy(good, "box1")).toBe(true);
    expect(isOurTokenPolicy({ ...good, require: [], exclude: [] }, "box1")).toBe(true);
    expect(isOurTokenPolicy(good, "box2")).toBe(false);
    expect(isOurTokenPolicy(good, "Box1")).toBe(false);
  });

  it("refuses everything else", () => {
    const bad: Record<string, unknown>[] = [
      { ...good, name: "stayfrosty-box1" },
      { ...good, name: "stayfrosty-box1:service-tokens:x" },
      { ...good, decision: "allow" },
      { ...good, decision: "bypass" },
      { ...good, include: [] },
      { ...good, include: [{ everyone: {} }] },
      { ...good, include: [{ email: { email: "me@example.com" } }] },
      { ...good, include: [{ any_valid_service_token: {} }] },
      { ...good, include: [{ service_token: { token_id: ID1 }, email: { email: "me@example.com" } }] },
      { ...good, include: [{ service_token: { token_id: ID1, extra: 1 } }] },
      { ...good, include: [{ service_token: { token_id: 7 } }] },
      { ...good, include: [{ service_token: null }] },
      { ...good, include: [...good.include, { everyone: {} }] },
      { ...good, require: [{ email: { email: "me@example.com" } }] },
      { ...good, exclude: [{ ip: { ip: "192.0.2.1/32" } }] },
    ];
    for (const p of bad) {
      expect(isOurTokenPolicy(p as Parameters<typeof isOurTokenPolicy>[0], "box1"), JSON.stringify(p)).toBe(false);
    }
  });
});

describe("Cloudflare client guards for service tokens", () => {
  let http: FakeHttp;
  let cf: FakeCloudflare;
  let client: Cloudflare;

  beforeEach(() => {
    http = new FakeHttp();
    cf = new FakeCloudflare(http);
    client = new Cloudflare({ token: "cf-test-token-0123456789", fetch: http.fetch, sleep: noSleep });
    cf.policies.push({ id: "pol-email", name: "stayfrosty-box1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    cf.policies.push({ id: "pol-tok", name: "stayfrosty-box1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    cf.policies.push({ id: "pol-other", name: "someone-elses", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    cf.apps.push({ id: "app-ssh", name: "stayfrosty-box1", type: "self_hosted", domain: "ssh-box1.example.com", session_duration: "24h", policies: [{ id: "pol-email", precedence: 1 }] });
  });

  it("createAccessPolicy still refuses service token policies", async () => {
    await expect(client.createAccessPolicy("acc1", { name: "stayfrosty-box1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] })).rejects.toThrow(/only creates allow policies of plain email rules/);
    await expect(client.createAccessPolicy("acc1", { name: "stayfrosty-box1", decision: "allow", include: [{ service_token: { token_id: ID1 } }] })).rejects.toThrow(/only creates allow policies/);
    expect(http.writes()).toEqual([]);
  });

  it("putTokenPolicy builds the body itself and refuses bad ids or someone else's policy", async () => {
    await client.putTokenPolicy("acc1", "box1", [ID2, ID1]);
    expect(http.writes()[0]?.body).toEqual({ name: "stayfrosty-box1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID2 } }] });
    await expect(client.putTokenPolicy("acc1", "box1", [])).rejects.toThrow(/one or more distinct service token ids/);
    await expect(client.putTokenPolicy("acc1", "box1", [ID1, ID1])).rejects.toThrow(/distinct/);
    await expect(client.putTokenPolicy("acc1", "box1", ["not-a-token-id"])).rejects.toThrow(/distinct service token ids/);
    await expect(client.putTokenPolicy("acc1", "Box1", [ID1])).rejects.toThrow(/refused/);
    await expect(client.putTokenPolicy("acc1", "box1", [ID1], "pol-other")).rejects.toThrow(/pol-other is named someone-elses/);
    await expect(client.putTokenPolicy("acc1", "box1", [ID1], "pol-email")).rejects.toThrow(/is named stayfrosty-box1/);
    expect(http.writes()).toHaveLength(1);
  });

  it("appFieldsFrostyWouldReset allows only empty values, defaults and the app's own domain", () => {
    const base = { id: "a", aud: "x", name: "stayfrosty-box1", type: "self_hosted", domain: "ssh-box1.example.com", session_duration: "24h", app_launcher_visible: false, policies: [], created_at: "t", updated_at: "t" };
    expect(appFieldsFrostyWouldReset({ ...base, allowed_idps: [], auto_redirect_to_identity: false, custom_deny_message: "", cors_headers: { allow_all_origins: false, allowed_origins: [] }, http_only_cookie_attribute: true, tags: [], self_hosted_domains: ["ssh-box1.example.com"], destinations: [{ type: "public", uri: "ssh-box1.example.com" }] })).toEqual([]);
    expect(
      appFieldsFrostyWouldReset({
        ...base,
        allowed_idps: ["x"],
        auto_redirect_to_identity: true,
        enable_binding_cookie: true,
        same_site_cookie_attribute: "strict",
        cors_headers: { allowed_origins: ["https://example.net"] },
        custom_deny_url: "https://example.net",
        skip_interstitial: true,
        tags: ["t"],
        http_only_cookie_attribute: false,
        some_new_field: "on",
        destinations: [{ type: "public", uri: "other.example.com" }],
      }),
    ).toEqual(["allowed_idps", "auto_redirect_to_identity", "enable_binding_cookie", "same_site_cookie_attribute", "cors_headers", "custom_deny_url", "skip_interstitial", "tags", "some_new_field", "destinations"]);
  });

  it("putSshAppPolicies only sets the box's own email and token policies on its own SSH app", async () => {
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh", ["pol-tok"], "24h")).rejects.toThrow(/not the box's allow-by-email policy/);
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh", ["pol-email", "pol-other"], "24h")).rejects.toThrow(/not the box's service token policy/);
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh", ["pol-email", "pol-tok", "pol-other"], "24h")).rejects.toThrow(/at most the service token policy/);
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh", [], "24h")).rejects.toThrow(/at most/);
    await expect(client.putSshAppPolicies("acc1", "box2", "app-ssh", ["pol-email"], "24h")).rejects.toThrow(/not the self-hosted app for ssh-box2/);
    cf.apps.push({ id: "app-wild", name: "stayfrosty-box1", type: "self_hosted", domain: "*.example.com", policies: [] });
    cf.apps.push({ id: "app-ssh2", name: "stayfrosty-box1", type: "ssh", domain: "ssh-box1.example.com", policies: [] });
    await expect(client.putSshAppPolicies("acc1", "box1", "app-wild", ["pol-email"], "24h")).rejects.toThrow(/refused/);
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh2", ["pol-email"], "24h")).rejects.toThrow(/refused/);
    expect(http.writes()).toEqual([]);

    (cf.apps[0] as Record<string, unknown>)["allowed_idps"] = ["x"];
    await expect(client.putSshAppPolicies("acc1", "box1", "app-ssh", ["pol-email"], "24h")).rejects.toThrow(/has allowed_idps set, and frosty's update would reset them/);
    delete (cf.apps[0] as Record<string, unknown>)["allowed_idps"];
    expect(http.writes()).toEqual([]);

    await client.putSshAppPolicies("acc1", "box1", "app-ssh", ["pol-email", "pol-tok"], "12h");
    expect(http.writes()[0]?.body).toEqual({
      name: "stayfrosty-box1",
      type: "self_hosted",
      domain: "ssh-box1.example.com",
      session_duration: "24h",
      app_launcher_visible: false,
      policies: [
        { id: "pol-email", precedence: 1 },
        { id: "pol-tok", precedence: 2 },
      ],
    });
  });
});

describe("checkAccess with service tokens", () => {
  const email: CfAccessPolicy = { id: "pe", name: "stayfrosty-t1", decision: "allow", include: [{ email: { email: "me@example.com" } }] };
  const tokenPolicy: CfAccessPolicy = { id: "pt", name: "stayfrosty-t1:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] };
  const app = (policies: CfAccessPolicy[]): CfAccessApp => ({ id: "a", name: "stayfrosty-t1", type: "self_hosted", domain: "ssh-t1.example.com", policies: policies.map((p, i) => ({ ...p, precedence: i + 1 })) });
  const token: CfServiceToken = { id: ID1, name: "backup-puller-t1", expires_at: days(40) };
  const access = (extra: Partial<ServiceTokenAccess> = {}): ServiceTokenAccess => ({ names: ["backup-puller-t1"], tokens: [{ name: "backup-puller-t1", token }], problems: [], elsewhere: [], now: NOW, ...extra });
  const check = (a: CfAccessApp, tp: CfAccessPolicy | undefined, t: ServiceTokenAccess | undefined) => checkAccess("t1", a, email, "ssh-t1.example.com", ["me@example.com"], tp, t);

  it("passes with exactly the email policy and the configured tokens, listing days left", () => {
    const r = check(app([email, tokenPolicy]), tokenPolicy, access());
    expect(r.ok, r.detail).toBe(true);
    expect(r.name).toBe("Access: only your emails and this box's service tokens");
    expect(r.detail).toBe("allow me@example.com; service tokens backup-puller-t1 (40 days left)");
    const soon = check(app([email, tokenPolicy]), tokenPolicy, access({ tokens: [{ name: "backup-puller-t1", token: { ...token, expires_at: days(5) } }] }));
    expect(soon.ok).toBe(true);
    expect(soon.detail).toContain("5 days left, renew soon");
  });

  it("without tokens configured, checks exactly as before, and a token policy attached fails with the sync fix", () => {
    const r = check(app([email]), undefined, undefined);
    expect(r).toMatchObject({ ok: true, name: "Access: only your emails, no bypass or everyone", detail: "allow me@example.com" });
    const attached = check(app([email, tokenPolicy]), tokenPolicy, undefined);
    expect(attached.ok).toBe(false);
    expect(attached.detail).toContain("stayfrosty-t1:service-tokens is attached, but serviceTokens has no tokens for t1");
    expect(attached.fix).toBe("Run: frosty service-tokens sync t1");
  });

  it("fails when the token policy is missing, not attached, or the wrong shape", () => {
    const missing = check(app([email]), undefined, access());
    expect(missing.ok).toBe(false);
    expect(missing.detail).toContain("no Access policy stayfrosty-t1:service-tokens");
    expect(missing.fix).toBe("Run: frosty service-tokens sync t1");
    const detached = check(app([email]), tokenPolicy, access());
    expect(detached.detail).toContain("the app's policies are stayfrosty-t1, want stayfrosty-t1, stayfrosty-t1:service-tokens");
    const open = { ...tokenPolicy, include: [...tokenPolicy.include, { everyone: {} }] };
    const wide = check(app([email, open]), open, access());
    expect(wide.ok).toBe(false);
    expect(wide.detail).toContain("is not only service tokens");
    expect(wide.detail).toContain("decides non_identity");
  });

  it("fails on token ids that aren't configured, missing ones, use elsewhere, and expiry", () => {
    const extra = { ...tokenPolicy, include: [...tokenPolicy.include, { service_token: { token_id: ID2 } }] };
    expect(check(app([email, extra]), extra, access()).detail).toContain(`lets in token id(s) not in serviceTokens.t1: ${ID2}`);
    const two = access({ names: ["backup-puller-t1", "second"], tokens: [{ name: "backup-puller-t1", token }, { name: "second", token: { id: ID2, name: "second", expires_at: days(90) } }] });
    expect(check(app([email, tokenPolicy]), tokenPolicy, two).detail).toContain("does not include second");
    const elsewhere = check(app([email, tokenPolicy]), tokenPolicy, access({ elsewhere: ["Access application other (policy p) includes backup-puller-t1"] }));
    expect(elsewhere.ok).toBe(false);
    expect(elsewhere.detail).toContain("a token of t1 also opens: Access application other");
    expect(elsewhere.fix).toContain("A service token opens exactly one box");
    const expired = check(app([email, tokenPolicy]), tokenPolicy, access({ tokens: [{ name: "backup-puller-t1", token: { ...token, expires_at: days(-3) } }] }));
    expect(expired.ok).toBe(false);
    expect(expired.detail).toMatch(/service token backup-puller-t1 expired 2026-11-03, 3 days ago/);
    const unresolved = check(app([email, tokenPolicy]), tokenPolicy, access({ problems: ["Cloudflare has no service token named backup-puller-t1"] }));
    expect(unresolved.ok).toBe(false);
    expect(unresolved.fix).toContain("Access: Service Tokens · Read");
  });

  it("still refuses a bypass email policy", () => {
    const open = { ...email, decision: "bypass", include: [{ everyone: {} }] };
    const r = checkAccess("t1", app([open, tokenPolicy]), open, "ssh-t1.example.com", ["me@example.com"], tokenPolicy, access());
    expect(r.ok).toBe(false);
    expect(r.detail).toContain("decides bypass");
    expect(r.detail).toContain("an Everyone rule");
  });
});

describe("frosty service-tokens", () => {
  let home = "";
  let env: Record<string, string>;
  let http: FakeHttp;
  let cf: FakeCloudflare;

  const deps = (io: ScriptedIo): Deps => ({ io, env, fetch: http.fetch, sleep: noSleep, now: () => NOW, cloudflaredPath: "/usr/bin/cloudflared", isTty: false });
  const config = async (extra: Partial<Config>): Promise<void> => {
    await saveConfig({ ...sampleConfig, accountId: "acc1", cloudflareChangeLog: join(home, "cf.jsonl"), ...extra }, env);
  };
  const writes = (): string[] => http.writes().map((c) => `${c.method} ${c.url.pathname.replace("/client/v4/accounts/acc1", "")}`);
  const appPolicies = (): string[] => ((cf.apps.find((a) => a["id"] === "app-ssh") as { policies: { id: string }[] }).policies).map((p) => p.id);
  const tokenPolicy = (): Record<string, unknown> | undefined => cf.policies.find((p) => p["name"] === "stayfrosty-box1:service-tokens");
  const listedTokens = (): number => http.calls.filter((c) => c.url.pathname.endsWith("/access/service_tokens")).length;

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "frosty-service-tokens-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
    writeFileSync(join(home, ".ssh", "id_ed25519.pub"), `${PUBLIC_KEY}\n`);
    env = { HOME: home, HCLOUD_TOKEN: "hz-token-0123456789", CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
    await config({ serviceTokens: { box1: ["backup-puller-box1"] } });
    http = new FakeHttp();
    cf = new FakeCloudflare(http);
    cf.policies.push({ id: "pol-email", name: "stayfrosty-box1", decision: "allow", include: [{ email: { email: "me@example.com" } }] });
    cf.apps.push({ id: "app-ssh", name: "stayfrosty-box1", type: "self_hosted", domain: "ssh-box1.example.com", session_duration: "24h", app_launcher_visible: false, policies: [{ id: "pol-email", precedence: 1 }] });
    cf.serviceTokens.push({ id: ID1, name: "backup-puller-box1", client_id: "abc.access", expires_at: days(200), duration: "8760h" });
    cf.serviceTokens.push({ id: ID2, name: "second-box1", client_id: "def.access", expires_at: days(10), duration: "8760h" });
    cf.serviceTokens.push({ id: ID3, name: "old-box1", client_id: "ghi.access", expires_at: days(-2), duration: "8760h" });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    clearSecretsForTests();
  });

  it("plan lists the changes and each token's expiry, and changes nothing", async () => {
    const io = new ScriptedIo();
    expect(await runServiceTokens(deps(io), { action: "plan", box: "box1" }), io.text()).toBe(0);
    const text = io.text();
    expect(text).toContain("service token backup-puller-box1: expires 2027-05-25, in 200 days");
    expect(text).toContain("would: create Access policy stayfrosty-box1:service-tokens: let in service tokens backup-puller-box1");
    expect(text).toContain("would: set the policies of Access application stayfrosty-box1 to stayfrosty-box1, stayfrosty-box1:service-tokens (now stayfrosty-box1)");
    expect(text).toContain("box1: 2 change(s). Apply them with: frosty service-tokens sync box1");
    expect(http.writes()).toEqual([]);
    expect(() => readFileSync(join(home, "cf.jsonl"))).toThrow();
  });

  it("plan flags tokens that expire within 30 days or have expired", async () => {
    await config({ serviceTokens: { box1: ["second-box1", "old-box1"] } });
    const io = new ScriptedIo();
    await runServiceTokens(deps(io), { action: "plan", box: "box1" });
    expect(io.text()).toContain("service token second-box1: expires 2026-11-16, in 10 days  [expires within 30 days]");
    expect(io.text()).toContain("service token old-box1: expired 2026-11-04, 2 days ago  [EXPIRED");
  });

  it("sync writes the policy, then attaches it, logs both, and checks Access", async () => {
    const io = new ScriptedIo();
    expect(await runServiceTokens(deps(io), { action: "sync", box: "box1" }), io.text()).toBe(0);
    expect(writes()).toEqual(["POST /access/policies", "PUT /access/apps/app-ssh"]);
    const policy = tokenPolicy() as { id: string; decision: string; include: unknown[] };
    expect(policy).toMatchObject({ decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    expect(appPolicies()).toEqual(["pol-email", policy.id]);
    expect(cf.apps[0]).toMatchObject({ name: "stayfrosty-box1", type: "self_hosted", domain: "ssh-box1.example.com", session_duration: "24h", app_launcher_visible: false });
    expect(io.text()).toMatch(/pass\s+Access: only your emails and this box's service tokens\s+allow me@example.com; service tokens backup-puller-box1 \(200 days left\)/);
    const log = readFileSync(join(home, "cf.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(log.map((l) => [l["phase"], l["action"]])).toEqual([
      ["intent", "cloudflare POST"],
      ["done", "cloudflare POST"],
      ["intent", "cloudflare PUT"],
      ["done", "cloudflare PUT"],
    ]);
    expect(log[2]?.["before"]).toMatchObject({ id: "app-ssh", name: "stayfrosty-box1" });

    const again = new ScriptedIo();
    expect(await runServiceTokens(deps(again), { action: "sync", box: "box1" })).toBe(0);
    expect(again.text()).toContain("Nothing to change.");
    expect(writes()).toHaveLength(2);
  });

  it("sync updates the policy in place when a token is added", async () => {
    await runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" });
    const id = (tokenPolicy() as { id: string }).id;
    await config({ serviceTokens: { box1: ["backup-puller-box1", "second-box1"] } });
    const io = new ScriptedIo();
    expect(await runServiceTokens(deps(io), { action: "sync", box: "box1" }), io.text()).toBe(0);
    expect(writes().slice(2)).toEqual([`PUT /access/policies/${id}`]);
    expect(io.text()).toContain("changing: update Access policy stayfrosty-box1:service-tokens: add second-box1");
    expect(tokenPolicy()?.["include"]).toEqual([{ service_token: { token_id: ID1 } }, { service_token: { token_id: ID2 } }]);
    expect(appPolicies()).toEqual(["pol-email", id]);
    const log = readFileSync(join(home, "cf.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(log.at(-1)?.["before"]).toMatchObject({ id, name: "stayfrosty-box1:service-tokens" });
  });

  it("sync with the box taken out of config detaches the policy, then deletes it", async () => {
    await runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" });
    const id = (tokenPolicy() as { id: string }).id;
    await config({});
    const before = listedTokens();
    const io = new ScriptedIo();
    expect(await runServiceTokens(deps(io), { action: "sync", box: "box1" }), io.text()).toBe(0);
    expect(writes().slice(2)).toEqual(["PUT /access/apps/app-ssh", `DELETE /access/policies/${id}`]);
    expect(appPolicies()).toEqual(["pol-email"]);
    expect(tokenPolicy()).toBeUndefined();
    expect(io.text()).toMatch(/pass\s+Access: only your emails, no bypass or everyone/);
    expect(listedTokens()).toBe(before);
  });

  it("refuses a missing token, with the permission hint, before any write", async () => {
    await config({ serviceTokens: { box1: ["nope"] } });
    const error = (await runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" }).catch((e: unknown) => e)) as { message: string; hint: string };
    expect(error.message).toContain("Cloudflare has no service token named nope");
    expect(error.hint).toContain('the Cloudflare API token may lack "Account · Access: Service Tokens · Read"');
    expect(error.hint).toContain("empty list, not an error");
    expect(http.writes()).toEqual([]);
  });

  it("refuses a name that matches two tokens", async () => {
    cf.serviceTokens.push({ id: "44444444-4444-4444-8444-444444444444", name: "backup-puller-box1" });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "plan", box: "box1" })).rejects.toThrow(/2 Cloudflare service tokens are named backup-puller-box1/);
  });

  it("refuses a token that another policy already includes: a token opens exactly one box", async () => {
    cf.policies.push({ id: "pol-box2", name: "stayfrosty-box2:service-tokens", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] });
    const plan = new ScriptedIo();
    expect(await runServiceTokens(deps(plan), { action: "plan", box: "box1" })).toBe(1);
    expect(plan.text()).toContain("[problem] a token of box1 also opens: Access policy stayfrosty-box2:service-tokens includes backup-puller-box1");
    expect(plan.text()).toContain("sync would refuse");
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/A service token opens exactly one box/);
    expect(http.writes()).toEqual([]);
  });

  it("refuses a token that another app's inline policy includes, or an app that takes any token", async () => {
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "inline-1", name: "legacy", decision: "non_identity", include: [{ service_token: { token_id: ID1 } }] }] });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/Access application other-app \(policy legacy\) includes backup-puller-box1/);
    cf.apps.pop();
    cf.apps.push({ id: "app-any", name: "any-app", type: "self_hosted", domain: "any.example.net", policies: [{ id: "inline-2", name: "machines", decision: "non_identity", include: [{ any_valid_service_token: {} }] }] });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/any-app \(policy machines\) lets in any valid service token/);
    expect(http.writes()).toEqual([]);
  });

  it("refuses a token that an Access group names, wherever a policy uses that group", async () => {
    cf.groups.push({ id: "grp-1", name: "machines", include: [{ service_token: { token_id: ID1 } }] });
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "inline-1", name: "via-group", decision: "non_identity", include: [{ group: { id: "grp-1" } }] }] });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/other-app \(policy via-group\) includes backup-puller-box1/);
    cf.groups[0] = { id: "grp-1", name: "machines", include: [{ everyone: {} }], require: [{ any_valid_service_token: {} }] };
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/other-app \(policy via-group\) lets in any valid service token/);
    expect(http.writes()).toEqual([]);
  });

  it("fails closed on a group it can't see, naming the groups permission", async () => {
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "inline-1", name: "people", decision: "allow", include: [{ group: { id: "grp-unknown" } }] }] });
    const error = (await runServiceTokens(deps(new ScriptedIo()), { action: "plan", box: "box1" }).catch((e: unknown) => e)) as { message: string; hint: string };
    expect(error.message).toContain("can't check Access group grp-unknown");
    expect(error.hint).toContain("Access: Organizations, Identity Providers, and Groups · Read");
    http.on("GET", "api.cloudflare.com", "/client/v4/accounts/acc1/access/groups", { status: 403, body: { success: false, errors: [{ code: 10000, message: "Authentication error" }], result: null } });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/can't check Access groups/);
    expect(http.writes()).toEqual([]);
  });

  it("refuses an app whose policy requires any valid token, or is Service Auth for everyone", async () => {
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "inline-1", name: "req", decision: "allow", include: [{ everyone: {} }], require: [{ any_valid_service_token: {} }] }] });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/other-app \(policy req\) lets in any valid service token/);
    cf.apps[1] = { id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "inline-2", name: "svc-all", decision: "non_identity", include: [{ everyone: {} }] }] };
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/other-app \(policy svc-all\) lets in any valid service token/);
    expect(http.writes()).toEqual([]);
  });

  it("checks reusable policies attached to other apps, from the policy list", async () => {
    // The other app's list entry and its full read both carry only the reference.
    cf.policies.push({ id: "pol-any", name: "machines-any", decision: "non_identity", include: [{ everyone: {} }] });
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id: "pol-any", precedence: 1 }] });
    http.on("GET", "api.cloudflare.com", "/client/v4/accounts/acc1/access/apps/app-other", () => ({ body: { success: true, errors: [], result: cf.apps[1] } }));
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/Access policy machines-any \(on other-app\) lets in any valid service token/);
    // Not attached anywhere: not an opening.
    cf.apps.pop();
    expect(await runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).toBe(0);
  });

  it("refuses to rewrite an SSH app with settings frosty would reset, before any write", async () => {
    (cf.apps[0] as Record<string, unknown>)["allowed_idps"] = ["x"];
    (cf.apps[0] as Record<string, unknown>)["tags"] = [];
    (cf.apps[0] as Record<string, unknown>)["http_only_cookie_attribute"] = true;
    const plan = new ScriptedIo();
    expect(await runServiceTokens(deps(plan), { action: "plan", box: "box1" })).toBe(1);
    expect(plan.text()).toContain("[problem] Access application stayfrosty-box1 has allowed_idps set, and frosty's update would reset them");
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/has allowed_idps set, and frosty's update would reset them/);
    expect(http.writes()).toEqual([]);
  });

  it("refuses when the box's token policy is attached to another app", async () => {
    await runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" });
    const id = (tokenPolicy() as { id: string }).id;
    cf.apps.push({ id: "app-other", name: "other-app", type: "self_hosted", domain: "other.example.net", policies: [{ id, precedence: 1 }] });
    await config({ serviceTokens: { box1: ["second-box1"] } });
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "sync", box: "box1" })).rejects.toThrow(/other-app \(policy stayfrosty-box1:service-tokens\) is stayfrosty-box1:service-tokens itself/);
    expect(writes()).toHaveLength(2);
  });

  it("needs the box's SSH app, and makes no service token call when none are configured", async () => {
    await config({});
    const io = new ScriptedIo();
    expect(await runServiceTokens(deps(io), { action: "plan", box: "box1" })).toBe(0);
    expect(io.text()).toContain("box1: the service tokens already match config. Nothing to change.");
    expect(listedTokens()).toBe(0);
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "plan", box: "box9" })).rejects.toThrow(/box9 has no frosty Access application stayfrosty-box9/);
  });

  it("refuses an unknown action, and is wired into the CLI", async () => {
    await expect(runServiceTokens(deps(new ScriptedIo()), { action: "apply", box: "box1" })).rejects.toThrow(/needs plan or sync/);
    const io = new ScriptedIo();
    expect(await main(["--help"], io)).toBe(0);
    expect(io.text()).toContain("frosty service-tokens (plan | sync) <box>");
  });
});
