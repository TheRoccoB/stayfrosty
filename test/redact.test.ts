import { afterEach, describe, expect, it } from "vitest";
import { clearSecretsForTests, redact, redactJson, redactValue, registerSecret } from "../src/redact.ts";

afterEach(() => {
  clearSecretsForTests();
});

describe("redact", () => {
  it("removes a registered secret wherever it appears", () => {
    registerSecret("abcdefghijklmnopqrstuvwxyz");
    expect(redact("token=abcdefghijklmnopqrstuvwxyz; again abcdefghijklmnopqrstuvwxyz")).toBe("token=[redacted]; again [redacted]");
  });

  it("ignores values too short to be a secret", () => {
    registerSecret("ops");
    expect(redact("user ops")).toBe("user ops");
  });

  it("removes bearer tokens", () => {
    expect(redact("Authorization: Bearer abc.def-ghi")).toBe("Authorization: Bearer [redacted]");
  });

  it("removes tunnel tokens", () => {
    const token = Buffer.from(JSON.stringify({ a: "account", t: "tunnel-id", s: "c2VjcmV0c2VjcmV0c2VjcmV0" })).toString("base64");
    expect(token.startsWith("eyJhIjoi")).toBe(true);
    expect(redact(`run --token ${token} now`)).toBe("run --token [redacted] now");
  });

  it("removes JWT-shaped values", () => {
    expect(redact("cookie eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4f")).toBe("cookie [redacted]");
  });
});

describe("redactValue", () => {
  it("blanks keys that name a secret, at any depth", () => {
    const out = redactValue({
      server: { name: "web1", root_password: "hunter2hunter2" },
      tunnel_secret: "c2VjcmV0",
      list: [{ token: "x" }],
      ssh_key: "ssh-ed25519 AAAA",
    });
    expect(out).toEqual({
      server: { name: "web1", root_password: "[redacted]" },
      tunnel_secret: "[redacted]",
      list: [{ token: "[redacted]" }],
      ssh_key: "ssh-ed25519 AAAA",
    });
  });

  it("keeps null secret fields visible as null", () => {
    expect(redactValue({ root_password: null })).toEqual({ root_password: null });
  });

  it("redacts registered secrets inside string values", () => {
    registerSecret("supersecretvalue123");
    expect(redactJson({ message: "bad supersecretvalue123" })).toContain("bad [redacted]");
  });
});
