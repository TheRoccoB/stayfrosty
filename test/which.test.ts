import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findStableCommand } from "../src/which.ts";

function executable(path: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, "#!/bin/sh\n");
  chmodSync(path, 0o755);
}

describe("findStableCommand", () => {
  it("swaps a version manager's versioned install for its shim", () => {
    const data = mkdtempSync(join(tmpdir(), "frosty-which-"));
    const versioned = join(data, "installs", "cloudflared", "2026.1.0");
    executable(join(versioned, "cloudflared"));
    executable(join(data, "shims", "cloudflared"));
    expect(findStableCommand("cloudflared", { PATH: versioned })).toBe(join(data, "shims", "cloudflared"));
  });

  it("keeps the versioned path when there is no shim", () => {
    const data = mkdtempSync(join(tmpdir(), "frosty-which-"));
    const versioned = join(data, "installs", "cloudflared", "2026.1.0", "bin");
    executable(join(versioned, "cloudflared"));
    expect(findStableCommand("cloudflared", { PATH: versioned })).toBe(join(versioned, "cloudflared"));
  });

  it("leaves an ordinary path alone, and finds nothing when nothing is there", () => {
    const bin = mkdtempSync(join(tmpdir(), "frosty-which-"));
    executable(join(bin, "cloudflared"));
    expect(findStableCommand("cloudflared", { PATH: bin })).toBe(join(bin, "cloudflared"));
    expect(findStableCommand("missing", { PATH: bin })).toBeUndefined();
  });
});
