import { describe, expect, it } from "vitest";
import { main, reportError } from "../src/cli.ts";
import { FrostyError } from "../src/errors.ts";
import { ScriptedIo } from "./fixtures.ts";

describe("cli", () => {
  it("prints help", async () => {
    const io = new ScriptedIo();
    expect(await main(["--help"], io)).toBe(0);
    expect(io.text()).toContain("frosty init");
  });

  it("names the milestone of a command that is not built yet", async () => {
    const io = new ScriptedIo();
    expect(await main(["verify", "web1"], io)).toBe(2);
    expect(io.text()).toContain("milestone M3");
    expect(io.text()).toContain("Nothing was changed.");
  });

  it("rejects unknown commands", async () => {
    const io = new ScriptedIo();
    expect(await main(["frobnicate"], io)).toBe(2);
    expect(io.text()).toContain("frosty --help");
  });

  it("prints an error with its next step", () => {
    const io = new ScriptedIo();
    expect(reportError(new FrostyError("It broke.", "Run: frosty init"), io)).toBe(1);
    expect(io.stderr).toEqual(["Error: It broke.", "", "Run: frosty init"]);
  });
});
