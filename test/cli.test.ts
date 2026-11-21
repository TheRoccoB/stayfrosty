import { describe, expect, it } from "vitest";
import { main, reportError, shapeProblem } from "../src/cli.ts";
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
    expect(await main(["breakglass", "web1"], io)).toBe(2);
    expect(io.text()).toContain("milestone M3");
    expect(io.text()).toContain("Nothing was changed.");
  });

  it("rejects unknown commands", async () => {
    const io = new ScriptedIo();
    expect(await main(["frobnicate"], io)).toBe(2);
    expect(io.text()).toContain("frosty --help");
  });

  it("refuses --dry-run on route, ssh-users and service-tokens sync, before anything runs", async () => {
    // Before, sync ignored --dry-run and applied. The command never gets to load config or call an API:
    // there is none in this test, so getting that far would throw instead of returning 2.
    for (const command of ["route", "ssh-users", "service-tokens"]) {
      for (const argv of [[command, "sync", "box1", "--dry-run"], ["--dry-run", command, "sync", "box1"]]) {
        const io = new ScriptedIo();
        expect(await main(argv, io)).toBe(2);
        expect(io.text()).toContain(`frosty ${command} has no --dry-run. Use "frosty ${command} plan <box>"`);
        expect(io.text()).toContain("Nothing was changed.");
      }
    }
  });

  it("refuses flags a command doesn't take", async () => {
    for (const argv of [
      ["verify", "box1", "--dry-run"],
      ["ls", "--all"],
      ["destroy", "box1", "--resume"],
      ["route", "plan", "box1", "--all"],
    ]) {
      const io = new ScriptedIo();
      expect(await main(argv, io)).toBe(2);
      expect(io.text()).toMatch(/doesn't take --(dry-run|all|resume)\./);
      expect(io.text()).toContain("Nothing was changed.");
    }
  });

  it("refuses unknown flags, values on yes/no flags and missing values", async () => {
    for (const argv of [
      ["route", "sync", "box1", "--dryrun"],
      ["destroy", "box1", "--dry-run=false"],
      ["new", "box1", "--type"],
    ]) {
      const io = new ScriptedIo();
      expect(await main(argv, io)).toBe(2);
      expect(io.text()).toContain("Nothing was changed. Run: frosty --help");
    }
  });

  it("refuses extra words after a command", async () => {
    for (const argv of [
      ["route", "sync", "box1", "box2"],
      ["route", "sync", "box1", "--", "--dry-run"],
      ["destroy", "box1", "box2"],
    ]) {
      const io = new ScriptedIo();
      expect(await main(argv, io)).toBe(2);
      expect(io.text()).toMatch(/frosty (route|destroy) doesn't take "/);
    }
  });

  it("lets through the flags and words a command takes", () => {
    // shapeProblem directly: running these would read the real config.
    expect(shapeProblem("route", { "dry-run": true }, ["route", "plan", "box1"])).toBeUndefined();
    expect(shapeProblem("route", {}, ["route", "sync", "box1"])).toBeUndefined();
    expect(shapeProblem("destroy", { "dry-run": true }, ["destroy", "box1"])).toBeUndefined();
    expect(shapeProblem("new", { type: "cx22", location: "nbg1", resume: true, "dry-run": true }, ["new", "box1"])).toBeUndefined();
    expect(shapeProblem("adopt", { ip: "192.0.2.1", user: "root", "trust-first-use": true }, ["adopt", "box1"])).toBeUndefined();
    expect(shapeProblem("verify", { all: true }, ["verify"])).toBeUndefined();
    expect(shapeProblem("console-password", { direct: true, "dry-run": true }, ["console-password", "box1"])).toBeUndefined();
  });

  it("prints an error with its next step", () => {
    const io = new ScriptedIo();
    expect(reportError(new FrostyError("It broke.", "Run: frosty init"), io)).toBe(1);
    expect(io.stderr).toEqual(["Error: It broke.", "", "Run: frosty init"]);
  });
});
