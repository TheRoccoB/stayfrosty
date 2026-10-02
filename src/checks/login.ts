import { FRESH_CONNECTION, type SshRunner, type SshTarget } from "../box.ts";
import { fail, pass, reapplyFix, type CheckResult } from "./types.ts";

// Asks sshd which methods it offers, without offering a key: the "none" method fails and
// the server answers with the list it would accept.
export function parseOfferedMethods(stderr: string): string[] | undefined {
  const match = /Authentications that can continue:\s*(\S+)/.exec(stderr);
  if (match === null) {
    return undefined;
  }
  return (match[1] as string).split(",");
}

export async function checkOnlyPublickey(ssh: SshRunner, target: SshTarget, box: string): Promise<CheckResult> {
  const name = "sshd offers only public key login";
  const result = await ssh(target, "true", {
    extraOptions: [...FRESH_CONNECTION, "-v", "-o", "PreferredAuthentications=none", "-o", "PubkeyAuthentication=no"],
    timeoutMs: 30_000,
  });
  const methods = parseOfferedMethods(result.stderr);
  if (methods === undefined) {
    return fail(name, "could not read the methods sshd offers", "Check that the box is reachable, then run the command again.");
  }
  if (methods.length !== 1 || methods[0] !== "publickey") {
    return fail(name, `sshd offers: ${methods.join(", ")}`, reapplyFix(box));
  }
  return pass(name, "publickey only; passwords are refused");
}

export async function checkRootRefused(ssh: SshRunner, target: SshTarget, box: string): Promise<CheckResult> {
  const name = "root login is refused";
  const result = await ssh({ ...target, user: "root" }, "true", { timeoutMs: 30_000, extraOptions: FRESH_CONNECTION });
  if (result.code === 0) {
    return fail(name, "root logged in with the SSH key", reapplyFix(box));
  }
  if (!/Permission denied/i.test(result.stderr)) {
    return fail(name, `unexpected answer: ${result.stderr.trim().split("\n").slice(-1)[0] ?? ""}`, "Check that the box is reachable, then run the command again.");
  }
  return pass(name, "Permission denied for root");
}
