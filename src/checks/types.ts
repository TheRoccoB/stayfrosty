export interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
  // The next command to run when the check fails.
  fix?: string;
}

export function pass(name: string, detail: string): CheckResult {
  return { name, ok: true, detail };
}

export function fail(name: string, detail: string, fix: string): CheckResult {
  return { name, ok: false, detail, fix };
}

// Where a drifted box gets its hardening back. Boxes are disposable until adopt exists (M4).
export function reapplyFix(box: string): string {
  return `Rebuild the box from the reviewed config: frosty destroy ${box} && frosty new ${box}`;
}
