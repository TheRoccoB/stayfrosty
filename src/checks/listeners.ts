import { fail, pass, type CheckResult } from "./types.ts";

export interface Listener {
  proto: string;
  address: string;
  port: number;
  processes: string[];
}

// Parses `ss -tulnpH`: netid, state, recv-q, send-q, local, peer, process.
export function parseSs(text: string): Listener[] {
  const out: Listener[] = [];
  for (const raw of text.split("\n")) {
    const cols = raw.trim().split(/\s+/);
    if (cols.length < 5) {
      continue;
    }
    const proto = cols[0] as string;
    const local = cols[4] as string;
    const colon = local.lastIndexOf(":");
    if (colon === -1) {
      continue;
    }
    let address = local.slice(0, colon).replace(/^\[|\]$/g, "");
    address = address.replace(/%.*$/, "");
    const port = Number(local.slice(colon + 1));
    const processInfo = cols.slice(6).join(" ");
    const processes = [...processInfo.matchAll(/\("([^"]+)"/g)].map((m) => m[1] as string);
    out.push({ proto, address, port, processes });
  }
  return out;
}

export function isLoopback(address: string): boolean {
  return address.startsWith("127.") || address === "::1" || address.startsWith("::ffff:127.");
}

// Sockets every box has on purpose: sshd (or systemd holding ssh.socket) on 22, and the DHCP
// clients of systemd-networkd. Everything else non-loopback is reported by process, which
// catches Docker publishing ports that UFW cannot see.
function expected(l: Listener): boolean {
  if (l.proto === "tcp" && l.port === 22) {
    return l.processes.length === 0 || l.processes.every((p) => p === "sshd" || p === "systemd" || p === "sshd-session");
  }
  if (l.proto === "udp" && (l.port === 68 || l.port === 546)) {
    return l.processes.every((p) => p.startsWith("systemd-network"));
  }
  return false;
}

export function checkListeners(text: string): CheckResult {
  const name = "Listening sockets: only sshd off loopback";
  const listeners = parseSs(text).filter((l) => !isLoopback(l.address));
  const unexpected = listeners.filter((l) => !expected(l));
  if (unexpected.length > 0) {
    const list = unexpected.map((l) => `${l.proto} ${l.address}:${l.port} (${l.processes.join(", ") || "unknown process"})`).join("; ");
    return fail(name, `unexpected: ${list}`, "Stop or rebind that service to 127.0.0.1 and reach it through the tunnel. If Docker published it, remove the ports: mapping.");
  }
  return pass(name, `${listeners.length} expected socket(s)`);
}
