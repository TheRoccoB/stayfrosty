import { isIPv4, isIPv6 } from "node:net";
import { FrostyError } from "./errors.ts";
import type { Fetch } from "./http.ts";

export interface LaptopIp {
  ipv4: string | undefined;
  ipv6: string | undefined;
}

// Cloudflare's trace endpoint, reached by IP literal so each lookup is forced onto one family.
const TRACE_V4 = "https://1.1.1.1/cdn-cgi/trace";
const TRACE_V6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace";

export function parseTrace(text: string): string | undefined {
  for (const line of text.split("\n")) {
    if (line.startsWith("ip=")) {
      return line.slice(3).trim();
    }
  }
  return undefined;
}

async function lookup(fetchImpl: Fetch, url: string, valid: (ip: string) => boolean): Promise<string | undefined> {
  try {
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      return undefined;
    }
    const ip = parseTrace(await response.text());
    return ip !== undefined && valid(ip) ? ip : undefined;
  } catch {
    return undefined;
  }
}

export async function findLaptopIp(fetchImpl: Fetch = globalThis.fetch): Promise<LaptopIp> {
  const [ipv4, ipv6] = await Promise.all([lookup(fetchImpl, TRACE_V4, isIPv4), lookup(fetchImpl, TRACE_V6, isIPv6)]);
  if (ipv4 === undefined && ipv6 === undefined) {
    throw new FrostyError(
      "Could not find this laptop's public IP address (asked https://1.1.1.1/cdn-cgi/trace).",
      "Check your internet connection. A VPN or proxy that blocks 1.1.1.1 also causes this. Then run the command again.",
    );
  }
  return { ipv4, ipv6 };
}

// The window admits exactly one address. IPv4 when the laptop has it, since boxes are
// reached on their IPv4 during a window; IPv6 only for laptops without IPv4.
export function windowSource(ip: LaptopIp): { cidr: string; family: 4 | 6 } {
  if (ip.ipv4 !== undefined) {
    return { cidr: `${ip.ipv4}/32`, family: 4 };
  }
  return { cidr: `${ip.ipv6 as string}/128`, family: 6 };
}
