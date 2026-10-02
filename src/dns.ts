import { Resolver } from "node:dns/promises";
import { lookup, resolve4, resolveNs } from "node:dns/promises";

// Asks the zone's own nameservers, which never cache a negative answer.
export async function authoritativeResolves(hostname: string, domain: string): Promise<boolean> {
  try {
    const servers = await resolveNs(domain);
    const ips = (await Promise.all(servers.slice(0, 2).map((ns) => resolve4(ns).catch(() => [] as string[])))).flat();
    if (ips.length === 0) {
      return false;
    }
    const resolver = new Resolver({ timeout: 3000, tries: 1 });
    resolver.setServers(ips);
    return (await resolver.resolve4(hostname)).length > 0;
  } catch {
    return false;
  }
}

// What ssh and cloudflared will see: the laptop's own resolver, cache included.
export async function systemResolves(hostname: string): Promise<boolean> {
  try {
    await lookup(hostname);
    return true;
  } catch {
    return false;
  }
}
