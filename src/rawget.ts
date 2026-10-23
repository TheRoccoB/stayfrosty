import { request } from "node:https";

// For verify's route checks: an HTTPS GET with the path sent exactly as written (like curl
// --path-as-is), since fetch would clean up "..", "//" and the like before sending.

export interface RawResponse {
  status: number;
  location: string | null;
  body: string;
}

export type RawGet = (hostname: string, path: string) => Promise<RawResponse>;

// HTTPS GET with the path sent verbatim. Reads at most 64 KB of the body.
export const rawGet: RawGet = (hostname, path) =>
  new Promise((resolve, reject) => {
    const req = request({ host: hostname, servername: hostname, path, method: "GET", headers: { "user-agent": "stayfrosty-verify" }, timeout: 15_000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => {
        if (body.length < 65_536) {
          body += chunk;
        }
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, location: typeof res.headers.location === "string" ? res.headers.location : null, body }));
    });
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end();
  });

