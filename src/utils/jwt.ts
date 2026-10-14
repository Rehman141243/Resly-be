import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config.js";

// Minimal HS256 JWT. The algorithm is fixed (no "alg" negotiation, so no "alg: none" attacks).
const ISSUER = "fitconnect-api";
const b64u = (v: string | Buffer) => Buffer.from(v).toString("base64url");
const HEADER = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));

const sign = (data: string) => createHmac("sha256", config.jwtSecret).update(data).digest("base64url");

export type AccessClaims = { sub: string; sid: string };

export function signAccessToken(userId: string, sessionId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: ISSUER, sub: userId, sid: sessionId, iat: now, exp: now + config.accessTtlSec };
  const data = `${HEADER}.${b64u(JSON.stringify(payload))}`;
  return `${data}.${sign(data)}`;
}

export function verifyAccessToken(token: string): AccessClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  if (h !== HEADER) return null;

  const expected = Buffer.from(sign(`${h}.${p}`));
  const given = Buffer.from(s);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;

  try {
    const c = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>;
    if (c.iss !== ISSUER) return null;
    if (typeof c.exp !== "number" || c.exp <= Math.floor(Date.now() / 1000)) return null;
    if (typeof c.sub !== "string" || typeof c.sid !== "string") return null;
    return { sub: c.sub, sid: c.sid };
  } catch {
    return null;
  }
}
