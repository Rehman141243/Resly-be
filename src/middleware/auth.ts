import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../utils/jwt.js";
import { isSessionActive } from "../services/auth.service.js";
import { unauthorized } from "../utils/errors.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: { userId: string; sessionId: string };
    }
  }
}

export async function requireAuth(req: Request, _res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) throw unauthorized();

  const claims = verifyAccessToken(header.slice(7));
  if (!claims) throw unauthorized("Token is invalid or expired.");

  if (!(await isSessionActive(claims.sid, claims.sub))) throw unauthorized("Session has ended.");

  req.auth = { userId: claims.sub, sessionId: claims.sid };
  next();
}
