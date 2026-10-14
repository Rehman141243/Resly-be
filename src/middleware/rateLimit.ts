import { rateLimit } from "express-rate-limit";

const make = (windowMs: number, limit: number) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: { code: "RATE_LIMITED", message: "Too many requests. Please try again later." } },
  });

const MIN = 60_000;

export const globalLimiter = make(15 * MIN, 300);
export const loginLimiter = make(15 * MIN, 10);
export const signupLimiter = make(60 * MIN, 10);
export const refreshLimiter = make(15 * MIN, 60);
export const forgotLimiter = make(60 * MIN, 5);
export const resetLimiter = make(60 * MIN, 10);
