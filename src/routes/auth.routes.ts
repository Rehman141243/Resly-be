import { Router, type Request } from "express";
import * as auth from "../services/auth.service.js";
import { requireAuth } from "../middleware/auth.js";
import {
  forgotLimiter,
  loginLimiter,
  refreshLimiter,
  resetLimiter,
  signupLimiter,
} from "../middleware/rateLimit.js";
import {
  parseChangePassword,
  parseForgot,
  parseLogin,
  parseRefresh,
  parseReset,
  parseSignUp,
  parseUuid,
} from "../utils/validate.js";

const router = Router();

const meta = (req: Request): auth.ClientMeta => ({ ip: req.ip, userAgent: req.get("user-agent") });

// Tokens must never be cached by proxies or the client.
router.use((_req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

router.post("/signup", signupLimiter, async (req, res) => {
  const { name, email, password } = parseSignUp(req.body);
  res.status(201).json(await auth.signUp(name, email, password, meta(req)));
});

router.post("/login", loginLimiter, async (req, res) => {
  const { email, password, remember } = parseLogin(req.body);
  res.json(await auth.signIn(email, password, remember, meta(req)));
});

router.post("/refresh", refreshLimiter, async (req, res) => {
  const { refreshToken } = parseRefresh(req.body);
  res.json({ tokens: await auth.refreshSession(refreshToken, meta(req)) });
});

router.post("/logout", requireAuth, async (req, res) => {
  await auth.revokeSession(req.auth!.sessionId);
  res.status(204).end();
});

router.post("/logout-all", requireAuth, async (req, res) => {
  await auth.revokeAllSessions(req.auth!.userId);
  res.status(204).end();
});

router.post("/forgot-password", forgotLimiter, async (req, res) => {
  const { email } = parseForgot(req.body);
  await auth.requestPasswordReset(email);
  res.json({ message: "If that email is registered, a reset code has been sent." });
});

router.post("/reset-password", resetLimiter, async (req, res) => {
  const { email, code, password } = parseReset(req.body);
  await auth.resetPassword(email, code, password);
  res.json({ message: "Password updated. Please log in." });
});

router.get("/me", requireAuth, async (req, res) => {
  res.json({ user: await auth.getUser(req.auth!.userId) });
});

router.post("/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = parseChangePassword(req.body);
  await auth.changePassword(req.auth!.userId, req.auth!.sessionId, currentPassword, newPassword);
  res.json({ message: "Password changed. Other devices were logged out." });
});

router.get("/sessions", requireAuth, async (req, res) => {
  res.json({ sessions: await auth.listSessions(req.auth!.userId, req.auth!.sessionId) });
});

router.delete("/sessions/:id", requireAuth, async (req, res) => {
  await auth.revokeUserSession(req.auth!.userId, parseUuid(req.params.id));
  res.status(204).end();
});

export default router;
