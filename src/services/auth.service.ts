import { randomInt } from "node:crypto";
import { config } from "../config.js";
import { supabase } from "../db.js";
import { AppError, internal } from "../utils/errors.js";
import {
  burnPasswordCheck,
  decrypt,
  encrypt,
  hashPassword,
  hmac,
  randomToken,
  safeEqual,
  verifyPassword,
} from "../utils/crypto.js";
import { signAccessToken } from "../utils/jwt.js";
import { sendResetCode } from "../utils/email.js";

type DbUser = {
  id: string;
  email: string;
  name_enc: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: string | null;
};

export type ClientMeta = { ip?: string; userAgent?: string };

const iso = (ms: number) => new Date(ms).toISOString();
const publicUser = (u: Pick<DbUser, "id" | "email" | "name_enc">) => ({
  id: u.id,
  name: decrypt(u.name_enc),
  email: u.email,
});

const invalidSession = () => new AppError(401, "INVALID_TOKEN", "Session expired. Please log in again.");
const badCredentials = () => new AppError(401, "INVALID_CREDENTIALS", "Email or password is incorrect.");
const badCode = () => new AppError(400, "INVALID_CODE", "That code is invalid or has expired.");

/* ------------------------------- Sessions ------------------------------- */

function tokenBundle(userId: string, sessionId: string, refreshToken: string, refreshExpiresAt: number) {
  return {
    accessToken: signAccessToken(userId, sessionId),
    expiresIn: config.accessTtlSec,
    refreshToken,
    refreshExpiresAt: iso(refreshExpiresAt),
  };
}

async function issueSession(userId: string, remember: boolean, meta: ClientMeta) {
  const refreshToken = randomToken(32);
  const ttl = remember ? config.refreshTtlRememberSec : config.refreshTtlSec;
  const expiresAt = Date.now() + ttl * 1000;

  const { data, error } = await supabase
    .from("sessions")
    .insert({
      user_id: userId,
      refresh_hash: hmac(refreshToken),
      expires_at: iso(expiresAt),
      user_agent: meta.userAgent?.slice(0, 255) ?? null,
      ip: meta.ip ?? null,
    })
    .select("id")
    .single();
  if (error || !data) throw internal("issueSession", error);

  return tokenBundle(userId, data.id as string, refreshToken, expiresAt);
}

export async function revokeSession(sessionId: string) {
  const { error } = await supabase
    .from("sessions")
    .update({ revoked_at: iso(Date.now()) })
    .eq("id", sessionId)
    .is("revoked_at", null);
  if (error) throw internal("revokeSession", error);
}

export async function revokeAllSessions(userId: string, exceptSessionId?: string) {
  let q = supabase.from("sessions").update({ revoked_at: iso(Date.now()) }).eq("user_id", userId).is("revoked_at", null);
  if (exceptSessionId) q = q.neq("id", exceptSessionId);
  const { error } = await q;
  if (error) throw internal("revokeAllSessions", error);
}

export async function revokeUserSession(userId: string, sessionId: string) {
  const { error } = await supabase
    .from("sessions")
    .update({ revoked_at: iso(Date.now()) })
    .eq("id", sessionId)
    .eq("user_id", userId)
    .is("revoked_at", null);
  if (error) throw internal("revokeUserSession", error);
}

export async function listSessions(userId: string, currentSessionId: string) {
  const { data, error } = await supabase
    .from("sessions")
    .select("id,user_agent,ip,created_at,last_used_at,expires_at")
    .eq("user_id", userId)
    .is("revoked_at", null)
    .gt("expires_at", iso(Date.now()))
    .order("last_used_at", { ascending: false });
  if (error) throw internal("listSessions", error);
  return (data ?? []).map((s) => ({ ...s, current: s.id === currentSessionId }));
}

/** Used by the auth middleware on every request, so revoked sessions stop working immediately. */
export async function isSessionActive(sessionId: string, userId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from("sessions")
    .select("id")
    .eq("id", sessionId)
    .eq("user_id", userId)
    .is("revoked_at", null)
    .gt("expires_at", iso(Date.now()))
    .maybeSingle();
  if (error) throw internal("isSessionActive", error);
  return !!data;
}

/**
 * Refresh-token rotation with reuse detection:
 * every refresh issues a NEW refresh token and the old one becomes invalid.
 * If an already-rotated token shows up again, someone is replaying a stolen token,
 * so the whole session is revoked. (A 10s grace window covers honest network retries.)
 */
export async function refreshSession(refreshToken: string, meta: ClientMeta) {
  const h = hmac(refreshToken);
  const { data: s, error } = await supabase
    .from("sessions")
    .select("id,user_id,refresh_hash,rotated_at,expires_at,revoked_at")
    .or(`refresh_hash.eq.${h},prev_refresh_hash.eq.${h}`)
    .maybeSingle();
  if (error) throw internal("refreshSession.find", error);
  if (!s) throw invalidSession();

  const expiresAt = Date.parse(s.expires_at as string);
  if (s.revoked_at || expiresAt <= Date.now()) throw invalidSession();

  if (s.refresh_hash !== h) {
    const rotatedAt = s.rotated_at ? Date.parse(s.rotated_at as string) : 0;
    if (Date.now() - rotatedAt > 10_000) await revokeSession(s.id as string);
    throw invalidSession();
  }

  const next = randomToken(32);
  const { data: updated, error: upErr } = await supabase
    .from("sessions")
    .update({
      refresh_hash: hmac(next),
      prev_refresh_hash: h,
      rotated_at: iso(Date.now()),
      last_used_at: iso(Date.now()),
      ip: meta.ip ?? null,
      user_agent: meta.userAgent?.slice(0, 255) ?? null,
    })
    .eq("id", s.id)
    .eq("refresh_hash", h) // compare-and-swap: only one concurrent refresh wins
    .is("revoked_at", null)
    .select("id");
  if (upErr) throw internal("refreshSession.rotate", upErr);
  if (!updated?.length) throw invalidSession();

  return tokenBundle(s.user_id as string, s.id as string, next, expiresAt);
}

/* ------------------------------ Sign up / in ------------------------------ */

export async function signUp(name: string, email: string, password: string, meta: ClientMeta) {
  const password_hash = await hashPassword(password);
  const { data, error } = await supabase
    .from("users")
    .insert({ email, name_enc: encrypt(name), password_hash })
    .select("id,email,name_enc")
    .single();

  if (error) {
    if (error.code === "23505") throw new AppError(409, "EMAIL_TAKEN", "Couldn't create your account. Try logging in instead.");
    throw internal("signUp", error);
  }

  const tokens = await issueSession(data.id as string, false, meta);
  return { user: publicUser(data as DbUser), tokens };
}

export async function signIn(email: string, password: string, remember: boolean, meta: ClientMeta) {
  const { data, error } = await supabase
    .from("users")
    .select("id,email,name_enc,password_hash,failed_attempts,locked_until")
    .eq("email", email)
    .maybeSingle();
  if (error) throw internal("signIn.find", error);

  if (!data) {
    await burnPasswordCheck(password);
    throw badCredentials();
  }
  const user = data as DbUser;

  if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
    throw new AppError(423, "ACCOUNT_LOCKED", "Too many failed attempts. Try again in a few minutes.");
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    const attempts = user.failed_attempts + 1;
    const lock = attempts >= config.lockout.maxFailures;
    await supabase
      .from("users")
      .update({
        failed_attempts: lock ? 0 : attempts,
        locked_until: lock ? iso(Date.now() + config.lockout.lockSec * 1000) : null,
      })
      .eq("id", user.id);
    throw badCredentials();
  }

  if (user.failed_attempts > 0 || user.locked_until) {
    await supabase.from("users").update({ failed_attempts: 0, locked_until: null }).eq("id", user.id);
  }

  const tokens = await issueSession(user.id, remember, meta);
  return { user: publicUser(user), tokens };
}

export async function getUser(userId: string) {
  const { data, error } = await supabase.from("users").select("id,email,name_enc").eq("id", userId).maybeSingle();
  if (error) throw internal("getUser", error);
  if (!data) throw new AppError(401, "UNAUTHORIZED", "Authentication required.");
  return publicUser(data as DbUser);
}

/* ---------------------------- Password management ---------------------------- */

export async function changePassword(userId: string, sessionId: string, current: string, next: string) {
  const { data, error } = await supabase.from("users").select("password_hash").eq("id", userId).maybeSingle();
  if (error) throw internal("changePassword.find", error);
  if (!data || !(await verifyPassword(current, data.password_hash as string))) {
    throw new AppError(400, "VALIDATION_ERROR", "Current password is incorrect.", {
      currentPassword: "Current password is incorrect.",
    });
  }
  const { error: upErr } = await supabase
    .from("users")
    .update({ password_hash: await hashPassword(next), updated_at: iso(Date.now()) })
    .eq("id", userId);
  if (upErr) throw internal("changePassword.update", upErr);

  await revokeAllSessions(userId, sessionId); // log out every other device
}

/** Always resolves the same way, whether or not the email exists (prevents account enumeration). */
export async function requestPasswordReset(email: string): Promise<void> {
  const { data: user } = await supabase.from("users").select("id").eq("email", email).maybeSingle();
  if (!user) return;
  const userId = user.id as string;

  // Cooldown: don't let someone spam a user's inbox.
  const { data: recent } = await supabase
    .from("password_resets")
    .select("created_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (recent && Date.now() - Date.parse(recent.created_at as string) < config.reset.cooldownSec * 1000) return;

  await supabase.from("password_resets").delete().eq("user_id", userId).is("used_at", null);

  const code = String(randomInt(0, 1_000_000)).padStart(6, "0"); // CSPRNG
  const { error } = await supabase.from("password_resets").insert({
    user_id: userId,
    code_hash: hmac(`${userId}:${code}`),
    expires_at: iso(Date.now() + config.reset.ttlSec * 1000),
  });
  if (error) {
    console.error("[reset] insert failed", error);
    return;
  }

  // Not awaited: response time must not reveal whether the email exists.
  sendResetCode(email, code).catch((e) => console.error("[reset] email failed", e));
}

export async function resetPassword(email: string, code: string, newPassword: string) {
  const { data: user } = await supabase.from("users").select("id").eq("email", email).maybeSingle();
  if (!user) {
    await burnPasswordCheck(newPassword);
    throw badCode();
  }
  const userId = user.id as string;

  const { data: reset } = await supabase
    .from("password_resets")
    .select("id,code_hash,attempts")
    .eq("user_id", userId)
    .is("used_at", null)
    .gt("expires_at", iso(Date.now()))
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!reset || (reset.attempts as number) >= config.reset.maxAttempts) throw badCode();

  if (!safeEqual(reset.code_hash as string, hmac(`${userId}:${code}`))) {
    await supabase
      .from("password_resets")
      .update({ attempts: (reset.attempts as number) + 1 })
      .eq("id", reset.id);
    throw badCode();
  }

  // Claim the code atomically so it can only ever be used once.
  const { data: claimed, error: claimErr } = await supabase
    .from("password_resets")
    .update({ used_at: iso(Date.now()) })
    .eq("id", reset.id)
    .is("used_at", null)
    .select("id");
  if (claimErr) throw internal("resetPassword.claim", claimErr);
  if (!claimed?.length) throw badCode();

  const { error } = await supabase
    .from("users")
    .update({
      password_hash: await hashPassword(newPassword),
      failed_attempts: 0,
      locked_until: null,
      updated_at: iso(Date.now()),
    })
    .eq("id", userId);
  if (error) throw internal("resetPassword.update", error);

  await revokeAllSessions(userId); // a password reset logs out every device
}

/* -------------------------------- Housekeeping -------------------------------- */

export async function cleanupExpired() {
  const week = iso(Date.now() - 7 * 24 * 3600 * 1000);
  await supabase.from("sessions").delete().lt("expires_at", week);
  await supabase.from("sessions").delete().lt("revoked_at", week);
  await supabase.from("password_resets").delete().lt("expires_at", iso(Date.now()));
}
