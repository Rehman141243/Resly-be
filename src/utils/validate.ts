import { AppError } from "./errors.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Fields = Record<string, string>;

const obj = (raw: unknown): Record<string, unknown> =>
  typeof raw === "object" && raw !== null && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};

const fail = (f: Fields) => {
  if (Object.keys(f).length) throw new AppError(400, "VALIDATION_ERROR", "Please check the highlighted fields.", f);
};

function readEmail(v: unknown, f: Fields): string {
  const e = typeof v === "string" ? v.trim().toLowerCase() : "";
  if (e.length > 254 || !EMAIL_RE.test(e)) f.email = "Enter a valid email address.";
  return e;
}

function readNewPassword(v: unknown, f: Fields, key = "password"): string {
  const pw = typeof v === "string" ? v : "";
  if (pw.length < 8) f[key] = "Use at least 8 characters.";
  else if (pw.length > 128) f[key] = "Use at most 128 characters.";
  return pw;
}

export function parseSignUp(raw: unknown) {
  const b = obj(raw);
  const f: Fields = {};
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (name.length < 2 || name.length > 80) f.name = "Enter your full name.";
  const email = readEmail(b.email, f);
  const password = readNewPassword(b.password, f);
  fail(f);
  return { name, email, password };
}

export function parseLogin(raw: unknown) {
  const b = obj(raw);
  const f: Fields = {};
  const email = readEmail(b.email, f);
  const password = typeof b.password === "string" ? b.password : "";
  if (!password || password.length > 128) f.password = "Enter your password.";
  fail(f);
  return { email, password, remember: b.remember === true };
}

export function parseRefresh(raw: unknown) {
  const b = obj(raw);
  const t = b.refreshToken;
  if (typeof t !== "string" || t.length < 20 || t.length > 200) {
    throw new AppError(400, "VALIDATION_ERROR", "refreshToken is required.");
  }
  return { refreshToken: t };
}

export function parseForgot(raw: unknown) {
  const f: Fields = {};
  const email = readEmail(obj(raw).email, f);
  fail(f);
  return { email };
}

export function parseReset(raw: unknown) {
  const b = obj(raw);
  const f: Fields = {};
  const email = readEmail(b.email, f);
  const code = typeof b.code === "string" ? b.code.trim() : "";
  if (!/^\d{6}$/.test(code)) f.code = "Enter the 6-digit code from your email.";
  const password = readNewPassword(b.password, f);
  fail(f);
  return { email, code, password };
}

export function parseChangePassword(raw: unknown) {
  const b = obj(raw);
  const f: Fields = {};
  const current = typeof b.currentPassword === "string" ? b.currentPassword : "";
  if (!current || current.length > 128) f.currentPassword = "Enter your current password.";
  const next = readNewPassword(b.newPassword, f, "newPassword");
  fail(f);
  return { currentPassword: current, newPassword: next };
}

export function parseUuid(v: unknown): string {
  if (typeof v !== "string" || !UUID_RE.test(v)) throw new AppError(400, "VALIDATION_ERROR", "Invalid id.");
  return v;
}
