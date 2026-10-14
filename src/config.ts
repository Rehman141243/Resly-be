function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

function secret(name: string, minLen = 32): string {
  const v = required(name);
  if (v.length < minLen) throw new Error(`${name} must be at least ${minLen} characters`);
  return v;
}

const encryptionKey = Buffer.from(required("ENCRYPTION_KEY"), "base64");
if (encryptionKey.length !== 32) {
  throw new Error("ENCRYPTION_KEY must be 32 random bytes, base64-encoded");
}

const env = process.env.NODE_ENV ?? "development";

export const config = {
  env,
  isProd: env === "production",
  port: Number(process.env.PORT ?? 4000),
  trustProxy: process.env.TRUST_PROXY === "true" ? 1 : false,

  supabaseUrl: required("SUPABASE_URL"),
  supabaseServiceKey: required("SUPABASE_SERVICE_ROLE_KEY"),

  jwtSecret: secret("JWT_SECRET"),
  pepper: secret("PEPPER"),
  encryptionKey,

  accessTtlSec: 15 * 60, // 15 minutes
  refreshTtlSec: 24 * 60 * 60, // 1 day (remember me off)
  refreshTtlRememberSec: 30 * 24 * 60 * 60, // 30 days (remember me on)

  reset: { ttlSec: 10 * 60, maxAttempts: 5, cooldownSec: 60 },
  lockout: { maxFailures: 5, lockSec: 15 * 60 },

  resendApiKey: process.env.RESEND_API_KEY,
  emailFrom: process.env.EMAIL_FROM ?? "FitConnect <no-reply@example.com>",
} as const;
