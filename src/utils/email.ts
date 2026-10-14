import { config } from "../config.js";

// Sends through Resend's HTTP API using built-in fetch (no extra library).
export async function sendResetCode(to: string, code: string): Promise<void> {
  if (!config.resendApiKey) {
    if (!config.isProd) console.log(`[dev email] Reset code for ${to}: ${code}`);
    else console.error("RESEND_API_KEY is not set; password reset email was NOT sent.");
    return;
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${config.resendApiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: config.emailFrom,
      to,
      subject: "Your FitConnect password reset code",
      text: `Your reset code is ${code}. It expires in ${Math.round(config.reset.ttlSec / 60)} minutes.\n\nIf you didn't request this, you can ignore this email.`,
    }),
  });
  if (!res.ok) throw new Error(`Email provider responded ${res.status}`);
}
