import { app } from "./app.js";
import { config } from "./config.js";
import { cleanupExpired } from "./services/auth.service.js";

const server = app.listen(config.port, () => {
  console.log(`FitConnect API listening on :${config.port} (${config.env})`);
});

// Purge expired/revoked sessions and used reset codes every hour.
const timer = setInterval(() => {
  cleanupExpired().catch((e) => console.error("[cleanup] failed", e));
}, 60 * 60 * 1000);
timer.unref();

const shutdown = () => {
  clearInterval(timer);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
