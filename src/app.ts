import express from "express";
import helmet from "helmet";
import { config } from "./config.js";
import authRoutes from "./routes/auth.routes.js";
import { globalLimiter } from "./middleware/rateLimit.js";
import { errorHandler, notFound } from "./middleware/errors.js";

export const app = express();

app.disable("x-powered-by");
if (config.trustProxy) app.set("trust proxy", config.trustProxy); // needed for correct client IPs behind a proxy

app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(globalLimiter);

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.use("/api/auth", authRoutes);

app.use(notFound);
app.use(errorHandler);
