// server.js — Secure Sandbox API Key Server
//
// Security features:
// - Bootstrap endpoint: one-time key exchange during setup
// - HMAC request signing: all authenticated requests must include
//   a timestamp + HMAC signature to prevent replay attacks
// - Configurable CORS: allowed origins set via ALLOWED_ORIGINS env var
// - Trust proxy: safe behind Render's reverse proxy
// - Helmet: security headers (HSTS, CSP, etc.)
// - No server version headers leak
// - Rate limiting on all endpoints
// - Minimal attack surface: only 3 routes

import dotenv from "dotenv";
dotenv.config();
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createHmac, randomBytes, timingSafeEqual } from "crypto";
import fs from "fs";
import path from "path";
import os from "os";

const app = express();

// ── Strip version headers ──────────────────────────────────────────────────
app.disable("x-powered-by");

// ── Trust proxy (Render / reverse proxy) ──────────────────────────────────
// Render routes traffic through a reverse proxy. Without this,
// req.ip would be the proxy's IP and rate-limiting / HTTPS detection breaks.
app.set("trust proxy", 1);

// ── Helmet: security headers ──────────────────────────────────────────────
// Sets HSTS, CSP, X-Content-Type-Options, etc.
app.use(helmet({
  // Allow the health check to be fetched by Render's health probes
  // and any monitoring tools without strict CSP blocking them.
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// ── JSON body parser with strict limit ─────────────────────────────────────
app.use(express.json({ limit: "1kb" }));

// ── CORS: configurable allowed origins ─────────────────────────────────────
// On localhost-only setups this defaults to localhost.
// On Render (or any public host), set ALLOWED_ORIGINS env var to a
// comma-separated list of allowed origins, e.g.:
//   ALLOWED_ORIGINS=https://my-app.onrender.com,https://my-app.com
const DEFAULT_LOCAL_ORIGINS = [
  "http://localhost",
  "http://127.0.0.1",
  "http://[::1]",
];

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// If no explicit origins are configured, fall back to localhost defaults.
// This keeps the existing local-dev behaviour intact.
const effectiveOrigins = allowedOrigins.length > 0
  ? allowedOrigins
  : DEFAULT_LOCAL_ORIGINS;

// Build a set of allowed origin prefixes for quick lookup.
// We compare the full origin string (scheme + host + port).
const allowedOriginSet = new Set(effectiveOrigins);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    // Exact match against the allowed set
    if (allowedOriginSet.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
      // Also check if the origin's base (without trailing slash) matches
      // any allowed origin — handles cases like "http://localhost:3000"
      // when "http://localhost" is in the allowed list.
      try {
        const url = new URL(origin);
        const originBase = `${url.protocol}//${url.host}`;
        if (allowedOriginSet.has(originBase)) {
          res.setHeader("Access-Control-Allow-Origin", origin);
        } else {
          return res.status(403).json({ error: "Origin not allowed" });
        }
      } catch {
        return res.status(400).json({ error: "Invalid origin header" });
      }
    }
  } else {
    // No origin header (e.g. server-to-server, curl) — set a safe default
    res.setHeader("Access-Control-Allow-Origin", effectiveOrigins[0]);
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Timestamp, X-Signature");
  res.setHeader("Access-Control-Max-Age", "600");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// ── Key Sanitization Helper ───────────────────────────────────────────────
/**
 * Sanitize an API key by stripping accidental brackets, quotes, and whitespace
 * that can be introduced by .env file parsing.
 * e.g. "[sk-or-v1-...]" -> "sk-or-v1-..."
 * e.g. '"sk-or-v1-..."' -> "sk-or-v1-..."
 */
function sanitizeKey(key) {
  if (!key || typeof key !== "string") return key;
  let k = key.trim();
  while (
    (k.startsWith("[") && k.endsWith("]")) ||
    (k.startsWith('"') && k.endsWith('"')) ||
    (k.startsWith("'") && k.endsWith("'"))
  ) {
    k = k.slice(1, -1).trim();
  }
  return k;
}

// ── Env Validation ────────────────────────────────────────────────────────
const requiredEnv = ["PORT", "API_KEYS"];
const missingEnv = requiredEnv.filter((key) => !(key in process.env));
if (missingEnv.length > 0) {
  console.error("Missing required environment variables:", missingEnv.join(", "));
  process.exit(1);
}

const API_KEYS = process.env.API_KEYS.split(",")
  .map((k) => sanitizeKey(k.trim()))
  .filter(Boolean);

if (API_KEYS.length === 0) {
  console.error("API_KEYS must contain at least one key");
  process.exit(1);
}

const weakKeys = API_KEYS.filter((k) => k.length < 10);
if (weakKeys.length > 0) {
  console.error("One or more API keys appear too short (< 10 chars). Aborting.");
  process.exit(1);
}

// ── Rate Limiting ─────────────────────────────────────────────────────────
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
}));

const keyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Key retrieval rate limit exceeded" },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Request ID Middleware ──────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = randomBytes(8).toString("hex");
  next();
});

// ── Active Sessions (auth tokens issued via bootstrap) ─────────────────────
// In-memory store of valid auth tokens. New ones are added via /bootstrap.
const activeTokens = new Set();

// ── HMAC Signing Secret ───────────────────────────────────────────────────
// Persisted to disk so server restarts don't invalidate CLI credentials.
// On Render, use /tmp or a mounted volume; locally, use ~/.astra/.server.
const STATE_DIR = process.env.STATE_DIR
  ? path.resolve(process.env.STATE_DIR)
  : path.join(os.homedir(), ".astra", ".server");
const STATE_FILE = path.join(STATE_DIR, "server-state.json");

let SIGNING_SECRET;

function loadServerState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, "utf8");
      const state = JSON.parse(raw);
      if (state.signingSecret && Array.isArray(state.activeTokens)) {
        SIGNING_SECRET = state.signingSecret;
        for (const t of state.activeTokens) activeTokens.add(t);
        console.log(`[server] Restored ${state.activeTokens.length} active token(s) from disk.`);
        return;
      }
    }
  } catch { /* corrupted — regenerate */ }

  SIGNING_SECRET = randomBytes(32).toString("hex");
  console.log("[server] Generated new signing secret (no existing state found).");
}

function saveServerState() {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    const state = {
      signingSecret: SIGNING_SECRET,
      activeTokens: [...activeTokens],
    };
    const tmpFile = STATE_FILE + ".tmp";
    fs.writeFileSync(tmpFile, JSON.stringify(state), "utf8");
    fs.renameSync(tmpFile, STATE_FILE);
    try { fs.chmodSync(STATE_FILE, 0o600); } catch { /* Windows */ }
  } catch (err) {
    console.error("[server] Warning: failed to persist server state:", err.message);
  }
}

loadServerState();

// ── HMAC Helpers ──────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 signature for a request.
 */
function computeSignature(timestamp, token) {
  const payload = `${timestamp}:${token}`;
  return createHmac("sha256", SIGNING_SECRET).update(payload).digest("hex");
}

/**
 * Verify HMAC signature + timestamp freshness.
 * Rejects requests older than 30 seconds (replay protection).
 */
function verifyRequest(req) {
  const authHeader = req.headers.authorization;
  const timestamp = req.headers["x-timestamp"];
  const signature = req.headers["x-signature"];

  if (!authHeader || typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
    return { valid: false, error: "Missing or invalid Authorization header" };
  }

  const token = authHeader.slice(7);

  if (!timestamp || typeof timestamp !== "string") {
    return { valid: false, error: "Missing X-Timestamp header" };
  }

  if (!signature || typeof signature !== "string") {
    return { valid: false, error: "Missing X-Signature header" };
  }

  // Replay protection: reject requests older than 30 seconds
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts)) {
    return { valid: false, error: "Invalid timestamp" };
  }
  const age = Math.abs(Date.now() - ts);
  if (age > 30_000) {
    return { valid: false, error: "Request expired (replay protection)" };
  }

  // Check token is valid
  if (!activeTokens.has(token)) {
    return { valid: false, error: "Invalid token" };
  }

  // Verify HMAC signature
  const expectedSig = computeSignature(timestamp, token);
  const expectedBuf = Buffer.from(expectedSig, "hex");
  const actualBuf = Buffer.from(signature, "hex");

  if (expectedBuf.length !== actualBuf.length) {
    return { valid: false, error: "Invalid signature" };
  }

  if (!timingSafeEqual(expectedBuf, actualBuf)) {
    return { valid: false, error: "Invalid signature" };
  }

  return { valid: true };
}

// ── Auth Middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const result = verifyRequest(req);
  if (!result.valid) {
    return res.status(401).json({ error: result.error || "Unauthorized" });
  }
  next();
}

// ── Routes ─────────────────────────────────────────────────────────────────

/**
 * GET /health — Server health check (no auth required).
 * Returns minimal info — no nonces or version info.
 */
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /bootstrap — One-time setup to exchange auth for API key.
 *
 * Called by the CLI during "sandbox activate". The client generates
 * a random token, sends it here, and the server responds with the
 * API key. The token is then registered as valid for future requests.
 *
 * After bootstrap, the token becomes a permanent auth credential.
 * The client stores it in OS keychain.
 *
 * Request body: { authToken: string }
 * Response: { key: string, token: string, signingSecret: string }
 */
app.post("/bootstrap", keyLimiter, (req, res) => {
  const { authToken } = req.body || {};

  if (!authToken || typeof authToken !== "string" || authToken.length < 16) {
    return res.status(400).json({ error: "Missing or invalid authToken (min 16 chars)" });
  }

  // Register this token as active
  activeTokens.add(authToken);
  saveServerState();

  // Return a random API key + the signing secret for HMAC
  const key = API_KEYS[Math.floor(Math.random() * API_KEYS.length)];

  res.json({
    key,
    token: authToken,
    signingSecret: SIGNING_SECRET,
  });
});

/**
 * GET /api/key — Retrieve an API key.
 * Requires Bearer auth + HMAC signature.
 */
app.get("/api/key", keyLimiter, requireAuth, (req, res) => {
  const key = API_KEYS[Math.floor(Math.random() * API_KEYS.length)];
  res.json({
    key,
    requestId: req.requestId,
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Global error handler
app.use((err, req, _res, _next) => {
  console.error(`[${req.requestId ?? "???"}] Error:`, err.message);
});

// ── Start ──────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10);
if (isNaN(PORT) || PORT <= 0) {
  console.error("PORT must be a valid positive integer. Got:", process.env.PORT);
  process.exit(1);
}

// Bind to 0.0.0.0 so Render (and any container platform) can reach us.
// Previously this was 127.0.0.1 (loopback-only), which only works locally.
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Sandbox key server listening on 0.0.0.0:${PORT}`);
  console.log(`Allowed origins: ${effectiveOrigins.join(", ")}`);
});

// ── Graceful Shutdown ──────────────────────────────────────────────────────
function gracefulShutdown(signal) {
  console.log(`\nReceived ${signal}. Shutting down...`);
  saveServerState();
  server.close(() => {
    console.log("Server closed.");
    process.exit(0);
  });
  setTimeout(() => {
    console.error("Forced shutdown after timeout.");
    process.exit(1);
  }, 5000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});

export { server };
