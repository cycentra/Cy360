/**
 * CyCentra360 Portal — Production Server
 *
 * Serves the Vite-built React SPA (dist/)
 *
 * NOTE: Node-RED is now deployed as a separate Docker container on port 1880,
 *       proxied via nginx at /node-red/ with authentication.
 *
 * Usage:
 *   NODE_ENV=production node server.cjs
 *
 * Env vars:
 *   PORT        HTTP port (default 3001)
 */

"use strict";

const express = require("express");
const fs      = require("fs");
const path    = require("path");

// ── Config ────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3001", 10);

// In dev: Vite outputs to dist/ → serve from __dirname/dist
// In production: deploy copies dist/* directly to /var/www/cycentra360/ (no dist/ subdir)
const DIST_DIR = fs.existsSync(path.join(__dirname, "dist", "index.html"))
                 ? path.join(__dirname, "dist")
                 : __dirname;

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();

// ── Serve React SPA ───────────────────────────────────────────────────────────

app.use(express.static(DIST_DIR));

// SPA fallback — any unmatched path returns index.html
app.get("*", (_req, res) => {
  res.sendFile(path.join(DIST_DIR, "index.html"));
});

// ── Start server ──────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[cycentra360] Portal server listening on port ${PORT}`);
  console.log(`[cycentra360] Serving React SPA from: ${DIST_DIR}`);
  console.log(`[cycentra360] Node-RED available at https://cy360.<domain>/node-red/ (Docker container)`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[cycentra360] Shutting down...");
  process.exit(0);
});
