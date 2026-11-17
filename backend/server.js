import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { pathToFileURL } from "node:url";
import { createChecker } from "./lib/checkUrl.js";
import { OpenPhishFeed } from "./lib/providers/openphish.js";
import { createTeamRouter } from "./lib/team/routes.js";
import { createSupabaseStore } from "./lib/team/supabaseStore.js";

dotenv.config();

export function parseOrigins(value) {
  return String(value)
    .split(",")
    .map((item) => item.trim().replace(/\/+$/, ""))
    .filter(Boolean);
}

export function loadConfig(env = process.env) {
  // Keys left as the placeholder text are treated as "not set".
  const clean = (value) =>
    !value || /PASTE_YOUR/i.test(value) ? "" : value.trim();

  return {
    port: env.PORT || 5000,
    // One or more allowed website addresses, separated by commas.
    frontendOrigins: parseOrigins(env.FRONTEND_ORIGIN || "http://localhost:5173"),
    safeBrowsingKey: clean(env.SAFE_BROWSING_API_KEY),
    webRiskKey: clean(env.WEBRISK_API_KEY),
    urlhausKey: clean(env.URLHAUS_AUTH_KEY),
    enableOpenPhish: env.ENABLE_OPENPHISH === "true",
    openPhishFeedUrl: env.OPENPHISH_FEED_URL || undefined,
    trustProxy: env.TRUST_PROXY,
    // Team training storage (optional). See sql/team_training.sql.
    supabaseUrl: clean(env.SUPABASE_URL),
    supabaseKey: clean(env.SUPABASE_SECRET_KEY),
  };
}

export function createApp({ config, checker, teamStore = null, teamLimits = {} }) {
  const app = express();

  // Behind a host such as Render or Railway the real client IP arrives in a
  // forwarded header. Without this, the rate limiter sees one shared IP.
  if (config.trustProxy) {
    app.set("trust proxy", Number(config.trustProxy) || 1);
  }

  app.use(cors({ origin: config.frontendOrigins }));
  app.use(express.json({ limit: "10kb" }));

  app.use(
    "/api/",
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 100,
      standardHeaders: "draft-8",
      legacyHeaders: false,
    })
  );

  app.get("/api/health", (req, res) => {
    res.json({
      status: "online",
      service: "PhishCheck API",
      sources: {
        safeBrowsing: Boolean(config.safeBrowsingKey),
        webRisk: Boolean(config.webRiskKey),
        urlhaus: Boolean(config.urlhausKey),
        openPhish: config.enableOpenPhish,
      },
      teamTraining: Boolean(teamStore),
    });
  });

  if (teamStore) {
    app.use("/api/teams", createTeamRouter({ store: teamStore, ...teamLimits }));
  } else {
    app.use("/api/teams", (req, res) =>
      res.status(503).json({
        status: "error",
        error: "Team training is not set up on this server yet.",
      })
    );
  }

  app.post("/api/check-url", async (req, res) => {
    const { url } = req.body || {};

    if (!url || typeof url !== "string") {
      return res.status(400).json({ status: "error", error: "Please provide a valid URL." });
    }

    const trimmedUrl = url.trim();

    if (trimmedUrl.length > 2048) {
      return res.status(400).json({ status: "error", error: "The URL is too long." });
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(trimmedUrl);
    } catch {
      return res.status(400).json({ status: "error", error: "The URL format is invalid." });
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res
        .status(400)
        .json({ status: "error", error: "Only HTTP and HTTPS URLs are supported." });
    }

    try {
      return res.json(await checker(parsedUrl.href));
    } catch (error) {
      // Never log the submitted URL: it may contain private tokens.
      console.error("PHISHCHECK URL CHECK ERROR:", error.name);

      return res.status(500).json({
        status: "error",
        error: "An unexpected error occurred while checking the URL.",
      });
    }
  });

  return app;
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const config = loadConfig();

  let openPhish = null;

  if (config.enableOpenPhish) {
    openPhish = new OpenPhishFeed({ feedUrl: config.openPhishFeedUrl });
    openPhish.start(); // retries by itself if the first download fails
  }

  const teamStore =
    config.supabaseUrl && config.supabaseKey
      ? createSupabaseStore({ url: config.supabaseUrl, key: config.supabaseKey })
      : null;

  const app = createApp({
    config,
    checker: createChecker({ config, openPhish }),
    teamStore,
  });

  app.listen(config.port, () => {
    console.log("-----------------------------------");
    console.log("       PHISHCHECK BACKEND");
    console.log("-----------------------------------");
    console.log(`Server running at http://localhost:${config.port}`);
    console.log(`API status: http://localhost:${config.port}/api/health`);
    console.log(
      "Sources:",
      [
        config.safeBrowsingKey && "Safe Browsing",
        config.webRiskKey && "Web Risk",
        config.urlhausKey && "URLhaus",
        config.enableOpenPhish && "OpenPhish",
      ]
        .filter(Boolean)
        .join(", ") || "none configured"
    );
    console.log(`Team training: ${teamStore ? "on" : "off (no Supabase settings)"}`);
    console.log("-----------------------------------");
  });
}
