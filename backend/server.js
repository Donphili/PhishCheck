
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Behind a host such as Render or Railway the real client IP arrives in a
// forwarded header. Without this, the rate limiter sees one shared IP.
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);
}

// ==========================================
// 1. MIDDLEWARE CONFIGURATION
// ==========================================

// Allow requests from our React frontend.
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
  })
);

// Limit incoming request size.
app.use(express.json({ limit: "10kb" }));

// Protect the API from excessive requests.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

app.use("/api/", apiLimiter);

// ==========================================
// 2. HEALTH CHECK ENDPOINT
// ==========================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    service: "PhishCheck API",
    message: "Backend is running successfully.",
  });
});

// ==========================================
// 3. GOOGLE WEB RISK URL CHECKER
// ==========================================

app.post("/api/check-url", async (req, res) => {
  try {
    const { url } = req.body;

    // Validate submitted URL.
    if (!url || typeof url !== "string") {
      return res.status(400).json({
        status: "error",
        error: "Please provide a valid URL.",
      });
    }

    const trimmedUrl = url.trim();

    if (trimmedUrl.length > 2048) {
      return res.status(400).json({
        status: "error",
        error: "The URL is too long.",
      });
    }

    // Parse and validate the URL.
    let parsedUrl;

    try {
      parsedUrl = new URL(trimmedUrl);
    } catch {
      return res.status(400).json({
        status: "error",
        error: "The URL format is invalid.",
      });
    }

    // Only HTTP and HTTPS are supported.
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.status(400).json({
        status: "error",
        error: "Only HTTP and HTTPS URLs are supported.",
      });
    }

    // Retrieve the private API key.
    const apiKey = process.env.WEBRISK_API_KEY;

    if (
      !apiKey ||
      apiKey === "PASTE_YOUR_GOOGLE_API_KEY_HERE"
    ) {
      return res.status(503).json({
        status: "unavailable",
        error: "Google Web Risk has not been configured yet.",
      });
    }

    // ==========================================
    // 4. GOOGLE WEB RISK API REQUEST
    // ==========================================

    const endpoint = new URL(
      "https://webrisk.googleapis.com/v1/uris:search"
    );

    endpoint.searchParams.set("key", apiKey);
    endpoint.searchParams.set("uri", parsedUrl.href);

    endpoint.searchParams.append(
      "threatTypes",
      "SOCIAL_ENGINEERING"
    );

    endpoint.searchParams.append(
      "threatTypes",
      "MALWARE"
    );

    endpoint.searchParams.append(
      "threatTypes",
      "UNWANTED_SOFTWARE"
    );

    // Send the URL to Google Web Risk.
    const response = await fetch(endpoint, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
    });

    // ==========================================
    // 5. HANDLE GOOGLE API ERRORS
    // ==========================================

    if (!response.ok) {
      const errorDetails = await response.text();

      // Log Google's actual error for debugging.
      console.error("-----------------------------------");
      console.error("GOOGLE WEB RISK API ERROR");
      console.error("HTTP Status:", response.status);
      console.error("Error Details:", errorDetails);
      console.error("-----------------------------------");

      return res.status(502).json({
        status: "unavailable",
        provider: "Google Web Risk",
        providerStatus: response.status,
        error: "Google Web Risk rejected the request.",
        details: (() => {
          try {
            const parsedError = JSON.parse(errorDetails);
            return parsedError.error?.message || "No additional details.";
          } catch {
            return "Google returned an unreadable error response.";
          }
        })(),
      });
    }

    // ==========================================
    // 6. PROCESS THREAT INTELLIGENCE RESULTS
    // ==========================================

    const data = await response.json();

    const threatTypes = data.threat?.threatTypes || [];

    const isListed = threatTypes.length > 0;

    return res.json({
      provider: "Google Web Risk",

      status: isListed ? "match" : "no_match",

      isListed,

      threatTypes,

      expireTime: data.threat?.expireTime || null,

      checkedAt: new Date().toISOString(),

      message: isListed
        ? "This URL matches one or more known threat lists."
        : "No match was found in the checked threat lists. This does not guarantee that the URL is safe.",
    });

  } catch (error) {

    // ==========================================
    // 7. HANDLE UNEXPECTED ERRORS
    // ==========================================

    console.error("-----------------------------------");
    console.error("PHISHCHECK URL CHECK ERROR");
    console.error("Error:", error.message);
    console.error("-----------------------------------");

    if (error.name === "TimeoutError" || error.name === "AbortError") {
      return res.status(504).json({
        status: "unavailable",
        error: "Google Web Risk took too long to respond.",
      });
    }

    return res.status(500).json({
      status: "error",
      error: "An unexpected error occurred while checking the URL.",
    });
  }
});

// ==========================================
// 8. START THE BACKEND SERVER
// ==========================================

app.listen(PORT, () => {
  console.log("-----------------------------------");
  console.log("       PHISHCHECK BACKEND");
  console.log("-----------------------------------");
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`API status: http://localhost:${PORT}/api/health`);
  console.log("-----------------------------------");
});
