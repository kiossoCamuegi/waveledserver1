// redisHttpCache.js  (ESM)
// npm i redis
import { createClient } from "redis";

/** Create & connect a Redis client */
export async function createRedisClient(url = process.env.REDIS_URL || "redis://127.0.0.1:6379") {
  const client = createClient({ url });
  client.on("error", (e) => console.error("Redis error:", e));
  await client.connect();
  return client;
}

/** Build a deterministic key: METHOD + path + sorted query */
function buildKey(prefix, req) {
  const url = new URL(req.originalUrl, "http://x"); // base is ignored
  const params = new URLSearchParams(url.search);
  params.sort();
  const qs = params.toString();
  const path = url.pathname + (qs ? `?${qs}` : "");
  return `${prefix}${req.method.toUpperCase()}:${path}`;
}

/** Quick check if we should cache based on content-type */
function isCacheableContentType(ct = "") {
  const t = String(ct).toLowerCase();
  return t.includes("application/json") || t.startsWith("text/");
}

/**
 * Express middleware that:
 *  - caches GET responses (200, JSON/text) for `ttl` seconds
 *  - on any write (POST/PUT/PATCH/DELETE) invalidates the whole prefix
 */
export function redisHttpCache({
  client,
  ttl = 60,                       // seconds
  prefix = "httpcache:",
  headerName = "X-Cache",
  shouldCache = (req, res) =>
    res.statusCode === 200 && isCacheableContentType(res.getHeader("content-type")),
} = {}) {
  if (!client) throw new Error("redisHttpCache: Redis client is required");

  const WRITE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

  async function flushAll() {
    try {
      for await (const key of client.scanIterator({ MATCH: `${prefix}*`, COUNT: 200 })) {
        await client.del(key);
      }
    } catch (e) {
      console.error("Redis flush error:", e);
    }
  }

  return async (req, res, next) => {
    const method = req.method.toUpperCase();

    // Invalidate on writes (before hitting route handlers)
    if (WRITE.has(method)) {
      await flushAll();
      return next();
    }

    // Cache GETs only
    if (method !== "GET") return next();

    const key = buildKey(prefix, req);

    // Try HIT
    try {
      const cached = await client.get(key);
      if (cached) {
        const { status, headers, body, isBinary } = JSON.parse(cached);

        // Re-apply minimal headers (avoid overriding user-set security headers)
        if (headers?.["content-type"]) res.setHeader("Content-Type", headers["content-type"]);
        res.setHeader(headerName, "HIT");

        if (isBinary) {
          const buf = Buffer.from(body, "base64");
          return res.status(status).send(buf);
        }
        return res.status(status).send(body);
      }
    } catch (e) {
      // cache failure should never break the request
      console.warn("Redis GET failed:", e.message);
    }

    // MISS: intercept the response to store it
    const originalSend = res.send.bind(res);
    res.send = async (payload) => {
      try {
        // Allow downstream to set status/headers first
        const status = res.statusCode;
        const ct = res.getHeader("content-type");
        const okToCache = shouldCache(req, res, payload);

        if (okToCache) {
          let bodyString = "";
          let isBinary = false;

          if (Buffer.isBuffer(payload)) {
            bodyString = payload.toString("base64");
            isBinary = true;
          } else if (typeof payload === "string") {
            bodyString = payload;
          } else {
            // res.json calls end up here too; stringify safely
            bodyString = JSON.stringify(payload);
            if (!res.getHeader("content-type")) {
              res.setHeader("Content-Type", "application/json; charset=utf-8");
            }
          }

          const toStore = JSON.stringify({
            status,
            headers: { "content-type": ct || res.getHeader("content-type") || "application/octet-stream" },
            body: bodyString,
            isBinary,
          });

          await client.setEx(key, ttl, toStore);
          res.setHeader(headerName, "MISS");
        } else {
          res.setHeader(headerName, "BYPASS");
        }
      } catch (e) {
        console.warn("Redis SET failed:", e.message);
      }
      return originalSend(payload);
    };

    return next();
  };
}
