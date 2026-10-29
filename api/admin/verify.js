**File:** `api/admin/verify.js`

Replace the entire file with this code:

```javascript
const crypto = require("crypto");

const COOKIE_NAME = "crown_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

// Temporary per-instance rate-limit storage.
const attempts = new Map();

function respond(res, status, data) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json(data);
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
}

function getClientIp(req) {
  // Vercel provides the connecting client's IP.
  return req.headers["x-real-ip"] ||
    (req.headers["x-forwarded-for"] || "")
      .split(",")[0]
      .trim() ||
    "unknown";
}

function getAttemptRecord(ip, now) {
  let record = attempts.get(ip);

  if (!record || now - record.startedAt >= WINDOW_MS) {
    record = {
      count: 0,
      startedAt: now,
      blockedUntil: 0
    };

    attempts.set(ip, record);
  }

  return record;
}

function cleanAttempts(now) {
  for (const [ip, record] of attempts) {
    if (
      now - record.startedAt >= WINDOW_MS &&
      record.blockedUntil <= now
    ) {
      attempts.delete(ip);
    }
  }

  // Bound memory use if many different IPs reach this instance.
  while (attempts.size > 5000) {
    attempts.delete(attempts.keys().next().value);
  }
}

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return respond(res, 405, {
      error: "Method not allowed."
    });
  }

  if (req.headers.origin !== "https://peacze-games.vercel.app") {
    return respond(res, 403, {
      error: "Request not allowed."
    });
  }

  const passcode = process.env.ADMIN_PASSCODE;

  if (!passcode) {
    return respond(res, 500, {
      error: "Admin passcode is not configured."
    });
  }

  const now = Date.now();
  cleanAttempts(now);

  const ip = getClientIp(req);
  const record = getAttemptRecord(ip, now);

  if (record.blockedUntil > now) {
    res.setHeader(
      "Retry-After",
      String(Math.ceil((record.blockedUntil - now) / 1000))
    );

    return respond(res, 429, {
      error: "Too many failed attempts. Try again later."
    });
  }

  const code = req.body?.code;

  const valid =
    typeof code === "string" &&
    code.length <= 200 &&
    safeEqual(code, passcode);

  if (!valid) {
    record.count += 1;

    if (record.count >= MAX_ATTEMPTS) {
      record.blockedUntil = now + WINDOW_MS;

      res.setHeader("Retry-After", String(WINDOW_MS / 1000));

      return respond(res, 429, {
        error: "Too many failed attempts. Try again in 15 minutes."
      });
    }

    return respond(res, 401, {
      error: "Invalid admin passcode."
    });
  }

  // Clear this IP's failed-attempt record after successful login.
  attempts.delete(ip);

  const payload =
    `${Date.now()}.${crypto.randomBytes(24).toString("hex")}`;

  const signature = sign(payload, passcode);
  const cookie = `${payload}.${signature}`;

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`
  );

  return respond(res, 200, {
    authorized: true,
    expiresIn: SESSION_SECONDS
  });
};
```
