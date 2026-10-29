const crypto = require("crypto");

const COOKIE_NAME = "crown_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

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
  return req.headers["x-real-ip"] ||
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    "unknown";
}

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return respond(res, 405, { error: "Method not allowed." });
  }

  if (req.headers.origin !== "https://peacze-games.vercel.app") {
    return respond(res, 403, { error: "Request not allowed." });
  }

  const secret = process.env.ADMIN_PASSCODE;

  if (!secret) {
    return respond(res, 500, { error: "Admin passcode is not configured." });
  }

  const now = Date.now();
  const ip = getClientIp(req);

  let record = attempts.get(ip);

  if (!record || now - record.startedAt >= WINDOW_MS) {
    record = { count: 0, startedAt: now, blockedUntil: 0 };
    attempts.set(ip, record);
  }

  if (record.blockedUntil > now) {
    res.setHeader("Retry-After", String(Math.ceil((record.blockedUntil - now) / 1000)));
    return respond(res, 429, { error: "Too many failed attempts. Try again later." });
  }

  const code = req.body?.code;
  const valid = typeof code === "string" &&
    code.length <= 200 &&
    safeEqual(code, secret);

  if (!valid) {
    record.count++;

    if (record.count >= MAX_ATTEMPTS) {
      record.blockedUntil = now + WINDOW_MS;
      res.setHeader("Retry-After", String(WINDOW_MS / 1000));
      return respond(res, 429, { error: "Too many failed attempts. Try again in 15 minutes." });
    }

    return respond(res, 401, { error: "Invalid admin passcode." });
  }

  attempts.delete(ip);

  const issuedAt = String(now);
  const nonce = crypto.randomBytes(24).toString("hex");
  const payload = `${issuedAt}.${nonce}`;
  const signature = sign(payload, secret);

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
