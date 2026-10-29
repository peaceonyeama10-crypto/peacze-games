const crypto = require("crypto");

const SESSION_SECONDS = 8 * 60 * 60;

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");
    if (index < 0) continue;

    if (item.slice(0, index).trim() === name) {
      return decodeURIComponent(item.slice(index + 1).trim());
    }
  }

  return null;
}

// Must stay identical to the check in api/admin/session.js:
// cookie format is issuedAt.nonce.signature, where
// signature = HMAC-SHA256(ADMIN_PASSCODE, "issuedAt.nonce") in hex.
function verifyAdminSession(req) {
  const passcode = process.env.ADMIN_PASSCODE;
  if (!passcode) return false;

  const token = getCookie(req, "crown_admin_session");
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 3) return false;

  const [issuedAtText, nonce, suppliedSignature] = parts;
  const issuedAt = Number(issuedAtText);

  if (
    !Number.isSafeInteger(issuedAt) ||
    !/^[a-f0-9]{48}$/.test(nonce) ||
    !/^[a-f0-9]{64}$/.test(suppliedSignature)
  ) {
    return false;
  }

  const now = Date.now();

  if (
    issuedAt > now + 30000 ||
    now - issuedAt >= SESSION_SECONDS * 1000
  ) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", passcode)
    .update(`${issuedAtText}.${nonce}`)
    .digest("hex");

  const actualBuffer = Buffer.from(suppliedSignature, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");

  if (
    actualBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  ) {
    return false;
  }

  return true;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (!verifyAdminSession(req)) {
    return res.status(401).json({ error: "Administrator session required." });
  }

  const allowedOrigin = "https://peacze-games.vercel.app";
  const origin = req.headers.origin;

  if (origin && origin !== allowedOrigin) {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const secret = process.env.CREATOR_ADMIN_API_SECRET;
  const backend = (process.env.TIKTOK_BACKEND_URL || "").replace(/\/+$/, "");

  if (!secret || !backend) {
    return res.status(500).json({
      error: "Creator API environment configuration is missing."
    });
  }

  if (!["GET", "POST", "PATCH"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, PATCH");
    return res.status(405).json({ error: "Method not allowed." });
  }

  const discordUserId =
    typeof req.query?.discordUserId === "string"
      ? req.query.discordUserId.trim()
      : "";

  // The Render backend expects PATCH /api/admin/creators/:discordUserId
  // (the ID in the path, not in the query string).
  let targetPath = "/api/admin/creators";

  if (req.method === "PATCH") {
    if (!/^[0-9]{17,20}$/.test(discordUserId)) {
      return res.status(400).json({ error: "A valid Discord user ID is required." });
    }

    targetPath = `/api/admin/creators/${discordUserId}`;
  }

  const target = new URL(targetPath, backend);

  const headers = {
    "Authorization": `Bearer ${secret}`,
    "Accept": "application/json"
  };

  const options = {
    method: req.method,
    headers,
    signal: AbortSignal.timeout(15000)
  };

  if (req.method === "POST" || req.method === "PATCH") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(req.body || {});
  }

  try {
    const response = await fetch(target, options);
    const text = await response.text();

    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { error: "The creator backend returned an invalid response." };
    }

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("Creator API proxy error:", error);

    return res.status(502).json({
      error: "Could not reach the creator backend."
    });
  }
};
