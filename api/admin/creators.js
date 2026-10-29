const crypto = require("crypto");

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

function verifyAdminSession(req) {
  const passcode = process.env.ADMIN_PASSCODE;
  if (!passcode) return false;

  const token = getCookie(req, "crown_admin_session");
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [nonce, signature] = parts;

  if (!/^[a-f0-9]{64}$/i.test(nonce)) return false;
  if (!/^[a-f0-9]{64}$/i.test(signature)) return false;

  const expected = crypto
    .createHmac("sha256", passcode)
    .update(nonce)
    .digest("hex");

  const actualBuffer = Buffer.from(signature, "hex");
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

  const target = new URL("/api/admin/creators", backend);

  if (req.method === "PATCH") {
    if (!/^[0-9]{17,20}$/.test(discordUserId)) {
      return res.status(400).json({ error: "A valid Discord user ID is required." });
    }

    target.searchParams.set("discordUserId", discordUserId);
  }

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
