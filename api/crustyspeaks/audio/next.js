const crypto = require("crypto");

function verifySession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)peacze_session=([^;]+)/);

  if (!match) {
  console.log("[AUTH CHECK] Cookie missing");
  return null;
}

  try {
    const token = decodeURIComponent(match[1]);
    const [payload, signature] = token.split(".");

    if (!payload || !signature) return null;

    const expected = crypto
      .createHmac("sha256", process.env.DAILY_CODE_SECRET)
      .update(payload)
      .digest("base64url");

const a = Buffer.from(signature, "base64url");
const b = Buffer.from(expected, "base64url");

   if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
  console.log("[AUTH CHECK] Signature mismatch");
  return null;
}

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.discordUserId) return null;
    if (!Number.isFinite(session.expiresAt)) {
      console.log("[AUTH CHECK] expiresAt missing or invalid");
      return null;
    }

    if (Date.now() / 1000 > session.expiresAt) {
      console.log("[AUTH CHECK] Session expired");
      return null;
    }

    const approved = (process.env.APPROVED_DISCORD_IDS || "")
      .split(",")
      .map(id => id.trim());

       if (!approved.includes(String(session.discordUserId))) {
      console.log("[AUTH CHECK] Discord ID not in approved list");
      return null;
    }

    return String(session.discordUserId);
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const discordUserId = verifySession(req);

if (!discordUserId) {
  console.log("[CRUSTYSPEAKS AUTH] Session rejected");
  return res.status(401).json({ error: "Unauthorized" });
}

console.log("[CRUSTYSPEAKS AUTH] Session accepted");

  try {
    const backend = process.env.TIKTOK_BACKEND_URL;

    if (!backend || !process.env.TIKTOK_QUEUE_TOKEN) {
      return res.status(500).json({ error: "Backend not configured" });
    }

    const response = await fetch(
      `${backend.replace(/\/$/, "")}/api/crustyspeaks/next?discordUserId=${encodeURIComponent(discordUserId)}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.TIKTOK_QUEUE_TOKEN}`
        },
        signal: AbortSignal.timeout(15000)
      }
    );

    const data = await response.json();

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("[CRUSTYSPEAKS AUDIO PROXY]", error);
    return res.status(502).json({ error: "Audio backend unavailable" });
  }
};
