
const crypto = require("crypto");

function verifySession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)peacze_session=([^;]+)/);

  if (!match) return null;

  try {
    const token = decodeURIComponent(match[1]);
    const [payload, signature] = token.split(".");

    if (!payload || !signature) return null;

    const expected = crypto
      .createHmac("sha256", process.env.DAILY_CODE_SECRET)
      .update(payload)
      .digest("hex");

    const a = Buffer.from(signature, "hex");
    const b = Buffer.from(expected, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.discordUserId) return null;
    if (Date.now() > session.expiresAt) return null;

    const approved = (process.env.APPROVED_DISCORD_IDS || "")
      .split(",")
      .map(id => id.trim());

    if (!approved.includes(String(session.discordUserId))) {
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
    return res.status(401).json({ error: "Unauthorized" });
  }

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
