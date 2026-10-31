const crypto = require("crypto");

function verifySession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)peacze_session=([^;]+)/);

  if (!match) return null;

  try {
    const token = decodeURIComponent(match[1]);
    const [payload, signature] = token.split(".");

    if (!payload || !signature) return null;

    const secret = process.env.DAILY_CODE_SECRET;
    if (!secret) return null;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature, "base64url");
    const b = Buffer.from(expected, "base64url");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.discordUserId) return null;
    if (!Number.isFinite(session.expiresAt)) return null;
    if (Date.now() / 1000 > session.expiresAt) return null;

    const approved = (process.env.APPROVED_DISCORD_IDS || "")
      .split(",")
      .map(id => id.trim());

    if (!approved.includes(String(session.discordUserId))) return null;

    return String(session.discordUserId);
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const discordUserId = verifySession(req);

  if (!discordUserId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const backend = process.env.TIKTOK_BACKEND_URL;
    const queueToken = process.env.TIKTOK_QUEUE_TOKEN;

    if (!backend || !queueToken) {
      return res.status(500).json({ error: "Backend not configured" });
    }

    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

    const { clipId, status, characterName } = body;

    if (
      typeof clipId !== "string" ||
      clipId.length < 1 ||
      clipId.length > 150
    ) {
      return res.status(400).json({ error: "Invalid clipId" });
    }

    if (!["started", "ended", "stopped"].includes(status)) {
      return res.status(400).json({ error: "Invalid playback status" });
    }

    const response = await fetch(
      `${backend.replace(/\/$/, "")}/api/crustyspeaks/playback`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${queueToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          discordUserId,
          clipId,
          status,
          characterName:
            typeof characterName === "string"
              ? characterName.slice(0, 60)
              : ""
        }),
        signal: AbortSignal.timeout(15000)
      }
    );

    const data = await response.json();

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("[CRUSTYSPEAKS PLAYBACK PROXY]", error);
    return res.status(502).json({
      error: "Playback notification backend unavailable"
    });
  }
};
