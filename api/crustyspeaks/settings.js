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
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.discordUserId) return null;
    if (Date.now() / 1000 > session.expiresAt) return null;

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
  if (!["GET", "POST"].includes(req.method)) {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const discordUserId = verifySession(req);

 if (!discordUserId) {
  const cookie = req.headers.cookie || "";
  console.log("[CRUSTYSPEAKS AUTH DEBUG]", {
    cookiePresent: cookie.includes("peacze_session="),
    secretPresent: Boolean(process.env.DAILY_CODE_SECRET),
    approvedIdsPresent: Boolean(process.env.APPROVED_DISCORD_IDS)
  });

  return res.status(401).json({ error: "Unauthorized" });
}

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;

  if (!backend || !token) {
    return res.status(500).json({ error: "Backend not configured" });
  }

  try {
    const response = await fetch(
      `${backend.replace(/\/$/, "")}/api/crustyspeaks/settings`,
      {
        method: req.method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        ...(req.method === "POST"
          ? {
              body: JSON.stringify({
                voicesEnabled: req.body?.voicesEnabled,
                commentVoices: req.body?.commentVoices,
                giftVoices: req.body?.giftVoices,
                discordUserId
              })
            }
          : {}),
        signal: AbortSignal.timeout(15000)
      }
    );

  const responseText = await response.text();

console.log("[CRUSTYSPEAKS SETTINGS BACKEND]", {
  status: response.status,
  contentType: response.headers.get("content-type"),
  responsePreview: responseText.slice(0, 300)
});

let data;

try {
  data = JSON.parse(responseText);
} catch {
  return res.status(502).json({
    error: "Settings backend returned HTML or invalid JSON",
    backendStatus: response.status
  });
}

return res.status(response.status).json(data);
  } catch (error) {
    console.error("[CRUSTYSPEAKS SETTINGS PROXY]", error);
    return res.status(502).json({ error: "Settings backend unavailable" });
  }
};
