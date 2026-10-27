import crypto from "node:crypto";

function getSession(req, secret) {
  const cookies = Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map(item => item.trim())
      .filter(Boolean)
      .map(item => {
        const index = item.indexOf("=");
        return [
          item.slice(0, index),
          decodeURIComponent(item.slice(index + 1))
        ];
      })
  );

  const parts = String(cookies.peacze_session || "").split(".");

  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest();

  let actual;

  try {
    actual = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      !/^\d{17,20}$/.test(String(data.discordUserId || "")) ||
      !Number.isFinite(data.expiresAt) ||
      data.expiresAt <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      error: "Method not allowed."
    });
  }

  const {
    TIKTOK_BACKEND_URL,
    TIKTOK_QUEUE_TOKEN,
    DAILY_CODE_SECRET,
    APPROVED_DISCORD_IDS
  } = process.env;

  if (
    !TIKTOK_BACKEND_URL ||
    !TIKTOK_QUEUE_TOKEN ||
    !DAILY_CODE_SECRET ||
    !APPROVED_DISCORD_IDS
  ) {
    return res.status(500).json({
      error: "TikTok disconnect is not configured."
    });
  }

  const allowedOrigins = [
    "https://peacze-games.vercel.app",
    "https://peacze-games-git-main-peace-sever.vercel.app"
  ];

  const origin = req.headers.origin;

  if (!origin || !allowedOrigins.includes(origin)) {
    return res.status(403).json({
      error: "Origin not allowed."
    });
  }

  const session = getSession(req, DAILY_CODE_SECRET);

  if (!session) {
    return res.status(401).json({
      error: "Please log in with Discord first."
    });
  }

  const approvedIds = APPROVED_DISCORD_IDS
    .split(",")
    .map(id => id.trim())
    .filter(Boolean);

  if (!approvedIds.includes(session.discordUserId)) {
    return res.status(403).json({
      error: "Your Discord account is not approved."
    });
  }

  try {
    const response = await fetch(
      `${TIKTOK_BACKEND_URL.replace(/\/+$/, "")}/api/tiktok/disconnect`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${TIKTOK_QUEUE_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          discordUserId: session.discordUserId
        })
      }
    );

    const body = await response.text();

    if (!response.ok) {
      console.error(
        "TikTok disconnect backend error:",
        response.status,
        body
      );

      return res.status(502).json({
        error: "The TikTok backend could not disconnect this creator."
      });
    }

    let data;

    try {
      data = JSON.parse(body);
    } catch {
      return res.status(502).json({
        error: "The TikTok backend returned an invalid response."
      });
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error("TikTok disconnect proxy failed:", error);

    return res.status(502).json({
      error: "Could not contact the TikTok backend."
    });
  }
}
