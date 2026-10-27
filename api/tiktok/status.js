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

  const session = String(cookies.peacze_session || "");
  const parts = session.split(".");

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

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      status: "error",
      message: "Method not allowed."
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
      status: "error",
      message: "TikTok status is not configured."
    });
  }

  const allowedOrigins = [
    "https://peacze-games.vercel.app",
    "https://peacze-games-git-main-peace-sever.vercel.app"
  ];

  const origin = req.headers.origin;

  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({
      status: "error",
      message: "Origin not allowed."
    });
  }

  const session = getSession(req, DAILY_CODE_SECRET);

  if (!session) {
    return res.status(401).json({
      status: "error",
      message: "Please log in with Discord first."
    });
  }

  const approvedIds = APPROVED_DISCORD_IDS
    .split(",")
    .map(id => id.trim())
    .filter(Boolean);

  if (!approvedIds.includes(session.discordUserId)) {
    return res.status(403).json({
      status: "error",
      message: "Your Discord account is not approved."
    });
  }

  try {
    const backendUrl =
      `${TIKTOK_BACKEND_URL.replace(/\/+$/, "")}` +
      `/api/tiktok/status?discordUserId=` +
      encodeURIComponent(session.discordUserId);

    const response = await fetch(backendUrl, {
      headers: {
        Authorization: `Bearer ${TIKTOK_QUEUE_TOKEN}`
      },
      cache: "no-store"
    });

    const body = await response.text();

    if (!response.ok) {
      console.error(
        "TikTok status backend error:",
        response.status,
        body
      );

      return res.status(502).json({
        status: "error",
        message: "Could not retrieve TikTok status from the backend."
      });
    }

    let data;

    try {
      data = JSON.parse(body);
    } catch {
      return res.status(502).json({
        status: "error",
        message: "The TikTok backend returned an invalid response."
      });
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error("TikTok status proxy failed:", error);

    return res.status(502).json({
      status: "error",
      message: "Could not contact the TikTok backend."
    });
  }
}
