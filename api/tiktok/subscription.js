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

function plainDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)
    ? value
    : null;
}

// GET: returns ONLY the logged-in creator's own subscription dates.
// The Discord ID always comes from the signed session cookie, never from the URL.
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
    CREATOR_ADMIN_API_SECRET,
    DAILY_CODE_SECRET
  } = process.env;

  if (!TIKTOK_BACKEND_URL || !CREATOR_ADMIN_API_SECRET || !DAILY_CODE_SECRET) {
    return res.status(500).json({
      status: "error",
      message: "Subscription lookup is not configured."
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

  try {
    const url =
      `${TIKTOK_BACKEND_URL.replace(/\/+$/, "")}` +
      `/api/admin/creators/${encodeURIComponent(session.discordUserId)}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${CREATOR_ADMIN_API_SECRET}`,
        Accept: "application/json"
      },
      cache: "no-store",
      signal: AbortSignal.timeout(15000)
    });

    const body = await response.text();

    if (response.status === 404) {
      return res.status(404).json({
        status: "error",
        message: "No subscription record was found for your account."
      });
    }

    if (!response.ok) {
      console.error(
        "Subscription backend error:",
        response.status,
        body.slice(0, 300)
      );

      return res.status(502).json({
        status: "error",
        message: "Could not retrieve your subscription from the backend."
      });
    }

    let data;

    try {
      data = JSON.parse(body);
    } catch {
      return res.status(502).json({
        status: "error",
        message: "The backend returned an invalid response."
      });
    }

    const creator = data && data.creator;

    if (!creator || typeof creator !== "object") {
      return res.status(502).json({
        status: "error",
        message: "The backend returned an unexpected response."
      });
    }

    // Only the fields a creator needs. Nothing else is passed through.
    return res.status(200).json({
      status: "ok",
      subscription: {
        plan: String(creator.plan || ""),
        startsAt: plainDate(creator.startsAt),
        expiresOn: plainDate(creator.expiresOn),
        accessStatus: creator.accessStatus === "active" ? "active" : "revoked"
      }
    });
  } catch (error) {
    console.error("Subscription proxy failed:", error.message);

    return res.status(502).json({
      status: "error",
      message: "Could not contact the subscription service."
    });
  }
}
