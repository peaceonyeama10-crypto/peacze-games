import crypto from "node:crypto";

// ===== APPROVAL FROM THE ADMIN DASHBOARD =====
// A creator is approved when their record in admin-dashboard.html is ACTIVE:
// access not revoked, start date reached, and not expired.
// Same rules as statusFor() in admin-dashboard.html.
// Results are remembered for 60 seconds so the backend isn't asked on every poll.
const approvalCache = new Map();
const APPROVAL_CACHE_MS = 60 * 1000;

function torontoToday() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Toronto",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map(({ type, value }) => [type, value])
  );

  return `${values.year}-${values.month}-${values.day}`;
}

async function isApprovedCreator(discordUserId) {
  const id = String(discordUserId || "").trim();
  const backend = (process.env.TIKTOK_BACKEND_URL || "").replace(/\/+$/, "");
  const secret = process.env.CREATOR_ADMIN_API_SECRET;

  if (!backend || !secret || !/^\d{17,20}$/.test(id)) return false;

  const cached = approvalCache.get(id);
  if (cached && Date.now() - cached.at < APPROVAL_CACHE_MS) {
    return cached.approved;
  }

  let approved = false;

  try {
    const response = await fetch(
      `${backend}/api/admin/creators/${encodeURIComponent(id)}`,
      {
        headers: {
          Authorization: `Bearer ${secret}`,
          Accept: "application/json"
        },
        cache: "no-store",
        signal: AbortSignal.timeout(10000)
      }
    );

    if (response.ok) {
      const data = await response.json().catch(() => null);
      const creator = data && data.creator;

      if (creator && creator.accessStatus === "active") {
        const today = torontoToday();
        const start = creator.startsAt ? String(creator.startsAt).slice(0, 10) : "";
        const expiry = creator.expiresOn ? String(creator.expiresOn).slice(0, 10) : "";

        approved = !(start && start > today) && !(expiry && expiry < today);
      }
    } else if (response.status !== 404) {
      // Backend problem: don't remember this answer, try again next time.
      console.error("[APPROVAL] Creator lookup failed:", response.status);
      return false;
    }
  } catch (error) {
    console.error("[APPROVAL] Creator lookup error:", error.message);
    return false;
  }

  approvalCache.set(id, { approved, at: Date.now() });
  return approved;
}

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
    DAILY_CODE_SECRET
  } = process.env;

  if (
    !TIKTOK_BACKEND_URL ||
    !TIKTOK_QUEUE_TOKEN ||
    !DAILY_CODE_SECRET
  ) {
    return res.status(500).json({
      error: "TikTok disconnect is not configured."
    });
  }

  const allowedOrigins = [
    "https://crownnetwork.live"
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

  if (!(await isApprovedCreator(session.discordUserId))) {
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
