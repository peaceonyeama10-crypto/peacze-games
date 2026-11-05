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

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  if (req.headers.origin !== "https://crownnetwork.live") {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;
  const secret = process.env.DAILY_CODE_SECRET;

  if (!backend || !token || !secret) {
    return res.status(500).json({
      error: "Server configuration is missing."
    });
  }

  try {
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

    const session = String(cookies.peacze_session || "").split(".");
    if (session.length !== 2) {
      return res.status(401).json({
        error: "Please log in with Discord first."
      });
    }

    const [payload, signature] = session;
    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest();

    const actual = Buffer.from(signature, "base64url");

    if (
      actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)
    ) {
      return res.status(401).json({
        error: "Invalid session. Please log in again."
      });
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      !data.discordUserId ||
      !Number.isFinite(data.expiresAt) ||
      data.expiresAt <= Math.floor(Date.now() / 1000)
    ) {
      return res.status(401).json({
        error: "Your session expired. Please log in again."
      });
    }

    if (!(await isApprovedCreator(data.discordUserId))) {
      return res.status(403).json({
        error: "Your Discord account is not approved."
      });
    }

    const code = String(req.body?.code || "").trim().toUpperCase();
    const username = req.body?.username;

    if (!code) {
      return res.status(400).json({
        error: "Enter your daily access code."
      });
    }

    const verification = await fetch(`${backend}/api/access/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
  code,
  discordUserId: data.discordUserId
})
    });

    const verificationText = await verification.text();
    let verificationData;

    try {
      verificationData = JSON.parse(verificationText);
    } catch {
      return res.status(502).json({
        error: "Access verification returned an invalid response."
      });
    }

    if (!verification.ok || verificationData.valid !== true) {
      return res.status(401).json({
        error: verificationData.error || "Invalid or expired daily code."
      });
    }

    const response = await fetch(`${backend}/api/tiktok/connect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        username,
        code,
        discordUserId: data.discordUserId
      })
    });

    const text = await response.text();

    try {
      return res.status(response.status).json(JSON.parse(text));
    } catch {
      console.error(
        "TikTok backend returned non-JSON:",
        response.status,
        text.slice(0, 300)
      );

      return res.status(502).json({
        error: "TikTok backend returned a non-JSON response.",
        backendStatus: response.status
      });
    }
  } catch (error) {
    console.error("TikTok connect proxy failed:", error.message);

    return res.status(502).json({
      error: "Could not reach the TikTok backend."
    });
  }
}
