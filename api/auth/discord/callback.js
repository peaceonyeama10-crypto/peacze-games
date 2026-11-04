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

const SESSION_SECONDS = 30 * 24 * 60 * 60;

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed.");
  }

  const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DAILY_CODE_SECRET
  } = process.env;

  if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DAILY_CODE_SECRET
  ) {
    return res.status(500).send("Discord login is not configured.");
  }

  const { code, state, error } = req.query || {};

  const cookies = Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map(item => item.trim())
      .filter(Boolean)
      .map(item => {
        const index = item.indexOf("=");
        if (index < 0) return [item, ""];

        return [
          item.slice(0, index),
          decodeURIComponent(item.slice(index + 1))
        ];
      })
  );

  const expectedState = cookies.discord_oauth_state;

  if (error || !code || !state || !expectedState) {
    res.setHeader("Set-Cookie",
      "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=0"
    );
    return res.status(400).send(
      "Discord login was cancelled or failed. Please try again."
    );
  }

  const a = Buffer.from(String(state));
  const b = Buffer.from(String(expectedState));

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.setHeader("Set-Cookie",
      "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=0"
    );
    return res.status(400).send("Invalid login state. Please try again.");
  }

  try {
    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code: String(code),
          redirect_uri:
            "https://peacze-games.vercel.app/api/auth/discord/callback"
        })
      }
    );

    if (!tokenResponse.ok) {
      return res.status(401).send(
        "Discord login failed. Please try again."
      );
    }

    const tokenData = await tokenResponse.json();

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`
        }
      }
    );

    if (!userResponse.ok) {
      return res.status(401).send(
        "Could not verify your Discord account."
      );
    }

    const user = await userResponse.json();

    const approved = await isApprovedCreator(user.id);

    console.log("Approval diagnostic:", {
      discordIdLast4: String(user.id || "").slice(-4),
      matched: approved
    });

    if (!approved) {
      return res.status(403).send(
        "Your Discord account has not been approved for Peacze Games."
      );
    }

    const expiresAt =
      Math.floor(Date.now() / 1000) + SESSION_SECONDS;

    const payload = Buffer.from(
      JSON.stringify({
        discordUserId: user.id,
        expiresAt
      })
    ).toString("base64url");

    const signature = crypto
      .createHmac("sha256", DAILY_CODE_SECRET)
      .update(payload)
      .digest("base64url");

    res.setHeader("Set-Cookie", [
      "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=0",
      `peacze_session=${payload}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}`
    ]);

    res.redirect("/games.html");
  } catch (err) {
    console.error("Discord OAuth callback failed:", err);
    return res.status(500).send("Login failed. Please try again.");
  }
}
