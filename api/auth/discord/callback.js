import crypto from "node:crypto";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed.");
  }

  const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DAILY_CODE_SECRET,
    APPROVED_DISCORD_IDS
  } = process.env;

  if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DAILY_CODE_SECRET ||
    !APPROVED_DISCORD_IDS
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
        return [
          item.slice(0, index),
          decodeURIComponent(item.slice(index + 1))
        ];
      })
  );

  const expectedState = cookies.discord_oauth_state;

  res.setHeader("Set-Cookie",
    "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=0"
  );

  if (error || !code || !state || !expectedState) {
    return res.status(400).send("Discord login was cancelled or failed.");
  }

  const a = Buffer.from(String(state));
  const b = Buffer.from(String(expectedState));

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
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
      return res.status(401).send("Discord login failed. Please try again.");
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
      return res.status(401).send("Could not verify your Discord account.");
    }

    const user = await userResponse.json();
    console.log("Discord approval diagnostic:", {
  userIdLast4: user.id.slice(-4),
  approvedCount: approvedIds.length,
  matched: approvedIds.includes(user.id),
  approvedIdLast4: approvedIds.map(id => id.slice(-4))
});
    const approvedIds = APPROVED_DISCORD_IDS
      .split(",")
      .map(id => id.trim())
      .filter(Boolean);

    if (!approvedIds.includes(user.id)) {
      return res.status(403).send(
        "Your Discord account has not been approved for Peacze Games."
      );
    }

    const expiresAt = Math.floor(Date.now() / 1000) + 12 * 60 * 60;

    const payload = Buffer.from(
      JSON.stringify({ discordUserId: user.id, expiresAt })
    ).toString("base64url");

    const signature = crypto
      .createHmac("sha256", DAILY_CODE_SECRET)
      .update(payload)
      .digest("base64url");

    res.setHeader("Set-Cookie", [
      "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=0",
      `peacze_session=${payload}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${12 * 60 * 60}`
    ]);

    return res.redirect(302, "/");
  } catch (err) {
    console.error("Discord OAuth callback failed:", err);
    return res.status(500).send("Login failed. Please try again.");
  }
}
