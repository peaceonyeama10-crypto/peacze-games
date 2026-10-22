import crypto from "node:crypto";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed.");
  }

  const clientId = process.env.DISCORD_CLIENT_ID;

  if (!clientId) {
    return res.status(500).send("Discord login is not configured.");
  }

  const state = crypto.randomBytes(32).toString("hex");

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Set-Cookie", [
    `discord_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord; Max-Age=600`
  ]);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "https://peacze-games.vercel.app/api/auth/discord/callback",
    response_type: "code",
    scope: "identify",
    state
  });

  return res.redirect(
    302,
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
}
