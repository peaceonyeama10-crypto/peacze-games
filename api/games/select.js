import crypto from "node:crypto";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  if (req.headers.origin !== "https://peacze-games.vercel.app") {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;
  const secret = process.env.DAILY_CODE_SECRET;
  const approvedIds = (process.env.APPROVED_DISCORD_IDS || "")
    .split(",")
    .map(id => id.trim())
    .filter(Boolean);

  if (!backend || !token || !secret || approvedIds.length === 0) {
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
          const i = item.indexOf("=");
          return [
            item.slice(0, i),
            decodeURIComponent(item.slice(i + 1))
          ];
        })
    );

    const sessionCookie = cookies.peacze_session;
    const session = String(sessionCookie || "").split(".");

    if (session.length !== 2) {
      return res.status(401).json({
        error: "Log in with Discord first."
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
        error: "Invalid session. Log in again."
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
        error: "Session expired. Log in again."
      });
    }

    if (!approvedIds.includes(data.discordUserId)) {
      return res.status(403).json({
        error: "Your Discord account is not approved."
      });
    }

    const code = String(req.body?.code || "")
      .trim()
      .toUpperCase();

    const game = String(req.body?.game || "").trim();
    const allowedGames = ["racing", "jungle", "savecity"];

    if (!allowedGames.includes(game)) {
      return res.status(400).json({
        error: "Choose a valid game."
      });
    }

    if (!code) {
      return res.status(400).json({
        error: "Enter your daily access code."
      });
    }

    const verification = await fetch(
      `${backend}/api/access/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          Cookie: `peacze_session=${encodeURIComponent(sessionCookie)}`
        },
        body: JSON.stringify({
          code,
          discordUserId: data.discordUserId
        })
      }
    );

    const verificationData = await verification.json().catch(() => null);

    if (!verification.ok || verificationData?.valid !== true) {
      console.error(
        "Daily code verification rejected:",
        verification.status,
        verificationData?.error || "No backend error returned."
      );

      return res.status(401).json({
        error: verificationData?.error || "Invalid or expired daily code."
      });
    }

    const response = await fetch(
      `${backend}/api/creator/session`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          code,
          discordUserId: data.discordUserId,
          game
        })
      }
    );

    const resultData = await response.json().catch(() => null);

    if (!response.ok) {
      return res.status(response.status).json(
        resultData || {
          error: "Could not create creator session."
        }
      );
    }

    return res.status(201).json(resultData);
  } catch (error) {
    console.error(
      "Creator session proxy failed:",
      error.message
    );

    return res.status(502).json({
      error: "Could not reach the game backend."
    });
  }
}
