import crypto from "node:crypto";

function getDailyCode(userId, secret) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Toronto",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map(({ type, value }) => [type, value])
  );

  const day = `${values.year}-${values.month}-${values.day}`;

  return crypto
    .createHmac("sha256", secret)
    .update(`${day}:${userId}`)
    .digest("hex")
    .slice(0, 6)
    .toUpperCase();
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      valid: false,
      error: "Method not allowed."
    });
  }

  const secret = process.env.DAILY_CODE_SECRET;
  const approvedIds = (process.env.APPROVED_DISCORD_IDS || "")
    .split(",")
    .map(id => id.trim())
    .filter(Boolean);

  if (!secret || approvedIds.length === 0) {
    return res.status(500).json({
      valid: false,
      error: "Access verification is not configured."
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
        valid: false,
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
        valid: false,
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
        valid: false,
        error: "Your session expired. Please log in again."
      });
    }

    if (!approvedIds.includes(data.discordUserId)) {
      return res.status(403).json({
        valid: false,
        error: "Your Discord account is not approved."
      });
    }

    const submittedCode = String(req.body?.code || "")
      .trim()
      .toUpperCase();

    const expectedCode = getDailyCode(data.discordUserId, secret);

    if (
      submittedCode.length !== expectedCode.length ||
      !crypto.timingSafeEqual(
        Buffer.from(submittedCode),
        Buffer.from(expectedCode)
      )
    ) {
      return res.status(401).json({
        valid: false,
        error: "Invalid or expired daily code."
      });
    }

    return res.status(200).json({
      valid: true,
      message: "Daily access code verified."
    });
  } catch (error) {
    console.error("Access verification failed:", error);
    return res.status(400).json({
      valid: false,
      error: "Could not verify access."
    });
  }
}
