export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  if (req.headers.origin !== "https://peacze-games.vercel.app") {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;

  if (!backend || !token) {
    return res.status(500).json({
      error: "Server configuration is missing."
    });
  }

  const code = String(req.body?.code || "").trim().toUpperCase();
  const username = req.body?.username;

  if (!code) {
    return res.status(400).json({
      error: "Enter your daily access code."
    });
  }

  try {
    const verification = await fetch(
      `${backend}/api/access/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ code })
      }
    );

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
      body: JSON.stringify({ username, code })
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
