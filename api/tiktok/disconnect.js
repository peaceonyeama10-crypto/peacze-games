export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  const allowedOrigins = [
    "https://peacze-games.vercel.app",
    "https://peacze-games-git-main-peace-sever.vercel.app"
  ];

  const origin = req.headers.origin;

  if (!origin || !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const discordUserId = String(req.body?.discordUserId || "").trim();

  if (!/^\d{17,20}$/.test(discordUserId)) {
    return res.status(400).json({
      error: "A valid creator account is required."
    });
  }

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;

  if (!backend || !token) {
    return res.status(500).json({
      error: "Server configuration is missing."
    });
  }

  try {
    const response = await fetch(
      `${backend.replace(/\/+$/, "")}/api/tiktok/disconnect`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ discordUserId })
      }
    );

    return res.status(response.status).json(await response.json());
  } catch (error) {
    console.error("TikTok disconnect proxy failed:", error.message);
    return res.status(502).json({
      error: "Could not reach the TikTok backend."
    });
  }
}
