export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  const origin = req.headers.origin;
  if (origin !== "https://peacze-games.vercel.app") {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;

  if (!backend || !token) {
    return res.status(500).json({
      error: "Server configuration is missing."
    });
  }

  try {
    const response = await fetch(`${backend}/api/tiktok/connect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("TikTok connect proxy failed:", error.message);

    return res.status(502).json({
      error: "Could not reach the TikTok backend.",
      details: error.message
    });
  }
}
