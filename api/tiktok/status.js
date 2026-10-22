export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed." });
  }

 const allowedOrigins = [
  "https://peacze-games.vercel.app",
  "https://peacze-games-git-main-peace-sever.vercel.app"
];

const origin = req.headers.origin;

if (origin && !allowedOrigins.includes(origin)) {
  return res.status(403).json({ error: "Origin not allowed." });
}
  const backend = process.env.TIKTOK_BACKEND_URL;
  const token = process.env.TIKTOK_QUEUE_TOKEN;

  if (!backend || !token) {
    return res.status(500).json({ error: "Server configuration is missing." });
  }

  try {
    const response = await fetch(`${backend}/api/tiktok/status`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    return res.status(response.status).json(await response.json());
  } catch (error) {
    console.error("TikTok status proxy failed:", error.message);
    return res.status(502).json({
      error: "Could not reach the TikTok backend.",
      details: error.message
    });
  }
}
