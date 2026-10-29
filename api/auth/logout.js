export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      error: "Method not allowed."
    });
  }

  const allowedOrigins = [
    "https://peacze-games.vercel.app",
    "https://peacze-games-git-main-peace-sever.vercel.app"
  ];

  if (!allowedOrigins.includes(req.headers.origin)) {
    return res.status(403).json({
      error: "Origin not allowed."
    });
  }

  res.setHeader("Set-Cookie", [
    "peacze_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  ]);

  return res.status(200).json({
    success: true,
    message: "You have been logged out."
  });
}
