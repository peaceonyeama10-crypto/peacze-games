export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  res.setHeader("Cache-Control", "no-store");

  return res.status(401).json({
    valid: false,
    error: "Discord login verification is not configured yet."
  });
}
