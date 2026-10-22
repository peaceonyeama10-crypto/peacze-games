export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  return res.status(501).json({
    error: "Discord login setup is not finished yet."
  });
}
