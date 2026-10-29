function respond(res, status, data) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json(data);
}

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return respond(res, 405, {
      error: "Method not allowed."
    });
  }

  if (
    req.headers.origin !==
    "https://peacze-games.vercel.app"
  ) {
    return respond(res, 403, {
      error: "Request not allowed."
    });
  }

  res.setHeader(
    "Set-Cookie",
    "crown_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
  );

  return respond(res, 200, {
    success: true,
    message: "Admin session ended."
  });
};
