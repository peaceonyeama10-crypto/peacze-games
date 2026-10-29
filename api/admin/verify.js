const crypto = require("crypto");

const COOKIE_NAME = "crown_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;

function respond(res, status, data) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json(data);
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
}

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return respond(res, 405, { error: "Method not allowed." });
  }

  const origin = req.headers.origin;
  if (origin !== "https://peacze-games.vercel.app") {
    return respond(res, 403, { error: "Request not allowed." });
  }

  const passcode = process.env.ADMIN_PASSCODE;
  if (!passcode) {
    return respond(res, 500, {
      error: "Admin passcode is not configured."
    });
  }

  const code = req.body?.code;
  if (
    typeof code !== "string" ||
    code.length > 200 ||
    !safeEqual(code, passcode)
  ) {
    return respond(res, 401, {
      error: "Invalid admin passcode."
    });
  }

  const payload =
    `${Date.now()}.${crypto.randomBytes(24).toString("hex")}`;
  const signature = sign(payload, passcode);
  const cookie = `${payload}.${signature}`;

  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`
  );

  return respond(res, 200, {
    authorized: true,
    expiresIn: SESSION_SECONDS
  });
};
