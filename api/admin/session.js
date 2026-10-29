const crypto = require("crypto");

const COOKIE_NAME = "crown_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;

function respond(res, status, data) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json(data);
}

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
}

module.exports = function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return respond(res, 405, { error: "Method not allowed." });
  }

  const origin = req.headers.origin;
  if (
    origin &&
    origin !== "https://peacze-games.vercel.app"
  ) {
    return respond(res, 403, { error: "Request not allowed." });
  }

  const secret = process.env.ADMIN_PASSCODE;
  if (!secret) {
    return respond(res, 500, {
      authorized: false,
      error: "Admin verification is not configured."
    });
  }

  const cookieHeader = req.headers.cookie || "";
  const cookiePart = cookieHeader
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(`${COOKIE_NAME}=`));

  if (!cookiePart) {
    return respond(res, 401, { authorized: false });
  }

  const value = cookiePart.slice(COOKIE_NAME.length + 1);
  const parts = value.split(".");

  if (parts.length !== 3) {
    return respond(res, 401, { authorized: false });
  }

  const [issuedAtText, nonce, suppliedSignature] = parts;
  const issuedAt = Number(issuedAtText);

  if (
    !Number.isSafeInteger(issuedAt) ||
    !/^[a-f0-9]{48}$/.test(nonce) ||
    !/^[a-f0-9]{64}$/.test(suppliedSignature)
  ) {
    return respond(res, 401, { authorized: false });
  }

  const now = Date.now();

  if (
    issuedAt > now + 30000 ||
    now - issuedAt >= SESSION_SECONDS * 1000
  ) {
    return respond(res, 401, { authorized: false });
  }

  const expectedSignature = sign(
    `${issuedAtText}.${nonce}`,
    secret
  );

  const supplied = Buffer.from(suppliedSignature, "hex");
  const expected = Buffer.from(expectedSignature, "hex");

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return respond(res, 401, { authorized: false });
  }

  return respond(res, 200, {
    authorized: true,
    expiresIn: Math.max(
      0,
      SESSION_SECONDS - Math.floor((now - issuedAt) / 1000)
    )
  });
};
