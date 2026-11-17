import crypto from "node:crypto";

// HMAC-SHA256 hex over the RAW body. Header: x-agent-games-signature: <hmac-sha256-hex>
// (format confirmed from the official Build guide starter prompt).
export function signBody(rawBody, secret) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

export function verifySignature(rawBody, headerValue, secret) {
  if (!headerValue || !secret) return false;
  const provided = String(headerValue).trim().replace(/^sha256=/i, "");
  const expected = signBody(rawBody, secret);
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
