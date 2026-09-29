import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";
import { parseServiceAccountKey, serviceAccountAssertion } from "../src/gcal";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const KEY = {
  clientEmail: "robot@project.iam.gserviceaccount.com",
  privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};

function decode(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

test("the assertion is an RS256 JWT for the token endpoint, signed with the key", () => {
  const now = Date.UTC(2026, 8, 29, 12, 0, 0);
  const [header = "", claims = "", signature = ""] = serviceAccountAssertion(KEY, now).split(".");

  assert.deepEqual(decode(header), { alg: "RS256", typ: "JWT" });
  assert.deepEqual(decode(claims), {
    iss: KEY.clientEmail,
    scope: "https://www.googleapis.com/auth/calendar",
    aud: "https://oauth2.googleapis.com/token",
    iat: now / 1000,
    exp: now / 1000 + 3600,
  });
  assert.ok(
    verify(
      "RSA-SHA256",
      Buffer.from(`${header}.${claims}`),
      publicKey,
      Buffer.from(signature, "base64url"),
    ),
  );
});

test("a downloaded key file is read, and anything else is refused", () => {
  const json = JSON.stringify({
    type: "service_account",
    client_email: KEY.clientEmail,
    private_key: KEY.privateKey,
  });
  assert.deepEqual(parseServiceAccountKey(json), KEY);
  assert.throws(() => parseServiceAccountKey("{"), /not valid JSON/);
  assert.throws(
    () => parseServiceAccountKey(JSON.stringify({ type: "authorized_user" })),
    /not a Google service-account key/,
  );
});
