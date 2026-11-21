import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function sha256Buffer(input: string): Buffer {
  return createHash("sha256").update(input, "utf8").digest();
}

export function timingSafeEqualStrings(a: string, b: string): boolean {
  const digestA = sha256Buffer(a);
  const digestB = sha256Buffer(b);
  return timingSafeEqual(digestA, digestB);
}

export function generateRandomToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

export function generateApprovalCode(): string {
  const raw = randomBytes(6).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

export function computePkceS256(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyPkceS256(verifier: string, expectedChallenge: string): boolean {
  if (verifier.length < 43 || verifier.length > 128) {
    return false;
  }
  const computed = computePkceS256(verifier);
  return timingSafeEqualStrings(computed, expectedChallenge);
}
