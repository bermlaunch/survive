const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
});

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_MAP = new Map(Array.from(BECH32_CHARSET, (char, index) => [char, index]));

export function utf8Bytes(value) {
  return new TextEncoder().encode(String(value));
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(value, expectedBytes) {
  const hex = String(value).replace(/^0x/i, "");
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) throw new Error("invalid_hex");
  if (expectedBytes !== undefined && hex.length !== expectedBytes * 2) throw new Error(`invalid_hex_length:${expectedBytes}`);
  return Uint8Array.from(hex.match(/.{2}/g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

export function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export async function sha256Bytes(bytes) {
  if (!globalThis.crypto?.subtle) throw new Error("webcrypto_sha256_unavailable");
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Hex(value) {
  const bytes = value instanceof Uint8Array ? value : utf8Bytes(value);
  return bytesToHex(await sha256Bytes(bytes));
}

function mod(value, modulus = P) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function powMod(base, exponent, modulus) {
  let result = 1n;
  let factor = mod(base, modulus);
  for (let power = exponent; power > 0n; power >>= 1n) {
    if (power & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
  }
  return result;
}

function invert(value, modulus) {
  const normalized = mod(value, modulus);
  if (normalized === 0n) throw new Error("inverse_of_zero");
  return powMod(normalized, modulus - 2n, modulus);
}

function pointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x && mod(left.y + right.y) === 0n) return null;
  const slope = left.x === right.x && left.y === right.y
    ? mod(3n * left.x * left.x * invert(2n * left.y, P))
    : mod((right.y - left.y) * invert(right.x - left.x, P));
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
}

function pointMultiply(scalar, point = G) {
  let value = mod(scalar, N);
  let result = null;
  let addend = point;
  while (value > 0n) {
    if (value & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    value >>= 1n;
  }
  return result;
}

function liftX(x) {
  if (x < 0n || x >= P) throw new Error("x_coordinate_outside_curve");
  const squared = mod(x * x * x + 7n);
  let y = powMod(squared, (P + 1n) >> 2n, P);
  if (mod(y * y) !== squared) throw new Error("x_coordinate_not_on_curve");
  if (y & 1n) y = P - y;
  return { x, y };
}

function bigintBytes(value, length = 32) {
  const hex = value.toString(16).padStart(length * 2, "0");
  if (hex.length !== length * 2) throw new Error("integer_byte_length_overflow");
  return hexToBytes(hex, length);
}

function bytesBigint(bytes) {
  return BigInt(`0x${bytesToHex(bytes) || "0"}`);
}

async function taggedHash(tag, bytes) {
  const tagHash = await sha256Bytes(utf8Bytes(tag));
  return sha256Bytes(concatBytes(tagHash, tagHash, bytes));
}

export async function schnorrVerify(messageHex, pubkeyHex, signatureHex) {
  try {
    const message = hexToBytes(messageHex, 32);
    const pubkey = hexToBytes(pubkeyHex, 32);
    const signature = hexToBytes(signatureHex, 64);
    const px = bytesBigint(pubkey);
    const r = bytesBigint(signature.slice(0, 32));
    const s = bytesBigint(signature.slice(32));
    if (px >= P || r >= P || s >= N) return false;
    const point = liftX(px);
    const challenge = bytesBigint(await taggedHash("BIP0340/challenge", concatBytes(bigintBytes(r), pubkey, message))) % N;
    const reconstructed = pointAdd(pointMultiply(s), pointMultiply(N - challenge, point));
    return reconstructed !== null && (reconstructed.y & 1n) === 0n && reconstructed.x === r;
  } catch {
    return false;
  }
}

async function schnorrSign(messageHex, secretBytes) {
  const message = hexToBytes(messageHex, 32);
  let secret = bytesBigint(secretBytes);
  if (secret <= 0n || secret >= N) throw new Error("invalid_ephemeral_secret");
  const originalPoint = pointMultiply(secret);
  if (originalPoint.y & 1n) secret = N - secret;
  const publicKey = bigintBytes(pointMultiply(secret).x);
  const auxiliary = await sha256Bytes(concatBytes(utf8Bytes("bermlaunch-ephemeral-signer-r1"), secretBytes, message));
  const masked = bigintBytes(secret);
  const auxHash = await taggedHash("BIP0340/aux", auxiliary);
  for (let index = 0; index < 32; index += 1) masked[index] ^= auxHash[index];
  let nonce = bytesBigint(await taggedHash("BIP0340/nonce", concatBytes(masked, publicKey, message))) % N;
  if (nonce === 0n) throw new Error("invalid_ephemeral_nonce");
  let noncePoint = pointMultiply(nonce);
  if (noncePoint.y & 1n) {
    nonce = N - nonce;
    noncePoint = pointMultiply(nonce);
  }
  const challenge = bytesBigint(await taggedHash("BIP0340/challenge", concatBytes(bigintBytes(noncePoint.x), publicKey, message))) % N;
  return bytesToHex(concatBytes(bigintBytes(noncePoint.x), bigintBytes(mod(nonce + challenge * secret, N))));
}

export function createEphemeralNostrSigner(randomSource = globalThis.crypto) {
  if (!randomSource?.getRandomValues) throw new Error("secure_random_unavailable");
  let secretBytes;
  let scalar = 0n;
  do {
    secretBytes = randomSource.getRandomValues(new Uint8Array(32));
    scalar = bytesBigint(secretBytes);
  } while (scalar <= 0n || scalar >= N);
  const point = pointMultiply(scalar);
  const normalized = point.y & 1n ? N - scalar : scalar;
  const normalizedSecret = bigintBytes(normalized);
  const normalizedPoint = pointMultiply(normalized);
  if (!normalizedPoint) throw new Error("invalid_ephemeral_public_key");
  const publicKey = bytesToHex(bigintBytes(normalizedPoint.x));
  return Object.freeze({
    publicKey,
    async signEvent(unsignedEvent) {
      const id = await nostrEventId(unsignedEvent);
      const sig = await schnorrSign(id, normalizedSecret);
      return { ...unsignedEvent, id, sig };
    },
  });
}

export async function nostrEventId(event) {
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return sha256Hex(serialized);
}

export async function verifyNostrEvent(event) {
  if (!event || !/^[0-9a-f]{64}$/.test(String(event.pubkey ?? ""))) return false;
  if (!/^[0-9a-f]{64}$/.test(String(event.id ?? "")) || !/^[0-9a-f]{128}$/.test(String(event.sig ?? ""))) return false;
  if (!Number.isSafeInteger(event.created_at) || !Number.isSafeInteger(event.kind) || !Array.isArray(event.tags) || typeof event.content !== "string") return false;
  const id = await nostrEventId(event);
  return id === event.id && schnorrVerify(id, event.pubkey, event.sig);
}

function bech32Polymod(values) {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) if ((top >>> index) & 1) checksum ^= generators[index];
  }
  return checksum >>> 0;
}

function bech32HrpExpand(hrp) {
  return [...Array.from(hrp, (char) => char.charCodeAt(0) >>> 5), 0, ...Array.from(hrp, (char) => char.charCodeAt(0) & 31)];
}

function convertBits(values, fromBits, toBits, pad) {
  let accumulator = 0;
  let bits = 0;
  const output = [];
  const maxValue = (1 << toBits) - 1;
  for (const value of values) {
    if (value < 0 || value >>> fromBits !== 0) throw new Error("bech32_value_out_of_range");
    accumulator = (accumulator << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      output.push((accumulator >>> bits) & maxValue);
    }
  }
  if (pad && bits > 0) output.push((accumulator << (toBits - bits)) & maxValue);
  if (!pad && (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue) !== 0)) throw new Error("bech32_noncanonical_padding");
  return output;
}

export function decodeNpub(npub) {
  const value = String(npub ?? "");
  if (value !== value.toLowerCase() && value !== value.toUpperCase()) throw new Error("npub_mixed_case");
  const normalized = value.toLowerCase();
  const separator = normalized.lastIndexOf("1");
  if (separator < 1 || separator + 7 > normalized.length || normalized.length > 90) throw new Error("npub_bech32_shape");
  const hrp = normalized.slice(0, separator);
  if (hrp !== "npub") throw new Error("npub_hrp");
  const words = Array.from(normalized.slice(separator + 1), (char) => {
    const mapped = BECH32_MAP.get(char);
    if (mapped === undefined) throw new Error("npub_bech32_character");
    return mapped;
  });
  if (bech32Polymod([...bech32HrpExpand(hrp), ...words]) !== 1) throw new Error("npub_checksum");
  const decoded = Uint8Array.from(convertBits(words.slice(0, -6), 5, 8, false));
  if (decoded.length !== 32) throw new Error("npub_payload_length");
  return { npub: normalized, pubkeyHex: bytesToHex(decoded), bytes: decoded };
}

export function encodeNpub(pubkeyHex) {
  const words = convertBits(hexToBytes(pubkeyHex, 32), 8, 5, true);
  const values = [...bech32HrpExpand("npub"), ...words, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, index) => (polymod >>> (5 * (5 - index))) & 31);
  return `npub1${[...words, ...checksum].map((word) => BECH32_CHARSET[word]).join("")}`;
}

export const secp256k1 = Object.freeze({ P, N });
