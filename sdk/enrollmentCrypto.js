// Browser consumers of the pure Keccak/EIP-191 recovery functions must not
// resolve a static Node builtin. Existing synchronous SHA-256 users remain
// Node-only and keep the exact same implementation and bytes.
const nodeCreateHash = globalThis.process?.versions?.node
  ? (await import("node:crypto")).createHash
  : null;

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;
const G = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
});
const MASK_64 = (1n << 64n) - 1n;

const KECCAK_ROTC = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

export function utf8Bytes(value) {
  return new TextEncoder().encode(String(value));
}

export function bytesToHex(bytes) {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function strip0x(hex) {
  return String(hex).startsWith("0x") ? String(hex).slice(2) : String(hex);
}

export function hexToBytes(hex, expectedBytes) {
  const raw = strip0x(hex);
  if (!/^[0-9a-fA-F]*$/.test(raw) || raw.length % 2 !== 0) throw new Error(`invalid hex: ${hex}`);
  if (expectedBytes !== undefined && raw.length !== expectedBytes * 2) {
    throw new Error(`invalid hex length: expected ${expectedBytes} bytes`);
  }
  const out = new Uint8Array(raw.length / 2);
  for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  return out;
}

export function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function mod(value, modulus = P) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function powMod(base, exponent, modulus) {
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }
  return result;
}

function invert(value, modulus) {
  const x = mod(value, modulus);
  if (x === 0n) throw new Error("cannot invert zero");
  return powMod(x, modulus - 2n, modulus);
}

function bytesToBigInt(bytes) {
  return BigInt(bytesToHex(bytes));
}

function bigintToBytes(value, length = 32) {
  let hex = value.toString(16);
  if (hex.length > length * 2) throw new Error("integer does not fit byte length");
  hex = hex.padStart(length * 2, "0");
  return hexToBytes(hex);
}

function normalizePrivateScalar(secretHex) {
  const d = BigInt(`0x${strip0x(secretHex)}`);
  if (d <= 0n || d >= N) throw new Error("invalid secp256k1 private key");
  return d;
}

function pointAdd(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x && mod(a.y + b.y) === 0n) return null;
  let slope;
  if (a.x === b.x && a.y === b.y) {
    slope = mod((3n * a.x * a.x) * invert(2n * a.y, P));
  } else {
    slope = mod((b.y - a.y) * invert(b.x - a.x, P));
  }
  const x = mod(slope * slope - a.x - b.x);
  const y = mod(slope * (a.x - x) - a.y);
  return { x, y };
}

function pointMultiply(scalar, point = G) {
  let n = mod(scalar, N);
  let result = null;
  let addend = point;
  while (n > 0n) {
    if (n & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    n >>= 1n;
  }
  return result;
}

function liftX(x, oddY = false) {
  if (x < 0n || x >= P) throw new Error("x coordinate outside field");
  const ySquared = mod(x * x * x + 7n);
  let y = powMod(ySquared, (P + 1n) >> 2n, P);
  if (mod(y * y) !== ySquared) throw new Error("x coordinate is not on secp256k1");
  if (Boolean(y & 1n) !== oddY) y = P - y;
  return { x, y };
}

function hasEvenY(point) {
  return (point.y & 1n) === 0n;
}

export function sha256Bytes(bytes) {
  if (!nodeCreateHash) throw new Error("sha256_sync_node_only");
  return new Uint8Array(nodeCreateHash("sha256").update(bytes).digest());
}

export function sha256Hex(bytes) {
  return bytesToHex(sha256Bytes(bytes));
}

function rotl64(value, shift) {
  const s = BigInt(shift);
  if (s === 0n) return value & MASK_64;
  return ((value << s) | (value >> (64n - s))) & MASK_64;
}

function keccakF1600(state) {
  for (const rc of KECCAK_RC) {
    const c = new Array(5).fill(0n);
    const d = new Array(5).fill(0n);
    for (let x = 0; x < 5; x += 1) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    for (let x = 0; x < 5; x += 1) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & MASK_64;
    }
    const b = new Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], KECCAK_ROTC[x + 5 * y]);
      }
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = (b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])) & MASK_64;
      }
    }
    state[0] = (state[0] ^ rc) & MASK_64;
  }
}

export function keccak256(bytes) {
  const rate = 136;
  const state = new Array(25).fill(0n);
  const padded = Array.from(bytes);
  padded.push(0x01);
  while (padded.length % rate !== rate - 1) padded.push(0x00);
  padded.push(0x80);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let index = 0; index < rate; index += 1) {
      const lane = Math.floor(index / 8);
      const shift = BigInt((index % 8) * 8);
      state[lane] ^= BigInt(padded[offset + index]) << shift;
      state[lane] &= MASK_64;
    }
    keccakF1600(state);
  }
  const out = new Uint8Array(32);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number((state[Math.floor(index / 8)] >> BigInt((index % 8) * 8)) & 0xffn);
  }
  return out;
}

export function keccak256Hex(bytes) {
  return bytesToHex(keccak256(bytes));
}

function taggedHash(tag, bytes) {
  const tagHash = sha256Bytes(utf8Bytes(tag));
  return sha256Bytes(concatBytes(tagHash, tagHash, bytes));
}

export function normalizePrivateKeyForXOnly(secretHex) {
  const original = normalizePrivateScalar(secretHex);
  const originalPoint = pointMultiply(original);
  const wasOdd = !hasEvenY(originalPoint);
  const normalized = wasOdd ? N - original : original;
  const normalizedPoint = pointMultiply(normalized);
  return {
    normalizedPrivateKeyHex: bytesToHex(bigintToBytes(normalized)),
    publicKeyXOnly: bytesToHex(bigintToBytes(normalizedPoint.x)),
    originalPublicKeyWasOdd: wasOdd,
  };
}

export function publicKeyFromPrivate(secretHex) {
  const point = pointMultiply(normalizePrivateScalar(secretHex));
  return {
    x: bytesToHex(bigintToBytes(point.x)),
    y: bytesToHex(bigintToBytes(point.y)),
    uncompressed: bytesToHex(concatBytes(bigintToBytes(point.x), bigintToBytes(point.y))),
  };
}

export function evmAddressFromPrivateKey(secretHex) {
  const pub = publicKeyFromPrivate(secretHex);
  const digest = keccak256(hexToBytes(pub.uncompressed, 64));
  return bytesToHex(digest.slice(12)).toLowerCase();
}

export function evmAddressFromXOnlyPubkey(pubkeyHex) {
  const point = liftX(BigInt(`0x${strip0x(pubkeyHex)}`), false);
  const digest = keccak256(concatBytes(bigintToBytes(point.x), bigintToBytes(point.y)));
  return bytesToHex(digest.slice(12)).toLowerCase();
}

export function schnorrSign(message32Hex, secretHex, auxBytes = new Uint8Array(32)) {
  const message = hexToBytes(message32Hex, 32);
  if (auxBytes.length !== 32) throw new Error("BIP340 aux data must be 32 bytes");
  let d = normalizePrivateScalar(secretHex);
  const point = pointMultiply(d);
  if (!hasEvenY(point)) d = N - d;
  const pubkey = bigintToBytes(pointMultiply(d).x);
  const t = bigintToBytes(d);
  const aux = taggedHash("BIP0340/aux", auxBytes);
  for (let index = 0; index < 32; index += 1) t[index] ^= aux[index];
  const k0 = bytesToBigInt(taggedHash("BIP0340/nonce", concatBytes(t, pubkey, message))) % N;
  if (k0 === 0n) throw new Error("invalid Schnorr nonce");
  const rPoint = pointMultiply(k0);
  const k = hasEvenY(rPoint) ? k0 : N - k0;
  const r = hasEvenY(rPoint) ? rPoint.x : pointMultiply(k).x;
  const e = bytesToBigInt(taggedHash("BIP0340/challenge", concatBytes(bigintToBytes(r), pubkey, message))) % N;
  const s = mod(k + e * d, N);
  return bytesToHex(concatBytes(bigintToBytes(r), bigintToBytes(s)));
}

export function schnorrVerify(message32Hex, pubkeyHex, signatureHex) {
  try {
    const message = hexToBytes(message32Hex, 32);
    const pubkey = hexToBytes(pubkeyHex, 32);
    const sig = hexToBytes(signatureHex, 64);
    const px = BigInt(`0x${strip0x(pubkeyHex)}`);
    const r = bytesToBigInt(sig.slice(0, 32));
    const s = bytesToBigInt(sig.slice(32, 64));
    if (px >= P || r >= P || s >= N) return false;
    const p = liftX(px, false);
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", concatBytes(bigintToBytes(r), pubkey, message))) % N;
    const rPoint = pointAdd(pointMultiply(s), pointMultiply(N - e, p));
    return rPoint !== null && hasEvenY(rPoint) && rPoint.x === r;
  } catch {
    return false;
  }
}

function personalSignDigest(message) {
  const body = utf8Bytes(message);
  const prefix = utf8Bytes(`\x19Ethereum Signed Message:\n${body.length}`);
  return keccak256(concatBytes(prefix, body));
}

function recoverAddressFromDigest(digest, r, s, recoveryId) {
  const x = r + BigInt(recoveryId >> 1) * N;
  if (x >= P) return null;
  let rPoint;
  try {
    rPoint = liftX(x, Boolean(recoveryId & 1));
  } catch {
    return null;
  }
  if (pointMultiply(N, rPoint) !== null) return null;
  const z = bytesToBigInt(digest) % N;
  const rInv = invert(r, N);
  const q = pointMultiply(rInv, pointAdd(pointMultiply(s, rPoint), pointMultiply(N - z, G)));
  if (q === null) return null;
  const publicBytes = concatBytes(bigintToBytes(q.x), bigintToBytes(q.y));
  return bytesToHex(keccak256(publicBytes).slice(12)).toLowerCase();
}

export function signEip191PersonalMessage(message, secretHex) {
  const d = normalizePrivateScalar(secretHex);
  const expectedAddress = evmAddressFromPrivateKey(secretHex);
  const digest = personalSignDigest(message);
  const z = bytesToBigInt(digest) % N;
  let counter = 0;
  while (counter < 1000) {
    const seed = concatBytes(utf8Bytes("BermLaunch deterministic ECDSA k v1"), bigintToBytes(d), digest, bigintToBytes(BigInt(counter)));
    const k = bytesToBigInt(sha256Bytes(seed)) % N;
    counter += 1;
    if (k === 0n) continue;
    const rPoint = pointMultiply(k);
    const r = rPoint.x % N;
    if (r === 0n) continue;
    let s = mod(invert(k, N) * (z + r * d), N);
    if (s === 0n) continue;
    if (s > HALF_N) s = N - s;
    for (let recoveryId = 0; recoveryId < 4; recoveryId += 1) {
      const recovered = recoverAddressFromDigest(digest, r, s, recoveryId);
      if (recovered === expectedAddress) {
        return bytesToHex(concatBytes(bigintToBytes(r), bigintToBytes(s), new Uint8Array([27 + recoveryId])));
      }
    }
  }
  throw new Error("could not produce recoverable deterministic signature");
}

export function recoverEip191PersonalMessageAddress(message, signatureHex) {
  const sig = hexToBytes(signatureHex, 65);
  const r = bytesToBigInt(sig.slice(0, 32));
  const s = bytesToBigInt(sig.slice(32, 64));
  let recoveryId = sig[64];
  if (recoveryId >= 27) recoveryId -= 27;
  if (recoveryId < 0 || recoveryId > 3 || r <= 0n || r >= N || s <= 0n || s >= N) throw new Error("invalid EIP-191 signature");
  const recovered = recoverAddressFromDigest(personalSignDigest(message), r, s, recoveryId);
  if (!recovered) throw new Error("could not recover EIP-191 signer");
  return recovered;
}

// The V02 wallet-first campaign authorization signs an exact 32-byte digest
// with EIP-191 personal_sign. This additive verifier does not alter enrollment
// signing or its human-readable personal-message format.
export function recoverEip191Bytes32Address(messageHashHex, signatureHex) {
  const messageHash = hexToBytes(messageHashHex, 32);
  const sig = hexToBytes(signatureHex, 65);
  const r = bytesToBigInt(sig.slice(0, 32));
  const s = bytesToBigInt(sig.slice(32, 64));
  let recoveryId = sig[64];
  if (recoveryId >= 27) recoveryId -= 27;
  if (recoveryId < 0 || recoveryId > 1 || r <= 0n || r >= N || s <= 0n || s > HALF_N) {
    throw new Error("invalid EIP-191 bytes32 signature");
  }
  const digest = keccak256(concatBytes(utf8Bytes("\x19Ethereum Signed Message:\n32"), messageHash));
  const recovered = recoverAddressFromDigest(digest, r, s, recoveryId);
  if (!recovered) throw new Error("could not recover EIP-191 bytes32 signer");
  return recovered;
}

export const secp256k1 = Object.freeze({ P, N });
