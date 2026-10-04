import { decodeNpub, sha256Hex, utf8Bytes } from "./identityCrypto.js";
import { R13aStrictJsonError, strictParseR13aJsonBytes } from "./r13aStrictJson.js";

export const BERM_R13A_METHOD_ID = "berm.external_account_binding.x/2";
export const BERM_R13A_METHOD_HASH = "sha256:a95319d8664b16ca355b3d82bc8c4d5bb6007c8aed65116a74447f79b0e5e193";
export const BERM_R13A_ACQUISITION_ID = "berm.acquisition.x-direct-status/1";
export const BERM_R13A_ACQUISITION_HASH = "sha256:46fbed235696decc92e298e55e3a4ee1ebd5e61d169cd3462265cb3ff5c98f1d";
export const BERM_R13A_VECTOR_SET_HASH = "sha256:0ced853da13b3378b4e138883398ecd7831e27b00c2f03ee759af9668a45e6c5";
export const BERM_R13A_GENERIC_BINDING_ID = "berm.external_account_binding/1";
export const BERM_R13A_GENERIC_BINDING_HASH = "sha256:6a8585232f8c9feaac62310e6414edc476f5c9d13c1a2537e43e812decab0862";
export const BERM_R13A_COMPOSER_ID = "berm.composer_producer_law/2";
export const BERM_R13A_COMPOSER_HASH = "sha256:ed9e25056cbdec7d14fa568a731513eef5255c5febed061573afee4db1143aaa";
export const BERM_R13A_WINDOW_MS = 300_000;
export const BERM_R13A_MAX_RESPONSE_BYTES = 1_048_576;
export const BERM_R13A_UINT64_MAX = 18_446_744_073_709_551_615n;
export const BERM_R13A_PROTOCOL_ID_RE = /^berm\.[a-z](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z](?:[a-z0-9_-]*[a-z0-9])?)*\/[1-9][0-9]*$/;
export const BERM_R13A_POSITIVE_UINT64_RE = /^[1-9][0-9]{0,19}$/;

const FIRST_SNOWFLAKE_ID = 29_700_859_247n;
const X_EPOCH_MS = 1_288_834_974_657n;
const HANDLE_RE = /^[A-Za-z0-9_]{1,15}$/;
const BINDING_FIELDS = Object.freeze(["npub", "accountId", "handle", "postId", "textHash", "methodHash"]);
const CAPTURE_FIELDS = Object.freeze(["body", "redirects", "status"]);

const failure = (code) => ({ ok: false, code });

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function isCanonicalPositiveUint64Decimal(value) {
  return typeof value === "string"
    && BERM_R13A_POSITIVE_UINT64_RE.test(value)
    && BigInt(value) <= BERM_R13A_UINT64_MAX;
}

export function isCanonicalR13aNpub(value) {
  if (typeof value !== "string" || value !== value.toLowerCase()) return false;
  try {
    return decodeNpub(value).npub === value;
  } catch {
    return false;
  }
}

function captureShapeValid(capture) {
  if (!isPlainObject(capture)) return false;
  const keys = Object.keys(capture).sort();
  if (keys.length !== CAPTURE_FIELDS.length || !CAPTURE_FIELDS.every((field, index) => field === keys[index])) return false;
  if (!Number.isSafeInteger(capture.status)) return false;
  if (!Number.isSafeInteger(capture.redirects) || capture.redirects < 0) return false;
  return capture.body instanceof Uint8Array;
}

function own(owner, key) {
  return owner !== null && typeof owner === "object" && Object.hasOwn(owner, key);
}

export function r13aTextLines(text) {
  return text.split("\n");
}

const R13A_PROOF_LINE_RE = /^Berm Protocol: @[a-z0-9_]{1,15} permanently binds to npub1[02-9ac-hj-np-z]{58} #bermprotocol$/;

export function asciiLower(value) {
  return value.replace(/[A-Z]/g, (character) => String.fromCharCode(character.charCodeAt(0) + 32));
}

export function r13aExpectedProofLine(handle, expectedNpub) {
  return `Berm Protocol: @${asciiLower(handle)} permanently binds to ${expectedNpub} #bermprotocol`;
}

export function r13aProofLines(text) {
  return r13aTextLines(text).filter((line) => R13A_PROOF_LINE_RE.test(line));
}

export function jcsCanonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new Error("jcs_lone_surrogate");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("jcs_non_finite_number");
    if (!Number.isInteger(value)) throw new Error("jcs_non_integer_number");
    if (Object.is(value, -0)) throw new Error("jcs_negative_zero");
    if (!Number.isSafeInteger(value)) throw new Error("jcs_unsafe_integer");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcsCanonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    for (const key of keys) if (hasLoneSurrogate(key)) throw new Error("jcs_lone_surrogate");
    return `{${keys.sort().map((key) => `${JSON.stringify(key)}:${jcsCanonicalize(value[key])}`).join(",")}}`;
  }
  throw new Error(`jcs_unsupported_type:${typeof value}`);
}

export async function bindingHash(binding) {
  assertR13aBinding(binding);
  return `sha256:${await sha256Hex(utf8Bytes(jcsCanonicalize(binding)))}`;
}

export async function exactBodyHash(body) {
  if (!(body instanceof Uint8Array)) throw new Error("body_bytes_required");
  return `sha256:${await sha256Hex(body)}`;
}

export function assertR13aBinding(binding) {
  if (!isPlainObject(binding)) throw new Error("binding_required");
  if (Object.keys(binding).sort().join("\u0000") !== [...BINDING_FIELDS].sort().join("\u0000")) throw new Error("binding_fields_invalid");
  if (!isCanonicalR13aNpub(binding.npub)) throw new Error("binding_npub_invalid");
  if (!isCanonicalPositiveUint64Decimal(binding.accountId)) throw new Error("binding_account_id_invalid");
  if (typeof binding.handle !== "string" || !HANDLE_RE.test(binding.handle)) throw new Error("binding_handle_invalid");
  if (!isCanonicalPositiveUint64Decimal(binding.postId)) throw new Error("binding_post_id_invalid");
  if (typeof binding.textHash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(binding.textHash)) throw new Error("binding_text_hash_invalid");
  if (binding.methodHash !== BERM_R13A_METHOD_HASH) throw new Error("binding_method_hash_invalid");
  return true;
}

export function xPostTimestampMs(postId) {
  const normalized = String(postId ?? "");
  if (!isCanonicalPositiveUint64Decimal(normalized)) throw new Error("post_id_invalid");
  return Number((BigInt(normalized) >> 22n) + X_EPOCH_MS);
}

export async function verifyXBinding(capture, expectedNpub, observedAt) {
  try {
    if (!isCanonicalR13aNpub(expectedNpub)) return failure("bad_expected_npub");
    if (typeof observedAt !== "number" || !Number.isSafeInteger(observedAt) || observedAt < 0 || Object.is(observedAt, -0)) {
      return failure("bad_observed_at");
    }
    if (!captureShapeValid(capture)) return failure("capture_malformed");
    if (capture.redirects !== 0) return failure("redirect_present");
    if (capture.status !== 200) return failure("status_not_success");
    if (capture.body.length > BERM_R13A_MAX_RESPONSE_BYTES) return failure("response_too_large");

    let doc;
    try {
      doc = strictParseR13aJsonBytes(capture.body);
    } catch (error) {
      if (error instanceof R13aStrictJsonError) return failure(error.kind);
      throw error;
    }
    if (!isPlainObject(doc)) return failure("json_parse_failed");

    if ((own(doc, "truncated") && doc.truncated === true) || own(doc, "note_tweet") || own(doc, "extended_tweet")) {
      return failure("text_incomplete");
    }
    if (!own(doc, "text") || typeof doc.text !== "string") return failure("no_text");
    if (!own(doc, "user") || !isPlainObject(doc.user) || !own(doc.user, "id_str")) return failure("no_account_id");
    const accountId = doc.user.id_str;
    if (!isCanonicalPositiveUint64Decimal(accountId)) return failure("bad_account_id");
    if (!own(doc.user, "screen_name")) return failure("no_handle");
    const handle = doc.user.screen_name;
    if (typeof handle !== "string" || !HANDLE_RE.test(handle)) return failure("bad_handle");
    if (!own(doc, "id_str")) return failure("no_post_id");
    const postId = doc.id_str;
    if (!isCanonicalPositiveUint64Decimal(postId)) return failure("bad_post_id");
    if (own(doc, "user_id_str") && doc.user_id_str !== accountId) return failure("author_account_mismatch");

    const lines = r13aTextLines(doc.text);
    const expectedLine = r13aExpectedProofLine(handle, expectedNpub);
    if (!lines.some((line) => line === expectedLine)) {
      return failure(doc.text.includes(expectedLine) ? "npub_undelimited" : "npub_absent");
    }
    if (r13aProofLines(doc.text).length > 1) return failure("npub_multiple");

    const numericPostId = BigInt(postId);
    if (numericPostId < FIRST_SNOWFLAKE_ID) return failure("no_creation_time");
    const postCreatedAt = xPostTimestampMs(postId);
    const delta = observedAt - postCreatedAt;
    if (delta < 0) return failure("observation_predates_post");
    if (delta >= BERM_R13A_WINDOW_MS) return failure("observation_outside_window");

    const binding = {
      npub: expectedNpub,
      accountId,
      handle,
      postId,
      textHash: `sha256:${await sha256Hex(utf8Bytes(doc.text))}`,
      methodHash: BERM_R13A_METHOD_HASH,
    };
    assertR13aBinding(binding);
    return binding;
  } catch {
    return failure("capture_malformed");
  }
}

function postIdInDomain(value) {
  return isCanonicalPositiveUint64Decimal(value);
}

function rawAuthority(urlText) {
  const match = urlText.match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/);
  return match?.[1] ?? null;
}

export function admitXStatusUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim() || utf8Bytes(value).length > 2048) return failure("not_a_url");
  let url;
  try {
    url = new URL(value);
  } catch {
    return failure("not_a_url");
  }
  if (url.protocol !== "https:") return failure("scheme_not_https");
  if (url.hostname !== "x.com") return failure("host_not_x_com");
  if (url.username !== "" || url.password !== "") return failure("userinfo_present");
  const authority = rawAuthority(value.replace(/[\u0009\u000a\u000d]/g, ""));
  const hostPort = authority?.slice((authority.lastIndexOf("@") + 1) || 0) ?? "";
  if (hostPort.includes(":")) return failure("explicit_port_present");
  if (url.search !== "") return failure("query_present");
  if (url.hash !== "") return failure("fragment_present");
  const segments = url.pathname.split("/");
  if (segments.length !== 4 || segments[0] !== "" || segments[2] !== "status") return failure("path_shape_invalid");
  const [handle, postId] = [segments[1], segments[3]];
  if (!HANDLE_RE.test(handle)) return failure("handle_invalid");
  if (!postIdInDomain(postId)) return failure("post_id_invalid");
  return { handle, postId, canonicalUrl: `https://x.com/${handle}/status/${postId}` };
}

export function normalizeDirectXStatusUrl(value) {
  const canonical = admitXStatusUrl(value);
  if (canonical.ok !== false) return canonical;
  if (typeof value !== "string" || value.length === 0 || value !== value.trim() || utf8Bytes(value).length > 2048) return failure("not_a_url");
  let url;
  try {
    url = new URL(value);
  } catch {
    return failure("not_a_url");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash) return canonical;
  const allowedHosts = new Set(["x.com", "www.x.com", "mobile.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"]);
  if (!allowedHosts.has(url.hostname)) return canonical;
  const match = url.pathname.match(/^\/([A-Za-z0-9_]{1,15})\/status\/([1-9][0-9]{0,19})\/?$/);
  if (!match || !postIdInDomain(match[2])) return canonical;
  return { handle: match[1], postId: match[2], canonicalUrl: `https://x.com/${match[1]}/status/${match[2]}`, normalizedLocally: true };
}

export function createR13aValidatorB({ captureProvider = null } = {}) {
  return Object.freeze({
    methodId: BERM_R13A_METHOD_ID,
    methodHash: BERM_R13A_METHOD_HASH,
    acquisitionId: BERM_R13A_ACQUISITION_ID,
    acquisitionHash: BERM_R13A_ACQUISITION_HASH,
    liveTransport: captureProvider ? "INJECTED_CAPTURE_PROVIDER" : "UNBOUND_LIVE_TRANSPORT",
    async verifyStatus({ statusUrl, expectedNpub, observedAt }) {
      const locator = normalizeDirectXStatusUrl(statusUrl);
      if (locator.ok === false) return { status: "REFUSED_LOCATOR", reason: locator.code, binding: null };
      if (typeof captureProvider !== "function") return { status: "UNBOUND_LIVE_TRANSPORT", binding: null, locator };
      const capture = await captureProvider(locator.canonicalUrl);
      const result = await verifyXBinding(capture, expectedNpub, observedAt);
      return result.ok === false
        ? { status: "NOT_ACCEPTED", reason: result.code, binding: null, locator }
        : { status: "VERIFIED_R13A_BINDING", binding: result, bindingHash: await bindingHash(result), locator };
    },
  });
}
