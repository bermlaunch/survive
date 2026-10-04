const NODE_RUNTIME = typeof process !== "undefined" && Boolean(process.versions?.node);
const enrollmentCrypto = NODE_RUNTIME ? await import("./enrollmentCrypto.js") : null;
const browserCrypto = NODE_RUNTIME ? null : await import("./identityCrypto.js");
const {
  bytesToHex,
  evmAddressFromPrivateKey,
  evmAddressFromXOnlyPubkey,
  hexToBytes,
  normalizePrivateKeyForXOnly,
  recoverEip191PersonalMessageAddress,
  schnorrSign,
  schnorrVerify,
  sha256Hex,
  signEip191PersonalMessage,
  utf8Bytes,
} = enrollmentCrypto ?? {};
const strip0x = enrollmentCrypto?.strip0x ?? ((value) => String(value).replace(/^0x/i, ""));

export const ENROLLMENT_SCHEMA = "bermlaunch.supporter_enrollment.v1";
export const VERIFIED_ENROLLMENT_SCHEMA = "bermlaunch.supporter_enrollment_verified.v1";
export const ENROLLMENT_R3_SCHEMA = "bermlaunch.supporter_enrollment.v3";
export const VERIFIED_ENROLLMENT_R3_SCHEMA = "bermlaunch.supporter_enrollment_verified.v3";
export const ENROLLMENT_R3_MODE = "declared_destination_v1";
export const ENROLLMENT_R3_CONFIRMATION_VERSION = 1;
export const ENROLLMENT_EVENT_KIND = 30466;
export const ENROLLMENT_MODES = Object.freeze(["derived_v1", "bound_wallet_v1"]);
export const EVM_PROOF_SCHEME = "eip191-personal-sign";
export const ROBINHOOD_CHAIN_ID = 4663;
export const ROBINHOOD_CHAIN_DOMAIN = "0x5d322d37f397baa2c07d79a8d9b03a8f80ed0b32737661864dda5f7ca7eda84c";

const CRITICAL_TAGS = new Set([
  "schema",
  "campaign",
  "chain-id",
  "chain-domain",
  "mode",
  "evm-address",
  "evm-proof-scheme",
  "evm-proof",
  "backup-required",
  "observed-sequence",
]);

const R3_CRITICAL_TAGS = new Set([
  "schema",
  "campaign",
  "chain-id",
  "chain-domain",
  "mode",
  "evm-address",
  "destination-confirmation",
  "observed-sequence",
  "broker",
  "source",
]);

const MAX_SAFE_CANONICAL_INTEGER = 9_007_199_254_740_991;

function quoteCanonicalString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
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

function assertNfcString(value, label) {
  if (hasLoneSurrogate(value)) throw new Error(`${label}_lone_surrogate_forbidden`);
  if (value.normalize("NFC") !== value) throw new Error(`${label}_string_not_nfc`);
}

function assertCanonicalJsonValue(value, label = "json") {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    assertNfcString(value, label);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error(`${label}_float_forbidden`);
    if (value < 0 || value > MAX_SAFE_CANONICAL_INTEGER) throw new Error(`${label}_unsafe_integer`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertCanonicalJsonValue(item, `${label}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      assertNfcString(key, `${label}.key`);
      assertCanonicalJsonValue(item, `${label}.${key}`);
    }
    return;
  }
  throw new Error(`unsupported canonical JSON value: ${typeof value}`);
}

function scanCanonicalJsonText(text, label) {
  let index = 0;
  const skipWs = () => {
    while (/[ \t\r\n]/.test(text[index] ?? "")) index += 1;
  };
  const parseString = () => {
    if (text[index] !== "\"") throw new Error(`${label}_expected_string`);
    const start = index;
    index += 1;
    while (index < text.length) {
      const char = text[index];
      if (char === "\"") {
        index += 1;
        const token = text.slice(start, index);
        const parsed = JSON.parse(token);
        assertNfcString(parsed, label);
        return parsed;
      }
      if (char === "\\") {
        index += 1;
        if (index >= text.length) throw new Error(`${label}_invalid_escape`);
        index += 1;
      } else {
        index += 1;
      }
    }
    throw new Error(`${label}_unterminated_string`);
  };
  const parseNumber = () => {
    const start = index;
    if (text[index] === "-") index += 1;
    while (/[0-9]/.test(text[index] ?? "")) index += 1;
    if (text[index] === "." || text[index] === "e" || text[index] === "E") throw new Error(`${label}_float_forbidden`);
    const token = text.slice(start, index);
    if (!/^-?(0|[1-9][0-9]*)$/.test(token)) throw new Error(`${label}_invalid_number`);
    const value = Number(token);
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label}_unsafe_integer`);
  };
  const parseLiteral = (literal) => {
    if (text.slice(index, index + literal.length) !== literal) throw new Error(`${label}_invalid_literal`);
    index += literal.length;
  };
  const parseValue = () => {
    skipWs();
    const char = text[index];
    if (char === "{") return parseObject();
    if (char === "[") return parseArray();
    if (char === "\"") return void parseString();
    if (char === "t") return void parseLiteral("true");
    if (char === "f") return void parseLiteral("false");
    if (char === "n") return void parseLiteral("null");
    if (char === "-" || /[0-9]/.test(char ?? "")) return void parseNumber();
    throw new Error(`${label}_invalid_json`);
  };
  const parseObject = () => {
    index += 1;
    const keys = new Set();
    skipWs();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    while (index < text.length) {
      skipWs();
      const key = parseString();
      if (keys.has(key)) throw new Error(`duplicate_json_key:${key}`);
      keys.add(key);
      skipWs();
      if (text[index] !== ":") throw new Error(`${label}_expected_colon`);
      index += 1;
      parseValue();
      skipWs();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") throw new Error(`${label}_expected_comma`);
      index += 1;
    }
    throw new Error(`${label}_unterminated_object`);
  };
  const parseArray = () => {
    index += 1;
    skipWs();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (index < text.length) {
      parseValue();
      skipWs();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") throw new Error(`${label}_expected_comma`);
      index += 1;
    }
    throw new Error(`${label}_unterminated_array`);
  };
  parseValue();
  skipWs();
  if (index !== text.length) throw new Error(`${label}_trailing_bytes`);
}

export function parseStrictJson(raw, label = "json") {
  let text;
  if (raw instanceof Uint8Array || (typeof Buffer !== "undefined" && Buffer.isBuffer(raw))) {
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new Error(`${label}_invalid_utf8`);
    }
  } else {
    text = String(raw);
  }
  if (text.charCodeAt(0) === 0xfeff) throw new Error(`${label}_bom_forbidden`);
  scanCanonicalJsonText(text, label);
  const parsed = JSON.parse(text);
  assertCanonicalJsonValue(parsed, label);
  return parsed;
}

export function parseCanonicalJson(raw, label = "json") {
  let text;
  if (raw instanceof Uint8Array || (typeof Buffer !== "undefined" && Buffer.isBuffer(raw))) {
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new Error(`${label}_invalid_utf8`);
    }
  } else {
    text = String(raw);
  }
  const parsed = parseStrictJson(text, label);
  if (canonicalJson(parsed) !== text) throw new Error(`${label}_not_canonical`);
  return parsed;
}

function normalizeHex32(value, label) {
  const raw = strip0x(value);
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error(`${label}_invalid_hex32`);
  return `0x${raw.toLowerCase()}`;
}

export function normalizeNostrPubkey(value) {
  return normalizeHex32(value, "nostr_pubkey");
}

export function normalizeAddress(value) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(value))) throw new Error("evm_address_invalid");
  return String(value).toLowerCase();
}

export function canonicalJson(value) {
  assertCanonicalJsonValue(value);
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${quoteCanonicalString(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  if (typeof value === "string") return quoteCanonicalString(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("json_float_forbidden");
    if (value < 0 || value > MAX_SAFE_CANONICAL_INTEGER) throw new Error("json_unsafe_integer");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  throw new Error(`unsupported canonical JSON value: ${typeof value}`);
}

function normalizeCampaignId(value) {
  return normalizeHex32(value, "campaign_id");
}

function assertMode(mode) {
  if (!ENROLLMENT_MODES.includes(mode)) throw new Error("mode_unknown");
}

export function canonicalEnrollmentPayload(input) {
  if (!input?.campaignId) throw new Error("campaign_required");
  if (!input?.mode) throw new Error("mode_required");
  assertMode(input.mode);
  if (!input?.nostrPubkey) throw new Error("nostr_pubkey_required");
  if (!input?.evmAddress) throw new Error("evm_address_required");
  const chainId = Number(input.chainId ?? ROBINHOOD_CHAIN_ID);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("chain_id_invalid");
  const chainDomain = normalizeHex32(input.chainDomain ?? ROBINHOOD_CHAIN_DOMAIN, "chain_domain");
  const observedSequence = Number(input.observedSequence ?? 0);
  if (!Number.isSafeInteger(observedSequence) || observedSequence < 0) throw new Error("observed_sequence_invalid");
  const createdAt = Number(input.createdAt ?? 1_800_000_000);
  if (!Number.isSafeInteger(createdAt) || createdAt <= 0) throw new Error("created_at_invalid");
  const backupRequired = input.mode === "derived_v1";
  return {
    schema: ENROLLMENT_SCHEMA,
    campaign_id: normalizeCampaignId(input.campaignId),
    chain_id: chainId,
    chain_domain: chainDomain,
    mode: input.mode,
    nostr_pubkey: normalizeNostrPubkey(input.nostrPubkey),
    evm_address: normalizeAddress(input.evmAddress),
    evm_proof_scheme: EVM_PROOF_SCHEME,
    intent: "bermlaunch-supporter-destination-binding",
    created_at: createdAt,
    observed_sequence: observedSequence,
    broker: input.broker ?? "direct",
    backup_required: backupRequired,
    backup_commitment: backupRequired ? normalizeHex32(input.backupCommitment, "backup_commitment") : null,
  };
}

function requireBoundedMetadata(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || value !== value.trim() || /[\r\n]/.test(value)) {
    throw new Error(`${label}_invalid`);
  }
  assertNfcString(value, label);
  return value;
}

export function canonicalEnrollmentR3Payload(input) {
  if (!input?.campaignId) throw new Error("campaign_required");
  if (!input?.nostrPubkey) throw new Error("nostr_pubkey_required");
  if (!input?.evmAddress) throw new Error("evm_address_required");
  if (input.destinationConfirmed !== true) throw new Error("destination_explicit_confirmation_required");
  const confirmationVersion = Number(input.confirmationVersion ?? ENROLLMENT_R3_CONFIRMATION_VERSION);
  if (confirmationVersion !== ENROLLMENT_R3_CONFIRMATION_VERSION) throw new Error("destination_confirmation_version_invalid");
  const chainId = Number(input.chainId ?? ROBINHOOD_CHAIN_ID);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("chain_id_invalid");
  const observedSequence = Number(input.observedSequence ?? 0);
  if (!Number.isSafeInteger(observedSequence) || observedSequence < 0) throw new Error("observed_sequence_invalid");
  const createdAt = Number(input.createdAt ?? 1_800_000_000);
  if (!Number.isSafeInteger(createdAt) || createdAt <= 0) throw new Error("created_at_invalid");
  return {
    schema: ENROLLMENT_R3_SCHEMA,
    campaign_id: normalizeCampaignId(input.campaignId),
    chain_id: chainId,
    chain_domain: normalizeHex32(input.chainDomain ?? ROBINHOOD_CHAIN_DOMAIN, "chain_domain"),
    mode: ENROLLMENT_R3_MODE,
    nostr_pubkey: normalizeNostrPubkey(input.nostrPubkey),
    destination_evm_address: normalizeAddress(input.evmAddress),
    destination_confirmation: Object.freeze({ state: "CONFIRMED", version: confirmationVersion }),
    intent: "bermlaunch-supporter-destination-declaration",
    created_at: createdAt,
    observed_sequence: observedSequence,
    broker: requireBoundedMetadata(input.broker ?? "direct", "broker"),
    source: requireBoundedMetadata(input.source ?? "bermlaunch-web", "source"),
  };
}

export function evmProofMessage(payload) {
  return [
    "BermLaunch Supporter Enrollment R2",
    "EVM destination proof over exact canonical enrollment bytes.",
    canonicalJson(payload),
  ].join("\n");
}

function eventHashPayload(event) {
  const raw = JSON.stringify([0, strip0x(event.pubkey), event.created_at, event.kind, event.tags, event.content]);
  return sha256Hex(utf8Bytes(raw));
}

export function computeNostrEventId(event) {
  return eventHashPayload(event);
}

function tag(name, tags) {
  const matches = tags.filter((item) => item[0] === name);
  if (matches.length > 1 && CRITICAL_TAGS.has(name)) throw new Error(`duplicate_critical_tag:${name}`);
  return matches[0]?.[1];
}

function requireTag(name, tags) {
  const value = tag(name, tags);
  if (value === undefined || value === "") throw new Error(`missing_critical_tag:${name}`);
  return value;
}

function assertTagEquals(tags, name, expected) {
  const actual = requireTag(name, tags);
  if (String(actual) !== String(expected)) throw new Error(`tag_mismatch:${name}`);
}

function eventTags(payload, evmProof) {
  const tags = [
    ["schema", payload.schema],
    ["campaign", payload.campaign_id],
    ["chain-id", String(payload.chain_id)],
    ["chain-domain", payload.chain_domain],
    ["mode", payload.mode],
    ["evm-address", payload.evm_address],
    ["evm-proof-scheme", payload.evm_proof_scheme],
    ["evm-proof", evmProof],
    ["backup-required", payload.backup_required ? "YES" : "NO"],
    ["observed-sequence", String(payload.observed_sequence)],
    ["broker", payload.broker],
  ];
  if (payload.backup_commitment) tags.push(["backup-commitment", payload.backup_commitment]);
  return tags;
}

function r3EventTags(payload) {
  return [
    ["schema", payload.schema],
    ["campaign", payload.campaign_id],
    ["chain-id", String(payload.chain_id)],
    ["chain-domain", payload.chain_domain],
    ["mode", payload.mode],
    ["evm-address", payload.destination_evm_address],
    ["destination-confirmation", `${payload.destination_confirmation.state}:${payload.destination_confirmation.version}`],
    ["observed-sequence", String(payload.observed_sequence)],
    ["broker", payload.broker],
    ["source", payload.source],
  ];
}

export function createEncryptedBackupCommitment({ backupArtifact }) {
  if (!backupArtifact?.commitment) throw new Error("path_a_backup_artifact_required");
  return normalizeHex32(backupArtifact.commitment, "backup_commitment");
}

export function createPathAEnrollment(input) {
  const normalized = normalizePrivateKeyForXOnly(input.nostrSecretHex);
  const evmAddress = evmAddressFromPrivateKey(normalized.normalizedPrivateKeyHex);
  const backupCommitment =
    input.backupCommitment ??
    createEncryptedBackupCommitment({ backupArtifact: input.backupArtifact });
  const payload = canonicalEnrollmentPayload({
    ...input,
    mode: "derived_v1",
    nostrPubkey: normalized.publicKeyXOnly,
    evmAddress,
    backupCommitment,
  });
  return finalizeEnrollment({ payload, nostrSecretHex: normalized.normalizedPrivateKeyHex, evmSecretHex: normalized.normalizedPrivateKeyHex, parity: normalized });
}

export function createPathBEnrollment(input) {
  const normalized = normalizePrivateKeyForXOnly(input.nostrSecretHex);
  if (!input.evmAddress && !input.evmSecretHex) throw new Error("path_b_explicit_wallet_required");
  const evmAddress = normalizeAddress(input.evmAddress ?? evmAddressFromPrivateKey(input.evmSecretHex));
  const payload = canonicalEnrollmentPayload({
    ...input,
    mode: "bound_wallet_v1",
    nostrPubkey: normalized.publicKeyXOnly,
    evmAddress,
    backupCommitment: null,
  });
  if (!input.evmSecretHex) throw new Error("path_b_evm_signer_required");
  return finalizeEnrollment({ payload, nostrSecretHex: normalized.normalizedPrivateKeyHex, evmSecretHex: input.evmSecretHex, parity: normalized });
}

export function createDeclaredDestinationEnrollment(input) {
  const normalized = normalizePrivateKeyForXOnly(input.nostrSecretHex);
  const { payload, unsignedEvent: unsigned } = buildUnsignedEnrollmentR3Event({
    ...input,
    nostrPubkey: normalized.publicKeyXOnly,
  });
  const id = computeNostrEventId(unsigned);
  const sig = schnorrSign(id, normalized.normalizedPrivateKeyHex);
  return {
    schema: "bermlaunch.supporter_enrollment_signed_fixture.v3",
    payload,
    event: { ...unsigned, id: strip0x(id), sig: strip0x(sig) },
    destinationControlProof: null,
    destinationControlVerified: false,
    parity: normalized,
  };
}

// Browser integrations receive a signer capability, never private-key bytes. This
// helper materializes the exact R3 event preimage so that capability can sign it.
export function buildUnsignedEnrollmentR3Event(input) {
  const payload = canonicalEnrollmentR3Payload(input);
  return Object.freeze({
    payload,
    unsignedEvent: Object.freeze({
      kind: ENROLLMENT_EVENT_KIND,
      pubkey: strip0x(payload.nostr_pubkey),
      created_at: payload.created_at,
      tags: Object.freeze(r3EventTags(payload).map((item) => Object.freeze(item))),
      content: canonicalJson(payload),
    }),
  });
}

function finalizeEnrollment({ payload, nostrSecretHex, evmSecretHex, parity }) {
  const evmProof = signEip191PersonalMessage(evmProofMessage(payload), evmSecretHex);
  const unsigned = {
    kind: ENROLLMENT_EVENT_KIND,
    pubkey: strip0x(payload.nostr_pubkey),
    created_at: payload.created_at,
    tags: eventTags(payload, evmProof),
    content: canonicalJson(payload),
  };
  const id = computeNostrEventId(unsigned);
  const sig = schnorrSign(id, nostrSecretHex);
  return {
    schema: "bermlaunch.supporter_enrollment_signed_fixture.v1",
    payload,
    event: { ...unsigned, id: strip0x(id), sig: strip0x(sig) },
    evmProof,
    parity,
    evmProofMessage: evmProofMessage(payload),
  };
}

function parseEventContent(event) {
  try {
    return parseCanonicalJson(event.content, "event_content");
  } catch (error) {
    if (error instanceof Error && error.message.includes("not_canonical")) throw new Error("event_content_not_canonical");
    if (error instanceof Error) throw error;
    throw new Error("event_content_not_json");
  }
}

function assertClosedPayload(payload) {
  const allowed = new Set([
    "schema",
    "campaign_id",
    "chain_id",
    "chain_domain",
    "mode",
    "nostr_pubkey",
    "evm_address",
    "evm_proof_scheme",
    "intent",
    "created_at",
    "observed_sequence",
    "broker",
    "backup_required",
    "backup_commitment",
  ]);
  const keys = Object.keys(payload);
  for (const key of keys) {
    if (!allowed.has(key)) throw new Error(`payload_unknown_field:${key}`);
  }
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(payload, key)) throw new Error(`payload_missing_field:${key}`);
  }
}

function assertClosedR3Payload(payload) {
  const required = new Set([
    "schema",
    "campaign_id",
    "chain_id",
    "chain_domain",
    "mode",
    "nostr_pubkey",
    "destination_evm_address",
    "destination_confirmation",
    "intent",
    "created_at",
    "observed_sequence",
    "broker",
    "source",
  ]);
  for (const key of Object.keys(payload ?? {})) if (!required.has(key)) throw new Error(`r3_payload_unknown_field:${key}`);
  for (const key of required) if (!Object.hasOwn(payload ?? {}, key)) throw new Error(`r3_payload_missing_field:${key}`);
  const confirmation = payload.destination_confirmation;
  if (!confirmation || typeof confirmation !== "object" || Array.isArray(confirmation)
      || Object.keys(confirmation).sort().join(",") !== "state,version") {
    throw new Error("destination_confirmation_shape_invalid");
  }
}

function requireUniqueR3Tag(name, tags) {
  const matches = tags.filter((item) => item[0] === name);
  if (matches.length !== 1 || matches[0].length !== 2 || matches[0][1] === "") {
    throw new Error(`r3_critical_tag_invalid:${name}`);
  }
  return matches[0][1];
}

async function verifyEnrollmentR3EventBrowser(event, options = {}) {
  if (!event || typeof event !== "object") throw new Error("event_required");
  if (event.kind !== ENROLLMENT_EVENT_KIND) throw new Error("event_kind_invalid");
  if (!Array.isArray(event.tags)) throw new Error("event_tags_required");
  const tags = event.tags.map((item) => item.map(String));
  for (const item of tags) {
    if (item.length !== 2 || !R3_CRITICAL_TAGS.has(item[0])) throw new Error(`r3_tag_forbidden:${item[0] ?? "unknown"}`);
  }
  for (const name of R3_CRITICAL_TAGS) requireUniqueR3Tag(name, tags);
  const computedBareId = await browserCrypto.nostrEventId({ ...event, tags });
  if (strip0x(event.id).toLowerCase() !== computedBareId) throw new Error("nostr_event_id_invalid");
  const pubkey = normalizeNostrPubkey(event.pubkey);
  if (!await browserCrypto.schnorrVerify(computedBareId, pubkey, event.sig)) throw new Error("nostr_signature_invalid");
  if (options.expectedNostrPubkey && normalizeNostrPubkey(options.expectedNostrPubkey) !== pubkey) throw new Error("nostr_pubkey_mismatch");

  const payload = parseEventContent(event);
  assertClosedR3Payload(payload);
  const canonical = canonicalEnrollmentR3Payload({
    campaignId: payload.campaign_id,
    chainId: payload.chain_id,
    chainDomain: payload.chain_domain,
    nostrPubkey: payload.nostr_pubkey,
    evmAddress: payload.destination_evm_address,
    destinationConfirmed: payload.destination_confirmation?.state === "CONFIRMED",
    confirmationVersion: payload.destination_confirmation?.version,
    createdAt: payload.created_at,
    observedSequence: payload.observed_sequence,
    broker: payload.broker,
    source: payload.source,
  });
  if (payload.schema !== ENROLLMENT_R3_SCHEMA || payload.mode !== ENROLLMENT_R3_MODE) throw new Error("r3_payload_schema_or_mode_invalid");
  if (payload.intent !== "bermlaunch-supporter-destination-declaration") throw new Error("r3_payload_intent_invalid");
  if (canonicalJson(canonical) !== event.content) throw new Error("r3_payload_not_canonical_enrollment");
  if (canonical.nostr_pubkey !== pubkey) throw new Error("event_pubkey_payload_mismatch");
  if (options.expectedCampaignId && normalizeCampaignId(options.expectedCampaignId) !== canonical.campaign_id) throw new Error("campaign_replay");
  if (options.expectedChainId !== undefined && Number(options.expectedChainId) !== canonical.chain_id) throw new Error("chain_mismatch");
  if (options.expectedChainDomain && normalizeHex32(options.expectedChainDomain, "chain_domain") !== canonical.chain_domain) throw new Error("chain_domain_mismatch");

  assertTagEquals(tags, "schema", canonical.schema);
  assertTagEquals(tags, "campaign", canonical.campaign_id);
  assertTagEquals(tags, "chain-id", String(canonical.chain_id));
  assertTagEquals(tags, "chain-domain", canonical.chain_domain);
  assertTagEquals(tags, "mode", canonical.mode);
  assertTagEquals(tags, "evm-address", canonical.destination_evm_address);
  assertTagEquals(tags, "destination-confirmation", "CONFIRMED:1");
  assertTagEquals(tags, "observed-sequence", String(canonical.observed_sequence));
  assertTagEquals(tags, "broker", canonical.broker);
  assertTagEquals(tags, "source", canonical.source);

  return {
    schema: VERIFIED_ENROLLMENT_R3_SCHEMA,
    eventId: `0x${computedBareId}`,
    nostrPubkey: pubkey,
    evmAddress: canonical.destination_evm_address,
    campaignId: canonical.campaign_id,
    chainId: canonical.chain_id,
    chainDomain: canonical.chain_domain,
    mode: canonical.mode,
    createdAt: canonical.created_at,
    selfDeclaredObservedSequence: canonical.observed_sequence,
    trustedObservationRequired: true,
    broker: canonical.broker,
    source: canonical.source,
    backupRequired: false,
    backupCommitment: null,
    backupStatus: "NOT_REQUIRED_R3_DECLARED_DESTINATION",
    nostrIdentitySource: "verified_nostr_event_pubkey",
    destinationConfirmation: Object.freeze({ ...canonical.destination_confirmation }),
    destinationControlProof: "NOT_PERFORMED_USER_DECLARED_EXPLICITLY_CONFIRMED",
    destinationControlVerified: false,
    canonicalPayloadBytesSha256: `0x${await browserCrypto.sha256Hex(browserCrypto.utf8Bytes(canonicalJson(canonical)))}`,
  };
}

function verifyEnrollmentR3EventNode(event, options = {}) {
  if (!event || typeof event !== "object") throw new Error("event_required");
  if (event.kind !== ENROLLMENT_EVENT_KIND) throw new Error("event_kind_invalid");
  if (!Array.isArray(event.tags)) throw new Error("event_tags_required");
  const tags = event.tags.map((item) => item.map(String));
  const allowedTags = R3_CRITICAL_TAGS;
  for (const item of tags) {
    if (item.length !== 2 || !allowedTags.has(item[0])) throw new Error(`r3_tag_forbidden:${item[0] ?? "unknown"}`);
  }
  for (const name of R3_CRITICAL_TAGS) requireUniqueR3Tag(name, tags);
  if (tags.some((item) => item[0] === "evm-proof" || item[0] === "evm-proof-scheme")) {
    throw new Error("r3_evm_control_proof_forbidden");
  }
  const computedId = computeNostrEventId({ ...event, tags });
  if (strip0x(event.id).toLowerCase() !== strip0x(computedId)) throw new Error("nostr_event_id_invalid");
  const pubkey = normalizeNostrPubkey(event.pubkey);
  if (!schnorrVerify(computedId, pubkey, event.sig)) throw new Error("nostr_signature_invalid");
  if (options.expectedNostrPubkey && normalizeNostrPubkey(options.expectedNostrPubkey) !== pubkey) {
    throw new Error("nostr_pubkey_mismatch");
  }

  const payload = parseEventContent(event);
  assertClosedR3Payload(payload);
  const canonical = canonicalEnrollmentR3Payload({
    campaignId: payload.campaign_id,
    chainId: payload.chain_id,
    chainDomain: payload.chain_domain,
    nostrPubkey: payload.nostr_pubkey,
    evmAddress: payload.destination_evm_address,
    destinationConfirmed: payload.destination_confirmation?.state === "CONFIRMED",
    confirmationVersion: payload.destination_confirmation?.version,
    createdAt: payload.created_at,
    observedSequence: payload.observed_sequence,
    broker: payload.broker,
    source: payload.source,
  });
  if (payload.schema !== ENROLLMENT_R3_SCHEMA || payload.mode !== ENROLLMENT_R3_MODE) throw new Error("r3_payload_schema_or_mode_invalid");
  if (payload.intent !== "bermlaunch-supporter-destination-declaration") throw new Error("r3_payload_intent_invalid");
  if (canonicalJson(canonical) !== event.content) throw new Error("r3_payload_not_canonical_enrollment");
  if (canonical.nostr_pubkey !== pubkey) throw new Error("event_pubkey_payload_mismatch");
  if (options.expectedCampaignId && normalizeCampaignId(options.expectedCampaignId) !== canonical.campaign_id) throw new Error("campaign_replay");
  if (options.expectedChainId !== undefined && Number(options.expectedChainId) !== canonical.chain_id) throw new Error("chain_mismatch");
  if (options.expectedChainDomain && normalizeHex32(options.expectedChainDomain, "chain_domain") !== canonical.chain_domain) throw new Error("chain_domain_mismatch");

  assertTagEquals(tags, "schema", canonical.schema);
  assertTagEquals(tags, "campaign", canonical.campaign_id);
  assertTagEquals(tags, "chain-id", String(canonical.chain_id));
  assertTagEquals(tags, "chain-domain", canonical.chain_domain);
  assertTagEquals(tags, "mode", canonical.mode);
  assertTagEquals(tags, "evm-address", canonical.destination_evm_address);
  assertTagEquals(tags, "destination-confirmation", "CONFIRMED:1");
  assertTagEquals(tags, "observed-sequence", String(canonical.observed_sequence));
  assertTagEquals(tags, "broker", canonical.broker);
  assertTagEquals(tags, "source", canonical.source);

  return {
    schema: VERIFIED_ENROLLMENT_R3_SCHEMA,
    eventId: bytesToHex(hexToBytes(computedId, 32)),
    nostrPubkey: pubkey,
    evmAddress: canonical.destination_evm_address,
    campaignId: canonical.campaign_id,
    chainId: canonical.chain_id,
    chainDomain: canonical.chain_domain,
    mode: canonical.mode,
    createdAt: canonical.created_at,
    selfDeclaredObservedSequence: canonical.observed_sequence,
    trustedObservationRequired: true,
    broker: canonical.broker,
    source: canonical.source,
    backupRequired: false,
    backupCommitment: null,
    backupStatus: "NOT_REQUIRED_R3_DECLARED_DESTINATION",
    nostrIdentitySource: "verified_nostr_event_pubkey",
    destinationConfirmation: Object.freeze({ ...canonical.destination_confirmation }),
    destinationControlProof: "NOT_PERFORMED_USER_DECLARED_EXPLICITLY_CONFIRMED",
    destinationControlVerified: false,
    canonicalPayloadBytesSha256: sha256Hex(utf8Bytes(canonicalJson(canonical))),
  };
}

export function verifyEnrollmentR3Event(event, options = {}) {
  return NODE_RUNTIME ? verifyEnrollmentR3EventNode(event, options) : verifyEnrollmentR3EventBrowser(event, options);
}

export function verifyEnrollmentEvent(event, options = {}) {
  if (!event || typeof event !== "object") throw new Error("event_required");
  if (event.kind !== ENROLLMENT_EVENT_KIND) throw new Error("event_kind_invalid");
  if (!Array.isArray(event.tags)) throw new Error("event_tags_required");
  const tags = event.tags.map((item) => item.map(String));
  const schemaTags = tags.filter((item) => item[0] === "schema");
  if (schemaTags.length === 1 && schemaTags[0][1] === ENROLLMENT_R3_SCHEMA) {
    return verifyEnrollmentR3Event({ ...event, tags }, options);
  }
  for (const name of CRITICAL_TAGS) requireTag(name, tags);
  const computedId = computeNostrEventId({ ...event, tags });
  if (strip0x(event.id).toLowerCase() !== strip0x(computedId)) throw new Error("nostr_event_id_invalid");
  const pubkey = normalizeNostrPubkey(event.pubkey);
  if (!schnorrVerify(computedId, pubkey, event.sig)) throw new Error("nostr_signature_invalid");
  if (options.expectedNostrPubkey && normalizeNostrPubkey(options.expectedNostrPubkey) !== pubkey) {
    throw new Error("nostr_pubkey_mismatch");
  }

  const payload = parseEventContent(event);
  assertClosedPayload(payload);
  const canonical = canonicalEnrollmentPayload({
    campaignId: payload.campaign_id,
    chainId: payload.chain_id,
    chainDomain: payload.chain_domain,
    mode: payload.mode,
    nostrPubkey: payload.nostr_pubkey,
    evmAddress: payload.evm_address,
    backupCommitment: payload.backup_commitment,
    broker: payload.broker,
    observedSequence: payload.observed_sequence,
    createdAt: payload.created_at,
  });
  if (payload.schema !== ENROLLMENT_SCHEMA) throw new Error("payload_schema_invalid");
  if (payload.evm_proof_scheme !== EVM_PROOF_SCHEME) throw new Error("payload_evm_proof_scheme_invalid");
  if (payload.intent !== "bermlaunch-supporter-destination-binding") throw new Error("payload_intent_invalid");
  if (payload.backup_required !== canonical.backup_required) throw new Error("payload_backup_required_mismatch");
  if (canonicalJson(canonical) !== event.content) throw new Error("payload_not_canonical_enrollment");
  if (canonical.nostr_pubkey !== pubkey) throw new Error("event_pubkey_payload_mismatch");
  if (options.expectedCampaignId && normalizeCampaignId(options.expectedCampaignId) !== canonical.campaign_id) {
    throw new Error("campaign_replay");
  }
  if (options.expectedChainId !== undefined && Number(options.expectedChainId) !== canonical.chain_id) {
    throw new Error("chain_mismatch");
  }
  if (options.expectedChainDomain && normalizeHex32(options.expectedChainDomain, "chain_domain") !== canonical.chain_domain) {
    throw new Error("chain_domain_mismatch");
  }

  assertTagEquals(tags, "schema", canonical.schema);
  assertTagEquals(tags, "campaign", canonical.campaign_id);
  assertTagEquals(tags, "chain-id", String(canonical.chain_id));
  assertTagEquals(tags, "chain-domain", canonical.chain_domain);
  assertTagEquals(tags, "mode", canonical.mode);
  assertTagEquals(tags, "evm-address", canonical.evm_address);
  assertTagEquals(tags, "evm-proof-scheme", canonical.evm_proof_scheme);
  assertTagEquals(tags, "backup-required", canonical.backup_required ? "YES" : "NO");
  assertTagEquals(tags, "observed-sequence", String(canonical.observed_sequence));

  const evmProof = requireTag("evm-proof", tags);
  const recovered = recoverEip191PersonalMessageAddress(evmProofMessage(canonical), evmProof);
  if (normalizeAddress(recovered) !== canonical.evm_address) throw new Error("evm_proof_wrong_wallet");

  if (canonical.mode === "derived_v1") {
    const artifactCommitment = options.backupArtifact?.commitment ? normalizeHex32(options.backupArtifact.commitment, "backup_commitment") : null;
    if (options.backupArtifact?.roundTripVerified !== true || artifactCommitment !== canonical.backup_commitment) {
      throw new Error("path_a_verified_backup_artifact_required");
    }
    if (!canonical.backup_commitment || tag("backup-commitment", tags) !== canonical.backup_commitment) {
      throw new Error("path_a_backup_commitment_missing");
    }
    const derivedAddress = evmAddressFromXOnlyPubkey(pubkey);
    if (derivedAddress !== canonical.evm_address) throw new Error("path_a_derived_address_mismatch");
  }

  if (canonical.mode === "bound_wallet_v1" && options.explicitWalletConnected !== true) {
    throw new Error("path_b_explicit_wallet_connection_required");
  }

  return {
    schema: VERIFIED_ENROLLMENT_SCHEMA,
    eventId: bytesToHex(hexToBytes(computedId, 32)),
    nostrPubkey: pubkey,
    evmAddress: canonical.evm_address,
    campaignId: canonical.campaign_id,
    chainId: canonical.chain_id,
    chainDomain: canonical.chain_domain,
    mode: canonical.mode,
    evmProofScheme: canonical.evm_proof_scheme,
    evmProofSigner: recovered,
    createdAt: canonical.created_at,
    selfDeclaredObservedSequence: canonical.observed_sequence,
    trustedObservationRequired: true,
    broker: canonical.broker,
    backupRequired: canonical.backup_required,
    backupCommitment: canonical.backup_commitment,
    backupStatus: canonical.backup_required ? "ROUND_TRIP_VERIFIED_PORTABLE_ENCRYPTED_BACKUP" : "NOT_REQUIRED",
    nostrIdentitySource: "verified_nostr_event_pubkey",
    destinationControlProof: "eip191_personal_sign_recovered_to_committed_wallet",
    signerBrokerDependency: canonical.broker === "signer.xonly.ai" ? "optional_convenience_not_sole_truth" : "none",
    canonicalPayloadBytesSha256: sha256Hex(utf8Bytes(canonicalJson(canonical))),
    canonicalEvmMessageSha256: sha256Hex(utf8Bytes(evmProofMessage(canonical))),
  };
}

export function tamperEnrollmentEvent(event, mutator) {
  const copy = JSON.parse(JSON.stringify(event));
  mutator(copy);
  return copy;
}
