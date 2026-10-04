import { normalizePrivateKeyForXOnly, schnorrSign, schnorrVerify, sha256Hex, strip0x, utf8Bytes } from "./enrollmentCrypto.js";
import { canonicalJson, normalizeNostrPubkey, ROBINHOOD_CHAIN_DOMAIN, ROBINHOOD_CHAIN_ID } from "./enrollmentProtocol.js";

export const OBSERVATION_SCHEMA = "bermlaunch.enrollment_observation.v1";
export const OBSERVER_POLICY_SCHEMA = "bermlaunch.enrollment_observer_policy.v1";

function normalizeHex32(value, label) {
  const raw = strip0x(value);
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error(`${label}_invalid_hex32`);
  return `0x${raw.toLowerCase()}`;
}

function observerMessageHash(payload) {
  return sha256Hex(utf8Bytes(`${OBSERVATION_SCHEMA}\n${canonicalJson(payload)}`));
}

function assertClosedObservationPayload(payload) {
  const allowed = new Set([
    "schema",
    "event_id",
    "campaign_id",
    "chain_id",
    "chain_domain",
    "observation_sequence",
    "observed_at",
    "source_relay",
    "source_event_hash",
    "observer_pubkey",
  ]);
  for (const key of Object.keys(payload ?? {})) {
    if (!allowed.has(key)) throw new Error(`observation_payload_unknown_field:${key}`);
  }
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(payload ?? {}, key)) throw new Error(`observation_payload_missing_field:${key}`);
  }
}

export function canonicalObservationPayload(input) {
  const sequence = Number(input.observationSequence ?? input.observation_sequence ?? input.sequence);
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error("observation_sequence_invalid");
  const observedAt = Number(input.observedAt ?? input.observed_at ?? 1_800_000_000 + sequence);
  if (!Number.isSafeInteger(observedAt) || observedAt <= 0) throw new Error("observed_at_invalid");
  return {
    schema: OBSERVATION_SCHEMA,
    event_id: normalizeHex32(input.eventId ?? input.event_id, "event_id"),
    campaign_id: normalizeHex32(input.campaignId ?? input.campaign_id, "campaign_id"),
    chain_id: Number(input.chainId ?? input.chain_id ?? ROBINHOOD_CHAIN_ID),
    chain_domain: normalizeHex32(input.chainDomain ?? input.chain_domain ?? ROBINHOOD_CHAIN_DOMAIN, "chain_domain"),
    observation_sequence: sequence,
    observed_at: observedAt,
    source_relay: String(input.sourceRelay ?? input.source_relay ?? "relay.bermlaunch.local/mock-beta"),
    source_event_hash: normalizeHex32(input.sourceEventHash ?? input.source_event_hash ?? input.eventId ?? input.event_id, "source_event_hash"),
    observer_pubkey: normalizeNostrPubkey(input.observerPubkey ?? input.observer_pubkey),
  };
}

export function signObservationReceipt({ payload, observerSecretHex }) {
  const observer = normalizePrivateKeyForXOnly(observerSecretHex);
  const canonical = canonicalObservationPayload({ ...payload, observerPubkey: payload.observerPubkey ?? observer.publicKeyXOnly });
  if (canonical.observer_pubkey !== observer.publicKeyXOnly) throw new Error("observer_pubkey_secret_mismatch");
  const messageHash = observerMessageHash(canonical);
  return {
    schema: OBSERVATION_SCHEMA,
    payload: canonical,
    observerPubkey: observer.publicKeyXOnly,
    signature: schnorrSign(messageHash, observer.normalizedPrivateKeyHex),
    receiptId: sha256Hex(utf8Bytes(`${messageHash}:${observer.publicKeyXOnly}`)),
    signatureScheme: "BIP340-Schnorr-over-observation-canonical-json-sha256",
  };
}

export function verifyObservationReceipt(receipt, options = {}) {
  if (receipt?.schema !== OBSERVATION_SCHEMA) throw new Error("observation_schema_invalid");
  assertClosedObservationPayload(receipt.payload);
  const payload = canonicalObservationPayload(receipt.payload);
  const messageHash = observerMessageHash(payload);
  const recomputedReceiptId = sha256Hex(utf8Bytes(`${messageHash}:${payload.observer_pubkey}`));
  if (!receipt.receiptId) throw new Error("observation_receipt_id_required");
  if (normalizeHex32(receipt.receiptId, "observation_receipt_id") !== recomputedReceiptId) {
    throw new Error("observation_receipt_id_mismatch");
  }
  if (!schnorrVerify(messageHash, payload.observer_pubkey, receipt.signature)) throw new Error("observation_signature_invalid");
  if (receipt.observerPubkey && normalizeNostrPubkey(receipt.observerPubkey) !== payload.observer_pubkey) throw new Error("observation_observer_mismatch");
  if (options.expectedObserverPubkeys?.length) {
    const allowed = new Set(options.expectedObserverPubkeys.map((item) => normalizeNostrPubkey(item)));
    if (!allowed.has(payload.observer_pubkey)) throw new Error("observation_observer_not_allowed");
  }
  if (options.expectedEventId && normalizeHex32(options.expectedEventId, "event_id") !== payload.event_id) throw new Error("observation_event_mismatch");
  if (options.expectedCampaignId && normalizeHex32(options.expectedCampaignId, "campaign_id") !== payload.campaign_id) throw new Error("observation_campaign_mismatch");
  if (options.expectedChainId !== undefined && Number(options.expectedChainId) !== payload.chain_id) throw new Error("observation_chain_mismatch");
  if (options.expectedChainDomain && normalizeHex32(options.expectedChainDomain, "chain_domain") !== payload.chain_domain) throw new Error("observation_chain_domain_mismatch");
  return {
    schema: "bermlaunch.enrollment_observation_verified.v1",
    eventId: payload.event_id,
    campaignId: payload.campaign_id,
    chainId: payload.chain_id,
    chainDomain: payload.chain_domain,
    sequence: payload.observation_sequence,
    observedAt: payload.observed_at,
    sourceRelay: payload.source_relay,
    sourceEventHash: payload.source_event_hash,
    observerPubkey: payload.observer_pubkey,
    receiptId: recomputedReceiptId,
    signatureVerified: true,
  };
}

export function observationPolicy({ observerPubkeys, minimumSequence = 0, description = "R2 isolated mock-beta observer allowlist" }) {
  return {
    schema: OBSERVER_POLICY_SCHEMA,
    observerPubkeys: observerPubkeys.map((item) => normalizeNostrPubkey(item)),
    minimumSequence: Number(minimumSequence),
    description,
  };
}
