import { bytesToHex, concatBytes, hexToBytes, keccak256Hex, strip0x, utf8Bytes } from "./enrollmentCrypto.js";
import {
  VERIFIED_ENROLLMENT_R3_SCHEMA,
  VERIFIED_ENROLLMENT_SCHEMA,
  canonicalJson,
  normalizeAddress,
  normalizeNostrPubkey,
  ROBINHOOD_CHAIN_DOMAIN,
  ROBINHOOD_CHAIN_ID,
  verifyEnrollmentEvent,
} from "./enrollmentProtocol.js";
import { verifyObservationReceipt } from "./enrollmentObservation.js";

export const PORTABLE_PROOF_BUNDLE_SCHEMA = "bermlaunch.supporter_portable_proof_bundle.r2";
export const ROSTER_MANIFEST_SCHEMA = "bermlaunch.supporter_enrollment_roster_manifest.r2";
export const CHAIN_DOMAIN = ROBINHOOD_CHAIN_DOMAIN;
export const MAX_PROOF_LENGTH = 9;
export const ROBINHOOD_COHORT_CAPACITIES = Object.freeze({ 0: 50, 1: 100, 2: 300 });
export const SUPPORTED_VERIFIED_ENROLLMENT_SCHEMAS = Object.freeze([
  VERIFIED_ENROLLMENT_SCHEMA,
  VERIFIED_ENROLLMENT_R3_SCHEMA,
]);
const COHORT_PUBLIC_NAMES = Object.freeze({
  0: "Founding Supporters",
  1: "Graduation Supporters",
  2: "Momentum Supporters",
});

function wordFromBigInt(value) {
  const hex = BigInt(value).toString(16).padStart(64, "0");
  return hexToBytes(hex, 32);
}

function wordFromBytes32(value) {
  return hexToBytes(value, 32);
}

function wordFromAddress(value) {
  return concatBytes(new Uint8Array(12), hexToBytes(normalizeAddress(value), 20));
}

function abiEncodeLeaf({ campaignId, cohortId, slotIndex, memberCount, npubRaw32, wallet }) {
  return concatBytes(
    wordFromBigInt(1),
    wordFromBytes32(CHAIN_DOMAIN),
    wordFromBytes32(campaignId),
    wordFromBigInt(cohortId),
    wordFromBigInt(slotIndex),
    wordFromBigInt(memberCount),
    wordFromBytes32(npubRaw32),
    wordFromAddress(wallet),
  );
}

export function robinhoodLeafHash({ campaignId, cohortId, slotIndex, memberCount, npubRaw32, wallet }) {
  return keccak256Hex(concatBytes(new Uint8Array([0]), abiEncodeLeaf({ campaignId, cohortId, slotIndex, memberCount, npubRaw32, wallet })));
}

export function merkleNodeHash(a, b) {
  const left = BigInt(`0x${strip0x(a)}`);
  const right = BigInt(`0x${strip0x(b)}`);
  const ordered = left <= right ? [a, b] : [b, a];
  return keccak256Hex(concatBytes(new Uint8Array([1]), hexToBytes(ordered[0], 32), hexToBytes(ordered[1], 32)));
}

export function merkleRoot(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) throw new Error("no leaves");
  let level = leaves.map((leaf) => leaf.toLowerCase());
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      if (index + 1 === level.length) next.push(level[index]);
      else next.push(merkleNodeHash(level[index], level[index + 1]));
    }
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves, slotIndex) {
  let index = slotIndex;
  let level = leaves.map((leaf) => leaf.toLowerCase());
  const proof = [];
  while (level.length > 1) {
    const siblingIndex = index ^ 1;
    if (siblingIndex < level.length) proof.push(level[siblingIndex]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) next.push(level[i]);
      else next.push(merkleNodeHash(level[i], level[i + 1]));
    }
    index = Math.floor(index / 2);
    level = next;
  }
  return proof;
}

export function verifyMerkleProof({ leaf, proof, root }) {
  let node = leaf.toLowerCase();
  for (const sibling of proof) node = merkleNodeHash(node, sibling);
  return node === root.toLowerCase();
}

function trustedSequence(record) {
  const sequence = record.trustedObservation?.sequence;
  if (!Number.isSafeInteger(sequence)) throw new Error(`trusted_observation_required:${record.eventId ?? "unknown"}`);
  return sequence;
}

function eventTieBreak(a, b) {
  const aSequence = trustedSequence(a);
  const bSequence = trustedSequence(b);
  if (aSequence !== bSequence) return aSequence - bSequence;
  return String(a.eventId).localeCompare(String(b.eventId));
}

function assertCohortDomain(cohortBundle) {
  if (Number(cohortBundle.chain_id) !== ROBINHOOD_CHAIN_ID) throw new Error("cohort_chain_mismatch");
  if (String(cohortBundle.chain_domain).toLowerCase() !== CHAIN_DOMAIN) throw new Error("cohort_chain_domain_mismatch");
}

function expectedCapacity(cohortId) {
  const capacity = ROBINHOOD_COHORT_CAPACITIES[cohortId];
  if (!capacity) throw new Error("cohort_id_invalid");
  return capacity;
}

function normalizeRelaySet(relays, { required }) {
  if (!Array.isArray(relays)) throw new Error("declared_relay_set_required");
  const normalized = relays.map((relay, index) => {
    const value = String(relay ?? "");
    if (!value || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new Error(`declared_relay_invalid:${index}`);
    }
    return value;
  });
  if (required && normalized.length === 0) throw new Error("declared_relay_set_required");
  if (new Set(normalized).size !== normalized.length) throw new Error("declared_relay_duplicate");
  return normalized.slice().sort();
}

function assertConstitutionAgreement(cohortBundle, campaignConstitution) {
  if (!campaignConstitution || typeof campaignConstitution !== "object") throw new Error("campaign_constitution_required");
  if (campaignConstitution.schema !== "BERM_CAMPAIGN_CONSTITUTION_V2") throw new Error("campaign_constitution_schema_mismatch");
  if (String(campaignConstitution.campaign_id).toLowerCase() !== String(cohortBundle.campaign_id).toLowerCase()) {
    throw new Error("campaign_constitution_campaign_mismatch");
  }
  if (Number(campaignConstitution.chain_id) !== Number(cohortBundle.chain_id)) throw new Error("campaign_constitution_chain_mismatch");
  if (String(campaignConstitution.chain_domain).toLowerCase() !== String(cohortBundle.chain_domain).toLowerCase()) {
    throw new Error("campaign_constitution_domain_mismatch");
  }
  const cohortId = Number(cohortBundle.cohort_id);
  const law = campaignConstitution.cohort_law?.cohorts?.find((item) => Number(item.cohort_id) === cohortId);
  if (!law) throw new Error("campaign_constitution_cohort_missing");
  if (Number(law.member_count) !== Number(cohortBundle.member_count)) throw new Error("campaign_constitution_capacity_mismatch");
  if (String(law.contract_id).toUpperCase() !== String(cohortBundle.cohort_name).toUpperCase()) {
    throw new Error("campaign_constitution_contract_id_mismatch");
  }
  const bundleRange = cohortBundle.bps_range;
  if (Array.isArray(bundleRange) && (Number(bundleRange[0]) !== Number(law.bps_start) || Number(bundleRange[1]) !== Number(law.bps_end))) {
    throw new Error("campaign_constitution_bps_range_mismatch");
  }
  return law;
}

function validateCohortBundle(cohortBundle, { campaignConstitution = null, requireConstitution }) {
  if (!cohortBundle || typeof cohortBundle !== "object") throw new Error("cohort_bundle_required");
  assertCohortDomain(cohortBundle);
  const cohortId = Number(cohortBundle.cohort_id);
  const capacity = expectedCapacity(cohortId);
  if (Number(cohortBundle.member_count) !== capacity) throw new Error(`cohort_capacity_mismatch:${cohortId}:${capacity}`);
  if (requireConstitution) assertConstitutionAgreement(cohortBundle, campaignConstitution);
  if (!Array.isArray(cohortBundle.proofs)) throw new Error("cohort_proofs_required");
  if (cohortBundle.proofs.length === 0) throw new Error("zero_selected_cohort_founder_decision_required");
  if (cohortBundle.proofs.length > capacity) throw new Error(`selected_count_exceeds_capacity:${cohortId}`);
  const proofs = cohortBundle.proofs.slice().sort((a, b) => Number(a.slot_index) - Number(b.slot_index));
  proofs.forEach((proof, index) => {
    if (!Number.isSafeInteger(Number(proof.slot_index)) || Number(proof.slot_index) !== index) {
      throw new Error(`sparse_or_non_dense_slot:${cohortId}:${index}`);
    }
    if (proof.cohort_id !== undefined && Number(proof.cohort_id) !== cohortId) throw new Error(`proof_cohort_mismatch:${index}`);
    if (proof.member_count !== undefined && Number(proof.member_count) !== capacity) throw new Error(`proof_capacity_mismatch:${index}`);
  });
  return { cohortId, capacity, proofs };
}

function recordWallet(record) {
  return record?.wallet ?? record?.evm_wallet ?? record?.expected_wallet ?? null;
}

function recordsFromRawEvidence({ rawEvidenceRecords, observerPolicy, campaignId, declaredRelaySet }) {
  const policyPubkeys = observerPolicy?.observerPubkeys ?? [];
  if (!Array.isArray(policyPubkeys) || policyPubkeys.length === 0) throw new Error("observer_policy_required");
  if (!Array.isArray(rawEvidenceRecords) || rawEvidenceRecords.length === 0) throw new Error("raw_signed_enrollment_records_required");
  const seenEvents = new Set();
  const seenReceipts = new Set();
  return rawEvidenceRecords.map((record, index) => {
    if (!record || typeof record !== "object") throw new Error(`raw_record_invalid:${index}`);
    const event = record.enrollment_event ?? record.event;
    if (!event) throw new Error(`raw_enrollment_event_required:${index}`);
    const observationReceipt = record.observation_receipt ?? record.observationReceipt;
    if (!observationReceipt) throw new Error(`raw_observation_receipt_required:${index}`);
    const expectedNpub = normalizeNostrPubkey(record.npub_raw_32 ?? record.npubRaw32 ?? record.expected_npub_raw_32);
    const verified = verifyEnrollmentEvent(event, {
      expectedCampaignId: campaignId,
      expectedChainId: ROBINHOOD_CHAIN_ID,
      expectedChainDomain: CHAIN_DOMAIN,
      expectedNostrPubkey: expectedNpub,
      backupArtifact: record.backup_artifact ?? record.backupArtifact ?? null,
      explicitWalletConnected: Boolean(record.explicit_wallet_connected ?? record.explicitWalletConnected),
    });
    if (!SUPPORTED_VERIFIED_ENROLLMENT_SCHEMAS.includes(verified.schema)) {
      throw new Error(`verified_enrollment_schema_not_supported:${index}`);
    }
    const expectedWallet = recordWallet(record);
    if (expectedWallet && normalizeAddress(expectedWallet) !== verified.evmAddress) throw new Error(`member_wallet_mismatch:${index}`);
    const trustedObservation = verifyObservationReceipt(observationReceipt, {
      expectedObserverPubkeys: policyPubkeys,
      expectedEventId: verified.eventId,
      expectedCampaignId: campaignId,
      expectedChainId: ROBINHOOD_CHAIN_ID,
      expectedChainDomain: CHAIN_DOMAIN,
    });
    if (!declaredRelaySet.includes(trustedObservation.sourceRelay)) {
      throw new Error(`observation_relay_not_declared:${index}`);
    }
    if (seenEvents.has(verified.eventId)) throw new Error(`duplicate_enrollment_event:${index}`);
    if (seenReceipts.has(trustedObservation.receiptId)) throw new Error(`duplicate_observation_receipt:${index}`);
    seenEvents.add(verified.eventId);
    seenReceipts.add(trustedObservation.receiptId);
    return { ...verified, trustedObservation };
  });
}

export function selectBindingForFinalization({ npubRaw32, campaignId, chainId = ROBINHOOD_CHAIN_ID, chainDomain = CHAIN_DOMAIN, enrollments, finalizationSequence, slotIndex = null }) {
  const identity = normalizeNostrPubkey(npubRaw32);
  const eligible = enrollments
    .filter((record) => record.campaignId === campaignId && record.nostrPubkey === identity)
    .filter((record) => Number(record.chainId) === Number(chainId) && String(record.chainDomain).toLowerCase() === String(chainDomain).toLowerCase())
    .filter((record) => finalizationSequence === null || trustedSequence(record) <= finalizationSequence)
    .sort(eventTieBreak);
  if (eligible.length === 0) {
    throw new Error(`missing_verified_enrollment:${identity}${slotIndex === null ? "" : `:${slotIndex}`}`);
  }
  const selected = eligible[eligible.length - 1];
  const ignoredPostFinalizationEvents =
    finalizationSequence === null
      ? []
      : enrollments
          .filter((record) => record.campaignId === campaignId && record.nostrPubkey === identity)
          .filter((record) => trustedSequence(record) > finalizationSequence)
          .sort(eventTieBreak)
          .map((record) => record.eventId);
  return {
    status: "BOUND_BEFORE_FINALIZATION",
    mode: selected.mode,
    evmAddress: selected.evmAddress,
    selectedEnrollmentEventId: selected.eventId,
    selectedObservationReceiptId: selected.trustedObservation.receiptId,
    selectedObservationSequence: selected.trustedObservation.sequence,
    selfDeclaredObservedSequenceIgnored: selected.selfDeclaredObservedSequence,
    broker: selected.broker,
    ignoredPostFinalizationEvents,
  };
}

function compileRecords({ cohortBundle, records, sourceProvenance, classification, finalizationSequence, declaredRelaySet }) {
  const campaignId = String(cohortBundle.campaign_id).toLowerCase();
  const cohortId = Number(cohortBundle.cohort_id);
  const memberCount = Number(cohortBundle.member_count);
  const leaves = records.map((record) => record.leaf);
  const root = merkleRoot(leaves);
  const recordsWithProofs = records.map((record) => ({
    ...record,
    proof: merkleProof(leaves, record.slotIndex),
  }));
  for (const record of recordsWithProofs) {
    if (record.proof.length > MAX_PROOF_LENGTH) throw new Error(`proof_length_exceeds_max:${record.slotIndex}`);
  }
  const selectedCount = recordsWithProofs.length;
  const emptyCount = memberCount - selectedCount;
  const manifest = {
    schema: ROSTER_MANIFEST_SCHEMA,
    version: 2,
    campaignId,
    chain: cohortBundle.chain,
    chainId: Number(cohortBundle.chain_id),
    chainDomain: String(cohortBundle.chain_domain).toLowerCase(),
    cohortId,
    contractCohortName: String(cohortBundle.cohort_name).toUpperCase(),
    publicCohortName: COHORT_PUBLIC_NAMES[cohortId],
    memberCount,
    capacity: memberCount,
    selectedCount,
    slotAssignment: {
      mode: "DENSE_PREFIX_NO_PADDING",
      assigned: { start: 0, endExclusive: selectedCount, count: selectedCount },
      emptyTail: {
        start: selectedCount,
        endExclusive: memberCount,
        count: emptyCount,
        permanentlyUnclaimable: true,
        fillAfterFinalizationAllowed: false,
      },
    },
    declaredRelaySet,
    declaredRelaySetHash: keccak256Hex(utf8Bytes(canonicalJson(declaredRelaySet))),
    maxProofLength: MAX_PROOF_LENGTH,
    maximumCapacityProofLength: Math.ceil(Math.log2(Math.max(...Object.values(ROBINHOOD_COHORT_CAPACITIES)))),
    maximumCapacityProofHeadroom: MAX_PROOF_LENGTH - Math.ceil(Math.log2(Math.max(...Object.values(ROBINHOOD_COHORT_CAPACITIES)))),
    finalizationSequence,
    root,
    classification,
    finalizable: classification === "PRODUCTION_VERIFIED_ENROLLMENT",
    bindingObservationOrder: classification === "PRODUCTION_VERIFIED_ENROLLMENT" ? "signed_observation_receipt_sequence_then_event_id" : "none_unproven_historical",
    selfTimestampUsedForOrdering: false,
    selfDeclaredSequenceUsedForOrdering: false,
    sourceProvenance,
    recordCount: recordsWithProofs.length,
    manifestHash: null,
  };
  manifest.manifestHash = keccak256Hex(utf8Bytes(canonicalJson({ ...manifest, manifestHash: null })));
  return { manifest, records: recordsWithProofs };
}

export function compileEnrollmentRoster({ cohortBundle, campaignConstitution = null, declaredRelaySet = null, rawEvidenceRecords = null, verifiedEnrollments = [], observationReceipts = [], observerPolicy = null, finalizationSequence, sourceProvenance }) {
  if (!Number.isSafeInteger(finalizationSequence) && finalizationSequence !== null) throw new Error("finalization_sequence_required");
  const campaignId = String(cohortBundle.campaign_id).toLowerCase();
  const { cohortId, capacity: memberCount, proofs } = validateCohortBundle(cohortBundle, { campaignConstitution, requireConstitution: true });
  const normalizedRelaySet = normalizeRelaySet(declaredRelaySet, { required: true });
  if ((verifiedEnrollments?.length ?? 0) !== 0 || (observationReceipts?.length ?? 0) !== 0) {
    throw new Error("pre_normalized_verified_enrollments_are_not_production_authority");
  }
  const enrollments = recordsFromRawEvidence({ rawEvidenceRecords, observerPolicy, campaignId, declaredRelaySet: normalizedRelaySet });
  const records = proofs
    .map((proof) => {
      const binding = selectBindingForFinalization({
        npubRaw32: proof.npub_raw_32,
        campaignId,
        chainId: Number(cohortBundle.chain_id),
        chainDomain: String(cohortBundle.chain_domain).toLowerCase(),
        enrollments,
        finalizationSequence,
        slotIndex: Number(proof.slot_index),
      });
      const leaf = robinhoodLeafHash({
        campaignId,
        cohortId,
        slotIndex: Number(proof.slot_index),
        memberCount,
        npubRaw32: proof.npub_raw_32,
        wallet: binding.evmAddress,
      });
      return {
        cohortId,
        cohortName: String(proof.cohort_name).toUpperCase(),
        publicCohortName: COHORT_PUBLIC_NAMES[cohortId],
        slotIndex: Number(proof.slot_index),
        memberCount,
        npubRaw32: normalizeNostrPubkey(proof.npub_raw_32),
        wallet: binding.evmAddress,
        leaf,
        binding,
      };
    });
  return compileRecords({ cohortBundle, records, sourceProvenance, classification: "PRODUCTION_VERIFIED_ENROLLMENT", finalizationSequence, declaredRelaySet: normalizedRelaySet });
}

export function compileHistoricalUnprovenRoster({ cohortBundle, sourceProvenance }) {
  const { cohortId, capacity: memberCount, proofs } = validateCohortBundle(cohortBundle, { requireConstitution: false });
  const campaignId = String(cohortBundle.campaign_id).toLowerCase();
  const records = proofs
    .map((proof) => {
      const leaf = robinhoodLeafHash({
        campaignId,
        cohortId,
        slotIndex: Number(proof.slot_index),
        memberCount,
        npubRaw32: proof.npub_raw_32,
        wallet: proof.wallet,
      });
      return {
        cohortId,
        cohortName: String(proof.cohort_name).toUpperCase(),
        publicCohortName: COHORT_PUBLIC_NAMES[cohortId],
        slotIndex: Number(proof.slot_index),
        memberCount,
        npubRaw32: normalizeNostrPubkey(proof.npub_raw_32),
        wallet: normalizeAddress(proof.wallet),
        leaf,
        binding: {
          status: "UNPROVEN_HISTORICAL",
          mode: "historical_roster_wallet_unproven_v0",
          evmAddress: normalizeAddress(proof.wallet),
          selectedEnrollmentEventId: null,
          ignoredPostFinalizationEvents: [],
          finalizable: false,
        },
      };
    });
  return compileRecords({ cohortBundle, records, sourceProvenance, classification: "UNPROVEN_HISTORICAL", finalizationSequence: null, declaredRelaySet: [] });
}

export function buildPortableProofBundle({ compiledRoster, slotIndex, distributorAddress, launchedTokenAddress, sourceCommit, buildManifestHash = null }) {
  if (compiledRoster.manifest.classification !== "PRODUCTION_VERIFIED_ENROLLMENT") throw new Error("portable_bundle_requires_verified_roster");
  const record = compiledRoster.records.find((item) => item.slotIndex === slotIndex);
  if (!record) throw new Error(`slot ${slotIndex} not found`);
  if (!verifyMerkleProof({ leaf: record.leaf, proof: record.proof, root: compiledRoster.manifest.root })) {
    throw new Error("compiled proof does not verify");
  }
  return {
    schema: PORTABLE_PROOF_BUNDLE_SCHEMA,
    version: 2,
    campaign: {
      campaignId: compiledRoster.manifest.campaignId,
      chain: "robinhood",
      chainId: compiledRoster.manifest.chainId,
      chainDomain: compiledRoster.manifest.chainDomain,
    },
    contracts: {
      distributor: normalizeAddress(distributorAddress),
      launchedToken: normalizeAddress(launchedTokenAddress),
      distributorInterface: "BermRobinhoodDistributorV01.claimBuyback(uint8,uint32,bytes32,address,bytes32[],uint256,uint256)",
      buybackPath: "full-pocket-fixed-route-after-graduation",
    },
    supporter: {
      verifiedNostrPubkey: record.npubRaw32,
      npubRaw32: record.npubRaw32,
      mode: record.binding.mode,
      committedDestination: record.wallet,
      cohortId: record.cohortId,
      contractCohortName: record.cohortName,
      publicCohortName: record.publicCohortName,
      slotIndex: record.slotIndex,
      memberCount: record.memberCount,
      bindingStatus: record.binding.status,
      selectedEnrollmentEventId: record.binding.selectedEnrollmentEventId,
      selectedObservationReceiptId: record.binding.selectedObservationReceiptId,
      selectedObservationSequence: record.binding.selectedObservationSequence,
      ignoredPostFinalizationEvents: record.binding.ignoredPostFinalizationEvents,
    },
    merkle: {
      leafVersion: 1,
      leaf: record.leaf,
      root: compiledRoster.manifest.root,
      proof: record.proof,
      leafData: {
        cohortId: record.cohortId,
        slotIndex: record.slotIndex,
        memberCount: record.memberCount,
        npubRaw32: record.npubRaw32,
        wallet: record.wallet,
      },
    },
    manifests: {
      rosterManifestHash: compiledRoster.manifest.manifestHash,
      buildManifestHash,
      rootFinalizationSequence: compiledRoster.manifest.finalizationSequence,
      capacity: compiledRoster.manifest.capacity,
      selectedCount: compiledRoster.manifest.selectedCount,
      slotAssignment: compiledRoster.manifest.slotAssignment,
      declaredRelaySet: compiledRoster.manifest.declaredRelaySet,
      declaredRelaySetHash: compiledRoster.manifest.declaredRelaySetHash,
    },
    sourceProvenance: {
      sourceCommit,
      currentRepoHeadWasImplementationBase: true,
      predecessorSourceCopiedWholesale: false,
    },
    independentUse: [
      "Use any public Robinhood RPC endpoint for chain 4663.",
      "Read Distributor cohort root and graduation status from the public contract.",
      "Connect the ordinary EVM wallet equal to committedDestination.",
      "Call claimBuyback with this bundle's leaf data, proof, minTokensOut, and deadline.",
      "Do not send private keys, seed phrases, passphrases, or Nostr secrets to BermLaunch or signer.xonly.ai.",
    ],
    noSecrets: true,
    dependencies: {
      bermlaunchWebsiteRequired: false,
      signerXonlyRequiredAfterFinalization: false,
      apiIndexerRequiredAfterFinalization: false,
      bagsUpstreamAuthorityDisclosure: "Bags can change future claimers and upgrade upstream infrastructure; disclosed dependency.",
    },
  };
}

export function simulateWebsiteIndependentClaim({ bundle, connectedWallet, routeAvailable = true, minTokensOut = "1", deadlineUnix = 1_800_000_000 }) {
  const wallet = normalizeAddress(connectedWallet);
  if (bundle.schema !== PORTABLE_PROOF_BUNDLE_SCHEMA) throw new Error("unsupported_bundle_schema");
  if (wallet !== bundle.supporter.committedDestination) {
    return { status: "REJECTED_WRONG_WALLET", pocketConsumed: false, reason: "connected wallet differs from committed destination" };
  }
  const leaf = robinhoodLeafHash({
    campaignId: bundle.campaign.campaignId,
    cohortId: bundle.merkle.leafData.cohortId,
    slotIndex: bundle.merkle.leafData.slotIndex,
    memberCount: bundle.merkle.leafData.memberCount,
    npubRaw32: bundle.merkle.leafData.npubRaw32,
    wallet: bundle.merkle.leafData.wallet,
  });
  if (leaf !== bundle.merkle.leaf) {
    return { status: "REJECTED_LEAF_MISMATCH", pocketConsumed: false, reason: "bundle leaf data does not hash to leaf" };
  }
  if (!verifyMerkleProof({ leaf, proof: bundle.merkle.proof, root: bundle.merkle.root })) {
    return { status: "REJECTED_PROOF", pocketConsumed: false, reason: "proof does not match root" };
  }
  if (!routeAvailable) {
    return { status: "ROUTE_DOWN", pocketConsumed: false, reason: "fixed buyback route unavailable; entitlement remains in pocket accounting" };
  }
  return {
    status: "READY_TO_AUTHORIZE",
    pocketConsumed: false,
    bermlaunchWebsiteRequired: false,
    signerXonlyRequired: false,
    call: {
      contract: bundle.contracts.distributor,
      method: "claimBuyback",
      args: [
        bundle.merkle.leafData.cohortId,
        bundle.merkle.leafData.slotIndex,
        bundle.merkle.leafData.npubRaw32,
        bundle.merkle.leafData.wallet,
        bundle.merkle.proof,
        String(minTokensOut),
        Number(deadlineUnix),
      ],
    },
  };
}
