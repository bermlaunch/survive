import { concatBytes, hexToBytes, keccak256Hex, strip0x, utf8Bytes } from "./enrollmentCrypto.js";
import { normalizeAddress } from "./enrollmentProtocol.js";
import { robinhoodLeafHash, simulateWebsiteIndependentClaim, verifyMerkleProof } from "./enrollmentRoster.js";

export const REFERENCE_CLIENT_SCHEMA = "bermlaunch.supporter_reference_client.r2";

function selector(signature) {
  return strip0x(keccak256Hex(utf8Bytes(signature))).slice(0, 8);
}

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

function wordFromBool(value) {
  return wordFromBigInt(value ? 1n : 0n);
}

function bytesToHex(bytes) {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function normalizeRpcHex(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/.test(value)) throw new Error("rpc_hex_invalid");
  return value.toLowerCase();
}

export function encodeClaimBuybackCalldata({ bundle, minTokensOut = "1", deadline = 1_800_000_000 }) {
  const args = bundle.merkle.leafData;
  const proof = bundle.merkle.proof ?? [];
  const head = concatBytes(
    wordFromBigInt(args.cohortId),
    wordFromBigInt(args.slotIndex),
    wordFromBytes32(args.npubRaw32),
    wordFromAddress(args.wallet),
    wordFromBigInt(32n * 7n),
    wordFromBigInt(BigInt(minTokensOut)),
    wordFromBigInt(BigInt(deadline)),
  );
  const tail = concatBytes(wordFromBigInt(proof.length), ...proof.map(wordFromBytes32));
  return `0x${selector("claimBuyback(uint8,uint32,bytes32,address,bytes32[],uint256,uint256)")}${strip0x(bytesToHex(concatBytes(head, tail)))}`;
}

function encodeViewCall(signature, words = []) {
  return `0x${selector(signature)}${words.map((word) => strip0x(bytesToHex(word))).join("")}`;
}

async function rpc(fetchImpl, rpcUrl, method, params) {
  const response = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!response.ok) throw new Error(`rpc_http_${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`rpc_error:${body.error.message ?? body.error.code}`);
  return body.result;
}

export async function runIndependentReferenceClient({ bundle, connectedWallet, rpcUrl, fetchImpl = globalThis.fetch, minTokensOut = "1", deadline = 1_800_000_000 }) {
  const claimLocal = simulateWebsiteIndependentClaim({ bundle, connectedWallet, routeAvailable: true, minTokensOut, deadlineUnix: deadline });
  const leaf = robinhoodLeafHash({
    campaignId: bundle.campaign.campaignId,
    cohortId: bundle.merkle.leafData.cohortId,
    slotIndex: bundle.merkle.leafData.slotIndex,
    memberCount: bundle.merkle.leafData.memberCount,
    npubRaw32: bundle.merkle.leafData.npubRaw32,
    wallet: bundle.merkle.leafData.wallet,
  });
  if (leaf !== bundle.merkle.leaf) throw new Error("reference_leaf_mismatch");
  if (!verifyMerkleProof({ leaf, proof: bundle.merkle.proof, root: bundle.merkle.root })) throw new Error("reference_proof_root_mismatch");
  const calldata = encodeClaimBuybackCalldata({ bundle, minTokensOut, deadline });
  const result = {
    schema: REFERENCE_CLIENT_SCHEMA,
    localProof: "PASS",
    claimLocal,
    calldata,
    rpcReadback: "T07_RPC_READBACK_OR_EXECUTION_PENDING",
    ethCall: "T07_ETH_CALL_OR_FORK_SIM_PENDING",
  };
  if (!rpcUrl) return result;
  if (!fetchImpl) throw new Error("fetch_required_for_rpc_readback");
  const distributor = bundle.contracts.distributor;
  const cohortRootData = encodeViewCall("cohortRoots(uint256)", [wordFromBigInt(bundle.merkle.leafData.cohortId)]);
  const graduatedData = encodeViewCall("graduatedActive()", []);
  const [contractRootRaw, graduatedRaw] = await Promise.all([
    rpc(fetchImpl, rpcUrl, "eth_call", [{ to: distributor, data: cohortRootData }, "latest"]),
    rpc(fetchImpl, rpcUrl, "eth_call", [{ to: distributor, data: graduatedData }, "latest"]),
  ]);
  const contractRoot = normalizeRpcHex(contractRootRaw);
  const graduated = normalizeRpcHex(graduatedRaw).endsWith("1");
  result.rpcReadback = contractRoot === bundle.merkle.root.toLowerCase() ? "PASS" : "REJECTED_ROOT_MISMATCH";
  result.contractRoot = contractRoot;
  result.graduatedActive = graduated;
  const ethCallRaw = await rpc(fetchImpl, rpcUrl, "eth_call", [{ from: normalizeAddress(connectedWallet), to: distributor, data: calldata }, "latest"]);
  result.ethCall = normalizeRpcHex(ethCallRaw);
  return result;
}