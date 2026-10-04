import { jcsCanonicalize } from "./sdk/bermProtocolR13a.js";
import { parseStrictJson } from "./sdk/enrollmentProtocol.js";
import { decodeNpub } from "./sdk/identityCrypto.js";
import { robinhoodLeafHash, merkleNodeHash, verifyMerkleProof } from "./sdk/enrollmentRoster.js";
import { encodeClaimBuybackCalldata } from "./sdk/referenceClient.js";
import { keccak256Hex, utf8Bytes, hexToBytes } from "./sdk/enrollmentCrypto.js";

const HASH = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const ZERO = `0x${"00".repeat(20)}`;
const fail = (code) => { throw new Error(`survive_${code}`); };
const canonical = (value) => utf8Bytes(jcsCanonicalize(value));
export function formatWeth(value) {
  const n = BigInt(value); if (n < 0n) fail("negative_amount");
  const fraction = (n % 1000000000000000000n).toString().padStart(18, "0").replace(/0+$/, "");
  return `${n / 1000000000000000000n}${fraction ? `.${fraction}` : ""} WETH`;
}
export async function sha(bytes) {
  return `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    (v) => v.toString(16).padStart(2, "0")).join("")}`;
}
export const word = (value) => {
  const n = BigInt(value);
  if (n < 0n || n >= 1n << 256n) fail("uint256_invalid");
  return n.toString(16).padStart(64, "0");
};
export const callData = (signature, words = []) => `${keccak256Hex(utf8Bytes(signature)).slice(0, 10)}${words.join("")}`;
const addressWord = (address) => {
  if (!ADDRESS.test(address) || address.toLowerCase() === ZERO) fail("address_invalid");
  return address.slice(2).toLowerCase().padStart(64, "0");
};
const bytes32Word = (hash) => { if (!HASH.test(hash)) fail("bytes32_invalid"); return hash.slice(2); };
const outputWords = (hex, count) => {
  if (typeof hex !== "string" || !/^0x(?:[0-9a-f]{64})+$/i.test(hex)
      || hex.length !== 2 + count * 64) fail("rpc_result_invalid");
  return hex.slice(2).toLowerCase().match(/.{64}/g);
};
const addressResult = (hex) => {
  const [w] = outputWords(hex, 1);
  if (!/^0{24}/.test(w)) fail("rpc_address_invalid");
  const result = `0x${w.slice(24)}`;
  if (result === ZERO) fail("not_deployed");
  return result;
};
const boolResult = (hex) => {
  const [w] = outputWords(hex, 1);
  if (BigInt(`0x${w}`) > 1n) fail("rpc_bool_invalid");
  return w.endsWith("1");
};

export async function verifyRecoveryPackage(bytes, { lawSha256, packageSha256 = null } = {}) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 32 * 1024 * 1024) fail("package_size_invalid");
  const value = parseStrictJson(bytes, "survive_package");
  if (jcsCanonicalize(value) !== new TextDecoder("utf-8", { fatal: true }).decode(bytes)) fail("package_not_canonical");
  const actualHash = await sha(bytes);
  if (packageSha256 && actualHash !== packageSha256) fail("package_hash_mismatch");
  const { index, manifest: m, proofBundle: b, law, closeReceipt: r } = value;
  if (Object.keys(value).sort().join(",") !== "closeReceipt,closeSignature,index,law,manifest,proofBundle,schema"
      || typeof value.closeSignature !== "string" || !/^0x[0-9a-f]{130}$/i.test(value.closeSignature)) fail("package_shape_invalid");
  if (value.schema !== "bermlaunch.survivability_package.v1" || index?.schema !== "bermlaunch.survivability_recovery_index.v1"
      || index.chainId !== 4663 || !ADDRESS.test(index.factoryAddress) || index.factoryAddress.toLowerCase() === ZERO
      || law?.schema !== "bermlaunch.survivability_law.v1" || !/^sha256:[0-9a-f]{64}$/.test(lawSha256 || "")) fail("package_schema_invalid");
  const lawBytes = canonical(law), manifestBytes = canonical(m), bundleBytes = canonical(b);
  if (await sha(lawBytes) !== lawSha256 || index.law?.sha256 !== lawSha256 || index.law.bytes !== lawBytes.length) fail("law_mismatch");
  if (m?.schema !== "bermlaunch.prelaunch_manifest.v02" || b?.schema !== "bermlaunch.prelaunch_proof_bundle.v02"
      || b.proofVersion !== 2 || b.proofCeiling !== 32 || !Array.isArray(b.records) || !Array.isArray(m.members)
      || !Number.isSafeInteger(b.capacity) || b.capacity < 1 || b.capacity > 0xffff_ffff
      || !Number.isSafeInteger(b.acceptedCount) || b.acceptedCount < 1 || b.acceptedCount > b.capacity
      || b.records.length !== b.acceptedCount || m.members.length !== b.acceptedCount) fail("proof_shape_invalid");
  const { contentHash, ...content } = b;
  if (await sha(canonical(content)) !== contentHash || index.proofBundle?.contentHash !== contentHash
      || index.proofBundle.sha256 !== await sha(bundleBytes) || index.proofBundle.bytes !== bundleBytes.length
      || index.manifest?.sha256 !== await sha(manifestBytes) || index.manifest.bytes !== manifestBytes.length) fail("content_hash_mismatch");
  for (const key of ["campaignId", "commitmentHash", "prelaunchRoot", "capacity", "acceptedCount"]) {
    if (index[key] !== b[key] || b[key] !== m[key]) fail("cross_binding_invalid");
  }
  if (!HASH.test(b.campaignId) || !HASH.test(b.commitmentHash) || !HASH.test(b.prelaunchRoot)
      || m.compilerHash !== b.compilerHash || !HASH.test(m.compilerHash)
      || r?.campaignId !== b.campaignId || r.commitmentHash !== b.commitmentHash
      || r.prelaunchRoot !== b.prelaunchRoot || r.evidenceManifestHash !== b.evidenceManifestHash) fail("receipt_binding_invalid");
  const evidenceHash = keccak256Hex(manifestBytes);
  if (evidenceHash !== index.evidenceManifestHash || evidenceHash !== b.evidenceManifestHash) fail("evidence_hash_mismatch");
  const rebuiltIndex = { schema: "bermlaunch.survivability_recovery_index.v1", chainId: 4663,
    factoryAddress: index.factoryAddress, campaignId: m.campaignId, commitmentHash: m.commitmentHash,
    prelaunchRoot: m.prelaunchRoot, evidenceManifestHash: evidenceHash, acceptedCount: m.acceptedCount, capacity: m.capacity,
    manifest: { sha256: await sha(manifestBytes), bytes: manifestBytes.length },
    proofBundle: { sha256: await sha(bundleBytes), bytes: bundleBytes.length, contentHash },
    law: { sha256: lawSha256, bytes: lawBytes.length } };
  if (jcsCanonicalize(index) !== jcsCanonicalize(rebuiltIndex)) fail("index_binding_invalid");
  const identities = new Set(), wallets = new Set(), leaves = [];
  for (let i = 0; i < b.records.length; ++i) {
    const record = b.records[i];
    if (record.slotIndex !== i || identities.has(record.npub) || !ADDRESS.test(record.wallet)
        || record.wallet.toLowerCase() === ZERO || !Array.isArray(record.proof) || record.proof.length > 32
        || record.proof.some((p) => !HASH.test(p)) || !/^sha256:[0-9a-f]{64}$/.test(record.recordRef)
        || !/^sha256:[0-9a-f]{64}$/.test(record.evidenceHash)) fail("founder_record_invalid");
    identities.add(record.npub); wallets.add(record.wallet.toLowerCase());
    const { leaf, proof, ...member } = record;
    if (jcsCanonicalize(member) !== jcsCanonicalize(m.members[i])) fail("member_binding_invalid");
    const expected = robinhoodLeafHash({ campaignId: b.campaignId, cohortId: 0, slotIndex: i, memberCount: b.capacity,
      npubRaw32: `0x${decodeNpub(record.npub).pubkeyHex}`, wallet: record.wallet });
    if (leaf !== expected || !verifyMerkleProof({ leaf, proof, root: b.prelaunchRoot })) fail("founder_proof_invalid");
    leaves.push(leaf);
    // Yield to the browser while auditing large packages, never skip a proof.
    if (i % 128 === 127) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? merkleNodeHash(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  if (level[0] !== b.prelaunchRoot) fail("reconstructed_root_mismatch");
  return { value, packageSha256: actualHash, lawSha256, audit: { verifiedFounders: b.records.length,
    root: level[0], evidenceManifestHash: evidenceHash, duplicateNpubs: 0, duplicateSlots: 0,
    repeatedWallets: b.records.length - wallets.size, walletPolicy: "committed destination; not required unique",
    closeAttestation: "not a standalone signature verdict; onchain authenticated root/evidence required" } };
}

export function deriveFounder(verified, search) {
  const rows = verified.value.proofBundle.records;
  const matches = rows.filter((record) => String(record.slotIndex) === search || record.npub === search
    || record.wallet.toLowerCase() === search.toLowerCase());
  if (matches.length !== 1) fail(matches.length ? "founder_search_ambiguous_use_slot" : "founder_not_found");
  return matches[0];
}

export function createReadOnlyRpc(url, fetchImpl = fetch) {
  let endpoint;
  try { endpoint = new URL(url); } catch { fail("rpc_url_invalid"); }
  if (endpoint.username || endpoint.password || endpoint.hash
      || (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname)))) fail("rpc_url_invalid");
  let sequence = 0;
  return async (method, params = []) => {
    if (!["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"].includes(method)) fail("rpc_method_forbidden");
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 20_000);
    try {
      const id = ++sequence;
      const response = await fetchImpl(endpoint.href, { method: "POST", redirect: "error", credentials: "omit", cache: "no-store",
        signal: controller.signal, headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
      if (!response.ok) fail("rpc_unavailable");
      let size = 0; const parts = [];
      for await (const chunk of response.body) { size += chunk.length; if (size > 1_048_576) { controller.abort(); fail("rpc_overflow"); } parts.push(chunk); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const part of parts) { bytes.set(part, offset); offset += part.length; }
      const body = parseStrictJson(bytes, "survive_rpc");
      if (body.jsonrpc !== "2.0" || body.id !== id || body.error || !Object.hasOwn(body, "result")) fail("rpc_unavailable");
      return body.result;
    } catch { fail("rpc_unavailable"); } finally { clearTimeout(timer); }
  };
}

export async function verifyChain(verified, rpc, identities) {
  if (await rpc("eth_chainId") !== "0x1237") fail("chain_id_mismatch");
  const block = await rpc("eth_getBlockByNumber", ["latest", false]);
  if (!/^0x[0-9a-f]+$/i.test(block?.number) || !/^0x[0-9a-f]{64}$/i.test(block?.hash)) fail("block_invalid");
  const tag = block.number;
  const read = (to, signature, words = []) => rpc("eth_call", [{ to, data: callData(signature, words) }, tag]);
  async function code(address, label = null) {
    const raw = await rpc("eth_getCode", [address, tag]);
    if (!/^0x(?:[0-9a-f]{2})+$/i.test(raw)) fail("code_missing");
    if (label) {
      const pin = identities.identities[label]?.runtime;
      const bytes = hexToBytes(raw);
      if (!pin || bytes.length !== pin.bytes) fail("code_identity_mismatch");
      for (const { start, length } of pin.immutableReferences) bytes.fill(0, start, start + length);
      if (await sha(bytes) !== `sha256:${pin.normalizedSha256}` || keccak256Hex(bytes) !== pin.normalizedKeccak256) fail("code_identity_mismatch");
    }
    return raw;
  }
  const i = verified.value.index, factory = i.factoryAddress.toLowerCase();
  await code(factory, "factory");
  const controller = addressResult(await read(factory, "controllerForCampaign(bytes32)", [bytes32Word(i.campaignId)]));
  await code(controller, "controller");
  const distributor = addressResult(await read(controller, "distributor()"));
  await code(distributor, "distributor");
  const exact = async (address, signature, expected, args = []) => {
    if ((await read(address, signature, args)).toLowerCase() !== expected.toLowerCase()) fail("chain_wiring_mismatch");
  };
  await exact(controller, "campaignId()", i.campaignId);
  await exact(distributor, "campaignId()", i.campaignId);
  await exact(distributor, "launchBinder()", `0x${addressWord(controller)}`);
  await exact(distributor, "cohortRoots(uint256)", i.prelaunchRoot, [word(0)]);
  await exact(distributor, "cohortEvidenceHashes(uint256)", i.evidenceManifestHash, [word(0)]);
  await exact(distributor, "prelaunchCapacity()", `0x${word(i.capacity)}`);
  await exact(distributor, "founderFilled()", `0x${word(i.acceptedCount)}`);
  const bagsFactory = addressResult(await read(distributor, "bagsFactory()"));
  await exact(controller, "factory()", `0x${addressWord(bagsFactory)}`);
  const lens = addressResult(await read(distributor, "bagsLens()"));
  const weth = addressResult(await read(distributor, "weth()"));
  const hook = addressResult(await read(distributor, "expectedHook()"));
  const adapter = addressResult(await read(distributor, "swapAdapter()"));
  for (const address of [bagsFactory, lens, weth, hook, adapter]) await code(address);
  await exact(lens, "FACTORY()", `0x${addressWord(bagsFactory)}`);
  await exact(bagsFactory, "weth()", `0x${addressWord(weth)}`);
  await exact(bagsFactory, "hook()", `0x${addressWord(hook)}`);
  for (const [signature, address] of [["weth()", weth], ["bagsLens()", lens], ["bagsFactory()", bagsFactory], ["hook()", hook]]) await exact(adapter, signature, `0x${addressWord(address)}`);
  let route = "NOT_LAUNCHED";
  const launchBound = boolResult(await read(distributor, "launchBound()"));
  const launched = boolResult(await read(controller, "launched()"));
  if (launchBound !== launched) fail("launch_state_mismatch");
  if (launchBound) {
    const token = addressResult(await read(distributor, "token()")); await code(token);
    const state = outputWords(await read(lens, "getTokenState(address)", [addressWord(token)]), 13);
    if (BigInt(`0x${state[0]}`) !== 1n || BigInt(`0x${state[1]}`) > 1n) fail("provider_state_mismatch");
    await exact(distributor, "bondingCurve()", `0x${state[2]}`);
    await exact(distributor, "feeShare()", `0x${state[3]}`);
    await exact(distributor, "poolId()", `0x${state[4]}`);
    route = state[1].endsWith("1") ? "V4" : "CURVE";
  }
  const recheck = await rpc("eth_getBlockByNumber", [tag, false]);
  if (recheck?.hash !== block.hash) fail("block_reorg");
  return { status: "VERIFIED", factory, controller, distributor, blockNumber: tag, blockHash: block.hash, route, read };
}

export async function computePocket(chain, founder, verified) {
  const read = (signature, words = []) => chain.read(chain.distributor, signature, words);
  const uint = async (signature, words = []) => BigInt(`0x${outputWords(await read(signature, words), 1)[0]}`);
  const totalReceived = await uint("totalReceived()");
  const entitlement = await uint("slotEntitlement(uint256,uint8,uint32)", [word(totalReceived), word(0), word(founder.slotIndex)]);
  const npub = `0x${decodeNpub(founder.npub).pubkeyHex}`;
  const identityHash = keccak256Hex(hexToBytes(`0x${bytes32Word(verified.value.index.campaignId)}${bytes32Word(npub)}`));
  const cs = outputWords(await read("claimStates(bytes32)", [bytes32Word(identityHash)]), 5);
  if (BigInt(`0x${cs[0]}`) > 1n) fail("claim_state_invalid");
  const grossSpent = BigInt(`0x${cs[4]}`);
  if (cs[0].endsWith("1") && (BigInt(`0x${cs[1]}`) !== 0n || BigInt(`0x${cs[2]}`) !== BigInt(founder.slotIndex)
      || `0x${cs[3].slice(24)}` !== founder.wallet.toLowerCase())) fail("claim_identity_mismatch");
  const proofTail = word(founder.proof.length) + founder.proof.map(bytes32Word).join("");
  const available = await uint("availableFounderPocket(uint32,bytes32,address,bytes32[])",
    [word(founder.slotIndex), bytes32Word(npub), addressWord(founder.wallet), word(128), proofTail]);
  const minimumClaimGross = await uint("minimumClaimGross()"), operatingFeeBps = await uint("operatingFeeBps()");
  const [start, end] = outputWords(await read("cohortBpsRange(uint8)", [word(0)]), 2).map((w) => BigInt(`0x${w}`));
  const cohort = totalReceived * end / 10000n - totalReceived * start / 10000n;
  const capacity = BigInt(verified.value.index.capacity), slot = BigInt(founder.slotIndex);
  const localEntitlement = cohort * (slot + 1n) / capacity - cohort * slot / capacity;
  if (entitlement !== localEntitlement || grossSpent > entitlement || available !== entitlement - grossSpent
      || start > end || end > 10000n || operatingFeeBps > 1000n) fail("arithmetic_mismatch");
  const operatingFee = available * operatingFeeBps / 10000n;
  return Object.fromEntries(Object.entries({ totalReceived, entitlement, grossSpent, available,
    minimumClaimGross, operatingFeeBps, operatingFee, netWeth: available - operatingFee,
    formatted: { totalReceived: formatWeth(totalReceived), entitlement: formatWeth(entitlement),
      grossSpent: formatWeth(grossSpent), available: formatWeth(available), minimumClaimGross: formatWeth(minimumClaimGross),
      operatingFee: formatWeth(operatingFee), netWeth: formatWeth(available - operatingFee) },
    route: chain.route, claimAvailable: chain.route !== "NOT_LAUNCHED" && available > 0n && available >= minimumClaimGross })
    .map(([key, value]) => [key, typeof value === "bigint" ? value.toString() : value]));
}

export function unsignedClaim(chain, founder, minTokensOut, deadline) {
  if (chain.status !== "VERIFIED" || chain.route === "NOT_LAUNCHED") fail("claim_unavailable");
  if (!/^[1-9]\d*$/.test(minTokensOut) || !/^[1-9]\d*$/.test(deadline)) fail("claim_limits_invalid");
  word(minTokensOut); word(deadline);
  const bundle = { merkle: { leafData: { cohortId: 0, slotIndex: founder.slotIndex,
    npubRaw32: `0x${decodeNpub(founder.npub).pubkeyHex}`, wallet: founder.wallet }, proof: founder.proof } };
  return { chainId: "0x1237", from: founder.wallet.toLowerCase(), to: chain.distributor,
    value: "0x0", data: encodeClaimBuybackCalldata({ bundle, minTokensOut, deadline }),
    minTokensOut, deadline };
}

export async function checkWallet(wallet, transaction, requestAccounts = false) {
  if (!wallet || typeof wallet.request !== "function") fail("wallet_unavailable");
  const chainId = await wallet.request({ method: "eth_chainId" });
  const accounts = await wallet.request({ method: requestAccounts ? "eth_requestAccounts" : "eth_accounts" });
  if (chainId !== transaction.chainId || !Array.isArray(accounts) || accounts[0]?.toLowerCase() !== transaction.from) fail("wallet_mismatch");
  return true;
}
