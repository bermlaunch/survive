import { verifyRecoveryPackage, deriveFounder, createReadOnlyRpc, verifyChain, computePocket, unsignedClaim, checkWallet } from "./core.mjs";
const $ = (id) => document.getElementById(id);
const config = await (await fetch("./config.json", { cache: "no-store" })).json();
const identities = await (await fetch("./code-identities.json", { cache: "no-store" })).json();
let verified = null, chain = null, founder = null, pocket = null, transaction = null, rpc = null;
const show = (id, value) => { $(id).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2); };
function invalidate() {
  verified = chain = founder = pocket = transaction = rpc = null;
  for (const id of ["derive", "compute", "claim", "download", "copy", "wallet", "send", "audit"]) $(id).disabled = true;
  for (const id of ["founder", "pocket", "transaction", "audit-report"]) show(id, "");
}
function download(value, name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const run = (operation) => async () => {
  $("send").disabled = true;
  try { await operation(); } catch (error) { show("status", `MISMATCH / UNAVAILABLE: ${error.message}`); }
};
for (const id of ["package", "package-hash", "rpc"]) $(id).addEventListener("change", invalidate);
for (const id of ["search", "minimum", "deadline"]) $(id).addEventListener("input", () => {
  transaction = null; $("send").disabled = $("wallet").disabled = $("copy").disabled = $("download").disabled = true;
  if (id === "search") { founder = pocket = null; $("compute").disabled = $("claim").disabled = true; }
});
$("verify").onclick = run(async () => {
  invalidate(); show("status", "VERIFYING — every Founder proof is checked");
  const file = $("package").files[0]; if (!file) throw new Error("package_required");
  verified = await verifyRecoveryPackage(new Uint8Array(await file.arrayBuffer()), {
    lawSha256: config.lawSha256, packageSha256: $("package-hash").value.trim() || null });
  $("audit").disabled = false;
  rpc = createReadOnlyRpc($("rpc").value.trim());
  chain = await verifyChain(verified, rpc, identities);
  show("status", `VERIFIED — package ${verified.packageSha256}; same-block chain ${chain.blockNumber}; route ${chain.route}`);
  $("derive").disabled = false;
});
$("derive").onclick = run(async () => {
  founder = deriveFounder(verified, $("search").value.trim()); pocket = transaction = null;
  show("founder", { ...founder, proofStatus: "VERIFIED" }); $("compute").disabled = false;
});
$("compute").onclick = run(async () => {
  pocket = transaction = null; $("claim").disabled = true;
  chain = await verifyChain(verified, rpc, identities);
  pocket = await computePocket(chain, founder, verified); show("pocket", pocket);
  $("claim").disabled = !pocket.claimAvailable;
});
$("claim").onclick = run(async () => {
  if (!pocket?.claimAvailable) throw new Error("claim_unavailable");
  const deadline = $("deadline").value.trim();
  if (BigInt(deadline || "0") <= BigInt(Math.floor(Date.now() / 1000))) throw new Error("deadline_expired");
  transaction = unsignedClaim(chain, founder, $("minimum").value.trim(), deadline);
  show("transaction", transaction);
  $("download").disabled = $("copy").disabled = false; $("wallet").disabled = !window.ethereum;
});
$("download").onclick = () => download(transaction, "unsigned-founder-claim.json");
$("copy").onclick = run(async () => navigator.clipboard.writeText(transaction.data));
$("wallet").onclick = run(async () => {
  await checkWallet(window.ethereum, transaction, true);
  show("status", "Wallet matches. Review displayed chain, target, calldata, minimum output and deadline. Send is a separate explicit action.");
  $("send").disabled = false;
});
$("send").onclick = run(async () => {
  if (!transaction) throw new Error("unsigned_transaction_required");
  await checkWallet(window.ethereum, transaction, false);
  const currentChain = await verifyChain(verified, rpc, identities);
  const currentPocket = await computePocket(currentChain, founder, verified);
  if (!currentPocket.claimAvailable || currentChain.distributor !== transaction.to
      || BigInt(transaction.deadline) <= BigInt(Math.floor(Date.now() / 1000))) throw new Error("claim_unavailable");
  // Sole write boundary. User pressed this exact enabled button after reviewing
  // the unsigned transaction. No automatic retry or secret input exists.
  const { chainId, from, to, value, data } = transaction;
  transaction = null;
  const hash = await window.ethereum.request({ method: "eth_sendTransaction", params: [{ chainId, from, to, value, data }] });
  show("status", `Submitted by installed wallet: ${hash}`);
});
$("audit").onclick = run(async () => {
  show("audit-report", verified.audit); download({ ...verified.audit, packageSha256: verified.packageSha256,
    lawSha256: verified.lawSha256, chain: chain ? { status: chain.status, blockHash: chain.blockHash } : "not_verified" }, "founder-audit.json");
});
