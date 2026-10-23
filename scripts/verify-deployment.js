const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

/**
 * @title Deployment Verifier (T10)
 * @notice Cryptographically and functionally verifies a live deployment against its manifest:
 *         1. Chain ID and RPC availability
 *         2. Bytecode existence and keccak256 hash parity against manifest
 *         3. Bootstrap finalization and privilege revocation status
 *         4. Active participant threshold (>= 4)
 *         5. Cross-contract integration verification (AuditEngine, InsiderLog, ForensicTrail, MultiSig)
 */
async function verifyDeployment(manifestPath, rpcUrl) {
  const targetManifestPath =
    manifestPath ||
    path.join(__dirname, "..", "deployments", "deployment-manifest.json");

  if (!fs.existsSync(targetManifestPath)) {
    throw new Error(
      `[FAIL] Deployment manifest not found at ${targetManifestPath}. Run scripts/deploy.js first.`
    );
  }

  const manifest = JSON.parse(fs.readFileSync(targetManifestPath, "utf-8"));
  const targetRpcUrl =
    rpcUrl ||
    process.env.RPC_URL ||
    process.env.BLOCKCHAIN_RPC_URL ||
    manifest.rpc_url ||
    "http://127.0.0.1:8545";

  console.log("====================================================");
  console.log(`Verifying Deployment for: ${manifest.institution_id || "UNKNOWN"}`);
  console.log(`Manifest Path: ${targetManifestPath}`);
  console.log(`Target RPC: ${targetRpcUrl}`);
  console.log("====================================================");

  const provider = new ethers.JsonRpcProvider(targetRpcUrl);

  // 1. Verify RPC and Chain ID
  let network;
  try {
    network = await provider.getNetwork();
  } catch (err) {
    throw new Error(
      `[FAIL] RPC provider unreachable at ${targetRpcUrl}: ${err.message}`
    );
  }

  const actualChainId = Number(network.chainId);
  if (manifest.chain_id && actualChainId !== Number(manifest.chain_id)) {
    throw new Error(
      `[FAIL] Chain ID mismatch: expected ${manifest.chain_id}, connected to ${actualChainId}`
    );
  }
  console.log(`[PASS] Chain ID verified: ${actualChainId}`);

  // 2. Verify Contract Bytecode and Code Hashes
  const contracts = manifest.contracts || {};
  const codeHashes = manifest.code_hashes || {};

  for (const [name, address] of Object.entries(contracts)) {
    if (!address || address === ethers.ZeroAddress) {
      throw new Error(`[FAIL] Contract ${name} has zero or undefined address`);
    }

    const code = await provider.getCode(address);
    if (!code || code === "0x") {
      throw new Error(
        `[FAIL] Contract ${name} at ${address} has no deployed bytecode (empty code)`
      );
    }

    const actualHash = ethers.keccak256(code);
    const expectedHash = codeHashes[name];
    if (expectedHash && actualHash !== expectedHash) {
      throw new Error(
        `[FAIL] Bytecode hash mismatch for ${name} at ${address}:\n  Expected: ${expectedHash}\n  Actual:   ${actualHash}`
      );
    }
    console.log(`[PASS] Bytecode verified for ${name} (${address.slice(0, 8)}...)`);
  }

  // 3. Functional Invariant Checks via Minimal ABIs
  const multiSigAddress = contracts.MultiSigApproval;
  const roleManagerAddress = contracts.RoleManager;
  const auditEngineAddress = contracts.AuditEngine;
  const insiderLogAddress = contracts.InsiderActivityLog;
  const forensicTrailAddress = contracts.ForensicTrail;

  // MultiSig Checks
  const multiSigAbi = [
    "function isBootstrapFinalized() view returns (bool)",
    "function bootstrapAuthority() view returns (address)",
    "function requiredApprovals() view returns (uint256)",
  ];
  const multiSig = new ethers.Contract(multiSigAddress, multiSigAbi, provider);

  const isFinalized = await multiSig.isBootstrapFinalized();
  if (!isFinalized) {
    throw new Error(
      "[FAIL] MultiSigApproval bootstrap is NOT finalized. System is vulnerable to re-configuration."
    );
  }
  console.log("[PASS] MultiSigApproval bootstrap finalization verified.");

  const bootstrapAuth = await multiSig.bootstrapAuthority();
  if (bootstrapAuth !== ethers.ZeroAddress) {
    throw new Error(
      `[FAIL] MultiSigApproval bootstrap authority was not revoked (current: ${bootstrapAuth})`
    );
  }
  console.log("[PASS] Bootstrap authority revocation verified (address(0)).");

  // RoleManager Participant Checks
  const roleManagerAbi = [
    "function countActiveParticipants() view returns (uint256)",
  ];
  const roleManager = new ethers.Contract(
    roleManagerAddress,
    roleManagerAbi,
    provider
  );
  const activeParticipants = await roleManager.countActiveParticipants();
  if (Number(activeParticipants) < 4) {
    throw new Error(
      `[FAIL] Insufficient active participants: expected >= 4, found ${activeParticipants}`
    );
  }
  console.log(
    `[PASS] Active participants verified: ${activeParticipants} active signers.`
  );

  // AuditEngine Integration Checks
  const auditEngineAbi = [
    "function isIntegrated() view returns (bool)",
    "function multiSig() view returns (address)",
  ];
  const auditEngine = new ethers.Contract(
    auditEngineAddress,
    auditEngineAbi,
    provider
  );

  const isIntegrated = await auditEngine.isIntegrated();
  if (!isIntegrated) {
    throw new Error(
      "[FAIL] AuditEngine is not integrated with peripheral security contracts."
    );
  }

  const linkedMultiSig = await auditEngine.multiSig();
  if (linkedMultiSig.toLowerCase() !== multiSigAddress.toLowerCase()) {
    throw new Error(
      `[FAIL] AuditEngine MultiSig reference mismatch: ${linkedMultiSig} vs ${multiSigAddress}`
    );
  }
  console.log("[PASS] AuditEngine integration verified.");

  // InsiderLog Recorder Check
  const insiderLogAbi = [
    "function isRecorder(address) view returns (bool)",
  ];
  const insiderLog = new ethers.Contract(
    insiderLogAddress,
    insiderLogAbi,
    provider
  );
  const isRecorder = await insiderLog.isRecorder(auditEngineAddress);
  if (!isRecorder) {
    throw new Error(
      "[FAIL] AuditEngine is not an authorized recorder on InsiderActivityLog."
    );
  }
  console.log("[PASS] InsiderActivityLog recorder authorization verified.");

  // ForensicTrail Writer Check
  const forensicTrailAbi = [
    "function isEvidenceWriter(address) view returns (bool)",
  ];
  const forensicTrail = new ethers.Contract(
    forensicTrailAddress,
    forensicTrailAbi,
    provider
  );
  const isWriter = await forensicTrail.isEvidenceWriter(auditEngineAddress);
  if (!isWriter) {
    throw new Error(
      "[FAIL] AuditEngine is not an authorized evidence writer on ForensicTrail."
    );
  }
  console.log("[PASS] ForensicTrail writer authorization verified.");

  console.log("====================================================");
  console.log("[SUCCESS] ALL DEPLOYMENT VERIFICATION CHECKS PASSED!");
  console.log("====================================================");
  return true;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const manifestPath = args[0] || null;
  const rpcUrl = args[1] || null;

  verifyDeployment(manifestPath, rpcUrl)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}

module.exports = { verifyDeployment };
