const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * @title Standard Deployment & Binding Manifest (T10, reworked in R04)
 * @notice Deploys, links, bootstraps, and verifies all Phase 1 contracts under
 *         the STANDARD EIP-170 size limit (allowUnlimitedContractSize=false):
 *         1. MultiSigApproval (Four-Eyes Principle & Governance Coordinator)
 *         2. RoleManager (RBAC with governance = multiSig)
 *         3. InsiderActivityLog (governance = multiSig)
 *         4. ForensicTrail (governance = multiSig)
 *         5. ComplianceRules (AML Thresholds & Rule Engine)
 *         6. AuditEngine (AML/KYC core engine with governance = multiSig)
 *
 * R04 contract:
 * - Roster: the four UNIQUE voting participants required by spec §5
 *   (SUPER_ADMIN + 3x AUDITOR) PLUS deliberate non-voting OPERATOR and
 *   REGULATOR enrollments in the same atomic bootstrap (they never count
 *   toward the eligible-voter quorum).
 * - TTL/time-lock are on-chain protocol constants (PROPOSAL_TTL = 259,200s
 *   = 72h, TIMELOCK_DELAY = 86,400s) and are ASSERTED post-deploy.
 * - The DeploymentBinding manifest (manifest_version=3) is written ONLY after
 *   every deployment step and invariant assertion succeeded, via temp file +
 *   atomic rename. A failed bootstrap therefore leaves no manifest for this
 *   run (and any pre-existing manifest fails verification against the new
 *   chain state, so no valid manifest survives a failed deployment).
 * - No private keys are ever written: participants carry id/account/role/reason only.
 */

const MANIFEST_VERSION = 3;
const CONTRACT_VERSION = require("../package.json").version; // 2.1.0 (single source of truth)
const EXPECTED_TTL_SECONDS = 259200n; // 72h — must equal MultiSigApproval.PROPOSAL_TTL
const EXPECTED_TIMELOCK_DELAY_SECONDS = 86400n; // must equal MultiSigApproval.TIMELOCK_DELAY

// Canonical Hardhat/ethers default test accounts, used ONLY as fallbacks when
// the runtime exposes fewer signers than the roster needs. Public deterministic
// test keys — never production secrets.
const FALLBACK_ACCOUNTS = [
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // #1
  "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", // #2
  "0x90F79bf6EB2c4f870365E785982E1f101E93b906", // #3
  "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", // #4
  "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc", // #5 (OPERATOR)
  "0x976EA74026E726554dB657fA54763abd0C3a0aa9", // #6 (REGULATOR)
];

function signerOr(index) {
  return signerCache[index] || FALLBACK_ACCOUNTS[index];
}

let signerCache = [];

/**
 * Atomic file write: temp file in the same directory, fsync, rename over target.
 * On Windows libuv renames with MOVEFILE_REPLACE_EXISTING, so this replaces
 * an existing manifest atomically.
 */
function writeFileAtomic(filePath, data) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(
    dir,
    `.${path.basename(filePath)}.tmp-${process.pid}-${Date.now()}`
  );
  const fd = fs.openSync(tmpPath, "w");
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* tmp cleanup best-effort */
    }
    throw err;
  }
}

async function runDeployment(options = {}) {
  const persistFiles = options.persistFiles !== false;
  console.log("====================================================");
  console.log("Starting Cyber-Forensic Auditing Framework Deployment (V2, standard size limit)");
  console.log("====================================================");

  const signers = await hre.ethers.getSigners();
  signerCache = signers;
  const deployer = signers[0];
  console.log(`Deployer address: ${deployer.address}`);
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`Deployer balance: ${hre.ethers.formatEther(balance)} ETH\n`);

  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const institutionId = process.env.INSTITUTION_ID || "INST-CENTRAL-DEMO";

  // 1. Deploy MultiSigApproval (deployer is temporary bootstrap authority, 2
  //    required approvals; TTL 259,200s and time-lock 86,400s are fixed
  //    protocol constants since R03)
  console.log("1. Deploying MultiSigApproval...");
  const MultiSigApproval = await hre.ethers.getContractFactory("MultiSigApproval");
  const multiSig = await MultiSigApproval.deploy(deployer.address, 2);
  await multiSig.waitForDeployment();
  const multiSigAddress = await multiSig.getAddress();
  console.log(`   -> MultiSigApproval deployed at: ${multiSigAddress}`);

  // 2. Deploy RoleManager with governance = multiSig
  console.log("2. Deploying RoleManager...");
  const RoleManager = await hre.ethers.getContractFactory("RoleManager");
  const roleManager = await RoleManager.deploy(multiSigAddress);
  await roleManager.waitForDeployment();
  const roleManagerAddress = await roleManager.getAddress();
  console.log(`   -> RoleManager deployed at: ${roleManagerAddress}`);

  // 3. Deploy InsiderActivityLog with governance = multiSig
  console.log("3. Deploying InsiderActivityLog...");
  const InsiderActivityLog = await hre.ethers.getContractFactory("InsiderActivityLog");
  const insiderLog = await InsiderActivityLog.deploy(multiSigAddress);
  await insiderLog.waitForDeployment();
  const insiderLogAddress = await insiderLog.getAddress();
  console.log(`   -> InsiderActivityLog deployed at: ${insiderLogAddress}`);

  // 4. Deploy ForensicTrail with governance = multiSig
  console.log("4. Deploying ForensicTrail...");
  const ForensicTrail = await hre.ethers.getContractFactory("ForensicTrail");
  const forensicTrail = await ForensicTrail.deploy(multiSigAddress);
  await forensicTrail.waitForDeployment();
  const forensicTrailAddress = await forensicTrail.getAddress();
  console.log(`   -> ForensicTrail deployed at: ${forensicTrailAddress}`);

  // 5. Deploy ComplianceRules
  console.log("5. Deploying ComplianceRules...");
  const ComplianceRules = await hre.ethers.getContractFactory("ComplianceRules");
  const complianceRules = await ComplianceRules.deploy();
  await complianceRules.waitForDeployment();
  const complianceRulesAddress = await complianceRules.getAddress();
  console.log(`   -> ComplianceRules deployed at: ${complianceRulesAddress}`);

  // 6. Deploy AuditEngine with governance = multiSig
  console.log("6. Deploying AuditEngine...");
  const AuditEngine = await hre.ethers.getContractFactory("AuditEngine");
  const auditEngine = await AuditEngine.deploy(multiSigAddress);
  await auditEngine.waitForDeployment();
  const auditEngineAddress = await auditEngine.getAddress();
  console.log(`   -> AuditEngine deployed at: ${auditEngineAddress}`);

  // 7. Atomic cross-contract wiring (also grants recorder/writer roles)
  console.log("7. Configuring contracts and cross-contract authorizations...");
  const configTx = await multiSig.configureContracts(
    roleManagerAddress,
    auditEngineAddress,
    insiderLogAddress,
    forensicTrailAddress
  );
  await configTx.wait();
  console.log("   -> Cross-contract wiring configured successfully.");

  // 8. Bootstrap the institutional roster (spec §5 + R04 operational roles):
  //    - 4 UNIQUE ELIGIBLE voters (SUPER_ADMIN + 3 AUDITOR)
  //    - 1 non-voting OPERATOR (daily transactions) and 1 non-voting REGULATOR
  //      (external oversight), enrolled deliberately in the same atomic call.
  console.log("8. Bootstrapping institutional roster (4 eligible voters + OPERATOR + REGULATOR)...");
  const participantAccounts = [0, 1, 2, 3, 4, 5].map((i) => signerOr(i));
  // Deterministic institutional roster fixture ids (fixed off-chain roster
  // values, never derived from names or addresses — R02).
  const participantIds = [
    hre.ethers.id("INST-GOVERNANCE-01"),
    hre.ethers.id("INST-AUDIT-01"),
    hre.ethers.id("INST-AUDIT-02"),
    hre.ethers.id("INST-AUDIT-03"),
    hre.ethers.id("INST-OPERATIONS-01"),
    hre.ethers.id("INST-REGULATOR-01"),
  ];
  const participantRoles = [1, 2, 2, 2, 3, 4]; // SUPER_ADMIN, AUDITOR x3, OPERATOR, REGULATOR
  const participantReasons = [
    "SYSTEM: Chief Governance & Compliance Admin",
    "SYSTEM: Primary Forensic Compliance Auditor",
    "SYSTEM: Secondary Forensic Compliance Auditor",
    "SYSTEM: Tertiary Forensic Compliance Auditor",
    "SYSTEM: Daily Transaction Operator (non-voting)",
    "SYSTEM: External Regulator Observer (non-voting)",
  ];

  const bootstrapTx = await multiSig.bootstrapParticipants(
    participantIds,
    participantAccounts,
    participantRoles,
    participantReasons
  );
  await bootstrapTx.wait();
  console.log("   -> 6 roster participants enrolled (4 eligible voters + OPERATOR + REGULATOR).");

  // 9. Finalize Bootstrap and revoke deployer bootstrap authority permanently
  console.log("9. Finalizing bootstrap and revoking bootstrap privileges...");
  const finalizeTx = await multiSig.finalizeBootstrap();
  const finalizeReceipt = await finalizeTx.wait();
  console.log("   -> Bootstrap finalized. BootstrapAuthority revoked permanently.");

  // 10. Post-deployment invariant assertions — the manifest is only written if
  //     every one of these holds (a failed bootstrap leaves no valid manifest).
  console.log("10. Asserting on-chain deployment invariants...");
  const assertEq = (label, actual, expected) => {
    if (String(actual) !== String(expected)) {
      throw new Error(`Deployment invariant violated: ${label} = ${actual}, expected ${expected}`);
    }
    console.log(`   -> ${label} = ${actual}`);
  };

  assertEq("PROPOSAL_TTL (72h)", (await multiSig.PROPOSAL_TTL()).toString(), EXPECTED_TTL_SECONDS.toString());
  assertEq("TIMELOCK_DELAY", (await multiSig.TIMELOCK_DELAY()).toString(), EXPECTED_TIMELOCK_DELAY_SECONDS.toString());
  assertEq("requiredApprovals", await multiSig.requiredApprovals(), 2);
  assertEq("isBootstrapFinalized", await multiSig.isBootstrapFinalized(), true);
  assertEq("bootstrapAuthority revoked", await multiSig.bootstrapAuthority(), hre.ethers.ZeroAddress);
  assertEq("eligible participants", await roleManager.countEligibleParticipants(), 4);
  assertEq("active participants", await roleManager.countActiveParticipants(), participantAccounts.length);
  assertEq("AuditEngine.isIntegrated", await auditEngine.isIntegrated(), true);
  assertEq("AuditEngine.multiSig wiring", await auditEngine.multiSig(), multiSigAddress);
  assertEq("InsiderLog recorder=AuditEngine", await insiderLog.isRecorder(auditEngineAddress), true);
  assertEq("ForensicTrail writer=AuditEngine", await forensicTrail.isEvidenceWriter(auditEngineAddress), true);

  // 11. Compute deployed runtime code hashes for cryptographic verification
  const contractAddresses = {
    RoleManager: roleManagerAddress,
    InsiderActivityLog: insiderLogAddress,
    ForensicTrail: forensicTrailAddress,
    ComplianceRules: complianceRulesAddress,
    MultiSigApproval: multiSigAddress,
    AuditEngine: auditEngineAddress,
  };

  const deployedCodeHashes = {};
  for (const [name, addr] of Object.entries(contractAddresses)) {
    const code = await hre.ethers.provider.getCode(addr);
    deployedCodeHashes[name] = hre.ethers.keccak256(code);
  }

  // 12. Build the authoritative DeploymentBinding manifest (R04, manifest_version=3)
  const deployedAtBlock = finalizeReceipt.blockNumber;
  const manifest = {
    manifest_version: MANIFEST_VERSION,
    deployment_id: hre.ethers.id(
      `deployment:${chainId}:${multiSigAddress}:${finalizeReceipt.blockHash}`
    ),
    institution_id: institutionId,
    chain_id: chainId,
    network: hre.network.name,
    contract_version: CONTRACT_VERSION,
    status: "active",
    deployed_at: new Date().toISOString(),
    deployed_at_block: deployedAtBlock,
    // Spec §7: local/ephemeral chains settle with 2 confirmations; public
    // networks use a conservative 12.
    confirmation_depth: chainId === 31337 ? 2 : 12,
    deployer: deployer.address,
    bootstrap_finalized: true,
    addresses: contractAddresses,
    deployed_code_hashes: deployedCodeHashes,
    governance: {
      required_approvals: 2,
      proposal_ttl_seconds: Number(EXPECTED_TTL_SECONDS),
      timelock_delay_seconds: Number(EXPECTED_TIMELOCK_DELAY_SECONDS),
      eligible_participants: 4,
      active_participants: participantAccounts.length,
    },
    participants: participantAccounts.map((account, idx) => ({
      participant_id: participantIds[idx],
      account,
      role: participantRoles[idx],
      reason: participantReasons[idx],
    })),
  };

  console.log("\n====================================================");
  console.log("Deployment Manifest (v3):");
  console.log(JSON.stringify(manifest, null, 2));
  console.log("====================================================");

  if (!persistFiles) {
    console.log("[DRY-RUN] persistFiles=false — manifest not written to disk.");
    return manifest;
  }

  // 13. Persist artifacts. The manifest — the authoritative record — is written
  //     LAST, after every other step has already succeeded, atomically.
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  const manifestPath = path.join(deploymentsDir, "deployment-manifest.json");
  writeFileAtomic(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`[SUCCESS] Manifest (v${MANIFEST_VERSION}) written atomically to ${manifestPath}`);

  // 14. Export runtime config for frontend (derived convenience artifact)
  const runtimeConfig = {
    institution_id: institutionId,
    chain_id: chainId,
    rpc_url: process.env.VITE_RPC_URL || "http://127.0.0.1:8545",
    ai_engine_url: process.env.VITE_AI_ENGINE_URL || "/api",
    app_mode: process.env.APP_MODE || "demo",
    contract_version: CONTRACT_VERSION,
    contracts: contractAddresses,
  };
  const frontendPublicDir = path.join(__dirname, "..", "frontend", "public");
  if (!fs.existsSync(frontendPublicDir)) {
    fs.mkdirSync(frontendPublicDir, { recursive: true });
  }
  const frontendConfigPath = path.join(frontendPublicDir, "runtime-config.json");
  writeFileAtomic(frontendConfigPath, JSON.stringify(runtimeConfig, null, 2) + "\n");
  console.log(`[SUCCESS] Exported frontend runtime config to ${frontendConfigPath}`);

  return manifest;
}

async function main() {
  const manifest = await runDeployment({ persistFiles: true });
  return manifest;
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error("Deployment failed:", error);
      process.exit(1);
    });
}

module.exports = { main, runDeployment, writeFileAtomic, MANIFEST_VERSION, CONTRACT_VERSION };
