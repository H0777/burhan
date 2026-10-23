const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * @title Production & Local Deployment Script (T10)
 * @notice Deploys, links, bootstraps, and verifies all Phase 1 contracts:
 *         1. MultiSigApproval (Four-Eyes Principle & Governance Coordinator)
 *         2. RoleManager (RBAC with governance = multiSig)
 *         3. InsiderActivityLog (Insider threat behavior tracking with governance = multiSig)
 *         4. ForensicTrail (Chain of custody & evidence with governance = multiSig)
 *         5. ComplianceRules (AML Thresholds & Rule Engine)
 *         6. AuditEngine (AML/KYC core engine with governance = multiSig)
 *
 * Implements atomic phased bootstrap with 4 enrolled participants and privilege revocation.
 */
async function main() {
  console.log("====================================================");
  console.log("Starting Cyber-Forensic Auditing Framework Deployment (V2)");
  console.log("====================================================");

  const signers = await hre.ethers.getSigners();
  const deployer = signers[0];
  console.log(`Deployer address: ${deployer.address}`);
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`Deployer balance: ${hre.ethers.formatEther(balance)} ETH\n`);

  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const institutionId = process.env.INSTITUTION_ID || "INST-CENTRAL-DEMO";

  // 1. Deploy MultiSigApproval (deployer is temporary bootstrap authority, 2 required approvals, 24h TTL)
  console.log("1. Deploying MultiSigApproval...");
  const MultiSigApproval = await hre.ethers.getContractFactory("MultiSigApproval");
  const multiSig = await MultiSigApproval.deploy(deployer.address, 2, 24);
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

  // 7. Atomic Phased Bootstrap via MultiSigApproval
  console.log("7. Configuring contracts and cross-contract authorizations...");
  const configTx = await multiSig.configureContracts(
    roleManagerAddress,
    auditEngineAddress,
    insiderLogAddress,
    forensicTrailAddress
  );
  await configTx.wait();
  console.log("   -> Cross-contract wiring configured successfully.");

  // 8. Enroll initial 4+ participants required by Specification §5
  console.log("8. Bootstrapping initial 4 participants...");
  const participantAccounts = [
    signers[1] ? signers[1].address : "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    signers[2] ? signers[2].address : "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    signers[3] ? signers[3].address : "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    signers[4] ? signers[4].address : "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  ];
  const participantRoles = [2, 2, 3, 4]; // AUDITOR, AUDITOR, OPERATOR, REGULATOR
  const participantReasons = [
    "SYSTEM: Primary Forensic Compliance Auditor",
    "SYSTEM: Secondary Forensic Compliance Auditor",
    "SYSTEM: Core Banking Operations Lead",
    "SYSTEM: CBI Central Bank Oversight Inspector",
  ];

  const bootstrapTx = await multiSig.bootstrapParticipants(
    participantAccounts,
    participantRoles,
    participantReasons
  );
  await bootstrapTx.wait();
  console.log("   -> 4 participants enrolled into RoleManager.");

  // 9. Finalize Bootstrap and revoke deployer bootstrap authority permanently
  console.log("9. Finalizing bootstrap and revoking bootstrap privileges...");
  const finalizeTx = await multiSig.finalizeBootstrap();
  await finalizeTx.wait();
  console.log("   -> Bootstrap finalized. BootstrapAuthority revoked permanently.");

  // 10. Compute deployed bytecode hashes for cryptographic verification
  const contractAddresses = {
    RoleManager: roleManagerAddress,
    InsiderActivityLog: insiderLogAddress,
    ForensicTrail: forensicTrailAddress,
    ComplianceRules: complianceRulesAddress,
    MultiSigApproval: multiSigAddress,
    AuditEngine: auditEngineAddress,
  };

  const codeHashes = {};
  for (const [name, addr] of Object.entries(contractAddresses)) {
    const code = await hre.ethers.provider.getCode(addr);
    codeHashes[name] = hre.ethers.keccak256(code);
  }

  // 11. Build Authoritative Deployment Manifest (Specification §7, R05, R16)
  const manifest = {
    institution_id: institutionId,
    chain_id: chainId,
    deployed_at: new Date().toISOString(),
    contract_version: "2.0.0",
    network: hre.network.name,
    deployer: deployer.address,
    bootstrap_finalized: true,
    contracts: contractAddresses,
    code_hashes: codeHashes,
    participants: [
      {
        account: deployer.address,
        role: 1,
        reason: "SYSTEM: Genesis Deployer Super Admin",
      },
      ...participantAccounts.map((addr, idx) => ({
        account: addr,
        role: participantRoles[idx],
        reason: participantReasons[idx],
      })),
    ],
  };

  console.log("\n====================================================");
  console.log("Deployment Manifest:");
  console.log(JSON.stringify(manifest, null, 2));
  console.log("====================================================");

  // 12. Write Deployment Manifest to deployments/
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const manifestPath = path.join(deploymentsDir, "deployment-manifest.json");
  const networkManifestPath = path.join(deploymentsDir, `${hre.network.name}.json`);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  fs.writeFileSync(networkManifestPath, JSON.stringify(manifest, null, 2));
  console.log(`[SUCCESS] Saved manifest to ${manifestPath}`);

  // 13. Export runtime config for frontend
  const runtimeConfig = {
    institution_id: institutionId,
    chain_id: chainId,
    rpc_url: process.env.VITE_RPC_URL || "http://127.0.0.1:8545",
    ai_engine_url: process.env.VITE_AI_ENGINE_URL || "/api",
    app_mode: process.env.APP_MODE || "demo",
    contract_version: "2.0.0",
    contracts: contractAddresses,
  };

  const frontendPublicDir = path.join(__dirname, "..", "frontend", "public");
  if (!fs.existsSync(frontendPublicDir)) {
    fs.mkdirSync(frontendPublicDir, { recursive: true });
  }
  const frontendConfigPath = path.join(frontendPublicDir, "runtime-config.json");
  fs.writeFileSync(frontendConfigPath, JSON.stringify(runtimeConfig, null, 2));
  console.log(`[SUCCESS] Exported frontend runtime config to ${frontendConfigPath}`);

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

module.exports = { main };
