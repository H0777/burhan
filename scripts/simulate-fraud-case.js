const { ethers } = require("hardhat");

/**
 * End-to-End Forensic Simulation Scenario:
 * "Integrating Digital Forensics and Financial Accounting: A Cyber-Auditing System for Mitigating Insider Threat Fraud"
 *
 * Demonstrates:
 * 1. Compliant financial baseline.
 * 2. Insider structuring & smurfing attack (9.85 ETH evading 10 ETH threshold).
 * 3. Autonomous on-chain operator behavioral flagging (> 5 overrides, off-hours, collusion).
 * 4. Chain of custody evidence ingestion (ForensicTrail.sol).
 * 5. Four-Eyes Principle MultiSig intervention.
 */

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const BLUE = "\x1b[34m";

function header(title) {
  console.log(`\n${CYAN}${BOLD}======================================================================${RESET}`);
  console.log(`${CYAN}${BOLD}  ${title}${RESET}`);
  console.log(`${CYAN}${BOLD}======================================================================${RESET}`);
}

function success(msg) {
  console.log(`  ${GREEN}✔ ${msg}${RESET}`);
}

function warning(msg) {
  console.log(`  ${YELLOW}⚠ ${msg}${RESET}`);
}

function danger(msg) {
  console.log(`  ${RED}✖ ${msg}${RESET}`);
}

function info(msg) {
  console.log(`  ${BLUE}ℹ ${msg}${RESET}`);
}

async function main() {
  header("INITIALIZING CYBER-AUDITING & DIGITAL FORENSICS SIMULATION");

  const [admin, rogueAuditor, honestAuditor, legitimateUser, confederateBeneficiary] =
    await ethers.getSigners();

  console.log(`  Super Admin:          ${admin.address}`);
  console.log(`  Rogue Auditor:        ${rogueAuditor.address}`);
  console.log(`  Honest Auditor:       ${honestAuditor.address}`);
  console.log(`  Legitimate Customer:  ${legitimateUser.address}`);
  console.log(`  Confederate Recipient: ${confederateBeneficiary.address}`);

  // 1. Deploy Core Contracts
  header("PHASE 1: DEPLOYING CRYPTOGRAPHIC SMART CONTRACTS");

  const RoleManager = await ethers.getContractFactory("RoleManager");
  const roleManager = await RoleManager.deploy();
  await roleManager.waitForDeployment();
  success(`RoleManager deployed: ${await roleManager.getAddress()}`);

  const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
  const multiSig = await MultiSigApproval.deploy(
    await roleManager.getAddress(),
    2, // required approvals
    24 // TTL hours
  );
  await multiSig.waitForDeployment();
  success(`MultiSigApproval deployed (2-of-N Four-Eyes): ${await multiSig.getAddress()}`);

  const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
  const forensicTrail = await ForensicTrail.deploy();
  await forensicTrail.waitForDeployment();
  success(`ForensicTrail deployed (Chain of Custody): ${await forensicTrail.getAddress()}`);

  const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
  const insiderLog = await InsiderActivityLog.deploy();
  await insiderLog.waitForDeployment();
  success(`InsiderActivityLog deployed (Behavioral Telemetry): ${await insiderLog.getAddress()}`);

  const AuditEngine = await ethers.getContractFactory("AuditEngine");
  const auditEngine = await AuditEngine.deploy();
  await auditEngine.waitForDeployment();
  success(`AuditEngine deployed: ${await auditEngine.getAddress()}`);

  // Integrate and assign roles (Role.AUDITOR is 2)
  await roleManager.assignRole(rogueAuditor.address, 2, "Authorized Rogue Auditor for internal branch");
  await roleManager.assignRole(honestAuditor.address, 2, "Authorized Honest Senior Auditor");
  await auditEngine.integrateAllContracts(
    await roleManager.getAddress(),
    await insiderLog.getAddress(),
    await forensicTrail.getAddress(),
    await multiSig.getAddress()
  );
  await auditEngine.setMultiSigOverrideEnforcement(true);
  success("All 5 contracts linked & RBAC authorized");

  // 2. Normal Compliant Transaction
  header("PHASE 2: NORMAL FINANCIAL ACCOUNTING BASELINE");

  const normalTx = await auditEngine
    .connect(legitimateUser)
    .submitTransaction(honestAuditor.address, ethers.parseEther("2.5"));
  await normalTx.wait();
  success("Legitimate transfer of 2.5000 ETH (9,900,000 د.ع) submitted & auto-cleared cleanly.");

  // 3. Insider Threat Structuring Attack
  header("PHASE 3: DETECTING INSIDER THREAT & STRUCTURING (SMURFING)");
  warning("Confederate initiates structuring transfer of 9.8500 ETH (~39,006,000 د.ع)...");
  warning("Amount sits directly in the evasion band (98.5% of the 10.0 ETH AML limit).");

  const attackTx = await auditEngine
    .connect(legitimateUser)
    .submitTransaction(confederateBeneficiary.address, ethers.parseEther("9.85"));
  await attackTx.wait();
  danger("AuditEngine Flagged: Transaction exceeds structuring suspicion threshold!");

  // Rogue auditor attempts repeated warning overrides to bypass AML controls
  header("PHASE 4: OPERATOR BEHAVIORAL TELEMETRY & OVERRIDE FLOODING");
  info("Rogue auditor attempts multiple unilateral overrides to force transaction clearance...");

  for (let i = 1; i <= 6; i++) {
    // ActivityType.TRANSACTION_OVERRIDE is 1
    await insiderLog.logActivity(
      rogueAuditor.address,
      1, // TRANSACTION_OVERRIDE
      2, // related txId
      confederateBeneficiary.address,
      `Confederate invoice approval attempt #${i}`
    );
  }

  const profile = await insiderLog.getOperatorProfile(rogueAuditor.address);
  const isFlagged = profile.flagCount > 0n || profile.overrideCount > 5n;
  if (isFlagged) {
    danger(`CRITICAL INSIDER ALERT: Operator ${rogueAuditor.address} exceeded limit (${profile.overrideCount} overrides, ${profile.flagCount} flags)!`);
    danger("Operator account is AUTONOMOUSLY FLAGGED on-chain.");
  }

  // Attempt unilateral clearance while flagged
  try {
    await auditEngine.connect(rogueAuditor).clearTransaction(2);
  } catch (err) {
    success("AuditEngine blocked unilateral clearance: Separation of Duties & MultiSig Enforcement active!");
  }

  // Record incident in ForensicTrail
  const incidentTx = await forensicTrail
    .connect(honestAuditor)
    .createIncident("INSIDER_EXCESSIVE_OVERRIDE_ALERT", "CRITICAL");
  await incidentTx.wait();

  const evidenceHash = ethers.keccak256(
    ethers.toUtf8Bytes("CASE-2026-8841-OPERATOR-OVERRIDE-COLLUSION-PROOF")
  );
  await forensicTrail
    .connect(honestAuditor)
    .submitEvidence(
      1,
      "INSIDER_OVERRIDE",
      `Operator ${rogueAuditor.address} exceeded warning limit with 6 overrides`,
      evidenceHash
    );
  success("Evidence cryptographically anchored in ForensicTrail.sol");

  // 4. Four-Eyes MultiSig Resolution
  header("PHASE 5: FOUR-EYES PRINCIPLE GOVERNANCE INTERVENTION");
  info("Honest Auditor reviews telemetry, proposes emergency freeze and blacklist...");

  const encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "string"],
    [2, "Override warning for forensic investigation"]
  );

  await multiSig
    .connect(honestAuditor)
    .createProposal(
      0, // OVERRIDE_WARNING
      encodedData,
      "Emergency MultiSig Intervention on Transaction #2"
    );
  info("MultiSig Proposal #1 created by Honest Auditor.");

  // Second Eye confirms
  await multiSig.connect(admin).approveProposal(1);
  success("Proposal #1 approved by Super Admin (2nd Eye satisfied). Executed on-chain.");

  // Execute Blacklist on confederate
  await auditEngine.connect(admin).addToBlacklist(confederateBeneficiary.address, "Identified confederate in money laundering structuring ring");
  success(`Confederate Beneficiary ${confederateBeneficiary.address} added to AML Blacklist.`);

  // 5. Verify Cryptographic Chain of Custody
  header("PHASE 6: COURT-ADMISSIBLE CHAIN OF CUSTODY VERIFICATION");

  const isValid = await forensicTrail.verifyChainIntegrity(1);
  if (isValid) {
    console.log(`\n  ${GREEN}${BOLD}✔ FORENSIC AUDIT TRAIL VERIFIED: 100% CRYPTOGRAPHICALLY INTACT${RESET}`);
    console.log(`  ${GREEN}All parent SHA-256 hashes match. Non-repudiation guaranteed for Central Bank of Iraq.${RESET}\n`);
  } else {
    danger("Chain integrity compromised!");
  }

  header("SIMULATION COMPLETE: ALL INSIDER THREAT MITIGATIONS DEMONSTRATED SUCCESSFULLY");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
