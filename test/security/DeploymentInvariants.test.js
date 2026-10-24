const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  SIZE_BUDGET_BYTES,
  NETWORK_LIMIT_BYTES,
  evaluateSizeGate,
  checkLinkage,
  runSizeGate,
} = require("../../scripts/check-contract-size");

/**
 * R04 — Deployment Invariants (F08 + standard deployment + roster)
 *
 * 1. size_gate_rejects_24577_and_24001_and_accepts_24000 — the pure threshold
 *    logic of the contract size gate (protocol budget 24,000 runtime bytes;
 *    network hard limit 24,576). Threshold tests use synthetic sizes only —
 *    real contracts are never inflated.
 * 2. fresh_artifacts_within_standard_limit — every PRODUCTION artifact compiles
 *    fresh and measures <= budget via the real gate.
 * 3. fresh_standard_deployment — the full six-contract stack deploys and
 *    bootstraps on a standard-limit network (allowUnlimitedContractSize=false),
 *    with the operational roster: 4 eligible voting participants (unique) plus
 *    non-voting OPERATOR and REGULATOR enrollments.
 */

const Role = { NONE: 0, SUPER_ADMIN: 1, AUDITOR: 2, OPERATOR: 3, REGULATOR: 4 };

const TTL_SECONDS = 259200n; // 72h protocol constant

describe("Deployment Invariants (R04)", function () {
  describe("size_gate_rejects_24577_and_24001_and_accepts_24000", function () {
    it("accepts exactly the 24,000-byte budget", function () {
      expect(evaluateSizeGate(24000, SIZE_BUDGET_BYTES).passed).to.equal(true);
    });

    it("rejects 24,001 bytes (one over protocol budget)", function () {
      const verdict = evaluateSizeGate(24001, SIZE_BUDGET_BYTES);
      expect(verdict.passed).to.equal(false);
      expect(verdict.reason).to.match(/budget/);
    });

    it("rejects 24,577 bytes (one over the EIP-170 network limit)", function () {
      const verdict = evaluateSizeGate(24577, SIZE_BUDGET_BYTES);
      expect(verdict.passed).to.equal(false);
    });

    it("rejects 24,576 bytes against the protocol budget but flags network-limit breach distinctly", function () {
      const verdict = evaluateSizeGate(NETWORK_LIMIT_BYTES, SIZE_BUDGET_BYTES);
      expect(verdict.passed).to.equal(false);
      expect(verdict.reason).to.match(/budget/); // still a budget failure, not a network failure
      expect(evaluateSizeGate(NETWORK_LIMIT_BYTES + 1, SIZE_BUDGET_BYTES).reason).to.match(/network limit/);
    });

    it("rejects unlinked placeholder payloads and declared link references", function () {
      const placeholder = "0x73__$d64e1e4523ca3f8a2c9b0c1e0b64aaaa01$__" + "00".repeat(8);
      expect(checkLinkage(placeholder, {}).ok).to.equal(false);
      expect(
        checkLinkage("0x" + "00".repeat(16), {
          deployedLinkReferences: { "contracts/libraries/L.sol": { L: [{ start: 0, length: 20 }] } },
        }).ok
      ).to.equal(false);
      expect(checkLinkage("0x" + "00".repeat(16), { deployedLinkReferences: {} }).ok).to.equal(true);
    });
  });

  describe("fresh_artifacts_within_standard_limit", function () {
    it("measures every production contract from fresh artifacts within the budget", function () {
      const { results, allPassed } = runSizeGate();
      for (const r of results) {
        expect(r.passed, `${r.contract}: ${r.error || "ok"}`).to.equal(true);
        expect(r.runtime_bytes).to.be.at.most(SIZE_BUDGET_BYTES);
      }
      expect(allPassed).to.equal(true);
    });
  });

  describe("fresh_standard_deployment", function () {
    let deployer, voterB, voterC, voterD, operator, regulator;
    let multiSig, roleManager, insiderLog, forensicTrail, complianceRules, auditEngine;

    beforeEach(async function () {
      [, voterB, voterC, voterD, operator, regulator] = await ethers.getSigners();
      deployer = (await ethers.getSigners())[0];

      multiSig = await (await ethers.getContractFactory("MultiSigApproval")).deploy(deployer.address, 2);
      await multiSig.waitForDeployment();
      roleManager = await (await ethers.getContractFactory("RoleManager")).deploy(
        await multiSig.getAddress()
      );
      await roleManager.waitForDeployment();
      insiderLog = await (await ethers.getContractFactory("InsiderActivityLog")).deploy(
        await multiSig.getAddress()
      );
      await insiderLog.waitForDeployment();
      forensicTrail = await (await ethers.getContractFactory("ForensicTrail")).deploy(
        await multiSig.getAddress()
      );
      await forensicTrail.waitForDeployment();
      complianceRules = await (await ethers.getContractFactory("ComplianceRules")).deploy();
      await complianceRules.waitForDeployment();
      auditEngine = await (await ethers.getContractFactory("AuditEngine")).deploy(
        await multiSig.getAddress()
      );
      await auditEngine.waitForDeployment();

      await (await multiSig.configureContracts(
        await roleManager.getAddress(),
        await auditEngine.getAddress(),
        await insiderLog.getAddress(),
        await forensicTrail.getAddress()
      )).wait();
    });

    it("deploys the full stack under the standard size limit and finalizes governance with the operational roster", async function () {
      // Deployments above already prove every contract fits the standard
      // 24,576-byte limit (allowUnlimitedContractSize=false in hardhat.config).
      const rosterIds = [
        ethers.id("INST-GOVERNANCE-01"),
        ethers.id("INST-AUDIT-01"),
        ethers.id("INST-AUDIT-02"),
        ethers.id("INST-AUDIT-03"),
        ethers.id("INST-OPERATIONS-01"),
        ethers.id("INST-REGULATOR-01"),
      ];
      const rosterWallets = [
        voterB.address,
        voterC.address,
        voterD.address,
        deployer.address,
        operator.address,
        regulator.address,
      ];
      const rosterRoles = [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR, Role.REGULATOR];
      const rosterReasons = [
        "SYSTEM: Chief Governance & Compliance Admin",
        "SYSTEM: Primary Forensic Compliance Auditor",
        "SYSTEM: Secondary Forensic Compliance Auditor",
        "SYSTEM: Tertiary Forensic Compliance Auditor",
        "SYSTEM: Daily Transaction Operator (non-voting)",
        "SYSTEM: External Regulator Observer (non-voting)",
      ];

      await (await multiSig.bootstrapParticipants(rosterIds, rosterWallets, rosterRoles, rosterReasons)).wait();
      await (await multiSig.finalizeBootstrap()).wait();

      // Governance wiring
      expect(await multiSig.isBootstrapFinalized()).to.equal(true);
      expect(await multiSig.bootstrapAuthority()).to.equal(ethers.ZeroAddress);
      expect(await multiSig.requiredApprovals()).to.equal(2);
      expect(await multiSig.PROPOSAL_TTL()).to.equal(TTL_SECONDS);

      // Roster: exactly 4 eligible voters; operator/regulator enrolled but non-voting
      expect(await roleManager.countEligibleParticipants()).to.equal(4);
      expect(await roleManager.countActiveParticipants()).to.equal(6);
      expect(await roleManager.getRole(operator.address)).to.equal(Role.OPERATOR);
      expect(await roleManager.getRole(regulator.address)).to.equal(Role.REGULATOR);

      // Cross-contract writer/recorder wiring
      expect(await auditEngine.isIntegrated()).to.equal(true);
      expect(await auditEngine.multiSig()).to.equal(await multiSig.getAddress());
      expect(await insiderLog.isRecorder(await auditEngine.getAddress())).to.equal(true);
      expect(await forensicTrail.isEvidenceWriter(await auditEngine.getAddress())).to.equal(true);
    });
  });
});
