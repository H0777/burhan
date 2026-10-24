const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const {
  SIZE_BUDGET_BYTES,
  NETWORK_LIMIT_BYTES,
  evaluateSizeGate,
  checkLinkage,
  runSizeGate,
} = require("../../scripts/check-contract-size");
const {
  validateAgainstSchema,
  validateDeploymentBinding,
  scanForbiddenKeys,
  SCHEMA_PATH,
} = require("../../scripts/verify-deployment");

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
    let deployer, voterA, voterB, voterC, voterD, operator, regulator;
    let multiSig, roleManager, insiderLog, forensicTrail, complianceRules, auditEngine;

    beforeEach(async function () {
      [, voterA, voterB, voterC, voterD, operator, regulator] = await ethers.getSigners();
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
        voterA.address,
        voterB.address,
        voterC.address,
        voterD.address,
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

      // Roster: exactly 4 eligible voters (deployer un-enrolled); operator/regulator enrolled but non-voting
      expect(await roleManager.countEligibleParticipants()).to.equal(4);
      expect(await roleManager.countActiveParticipants()).to.equal(6);
      expect(await roleManager.getRole(operator.address)).to.equal(Role.OPERATOR);
      expect(await roleManager.getRole(regulator.address)).to.equal(Role.REGULATOR);
      expect(await roleManager.getRole(deployer.address)).to.equal(Role.NONE);

      // Cross-contract writer/recorder wiring
      expect(await auditEngine.isIntegrated()).to.equal(true);
      expect(await auditEngine.multiSig()).to.equal(await multiSig.getAddress());
      expect(await insiderLog.isRecorder(await auditEngine.getAddress())).to.equal(true);
      expect(await forensicTrail.isEvidenceWriter(await auditEngine.getAddress())).to.equal(true);
    });
  });

  describe("manifest_wrong_chain_or_codehash_is_rejected", function () {
    const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));
    const codeHash = ethers.id("runtime-code-fixture");
    const wallet = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    function validManifestFixture() {
      return {
        manifest_version: 3,
        deployment_id: ethers.id("deployment-fixture"),
        institution_id: "INST-CENTRAL-DEMO",
        chain_id: 31337,
        network: "hardhat",
        contract_version: "2.1.0",
        status: "active",
        deployed_at: new Date().toISOString(),
        deployed_at_block: 13,
        confirmation_depth: 2,
        deployer: wallet,
        bootstrap_finalized: true,
        addresses: {
          MultiSigApproval: wallet,
          RoleManager: wallet,
          InsiderActivityLog: wallet,
          ForensicTrail: wallet,
          ComplianceRules: wallet,
          AuditEngine: wallet,
        },
        deployed_code_hashes: {
          MultiSigApproval: codeHash,
          RoleManager: codeHash,
          InsiderActivityLog: codeHash,
          ForensicTrail: codeHash,
          ComplianceRules: codeHash,
          AuditEngine: codeHash,
        },
        governance: {
          required_approvals: 2,
          proposal_ttl_seconds: 259200,
          timelock_delay_seconds: 86400,
          eligible_participants: 4,
          active_participants: 6,
        },
        participants: [
          ["roster-governance-1", 1],
          ["roster-audit-1", 2],
          ["roster-audit-2", 2],
          ["roster-audit-3", 2],
        ].map(([seed, role], idx) => ({
          participant_id: ethers.id(seed),
          account: `0x${String(idx + 1).padStart(40, "0")}`.slice(0, 42),
          role,
          reason: "fixture roster participant",
        })),
      };
    }

    it("accepts a schema-valid v3 manifest fixture", function () {
      expect(validateAgainstSchema(validManifestFixture(), schema)).to.deep.equal([]);
      expect(validateDeploymentBinding(validManifestFixture(), { chainId: 31337 })).to.deep.equal([]);
    });

    it("rejects a manifest bound to the wrong chain id", function () {
      const errors = validateDeploymentBinding(validManifestFixture(), { chainId: 1 });
      expect(errors.some((e) => e.includes("chain_id mismatch"))).to.equal(true);
    });

    it("rejects a manifest whose recorded code hash was tampered with", function () {
      const tampered = validManifestFixture();
      tampered.deployed_code_hashes.AuditEngine = ethers.id("tampered-code");
      const errors = validateDeploymentBinding(tampered, {
        chainId: 31337,
        codeHashes: { AuditEngine: codeHash },
      });
      expect(errors.some((e) => e.includes("code hash mismatch for AuditEngine"))).to.equal(true);
    });

    it("rejects a manifest missing a required DeploymentBinding field", function () {
      const incomplete = validManifestFixture();
      delete incomplete.deployed_at_block;
      const errors = validateAgainstSchema(incomplete, schema);
      expect(errors.some((e) => e.includes("missing required field 'deployed_at_block'"))).to.equal(true);
      expect(
        validateDeploymentBinding(incomplete, {}).some((e) =>
          e.includes("missing required DeploymentBinding field: deployed_at_block")
        )
      ).to.equal(true);
    });

    it("rejects any manifest carrying private-key-like fields", function () {
      const poisoned = validManifestFixture();
      poisoned.private_keys = { deployer: "0xdeadbeef" };
      expect(validateAgainstSchema(poisoned, schema).length > 0).to.equal(true);
      expect(scanForbiddenKeys(poisoned)).to.deep.equal(["private_keys"]);
      expect(scanForbiddenKeys(validManifestFixture())).to.deep.equal([]);
    });

    it("rejects a local-chain manifest whose confirmation_depth is not 2", function () {
      const shallow = validManifestFixture();
      shallow.confirmation_depth = 12;
      expect(
        validateDeploymentBinding(shallow, { chainId: 31337 }).some((e) =>
          e.includes("confirmation_depth must be 2")
        )
      ).to.equal(true);
    });
  });
});
