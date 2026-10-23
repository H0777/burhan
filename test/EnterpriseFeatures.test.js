const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AuditEngine Enterprise & Forensic Enhancements (5 Features)", function () {
  let auditEngine, roleManager, insiderLog, forensicTrail, multiSig;
  let admin, auditor1, auditor2, operator, user1, user2, outsider;

  const Role = {
    NONE: 0,
    SUPER_ADMIN: 1,
    AUDITOR: 2,
    OPERATOR: 3,
    REGULATOR: 4,
  };

  const ProposalType = {
    OVERRIDE_WARNING: 0,
    POLICY_CHANGE: 1,
    EMERGENCY_UNPAUSE: 2,
    ROLE_CHANGE: 3,
    GOVERNANCE_CONFIG: 4,
  };

  const PolicyProfile = {
    IRAQ_CBI: 0,
    GLOBAL_FATF: 1,
    CUSTOM: 2,
  };

  const NORMAL_AMOUNT = ethers.parseEther("100");
  const LARGE_AMOUNT = ethers.parseEther("15000");
  const CRITICAL_LARGE_AMOUNT = ethers.parseEther("25000"); // 2.5x threshold (> 2x triggers automated forensic incident)

const { deploySystemFixture } = require("./helpers/deploySystem");

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    [admin, auditor1, auditor2, operator, user1, user2, outsider] = signers;

    const system = await deploySystemFixture(signers);
    roleManager = system.roleManager;
    insiderLog = system.insiderLog;
    forensicTrail = system.forensicTrail;
    multiSig = system.multiSig;
    auditEngine = system.auditEngine;
    admin = system.admin;
    auditor1 = system.auditor1;
    auditor2 = system.auditor2;
    operator = system.operator;
  });

  // ============================================================
  // FEATURE 1: ENFORCED MULTISIG BRIDGE
  // ============================================================

  describe("Feature 1: Enforced MultiSig Bridge", function () {
    let flaggedTxId;

    beforeEach(async function () {
      // User1 submits large transaction -> gets FLAGGED
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
      flaggedTxId = 1;
    });

    it("Should allow overriding a flagged transaction via MultiSig proposal approval", async function () {
      // Encode txId 1 as data for the proposal
      const abiCoder = new ethers.AbiCoder();
      const encodedData = abiCoder.encode(["uint256"], [flaggedTxId]);

      // Propose in MultiSig by auditor1
      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Customer provided source of funds documentation"));
      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        encodedData,
        reasonHash
      );

      // Auditor2 and Admin approve proposal (reaches 2 required approvals)
      await multiSig.connect(auditor2).approveProposal(1);
      await multiSig.connect(admin).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Execute override on AuditEngine using the approved proposal
      await expect(
        auditEngine.connect(auditor1).overrideWarningWithMultiSig(
          flaggedTxId,
          1,
          "Customer verified"
        )
      )
        .to.emit(auditEngine, "OverrideAttempted")
        .and.to.emit(auditEngine, "TransactionCleared");

      const txData = await auditEngine.getTransaction(flaggedTxId);
      expect(txData.isFlagged).to.equal(false);
      expect(txData.status).to.equal(1); // CLEARED

      // Verify that evidence was appended to ForensicTrail
      expect(await forensicTrail.totalIncidents()).to.be.greaterThan(0);
    });

    it("Should revert if proposal is not yet approved in MultiSig", async function () {
      const abiCoder = new ethers.AbiCoder();
      const encodedData = abiCoder.encode(["uint256"], [flaggedTxId]);

      // Only 1 approval (proposer only created it, no approvals yet)
      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Pending approval"));
      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        encodedData,
        reasonHash
      );

      await expect(
        auditEngine.connect(auditor1).overrideWarningWithMultiSig(
          flaggedTxId,
          1,
          "Premature override attempt"
        )
      ).to.be.revertedWith("AuditEngine: proposal not approved by MultiSig");
    });

    it("Should revert if proposal targets a different transaction ID", async function () {
      const abiCoder = new ethers.AbiCoder();
      const encodedData = abiCoder.encode(["uint256"], [999]); // targeting tx 999

      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Wrong tx"));
      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        encodedData,
        reasonHash
      );
      await multiSig.connect(auditor2).approveProposal(1);
      await multiSig.connect(admin).approveProposal(1);

      await expect(
        auditEngine.connect(auditor1).overrideWarningWithMultiSig(flaggedTxId, 1, "Mismatch")
      ).to.be.revertedWith("AuditEngine: proposal txId mismatch");
    });

    it("Should enforce MultiSig if enforceMultiSigOverride is enabled", async function () {
      await auditEngine.connect(admin).setMultiSigOverrideEnforcement(true);
      expect(await auditEngine.enforceMultiSigOverride()).to.equal(true);

      // Direct overrideWarning should now be blocked
      await expect(
        auditEngine.connect(auditor1).overrideWarning(flaggedTxId, "Trying direct override")
      ).to.be.revertedWith("AuditEngine: MultiSig approval required for overrides");
    });
  });

  // ============================================================
  // FEATURE 2: SEPARATION OF DUTIES (SoD)
  // ============================================================

  describe("Feature 2: Separation of Duties (SoD)", function () {
    it("Should prevent auditor from overriding their own transaction as sender", async function () {
      // Auditor1 is the sender of a flagged transaction
      await auditEngine.connect(auditor1).submitTransaction(user2.address, LARGE_AMOUNT);
      const txId = 1;

      // Auditor1 attempts to clear their own warning
      await expect(
        auditEngine.connect(auditor1).overrideWarning(txId, "Self override attempt")
      ).to.be.revertedWith("AuditEngine: SoD conflict - caller is transaction sender");
    });

    it("Should prevent auditor from overriding a transaction where they are the receiver", async function () {
      // User1 sends to Auditor1
      await auditEngine.connect(user1).submitTransaction(auditor1.address, LARGE_AMOUNT);
      const txId = 1;

      // Auditor1 attempts to clear the transaction where they are recipient
      await expect(
        auditEngine.connect(auditor1).overrideWarning(txId, "Self recipient override")
      ).to.be.revertedWith("AuditEngine: SoD conflict - caller is transaction receiver");
    });

    it("Should prevent auditor from blocking their own transaction as sender or receiver", async function () {
      await auditEngine.connect(auditor1).submitTransaction(user2.address, LARGE_AMOUNT);
      await expect(
        auditEngine.connect(auditor1).blockTransaction(1)
      ).to.be.revertedWith("AuditEngine: SoD conflict - caller is transaction sender");
    });

    it("Should prevent operator/auditor from verifying or revoking their own KYC", async function () {
      await expect(
        auditEngine.connect(auditor1).verifyKYC(auditor1.address)
      ).to.be.revertedWith("AuditEngine: SoD conflict - caller cannot verify self");

      // Verify auditor1 by admin first
      await auditEngine.connect(admin).verifyKYC(auditor1.address);

      await expect(
        auditEngine.connect(auditor1).revokeKYC(auditor1.address)
      ).to.be.revertedWith("AuditEngine: SoD conflict - caller cannot revoke self");
    });
  });

  // ============================================================
  // FEATURE 3: AUTOMATED FORENSIC INGESTION
  // ============================================================

  describe("Feature 3: Automated Forensic Ingestion", function () {
    it("Should automatically record incident in ForensicTrail upon critical large transfer", async function () {
      expect(await forensicTrail.totalIncidents()).to.equal(0);

      // Submit critical transaction >= 2x threshold (>= 20,000 ETH)
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, CRITICAL_LARGE_AMOUNT)
      ).to.emit(auditEngine, "AutomatedForensicIncidentCreated");

      expect(await forensicTrail.totalIncidents()).to.equal(1);
      const incident = await forensicTrail.getIncident(1);
      expect(incident.titleHash).to.equal(ethers.keccak256(ethers.toUtf8Bytes("CRITICAL_LARGE_TRANSFER")));
      expect(incident.severityHash).to.equal(ethers.keccak256(ethers.toUtf8Bytes("HIGH")));
      expect(incident.evidenceCount).to.equal(1);

      // Verify chain integrity
      expect(await forensicTrail.verifyChainIntegrity(1)).to.equal(true);
    });
  });

  // ============================================================
  // FEATURE 4: TIMELOCK ON POLICY CHANGES
  // ============================================================

  describe("Feature 4: Timelock on Policy Changes", function () {
    const ONE_DAY = 24 * 3600;

    beforeEach(async function () {
      // Set timelock delay to 24 hours
      await auditEngine.connect(admin).setPolicyTimelockDelay(ONE_DAY);
      expect(await auditEngine.policyTimelockDelay()).to.equal(ONE_DAY);
    });

    it("Should reject direct setPolicy when timelock is active", async function () {
      await expect(
        auditEngine.connect(admin).setPolicy(PolicyProfile.GLOBAL_FATF)
      ).to.be.revertedWith("AuditEngine: timelock active - use proposePolicyChange");
    });

    it("Should propose policy change and enforce timelock delay before execution", async function () {
      await expect(auditEngine.connect(admin).proposePolicyChange(PolicyProfile.GLOBAL_FATF))
        .to.emit(auditEngine, "PolicyChangeProposed");

      const pending = await auditEngine.pendingPolicyChange();
      expect(pending.active).to.equal(true);
      expect(pending.profile).to.equal(PolicyProfile.GLOBAL_FATF);

      // Premature execution should revert
      await expect(
        auditEngine.connect(admin).executePolicyChange()
      ).to.be.revertedWith("AuditEngine: timelock has not expired");

      // Advance time by 25 hours
      await ethers.provider.send("evm_increaseTime", [25 * 3600]);
      await ethers.provider.send("evm_mine");

      // Now execution succeeds
      await expect(auditEngine.connect(admin).executePolicyChange())
        .to.emit(auditEngine, "PolicyChangeExecuted");

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.GLOBAL_FATF);
    });

    it("Should allow immediate policy execution via MultiSig bypass", async function () {
      await auditEngine.connect(admin).proposePolicyChange(PolicyProfile.GLOBAL_FATF);

      // Create POLICY_CHANGE proposal in MultiSig
      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Emergency policy change needed immediately"));
      await multiSig.connect(auditor1).createProposal(
        ProposalType.POLICY_CHANGE,
        await auditEngine.getAddress(),
        "0x",
        reasonHash
      );
      await multiSig.connect(auditor2).approveProposal(1);
      await multiSig.connect(admin).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Execute immediately using MultiSig bypass
      await expect(auditEngine.connect(admin).executePolicyChangeWithMultiSig(1))
        .to.emit(auditEngine, "PolicyChangeExecuted");

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.GLOBAL_FATF);
    });

    it("Should allow admin to cancel a proposed policy change", async function () {
      await auditEngine.connect(admin).proposePolicyChange(PolicyProfile.GLOBAL_FATF);
      await expect(auditEngine.connect(admin).cancelPolicyChange())
        .to.emit(auditEngine, "PolicyChangeCancelled");

      const pending = await auditEngine.pendingPolicyChange();
      expect(pending.active).to.equal(false);
    });
  });

  // ============================================================
  // FEATURE 5: DUAL-CONTROL EMERGENCY CIRCUIT BREAKER
  // ============================================================

  describe("Feature 5: Dual-Control Emergency Circuit Breaker", function () {
    it("Should allow AUDITOR to activate emergency pause and freeze transactions", async function () {
      await expect(
        auditEngine.connect(auditor1).emergencyPause("Suspected insider collateral drain")
      ).to.emit(auditEngine, "EmergencyPaused");

      expect(await auditEngine.isPaused()).to.equal(true);

      // Submitting transactions must now revert
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT)
      ).to.be.revertedWith("AuditEngine: circuit breaker active - transactions paused");

      // Automated forensic incident must be created
      expect(await forensicTrail.totalIncidents()).to.equal(1);
      const inc = await forensicTrail.getIncident(1);
      expect(inc.titleHash).to.equal(ethers.keccak256(ethers.toUtf8Bytes("EMERGENCY_CIRCUIT_BREAKER")));
      expect(inc.severityHash).to.equal(ethers.keccak256(ethers.toUtf8Bytes("CRITICAL")));
    });

    it("Should require MultiSig approval to unpause the engine (Dual-Control)", async function () {
      await auditEngine.connect(auditor1).emergencyPause("Rogue insider attack suspected");
      expect(await auditEngine.isPaused()).to.equal(true);

      // Rogue insider or single auditor attempts to unpause directly -> fails without MultiSig
      await expect(
        auditEngine.connect(auditor1).emergencyUnpause(1)
      ).to.be.revertedWith("MultiSig: proposal does not exist");

      // Create unpause proposal in MultiSig (EMERGENCY_UNPAUSE type)
      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Threat resolved, safe to resume banking operations"));
      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        await auditEngine.getAddress(),
        "0x",
        reasonHash
      );
      await multiSig.connect(auditor2).approveProposal(1);
      await multiSig.connect(admin).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Unpause using approved MultiSig proposal
      await expect(auditEngine.connect(auditor1).emergencyUnpause(1))
        .to.emit(auditEngine, "EmergencyUnpaused");

      expect(await auditEngine.isPaused()).to.equal(false);

      // Normal transactions work again
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT)
      ).to.emit(auditEngine, "TransactionSubmitted");
    });
  });
});
