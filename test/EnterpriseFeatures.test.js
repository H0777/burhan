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
    SYSTEM_CONFIG: 4,
  };

  const PolicyProfile = {
    IRAQ_CBI: 0,
    GLOBAL_FATF: 1,
    CUSTOM: 2,
  };

  const NORMAL_AMOUNT = ethers.parseEther("100");
  const LARGE_AMOUNT = ethers.parseEther("15000");
  const CRITICAL_LARGE_AMOUNT = ethers.parseEther("25000"); // 2.5x threshold (> 2x triggers automated forensic incident)

  // Hand-built interface of the REMOVED parallel-admin functions (R03): raw
  // calldata proves the bypass is gone without needing the ABI to declare it.
  const LEGACY_INTERFACE = new ethers.Interface([
    "function overrideWarning(uint256,string)",
    "function emergencyUnpause(uint256)",
    "function setMultiSigOverrideEnforcement(bool)",
    "function setPolicyTimelockDelay(uint256)",
    "function proposePolicyChange(uint8)",
    "function setPolicy(uint8)",
  ]);

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

  async function setNextBlockTimestamp(ts) {
    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(ts)]);
  }

  // ============================================================
  // FEATURE 1: ENFORCED MULTISIG BRIDGE (R03: unified coordinator)
  // ============================================================

  describe("Feature 1: Enforced MultiSig Bridge", function () {
    let flaggedTxId;

    beforeEach(async function () {
      // User1 submits large transaction -> gets FLAGGED
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
      flaggedTxId = 1;
    });

    it("Should allow overriding a flagged transaction via an executed MultiSig proposal", async function () {
      const txn = await auditEngine.getTransaction(flaggedTxId);
      const callData = auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        flaggedTxId,
        txn.sender,
        txn.receiver,
        "Customer provided source of funds documentation",
      ]);

      // Propose in MultiSig by auditor1 (not a transaction party)
      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        callData,
        "Customer provided source of funds documentation"
      );

      // Admin and auditor2 approve (reaches 2 required approvals)
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Atomic execution through the coordinator clears the warning
      await expect(multiSig.connect(admin).executeProposal(1))
        .to.emit(auditEngine, "OverrideAttempted")
        .and.to.emit(auditEngine, "TransactionCleared");

      const txData = await auditEngine.getTransaction(flaggedTxId);
      expect(txData.isFlagged).to.equal(false);
      expect(txData.status).to.equal(1); // CLEARED

      // The override is captured in the InsiderActivityLog
      expect(await insiderLog.totalActivities()).to.be.greaterThan(0);
      const activities = await insiderLog.getAllActivityIds();
      const act = await insiderLog.getActivity(activities[activities.length - 1]);
      expect(act.activityType).to.equal(1); // TRANSACTION_OVERRIDE
    });

    it("Should revert execution if the proposal has not reached quorum yet", async function () {
      const txn = await auditEngine.getTransaction(flaggedTxId);
      const callData = auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        flaggedTxId,
        txn.sender,
        txn.receiver,
        "Pending approval",
      ]);

      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        callData,
        "Pending approval"
      );

      // Only one approval so far: execution must fail
      await multiSig.connect(admin).approveProposal(1);
      await expect(
        multiSig.connect(auditor1).executeProposal(1)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");
    });

    it("Should reject proposal creation when the parties do not match the transaction record", async function () {
      const callData = auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        flaggedTxId,
        outsider.address, // fabricated sender
        user2.address,
        "Wrong parties",
      ]);

      // R03: parties are validated against AuditEngine's own record at creation
      await expect(
        multiSig.connect(auditor1).createProposal(
          ProposalType.OVERRIDE_WARNING,
          await auditEngine.getAddress(),
          callData,
          "Wrong parties"
        )
      ).to.be.revertedWith("AuditEngine: transaction party mismatch");
    });

    it("Direct overrideWarning is permanently blocked — no enforcement flag to toggle anymore", async function () {
      const auditEngineAddress = await auditEngine.getAddress();

      // The enforcement toggle itself is gone (raw calldata reverts).
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("setMultiSigOverrideEnforcement", [true]),
        })
      ).to.be.reverted;

      // The direct override reverts for an eligible auditor — the ONLY path is
      // the coordinator.
      await expect(
        auditor1.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("overrideWarning", [
            flaggedTxId,
            "Trying direct override",
          ]),
        })
      ).to.be.reverted;

      const txData = await auditEngine.getTransaction(flaggedTxId);
      expect(txData.isFlagged).to.equal(true);
      expect(txData.status).to.equal(2); // FLAGGED
    });
  });

  // ============================================================
  // FEATURE 2: SEPARATION OF DUTIES (SoD)
  // ============================================================

  describe("Feature 2: Separation of Duties", function () {
    it("Should prevent auditor from overriding their own transaction as sender", async function () {
      // Auditor1 is the sender of a flagged transaction
      await auditEngine.connect(auditor1).submitTransaction(user2.address, LARGE_AMOUNT);
      const txId = 1;

      // R03: the direct override path no longer exists at all — raw legacy
      // calldata from the transaction party reverts.
      await expect(
        auditor1.sendTransaction({
          to: await auditEngine.getAddress(),
          data: LEGACY_INTERFACE.encodeFunctionData("overrideWarning", [txId, "Self override attempt"]),
        })
      ).to.be.reverted;
      expect((await auditEngine.getTransaction(txId)).status).to.equal(2); // FLAGGED
    });

    it("Should prevent a transaction party from approving the override of its own warning (identity-scoped)", async function () {
      // User1 sends to Auditor1; auditor1 (receiver, enrolled AUDITOR) must not
      // be able to approve the override proposal.
      await auditEngine.connect(user1).submitTransaction(auditor1.address, LARGE_AMOUNT);
      const txId = 1;
      const txn = await auditEngine.getTransaction(txId);

      const callData = auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        txId,
        txn.sender,
        txn.receiver,
        "Self recipient override",
      ]);
      await multiSig.connect(auditor2).createProposal(
        ProposalType.OVERRIDE_WARNING,
        await auditEngine.getAddress(),
        callData,
        "Self recipient override"
      );

      await expect(
        multiSig.connect(auditor1).approveProposal(1)
      ).to.be.revertedWith("MultiSig: transaction sender/receiver cannot approve override");
      expect((await multiSig.getProposal(1)).approvalCount).to.equal(0);
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
  // FEATURE 4: TIMELOCK ON POLICY CHANGES (R03: coordinator-owned)
  // ============================================================

  describe("Feature 4: Timelock on Policy Changes", function () {
    it("Should enforce the 86,400s coordinator timelock before a policy proposal executes", async function () {
      const callData = auditEngine.interface.encodeFunctionData("executePolicyChange", [
        PolicyProfile.GLOBAL_FATF,
      ]);
      await multiSig.connect(auditor1).createProposal(
        ProposalType.POLICY_CHANGE,
        await auditEngine.getAddress(),
        callData,
        "Switch to FATF policy"
      );
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Quorum reached, but the timelock has not elapsed.
      await expect(
        multiSig.connect(admin).executeProposal(1)
      ).to.be.revertedWith("MultiSig: timelock active");

      // Advance time by 24 hours
      const prop = await multiSig.getProposal(1);
      await setNextBlockTimestamp(prop.notBefore);
      await expect(multiSig.connect(admin).executeProposal(1))
        .to.emit(auditEngine, "PolicyChanged");

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.GLOBAL_FATF);
    });

    it("Should NOT allow immediate policy execution via a MultiSig bypass — governance-only, no parallel admin path", async function () {
      const auditEngineAddress = await auditEngine.getAddress();

      // The legacy admin paths (parallel timelock proposal + MultiSig bypass)
      // are gone: their selectors revert for everyone.
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("proposePolicyChange", [PolicyProfile.GLOBAL_FATF]),
        })
      ).to.be.reverted;
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("setPolicy", [PolicyProfile.GLOBAL_FATF]),
        })
      ).to.be.reverted;
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("setPolicyTimelockDelay", [86_400]),
        })
      ).to.be.reverted;

      // SUPER_ADMIN cannot call the governance-only execute interface either:
      // after bootstrap the coordinator is governance.
      await expect(
        auditEngine.connect(admin).executePolicyChange(PolicyProfile.GLOBAL_FATF)
      ).to.be.revertedWith("AuditEngine: caller is not governance");

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.IRAQ_CBI); // unchanged
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

    it("Should require an executed MultiSig proposal to unpause the engine (Dual-Control, epoch-bound)", async function () {
      await auditEngine.connect(auditor1).emergencyPause("Rogue insider attack suspected");
      expect(await auditEngine.isPaused()).to.equal(true);
      const epoch = await auditEngine.pauseEpoch();

      // The legacy direct emergencyUnpause(proposalId) consumer is GONE: raw
      // calldata from a single auditor reverts.
      await expect(
        auditor1.sendTransaction({
          to: await auditEngine.getAddress(),
          data: LEGACY_INTERFACE.encodeFunctionData("emergencyUnpause", [1]),
        })
      ).to.be.reverted;
      expect(await auditEngine.isPaused()).to.equal(true);

      // Create an epoch-bound unpause proposal in the coordinator
      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        await auditEngine.getAddress(),
        auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [epoch]),
        "Threat resolved, safe to resume banking operations"
      );
      await multiSig.connect(auditor2).approveProposal(1);
      await multiSig.connect(admin).approveProposal(1);
      expect(await multiSig.isApproved(1)).to.equal(true);

      // Unpause through atomic execution
      await expect(multiSig.connect(auditor1).executeProposal(1))
        .to.emit(auditEngine, "EmergencyUnpaused");

      expect(await auditEngine.isPaused()).to.equal(false);

      // Normal transactions work again
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT)
      ).to.emit(auditEngine, "TransactionSubmitted");
    });
  });
});
