const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySystemFixture, Role } = require("../helpers/deploySystem");

describe("Governance Execution & Atomic Approvals (T03)", function () {
  let system;
  let admin, auditor1, auditor2, operator, regulator, outsider;
  let multiSig, roleManager, auditEngine, insiderLog, forensicTrail;

  const ProposalType = {
    OVERRIDE_WARNING: 0,
    POLICY_CHANGE: 1,
    EMERGENCY_UNPAUSE: 2,
    ROLE_CHANGE: 3,
    GOVERNANCE_CONFIG: 4,
  };

  const ProposalStatus = {
    PENDING: 0,
    APPROVED: 1,
    EXECUTED: 2,
    REJECTED: 3,
    EXPIRED: 4,
    CANCELLED: 5,
  };

  beforeEach(async function () {
    system = await deploySystemFixture();
    multiSig = system.multiSig;
    roleManager = system.roleManager;
    auditEngine = system.auditEngine;
    insiderLog = system.insiderLog;
    forensicTrail = system.forensicTrail;

    admin = system.admin;
    auditor1 = system.auditor1;
    auditor2 = system.auditor2;
    operator = system.operator;
    regulator = system.regulator;
    outsider = system.outsider;
  });

  describe("Proposal Creation & Typed Action Integrity", function () {
    it("should allow authorized participant (AUDITOR) to create a structured proposal", async function () {
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("emergencyUnpause", [1]);
      const reasonHash = ethers.id("Unpause engine after incident review");

      const tx = await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );

      await expect(tx)
        .to.emit(multiSig, "ProposalCreated")
        .withArgs(1, ProposalType.EMERGENCY_UNPAUSE, auditor1.address, target, reasonHash);

      const prop = await multiSig.getProposal(1);
      expect(prop.proposalType).to.equal(ProposalType.EMERGENCY_UNPAUSE);
      expect(prop.target).to.equal(target);
      expect(prop.status).to.equal(ProposalStatus.PENDING);
      expect(prop.proposer).to.equal(auditor1.address);
    });

    it("should reject proposal creation by unauthorized outsider or OPERATOR", async function () {
      const target = await auditEngine.getAddress();
      const callData = "0x";
      const reasonHash = ethers.id("Malicious proposal");

      await expect(
        multiSig.connect(outsider).createProposal(
          ProposalType.POLICY_CHANGE,
          target,
          callData,
          reasonHash
        )
      ).to.be.revertedWith("MultiSig: caller not authorized to participate");

      await expect(
        multiSig.connect(operator).createProposal(
          ProposalType.POLICY_CHANGE,
          target,
          callData,
          reasonHash
        )
      ).to.be.revertedWith("MultiSig: caller not authorized to participate");
    });

    it("should reject proposal creation with zero address target or empty target code", async function () {
      const callData = "0x";
      const reasonHash = ethers.id("Zero target proposal");

      await expect(
        multiSig.connect(auditor1).createProposal(
          ProposalType.POLICY_CHANGE,
          ethers.ZeroAddress,
          callData,
          reasonHash
        )
      ).to.be.revertedWith("MultiSig: target must be an active contract");

      await expect(
        multiSig.connect(auditor1).createProposal(
          ProposalType.POLICY_CHANGE,
          outsider.address, // EOA has no code
          callData,
          reasonHash
        )
      ).to.be.revertedWith("MultiSig: target must be an active contract");
    });
  });

  describe("Approval Flow & Four-Eyes Enforcement", function () {
    let proposalId;
    let target;
    let callData;

    beforeEach(async function () {
      target = await auditEngine.getAddress();
      callData = auditEngine.interface.encodeFunctionData("emergencyUnpause", [1]);
      const reasonHash = ethers.id("Emergency unpause request");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );
      proposalId = 1;
    });

    it("should prevent proposer from approving own proposal (Four-Eyes Principle)", async function () {
      await expect(
        multiSig.connect(auditor1).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: proposer cannot approve own proposal");
    });

    it("should transition status to APPROVED only upon reaching required approvals (2 distinct approvers)", async function () {
      // First approval by admin
      await multiSig.connect(admin).approveProposal(proposalId);
      let prop = await multiSig.getProposal(proposalId);
      expect(prop.status).to.equal(ProposalStatus.PENDING);
      expect(prop.approvalCount).to.equal(1);

      // Second approval by auditor2
      const tx = await multiSig.connect(auditor2).approveProposal(proposalId);
      await expect(tx).to.emit(multiSig, "ProposalApproved");

      prop = await multiSig.getProposal(proposalId);
      expect(prop.status).to.equal(ProposalStatus.APPROVED);
      expect(prop.approvalCount).to.equal(2);
    });

    it("should NOT auto-execute on approval and MUST NOT emit ProposalExecuted during approval", async function () {
      await multiSig.connect(admin).approveProposal(proposalId);
      const tx = await multiSig.connect(auditor2).approveProposal(proposalId);

      const receipt = await tx.wait();
      const executedEvents = receipt.logs.filter((log) => {
        try {
          const parsed = multiSig.interface.parseLog(log);
          return parsed.name === "ProposalExecuted";
        } catch {
          return false;
        }
      });
      expect(executedEvents.length).to.equal(0);

      const prop = await multiSig.getProposal(proposalId);
      expect(prop.status).to.equal(ProposalStatus.APPROVED);
    });

    it("should reject duplicate approval from the same participant", async function () {
      await multiSig.connect(admin).approveProposal(proposalId);

      await expect(
        multiSig.connect(admin).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: caller has already voted");
    });
  });

  describe("Atomic Execution & Reentrancy / State Invariants", function () {
    it("should atomically execute approved proposal, changing status to EXECUTED and invoking target", async function () {
      // 1. Pause audit engine
      await auditEngine.connect(admin).emergencyPause("Test pause");
      expect(await auditEngine.isPaused()).to.equal(true);
      const currentEpoch = await auditEngine.pauseEpoch();

      // 2. Create proposal to unpause with correct current epoch
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [currentEpoch]);
      const reasonHash = ethers.id("Unpause incident cleared");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );

      // 3. Approve by 2 distinct participants
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // 4. Execute proposal
      const tx = await multiSig.connect(auditor1).executeProposal(1);
      await expect(tx)
        .to.emit(multiSig, "ProposalExecuted")
        .withArgs(1, auditor1.address, target);

      // 5. Verify engine is unpaused
      expect(await auditEngine.isPaused()).to.equal(false);
      const prop = await multiSig.getProposal(1);
      expect(prop.status).to.equal(ProposalStatus.EXECUTED);
    });

    it("should reject second execution of an already executed proposal (No Replay)", async function () {
      // 1. Pause audit engine
      await auditEngine.connect(admin).emergencyPause("First pause");
      const currentEpoch = await auditEngine.pauseEpoch();

      // 2. Create and approve proposal
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [currentEpoch]);
      const reasonHash = ethers.id("Unpause proposal 1");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // 3. First execution succeeds
      await multiSig.connect(admin).executeProposal(1);
      expect(await auditEngine.isPaused()).to.equal(false);

      // 4. Pause again
      await auditEngine.connect(admin).emergencyPause("Second pause");
      expect(await auditEngine.isPaused()).to.equal(true);

      // 5. Attempt second execution of proposal 1: MUST revert
      await expect(
        multiSig.connect(admin).executeProposal(1)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");
    });

    it("should revert entire execution transaction if target reverts, preserving proposal as APPROVED (Atomicity)", async function () {
      // 1. Pause audit engine so whenPaused modifier is satisfied
      await auditEngine.connect(admin).emergencyPause("Pause for atomicity test");
      expect(await auditEngine.isPaused()).to.equal(true);

      // 2. Target call that will revert inside target contract
      const target = await auditEngine.getAddress();
      // Calling executeEmergencyUnpause with wrong epoch causes target to revert!
      const wrongEpoch = 999;
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [wrongEpoch]);
      const reasonHash = ethers.id("Wrong epoch unpause");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // Execute proposal should revert because target reverted
      await expect(
        multiSig.connect(admin).executeProposal(1)
      ).to.be.revertedWith("AuditEngine: invalid pause epoch");

      // Verify proposal remains in APPROVED status, not EXECUTED
      const prop = await multiSig.getProposal(1);
      expect(prop.status).to.equal(ProposalStatus.APPROVED);
    });
  });

  describe("Participant Authorization Generation & Role Revocation Invalidation", function () {
    it("should invalidate previous votes if an approver's role was revoked before execution", async function () {
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [0]);
      const reasonHash = ethers.id("Unpause proposal");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );

      // Admin and Auditor2 approve
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // Now, Auditor2's role is revoked through the REAL governance path (R01):
      // revokeRole is onlyGovernance (the multiSig contract), so a ROLE_CHANGE
      // proposal must target roleManager and be executed atomically. revokeRole
      // bumps auditor2's authorization generation, making their earlier approval stale.
      const revokeCalldata = roleManager.interface.encodeFunctionData("revokeRole", [
        auditor2.address,
        "R01: auditor2 authorization revoked before execution",
      ]);
      await multiSig.connect(auditor1).createProposal(
        ProposalType.ROLE_CHANGE,
        await roleManager.getAddress(),
        revokeCalldata,
        ethers.id("Revoke auditor2 role")
      );
      await multiSig.connect(admin).approveProposal(2);
      await multiSig.connect(auditor2).approveProposal(2);
      await multiSig.connect(admin).executeProposal(2);
      expect(await roleManager.getRole(auditor2.address)).to.equal(0); // Role.NONE

      // Attempt execution: auditor2's generation is now stale
      await expect(
        multiSig.connect(auditor1).executeProposal(1)
      ).to.be.revertedWith("MultiSig: approver authorization generation is stale or revoked");
    });

    it("should reject execution if proposal expiresAt has elapsed", async function () {
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [0]);
      const reasonHash = ethers.id("Expiring proposal");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        reasonHash
      );
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // Advance time by 25 hours (TTL is 24 hours)
      await ethers.provider.send("evm_increaseTime", [25 * 3600]);
      await ethers.provider.send("evm_mine");

      await expect(
        multiSig.connect(admin).executeProposal(1)
      ).to.be.revertedWith("MultiSig: proposal expired");
    });
  });

  describe("Separation of Duties (SoD) on Override Warning Proposals", function () {
    it("should prevent transaction sender or receiver from approving warning override proposal", async function () {
      // 1. Submit a flagged transaction where auditor2 is the receiver
      const largeAmount = ethers.parseEther("15000");
      await auditEngine.connect(operator).submitTransaction(auditor2.address, largeAmount);
      const txId = 1;

      // 2. Create proposal to override warning
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        txId,
        operator.address,
        auditor2.address,
        "Legitimate large institutional transfer"
      ]);
      const reasonHash = ethers.id("Override warning for TX 1");

      await multiSig.connect(auditor1).createProposal(
        ProposalType.OVERRIDE_WARNING,
        target,
        callData,
        reasonHash
      );

      // Auditor2 is an authorized AUDITOR, but is the beneficiary/receiver of this transaction!
      // Attempting to approve must revert with SoD conflict error:
      await expect(
        multiSig.connect(auditor2).approveProposal(1)
      ).to.be.revertedWith("MultiSig: transaction sender/receiver cannot approve override");
    });
  });

  describe("Pause Epoch Protection (Regression Fix)", function () {
    it("should reject an old unpause proposal for an older pause epoch when engine was re-paused", async function () {
      // Pause 1
      await auditEngine.connect(admin).emergencyPause("First incident");
      const epoch1 = await auditEngine.pauseEpoch();

      // Create unpause proposal for epoch 1
      const target = await auditEngine.getAddress();
      const callData = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [epoch1]);
      await multiSig.connect(auditor1).createProposal(
        ProposalType.EMERGENCY_UNPAUSE,
        target,
        callData,
        ethers.id("Unpause epoch 1")
      );
      await multiSig.connect(admin).approveProposal(1);
      await multiSig.connect(auditor2).approveProposal(1);

      // Execute unpause 1
      await multiSig.connect(admin).executeProposal(1);
      expect(await auditEngine.isPaused()).to.equal(false);

      // Pause 2 (increments epoch to epoch2)
      await auditEngine.connect(admin).emergencyPause("Second incident");
      expect(await auditEngine.isPaused()).to.equal(true);

      // Attempting to reuse or re-execute proposal 1 MUST be rejected
      await expect(
        multiSig.connect(admin).executeProposal(1)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");
    });
  });
});
