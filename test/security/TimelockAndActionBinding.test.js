const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySystemFixture, PARTICIPANT_IDS } = require("../helpers/deploySystem");

/**
 * R03 — توحيد الحوكمة وربط بيانات التنفيذ (Unified governance, execution-data
 * binding, timelock/action-table enforcement)
 *
 * Binding design decisions (spec §4, §6, §7):
 *   - Every proposal type has a CLOSED target+selector table. Targets are only
 *     the contract addresses registered at configure time; setGovernance and
 *     any generic call are unreachable. Action data is decoded with the exact
 *     types, length-checked and RE-ENCODED so trailing garbage is rejected.
 *   - POLICY_CHANGE / ROLE_CHANGE / SYSTEM_CONFIG grants and setBusinessHours
 *     wait 86,400s; OVERRIDE_WARNING / EMERGENCY_UNPAUSE / SYSTEM_CONFIG
 *     revocations wait 0s (quorum still required). TTL = 259,200s for all
 *     types; execution at now >= expiresAt fails.
 *   - Execution re-checks permissions, generations (proposer + every recorded
 *     voter, identity-scoped via the CURRENT active wallet), quorum, expiry
 *     and epoch. Only the bytes stored at creation are executed, once.
 *   - Old parallel-admin paths (setPolicy, overrideWarning, emergencyUnpause,
 *     ...) are GONE: after bootstrap a SUPER_ADMIN cannot bypass governance.
 */

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

const ProposalStatus = {
  PENDING: 0,
  APPROVED: 1,
  EXECUTED: 2,
  REJECTED: 3,
  EXPIRED: 4,
  CANCELLED: 5,
};

const DAY = 86_400n;
const TTL = 259_200n;

// Hand-built interface of the REMOVED parallel-admin functions: the production
// ABI no longer declares them after R03, so raw calldata is the only way to
// probe them (same technique as the R01 NoTestBackdoor suite).
const LEGACY_INTERFACE = new ethers.Interface([
  "function overrideWarning(uint256,string)",
  "function overrideWarningWithMultiSig(uint256,uint256,string)",
  "function emergencyUnpause(uint256)",
  "function setMultiSigOverrideEnforcement(bool)",
  "function setPolicyTimelockDelay(uint256)",
  "function proposePolicyChange(uint8)",
  "function proposeCustomThresholds(uint256,uint256,uint256,uint256,uint256)",
  "function executePolicyChangeWithMultiSig(uint256)",
  "function cancelPolicyChange()",
  "function setPolicy(uint8)",
  "function setCustomThresholds(uint256,uint256,uint256,uint256,uint256)",
]);

const LARGE_AMOUNT = ethers.parseEther("15000");

async function setNextBlockTimestamp(ts) {
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(ts)]);
}

async function governanceProposal(system, { proposer, type, target, data, description }) {
  const descriptionString =
    description === undefined ? "R03 governance proposal" : description;
  await system.multiSig
    .connect(proposer)
    .createProposal(type, target, data, descriptionString);
  return Number(await system.multiSig.totalProposals());
}

describe("Timelock & Closed Action Binding (R03)", function () {
  let system;
  let multiSig, roleManager, auditEngine, insiderLog, forensicTrail;
  let bootstrapAuthority, admin, auditor1, auditor2, operator, regulator, outsider;

  beforeEach(async function () {
    system = await deploySystemFixture();
    multiSig = system.multiSig;
    roleManager = system.roleManager;
    auditEngine = system.auditEngine;
    insiderLog = system.insiderLog;
    forensicTrail = system.forensicTrail;
    bootstrapAuthority = system.bootstrapAuthority;
    admin = system.admin;
    auditor1 = system.auditor1;
    auditor2 = system.auditor2;
    operator = system.operator;
    regulator = system.regulator;
    outsider = system.outsider;
  });

  // Helper: calldata factories for the closed action table.
  function overrideCalldata(txId, sender, receiver, justification) {
    return auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
      txId,
      sender,
      receiver,
      justification,
    ]);
  }

  async function flagTransaction() {
    await auditEngine.connect(operator).submitTransaction(outsider.address, LARGE_AMOUNT);
    return 1;
  }

  describe("admin_cannot_bypass_after_bootstrap", function () {
    it("legacy SUPER_ADMIN direct calls all revert and neither policy nor FLAGGED state changes", async function () {
      const txId = await flagTransaction();
      const auditEngineAddress = await auditEngine.getAddress();

      const legacyCalls = [
        LEGACY_INTERFACE.encodeFunctionData("overrideWarning", [txId, "direct bypass"]),
        LEGACY_INTERFACE.encodeFunctionData("overrideWarningWithMultiSig", [txId, 1, "bypass"]),
        LEGACY_INTERFACE.encodeFunctionData("emergencyUnpause", [1]),
        LEGACY_INTERFACE.encodeFunctionData("setMultiSigOverrideEnforcement", [true]),
        LEGACY_INTERFACE.encodeFunctionData("setPolicyTimelockDelay", [DAY]),
        LEGACY_INTERFACE.encodeFunctionData("proposePolicyChange", [1]),
        LEGACY_INTERFACE.encodeFunctionData("proposeCustomThresholds", [1n, 2n, 3n, 4n, 5n]),
        LEGACY_INTERFACE.encodeFunctionData("executePolicyChangeWithMultiSig", [1]),
        LEGACY_INTERFACE.encodeFunctionData("cancelPolicyChange"),
        LEGACY_INTERFACE.encodeFunctionData("setPolicy", [1]),
        LEGACY_INTERFACE.encodeFunctionData("setCustomThresholds", [1n, 2n, 3n, 4n, 5n]),
      ];
      for (const data of legacyCalls) {
        await expect(
          admin.sendTransaction({ to: auditEngineAddress, data })
        ).to.be.reverted;
      }

      // The surviving execute interfaces are governance-only: after bootstrap
      // governance is the MultiSig coordinator, not the SUPER_ADMIN wallet.
      await expect(
        auditEngine.connect(admin).executePolicyChange(1)
      ).to.be.revertedWith("AuditEngine: caller is not governance");
      await expect(
        auditEngine.connect(admin).executeCustomThresholds(1n, 2n, 3n, 4n, 5n)
      ).to.be.revertedWith("AuditEngine: caller is not governance");
      await expect(
        auditEngine.connect(admin).executeEmergencyUnpause(1)
      ).to.be.revertedWith("AuditEngine: caller is not governance");

      // State untouched: policy unchanged, transaction still FLAGGED.
      expect(await auditEngine.activePolicy()).to.equal(0); // IRAQ_CBI
      const txn = await auditEngine.getTransaction(txId);
      expect(txn.isFlagged).to.equal(true);
      expect(txn.status).to.equal(2); // FLAGGED
    });
  });

  describe("forbidden_type_selector_target", function () {
    it("rejects ROLE_CHANGE carrying override calldata (wrong selector for the type)", async function () {
      const txId = await flagTransaction();
      const txn = await auditEngine.getTransaction(txId);
      const data = overrideCalldata(txId, txn.sender, txn.receiver, "type confusion");

      // Override calldata against the RoleManager target: selector not in the
      // ROLE_CHANGE closed list.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.ROLE_CHANGE,
            await roleManager.getAddress(),
            data,
            "ROLE_CHANGE with override selector"
          )
      ).to.be.revertedWith("MultiSig: forbidden selector for proposal type");

      // And against the AuditEngine target: wrong target for ROLE_CHANGE.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.ROLE_CHANGE,
            await auditEngine.getAddress(),
            data,
            "ROLE_CHANGE with wrong target"
          )
      ).to.be.revertedWith("MultiSig: forbidden target for proposal type");
    });

    it("rejects a random contract target and an EOA target", async function () {
      const data = auditEngine.interface.encodeFunctionData("executePolicyChange", [1]);

      // A deployed contract that is not the registered target for POLICY_CHANGE.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.POLICY_CHANGE,
            await forensicTrail.getAddress(),
            data,
            "random contract target"
          )
      ).to.be.revertedWith("MultiSig: forbidden target for proposal type");

      // An EOA target.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.POLICY_CHANGE,
            outsider.address,
            data,
            "EOA target"
          )
      ).to.be.revertedWith("MultiSig: forbidden target for proposal type");
    });

    it("rejects setGovernance under every proposal type (governance migration is unreachable)", async function () {
      const roleGovernanceData = roleManager.interface.encodeFunctionData("setGovernance", [
        outsider.address,
      ]);
      const forensicGovernanceData = forensicTrail.interface.encodeFunctionData("setGovernance", [
        outsider.address,
      ]);

      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.ROLE_CHANGE,
            await roleManager.getAddress(),
            roleGovernanceData,
            "roleManager.setGovernance"
          )
      ).to.be.revertedWith("MultiSig: forbidden selector for proposal type");

      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.SYSTEM_CONFIG,
            await forensicTrail.getAddress(),
            forensicGovernanceData,
            "forensicTrail.setGovernance"
          )
      ).to.be.revertedWith("MultiSig: forbidden selector for proposal type");
    });

    it("rejects override calldata whose sender/receiver do not match the AuditEngine record", async function () {
      const txId = await flagTransaction();
      const txn = await auditEngine.getTransaction(txId);

      // Swapped parties.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.OVERRIDE_WARNING,
            await auditEngine.getAddress(),
            overrideCalldata(txId, txn.receiver, txn.sender, "swapped parties"),
            "swapped parties"
          )
      ).to.be.revertedWith("AuditEngine: transaction party mismatch");

      // Fully fabricated parties.
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.OVERRIDE_WARNING,
            await auditEngine.getAddress(),
            overrideCalldata(txId, outsider.address, regulator.address, "fabricated parties"),
            "fabricated parties"
          )
      ).to.be.revertedWith("AuditEngine: transaction party mismatch");
    });

    it("rejects SYSTEM_CONFIG calldata with trailing garbage (decode + re-encode check)", async function () {
      const clean = auditEngine.interface.encodeFunctionData("setBusinessHours", [9, 18]);
      const garbage = clean + "deadbeef"; // extra bytes after a valid encoding

      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.SYSTEM_CONFIG,
            await auditEngine.getAddress(),
            garbage,
            "trailing garbage"
          )
      ).to.be.revertedWith("MultiSig: malformed action data");
    });
  });

  describe("timelock_boundaries", function () {
    it("POLICY_CHANGE fails at created+86,399, succeeds exactly once at +86,400, fails at expiresAt", async function () {
      const data = auditEngine.interface.encodeFunctionData("executePolicyChange", [1]); // GLOBAL_FATF
      const proposalId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.POLICY_CHANGE,
        target: await auditEngine.getAddress(),
        data,
        description: "Switch to FATF policy",
      });
      await multiSig.connect(admin).approveProposal(proposalId);
      await multiSig.connect(auditor2).approveProposal(proposalId);

      const prop = await multiSig.getProposal(proposalId);
      expect(prop.notBefore).to.equal(prop.createdAt + DAY);
      expect(prop.expiresAt).to.equal(prop.createdAt + TTL);

      // created + 86,399 -> timelock still active.
      await setNextBlockTimestamp(prop.createdAt + DAY - 1n);
      await expect(
        multiSig.connect(admin).executeProposal(proposalId)
      ).to.be.revertedWith("MultiSig: timelock active");
      expect((await multiSig.getProposal(proposalId)).status).to.equal(ProposalStatus.APPROVED);

      // created + 86,400 -> executes exactly once.
      await setNextBlockTimestamp(prop.createdAt + DAY);
      await multiSig.connect(outsider).executeProposal(proposalId);
      expect(await auditEngine.activePolicy()).to.equal(1); // GLOBAL_FATF
      expect((await multiSig.getProposal(proposalId)).status).to.equal(ProposalStatus.EXECUTED);
      await expect(
        multiSig.connect(admin).executeProposal(proposalId)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");

      // A second proposal at now >= expiresAt fails the now>=expiresAt rule.
      const secondId = await governanceProposal(system, {
        proposer: auditor2,
        type: ProposalType.POLICY_CHANGE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executePolicyChange", [0]),
        description: "Back to CBI policy",
      });
      await multiSig.connect(admin).approveProposal(secondId);
      await multiSig.connect(auditor1).approveProposal(secondId);
      const second = await multiSig.getProposal(secondId);
      await setNextBlockTimestamp(second.expiresAt);
      await expect(
        multiSig.connect(admin).executeProposal(secondId)
      ).to.be.revertedWith("MultiSig: proposal expired");
    });

    it("OVERRIDE_WARNING has zero delay but still expires at now>=expiresAt", async function () {
      const txId = await flagTransaction();
      const txn = await auditEngine.getTransaction(txId);
      const proposalId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.OVERRIDE_WARNING,
        target: await auditEngine.getAddress(),
        data: overrideCalldata(txId, txn.sender, txn.receiver, "Zero-delay override"),
        description: "Zero-delay override",
      });
      const prop = await multiSig.getProposal(proposalId);
      expect(prop.notBefore).to.equal(prop.createdAt); // delay 0

      await multiSig.connect(admin).approveProposal(proposalId);
      await multiSig.connect(auditor2).approveProposal(proposalId);
      await multiSig.connect(outsider).executeProposal(proposalId); // permissionless
      expect((await auditEngine.getTransaction(txId)).status).to.equal(1); // CLEARED

      await setNextBlockTimestamp(prop.expiresAt);
      await expect(
        multiSig.connect(admin).executeProposal(proposalId)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");
    });
  });

  describe("stale_generation_after_approval", function () {
    it("an approver whose generation changed via assignRole (still active, still eligible) fails execution", async function () {
      // Proposal 1: a POLICY_CHANGE approved by admin + auditor2.
      const firstId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.POLICY_CHANGE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executePolicyChange", [1]),
        description: "Policy change pending staleness",
      });
      await multiSig.connect(admin).approveProposal(firstId);
      await multiSig.connect(auditor2).approveProposal(firstId);

      // Proposal 2: rotate auditor2's ROLE (AUDITOR -> SUPER_ADMIN) through the
      // real governance path. assignRole bumps the identity generation while
      // the participant stays ACTIVE and ELIGIBLE — isolating the generation
      // conjunct of the execution re-check.
      const rotateId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.ROLE_CHANGE,
        target: await roleManager.getAddress(),
        data: roleManager.interface.encodeFunctionData("assignRole", [
          auditor2.address,
          Role.SUPER_ADMIN,
          "R03: rotate auditor2 role, isolating the generation conjunct",
        ]),
        description: "Rotate auditor2 role",
      });
      await multiSig.connect(admin).approveProposal(rotateId);
      await multiSig.connect(auditor2).approveProposal(rotateId);
      const rotate = await multiSig.getProposal(rotateId);
      await setNextBlockTimestamp(rotate.notBefore);
      await multiSig.connect(admin).executeProposal(rotateId);
      expect(await roleManager.getRole(auditor2.address)).to.equal(Role.SUPER_ADMIN);

      const voter = await roleManager.getParticipant(auditor2.address);
      expect(voter.active).to.equal(true); // active conjunct holds
      expect(voter.generation).to.equal(2n); // generation conjunct is stale

      await expect(
        multiSig.connect(admin).executeProposal(firstId)
      ).to.be.revertedWith("MultiSig: approver authorization generation is stale or revoked");
      expect((await multiSig.getProposal(firstId)).status).to.equal(ProposalStatus.APPROVED);
      expect(await auditEngine.activePolicy()).to.equal(0); // unchanged
    });
  });

  describe("proposer_rotation", function () {
    it("mid-proposal wallet rotation bumps the proposer generation and forces a new proposal", async function () {
      const [, , , , , , , freshWallet] = await ethers.getSigners();

      const firstId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.POLICY_CHANGE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executePolicyChange", [1]),
        description: "Proposed before rotation",
      });
      await multiSig.connect(admin).approveProposal(firstId);
      await multiSig.connect(auditor2).approveProposal(firstId);

      // Rotate the PROPOSER's wallet (PID_AUDITOR_1) through governance.
      const rotateId = await governanceProposal(system, {
        proposer: admin,
        type: ProposalType.ROLE_CHANGE,
        target: await roleManager.getAddress(),
        data: roleManager.interface.encodeFunctionData("rotateParticipantWallet", [
          PARTICIPANT_IDS.AUDITOR_1,
          freshWallet.address,
          "R03: proposer wallet rotation mid-proposal",
        ]),
        description: "Rotate proposer wallet",
      });
      await multiSig.connect(auditor2).approveProposal(rotateId);
      await multiSig.connect(regulator).approveProposal(rotateId);
      const rotate = await multiSig.getProposal(rotateId);
      await setNextBlockTimestamp(rotate.notBefore);
      await multiSig.connect(admin).executeProposal(rotateId);
      expect(await roleManager.getActiveWallet(PARTICIPANT_IDS.AUDITOR_1)).to.equal(
        freshWallet.address
      );

      await expect(
        multiSig.connect(admin).executeProposal(firstId)
      ).to.be.revertedWith("MultiSig: proposer authorization generation is stale or revoked");
      expect((await multiSig.getProposal(firstId)).status).to.equal(ProposalStatus.APPROVED);
      expect(await auditEngine.activePolicy()).to.equal(0); // never executed
    });
  });

  describe("participant_is_transaction_party", function () {
    it("a transaction party cannot propose or approve the override of its own warning", async function () {
      // admin (enrolled SUPER_ADMIN) is the SENDER, auditor2 the RECEIVER.
      await auditEngine.connect(admin).submitTransaction(auditor2.address, LARGE_AMOUNT);
      const txId = 1;
      const txn = await auditEngine.getTransaction(txId);
      expect(txn.isFlagged).to.equal(true);
      const data = overrideCalldata(txId, txn.sender, txn.receiver, "Party override attempt");

      // Sender party cannot propose.
      await expect(
        multiSig
          .connect(admin)
          .createProposal(
            ProposalType.OVERRIDE_WARNING,
            await auditEngine.getAddress(),
            data,
            "Proposed by the transaction sender"
          )
      ).to.be.revertedWith("MultiSig: transaction party cannot propose override");
      expect(await multiSig.totalProposals()).to.equal(0);

      // Receiver party cannot approve a valid proposal from a neutral proposer.
      const proposalId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.OVERRIDE_WARNING,
        target: await auditEngine.getAddress(),
        data,
        description: "Neutral proposer override",
      });
      await expect(
        multiSig.connect(auditor2).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: transaction sender/receiver cannot approve override");

      const prop = await multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(0);
      expect(prop.status).to.equal(ProposalStatus.PENDING);
      expect((await auditEngine.getTransaction(txId)).status).to.equal(2); // still FLAGGED
    });
  });

  describe("emergency_epoch_replay", function () {
    it("an unpause proposal for a previous epoch never unpauses a later pause", async function () {
      await auditEngine.connect(admin).emergencyPause("First incident");
      const epoch1 = await auditEngine.pauseEpoch();

      // Unpause for epoch 1 and execute it.
      const firstId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.EMERGENCY_UNPAUSE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [epoch1]),
        description: "Unpause epoch 1",
      });
      await multiSig.connect(admin).approveProposal(firstId);
      await multiSig.connect(auditor2).approveProposal(firstId);
      await multiSig.connect(admin).executeProposal(firstId);
      expect(await auditEngine.isPaused()).to.equal(false);

      // Re-pause: epoch becomes 2.
      await auditEngine.connect(admin).emergencyPause("Second incident");
      const epoch2 = await auditEngine.pauseEpoch();
      expect(epoch2).to.equal(epoch1 + 1n);

      // A stale proposal still bound to epoch 1 must NOT unpause epoch 2.
      const staleId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.EMERGENCY_UNPAUSE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [epoch1]),
        description: "Stale epoch unpause",
      });
      await multiSig.connect(admin).approveProposal(staleId);
      await multiSig.connect(auditor2).approveProposal(staleId);
      await expect(
        multiSig.connect(admin).executeProposal(staleId)
      ).to.be.revertedWith("AuditEngine: invalid pause epoch");
      expect(await auditEngine.isPaused()).to.equal(true);
      // Target revert must not consume the proposal.
      expect((await multiSig.getProposal(staleId)).status).to.equal(ProposalStatus.APPROVED);

      // The current-epoch proposal unpauses normally.
      const validId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.EMERGENCY_UNPAUSE,
        target: await auditEngine.getAddress(),
        data: auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [epoch2]),
        description: "Unpause current epoch",
      });
      await multiSig.connect(admin).approveProposal(validId);
      await multiSig.connect(auditor2).approveProposal(validId);
      await multiSig.connect(admin).executeProposal(validId);
      expect(await auditEngine.isPaused()).to.equal(false);
    });
  });

  describe("writer_revocation_immediate_but_grant_delayed", function () {
    it("revocation (authorized=false) executes at delay 0; grant (authorized=true) waits 86,400 — both with two approvals", async function () {
      // Grant to a new writer: delay 86,400 even with quorum reached.
      const grantId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.SYSTEM_CONFIG,
        target: await forensicTrail.getAddress(),
        data: forensicTrail.interface.encodeFunctionData("setEvidenceWriter", [
          outsider.address,
          true,
        ]),
        description: "Grant evidence writer",
      });
      await multiSig.connect(admin).approveProposal(grantId);
      await multiSig.connect(auditor2).approveProposal(grantId);
      const grant = await multiSig.getProposal(grantId);
      expect(grant.notBefore).to.equal(grant.createdAt + DAY);

      await setNextBlockTimestamp(grant.createdAt + DAY - 1n);
      await expect(
        multiSig.connect(admin).executeProposal(grantId)
      ).to.be.revertedWith("MultiSig: timelock active");
      expect(await forensicTrail.isEvidenceWriter(outsider.address)).to.equal(false);

      await setNextBlockTimestamp(grant.createdAt + DAY);
      await multiSig.connect(admin).executeProposal(grantId);
      expect(await forensicTrail.isEvidenceWriter(outsider.address)).to.equal(true);

      // Revocation of an existing writer: delay 0, quorum still required.
      const revokeId = await governanceProposal(system, {
        proposer: auditor1,
        type: ProposalType.SYSTEM_CONFIG,
        target: await forensicTrail.getAddress(),
        data: forensicTrail.interface.encodeFunctionData("setEvidenceWriter", [
          await auditEngine.getAddress(),
          false,
        ]),
        description: "Revoke evidence writer",
      });
      const revoke = await multiSig.getProposal(revokeId);
      expect(revoke.notBefore).to.equal(revoke.createdAt); // immediate

      await expect(
        multiSig.connect(admin).executeProposal(revokeId)
      ).to.be.revertedWith("MultiSig: proposal is not approved or already executed"); // quorum not reached yet
      await multiSig.connect(admin).approveProposal(revokeId);
      await multiSig.connect(auditor2).approveProposal(revokeId);
      await multiSig.connect(outsider).executeProposal(revokeId); // no delay, both approvals
      expect(await forensicTrail.isEvidenceWriter(await auditEngine.getAddress())).to.equal(false);
    });

    it("SYSTEM_CONFIG trailing-garbage setRecorder calldata is rejected at creation", async function () {
      const clean = insiderLog.interface.encodeFunctionData("setRecorder", [
        outsider.address,
        true,
      ]);
      await expect(
        multiSig
          .connect(auditor1)
          .createProposal(
            ProposalType.SYSTEM_CONFIG,
            await insiderLog.getAddress(),
            clean + "00",
            "trailing garbage recorder grant"
          )
      ).to.be.revertedWith("MultiSig: malformed action data");
    });
  });
});
