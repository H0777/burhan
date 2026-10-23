const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

/**
 * R02 — Participant Identity, Wallet Rotation & Bootstrap Quorum
 *
 * Binding design decisions (spec §4):
 *   - A participant is a FIXED institutional bytes32 identity with exactly one
 *     active wallet. Enrollment/rotation are governance-only; assignRole no
 *     longer mints address-derived identities — it requires prior enrollment.
 *   - A retired (rotated-away) wallet keeps its historical binding forever and
 *     can never be re-attributed to another person.
 *   - A participant's authorization generation strictly increases across every
 *     grant/revoke/rotation and is carried in the emitted events.
 *   - Bootstrap finalization requires >= 4 distinct eligible voting identities
 *     (SUPER_ADMIN/AUDITOR only); OPERATOR/REGULATOR never count.
 *   - MultiSigApproval counts votes by participant identity, so one person
 *     holding two wallets (old + rotated) still casts exactly ONE vote.
 */

// Enum Role: NONE(0), SUPER_ADMIN(1), AUDITOR(2), OPERATOR(3), REGULATOR(4)
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

// Fixed institutional roster IDs — deterministic fixture values, deliberately
// NOT derived from personal names or wallet addresses. The person↔id mapping
// is held off-chain in institutional membership records (spec §4).
const PID_A = "0xf75c6ebddefb3ccfcaf608a6e4ec673954d92c03384453b0558baad01b8f9312";
const PID_B = "0xb8e57f1639ee0d87d1d6e4dea50ad06c36252162aedfa000809b86eb52b816b5";
const PID_C = "0xdd00acd20d9aa7c09f37a8b907f5da520b77c0f437ffa54788911409a319c478";
const PID_D = "0x657abc488cdbeb7f617116b73ec1508431ff09c7bfabed6f1c83ab4967113ee7";

describe("Participant Identity, Wallet Rotation & Bootstrap Quorum (R02)", function () {
  // ------------------------------------------------------------------
  // Standalone RoleManager fixture (governance = governor EOA)
  // ------------------------------------------------------------------
  async function deployRoleManager() {
    const signers = await ethers.getSigners();
    const [governor, alice, bob, carol] = signers;
    const RoleManager = await ethers.getContractFactory("RoleManager");
    const roleManager = await RoleManager.deploy(governor.address);
    await roleManager.waitForDeployment();
    return { roleManager, governor, alice, bob, carol };
  }

  // ------------------------------------------------------------------
  // Full system fixture (deployed + configured, bootstrap NOT finalized)
  // ------------------------------------------------------------------
  async function deploySystemCore() {
    const signers = await ethers.getSigners();
    const authority = signers[0];

    const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
    const multiSig = await MultiSigApproval.deploy(authority.address, 2);
    await multiSig.waitForDeployment();

    // RoleManager is deployed by `authority`, so `roleManager.deployer()`
    // resolves to the temporary bootstrap authority wallet.
    const RoleManager = await ethers.getContractFactory("RoleManager");
    const roleManager = await RoleManager.deploy(await multiSig.getAddress());
    await roleManager.waitForDeployment();

    const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
    const insiderLog = await InsiderActivityLog.deploy(await multiSig.getAddress());
    await insiderLog.waitForDeployment();

    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    const forensicTrail = await ForensicTrail.deploy(await multiSig.getAddress());
    await forensicTrail.waitForDeployment();

    const AuditEngine = await ethers.getContractFactory("AuditEngine");
    const auditEngine = await AuditEngine.deploy(await multiSig.getAddress());
    await auditEngine.waitForDeployment();

    await multiSig.connect(authority).configureContracts(
      await roleManager.getAddress(),
      await auditEngine.getAddress(),
      await insiderLog.getAddress(),
      await forensicTrail.getAddress()
    );

    return { signers, authority, multiSig, roleManager, insiderLog, forensicTrail, auditEngine };
  }

  async function bootstrap(system, ids, wallets, roles, reasons) {
    return system.multiSig
      .connect(system.authority)
      .bootstrapParticipants(ids, wallets, roles, reasons);
  }

  // Governance-only rotation: must be driven through an executed ROLE_CHANGE
  // proposal because governance is the MultiSig contract itself. R03: the
  // ROLE_CHANGE timelock (86,400s) must elapse before execution.
  async function rotateViaGovernance(
    system,
    { proposer, approvers, executor },
    participantId,
    newWallet,
    reason
  ) {
    const calldata = system.roleManager.interface.encodeFunctionData("rotateParticipantWallet", [
      participantId,
      newWallet,
      reason,
    ]);
    await system.multiSig
      .connect(proposer)
      .createProposal(
        ProposalType.ROLE_CHANGE,
        await system.roleManager.getAddress(),
        calldata,
        ethers.id(reason)
      );
    const proposalId = await system.multiSig.totalProposals();
    for (const approver of approvers) {
      await system.multiSig.connect(approver).approveProposal(proposalId);
    }
    const proposal = await system.multiSig.getProposal(proposalId);
    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(proposal.notBefore)]);
    await system.multiSig.connect(executor).executeProposal(proposalId);
  }

  // R03 fix round 1: business hours belong to the SYSTEM_CONFIG closed action
  // targeting InsiderActivityLog directly (86,400s delay before execution).
  function policyProposalCalldata(system) {
    return system.insiderLog.interface.encodeFunctionData("setBusinessHours", [9, 18]);
  }

  // ==================================================================
  // duplicate_participant_rejected
  // ==================================================================
  describe("duplicate_participant_rejected", function () {
    it("reverts when the same institutional id is enrolled twice and keeps the original active wallet", async function () {
      const { roleManager, governor, alice, bob } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "Enroll chief auditor identity");

      await expect(
        roleManager
          .connect(governor)
          .enrollParticipant(PID_A, bob.address, Role.AUDITOR, "Duplicate identity attempt")
      ).to.be.revertedWith("RoleManager: participant already enrolled");

      // State unchanged: identity still bound to its original wallet only.
      expect(await roleManager.getActiveWallet(PID_A)).to.equal(alice.address);
      expect(await roleManager.countEligibleParticipants()).to.equal(1n);
    });

    it("does not count the address-derived deployer entry as an enrolled identity", async function () {
      const { roleManager, governor, alice } = await deployRoleManager();
      // The governor (constructor deployer) holds SUPER_ADMIN but is NOT enrolled.
      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "Single enrollment");
      expect(await roleManager.countEligibleParticipants()).to.equal(1n);
    });
  });

  // ==================================================================
  // duplicate_wallet_rejected
  // ==================================================================
  describe("duplicate_wallet_rejected", function () {
    it("reverts when a wallet already bound to an identity is enrolled for a second identity", async function () {
      const { roleManager, governor, alice } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "First identity");

      await expect(
        roleManager
          .connect(governor)
          .enrollParticipant(PID_B, alice.address, Role.AUDITOR, "Wallet alias attempt")
      ).to.be.revertedWith("RoleManager: wallet already bound");
    });

    it("a rotated-away (retired) wallet keeps its historical binding and can never be re-bound to another person", async function () {
      const { roleManager, governor, alice, bob } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "First identity");
      await roleManager
        .connect(governor)
        .rotateParticipantWallet(PID_A, bob.address, "Annual hardware rotation");

      await expect(
        roleManager
          .connect(governor)
          .enrollParticipant(PID_B, alice.address, Role.AUDITOR, "Retired wallet rebind attempt")
      ).to.be.revertedWith("RoleManager: wallet already bound");

      // Historical attribution preserved: retired wallet still maps to PID_A.
      const retired = await roleManager.getParticipant(alice.address);
      expect(retired.participantId).to.equal(PID_A);
      expect(retired.active).to.equal(false);
    });
  });

  // ==================================================================
  // zero_id_rejected
  // ==================================================================
  describe("zero_id_rejected", function () {
    it("reverts when enrollParticipant receives bytes32(0)", async function () {
      const { roleManager, governor, alice } = await deployRoleManager();

      await expect(
        roleManager
          .connect(governor)
          .enrollParticipant(ethers.ZeroHash, alice.address, Role.AUDITOR, "Zero id enrollment")
      ).to.be.revertedWith("RoleManager: zero participant id");
    });

    it("reverts when rotateParticipantWallet receives bytes32(0)", async function () {
      const { roleManager, governor, alice } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "Enroll before zero-id rotation");

      await expect(
        roleManager
          .connect(governor)
          .rotateParticipantWallet(ethers.ZeroHash, alice.address, "Zero id rotation")
      ).to.be.revertedWith("RoleManager: zero participant id");
    });

    it("reverts when the bootstrap roster contains a zero participant id (whole enrollment rolls back)", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await expect(
        bootstrap(
          system,
          [PID_A, PID_B, PID_C, ethers.ZeroHash],
          [p1.address, p2.address, p3.address, p4.address],
          [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
          ["A", "B", "C", "zero"]
        )
      ).to.be.revertedWith("RoleManager: zero participant id");

      expect(await system.roleManager.countEligibleParticipants()).to.equal(0n);
    });
  });

  // ==================================================================
  // rotation_invalidates_old_wallet
  // ==================================================================
  describe("rotation_invalidates_old_wallet", function () {
    it("old wallet inactive, new wallet keeps the participantId, generation strictly increases, event carries id+generation", async function () {
      const { roleManager, governor, alice, bob } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "Initial enrollment");
      const generationBefore = await roleManager.getGeneration(alice.address);
      expect(generationBefore).to.equal(1n);

      const tx = roleManager
        .connect(governor)
        .rotateParticipantWallet(PID_A, bob.address, "Compromise suspected: rotate wallet");

      await expect(tx)
        .to.emit(roleManager, "WalletRotated")
        .withArgs(PID_A, alice.address, bob.address, 2n, "Compromise suspected: rotate wallet", anyValue);

      // Old wallet: same participantId, no role, permanently inactive.
      const oldParticipant = await roleManager.getParticipant(alice.address);
      expect(oldParticipant.participantId).to.equal(PID_A);
      expect(oldParticipant.role).to.equal(Role.NONE);
      expect(oldParticipant.active).to.equal(false);
      expect(oldParticipant.generation).to.equal(generationBefore); // stale, never rolled back
      expect(await roleManager.getRole(alice.address)).to.equal(Role.NONE);

      // New wallet: same participantId, active, higher generation.
      const newParticipant = await roleManager.getParticipant(bob.address);
      expect(newParticipant.participantId).to.equal(PID_A);
      expect(newParticipant.role).to.equal(Role.AUDITOR);
      expect(newParticipant.active).to.equal(true);
      const generationAfter = await roleManager.getGeneration(bob.address);
      expect(generationAfter).to.be.gt(generationBefore);
      expect(newParticipant.generation).to.equal(generationAfter);

      expect(await roleManager.getActiveWallet(PID_A)).to.equal(bob.address);
    });

    it("assignRole cannot re-target a rotated-away wallet", async function () {
      const { roleManager, governor, alice, bob } = await deployRoleManager();

      await roleManager
        .connect(governor)
        .enrollParticipant(PID_A, alice.address, Role.AUDITOR, "Initial enrollment");
      await roleManager
        .connect(governor)
        .rotateParticipantWallet(PID_A, bob.address, "Rotate away from alice");

      await expect(
        roleManager.connect(governor).assignRole(alice.address, Role.AUDITOR, "Re-target retired wallet")
      ).to.be.revertedWith("RoleManager: wallet not active for participant");
    });
  });

  // ==================================================================
  // bootstrap_requires_four_eligible_identities
  // ==================================================================
  describe("bootstrap_requires_four_eligible_identities", function () {
    it("three AUDITOR identities plus one OPERATOR do not satisfy the quorum (finalize reverts)", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.AUDITOR, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR],
        ["Auditor 1", "Auditor 2", "Auditor 3", "Operations only"]
      );

      expect(await system.roleManager.countEligibleParticipants()).to.equal(3n);

      await expect(
        system.multiSig.connect(system.authority).finalizeBootstrap()
      ).to.be.revertedWith("MultiSig: need at least 4 eligible participants");
      expect(await system.multiSig.isBootstrapFinalized()).to.equal(false);
    });

    it("OPERATOR and REGULATOR identities are never counted as eligible voters", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.AUDITOR, Role.AUDITOR, Role.OPERATOR, Role.REGULATOR],
        ["Auditor 1", "Auditor 2", "Operator", "Regulator"]
      );

      expect(await system.roleManager.countEligibleParticipants()).to.equal(2n);

      await expect(
        system.multiSig.connect(system.authority).finalizeBootstrap()
      ).to.be.revertedWith("MultiSig: need at least 4 eligible participants");
    });

    it("four distinct eligible identities finalize bootstrap, drop the deployer temporary role, and seal bootstrap permanently", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Admin", "Auditor 1", "Auditor 2", "Auditor 3"]
      );
      expect(await system.roleManager.countEligibleParticipants()).to.equal(4n);

      await expect(system.multiSig.connect(system.authority).finalizeBootstrap())
        .to.emit(system.multiSig, "BootstrapFinalized");

      expect(await system.multiSig.isBootstrapFinalized()).to.equal(true);
      expect(await system.multiSig.bootstrapAuthority()).to.equal(ethers.ZeroAddress);

      // Deployer (bootstrap authority, NOT in roster) loses its temporary role.
      expect(await system.roleManager.getRole(system.authority.address)).to.equal(Role.NONE);
      const deployerTuple = await system.roleManager.getParticipant(system.authority.address);
      expect(deployerTuple.participantId).to.equal(ethers.ZeroHash);
      expect(deployerTuple.active).to.equal(false);

      // Bootstrap can never be re-invoked and the authority cannot be resurrected.
      await expect(
        system.multiSig.connect(system.authority).finalizeBootstrap()
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");
      await expect(
        system.multiSig.connect(p1).configureContracts(
          await system.roleManager.getAddress(),
          await system.auditEngine.getAddress(),
          await system.insiderLog.getAddress(),
          await system.forensicTrail.getAddress()
        )
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");
      await expect(
        system.multiSig.connect(p1).bootstrapParticipants(
          [PID_A, PID_B, PID_C, PID_D],
          [p1.address, p2.address, p3.address, p4.address],
          [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
          ["A", "B", "C", "D"]
        )
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");

      // Eligible quorum intact after finalization.
      expect(await system.roleManager.countEligibleParticipants()).to.equal(4n);
    });

    it("the deployer keeps a role only when its wallet is explicitly enrolled in the roster", async function () {
      const system = await deploySystemCore();
      const [, p2, p3, p4] = system.signers;

      // The bootstrap authority's own wallet is explicitly enrolled as SUPER_ADMIN.
      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [system.authority.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Deployer in roster", "Auditor 1", "Auditor 2", "Auditor 3"]
      );

      await system.multiSig.connect(system.authority).finalizeBootstrap();

      expect(await system.roleManager.getRole(system.authority.address)).to.equal(Role.SUPER_ADMIN);
      const deployerTuple = await system.roleManager.getParticipant(system.authority.address);
      expect(deployerTuple.participantId).to.equal(PID_A);
      expect(deployerTuple.active).to.equal(true);
    });

    it("same-proposer vote cannot reach quorum — even through a rotated second wallet", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4, , p2New] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Admin", "Auditor 1", "Auditor 2", "Auditor 3"]
      );
      await system.multiSig.connect(system.authority).finalizeBootstrap();

      // p2 proposes a policy change.
      await system.multiSig
        .connect(p2)
        .createProposal(
          ProposalType.SYSTEM_CONFIG,
          await system.insiderLog.getAddress(),
          policyProposalCalldata(system),
          ethers.id("Adjust business hours")
        );
      const proposalId = await system.multiSig.totalProposals();

      // One independent approval by p1.
      await system.multiSig.connect(p1).approveProposal(proposalId);
      let prop = await system.multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(1n);
      expect(prop.status).to.equal(0n); // PENDING

      // The proposer cannot approve with the same wallet...
      await expect(
        system.multiSig.connect(p2).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: proposer cannot approve own proposal");

      // ...nor with a rotated second wallet of the SAME identity (identity-level four-eyes).
      await rotateViaGovernance(
        system,
        { proposer: p3, approvers: [p1, p4], executor: p1 },
        PID_B,
        p2New.address,
        "Rotate proposer wallet mid-proposal"
      );
      expect(await system.roleManager.getActiveWallet(PID_B)).to.equal(p2New.address);

      await expect(
        system.multiSig.connect(p2New).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: proposer cannot approve own proposal");

      // Quorum was never reached by the proposer's own vote.
      prop = await system.multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(1n);
      expect(prop.status).to.equal(0n); // PENDING
    });

    it("with one participant absent, the three remaining voters can propose and secure two independent approvals", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Admin", "Auditor 1", "Auditor 2", "Auditor 3"]
      );
      await system.multiSig.connect(system.authority).finalizeBootstrap();

      // p4 is absent (never participates). p2 proposes; p1 and p3 approve.
      await system.multiSig
        .connect(p2)
        .createProposal(
          ProposalType.SYSTEM_CONFIG,
          await system.insiderLog.getAddress(),
          policyProposalCalldata(system),
          ethers.id("Quorum without the absent voter")
        );
      const proposalId = await system.multiSig.totalProposals();

      await system.multiSig.connect(p1).approveProposal(proposalId);
      await expect(system.multiSig.connect(p3).approveProposal(proposalId))
        .to.emit(system.multiSig, "ProposalApproved")
        .withArgs(proposalId, p3.address, 2n, 2n);

      const prop = await system.multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(2n);
      expect(prop.status).to.equal(1n); // APPROVED

      // Executable without the absent participant — after the 86,400s
      // SYSTEM_CONFIG timelock elapses.
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(prop.notBefore)]);
      await expect(system.multiSig.connect(p1).executeProposal(proposalId))
        .to.emit(system.multiSig, "ProposalExecuted");
      expect((await system.multiSig.getProposal(proposalId)).status).to.equal(2n); // EXECUTED
    });

    it("quorum cannot be assumed when two of the four eligible voters are parties to the case", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Admin", "Auditor 1", "Auditor 2", "Auditor 3"]
      );
      await system.multiSig.connect(system.authority).finalizeBootstrap();

      // p4 (eligible voter) sends a flagged transaction to p3 (eligible voter).
      const largeAmount = ethers.parseEther("15000");
      await system.auditEngine.connect(p4).submitTransaction(p3.address, largeAmount);
      const txId = 1;

      const callData = system.auditEngine.interface.encodeFunctionData("executeOverrideWarning", [
        txId,
        p4.address,
        p3.address,
        "Legitimate institutional transfer",
      ]);
      await system.multiSig
        .connect(p1)
        .createProposal(
          ProposalType.OVERRIDE_WARNING,
          await system.auditEngine.getAddress(),
          callData,
          ethers.id("Override flagged TX 1")
        );
      const proposalId = await system.multiSig.totalProposals();

      // Only ONE neutral approver (p2) is available: p3 (receiver) and p4 (sender)
      // are parties to the case and must be rejected.
      await system.multiSig.connect(p2).approveProposal(proposalId);

      await expect(
        system.multiSig.connect(p3).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: transaction sender/receiver cannot approve override");
      await expect(
        system.multiSig.connect(p4).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: transaction sender/receiver cannot approve override");

      const prop = await system.multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(1n);
      expect(prop.status).to.equal(0n); // PENDING — quorum NOT available
    });

    it("one person voting with an old wallet then a rotated new wallet still casts exactly ONE vote", async function () {
      const system = await deploySystemCore();
      const [, p1, p2, p3, p4, , p1New] = system.signers;

      await bootstrap(
        system,
        [PID_A, PID_B, PID_C, PID_D],
        [p1.address, p2.address, p3.address, p4.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.AUDITOR],
        ["Admin", "Auditor 1", "Auditor 2", "Auditor 3"]
      );
      await system.multiSig.connect(system.authority).finalizeBootstrap();

      // p2 proposes; p1 (PID_A) approves with the old wallet.
      await system.multiSig
        .connect(p2)
        .createProposal(
          ProposalType.SYSTEM_CONFIG,
          await system.insiderLog.getAddress(),
          policyProposalCalldata(system),
          ethers.id("Alias vote test proposal")
        );
      const proposalId = await system.multiSig.totalProposals();
      await system.multiSig.connect(p1).approveProposal(proposalId);

      // Rotate p1's wallet through the real governance path.
      await rotateViaGovernance(
        system,
        { proposer: p3, approvers: [p2, p4], executor: p2 },
        PID_A,
        p1New.address,
        "Rotate voter wallet after voting"
      );

      // The same person's new wallet cannot add a second vote for PID_A.
      await expect(
        system.multiSig.connect(p1New).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: participant has already voted");

      // The rotated-away old wallet is inactive and cannot vote either.
      await expect(
        system.multiSig.connect(p1).approveProposal(proposalId)
      ).to.be.revertedWith("MultiSig: caller not authorized to participate");

      const prop = await system.multiSig.getProposal(proposalId);
      expect(prop.approvalCount).to.equal(1n); // exactly one vote for the identity
    });
  });
});
