const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MultiSigApproval", function () {
  let roleManager;
  let multiSig;
  let deployer, auditor1, auditor2, operator, outsider;

  const Role = {
    NONE: 0,
    SUPER_ADMIN: 1,
    AUDITOR: 2,
    OPERATOR: 3,
    REGULATOR: 4,
  };

  const ProposalType = {
    OVERRIDE_WARNING: 0,
    HIGH_VALUE_APPROVAL: 1,
    POLICY_CHANGE: 2,
    ROLE_CHANGE: 3,
  };

  const ProposalStatus = {
    PENDING: 0,
    APPROVED: 1,
    REJECTED: 2,
    EXPIRED: 3,
  };

  const REQUIRED_APPROVALS = 2;
  const TTL_HOURS = 24;

const { deploySystemFixture } = require("./helpers/deploySystem");

  beforeEach(async function () {
    const system = await deploySystemFixture();
    multiSig = system.multiSig;
    roleManager = system.roleManager;
    deployer = system.admin;
    auditor1 = system.auditor1;
    auditor2 = system.auditor2;
    operator = system.operator;
    outsider = system.outsider;
  });

  describe("Deployment & Configuration", function () {
    it("Should configure correct initial parameters", async function () {
      expect(await multiSig.roleManager()).to.equal(await roleManager.getAddress());
      expect(await multiSig.requiredApprovals()).to.equal(REQUIRED_APPROVALS);
      expect(await multiSig.proposalTTL()).to.equal(BigInt(TTL_HOURS * 3600));
      expect(await multiSig.totalProposals()).to.equal(0);
    });

    it("Should revert deployment on invalid arguments", async function () {
      const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
      await expect(
        MultiSigApproval.deploy(ethers.ZeroAddress, REQUIRED_APPROVALS, TTL_HOURS)
      ).to.be.revertedWith("MultiSig: invalid bootstrap authority");

      await expect(
        MultiSigApproval.deploy(deployer.address, 1, TTL_HOURS)
      ).to.be.revertedWith("MultiSig: need at least 2 approvals");

      await expect(
        MultiSigApproval.deploy(deployer.address, REQUIRED_APPROVALS, 0)
      ).to.be.revertedWith("MultiSig: TTL must be positive");
    });
  });

  describe("Proposal Creation", function () {
    it("Should allow SUPER_ADMIN to create a proposal", async function () {
      const dummyData = ethers.hexlify(ethers.toUtf8Bytes("override-tx-42"));
      const tx = await multiSig.connect(deployer).createProposal(
        ProposalType.OVERRIDE_WARNING,
        dummyData,
        "Customer provided verifiable tax documentation"
      );

      const receipt = await tx.wait();
      expect(await multiSig.totalProposals()).to.equal(1);

      const prop = await multiSig.getProposal(1);
      expect(prop.id).to.equal(1);
      expect(prop.proposalType).to.equal(ProposalType.OVERRIDE_WARNING);
      expect(prop.proposer).to.equal(deployer.address);
      expect(prop.data).to.equal(dummyData);
      expect(prop.reason).to.equal("Customer provided verifiable tax documentation");
      expect(prop.status).to.equal(ProposalStatus.PENDING);
      expect(prop.approvalCount).to.equal(0);
    });

    it("Should allow AUDITOR to create a proposal", async function () {
      const dummyData = "0x1234";
      await expect(
        multiSig.connect(auditor1).createProposal(ProposalType.HIGH_VALUE_APPROVAL, dummyData, "Whale transfer")
      ).to.emit(multiSig, "ProposalCreated");
    });

    it("Should revert if OPERATOR or outsider creates proposal", async function () {
      const dummyData = "0x1234";
      await expect(
        multiSig.connect(operator).createProposal(ProposalType.POLICY_CHANGE, dummyData, "Operator attempt")
      ).to.be.revertedWith("MultiSig: caller not authorized to participate");

      await expect(
        multiSig.connect(outsider).createProposal(ProposalType.POLICY_CHANGE, dummyData, "Outsider attempt")
      ).to.be.revertedWith("MultiSig: caller not authorized to participate");
    });
  });

  describe("Approval Flow & Execution", function () {
    beforeEach(async function () {
      const dummyData = ethers.hexlify(ethers.toUtf8Bytes("override-tx-101"));
      await multiSig.connect(deployer).createProposal(
        ProposalType.OVERRIDE_WARNING,
        dummyData,
        "Clear false positive"
      );
    });

    it("Should revert if proposer tries to approve own proposal (Four-Eyes Principle)", async function () {
      await expect(
        multiSig.connect(deployer).approveProposal(1)
      ).to.be.revertedWith("MultiSig: proposer cannot self-approve");
    });

    it("Should record first approval without auto-executing", async function () {
      await expect(multiSig.connect(auditor1).approveProposal(1))
        .to.emit(multiSig, "ProposalApproved")
        .withArgs(1, auditor1.address, 1, REQUIRED_APPROVALS);

      const prop = await multiSig.getProposal(1);
      expect(prop.approvalCount).to.equal(1);
      expect(prop.status).to.equal(ProposalStatus.PENDING);
      expect(await multiSig.hasVoted(1, auditor1.address)).to.equal(true);
      expect(await multiSig.isApproved(1)).to.equal(false);
    });

    it("Should auto-execute and mark APPROVED when required approvals met", async function () {
      await multiSig.connect(auditor1).approveProposal(1);

      await expect(multiSig.connect(auditor2).approveProposal(1))
        .to.emit(multiSig, "ProposalExecuted");

      const prop = await multiSig.getProposal(1);
      expect(prop.approvalCount).to.equal(2);
      expect(prop.status).to.equal(ProposalStatus.APPROVED);
      expect(await multiSig.isApproved(1)).to.equal(true);
    });

    it("Should revert if same approver votes twice", async function () {
      await multiSig.connect(auditor1).approveProposal(1);
      await expect(
        multiSig.connect(auditor1).approveProposal(1)
      ).to.be.revertedWith("MultiSig: already voted");
    });
  });

  describe("Rejection Flow", function () {
    beforeEach(async function () {
      const dummyData = "0x9999";
      await multiSig.connect(deployer).createProposal(
        ProposalType.HIGH_VALUE_APPROVAL,
        dummyData,
        "Suspicious off-shore transfer"
      );
    });

    it("Should allow authorized auditor to reject proposal", async function () {
      await expect(
        multiSig.connect(auditor1).rejectProposal(1, "Suspected structuring fraud")
      )
        .to.emit(multiSig, "ProposalRejected")
        .withArgs(1, auditor1.address, "Suspected structuring fraud");

      const prop = await multiSig.getProposal(1);
      expect(prop.status).to.equal(ProposalStatus.REJECTED);
      expect(prop.rejectionCount).to.equal(1);
    });

    it("Should not allow approvals after rejection", async function () {
      await multiSig.connect(auditor1).rejectProposal(1, "Rejected");
      await expect(
        multiSig.connect(auditor2).approveProposal(1)
      ).to.be.revertedWith("MultiSig: not pending");
    });
  });

  describe("Proposal Expiration & View Queries", function () {
    beforeEach(async function () {
      const dummyData = "0x8888";
      await multiSig.connect(deployer).createProposal(ProposalType.POLICY_CHANGE, dummyData, "Policy update");
    });

    it("Should correctly track pending proposals", async function () {
      const pending = await multiSig.getPendingProposals();
      expect(pending.length).to.equal(1);
      expect(pending[0]).to.equal(1);
    });

    it("Should expire proposal after TTL has passed", async function () {
      // Fast forward time by 25 hours
      await ethers.provider.send("evm_increaseTime", [25 * 3600]);
      await ethers.provider.send("evm_mine");

      await expect(
        multiSig.connect(auditor1).approveProposal(1)
      ).to.be.revertedWith("MultiSig: proposal expired");

      // Mark expired
      await expect(multiSig.markExpired(1))
        .to.emit(multiSig, "ProposalExpired");

      const prop = await multiSig.getProposal(1);
      expect(prop.status).to.equal(ProposalStatus.EXPIRED);

      const pendingAfter = await multiSig.getPendingProposals();
      expect(pendingAfter.length).to.equal(0);
    });

    it("Should return individual vote info via getVote", async function () {
      await multiSig.connect(auditor1).approveProposal(1);
      const [voted, approved] = await multiSig.getVote(1, auditor1.address);
      expect(voted).to.equal(true);
      expect(approved).to.equal(true);

      const [voted2, approved2] = await multiSig.getVote(1, auditor2.address);
      expect(voted2).to.equal(false);
      expect(approved2).to.equal(false);
    });
  });
});
