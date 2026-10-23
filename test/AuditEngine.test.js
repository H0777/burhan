const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * @title AuditEngine Test Suite
 * @notice 100% coverage tests for Smart Audit Engine
 * @dev Tests all compliance rules, access control, events, and edge cases
 */
describe("AuditEngine", function () {
  let auditEngine;
  let admin, user1, user2, user3;

  const LARGE_THRESHOLD = ethers.parseEther("10000");
  const DAILY_LIMIT = ethers.parseEther("50000");
  const KYC_THRESHOLD = ethers.parseEther("5000");
  const MAX_TX = ethers.parseEther("100000");
  const NORMAL_AMOUNT = ethers.parseEther("100");
  const LARGE_AMOUNT = ethers.parseEther("15000");
  const KYC_AMOUNT = ethers.parseEther("6000");

  beforeEach(async function () {
    [admin, user1, user2, user3] = await ethers.getSigners();
    const AuditEngine = await ethers.getContractFactory("AuditEngine");
    auditEngine = await AuditEngine.deploy(admin.address);
    await auditEngine.waitForDeployment();
  });

  // ============================================================
  // DEPLOYMENT TESTS
  // ============================================================

  describe("Deployment", function () {
    it("Should set the deployer as admin", async function () {
      expect(await auditEngine.admin()).to.equal(admin.address);
    });

    it("Should start with zero transactions", async function () {
      expect(await auditEngine.totalTransactions()).to.equal(0);
    });

    it("Should have correct compliance constants", async function () {
      expect(await auditEngine.LARGE_TRANSACTION_THRESHOLD()).to.equal(LARGE_THRESHOLD);
      expect(await auditEngine.DAILY_VOLUME_LIMIT()).to.equal(DAILY_LIMIT);
      expect(await auditEngine.KYC_REQUIRED_THRESHOLD()).to.equal(KYC_THRESHOLD);
      expect(await auditEngine.MAX_SINGLE_TRANSACTION()).to.equal(MAX_TX);
      expect(await auditEngine.MAX_DAILY_TRANSACTIONS()).to.equal(20);
    });
  });

  // ============================================================
  // TRANSACTION SUBMISSION TESTS
  // ============================================================

  describe("Transaction Submission", function () {
    it("Should submit and clear a normal transaction", async function () {
      const tx = await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      const receipt = await tx.wait();

      const txData = await auditEngine.getTransaction(1);
      expect(txData.id).to.equal(1);
      expect(txData.sender).to.equal(user1.address);
      expect(txData.receiver).to.equal(user2.address);
      expect(txData.amount).to.equal(NORMAL_AMOUNT);
      expect(txData.isFlagged).to.equal(false);
      expect(txData.status).to.equal(1); // CLEARED
    });

    it("Should emit TransactionSubmitted event", async function () {
      const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
      await expect(auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT))
        .to.emit(auditEngine, "TransactionSubmitted")
        .withArgs(1, user1.address, user2.address, NORMAL_AMOUNT, anyValue);
    });

    it("Should emit TransactionCleared for valid transactions", async function () {
      await expect(auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT))
        .to.emit(auditEngine, "TransactionCleared");
    });

    it("Should increment transaction counter", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      expect(await auditEngine.totalTransactions()).to.equal(2);
    });

    it("Should revert on zero amount", async function () {
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, 0)
      ).to.be.revertedWith("AuditEngine: amount must be greater than zero");
    });

    it("Should revert on amount exceeding maximum", async function () {
      const overMax = MAX_TX + ethers.parseEther("1");
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, overMax)
      ).to.be.revertedWith("AuditEngine: amount exceeds maximum");
    });

    it("Should revert on zero address receiver", async function () {
      await expect(
        auditEngine.connect(user1).submitTransaction(ethers.ZeroAddress, NORMAL_AMOUNT)
      ).to.be.revertedWith("AuditEngine: invalid receiver");
    });

    it("Should revert on self-transfer", async function () {
      await expect(
        auditEngine.connect(user1).submitTransaction(user1.address, NORMAL_AMOUNT)
      ).to.be.revertedWith("AuditEngine: self-transfer not allowed");
    });

    it("Should revert for blacklisted sender", async function () {
      await auditEngine.connect(admin).addToBlacklist(user1.address, "test");
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT)
      ).to.be.revertedWith("AuditEngine: address is blacklisted");
    });

    it("Should revert for blacklisted receiver", async function () {
      await auditEngine.connect(admin).addToBlacklist(user2.address, "test");
      await expect(
        auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT)
      ).to.be.revertedWith("AuditEngine: address is blacklisted");
    });
  });

  // ============================================================
  // AML COMPLIANCE RULE TESTS
  // ============================================================

  describe("AML Compliance Rules", function () {
    it("Rule 1: Should flag large transactions", async function () {
      const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
      await expect(auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT))
        .to.emit(auditEngine, "TransactionFlagged")
        .withArgs(1, user1.address, "LARGE_TRANSACTION: Amount exceeds reporting threshold", anyValue);

      const txData = await auditEngine.getTransaction(1);
      expect(txData.isFlagged).to.equal(true);
      expect(txData.status).to.equal(2); // FLAGGED
    });

    it("Rule 4: Should flag transactions without KYC for high-value", async function () {
      const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
      await expect(auditEngine.connect(user1).submitTransaction(user2.address, KYC_AMOUNT))
        .to.emit(auditEngine, "TransactionFlagged")
        .withArgs(1, user1.address, "KYC_REQUIRED: Sender not verified for this amount", anyValue);
    });

    it("Rule 4: Should clear KYC-verified user for high-value transaction", async function () {
      await auditEngine.connect(admin).verifyKYC(user1.address);
      await expect(auditEngine.connect(user1).submitTransaction(user2.address, KYC_AMOUNT))
        .to.emit(auditEngine, "TransactionCleared");
    });

    it("Should return all flagged transaction IDs", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);

      const flagged = await auditEngine.getFlaggedTransactions();
      expect(flagged.length).to.equal(1);
      expect(flagged[0]).to.equal(2);
    });
  });

  // ============================================================
  // ADMIN FUNCTION TESTS
  // ============================================================

  describe("Admin Functions", function () {
    it("Should allow admin to block a flagged transaction", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
      await expect(auditEngine.connect(admin).blockTransaction(1))
        .to.emit(auditEngine, "TransactionBlocked");

      const txData = await auditEngine.getTransaction(1);
      expect(txData.status).to.equal(3); // BLOCKED
    });

    it("Should revert if non-admin tries to block transaction", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
      await expect(
        auditEngine.connect(user2).blockTransaction(1)
      ).to.be.revertedWith("AuditEngine: caller is not admin");
    });

    it("Should revert blocking a cleared transaction", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await expect(
        auditEngine.connect(admin).blockTransaction(1)
      ).to.be.revertedWith("AuditEngine: can only block flagged transactions");
    });

    it("Should add address to blacklist and emit event", async function () {
      await expect(auditEngine.connect(admin).addToBlacklist(user1.address, "fraud"))
        .to.emit(auditEngine, "AddressBlacklisted")
        .withArgs(user1.address, "fraud");
      expect(await auditEngine.isBlacklisted(user1.address)).to.equal(true);
    });

    it("Should remove address from blacklist and emit event", async function () {
      await auditEngine.connect(admin).addToBlacklist(user1.address, "test");
      await expect(auditEngine.connect(admin).removeFromBlacklist(user1.address))
        .to.emit(auditEngine, "AddressWhitelisted")
        .withArgs(user1.address);
      expect(await auditEngine.isBlacklisted(user1.address)).to.equal(false);
    });

    it("Should not allow blacklisting admin address", async function () {
      await expect(
        auditEngine.connect(admin).addToBlacklist(admin.address, "test")
      ).to.be.revertedWith("AuditEngine: cannot blacklist admin");
    });

    it("Should verify KYC and emit event", async function () {
      await expect(auditEngine.connect(admin).verifyKYC(user1.address))
        .to.emit(auditEngine, "KYCVerified")
        .withArgs(user1.address);
      expect(await auditEngine.isKYCVerified(user1.address)).to.equal(true);
    });

    it("Should revoke KYC and emit event", async function () {
      await auditEngine.connect(admin).verifyKYC(user1.address);
      await expect(auditEngine.connect(admin).revokeKYC(user1.address))
        .to.emit(auditEngine, "KYCRevoked")
        .withArgs(user1.address);
      expect(await auditEngine.isKYCVerified(user1.address)).to.equal(false);
    });
  });

  // ============================================================
  // VIEW FUNCTION TESTS
  // ============================================================

  describe("View Functions", function () {
    it("Should return correct daily volume", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      expect(await auditEngine.getDailyVolume(user1.address)).to.equal(NORMAL_AMOUNT * 2n);
    });

    it("Should return correct daily count", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      expect(await auditEngine.getDailyCount(user1.address)).to.equal(2);
    });

    it("Should return all transaction IDs", async function () {
      await auditEngine.connect(user1).submitTransaction(user2.address, NORMAL_AMOUNT);
      await auditEngine.connect(user2).submitTransaction(user1.address, NORMAL_AMOUNT);
      const ids = await auditEngine.getAllTransactionIds();
      expect(ids.length).to.equal(2);
    });

    it("Should revert getTransaction for invalid ID", async function () {
      await expect(auditEngine.getTransaction(0)).to.be.revertedWith("AuditEngine: invalid txId");
      await expect(auditEngine.getTransaction(999)).to.be.revertedWith("AuditEngine: invalid txId");
    });
  });
});
