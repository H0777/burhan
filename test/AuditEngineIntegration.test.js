const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

// Hand-built interface of the REMOVED parallel-admin functions: the R03
// production ABI no longer declares them, so raw calldata is the only way to
// probe that the bypass is really gone (same technique as NoTestBackdoor).
const LEGACY_INTERFACE = new ethers.Interface([
  "function overrideWarning(uint256,string)",
  "function setPolicy(uint8)",
  "function setCustomThresholds(uint256,uint256,uint256,uint256,uint256)",
]);

describe("AuditEngine Integration & Cyber-Forensic Controls", function () {
  let auditEngine, roleManager, insiderLog;
  let admin, auditor, operator, user1, user2;

  const Role = {
    NONE: 0,
    SUPER_ADMIN: 1,
    AUDITOR: 2,
    OPERATOR: 3,
    REGULATOR: 4,
  };

  const PolicyProfile = {
    IRAQ_CBI: 0,
    GLOBAL_FATF: 1,
    CUSTOM: 2,
  };

  const NORMAL_AMOUNT = ethers.parseEther("100");
  const LARGE_AMOUNT = ethers.parseEther("15000");

  beforeEach(async function () {
    [admin, auditor, operator, user1, user2] = await ethers.getSigners();

    // 1. Deploy AuditEngine with governance = admin
    const AuditEngine = await ethers.getContractFactory("AuditEngine");
    auditEngine = await AuditEngine.deploy(admin.address);
    await auditEngine.waitForDeployment();

    // 2. Deploy RoleManager with governance = admin
    const RoleManager = await ethers.getContractFactory("RoleManager");
    roleManager = await RoleManager.deploy(admin.address);
    await roleManager.waitForDeployment();

    // 3. Deploy InsiderActivityLog with governance = admin
    const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
    insiderLog = await InsiderActivityLog.deploy(admin.address);
    await insiderLog.waitForDeployment();

    // Authorize auditEngine as recorder
    await insiderLog.connect(admin).setRecorder(await auditEngine.getAddress(), true);

    // Setup roles (R02: identity comes only from enrollment with fixed institutional ids)
    await roleManager.connect(admin).enrollParticipant(
      "0xB8E57F1639EE0D87D1D6E4DEA50AD06C36252162AEDFA000809B86EB52B816B5",
      auditor.address,
      Role.AUDITOR,
      "Appointed Auditor"
    );
    await roleManager.connect(admin).enrollParticipant(
      "0xDD00ACD20D9AA7C09F37A8B907F5DA520B77C0F437FFA54788911409A319C478",
      operator.address,
      Role.OPERATOR,
      "Appointed Operator"
    );
  });

  describe("Contract Integration", function () {
    it("Should integrate RoleManager and InsiderActivityLog", async function () {
      expect(await auditEngine.isIntegrated()).to.equal(false);

      await expect(
        auditEngine.connect(admin).integrateContracts(
          await roleManager.getAddress(),
          await insiderLog.getAddress()
        )
      ).to.emit(auditEngine, "ContractsIntegrated");

      expect(await auditEngine.isIntegrated()).to.equal(true);
      expect(await auditEngine.roleManager()).to.equal(await roleManager.getAddress());
      expect(await auditEngine.insiderLog()).to.equal(await insiderLog.getAddress());
    });

    it("Should revert if non-admin attempts integration", async function () {
      await expect(
        auditEngine.connect(auditor).integrateContracts(
          await roleManager.getAddress(),
          await insiderLog.getAddress()
        )
      ).to.be.revertedWith("AuditEngine: unauthorized integration");
    });

    it("Should revert if integration attempted twice", async function () {
      await auditEngine.connect(admin).integrateContracts(
        await roleManager.getAddress(),
        await insiderLog.getAddress()
      );

      await expect(
        auditEngine.connect(admin).integrateContracts(
          await roleManager.getAddress(),
          await insiderLog.getAddress()
        )
      ).to.be.revertedWith("AuditEngine: already integrated");
    });
  });

  describe("RBAC Access Enforcement", function () {
    beforeEach(async function () {
      await auditEngine.connect(admin).integrateContracts(
        await roleManager.getAddress(),
        await insiderLog.getAddress()
      );
    });

    it("AUDITOR should be authorized to blacklist addresses", async function () {
      await expect(
        auditEngine.connect(auditor).addToBlacklist(user1.address, "Suspicious activity detected")
      ).to.emit(auditEngine, "AddressBlacklisted");

      expect(await auditEngine.isBlacklisted(user1.address)).to.equal(true);
    });

    it("OPERATOR should NOT be authorized to blacklist addresses", async function () {
      await expect(
        auditEngine.connect(operator).addToBlacklist(user1.address, "Operator unauthorized attempt")
      ).to.be.revertedWith("AuditEngine: insufficient role");
    });
  });

  describe("Insider Threat Logging & Warnings Override (R03: bypass blocked)", function () {
    beforeEach(async function () {
      await auditEngine.connect(admin).integrateContracts(
        await roleManager.getAddress(),
        await insiderLog.getAddress()
      );

      // Submit large transaction to get it FLAGGED
      await auditEngine.connect(user1).submitTransaction(user2.address, LARGE_AMOUNT);
    });

    it("AUDITOR cannot clear a warning directly: the legacy overrideWarning path is gone", async function () {
      const auditEngineAddress = await auditEngine.getAddress();
      const legacyCalldata = LEGACY_INTERFACE.encodeFunctionData("overrideWarning", [
        1,
        "Customer identity re-verified by audit team",
      ]);

      // The direct (non-governance) override must revert — R03 removed the path.
      await expect(
        auditor.sendTransaction({ to: auditEngineAddress, data: legacyCalldata })
      ).to.be.reverted;

      // State untouched: still FLAGGED and nothing was logged.
      const txDataAfter = await auditEngine.getTransaction(1);
      expect(txDataAfter.isFlagged).to.equal(true);
      expect(txDataAfter.status).to.equal(2); // FLAGGED
      expect(await insiderLog.totalActivities()).to.equal(0);
    });

    it("OPERATOR cannot override warning (raw legacy calldata reverts too)", async function () {
      const auditEngineAddress = await auditEngine.getAddress();
      const legacyCalldata = LEGACY_INTERFACE.encodeFunctionData("overrideWarning", [
        1,
        "Unauthorized operator override",
      ]);
      await expect(
        operator.sendTransaction({ to: auditEngineAddress, data: legacyCalldata })
      ).to.be.reverted;
      expect((await auditEngine.getTransaction(1)).status).to.equal(2); // still FLAGGED
    });
  });

  describe("Configurable Compliance Policies (R03: governance-only execution)", function () {
    it("Should switch from IRAQ_CBI to GLOBAL_FATF policy via executePolicyChange", async function () {
      // Default is IRAQ_CBI (threshold: 10,000 ETH)
      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.IRAQ_CBI);
      expect(await auditEngine.largeTransactionThreshold()).to.equal(ethers.parseEther("10000"));

      // In this standalone fixture governance IS the admin wallet, so the
      // governance-only execute interface is callable directly here (in the
      // integrated system only the MultiSig coordinator reaches it).
      await expect(auditEngine.connect(admin).executePolicyChange(PolicyProfile.GLOBAL_FATF))
        .to.emit(auditEngine, "PolicyChanged")
        .withArgs(
          PolicyProfile.GLOBAL_FATF,
          admin.address,
          anyValue
        );

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.GLOBAL_FATF);
      expect(await auditEngine.largeTransactionThreshold()).to.equal(ethers.parseEther("8000"));
      expect(await auditEngine.dailyVolumeLimit()).to.equal(ethers.parseEther("30000"));
      expect(await auditEngine.maxDailyTransactions()).to.equal(15);
      expect(await auditEngine.maxSingleTransaction()).to.equal(ethers.parseEther("50000"));
      expect(await auditEngine.kycRequiredThreshold()).to.equal(ethers.parseEther("3000"));
    });

    it("GLOBAL_FATF should flag transaction of 9,000 ETH which IRAQ_CBI would allow", async function () {
      const amount9k = ethers.parseEther("9000");

      // Verify KYC first so KYC rule doesn't flag it
      await auditEngine.connect(admin).verifyKYC(user1.address);

      // Under IRAQ_CBI (threshold 10,000), 9,000 clears
      await auditEngine.connect(user1).submitTransaction(user2.address, amount9k);
      let tx = await auditEngine.getTransaction(1);
      expect(tx.isFlagged).to.equal(false);
      expect(tx.status).to.equal(1); // CLEARED

      // Now switch to GLOBAL_FATF (threshold 8,000) via the governance path
      await auditEngine.connect(admin).executePolicyChange(PolicyProfile.GLOBAL_FATF);

      // Under FATF, 9,000 is flagged as LARGE_TRANSACTION
      await auditEngine.connect(user1).submitTransaction(user2.address, amount9k);
      tx = await auditEngine.getTransaction(2);
      expect(tx.isFlagged).to.equal(true);
      expect(tx.flagReason).to.include("LARGE_TRANSACTION");
    });

    it("Should allow setting custom compliance thresholds via executeCustomThresholds", async function () {
      await auditEngine.connect(admin).executeCustomThresholds(
        ethers.parseEther("2000"),  // largeThreshold
        ethers.parseEther("10000"), // dailyLimit
        5,                          // maxDaily
        ethers.parseEther("15000"), // maxSingle
        ethers.parseEther("1000")   // kycThreshold
      );

      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.CUSTOM);
      expect(await auditEngine.largeTransactionThreshold()).to.equal(ethers.parseEther("2000"));
      expect(await auditEngine.maxDailyTransactions()).to.equal(5);
    });

    it("Should revert if non-governance attempts policy change, and the legacy setPolicy path is gone", async function () {
      await expect(
        auditEngine.connect(auditor).executePolicyChange(PolicyProfile.GLOBAL_FATF)
      ).to.be.revertedWith("AuditEngine: caller is not governance");

      // The legacy direct setPolicy/setCustomThresholds selectors must be
      // unreachable for everyone (governance included).
      const auditEngineAddress = await auditEngine.getAddress();
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("setPolicy", [PolicyProfile.GLOBAL_FATF]),
        })
      ).to.be.reverted;
      await expect(
        admin.sendTransaction({
          to: auditEngineAddress,
          data: LEGACY_INTERFACE.encodeFunctionData("setCustomThresholds", [
            ethers.parseEther("2000"),
            ethers.parseEther("10000"),
            5,
            ethers.parseEther("15000"),
            ethers.parseEther("1000"),
          ]),
        })
      ).to.be.reverted;

      // Policy untouched by the blocked attempts.
      expect(await auditEngine.activePolicy()).to.equal(PolicyProfile.IRAQ_CBI);
    });
  });
});
