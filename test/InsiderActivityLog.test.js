const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("InsiderActivityLog", function () {
  let insiderLog;
  let admin, operator, beneficiary1, beneficiary2;

  // Enum ActivityType:
  // TRANSACTION_APPROVAL(0), TRANSACTION_OVERRIDE(1), BLACKLIST_ACTION(2),
  // KYC_ACTION(3), ROLE_CHANGE(4), POLICY_CHANGE(5), AFTER_HOURS_ACCESS(6),
  // REPEATED_BENEFICIARY(7), MANUAL_CLEAR(8)
  const ActivityType = {
    TRANSACTION_APPROVAL: 0,
    TRANSACTION_OVERRIDE: 1,
    BLACKLIST_ACTION: 2,
    KYC_ACTION: 3,
    ROLE_CHANGE: 4,
    POLICY_CHANGE: 5,
    AFTER_HOURS_ACCESS: 6,
    REPEATED_BENEFICIARY: 7,
    MANUAL_CLEAR: 8,
  };

  beforeEach(async function () {
    [admin, operator, beneficiary1, beneficiary2] = await ethers.getSigners();
    const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
    insiderLog = await InsiderActivityLog.deploy(admin.address);
    await insiderLog.waitForDeployment();
    await insiderLog.connect(admin).setRecorder(admin.address, true);
  });

  describe("Deployment & Configuration", function () {
    it("Should initialize with default business hours 8 to 17", async function () {
      expect(await insiderLog.businessHourStart()).to.equal(8);
      expect(await insiderLog.businessHourEnd()).to.equal(17);
      expect(await insiderLog.totalActivities()).to.equal(0);
    });

    it("Should allow updating business hours", async function () {
      await insiderLog.setBusinessHours(9, 18);
      expect(await insiderLog.businessHourStart()).to.equal(9);
      expect(await insiderLog.businessHourEnd()).to.equal(18);
    });

    it("Should revert on invalid business hours", async function () {
      await expect(insiderLog.setBusinessHours(18, 9)).to.be.revertedWith(
        "InsiderLog: start must be before end"
      );
      await expect(insiderLog.setBusinessHours(25, 26)).to.be.revertedWith(
        "InsiderLog: invalid hours"
      );
    });
  });

  describe("Logging Activities & Profiles", function () {
    it("Should log an activity and emit ActivityLogged", async function () {
      await expect(
        insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_APPROVAL,
          42,
          beneficiary1.address,
          "Approved regular transaction"
        )
      ).to.emit(insiderLog, "ActivityLogged");

      expect(await insiderLog.totalActivities()).to.equal(1);

      const act = await insiderLog.getActivity(1);
      expect(act.id).to.equal(1);
      expect(act.operator).to.equal(operator.address);
      expect(act.activityType).to.equal(ActivityType.TRANSACTION_APPROVAL);
      expect(act.relatedTxId).to.equal(42);
      expect(act.relatedAddress).to.equal(beneficiary1.address);
      expect(act.details).to.equal("Approved regular transaction");

      const profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.totalActions).to.equal(1);
      expect(profile.overrideCount).to.equal(0);
    });

    it("Should revert when logging with zero address operator", async function () {
      await expect(
        insiderLog.logActivity(
          ethers.ZeroAddress,
          ActivityType.TRANSACTION_APPROVAL,
          1,
          beneficiary1.address,
          "Invalid"
        )
      ).to.be.revertedWith("InsiderLog: invalid operator");
    });
  });

  describe("Excessive Overrides Anomaly Detection", function () {
    it("Should flag operator when override count exceeds threshold (> 5)", async function () {
      await insiderLog.setBusinessHours(0, 24);

      // Perform 5 overrides - should not flag
      for (let i = 1; i <= 5; i++) {
        await insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_OVERRIDE,
          i,
          beneficiary1.address,
          `Override #${i}`
        );
      }

      let profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.overrideCount).to.equal(5);
      expect(profile.flagCount).to.equal(0);

      // 6th override should trigger OperatorFlagged
      await expect(
        insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_OVERRIDE,
          6,
          beneficiary1.address,
          "Override #6"
        )
      )
        .to.emit(insiderLog, "OperatorFlagged")
        .withArgs(
          operator.address,
          "EXCESSIVE_OVERRIDES",
          "Operator has overridden warnings more than 5 times",
          1,
          await ethers.provider.getBlock("latest").then((b) => b.timestamp + 1)
        );

      profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.overrideCount).to.equal(6);
      expect(profile.flagCount).to.equal(1);
    });
  });

  describe("Repeated Beneficiary Approvals Detection", function () {
    it("Should track approvals per beneficiary and flag after 10 approvals", async function () {
      await insiderLog.setBusinessHours(0, 24);

      // 10 approvals for beneficiary1
      for (let i = 1; i <= 10; i++) {
        await insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_APPROVAL,
          i,
          beneficiary1.address,
          `Approval #${i}`
        );
      }

      expect(
        await insiderLog.getBeneficiaryApprovalCount(operator.address, beneficiary1.address)
      ).to.equal(10);

      let profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.flagCount).to.equal(0);

      // 11th approval for same beneficiary triggers flag
      await expect(
        insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_APPROVAL,
          11,
          beneficiary1.address,
          "Approval #11"
        )
      )
        .to.emit(insiderLog, "OperatorFlagged")
        .withArgs(
          operator.address,
          "REPEATED_BENEFICIARY",
          "Operator repeatedly approves same beneficiary",
          1,
          await ethers.provider.getBlock("latest").then((b) => b.timestamp + 1)
        );

      profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.flagCount).to.equal(1);
    });
  });

  describe("After-Hours Activity Tracking", function () {
    it("Should detect after-hours activity and flag after 3 occurrences", async function () {
      // Configure business hours so that current hour is outside business hours
      // Get current block hour
      const block = await ethers.provider.getBlock("latest");
      const currentHour = Number((BigInt(block.timestamp) % 86400n) / 3600n);

      // Set business hours to window that excludes currentHour
      let start = (currentHour + 2) % 24;
      let end = (currentHour + 4) % 24;
      if (start > end) {
        start = 0;
        end = 1;
      }
      // If current hour happens to be in [start, end), adjust
      if (currentHour >= start && currentHour < end) {
        start = (end + 1) % 24;
        end = (start + 2) % 24;
      }

      await insiderLog.setBusinessHours(start, end);

      // 3 after-hours actions trigger InsiderAlert each time
      for (let i = 1; i <= 3; i++) {
        await expect(
          insiderLog.logActivity(
            operator.address,
            ActivityType.TRANSACTION_APPROVAL,
            i,
            beneficiary1.address,
            `Late night task #${i}`
          )
        ).to.emit(insiderLog, "InsiderAlert");
      }

      let profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.afterHoursCount).to.equal(3);
      expect(profile.flagCount).to.equal(0);

      // 4th after-hours action triggers OperatorFlagged
      await expect(
        insiderLog.logActivity(
          operator.address,
          ActivityType.TRANSACTION_APPROVAL,
          4,
          beneficiary1.address,
          "Late night task #4"
        )
      ).to.emit(insiderLog, "OperatorFlagged");

      profile = await insiderLog.getOperatorProfile(operator.address);
      expect(profile.afterHoursCount).to.equal(4);
      expect(profile.flagCount).to.equal(1);
    });
  });

  describe("View Functions", function () {
    it("Should return operator activities list and total activities count", async function () {
      await insiderLog.logActivity(operator.address, ActivityType.KYC_ACTION, 0, beneficiary1.address, "KYC 1");
      await insiderLog.logActivity(operator.address, ActivityType.KYC_ACTION, 0, beneficiary2.address, "KYC 2");

      const ids = await insiderLog.getOperatorActivities(operator.address);
      expect(ids.length).to.equal(2);
      expect(ids[0]).to.equal(1);
      expect(ids[1]).to.equal(2);

      const allIds = await insiderLog.getAllActivityIds();
      expect(allIds.length).to.equal(2);
    });
  });
});
