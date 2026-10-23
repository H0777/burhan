const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Write Authorization & Phased Bootstrap (T02)", function () {
  let bootstrapAuthority, admin, operator, auditor1, auditor2, regulator, outsider;
  let multiSig, roleManager, insiderLog, forensicTrail, auditEngine;

  const Role = {
    NONE: 0,
    SUPER_ADMIN: 1,
    AUDITOR: 2,
    OPERATOR: 3,
    REGULATOR: 4,
  };

  beforeEach(async function () {
    [bootstrapAuthority, admin, operator, auditor1, auditor2, regulator, outsider] =
      await ethers.getSigners();

    // 1. Deploy MultiSig with bootstrapAuthority
    const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
    multiSig = await MultiSigApproval.deploy(bootstrapAuthority.address, 2, 24);
    await multiSig.waitForDeployment();

    // 2. Deploy RoleManager with initialGovernance = multiSig
    const RoleManager = await ethers.getContractFactory("RoleManager");
    roleManager = await RoleManager.deploy(await multiSig.getAddress());
    await roleManager.waitForDeployment();

    // 3. Deploy InsiderActivityLog with governance = multiSig
    const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
    insiderLog = await InsiderActivityLog.deploy(await multiSig.getAddress());
    await insiderLog.waitForDeployment();

    // 4. Deploy ForensicTrail with governance = multiSig
    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    forensicTrail = await ForensicTrail.deploy(await multiSig.getAddress());
    await forensicTrail.waitForDeployment();

    // 5. Deploy AuditEngine with governance = multiSig
    const AuditEngine = await ethers.getContractFactory("AuditEngine");
    auditEngine = await AuditEngine.deploy(await multiSig.getAddress());
    await auditEngine.waitForDeployment();
  });

  describe("Pre-Finalization Bootstrap Controls", function () {
    it("should revert normal multiSig execution before bootstrap is finalized", async function () {
      const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Pre-bootstrap proposal"));
      await expect(
        multiSig.connect(auditor1).createProposal(0, await auditEngine.getAddress(), "0x", reasonHash)
      ).to.be.revertedWith("MultiSig: bootstrap not finalized");
    });

    it("should reject an EOA as contract address during configureContracts", async function () {
      const eoaAddress = outsider.address; // has no code
      await expect(
        multiSig.connect(bootstrapAuthority).configureContracts(
          eoaAddress,
          await auditEngine.getAddress(),
          await insiderLog.getAddress(),
          await forensicTrail.getAddress()
        )
      ).to.be.revertedWith("MultiSig: RoleManager must be a contract");
    });

    it("should reject zero addresses during configureContracts", async function () {
      await expect(
        multiSig.connect(bootstrapAuthority).configureContracts(
          ethers.ZeroAddress,
          await auditEngine.getAddress(),
          await insiderLog.getAddress(),
          await forensicTrail.getAddress()
        )
      ).to.be.revertedWith("MultiSig: zero address");
    });

    it("should reject configureContracts called by unauthorized outsider", async function () {
      await expect(
        multiSig.connect(outsider).configureContracts(
          await roleManager.getAddress(),
          await auditEngine.getAddress(),
          await insiderLog.getAddress(),
          await forensicTrail.getAddress()
        )
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");
    });

    it("should reject finalizeBootstrap if fewer than 4 participants are enrolled", async function () {
      // Configure contracts successfully
      await multiSig.connect(bootstrapAuthority).configureContracts(
        await roleManager.getAddress(),
        await auditEngine.getAddress(),
        await insiderLog.getAddress(),
        await forensicTrail.getAddress()
      );

      // Attempting to finalize without enrolling 4 ELIGIBLE voting identities
      // (SUPER_ADMIN/AUDITOR) must revert
      await expect(
        multiSig.connect(bootstrapAuthority).finalizeBootstrap()
      ).to.be.revertedWith("MultiSig: need at least 4 eligible participants");
    });
  });

  describe("Successful Phased Bootstrap & Privilege Revocation", function () {
    beforeEach(async function () {
      // 1. Configure contracts
      await multiSig.connect(bootstrapAuthority).configureContracts(
        await roleManager.getAddress(),
        await auditEngine.getAddress(),
        await insiderLog.getAddress(),
        await forensicTrail.getAddress()
      );

      // 2. Enroll 5 distinct institutional identities (fixed roster ids, R02):
      //    four ELIGIBLE voters (SUPER_ADMIN/AUDITOR) + one OPERATOR.
      await multiSig.connect(bootstrapAuthority).bootstrapParticipants(
        [
          "0xF75C6EBDDEFB3CCFCAF608A6E4EC673954D92C03384453B0558BAAD01B8F9312",
          "0xB8E57F1639EE0D87D1D6E4DEA50AD06C36252162AEDFA000809B86EB52B816B5",
          "0xDD00ACD20D9AA7C09F37A8B907F5DA520B77C0F437FFA54788911409A319C478",
          "0x9A1F04C6E2B3D75A8C41F60E92B7AD13C5E08D6427FA91B35C0D4E7A2F8B63C1",
          "0x657ABC488CDBEB7F617116B73EC1508431FF09C7BFABED6F1C83AB4967113EE7",
        ],
        [admin.address, auditor1.address, auditor2.address, operator.address, regulator.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR, Role.AUDITOR],
        ["Init Admin", "Init Auditor 1", "Init Auditor 2", "Init Operator", "Init Auditor 3"]
      );

      // 3. Finalize bootstrap
      await multiSig.connect(bootstrapAuthority).finalizeBootstrap();
    });

    it("should mark bootstrap finalized and revoke bootstrapAuthority to address(0)", async function () {
      expect(await multiSig.isBootstrapFinalized()).to.equal(true);
      expect(await multiSig.bootstrapAuthority()).to.equal(ethers.ZeroAddress);
    });

    it("should prevent bootstrapAuthority from re-calling bootstrap methods after finalization", async function () {
      await expect(
        multiSig.connect(bootstrapAuthority).finalizeBootstrap()
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");

      await expect(
        multiSig.connect(bootstrapAuthority).configureContracts(
          await roleManager.getAddress(),
          await auditEngine.getAddress(),
          await insiderLog.getAddress(),
          await forensicTrail.getAddress()
        )
      ).to.be.revertedWith("MultiSig: caller is not bootstrap authority");
    });

    it("should prevent re-integrating contracts once configured", async function () {
      await expect(
        auditEngine.connect(bootstrapAuthority).integrateAllContracts(
          await roleManager.getAddress(),
          await insiderLog.getAddress(),
          await forensicTrail.getAddress(),
          await multiSig.getAddress()
        )
      ).to.be.revertedWith("AuditEngine: already integrated");
    });
  });

  describe("Write Authorization & Logging Restrictions", function () {
    beforeEach(async function () {
      await multiSig.connect(bootstrapAuthority).configureContracts(
        await roleManager.getAddress(),
        await auditEngine.getAddress(),
        await insiderLog.getAddress(),
        await forensicTrail.getAddress()
      );

      await multiSig.connect(bootstrapAuthority).bootstrapParticipants(
        [
          "0xF75C6EBDDEFB3CCFCAF608A6E4EC673954D92C03384453B0558BAAD01B8F9312",
          "0xB8E57F1639EE0D87D1D6E4DEA50AD06C36252162AEDFA000809B86EB52B816B5",
          "0xDD00ACD20D9AA7C09F37A8B907F5DA520B77C0F437FFA54788911409A319C478",
          "0x9A1F04C6E2B3D75A8C41F60E92B7AD13C5E08D6427FA91B35C0D4E7A2F8B63C1",
          "0x657ABC488CDBEB7F617116B73EC1508431FF09C7BFABED6F1C83AB4967113EE7",
        ],
        [admin.address, auditor1.address, auditor2.address, operator.address, regulator.address],
        [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR, Role.AUDITOR],
        ["Init Admin", "Init Auditor 1", "Init Auditor 2", "Init Operator", "Init Auditor 3"]
      );

      await multiSig.connect(bootstrapAuthority).finalizeBootstrap();
    });

    it("should reject outsider or auditor logging activity directly in InsiderActivityLog", async function () {
      // outsider is not a recorder
      await expect(
        insiderLog.connect(outsider).logActivity(
          operator.address,
          1, // TRANSACTION_OVERRIDE
          1001,
          outsider.address,
          "Forged entry"
        )
      ).to.be.revertedWith("InsiderActivityLog: caller is not authorized recorder");

      // Even an auditor is not an authorized recorder contract
      await expect(
        insiderLog.connect(auditor1).logActivity(
          operator.address,
          1,
          1001,
          outsider.address,
          "Auditor direct forged log"
        )
      ).to.be.revertedWith("InsiderActivityLog: caller is not authorized recorder");
    });

    it("should reject updating business hours by anyone other than governance", async function () {
      await expect(
        insiderLog.connect(outsider).setBusinessHours(8, 16)
      ).to.be.revertedWith("InsiderActivityLog: caller is not governance");

      await expect(
        insiderLog.connect(admin).setBusinessHours(8, 16)
      ).to.be.revertedWith("InsiderActivityLog: caller is not governance");
    });

    it("should reject unregistered evidence writer from submitting evidence to ForensicTrail", async function () {
      const titleHash = ethers.keccak256(ethers.toUtf8Bytes("Unauthorized Incident"));
      const severityHash = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));
      await expect(
        forensicTrail.connect(outsider).createIncident(titleHash, severityHash)
      ).to.be.revertedWith("ForensicTrail: caller is not authorized evidence writer");

      await expect(
        forensicTrail.connect(outsider).submitEvidence(
          1,
          ethers.keccak256(ethers.toUtf8Bytes("req_unauth")),
          ethers.keccak256(ethers.toUtf8Bytes("SUSPICIOUS_TX")),
          ethers.keccak256(ethers.toUtf8Bytes("Tampered document")),
          ethers.sha256(ethers.toUtf8Bytes("hash1"))
        )
      ).to.be.revertedWith("ForensicTrail: caller is not authorized evidence writer");
    });

    it("should reject direct role assignments in RoleManager from non-governance callers", async function () {
      await expect(
        roleManager.connect(admin).assignRole(outsider.address, Role.OPERATOR, "Direct assign attempt")
      ).to.be.revertedWith("RoleManager: caller is not governance");
    });

    it("should allow authorized recorder (AuditEngine) to log activity from transaction execution context", async function () {
      // AuditEngine is a registered recorder
      expect(await insiderLog.isRecorder(await auditEngine.getAddress())).to.equal(true);

      // Perform authorized administrative action via AuditEngine from admin
      await auditEngine.connect(admin).addToBlacklist(outsider.address, "Suspicious blacklist test");

      // Total activities in insiderLog should have incremented
      expect(await insiderLog.totalActivities()).to.be.greaterThan(0);
      const activity = await insiderLog.getActivity(1);
      expect(activity.operator).to.equal(admin.address);
    });
  });
});
