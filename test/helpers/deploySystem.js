const { ethers } = require("hardhat");

const Role = {
  NONE: 0,
  SUPER_ADMIN: 1,
  AUDITOR: 2,
  OPERATOR: 3,
  REGULATOR: 4,
};

async function deploySystemFixture(customSigners) {
  const signers = customSigners || (await ethers.getSigners());
  const [bootstrapAuthority, admin, auditor1, auditor2, operator, regulator, outsider] = signers;

  // 1. Deploy MultiSig
  const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
  const multiSig = await MultiSigApproval.deploy(bootstrapAuthority.address, 2, 24);
  await multiSig.waitForDeployment();
  const multiSigAddress = await multiSig.getAddress();

  // 2. Deploy RoleManager with governance = multiSig
  const RoleManager = await ethers.getContractFactory("RoleManager");
  const roleManager = await RoleManager.deploy(multiSigAddress);
  await roleManager.waitForDeployment();

  // 3. Deploy InsiderActivityLog with governance = multiSig
  const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
  const insiderLog = await InsiderActivityLog.deploy(multiSigAddress);
  await insiderLog.waitForDeployment();

  // 4. Deploy ForensicTrail with governance = multiSig
  const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
  const forensicTrail = await ForensicTrail.deploy(multiSigAddress);
  await forensicTrail.waitForDeployment();

  // 5. Deploy AuditEngine with governance = multiSig
  const AuditEngine = await ethers.getContractFactory("AuditEngine");
  const auditEngine = await AuditEngine.deploy(multiSigAddress);
  await auditEngine.waitForDeployment();

  // 6. Bootstrap Configure Contracts
  await multiSig.connect(bootstrapAuthority).configureContracts(
    await roleManager.getAddress(),
    await auditEngine.getAddress(),
    await insiderLog.getAddress(),
    await forensicTrail.getAddress()
  );

  // 7. Bootstrap Enroll 4+ Participants
  await multiSig.connect(bootstrapAuthority).bootstrapParticipants(
    [admin.address, auditor1.address, auditor2.address, operator.address],
    [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR],
    ["Initial Admin", "Lead Auditor 1", "Lead Auditor 2", "Primary Operator"]
  );

  // 8. Finalize Bootstrap
  await multiSig.connect(bootstrapAuthority).finalizeBootstrap();

  return {
    multiSig,
    roleManager,
    insiderLog,
    forensicTrail,
    auditEngine,
    bootstrapAuthority,
    admin,
    auditor1,
    auditor2,
    operator,
    regulator,
    outsider,
    Role,
  };
}

module.exports = {
  deploySystemFixture,
  Role,
};
