const { ethers } = require("hardhat");

const Role = {
  NONE: 0,
  SUPER_ADMIN: 1,
  AUDITOR: 2,
  OPERATOR: 3,
  REGULATOR: 4,
};

// Fixed institutional roster IDs (R02): deterministic fixture values, NOT
// derived from wallet addresses or person names. The person↔id mapping lives
// off-chain in institutional membership records.
const PARTICIPANT_IDS = {
  ADMIN: "0xF75C6EBDDEFB3CCFCAF608A6E4EC673954D92C03384453B0558BAAD01B8F9312",
  AUDITOR_1: "0xB8E57F1639EE0D87D1D6E4DEA50AD06C36252162AEDFA000809B86EB52B816B5",
  AUDITOR_2: "0xDD00ACD20D9AA7C09F37A8B907F5DA520B77C0F437FFA54788911409A319C478",
  AUDITOR_3: "0x657ABC488CDBEB7F617116B73EC1508431FF09C7BFABED6F1C83AB4967113EE7",
  OPERATOR: "0x9A1F04C6E2B3D75A8C41F60E92B7AD13C5E08D6427FA91B35C0D4E7A2F8B63C1",
};

async function deploySystemFixture(customSigners) {
  const signers = customSigners || (await ethers.getSigners());
  const [bootstrapAuthority, admin, auditor1, auditor2, operator, regulator, outsider] = signers;

  // 1. Deploy MultiSig (TTL is the fixed protocol constant 259,200s — not a
  //    deployment parameter since R03)
  const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
  const multiSig = await MultiSigApproval.deploy(bootstrapAuthority.address, 2);
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

  // 7. Bootstrap Enroll 4+ institutional participants (R02: fixed ids + wallets).
  //    Roster keeps operator as OPERATOR and enrolls the regulator signer as a
  //    third AUDITOR so the roster holds FOUR eligible voting identities
  //    (SUPER_ADMIN/AUDITOR), as finalizeBootstrap requires.
  await multiSig.connect(bootstrapAuthority).bootstrapParticipants(
    [
      PARTICIPANT_IDS.ADMIN,
      PARTICIPANT_IDS.AUDITOR_1,
      PARTICIPANT_IDS.AUDITOR_2,
      PARTICIPANT_IDS.OPERATOR,
      PARTICIPANT_IDS.AUDITOR_3,
    ],
    [admin.address, auditor1.address, auditor2.address, operator.address, regulator.address],
    [Role.SUPER_ADMIN, Role.AUDITOR, Role.AUDITOR, Role.OPERATOR, Role.AUDITOR],
    [
      "Initial Admin",
      "Lead Auditor 1",
      "Lead Auditor 2",
      "Primary Operator",
      "Tertiary Auditor",
    ]
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
  PARTICIPANT_IDS,
};
