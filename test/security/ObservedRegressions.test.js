const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Security Regressions Baseline Reproduction (T01)", function () {
  let admin, operator, auditor, auditor2, outsider, beneficiary;
  let roleManager, multiSig, forensicTrail, insiderLog, auditEngine;

  beforeEach(async function () {
    [admin, operator, auditor, auditor2, outsider, beneficiary] = await ethers.getSigners();

    const RoleManager = await ethers.getContractFactory("RoleManager");
    roleManager = await RoleManager.deploy();
    await roleManager.waitForDeployment();

    const MultiSigApproval = await ethers.getContractFactory("MultiSigApproval");
    multiSig = await MultiSigApproval.deploy(await roleManager.getAddress(), 2, 24);
    await multiSig.waitForDeployment();

    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    forensicTrail = await ForensicTrail.deploy();
    await forensicTrail.waitForDeployment();

    const InsiderActivityLog = await ethers.getContractFactory("InsiderActivityLog");
    insiderLog = await InsiderActivityLog.deploy();
    await insiderLog.waitForDeployment();

    const AuditEngine = await ethers.getContractFactory("AuditEngine");
    auditEngine = await AuditEngine.deploy();
    await auditEngine.waitForDeployment();

    await auditEngine.integrateAllContracts(
      await roleManager.getAddress(),
      await insiderLog.getAddress(),
      await forensicTrail.getAddress(),
      await multiSig.getAddress()
    );

    // Assign AUDITOR role to auditor and auditor2
    await roleManager.assignRole(auditor.address, 2, "Authorized Auditor");
    await roleManager.assignRole(auditor2.address, 2, "Second Authorized Auditor");
  });

  it("regression: outsider_logs_for_other_operator should be rejected", async function () {
    // Expected behavior under R01: An outsider cannot forge an activity log on behalf of another operator.
    // In legacy/v1 contract, logActivity has NO caller check, so this call succeeds instead of reverting!
    await expect(
      insiderLog.connect(outsider).logActivity(
        operator.address,
        1, // TRANSACTION_OVERRIDE
        101,
        beneficiary.address,
        "Forged override by outsider"
      )
    ).to.be.revertedWith("InsiderActivityLog: caller is not authorized recorder");
  });

  it("regression: outsider_changes_business_hours should be rejected", async function () {
    // Expected behavior under R01/R03: Only governance can update business hours.
    // In legacy/v1 contract, setBusinessHours is unconstrained public, so outsider succeeds!
    await expect(
      insiderLog.connect(outsider).setBusinessHours(0, 24)
    ).to.be.revertedWith("InsiderActivityLog: caller is not governance");
  });

  it("regression: approved_proposal_reused should be rejected upon second execution", async function () {
    // Expected behavior under R02: A proposal must be consumed atomically and cannot be replayed.
    // In legacy/v1 contract, emergencyUnpause only checks isApproved(id) which never expires/marks consumed.
    
    // 1. Pause the engine
    await auditEngine.connect(admin).emergencyPause("First emergency pause");
    expect(await auditEngine.isPaused()).to.equal(true);

    // 2. Create proposal to unpause (ProposalType.POLICY_CHANGE is index 2)
    await multiSig.connect(auditor).createProposal(2, "0x", "Unpause proposal");
    // Approve proposal by admin (1st approval) and auditor2 (2nd approval)
    await multiSig.connect(admin).approveProposal(1);
    await multiSig.connect(auditor2).approveProposal(1);
    expect(await multiSig.isApproved(1)).to.equal(true);

    // 3. First unpause succeeds
    await auditEngine.connect(admin).emergencyUnpause(1);
    expect(await auditEngine.isPaused()).to.equal(false);

    // 4. Engine paused again due to another emergency incident
    await auditEngine.connect(admin).emergencyPause("Second emergency pause");
    expect(await auditEngine.isPaused()).to.equal(true);

    // 5. Attempt to REUSE proposal #1 to unpause again: MUST be rejected!
    await expect(
      auditEngine.connect(admin).emergencyUnpause(1)
    ).to.be.revertedWith("AuditEngine: proposal already executed or expired");
  });
});
