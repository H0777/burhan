const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Security Regressions Baseline Reproduction (T01)", function () {
  let admin, operator, auditor, auditor2, outsider, beneficiary;
  let roleManager, multiSig, forensicTrail, insiderLog, auditEngine;

const { deploySystemFixture } = require("../helpers/deploySystem");

  beforeEach(async function () {
    const system = await deploySystemFixture();
    roleManager = system.roleManager;
    multiSig = system.multiSig;
    forensicTrail = system.forensicTrail;
    insiderLog = system.insiderLog;
    auditEngine = system.auditEngine;
    admin = system.admin;
    auditor = system.auditor1;
    auditor2 = system.auditor2;
    operator = system.operator;
    outsider = system.outsider;
    beneficiary = system.regulator;
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

    // 2. Create proposal to unpause (ProposalType.EMERGENCY_UNPAUSE is index 2)
    const unpauseCalldata = auditEngine.interface.encodeFunctionData("executeEmergencyUnpause", [1]);
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("Unpause proposal"));
    await multiSig.connect(auditor).createProposal(2, await auditEngine.getAddress(), unpauseCalldata, reasonHash);
    // Approve proposal by admin (1st approval) and auditor2 (2nd approval)
    await multiSig.connect(admin).approveProposal(1);
    await multiSig.connect(auditor2).approveProposal(1);
    expect(await multiSig.isApproved(1)).to.equal(true);

    // 3. First unpause succeeds via atomic executeProposal
    await multiSig.connect(admin).executeProposal(1);
    expect(await auditEngine.isPaused()).to.equal(false);

    // 4. Engine paused again due to another emergency incident
    await auditEngine.connect(admin).emergencyPause("Second emergency pause");
    expect(await auditEngine.isPaused()).to.equal(true);

    // 5. Attempt to REUSE proposal #1 to unpause again: MUST be rejected!
    await expect(
      multiSig.connect(admin).executeProposal(1)
    ).to.be.revertedWith("MultiSig: proposal is not approved or already executed");
  });
});
