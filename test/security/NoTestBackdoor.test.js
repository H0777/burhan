const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * R01 / Finding F01 — No Test Backdoor in Production RoleManager
 *
 * RoleManager previously exposed `testSetGeneration(address,uint256)` with NO
 * authorization. Anyone could rewrite the security generation that vote
 * validity in MultiSigApproval.executeProposal depends on. These tests pin the
 * fixed behavior:
 *   1. outsider_cannot_call_generation_setter — raw calldata for the removed
 *      selector, sent from a plain external address, must revert and leave
 *      getGeneration unchanged.
 *   2. production_abi_has_no_test_mutator — the compiled artifact and every
 *      exported ABI file must not declare testSetGeneration, while the
 *      spec-mandated views (getGeneration, getParticipant) must remain.
 */

// Enum Role: NONE(0), SUPER_ADMIN(1), AUDITOR(2), OPERATOR(3), REGULATOR(4)
const Role = {
  NONE: 0,
  SUPER_ADMIN: 1,
  AUDITOR: 2,
  OPERATOR: 3,
  REGULATOR: 4,
};

const ROOT_DIR = path.join(__dirname, "..", "..");

// Compiled artifact nests the ABI under "abi"; exported files are bare arrays.
function loadAbi(file) {
  let raw = fs.readFileSync(file, "utf-8");
  if (file.endsWith(".js")) {
    raw = raw.replace(/^export default\s*/, "").trim();
  }
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : parsed.abi;
}

function functionNames(abi) {
  return abi.filter((entry) => entry.type === "function").map((entry) => entry.name);
}

describe("No Test Backdoor in Production RoleManager (R01/F01)", function () {
  describe("outsider_cannot_call_generation_setter", function () {
    it("raw testSetGeneration calldata from an external address reverts and leaves generation unchanged", async function () {
      const [governance, auditor, outsider] = await ethers.getSigners();

      const RoleManager = await ethers.getContractFactory("RoleManager");
      const roleManager = await RoleManager.deploy(governance.address);
      await roleManager.waitForDeployment();
      const roleManagerAddress = await roleManager.getAddress();

      // Enroll the auditor through the real path so it holds a live generation.
      await roleManager
        .connect(governance)
        .assignRole(auditor.address, Role.AUDITOR, "R01 fixture: auditor enrollment");

      const generationBefore = await roleManager.getGeneration(auditor.address);
      expect(generationBefore).to.equal(1n);

      // Build calldata for the removed test-only signature ourselves: the
      // production artifact ABI no longer declares it, so we must not rely on it.
      const backdoorInterface = new ethers.Interface([
        "function testSetGeneration(address,uint256)",
      ]);
      const backdoorCalldata = backdoorInterface.encodeFunctionData("testSetGeneration", [
        auditor.address,
        999n,
      ]);

      // A plain external address sending the forged mutation must be rejected.
      // (Before R01 this transaction SUCCEEDED and set generation to 999 —
      // that was the vulnerability this test locks out.)
      await expect(
        outsider.sendTransaction({ to: roleManagerAddress, data: backdoorCalldata })
      ).to.be.reverted;

      // State must be untouched by the rejected call.
      expect(await roleManager.getGeneration(auditor.address)).to.equal(generationBefore);
    });
  });

  describe("production_abi_has_no_test_mutator", function () {
    const abiSources = [
      ["compiled artifact", path.join(ROOT_DIR, "artifacts", "contracts", "access", "RoleManager.sol", "RoleManager.json")],
      ["exported ABI json", path.join(ROOT_DIR, "frontend", "src", "contracts", "generated", "RoleManager.json")],
      ["exported ABI js", path.join(ROOT_DIR, "frontend", "src", "contracts", "generated", "RoleManager.js")],
    ];

    for (const [label, file] of abiSources) {
      it(`${label} declares no testSetGeneration function`, function () {
        expect(fs.existsSync(file), `${label} not found at ${file}`).to.equal(true);
        const names = functionNames(loadAbi(file));
        expect(names, `${label} must not expose the test backdoor`).to.not.include(
          "testSetGeneration"
        );
      });
    }

    it("spec-mandated view interface is preserved", function () {
      for (const [label, file] of abiSources) {
        const names = functionNames(loadAbi(file));
        expect(names, `${label} must keep the spec §5 views`).to.include.members([
          "getGeneration",
          "getParticipant",
        ]);
      }
    });
  });
});
