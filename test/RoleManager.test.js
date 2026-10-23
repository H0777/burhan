const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("RoleManager", function () {
  let roleManager;
  let deployer, superAdmin2, auditor, operator, regulator, outsider;

  // Enum Role: NONE(0), SUPER_ADMIN(1), AUDITOR(2), OPERATOR(3), REGULATOR(4)
  const Role = {
    NONE: 0,
    SUPER_ADMIN: 1,
    AUDITOR: 2,
    OPERATOR: 3,
    REGULATOR: 4,
  };

  beforeEach(async function () {
    [deployer, superAdmin2, auditor, operator, regulator, outsider] = await ethers.getSigners();
    const RoleManager = await ethers.getContractFactory("RoleManager");
    roleManager = await RoleManager.deploy(deployer.address);
    await roleManager.waitForDeployment();
  });

  describe("Deployment & Initialization", function () {
    it("Should set deployer as SUPER_ADMIN", async function () {
      expect(await roleManager.deployer()).to.equal(deployer.address);
      expect(await roleManager.getRole(deployer.address)).to.equal(Role.SUPER_ADMIN);
      expect(await roleManager.hasRole(deployer.address, Role.SUPER_ADMIN)).to.equal(true);
    });

    it("Should record initial deployer role history", async function () {
      const history = await roleManager.getRoleHistory(deployer.address);
      expect(history.length).to.equal(1);
      expect(history[0].previousRole).to.equal(Role.NONE);
      expect(history[0].newRole).to.equal(Role.SUPER_ADMIN);
      expect(history[0].changedBy).to.equal(deployer.address);
      expect(history[0].reason).to.equal("SYSTEM: Initial deployer assignment");
    });

    it("Should include deployer in allMembers and count", async function () {
      const members = await roleManager.getAllMembers();
      expect(members.length).to.equal(1);
      expect(members[0]).to.equal(deployer.address);
      expect(await roleManager.countByRole(Role.SUPER_ADMIN)).to.equal(1);
      expect(await roleManager.countByRole(Role.AUDITOR)).to.equal(0);
    });
  });

  describe("Assigning Roles", function () {
    it("Should allow SUPER_ADMIN to assign AUDITOR role", async function () {
      await expect(
        roleManager.connect(deployer).assignRole(auditor.address, Role.AUDITOR, "Hired as lead auditor")
      )
        .to.emit(roleManager, "RoleAssigned")
        .withArgs(
          auditor.address,
          Role.AUDITOR,
          deployer.address,
          "Hired as lead auditor",
          await ethers.provider.getBlock("latest").then((b) => b.timestamp + 1)
        );

      expect(await roleManager.getRole(auditor.address)).to.equal(Role.AUDITOR);
      expect(await roleManager.hasRole(auditor.address, Role.AUDITOR)).to.equal(true);
    });

    it("Should allow SUPER_ADMIN to assign OPERATOR and REGULATOR roles", async function () {
      await roleManager.connect(deployer).assignRole(operator.address, Role.OPERATOR, "New operator");
      await roleManager.connect(deployer).assignRole(regulator.address, Role.REGULATOR, "CBI Oversight");

      expect(await roleManager.getRole(operator.address)).to.equal(Role.OPERATOR);
      expect(await roleManager.getRole(regulator.address)).to.equal(Role.REGULATOR);
    });

    it("Should revert if non-admin tries to assign a role", async function () {
      await expect(
        roleManager.connect(outsider).assignRole(operator.address, Role.OPERATOR, "Unauthorized")
      ).to.be.revertedWith("RoleManager: caller is not governance");
    });

    it("Should revert when assigning to zero address", async function () {
      await expect(
        roleManager.connect(deployer).assignRole(ethers.ZeroAddress, Role.AUDITOR, "Zero address")
      ).to.be.revertedWith("RoleManager: invalid address");
    });

    it("Should revert when assigning Role.NONE via assignRole", async function () {
      await expect(
        roleManager.connect(deployer).assignRole(auditor.address, Role.NONE, "Invalid none")
      ).to.be.revertedWith("RoleManager: use revokeRole to remove roles");
    });

    it("Should revert when re-assigning the same role", async function () {
      await roleManager.connect(deployer).assignRole(auditor.address, Role.AUDITOR, "Initial");
      await expect(
        roleManager.connect(deployer).assignRole(auditor.address, Role.AUDITOR, "Duplicate")
      ).to.be.revertedWith("RoleManager: role already assigned");
    });
  });

  describe("Revoking Roles", function () {
    beforeEach(async function () {
      await roleManager.connect(deployer).assignRole(auditor.address, Role.AUDITOR, "Audit hire");
    });

    it("Should allow SUPER_ADMIN to revoke role", async function () {
      await expect(
        roleManager.connect(deployer).revokeRole(auditor.address, "Contract ended")
      )
        .to.emit(roleManager, "RoleRevoked")
        .withArgs(
          auditor.address,
          Role.AUDITOR,
          deployer.address,
          "Contract ended",
          await ethers.provider.getBlock("latest").then((b) => b.timestamp + 1)
        );

      expect(await roleManager.getRole(auditor.address)).to.equal(Role.NONE);
      expect(await roleManager.hasRole(auditor.address, Role.AUDITOR)).to.equal(false);
    });

    it("Should revert if non-admin tries to revoke role", async function () {
      await expect(
        roleManager.connect(outsider).revokeRole(auditor.address, "Hacker revoke")
      ).to.be.revertedWith("RoleManager: caller is not governance");
    });

    it("Should allow governance to revoke deployer role (no permanent privilege)", async function () {
      await expect(
        roleManager.connect(deployer).revokeRole(deployer.address, "Cannot remove deployer")
      ).to.emit(roleManager, "RoleRevoked");
      expect(await roleManager.hasRole(deployer.address, Role.SUPER_ADMIN)).to.equal(false);
    });

    it("Should revert if address has no role to revoke", async function () {
      await expect(
        roleManager.connect(deployer).revokeRole(outsider.address, "No role")
      ).to.be.revertedWith("RoleManager: no role to revoke");
    });
  });

  describe("Role History & Forensics", function () {
    it("Should maintain full history across role changes", async function () {
      await roleManager.connect(deployer).assignRole(operator.address, Role.OPERATOR, "Hired as Operator");
      await roleManager.connect(deployer).assignRole(operator.address, Role.AUDITOR, "Promoted to Auditor");
      await roleManager.connect(deployer).revokeRole(operator.address, "Suspended for audit");

      const count = await roleManager.getRoleChangeCount(operator.address);
      expect(count).to.equal(3);

      const history = await roleManager.getRoleHistory(operator.address);
      expect(history[0].previousRole).to.equal(Role.NONE);
      expect(history[0].newRole).to.equal(Role.OPERATOR);
      expect(history[0].reason).to.equal("Hired as Operator");

      expect(history[1].previousRole).to.equal(Role.OPERATOR);
      expect(history[1].newRole).to.equal(Role.AUDITOR);
      expect(history[1].reason).to.equal("Promoted to Auditor");

      expect(history[2].previousRole).to.equal(Role.AUDITOR);
      expect(history[2].newRole).to.equal(Role.NONE);
      expect(history[2].reason).to.equal("Suspended for audit");
    });
  });

  describe("Role Queries & Minimum Role Check", function () {
    beforeEach(async function () {
      await roleManager.connect(deployer).assignRole(auditor.address, Role.AUDITOR, "Auditor role");
      await roleManager.connect(deployer).assignRole(operator.address, Role.OPERATOR, "Operator role");
    });

    it("hasMinimumRole should treat SUPER_ADMIN as having all minimum roles", async function () {
      expect(await roleManager.hasMinimumRole(deployer.address, Role.SUPER_ADMIN)).to.equal(true);
      expect(await roleManager.hasMinimumRole(deployer.address, Role.AUDITOR)).to.equal(true);
      expect(await roleManager.hasMinimumRole(deployer.address, Role.OPERATOR)).to.equal(true);
      expect(await roleManager.hasMinimumRole(deployer.address, Role.REGULATOR)).to.equal(true);
      expect(await roleManager.hasMinimumRole(deployer.address, Role.NONE)).to.equal(true);
    });

    it("hasMinimumRole should match exact roles for non-superadmins", async function () {
      expect(await roleManager.hasMinimumRole(auditor.address, Role.AUDITOR)).to.equal(true);
      expect(await roleManager.hasMinimumRole(auditor.address, Role.OPERATOR)).to.equal(false);
      expect(await roleManager.hasMinimumRole(operator.address, Role.OPERATOR)).to.equal(true);
      expect(await roleManager.hasMinimumRole(outsider.address, Role.OPERATOR)).to.equal(false);
    });

    it("countByRole should return accurate counts", async function () {
      expect(await roleManager.countByRole(Role.SUPER_ADMIN)).to.equal(1);
      expect(await roleManager.countByRole(Role.AUDITOR)).to.equal(1);
      expect(await roleManager.countByRole(Role.OPERATOR)).to.equal(1);
      expect(await roleManager.countByRole(Role.REGULATOR)).to.equal(0);
    });
  });
});
