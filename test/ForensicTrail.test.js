const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ForensicTrail", function () {
  let forensicTrail;
  let investigator, auditor, suspect, outsider;

  beforeEach(async function () {
    [investigator, auditor, suspect, outsider] = await ethers.getSigners();
    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    forensicTrail = await ForensicTrail.deploy(investigator.address);
    await forensicTrail.waitForDeployment();
    await forensicTrail.connect(investigator).setEvidenceWriter(investigator.address, true);
    await forensicTrail.connect(investigator).setEvidenceWriter(auditor.address, true);
  });

  describe("Deployment", function () {
    it("Should initialize with zero incidents and zero evidence entries", async function () {
      expect(await forensicTrail.totalIncidents()).to.equal(0);
      expect(await forensicTrail.totalEvidence()).to.equal(0);
      const allIds = await forensicTrail.getAllIncidentIds();
      expect(allIds.length).to.equal(0);
    });
  });

  describe("Incident Creation", function () {
    it("Should create an incident with correct details and emit event", async function () {
      const tx = await forensicTrail.connect(investigator).createIncident(
        "Unauthorized Treasury Withdrawal Attempt",
        "CRITICAL"
      );
      await expect(tx)
        .to.emit(forensicTrail, "IncidentCreated")
        .withArgs(
          1,
          "Unauthorized Treasury Withdrawal Attempt",
          "CRITICAL",
          investigator.address,
          await ethers.provider.getBlock("latest").then((b) => b.timestamp)
        );

      expect(await forensicTrail.totalIncidents()).to.equal(1);
      const inc = await forensicTrail.getIncident(1);
      expect(inc.id).to.equal(1);
      expect(inc.title).to.equal("Unauthorized Treasury Withdrawal Attempt");
      expect(inc.severity).to.equal("CRITICAL");
      expect(inc.reportedBy).to.equal(investigator.address);
      expect(inc.isOpen).to.equal(true);
      expect(inc.evidenceCount).to.equal(0);
    });

    it("Should revert on empty title or empty severity", async function () {
      await expect(
        forensicTrail.connect(investigator).createIncident("", "HIGH")
      ).to.be.revertedWith("ForensicTrail: title required");

      await expect(
        forensicTrail.connect(investigator).createIncident("Incident 1", "")
      ).to.be.revertedWith("ForensicTrail: severity required");
    });
  });

  describe("Evidence Submission & Chain of Custody", function () {
    beforeEach(async function () {
      await forensicTrail.connect(investigator).createIncident(
        "AML Structuring Pattern Detected",
        "HIGH"
      );
    });

    it("Should submit first evidence entry with zero previous hash", async function () {
      const docHash = ethers.keccak256(ethers.toUtf8Bytes("bank_statement_2026.pdf"));
      await expect(
        forensicTrail.connect(investigator).submitEvidence(
          1,
          "TRANSACTION_ANOMALY",
          "Multiple transactions just under 10,000 threshold within 1 hour",
          docHash
        )
      ).to.emit(forensicTrail, "EvidenceSubmitted");

      expect(await forensicTrail.totalEvidence()).to.equal(1);

      const chain = await forensicTrail.getEvidenceChain(1);
      expect(chain.length).to.equal(1);
      expect(chain[0].id).to.equal(1);
      expect(chain[0].incidentId).to.equal(1);
      expect(chain[0].submittedBy).to.equal(investigator.address);
      expect(chain[0].evidenceType).to.equal("TRANSACTION_ANOMALY");
      expect(chain[0].evidenceHash).to.equal(docHash);
      expect(chain[0].previousEntryHash).to.equal(ethers.ZeroHash);
      expect(chain[0].entryHash).to.not.equal(ethers.ZeroHash);
    });

    it("Should link subsequent evidence to the previous entry hash", async function () {
      const doc1 = ethers.keccak256(ethers.toUtf8Bytes("audit_log_1.json"));
      const doc2 = ethers.keccak256(ethers.toUtf8Bytes("witness_statement.pdf"));

      await forensicTrail.connect(investigator).submitEvidence(
        1,
        "INSIDER_ACTIVITY",
        "Employee overrode AML warnings 3 times consecutively",
        doc1
      );

      await forensicTrail.connect(auditor).submitEvidence(
        1,
        "INTERVIEW_RECORD",
        "Operator failed to provide written authorization for overrides",
        doc2
      );

      const chain = await forensicTrail.getEvidenceChain(1);
      expect(chain.length).to.equal(2);
      expect(chain[1].previousEntryHash).to.equal(chain[0].entryHash);
    });

    it("Should verify cryptographic chain integrity", async function () {
      const doc1 = ethers.keccak256(ethers.toUtf8Bytes("entry1"));
      const doc2 = ethers.keccak256(ethers.toUtf8Bytes("entry2"));
      const doc3 = ethers.keccak256(ethers.toUtf8Bytes("entry3"));

      await forensicTrail.connect(investigator).submitEvidence(1, "TYPE_A", "Step 1", doc1);
      await forensicTrail.connect(auditor).submitEvidence(1, "TYPE_B", "Step 2", doc2);
      await forensicTrail.connect(investigator).submitEvidence(1, "TYPE_C", "Step 3", doc3);

      const isChainValid = await forensicTrail.verifyChainIntegrity(1);
      expect(isChainValid).to.equal(true);
    });

    it("Should revert evidence submission on non-existent or closed incident", async function () {
      const doc = ethers.keccak256(ethers.toUtf8Bytes("file"));
      await expect(
        forensicTrail.connect(investigator).submitEvidence(999, "TYPE", "Desc", doc)
      ).to.be.revertedWith("ForensicTrail: incident does not exist");
    });
  });

  describe("Incident Lifecycle & Closure", function () {
    beforeEach(async function () {
      await forensicTrail.connect(investigator).createIncident("Insider Collusion Case", "HIGH");
    });

    it("Should allow only the reporter to close an incident", async function () {
      await expect(
        forensicTrail.connect(outsider).closeIncident(1)
      ).to.be.revertedWith("ForensicTrail: only reporter can close");

      await expect(forensicTrail.connect(investigator).closeIncident(1))
        .to.emit(forensicTrail, "IncidentClosed");

      const inc = await forensicTrail.getIncident(1);
      expect(inc.isOpen).to.equal(false);
    });

    it("Should reject evidence submissions once incident is closed", async function () {
      await forensicTrail.connect(investigator).closeIncident(1);

      const doc = ethers.keccak256(ethers.toUtf8Bytes("late_entry"));
      await expect(
        forensicTrail.connect(investigator).submitEvidence(1, "LATE_EVIDENCE", "Post closure note", doc)
      ).to.be.revertedWith("ForensicTrail: incident is closed");
    });

    it("Should revert if closing an already closed incident", async function () {
      await forensicTrail.connect(investigator).closeIncident(1);
      await expect(
        forensicTrail.connect(investigator).closeIncident(1)
      ).to.be.revertedWith("ForensicTrail: already closed");
    });
  });
});
