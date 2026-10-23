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
      const titleHash = ethers.keccak256(ethers.toUtf8Bytes("Unauthorized Treasury Withdrawal Attempt"));
      const severityHash = ethers.keccak256(ethers.toUtf8Bytes("CRITICAL"));

      const tx = await forensicTrail.connect(investigator).createIncident(
        titleHash,
        severityHash
      );
      await expect(tx)
        .to.emit(forensicTrail, "IncidentCreated")
        .withArgs(
          1,
          titleHash,
          severityHash,
          investigator.address,
          await ethers.provider.getBlock("latest").then((b) => b.timestamp)
        );

      expect(await forensicTrail.totalIncidents()).to.equal(1);
      const inc = await forensicTrail.getIncident(1);
      expect(inc.id).to.equal(1);
      expect(inc.titleHash).to.equal(titleHash);
      expect(inc.severityHash).to.equal(severityHash);
      expect(inc.reportedBy).to.equal(investigator.address);
      expect(inc.isOpen).to.equal(true);
      expect(inc.evidenceCount).to.equal(0);
    });

    it("Should revert on empty title or empty severity", async function () {
      const validHash = ethers.keccak256(ethers.toUtf8Bytes("Valid"));
      await expect(
        forensicTrail.connect(investigator).createIncident(ethers.ZeroHash, validHash)
      ).to.be.revertedWith("ForensicTrail: title required");

      await expect(
        forensicTrail.connect(investigator).createIncident(validHash, ethers.ZeroHash)
      ).to.be.revertedWith("ForensicTrail: severity required");
    });
  });

  describe("Evidence Submission & Chain of Custody", function () {
    const titleHash = ethers.keccak256(ethers.toUtf8Bytes("AML Structuring Pattern Detected"));
    const severityHash = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));

    beforeEach(async function () {
      await forensicTrail.connect(investigator).createIncident(
        titleHash,
        severityHash
      );
    });

    it("Should submit first evidence entry with zero previous hash", async function () {
      const typeHash = ethers.keccak256(ethers.toUtf8Bytes("TRANSACTION_ANOMALY"));
      const descHash = ethers.keccak256(ethers.toUtf8Bytes("Multiple transactions just under 10,000 threshold within 1 hour"));
      const docHash = ethers.sha256(ethers.toUtf8Bytes("bank_statement_2026.pdf"));
      const reqId = ethers.keccak256(ethers.toUtf8Bytes("req_initial_01"));

      await expect(
        forensicTrail.connect(investigator).submitEvidence(
          1,
          reqId,
          typeHash,
          descHash,
          docHash
        )
      ).to.emit(forensicTrail, "EvidenceSubmitted");

      expect(await forensicTrail.totalEvidence()).to.equal(1);

      const chain = await forensicTrail.getEvidenceChain(1);
      expect(chain.length).to.equal(1);
      expect(chain[0].id).to.equal(1);
      expect(chain[0].incidentId).to.equal(1);
      expect(chain[0].submittedBy).to.equal(investigator.address);
      expect(chain[0].evidenceTypeHash).to.equal(typeHash);
      expect(chain[0].evidenceHash).to.equal(docHash);
      expect(chain[0].previousEntryHash).to.equal(ethers.ZeroHash);
      expect(chain[0].entryHash).to.not.equal(ethers.ZeroHash);
    });

    it("Should link subsequent evidence to the previous entry hash", async function () {
      const type1 = ethers.keccak256(ethers.toUtf8Bytes("INSIDER_ACTIVITY"));
      const desc1 = ethers.keccak256(ethers.toUtf8Bytes("Employee overrode AML warnings 3 times consecutively"));
      const doc1 = ethers.sha256(ethers.toUtf8Bytes("audit_log_1.json"));
      const req1 = ethers.keccak256(ethers.toUtf8Bytes("req_1"));

      const type2 = ethers.keccak256(ethers.toUtf8Bytes("INTERVIEW_RECORD"));
      const desc2 = ethers.keccak256(ethers.toUtf8Bytes("Operator failed to provide written authorization for overrides"));
      const doc2 = ethers.sha256(ethers.toUtf8Bytes("witness_statement.pdf"));
      const req2 = ethers.keccak256(ethers.toUtf8Bytes("req_2"));

      await forensicTrail.connect(investigator).submitEvidence(1, req1, type1, desc1, doc1);
      await forensicTrail.connect(auditor).submitEvidence(1, req2, type2, desc2, doc2);

      const chain = await forensicTrail.getEvidenceChain(1);
      expect(chain.length).to.equal(2);
      expect(chain[1].previousEntryHash).to.equal(chain[0].entryHash);
    });

    it("Should verify cryptographic chain integrity", async function () {
      const typeA = ethers.keccak256(ethers.toUtf8Bytes("TYPE_A"));
      const descA = ethers.keccak256(ethers.toUtf8Bytes("Step 1"));
      const docA = ethers.sha256(ethers.toUtf8Bytes("entry1"));

      const typeB = ethers.keccak256(ethers.toUtf8Bytes("TYPE_B"));
      const descB = ethers.keccak256(ethers.toUtf8Bytes("Step 2"));
      const docB = ethers.sha256(ethers.toUtf8Bytes("entry2"));

      const typeC = ethers.keccak256(ethers.toUtf8Bytes("TYPE_C"));
      const descC = ethers.keccak256(ethers.toUtf8Bytes("Step 3"));
      const docC = ethers.sha256(ethers.toUtf8Bytes("entry3"));

      await forensicTrail.connect(investigator).submitEvidence(1, ethers.keccak256(ethers.toUtf8Bytes("r1")), typeA, descA, docA);
      await forensicTrail.connect(auditor).submitEvidence(1, ethers.keccak256(ethers.toUtf8Bytes("r2")), typeB, descB, docB);
      await forensicTrail.connect(investigator).submitEvidence(1, ethers.keccak256(ethers.toUtf8Bytes("r3")), typeC, descC, docC);

      const isChainValid = await forensicTrail.verifyChainIntegrity(1);
      expect(isChainValid).to.equal(true);
    });

    it("Should revert evidence submission on non-existent or closed incident", async function () {
      const type = ethers.keccak256(ethers.toUtf8Bytes("TYPE"));
      const desc = ethers.keccak256(ethers.toUtf8Bytes("Desc"));
      const doc = ethers.sha256(ethers.toUtf8Bytes("file"));
      const req = ethers.keccak256(ethers.toUtf8Bytes("r_non_existent"));

      await expect(
        forensicTrail.connect(investigator).submitEvidence(999, req, type, desc, doc)
      ).to.be.revertedWith("ForensicTrail: incident does not exist");
    });
  });

  describe("Incident Lifecycle & Closure", function () {
    beforeEach(async function () {
      const titleHash = ethers.keccak256(ethers.toUtf8Bytes("Insider Collusion Case"));
      const severityHash = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));
      await forensicTrail.connect(investigator).createIncident(titleHash, severityHash);
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

      const type = ethers.keccak256(ethers.toUtf8Bytes("LATE_EVIDENCE"));
      const desc = ethers.keccak256(ethers.toUtf8Bytes("Post closure note"));
      const doc = ethers.sha256(ethers.toUtf8Bytes("late_entry"));
      const req = ethers.keccak256(ethers.toUtf8Bytes("r_late"));

      await expect(
        forensicTrail.connect(investigator).submitEvidence(1, req, type, desc, doc)
      ).to.be.revertedWith("ForensicTrail: incident is closed");
    });

    it("Should revert if closing an already closed incident", async function () {
      await forensicTrail.connect(investigator).closeIncident(1);
      await expect(
        forensicTrail.connect(investigator).closeIncident(1)
      ).to.be.revertedWith("ForensicTrail: already closed");
    });
  });

  // ============================================================
  // R03: ATTESTED MANIFEST COMMITMENT & CASE REFERENCES
  // (deep behavioral suite: test/forensics/ManifestCommitment.test.js)
  // ============================================================

  describe("R03: Attested Evidence Manifest Commitment", function () {
    beforeEach(async function () {
      await forensicTrail.connect(investigator).createIncident(
        ethers.keccak256(ethers.toUtf8Bytes("Attested case")),
        ethers.keccak256(ethers.toUtf8Bytes("MEDIUM"))
      );
    });

    it("Should anchor the manifest digest in the same transaction and expose it via lookup", async function () {
      const requestId = ethers.keccak256(ethers.toUtf8Bytes("att-req-1"));
      const manifestDigest = ethers.keccak256(ethers.toUtf8Bytes("manifest-1"));

      await expect(
        forensicTrail.connect(investigator).submitEvidenceAttested(
          1,
          requestId,
          ethers.keccak256(ethers.toUtf8Bytes("KYC_DOSSIER")),
          ethers.keccak256(ethers.toUtf8Bytes("Notarized KYC bundle")),
          ethers.sha256(ethers.toUtf8Bytes("kyc.tar")),
          manifestDigest
        )
      ).to.emit(forensicTrail, "EvidenceManifestAnchored");

      expect(await forensicTrail.getManifestDigest(requestId)).to.equal(manifestDigest);
      expect(await forensicTrail.totalEvidence()).to.equal(1);
    });

    it("Should reject a zero manifest digest", async function () {
      await expect(
        forensicTrail.connect(investigator).submitEvidenceAttested(
          1,
          ethers.keccak256(ethers.toUtf8Bytes("att-req-2")),
          ethers.keccak256(ethers.toUtf8Bytes("KYC_DOSSIER")),
          ethers.keccak256(ethers.toUtf8Bytes("Notarized KYC bundle")),
          ethers.sha256(ethers.toUtf8Bytes("kyc.tar")),
          ethers.ZeroHash
        )
      ).to.be.revertedWith("ForensicTrail: manifest digest required");
    });
  });

  describe("R03: Case-Referenced Incidents", function () {
    it("Should return the same incident for the same case reference and conflict on different metadata", async function () {
      const caseRef = ethers.keccak256(ethers.toUtf8Bytes("case-ref-1"));
      const titleHash = ethers.keccak256(ethers.toUtf8Bytes("Case-referenced incident"));
      const severityHash = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));

      await forensicTrail.connect(investigator).createIncidentForCase(caseRef, titleHash, severityHash);
      expect(await forensicTrail.getIncidentByCaseReference(caseRef)).to.equal(1);
      expect(await forensicTrail.totalIncidents()).to.equal(1);

      // Another authorized writer, same reference + metadata: same incident.
      await forensicTrail.connect(auditor).createIncidentForCase(caseRef, titleHash, severityHash);
      expect(await forensicTrail.totalIncidents()).to.equal(1);

      // Different metadata for the same reference: conflict.
      await expect(
        forensicTrail
          .connect(auditor)
          .createIncidentForCase(caseRef, ethers.keccak256(ethers.toUtf8Bytes("Different")), severityHash)
      ).to.be.revertedWith("ForensicTrail: case reference metadata conflict");
    });
  });
});
