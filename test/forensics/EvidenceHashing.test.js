const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("Evidence V2 Hashing & ForensicTrail Deduplication (T04)", function () {
  let evidenceHashing;
  let forensicTrail;
  let admin, auditor, writer2, outsider;
  let fixtureData;

  before(function () {
    const fixturePath = path.join(__dirname, "../../shared/fixtures/evidence-v2.json");
    fixtureData = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  });

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    [admin, auditor, writer2, outsider] = signers;

    // Deploy EvidenceHashingWrapper to test library directly
    const EvidenceHashingWrapper = await ethers.getContractFactory("EvidenceHashingWrapper");
    evidenceHashing = await EvidenceHashingWrapper.deploy();
    await evidenceHashing.waitForDeployment();

    // Deploy ForensicTrail with admin as initial governance
    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    forensicTrail = await ForensicTrail.deploy(admin.address);
    await forensicTrail.waitForDeployment();

    // Authorize auditor and writer2 as evidence writers
    await forensicTrail.connect(admin).setEvidenceWriter(auditor.address, true);
    await forensicTrail.connect(admin).setEvidenceWriter(writer2.address, true);
  });

  describe("EvidenceHashing Library - Fixtures Parity", function () {
    it("should match constant DOMAIN and SCHEMA_VERSION", async function () {
      expect(await evidenceHashing.getDomain()).to.equal(fixtureData.domain);
      expect(await evidenceHashing.getSchemaVersion()).to.equal(fixtureData.schemaVersion);
    });

    it("should compute exact hashEntry matching all fixtures in shared/fixtures/evidence-v2.json", async function () {
      for (const fix of fixtureData.fixtures) {
        const entry = {
          schemaVersion: fix.schemaVersion || 2,
          chainId: fix.chainId,
          contractAddress: fix.contractAddress,
          incidentId: fix.incidentId,
          evidenceId: fix.evidenceId,
          submittedBy: fix.submittedBy,
          timestamp: fix.timestamp,
          evidenceTypeHash: fix.evidenceTypeHash,
          descriptionHash: fix.descriptionHash,
          evidenceHash: fix.evidenceHash,
          previousEntryHash: fix.previousEntryHash,
        };

        const computed = await evidenceHashing.hashEntry(entry);
        expect(computed.toLowerCase()).to.equal(fix.expectedEntryHash.toLowerCase(), `Failed for ${fix.name}`);
      }
    });

    it("should reflect sensitivity across all 10 field variations", async function () {
      const baseExpected = fixtureData.fixtures[0].expectedEntryHash.toLowerCase();

      for (const varEntry of fixtureData.variations) {
        const entry = {
          schemaVersion: varEntry.schemaVersion || 2,
          chainId: varEntry.chainId,
          contractAddress: varEntry.contractAddress,
          incidentId: varEntry.incidentId,
          evidenceId: varEntry.evidenceId,
          submittedBy: varEntry.submittedBy,
          timestamp: varEntry.timestamp,
          evidenceTypeHash: varEntry.evidenceTypeHash,
          descriptionHash: varEntry.descriptionHash,
          evidenceHash: varEntry.evidenceHash,
          previousEntryHash: varEntry.previousEntryHash,
        };

        const computed = (await evidenceHashing.hashEntry(entry)).toLowerCase();
        expect(computed).to.equal(varEntry.expectedEntryHash.toLowerCase(), `Failed for ${varEntry.name}`);
        expect(computed).to.not.equal(baseExpected, `Variation ${varEntry.name} must differ from base`);
      }
    });
  });

  describe("ForensicTrail V2 - Incident Creation & Deduplicated Submissions", function () {
    let incidentId;
    const titleHash = ethers.keccak256(ethers.toUtf8Bytes("SUSPICIOUS_STRUCTURING"));
    const severityHash = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));
    const typeHash = ethers.keccak256(ethers.toUtf8Bytes("TRANSACTION_ANOMALY"));
    const descHash = ethers.keccak256(ethers.toUtf8Bytes("Smurfing pattern detected across 4 transfers"));
    const fileSha256 = ethers.sha256(ethers.toUtf8Bytes("dummy_offchain_file_content_123"));
    const anchorRequestId = ethers.keccak256(ethers.toUtf8Bytes("operation_request_uuid_001"));

    beforeEach(async function () {
      const tx = await forensicTrail.connect(auditor).createIncident(titleHash, severityHash);
      const receipt = await tx.wait();
      incidentId = 1;
    });

    it("should allow authorized writer to submit evidence and compute canonical V2 hash", async function () {
      const tx = await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorRequestId,
        typeHash,
        descHash,
        fileSha256
      );

      await expect(tx)
        .to.emit(forensicTrail, "EvidenceSubmitted")
        .withArgs(incidentId, 1, auditor.address, typeHash, (hash) => hash.length === 66, (ts) => ts > 0);

      expect(await forensicTrail.totalEvidence()).to.equal(1);

      // Verify dedup record query
      const [evId, entryHash, submittedBy, exists] = await forensicTrail.getEvidenceByRequestId(anchorRequestId);
      expect(exists).to.equal(true);
      expect(evId).to.equal(1);
      expect(submittedBy).to.equal(auditor.address);
      expect(entryHash).to.not.equal(ethers.ZeroHash);
    });

    it("should idempotently return existing evidenceId on duplicate anchorRequestId with same payload and writer", async function () {
      // 1st submission
      await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorRequestId,
        typeHash,
        descHash,
        fileSha256
      );
      expect(await forensicTrail.totalEvidence()).to.equal(1);

      // 2nd submission with EXACT same writer and payload -> must return 1 without emitting new event or incrementing count
      const tx = await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorRequestId,
        typeHash,
        descHash,
        fileSha256
      );
      const receipt = await tx.wait();

      expect(await forensicTrail.totalEvidence()).to.equal(1);

      // Verify no duplicate EvidenceSubmitted event emitted in receipt
      const submittedEvents = receipt.logs.filter(
        (log) => log.fragment && log.fragment.name === "EvidenceSubmitted"
      );
      expect(submittedEvents.length).to.equal(0);
    });

    it("should revert if same anchorRequestId is reused with a different payload", async function () {
      await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorRequestId,
        typeHash,
        descHash,
        fileSha256
      );

      const differentFileSha256 = ethers.sha256(ethers.toUtf8Bytes("completely_different_payload"));

      await expect(
        forensicTrail.connect(auditor).submitEvidence(
          incidentId,
          anchorRequestId,
          typeHash,
          descHash,
          differentFileSha256
        )
      ).to.be.revertedWith("ForensicTrail: anchorRequestId payload mismatch");
    });

    it("should revert if same anchorRequestId is reused by a different writer", async function () {
      await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorRequestId,
        typeHash,
        descHash,
        fileSha256
      );

      await expect(
        forensicTrail.connect(writer2).submitEvidence(
          incidentId,
          anchorRequestId,
          typeHash,
          descHash,
          fileSha256
        )
      ).to.be.revertedWith("ForensicTrail: anchorRequestId submittedBy mismatch");
    });

    it("should maintain and verify cryptographic chain integrity across multiple entries", async function () {
      const anchorReq1 = ethers.keccak256(ethers.toUtf8Bytes("req_1"));
      const anchorReq2 = ethers.keccak256(ethers.toUtf8Bytes("req_2"));
      const anchorReq3 = ethers.keccak256(ethers.toUtf8Bytes("req_3"));

      await forensicTrail.connect(auditor).submitEvidence(incidentId, anchorReq1, typeHash, descHash, fileSha256);
      await forensicTrail.connect(writer2).submitEvidence(
        incidentId,
        anchorReq2,
        ethers.keccak256(ethers.toUtf8Bytes("SECONDARY_LOG")),
        ethers.keccak256(ethers.toUtf8Bytes("Second piece of evidence")),
        ethers.sha256(ethers.toUtf8Bytes("second_file_bytes"))
      );
      await forensicTrail.connect(auditor).submitEvidence(
        incidentId,
        anchorReq3,
        ethers.keccak256(ethers.toUtf8Bytes("FINAL_MEMO")),
        ethers.keccak256(ethers.toUtf8Bytes("Auditor signoff")),
        ethers.sha256(ethers.toUtf8Bytes("signoff_pdf"))
      );

      expect(await forensicTrail.verifyChainIntegrity(incidentId)).to.equal(true);
    });
  });
});
