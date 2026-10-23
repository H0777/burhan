const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySystemFixture } = require("../helpers/deploySystem");

/**
 * R03 — التزام البيان (Evidence manifest commitment) + case references
 *
 * Binding design decisions (spec §4, §6, §7):
 *   - submitEvidenceAttested stores the requestId -> manifestDigest commitment
 *     in the SAME transaction that adds the evidence, emits
 *     EvidenceManifestAnchored, and never touches the Evidence V2 entry hash.
 *     Zero digest rejected; same requestId + different digest = conflict;
 *     same requestId + same digest is idempotent (evidence count unchanged).
 *     No backfill function exists for previously-recorded evidence.
 *   - createIncidentForCase maps an institution-wide caseReferenceHash to
 *     exactly one incident. The FIRST reference keeps metadata + creator;
 *     later requests from other writers return the same incident and never
 *     take it over; different metadata conflicts. caseReferenceHash is
 *     computed OFF-chain: keccak256(abi.encode(chainId, ForensicTrail,
 *     institutionRefHash, caseIdHash)).
 *   - The legacy submitEvidence path stays for automated AuditEngine alarms
 *     (chain_generated_unattested evidence class, classified by R07).
 */

const CRITICAL_LARGE_AMOUNT = ethers.parseEther("25000"); // > 2x threshold

describe("Manifest Commitment & Case References (R03)", function () {
  // ------------------------------------------------------------------
  // Standalone ForensicTrail fixture (governance = governance EOA)
  // ------------------------------------------------------------------
  async function deployForensicTrail() {
    const [governance, writer1, writer2, outsider] = await ethers.getSigners();
    const ForensicTrail = await ethers.getContractFactory("ForensicTrail");
    const forensicTrail = await ForensicTrail.deploy(governance.address);
    await forensicTrail.waitForDeployment();
    await forensicTrail.connect(governance).setEvidenceWriter(writer1.address, true);
    await forensicTrail.connect(governance).setEvidenceWriter(writer2.address, true);
    return { forensicTrail, governance, writer1, writer2, outsider };
  }

  const TITLE_HASH = ethers.keccak256(ethers.toUtf8Bytes("Structuring case #41"));
  const SEVERITY_HASH = ethers.keccak256(ethers.toUtf8Bytes("HIGH"));
  const TYPE_HASH = ethers.keccak256(ethers.toUtf8Bytes("BANK_STATEMENT"));
  const DESC_HASH = ethers.keccak256(ethers.toUtf8Bytes("Quarterly statement bundle"));
  const FILE_SHA = ethers.sha256(ethers.toUtf8Bytes("statements_2026_q3.tar"));

  describe("manifest_is_bound_to_request", function () {
    let forensicTrail, writer1, writer2;

    beforeEach(async function () {
      const fixture = await deployForensicTrail();
      forensicTrail = fixture.forensicTrail;
      writer1 = fixture.writer1;
      writer2 = fixture.writer2;
      await forensicTrail.connect(writer1).createIncident(TITLE_HASH, SEVERITY_HASH);
    });

    it("rejects a zero manifest digest", async function () {
      await expect(
        forensicTrail
          .connect(writer1)
          .submitEvidenceAttested(1, ethers.id("req-a1"), TYPE_HASH, DESC_HASH, FILE_SHA, ethers.ZeroHash)
      ).to.be.revertedWith("ForensicTrail: manifest digest required");
    });

    it("anchors the digest in the same transaction and returns it via lookup and event", async function () {
      const requestId = ethers.id("req-a2");
      const manifestDigest = ethers.keccak256(ethers.toUtf8Bytes("manifest-v1"));

      const tx = forensicTrail
        .connect(writer1)
        .submitEvidenceAttested(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, manifestDigest);
      await expect(tx)
        .to.emit(forensicTrail, "EvidenceManifestAnchored")
        .withArgs(requestId, 1, manifestDigest);

      expect(await forensicTrail.getManifestDigest(requestId)).to.equal(manifestDigest);
      expect(await forensicTrail.totalEvidence()).to.equal(1n);
      expect((await forensicTrail.getIncident(1)).evidenceCount).to.equal(1n);

      // The Evidence V2 entry hash stays canonical (untouched schema).
      const chain = await forensicTrail.getEvidenceChain(1);
      expect(chain[0].entryHash).to.not.equal(ethers.ZeroHash);
      expect(await forensicTrail.verifyChainIntegrity(1)).to.equal(true);
    });

    it("re-submitting the same request does not increment the evidence count", async function () {
      const requestId = ethers.id("req-a3");
      const manifestDigest = ethers.keccak256(ethers.toUtf8Bytes("manifest-a3"));

      const firstId = await forensicTrail
        .connect(writer1)
        .submitEvidenceAttested.staticCall(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, manifestDigest);
      expect(firstId).to.equal(1n);
      await forensicTrail
        .connect(writer1)
        .submitEvidenceAttested(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, manifestDigest);

      // Idempotent replay — even from another authorized writer.
      const replayId = await forensicTrail
        .connect(writer2)
        .submitEvidenceAttested.staticCall(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, manifestDigest);
      expect(replayId).to.equal(firstId);
      await forensicTrail
        .connect(writer2)
        .submitEvidenceAttested(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, manifestDigest);

      expect(await forensicTrail.totalEvidence()).to.equal(1n);
      expect((await forensicTrail.getIncident(1)).evidenceCount).to.equal(1n);
    });

    it("rejects the same requestId with a different manifest digest (conflict)", async function () {
      const requestId = ethers.id("req-a4");
      const digestA = ethers.keccak256(ethers.toUtf8Bytes("manifest-a4-A"));
      const digestB = ethers.keccak256(ethers.toUtf8Bytes("manifest-a4-B"));

      await forensicTrail
        .connect(writer1)
        .submitEvidenceAttested(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, digestA);

      await expect(
        forensicTrail
          .connect(writer1)
          .submitEvidenceAttested(1, requestId, TYPE_HASH, DESC_HASH, FILE_SHA, digestB)
      ).to.be.revertedWith("ForensicTrail: manifest digest conflict");
      expect(await forensicTrail.getManifestDigest(requestId)).to.equal(digestA);
    });
  });

  describe("case_reference_is_idempotent", function () {
    let forensicTrail, writer1, writer2;

    beforeEach(async function () {
      const fixture = await deployForensicTrail();
      forensicTrail = fixture.forensicTrail;
      writer1 = fixture.writer1;
      writer2 = fixture.writer2;
    });

    function caseReferenceHash(forensicTrailAddress, institutionRefHash, caseIdHash) {
      // keccak256(abi.encode(chainId, ForensicTrail, institutionRefHash, caseIdHash))
      // computed OFF-chain by the caller.
      return ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "address", "bytes32", "bytes32"],
          [31337n, forensicTrailAddress, institutionRefHash, caseIdHash]
        )
      );
    }

    it("keeps exactly one incident per reference; the first reference keeps metadata and creator", async function () {
      const ref = caseReferenceHash(
        await forensicTrail.getAddress(),
        ethers.id("IRAQ-AML-INSTITUTION"),
        ethers.id("CASE-2026-0041")
      );

      const firstId = await forensicTrail
        .connect(writer1)
        .createIncidentForCase.staticCall(ref, TITLE_HASH, SEVERITY_HASH);
      expect(firstId).to.equal(1n);
      await forensicTrail.connect(writer1).createIncidentForCase(ref, TITLE_HASH, SEVERITY_HASH);
      expect(await forensicTrail.getIncidentByCaseReference(ref)).to.equal(1n);
      expect(await forensicTrail.totalIncidents()).to.equal(1n);

      // Same reference + same metadata from ANOTHER writer: same incident,
      // no takeover, no second incident.
      const replayId = await forensicTrail
        .connect(writer2)
        .createIncidentForCase.staticCall(ref, TITLE_HASH, SEVERITY_HASH);
      expect(replayId).to.equal(1n);
      await forensicTrail.connect(writer2).createIncidentForCase(ref, TITLE_HASH, SEVERITY_HASH);
      expect(await forensicTrail.totalIncidents()).to.equal(1n);

      const incident = await forensicTrail.getIncident(1);
      expect(incident.titleHash).to.equal(TITLE_HASH); // first-ref metadata kept
      expect(incident.severityHash).to.equal(SEVERITY_HASH);
      expect(incident.reportedBy).to.equal(writer1.address); // creator kept
    });

    it("conflicting metadata for the same reference reverts", async function () {
      const ref = caseReferenceHash(
        await forensicTrail.getAddress(),
        ethers.id("IRAQ-AML-INSTITUTION"),
        ethers.id("CASE-2026-0042")
      );
      await forensicTrail.connect(writer1).createIncidentForCase(ref, TITLE_HASH, SEVERITY_HASH);

      const otherTitle = ethers.keccak256(ethers.toUtf8Bytes("Different case title"));
      await expect(
        forensicTrail.connect(writer2).createIncidentForCase(ref, otherTitle, SEVERITY_HASH)
      ).to.be.revertedWith("ForensicTrail: case reference metadata conflict");

      const otherSeverity = ethers.keccak256(ethers.toUtf8Bytes("CRITICAL"));
      await expect(
        forensicTrail.connect(writer2).createIncidentForCase(ref, TITLE_HASH, otherSeverity)
      ).to.be.revertedWith("ForensicTrail: case reference metadata conflict");

      expect(await forensicTrail.totalIncidents()).to.equal(1n);
    });

    it("rejects a zero case reference", async function () {
      await expect(
        forensicTrail.connect(writer1).createIncidentForCase(ethers.ZeroHash, TITLE_HASH, SEVERITY_HASH)
      ).to.be.revertedWith("ForensicTrail: case reference required");
    });
  });

  describe("automated_alarm_still_records", function () {
    it("the AuditEngine automated alarm path (legacy unattested submitEvidence) still records", async function () {
      const system = await deploySystemFixture();
      const { auditEngine, forensicTrail, operator, outsider } = system;

      await expect(
        auditEngine.connect(operator).submitTransaction(outsider.address, CRITICAL_LARGE_AMOUNT)
      ).to.emit(auditEngine, "AutomatedForensicIncidentCreated");

      expect(await forensicTrail.totalIncidents()).to.equal(1n);
      const incident = await forensicTrail.getIncident(1);
      expect(incident.evidenceCount).to.equal(1n);
      expect(await forensicTrail.totalEvidence()).to.equal(1n);
      expect(await forensicTrail.verifyChainIntegrity(1)).to.equal(true);
    });
  });
});
