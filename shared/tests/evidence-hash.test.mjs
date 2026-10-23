import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hashEvidence, DOMAIN, SCHEMA_VERSION } from "../../frontend/src/utils/evidenceHash.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fixturePath = path.join(__dirname, "../fixtures/evidence-v2.json");
const fixtureData = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

test("Evidence V2 JS Hashing - Constants Parity", () => {
  assert.equal(SCHEMA_VERSION, 2);
  assert.equal(DOMAIN, fixtureData.domain);
});

test("Evidence V2 JS Hashing - Fixtures Parity", () => {
  for (const fixture of fixtureData.fixtures) {
    const computed = hashEvidence(fixture);
    assert.equal(
      computed.toLowerCase(),
      fixture.expectedEntryHash.toLowerCase(),
      `Mismatch for fixture: ${fixture.name}`
    );
  }
});

test("Evidence V2 JS Hashing - Field Variations Sensitivity", () => {
  for (const variation of fixtureData.variations) {
    const computed = hashEvidence(variation);
    assert.equal(
      computed.toLowerCase(),
      variation.expectedEntryHash.toLowerCase(),
      `Mismatch for variation: ${variation.name}`
    );
    // Must also not match the base fixture hash
    assert.notEqual(
      computed.toLowerCase(),
      fixtureData.fixtures[0].expectedEntryHash.toLowerCase(),
      `Variation ${variation.name} should alter the hash from base`
    );
  }
});
