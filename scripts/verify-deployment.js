const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

/**
 * @title Deployment Verifier (T10, reworked in R04)
 * @notice Cryptographically and functionally verifies a live deployment against
 *         its DeploymentBinding manifest (manifest_version=3):
 *         0. Manifest structure — validated against
 *            deployments/deployment-manifest.schema.json; missing required
 *            fields fail hard. Private keys are never valid manifest fields
 *            (schema + recursive scan both enforce this).
 *         1. REAL RPC: chain ID parity with the manifest
 *         2. REAL RPC: bytecode existence + keccak256 parity against
 *            deployed_code_hashes
 *         3. REAL RPC: governance wiring — required approvals, fixed 72h TTL
 *            (PROPOSAL_TTL = 259,200s), time-lock delay (86,400s), bootstrap
 *            finalization and permanent authority revocation
 *         4. REAL RPC: roster — 4+ eligible voters, participant ids still bound
 *            to their recorded wallets, recorded roles still held
 *         5. REAL RPC: writer/recorder integration — AuditEngine is the only
 *            authorized evidence writer / recorder
 */

const SCHEMA_PATH = path.join(__dirname, "..", "deployments", "deployment-manifest.schema.json");

// Defensive second layer (schema patternProperties already ban these): any key
// anywhere in the manifest matching this pattern makes the manifest invalid.
const FORBIDDEN_KEY_PATTERN = /private[_ -]?key|mnemonic|seed[_ -]?phrase|secret/i;

/**
 * Minimal JSON Schema (draft-07 subset) validator — dependency-free, covers
 * exactly the keywords used by deployment-manifest.schema.json: type, const,
 * enum, pattern, minLength, minimum, maximum, required, properties,
 * additionalProperties, propertyNames, patternProperties, items, minItems,
 * $ref (#/definitions/...), plus the "not": {} ban construct.
 */
function validateAgainstSchema(value, schema, root, schemaPath, errors) {
  root = root || schema;
  errors = errors || [];
  schemaPath = schemaPath || "#";

  if (schema.$ref) {
    const resolved = resolveRef(root, schema.$ref);
    return validateAgainstSchema(value, resolved, root, schemaPath, errors);
  }
  if ("const" in schema && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errors.push(`${schemaPath}: must equal ${JSON.stringify(schema.const)} (got ${JSON.stringify(value)})`);
  }
  if (schema.enum && !schema.enum.some((v) => JSON.stringify(v) === JSON.stringify(value))) {
    errors.push(`${schemaPath}: must be one of ${JSON.stringify(schema.enum)} (got ${JSON.stringify(value)})`);
  }
  if (schema.not && Object.keys(schema.not).length === 0) {
    // "not": {} — always false (used to ban private-key-like keys)
    errors.push(`${schemaPath}: key is forbidden by schema policy`);
  }
  if (schema.type) {
    const t = schema.type;
    const ok =
      (t === "object" && typeof value === "object" && value !== null && !Array.isArray(value)) ||
      (t === "array" && Array.isArray(value)) ||
      (t === "string" && typeof value === "string") ||
      (t === "integer" && typeof value === "number" && Number.isInteger(value)) ||
      (t === "number" && typeof value === "number") ||
      (t === "boolean" && typeof value === "boolean");
    if (!ok) errors.push(`${schemaPath}: expected type ${t} (got ${describeType(value)})`);
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${schemaPath}: shorter than minLength ${schema.minLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${schemaPath}: does not match pattern ${schema.pattern}`);
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${schemaPath}: below minimum ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${schemaPath}: above maximum ${schema.maximum}`);
    }
  }
  if (Array.isArray(value) && schema.items) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${schemaPath}: fewer than ${schema.minItems} items`);
    }
    value.forEach((item, i) => validateAgainstSchema(item, schema.items, root, `${schemaPath}[${i}]`, errors));
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const props = schema.properties || {};
    const patternProps = Object.entries(schema.patternProperties || {});
    const nameSchema = schema.propertyNames;

    if (Array.isArray(schema.required)) {
      for (const req of schema.required) {
        if (!(req in value)) errors.push(`${schemaPath}: missing required field '${req}'`);
      }
    }
    if (nameSchema) {
      for (const key of Object.keys(value)) {
        validateAgainstSchema(key, nameSchema, root, `${schemaPath} <key '${key}'>`, errors);
      }
    }
    for (const [key, v] of Object.entries(value)) {
      let covered = false;
      if (key in props) {
        validateAgainstSchema(v, props[key], root, `${schemaPath}.${key}`, errors);
        covered = true;
      }
      for (const [pattern, pSchema] of patternProps) {
        if (new RegExp(pattern).test(key)) {
          validateAgainstSchema(v, pSchema, root, `${schemaPath}.${key}`, errors);
          covered = true;
        }
      }
      if (!covered && schema.additionalProperties === false) {
        errors.push(`${schemaPath}: unexpected field '${key}'`);
      }
    }
  }
  return errors;
}

function resolveRef(root, ref) {
  if (!ref.startsWith("#/")) throw new Error(`Unsupported $ref: ${ref}`);
  let node = root;
  for (const part of ref.slice(2).split("/")) {
    node = node[part.replace(/~1/g, "/").replace(/~0/g, "~")];
    if (node === undefined) throw new Error(`Unresolvable $ref: ${ref}`);
  }
  return node;
}

function describeType(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/**
 * Recursive scan for forbidden key names (private keys are never valid fields).
 * @returns {string[]} offending key paths (empty = clean)
 */
function scanForbiddenKeys(value, prefix = "", out = []) {
  if (typeof value !== "object" || value === null) return out;
  for (const [k, v] of Object.entries(value)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (FORBIDDEN_KEY_PATTERN.test(k)) out.push(p);
    scanForbiddenKeys(v, p, out);
  }
  return out;
}

/**
 * Pure binding check — exported for tests. Rejects a manifest whose chain_id
 * or deployed code hashes do not match the observed deployment facts.
 * @param {object} manifest parsed manifest (v3)
 * @param {{chainId?: number, codeHashes?: object, contractVersion?: string}} observed
 * @returns {string[]} errors (empty = valid)
 */
function validateDeploymentBinding(manifest, observed) {
  const errors = [];
  if (manifest.manifest_version !== 3) {
    errors.push(`manifest_version must be 3 (got ${manifest.manifest_version})`);
  }
  for (const field of [
    "deployment_id",
    "institution_id",
    "chain_id",
    "addresses",
    "deployed_code_hashes",
    "deployed_at_block",
    "confirmation_depth",
    "contract_version",
    "status",
  ]) {
    if (manifest[field] === undefined || manifest[field] === null || manifest[field] === "") {
      errors.push(`missing required DeploymentBinding field: ${field}`);
    }
  }
  if (errors.length > 0) return errors; // structural errors first

  if (observed.chainId !== undefined && Number(manifest.chain_id) !== Number(observed.chainId)) {
    errors.push(`chain_id mismatch: manifest ${manifest.chain_id}, chain ${observed.chainId}`);
  }
  if (observed.chainId !== undefined && Number(observed.chainId) === 31337 && Number(manifest.confirmation_depth) !== 2) {
    errors.push(`confirmation_depth must be 2 on local chain 31337 (got ${manifest.confirmation_depth})`);
  }
  if (observed.codeHashes) {
    for (const [name, expectedHash] of Object.entries(manifest.deployed_code_hashes || {})) {
      const actual = observed.codeHashes[name];
      if (!actual) {
        errors.push(`no observed code hash for contract '${name}'`);
      } else if (String(actual).toLowerCase() !== String(expectedHash).toLowerCase()) {
        errors.push(`code hash mismatch for ${name}: manifest ${expectedHash}, chain ${actual}`);
      }
    }
  }
  if (observed.contractVersion && manifest.contract_version !== observed.contractVersion) {
    errors.push(`contract_version mismatch: manifest ${manifest.contract_version}, expected ${observed.contractVersion}`);
  }
  return errors;
}

/**
 * Loads the manifest and validates it structurally against the v3 schema.
 * Throws with a joined error report when the manifest is invalid.
 */
function loadAndValidateManifest(manifestPath) {
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`[FAIL] Deployment manifest not found at ${manifestPath}. Run scripts/deploy.js first.`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));
  const schemaErrors = validateAgainstSchema(manifest, schema);
  if (schemaErrors.length > 0) {
    throw new Error(`[FAIL] Manifest fails schema ${path.basename(SCHEMA_PATH)}:\n  - ${schemaErrors.join("\n  - ")}`);
  }
  const forbidden = scanForbiddenKeys(manifest);
  if (forbidden.length > 0) {
    throw new Error(`[FAIL] Manifest contains forbidden (secret-like) fields: ${forbidden.join(", ")}`);
  }
  return manifest;
}

async function verifyDeployment(manifestPath, rpcUrl) {
  const targetManifestPath =
    manifestPath ||
    path.join(__dirname, "..", "deployments", "deployment-manifest.json");

  const manifest = loadAndValidateManifest(targetManifestPath);

  const targetRpcUrl =
    rpcUrl ||
    process.env.RPC_URL ||
    process.env.BLOCKCHAIN_RPC_URL ||
    "http://127.0.0.1:8545";

  console.log("====================================================");
  console.log(`Verifying Deployment for: ${manifest.institution_id}`);
  console.log(`Manifest: v${manifest.manifest_version} (deployment_id ${manifest.deployment_id.slice(0, 12)}...)`);
  console.log(`Manifest Path: ${targetManifestPath}`);
  console.log(`Target RPC: ${targetRpcUrl}`);
  console.log("====================================================");

  const provider = new ethers.JsonRpcProvider(targetRpcUrl);

  // 1. REAL RPC — chain ID parity
  let network;
  try {
    network = await provider.getNetwork();
  } catch (err) {
    throw new Error(`[FAIL] RPC provider unreachable at ${targetRpcUrl}: ${err.message}`);
  }
  const bindingErrors = validateDeploymentBinding(manifest, {
    chainId: Number(network.chainId),
    contractVersion: require("../package.json").version,
  });
  if (bindingErrors.length > 0) {
    throw new Error(`[FAIL] DeploymentBinding rejected:\n  - ${bindingErrors.join("\n  - ")}`);
  }
  console.log(`[PASS] Chain ID verified: ${Number(network.chainId)} (depth ${manifest.confirmation_depth})`);

  // 2. REAL RPC — bytecode parity
  const observedCodeHashes = {};
  for (const [name, address] of Object.entries(manifest.addresses)) {
    if (!address || address === ethers.ZeroAddress) {
      throw new Error(`[FAIL] Contract ${name} has zero or undefined address`);
    }
    const code = await provider.getCode(address);
    if (!code || code === "0x") {
      throw new Error(`[FAIL] Contract ${name} at ${address} has no deployed bytecode (empty code)`);
    }
    observedCodeHashes[name] = ethers.keccak256(code);
    const expectedHash = manifest.deployed_code_hashes[name];
    if (expectedHash && observedCodeHashes[name] !== expectedHash) {
      throw new Error(
        `[FAIL] Bytecode hash mismatch for ${name} at ${address}:\n  Expected: ${expectedHash}\n  Actual:   ${observedCodeHashes[name]}`
      );
    }
    console.log(`[PASS] Bytecode verified for ${name} (${address.slice(0, 10)}...)`);
  }
  const bindingCodeErrors = validateDeploymentBinding(manifest, { codeHashes: observedCodeHashes });
  if (bindingCodeErrors.length > 0) {
    throw new Error(`[FAIL] DeploymentBinding rejected:\n  - ${bindingCodeErrors.join("\n  - ")}`);
  }

  // 3-5. REAL RPC — governance, roster, wiring
  const multiSig = new ethers.Contract(
    manifest.addresses.MultiSigApproval,
    [
      "function isBootstrapFinalized() view returns (bool)",
      "function bootstrapAuthority() view returns (address)",
      "function requiredApprovals() view returns (uint256)",
      "function PROPOSAL_TTL() view returns (uint256)",
      "function TIMELOCK_DELAY() view returns (uint256)",
    ],
    provider
  );
  const roleManager = new ethers.Contract(
    manifest.addresses.RoleManager,
    [
      "function countActiveParticipants() view returns (uint256)",
      "function countEligibleParticipants() view returns (uint256)",
      "function getRole(address) view returns (uint8)",
      "function getActiveWallet(bytes32) view returns (address)",
    ],
    provider
  );
  const auditEngine = new ethers.Contract(
    manifest.addresses.AuditEngine,
    ["function isIntegrated() view returns (bool)", "function multiSig() view returns (address)"],
    provider
  );
  const insiderLog = new ethers.Contract(
    manifest.addresses.InsiderActivityLog,
    ["function isRecorder(address) view returns (bool)"],
    provider
  );
  const forensicTrail = new ethers.Contract(
    manifest.addresses.ForensicTrail,
    ["function isEvidenceWriter(address) view returns (bool)"],
    provider
  );

  const fail = (msg) => {
    throw new Error(`[FAIL] ${msg}`);
  };

  // 3. Governance wiring, TTL, delays, finalization
  if (!(await multiSig.isBootstrapFinalized())) {
    fail("MultiSigApproval bootstrap is NOT finalized. System is vulnerable to re-configuration.");
  }
  console.log("[PASS] Bootstrap finalization verified.");
  if ((await multiSig.bootstrapAuthority()) !== ethers.ZeroAddress) {
    fail(`Bootstrap authority was not revoked (current: ${await multiSig.bootstrapAuthority()})`);
  }
  console.log("[PASS] Bootstrap authority revocation verified (address(0)).");
  if (Number(await multiSig.requiredApprovals()) !== manifest.governance.required_approvals) {
    fail(`requiredApprovals ${await multiSig.requiredApprovals()} != manifest ${manifest.governance.required_approvals}`);
  }
  const ttl = Number(await multiSig.PROPOSAL_TTL());
  if (ttl !== 259200) fail(`PROPOSAL_TTL is ${ttl}s, protocol requires 259,200s (72h)`);
  const delay = Number(await multiSig.TIMELOCK_DELAY());
  if (delay !== manifest.governance.timelock_delay_seconds) {
    fail(`TIMELOCK_DELAY is ${delay}s, manifest records ${manifest.governance.timelock_delay_seconds}s`);
  }
  console.log(`[PASS] Governance constants verified: approvals=${manifest.governance.required_approvals}, TTL=${ttl}s (72h), timelock=${delay}s.`);

  // 4. Roster
  const eligible = Number(await roleManager.countEligibleParticipants());
  if (eligible < 4) fail(`Insufficient eligible voters: expected >= 4, found ${eligible}`);
  const active = Number(await roleManager.countActiveParticipants());
  if (active < 4) fail(`Insufficient active participants: expected >= 4, found ${active}`);
  if (active !== manifest.governance.active_participants) {
    fail(`Active participants ${active} != manifest ${manifest.governance.active_participants}`);
  }
  for (const p of manifest.participants) {
    const activeWallet = await roleManager.getActiveWallet(p.participant_id);
    if (activeWallet.toLowerCase() !== p.account.toLowerCase()) {
      fail(`Participant ${p.participant_id} no longer bound to recorded wallet (active: ${activeWallet})`);
    }
    const role = Number(await roleManager.getRole(activeWallet));
    if (role !== p.role) fail(`Participant ${p.participant_id} role drifted: chain ${role}, manifest ${p.role}`);
  }
  console.log(`[PASS] Roster verified: ${eligible} eligible voters, ${active} active participants, all ids bound and roles intact.`);

  // 5. Writer/recorder integration
  if (!(await auditEngine.isIntegrated())) {
    fail("AuditEngine is not integrated with peripheral security contracts.");
  }
  if ((await auditEngine.multiSig()).toLowerCase() !== manifest.addresses.MultiSigApproval.toLowerCase()) {
    fail(`AuditEngine MultiSig reference mismatch: ${await auditEngine.multiSig()}`);
  }
  if (!(await insiderLog.isRecorder(manifest.addresses.AuditEngine))) {
    fail("AuditEngine is not an authorized recorder on InsiderActivityLog.");
  }
  if (!(await forensicTrail.isEvidenceWriter(manifest.addresses.AuditEngine))) {
    fail("AuditEngine is not an authorized evidence writer on ForensicTrail.");
  }
  console.log("[PASS] AuditEngine integration, InsiderActivityLog recorder and ForensicTrail writer verified.");

  // Block sanity: manifest must not claim a future block
  const currentBlock = await provider.getBlockNumber();
  if (manifest.deployed_at_block > currentBlock) {
    fail(`deployed_at_block ${manifest.deployed_at_block} is ahead of chain head ${currentBlock}`);
  }
  console.log(`[PASS] deployed_at_block ${manifest.deployed_at_block} <= chain head ${currentBlock}.`);

  console.log("====================================================");
  console.log("[SUCCESS] ALL DEPLOYMENT VERIFICATION CHECKS PASSED!");
  console.log("====================================================");
  return true;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const manifestPath = args[0] || null;
  const rpcUrl = args[1] || null;

  verifyDeployment(manifestPath, rpcUrl)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}

module.exports = {
  verifyDeployment,
  loadAndValidateManifest,
  validateAgainstSchema,
  validateDeploymentBinding,
  scanForbiddenKeys,
  FORBIDDEN_KEY_PATTERN,
  SCHEMA_PATH,
};
