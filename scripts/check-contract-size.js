/**
 * @title Contract Size Gate (R04 / F08)
 * @notice Reads deployedBytecode (runtime bytecode) from freshly compiled Hardhat
 *         artifacts for every PRODUCTION contract and enforces the EIP-170-derived
 *         budget: runtime bytecode must be <= 24,000 bytes (network hard limit is
 *         24,576; the protocol keeps a 576-byte safety margin).
 *
 * Invariants enforced here:
 *   1. Artifacts must be FRESH — an artifact older than its Solidity source is a
 *      hard failure (run `npm run compile` first); sizes are never reported from
 *      stale builds.
 *   2. Unlinked placeholders are rejected — a runtime payload containing
 *      `__$<hash>$__` link placeholders (or a non-empty deployedLinkReferences)
 *      cannot be measured and therefore fails the gate.
 *   3. Constructor/init bytecode is NOT counted — the gate measures
 *      `deployedBytecode` only, which by definition excludes creation code.
 *
 * Output: one JSON line per contract
 *   {contract, compiler, optimizer_runs, runtime_bytes, budget, passed}
 * followed by a summary object. Exit code 1 when any production contract fails.
 */

const fs = require("fs");
const path = require("path");

const ROOT_DIR = path.join(__dirname, "..");
const ARTIFACTS_DIR = path.join(ROOT_DIR, "artifacts", "contracts");

// Spec R04: deployed runtime bytecode budget (network limit is 24,576).
const NETWORK_LIMIT_BYTES = 24576;
const SIZE_BUDGET_BYTES = 24000;

/**
 * Production contracts measured by the gate. Test-only contracts
 * (contracts/test/**) and interfaces (empty runtime bytecode) are excluded.
 * Paths are relative to artifacts/contracts/.
 */
const PRODUCTION_CONTRACTS = [
  "access/MultiSigApproval.sol/MultiSigApproval.json",
  "access/RoleManager.sol/RoleManager.json",
  "forensics/ForensicTrail.sol/ForensicTrail.json",
  "forensics/InsiderActivityLog.sol/InsiderActivityLog.json",
  "libraries/EvidenceHashing.sol/EvidenceHashing.json",
  "AuditEngine.sol/AuditEngine.json",
  "ComplianceRules.sol/ComplianceRules.json",
];

const UNLINKED_PLACEHOLDER = /\_\$[0-9a-fA-F]{34}\$\_/;

/**
 * Pure gate logic — exported for tests. Size threshold boundary:
 * accepts exactly 24,000, rejects 24,001 and 24,577 (and everything above).
 * @param {number} runtimeBytes measured deployed (runtime) bytecode size
 * @param {number} budget maximum allowed runtime bytes
 * @returns {{passed: boolean, reason: string|null}}
 */
function evaluateSizeGate(runtimeBytes, budget = SIZE_BUDGET_BYTES) {
  if (!Number.isInteger(runtimeBytes) || runtimeBytes < 0) {
    return { passed: false, reason: `invalid runtime_bytes: ${runtimeBytes}` };
  }
  if (runtimeBytes > NETWORK_LIMIT_BYTES) {
    return {
      passed: false,
      reason: `runtime_bytes ${runtimeBytes} exceeds even the ${NETWORK_LIMIT_BYTES}-byte network limit`,
    };
  }
  if (runtimeBytes > budget) {
    return {
      passed: false,
      reason: `runtime_bytes ${runtimeBytes} exceeds the ${budget}-byte protocol budget`,
    };
  }
  return { passed: true, reason: null };
}

/**
 * Pure helper — rejects unlinked placeholder payloads. Exported for tests.
 * @param {string} deployedBytecode hex string (0x...)
 * @param {object} artifact full artifact JSON
 * @returns {{ok: boolean, reason: string|null}}
 */
function checkLinkage(deployedBytecode, artifact) {
  if (UNLINKED_PLACEHOLDER.test(deployedBytecode)) {
    return { ok: false, reason: "runtime bytecode contains unlinked __$...$__ placeholders" };
  }
  const linkRefs = artifact && artifact.deployedLinkReferences;
  if (linkRefs && Object.keys(linkRefs).length > 0) {
    return { ok: false, reason: "artifact declares non-empty deployedLinkReferences (unlinked library)" };
  }
  return { ok: true, reason: null };
}

/**
 * Byte length of a 0x-prefixed hex string (creation OR runtime payload).
 */
function hexByteLength(hex) {
  if (typeof hex !== "string" || !hex.startsWith("0x")) return -1;
  return (hex.length - 2) / 2;
}

/**
 * Compiler identity shared by every artifact of the single Hardhat compile
 * config (artifacts themselves do not embed compiler info). Parsed from
 * hardhat.config.js so the JSON report reflects the real build settings.
 */
function readCompilerSettings() {
  try {
    const configText = fs.readFileSync(path.join(ROOT_DIR, "hardhat.config.js"), "utf-8");
    const versionMatch = configText.match(/version\s*:\s*"([^"]+)"/);
    const runsMatch = configText.match(/runs\s*:\s*(\d+)/);
    const enabledMatch = configText.match(/enabled\s*:\s*(true|false)/);
    const runs = runsMatch ? Number(runsMatch[1]) : null;
    const enabled = enabledMatch ? enabledMatch[1] === "true" : null;
    return {
      compiler: versionMatch ? `solc-${versionMatch[1]}` : "unknown",
      optimizer_runs: enabled === false ? 0 : runs,
    };
  } catch {
    return { compiler: "unknown", optimizer_runs: null };
  }
}

/**
 * Fails when the artifact is older than its Solidity source (stale build).
 */
function assertArtifactFresh(artifactPath) {
  const sourceRel = path.relative(ARTIFACTS_DIR, artifactPath).split(path.sep).slice(0, -1).join(path.sep);
  const sourcePath = path.join(ROOT_DIR, "contracts", sourceRel);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`source missing for artifact: ${artifactPath}`);
  }
  const artifactMtime = fs.statSync(artifactPath).mtimeMs;
  const sourceMtime = fs.statSync(sourcePath).mtimeMs;
  if (artifactMtime < sourceMtime) {
    throw new Error(
      `stale artifact ${path.relative(ROOT_DIR, artifactPath)} is older than ` +
        `${path.relative(ROOT_DIR, sourcePath)} — run \`npm run compile\` for a fresh build`
    );
  }
}

/**
 * Measures one production contract from its artifact.
 * @returns {{contract, compiler, optimizer_runs, runtime_bytes, budget, passed, error}}
 */
function measureContract(artifactPath, budget = SIZE_BUDGET_BYTES) {
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
  assertArtifactFresh(artifactPath);

  const runtimeBytes = hexByteLength(artifact.deployedBytecode);
  const linkage = checkLinkage(artifact.deployedBytecode, artifact);

  const { compiler, optimizer_runs: optimizerRuns } = readCompilerSettings();

  let passed = false;
  let error = null;
  if (runtimeBytes < 0) {
    error = "artifact has no parsable deployedBytecode";
  } else if (!linkage.ok) {
    error = linkage.reason;
  } else {
    const gate = evaluateSizeGate(runtimeBytes, budget);
    passed = gate.passed;
    error = gate.reason;
  }

  return {
    contract: artifact.contractName || path.basename(artifactPath, ".json"),
    compiler,
    optimizer_runs: optimizerRuns,
    runtime_bytes: runtimeBytes,
    budget,
    passed,
    ...(error ? { error } : {}),
  };
}

/**
 * Runs the gate over all production contracts. Throws on stale artifacts.
 * @returns {{results: Array, allPassed: boolean}}
 */
function runSizeGate(budget = SIZE_BUDGET_BYTES) {
  const results = PRODUCTION_CONTRACTS.map((rel) => {
    const artifactPath = path.join(ARTIFACTS_DIR, ...rel.split("/"));
    if (!fs.existsSync(artifactPath)) {
      return {
        contract: path.basename(rel, ".json"),
        compiler: null,
        optimizer_runs: null,
        runtime_bytes: null,
        budget,
        passed: false,
        error: `artifact missing: ${rel} (compile first)`,
      };
    }
    return measureContract(artifactPath, budget);
  });
  return { results, allPassed: results.every((r) => r.passed) };
}

function main() {
  console.log("====================================================");
  console.log("Contract Size Gate (R04/F08)");
  console.log(`Budget: ${SIZE_BUDGET_BYTES} bytes runtime (network limit ${NETWORK_LIMIT_BYTES})`);
  console.log("====================================================");

  const { results, allPassed } = runSizeGate();
  for (const r of results) {
    console.log(JSON.stringify(r));
  }

  const summary = {
    gate: "deployed_runtime_bytecode",
    budget: SIZE_BUDGET_BYTES,
    network_limit: NETWORK_LIMIT_BYTES,
    contracts_checked: results.length,
    all_passed: allPassed,
    largest_runtime_bytes: results.reduce(
      (max, r) => (typeof r.runtime_bytes === "number" ? Math.max(max, r.runtime_bytes) : max),
      0
    ),
  };
  console.log(JSON.stringify(summary));

  if (!allPassed) {
    console.error("[FAIL] Contract size gate FAILED — see entries with passed=false above.");
    process.exit(1);
  }
  console.log("[SUCCESS] All production contracts within the 24,000-byte runtime budget.");
}

if (require.main === module) {
  main();
}

module.exports = {
  SIZE_BUDGET_BYTES,
  NETWORK_LIMIT_BYTES,
  PRODUCTION_CONTRACTS,
  evaluateSizeGate,
  checkLinkage,
  hexByteLength,
  readCompilerSettings,
  measureContract,
  runSizeGate,
};
