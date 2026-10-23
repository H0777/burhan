/**
 * Load Testing Runner Script (T22)
 * Cyber-Forensic Auditing Framework - Specification §7, §8 & Requirement R16
 *
 * Spawns the python load scenarios testbed and parses latency distributions (p50, p95, p99).
 */

const { spawn } = require('child_process');
const path = require('path');

function runLoadTest() {
  const runnerPath = path.join(__dirname, '..', '..', 'scripts', 'run-python.js');
  const scenariosPy = path.join(__dirname, 'scenarios.py');

  console.log(`[LoadRunner] Spawning load test scenarios from: ${scenariosPy}`);
  const proc = spawn(process.execPath, [runnerPath, scenariosPy], {
    cwd: path.join(__dirname, '..', '..', 'ai-engine'),
    stdio: 'inherit',
  });

  proc.on('close', (code) => {
    if (code !== 0) {
      console.error(`[LoadRunner] Benchmark failed with exit code ${code}`);
      process.exit(code);
    }
    console.log('[LoadRunner] Benchmark completed successfully with code 0.');
  });
}

runLoadTest();
