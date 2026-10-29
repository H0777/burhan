#!/usr/bin/env node
/**
 * Cross-Platform Integration Test Runner (T12)
 *
 * Orchestrates:
 * 1. Hardhat local EVM node (port 8545)
 * 2. Contract deployment & phased bootstrap (scripts/deploy.js)
 * 3. Python FastAPI Engine (port 8000)
 * 4. Playwright E2E Trust Flow test execution (tests/e2e/trust-flow.spec.js)
 * 5. Automatic cleanup on exit
 */

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..');
const RPC_PORT = process.env.RPC_PORT || 8545;
const API_PORT = process.env.API_PORT || 8000;

let hardhatProcess = null;
let apiProcess = null;

function checkHttp(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 400);
    }).on('error', () => {
      resolve(false);
    });
  });
}

function checkRpc(port) {
  return new Promise((resolve) => {
    const postData = JSON.stringify({ jsonrpc: '2.0', method: 'eth_chainId', params: [], id: 1 });
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: port,
        path: '/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      },
      (res) => {
        resolve(res.statusCode === 200);
      }
    );
    req.on('error', () => resolve(false));
    req.write(postData);
    req.end();
  });
}

async function waitFor(fn, maxRetries = 30, intervalMs = 1000) {
  for (let i = 0; i < maxRetries; i++) {
    const ok = await fn();
    if (ok) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function cleanup() {
  console.log('\n[Integration Runner] Cleaning up processes...');
  if (hardhatProcess) {
    try {
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/pid', hardhatProcess.pid.toString(), '/f', '/t']);
      } else {
        hardhatProcess.kill('SIGTERM');
      }
    } catch {}
  }
  if (apiProcess) {
    try {
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/pid', apiProcess.pid.toString(), '/f', '/t']);
      } else {
        apiProcess.kill('SIGTERM');
      }
    } catch {}
  }
}

process.on('SIGINT', () => { cleanup(); process.exit(1); });
process.on('SIGTERM', () => { cleanup(); process.exit(1); });

async function main() {
  console.log('====================================================');
  console.log('Starting G1 Trust Flow End-to-End Integration Runner');
  console.log('====================================================');

  // Ensure clean test database for reproducible integration run
  const testDbPath = path.join(ROOT_DIR, 'test-results', 'integration.db');
  if (fs.existsSync(testDbPath)) {
    try {
      fs.unlinkSync(testDbPath);
    } catch {}
  }
  // SQLite cannot create parent directories itself; on a fresh CI runner
  // test-results/ does not exist and the engine's DB open fails with
  // "unable to open database file" (Linux), leaving /health/ready at 503.
  fs.mkdirSync(path.dirname(testDbPath), { recursive: true });

  // 1. Check or start Hardhat Node
  const rpcRunning = await checkRpc(RPC_PORT);
  if (!rpcRunning) {
    console.log(`[1/4] Spawning Hardhat Node on port ${RPC_PORT}...`);
    const npxCmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    hardhatProcess = spawn(npxCmd, ['hardhat', 'node', '--port', RPC_PORT.toString()], {
      cwd: ROOT_DIR,
      stdio: 'pipe',
      shell: process.platform === 'win32',
    });
    hardhatProcess.on('error', (err) => console.error('[Hardhat error]:', err.message));

    const ready = await waitFor(() => checkRpc(RPC_PORT), 30, 1000);
    if (!ready) {
      console.error('[ERROR] Hardhat node failed to become ready in 30s');
      cleanup();
      process.exit(1);
    }
    console.log('      -> Hardhat Node is ready and accepting JSON-RPC.');
  } else {
    console.log(`[1/4] Hardhat Node is already running on port ${RPC_PORT}.`);
  }

  // 2. Deploy contracts to local node
  console.log('[2/4] Deploying and bootstrapping contracts to localhost...');
  const npxCmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const deployResult = spawnSync(npxCmd, ['hardhat', 'run', 'scripts/deploy.js', '--network', 'localhost'], {
    cwd: ROOT_DIR,
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: { ...process.env, INSTITUTION_ID: 'INST-CENTRAL-DEMO' },
  });
  if (deployResult.status !== 0) {
    console.error('[ERROR] Contract deployment failed!');
    cleanup();
    process.exit(deployResult.status || 1);
  }
  console.log('      -> Contracts deployed and bootstrapped successfully.');

  // 3. Check or start Python FastAPI AI Engine
  const apiRunning = await checkHttp(`http://127.0.0.1:${API_PORT}/api/v2/health/ready`);
  if (!apiRunning) {
    console.log(`[3/4] Spawning Python FastAPI Engine on port ${API_PORT}...`);
    const pythonRunner = path.join(ROOT_DIR, 'scripts', 'run-python.js');
    let apiLogs = '';
    apiProcess = spawn(
      process.execPath,
      [
        pythonRunner,
        '-m',
        'uvicorn',
        'app.main:app',
        '--port',
        API_PORT.toString(),
        '--app-dir',
        'ai-engine',
      ],
      {
        cwd: ROOT_DIR,
        stdio: 'pipe',
        env: {
          ...process.env,
          PYTHONPATH: path.join(ROOT_DIR, 'ai-engine'),
          INSTITUTION_ID: 'INST-CENTRAL-DEMO',
          BLOCKCHAIN_RPC_URL: `http://127.0.0.1:${RPC_PORT}`,
          DATABASE_URL: process.env.DATABASE_URL || `sqlite:///${path.join(ROOT_DIR, 'test-results', 'integration.db').replace(/\\/g, '/')}`,
          PYTHONIOENCODING: 'utf-8',
          PYTHONUTF8: '1',
        },
      }
    );
    apiProcess.stdout.on('data', (d) => { apiLogs += d.toString(); });
    apiProcess.stderr.on('data', (d) => { apiLogs += d.toString(); });
    apiProcess.on('error', (err) => console.error('[FastAPI error]:', err.message));

    const apiReady = await waitFor(() => checkHttp(`http://127.0.0.1:${API_PORT}/api/v2/health/ready`), 30, 1000);
    if (!apiReady) {
      console.error('[ERROR] FastAPI server failed to become ready in 30s. Logs:\n', apiLogs);
      cleanup();
      process.exit(1);
    }
    console.log('      -> FastAPI Engine V2 is ready.');
  } else {
    console.log(`[3/4] FastAPI Engine is already running on port ${API_PORT}.`);
  }

  // 4. Run Playwright Tests
  console.log('[4/4] Executing Playwright E2E Trust Flow test suite...');
  const testArgs = ['playwright', 'test', 'tests/e2e/trust-flow.spec.js', ...process.argv.slice(2)];
  const testResult = spawnSync(npxCmd, testArgs, {
    cwd: ROOT_DIR,
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: {
      ...process.env,
      API_BASE_URL: `http://127.0.0.1:${API_PORT}`,
      BLOCKCHAIN_RPC_URL: `http://127.0.0.1:${RPC_PORT}`,
    },
  });

  cleanup();
  console.log('====================================================');
  console.log(`Integration Test Result: ${testResult.status === 0 ? 'PASSED (0)' : 'FAILED (' + testResult.status + ')'}`);
  console.log('====================================================');
  process.exit(testResult.status ?? 0);
}

main().catch((err) => {
  console.error('[FATAL]:', err);
  cleanup();
  process.exit(1);
});
