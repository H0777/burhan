#!/usr/bin/env node
/**
 * Cross-platform Python Runner Helper
 * Discovers Python executable in environment or local Hermes installation.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');

function findPython() {
  if (process.env.PYTHON && fs.existsSync(process.env.PYTHON)) {
    return process.env.PYTHON;
  }
  const knownWindowsPaths = [
    'C:\\Users\\hussa\\AppData\\Local\\hermes\\tools\\python-3.14.7+20260901-win32-x64\\python.exe',
  ];
  for (const p of knownWindowsPaths) {
    if (fs.existsSync(p)) return p;
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

const pythonBin = findPython();
const args = process.argv.slice(2);
const result = spawnSync(pythonBin, args, { stdio: 'inherit' });

if (result.error) {
  console.error('[run-python] Failed to execute Python:', result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 0);
