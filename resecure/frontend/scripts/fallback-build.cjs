/**
 * ReSecure Frontend Build Script
 * Handles both Vite bundle execution and standalone production distribution packaging.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const distDir = path.resolve(rootDir, 'dist');

console.log('--- ReSecure Cybersecurity Frontend Build Process ---');
console.log('Target Directory:', distDir);

// 1. Ensure dist directory exists
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// 2. Check if Vite and TypeScript are installed in node_modules
const viteBin = path.resolve(rootDir, 'node_modules', '.bin', process.platform === 'win32' ? 'vite.cmd' : 'vite');
const tscBin = path.resolve(rootDir, 'node_modules', '.bin', process.platform === 'win32' ? 'tsc.cmd' : 'tsc');

let built = false;
if (fs.existsSync(tscBin) && fs.existsSync(viteBin)) {
  try {
    console.log('Running TypeScript type checking (tsc --noEmit)...');
    execSync(`"${tscBin}" --noEmit`, { cwd: rootDir, stdio: 'inherit' });
    console.log('✓ TypeScript typecheck passed with 0 errors.');

    console.log('Running Vite production build...');
    execSync(`"${viteBin}" build`, { cwd: rootDir, stdio: 'inherit' });
    console.log('✓ Vite build completed successfully.');
    built = true;
  } catch (err) {
    console.error('Build step encountered an error:', err.message);
    process.exit(1);
  }
} else {
  console.error('Missing tsc or vite binaries in node_modules.');
  process.exit(1);
}

console.log('✓ Build verification completed successfully with 0 errors.');
process.exit(0);
