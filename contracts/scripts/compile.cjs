// Compiles ./contracts with solc-js and writes ABI + bytecode to ./build/<Contract>.json
// Run from anywhere:  node scripts/compile.js
const solc = require('solc'), fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const dir = path.join(root, 'contracts');
const sources = {};
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.sol')))
  sources[f] = { content: fs.readFileSync(path.join(dir, f), 'utf8') };

const input = {
  language: 'Solidity', sources,
  settings: {
    evmVersion: "paris",
    optimizer: { enabled: true, runs: 200 },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']
      }
    }
  }
};
const findImport = p => {
  for (const base of [path.join(root, 'node_modules'), dir]) {
    try { return { contents: fs.readFileSync(path.join(base, p), 'utf8') }; } catch (e) {}
  }
  return { error: 'File not found: ' + p };
};
const out = JSON.parse(solc.compile(JSON.stringify(input), { import: findImport }));
let errors = 0;
(out.errors || []).forEach(e => { if (e.severity === 'error') errors++; console.log(e.severity.toUpperCase(), e.formattedMessage); });
if (errors) process.exit(1);

const buildDir = path.join(root, 'build');
fs.mkdirSync(buildDir, { recursive: true });
for (const f in out.contracts) {
  if (!sources[f]) continue; // skip OpenZeppelin
  for (const c in out.contracts[f]) {
    const o = out.contracts[f][c];
    if (!o.evm.bytecode.object) continue; // interfaces
    fs.writeFileSync(path.join(buildDir, c + '.json'), JSON.stringify({ abi: o.abi, bytecode: '0x' + o.evm.bytecode.object }));
    console.log(c.padEnd(24), (o.evm.deployedBytecode.object.length / 2) + ' bytes');
  }
}
console.log('solc', solc.version(), '→ build/');
