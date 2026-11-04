// Deploys and wires the whole system, registers domains, applies governance parameters,
// verifies the wiring, and writes deployments/<network>.json (+ ABIs) for the gateway.
//
//   node scripts/compile.js && node scripts/deploy.js
const { ethers } = require('ethers');
const fs = require('fs'), path = require('path');
const cfg = require('./deploy.config.cjs');

const root = path.join(__dirname, '..');
const artifact = n => JSON.parse(fs.readFileSync(path.join(root, 'build', n + '.json'), 'utf8'));

(async () => {
  const provider = new ethers.JsonRpcProvider(cfg.rpcUrl);
  const chainId = (await provider.getNetwork()).chainId;
  console.log(`Network "${cfg.network}" @ ${cfg.rpcUrl} (chainId ${chainId})`);

  // ---- resolve role signers ----
  const signers = {}, addr = {};
  for (const [role, r] of Object.entries(cfg.roles)) {
    const key = process.env[r.keyEnv];
    signers[role] = key ? new ethers.Wallet(key, provider) : await provider.getSigner(r.localIndex);
    addr[role] = await signers[role].getAddress();
    console.log(`  ${role.padEnd(17)} ${addr[role]}  ${key ? '(key from ' + r.keyEnv + ')' : '(local node account)'}`);
  }
  const sa = signers.secauth; // deployer == Security Authority

  const overrides = cfg.gasPrice !== undefined ? { gasPrice: BigInt(cfg.gasPrice) } : {};
  const gas = {}; let totalGas = 0n;
  const track = (label, receipt) => { gas[label] = receipt.gasUsed.toString(); totalGas += receipt.gasUsed; };

  const contracts = {};
  async function deploy(name, args) {
    const a = artifact(name);
    const c = await new ethers.ContractFactory(a.abi, a.bytecode, sa).deploy(...args, overrides);
    const receipt = await (await c.deploymentTransaction()).wait();
    await c.waitForDeployment();
    contracts[name] = c;
    track('deploy:' + name, receipt);
    console.log(`  deployed ${name.padEnd(22)} ${await c.getAddress()}  gas ${receipt.gasUsed}`);
    return c;
  }
  async function call(label, contract, fn, args = []) {
    const receipt = await (await contract[fn](...args, overrides)).wait();
    track(label, receipt);
  }
  const A = c => c.getAddress();

  // ---- 1. deploy (order matters only for constructor arguments) ----
  console.log('\n[1/5] Deploying contracts');
  const dr   = await deploy('DomainRegistry',        [addr.secauth]);
  const gp   = await deploy('GovernanceParams',      [await A(dr)]);
  const inc  = await deploy('IncidentRegistry',      [await A(dr)]);
  const ev   = await deploy('EvidenceCommitment',    [await A(dr), await A(inc)]);
  const cor  = await deploy('CorrelationDecision',   [await A(dr), await A(inc), await A(gp)]);
  const prop = await deploy('ResponseProposal',      [await A(dr), await A(inc), await A(cor), await A(ev), cfg.minimumConfidenceClass]);
  const vot  = await deploy('FederatedVoting',       [await A(dr), await A(prop), await A(gp), await A(inc)]);
  const dec  = await deploy('ResponseDecision',      [await A(vot), await A(prop), await A(inc)]);
  const exe  = await deploy('ResponseExecution',     [await A(dr), await A(dec), await A(prop), await A(inc), cfg.executionWindowSec]);
  const ver  = await deploy('ExecutionVerification', [await A(dr), await A(exe), await A(inc), cfg.requiredAttestations]);
  const dev  = await deploy('DeviceRegistry',        [await A(dr)]);
  const rec  = await deploy('DeviceRecovery',        [await A(dr), await A(dev), addr.recoveryVerifier, cfg.requiredRecoveryApprovals, cfg.recoveryValidationWindowSec]);

  // ---- 2. write-once wiring ----
  console.log('\n[2/5] Wiring (write-once setters)');
  await call('wire:incident.workflow',   inc,  'setWorkflowContracts',   [await A(cor), await A(prop)]);
  await call('wire:incident.governance', inc,  'setGovernanceContracts', [await A(vot), await A(dec)]);
  await call('wire:incident.execution',  inc,  'setExecutionContracts',  [await A(exe), await A(ver)]);
  await call('wire:proposal.decision',   prop, 'setResponseDecision',    [await A(dec)]);
  await call('wire:proposal.voting',     prop, 'setVotingContract',      [await A(vot)]);
  await call('wire:voting.decision',     vot,  'setResponseDecision',    [await A(dec)]);
  await call('wire:execution.verifier',  exe,  'setVerificationContract',[await A(ver)]);
  await call('wire:device.recovery',     dev,  'setRecoveryContract',    [await A(rec)]);
  await call('wire:device.governance',   dev,  'setGovernanceContracts', [await A(dec), await A(prop)]);
  console.log('  done');

  // ---- 3. domains, correlator ----
  console.log('\n[3/5] Registering domains');
  for (const d of cfg.domains) {
    // The registry stores a public key as bytes; replace with the domain's real signing key when available.
    const pubKey = ethers.hexlify(ethers.toUtf8Bytes('pubkey:' + d.name));
    await call('domain:' + d.name, dr, 'registerDomain', [addr[d.role], d.name, d.type, d.validator, pubKey]);
    console.log(`  ${d.name.padEnd(6)} ${addr[d.role]}`);
  }
  await call('setCorrelator', dr, 'setCorrelator', [addr.correlator, true]);
  console.log(`  correlator ${addr.correlator}`);

  // ---- 4. governance parameters ----
  console.log('\n[4/5] Governance parameters');
  const g = cfg.governance;
  await call('gov:thresholds', gp, 'updateThresholds', [g.quarantineBps, g.revokeBps, g.patchBps, g.quorumBps]);
  await call('gov:windows',    gp, 'updateWindows',    [g.commitWindowSec, g.revealWindowSec]);
  await call('gov:corrQuorum', gp, 'updateCorrelationQuorum', [g.correlationQuorumBps]);
  console.log(`  thresholds q/r/p/quorum = ${g.quarantineBps}/${g.revokeBps}/${g.patchBps}/${g.quorumBps} bps; windows ${g.commitWindowSec}s + ${g.revealWindowSec}s`);

  // ---- 5. verify wiring by reading it back ----
  console.log('\n[5/5] Verifying wiring');
  const checks = [
    ['incident.correlationDecision', await inc.correlationDecision(), await A(cor)],
    ['incident.responseProposal',    await inc.responseProposal(),    await A(prop)],
    ['incident.federatedVoting',     await inc.federatedVoting(),     await A(vot)],
    ['incident.responseDecision',    await inc.responseDecision(),    await A(dec)],
    ['incident.execution',           await inc.coordinatedResponseExecution(), await A(exe)],
    ['incident.verification',        await inc.executionVerification(),        await A(ver)],
    ['proposal.responseDecision',    await prop.responseDecision(),   await A(dec)],
    ['proposal.votingContract',      await prop.votingContract(),     await A(vot)],
    ['voting.responseDecision',      await vot.responseDecision(),    await A(dec)],
    ['execution.verificationContract', await exe.verificationContract(), await A(ver)],
    ['device.recoveryContract',      await dev.recoveryContract(),    await A(rec)],
    ['device.responseDecision',      await dev.responseDecision(),    await A(dec)],
    ['device.responseProposal',      await dev.responseProposal(),    await A(prop)]
  ];
  let bad = 0;
  for (const [n, got, want] of checks) if (got !== want) { bad++; console.log(`  ✗ ${n}: ${got} != ${want}`); }
  for (const d of cfg.domains) if (!(await dr.isActiveDomain(addr[d.role]))) { bad++; console.log(`  ✗ domain ${d.name} not active`); }
  if (!(await dr.isCorrelator(addr.correlator))) { bad++; console.log('  ✗ correlator role missing'); }
  if (!(await dr.isSecurityAuthority(addr.secauth))) { bad++; console.log('  ✗ secauth role missing'); }
  if (bad) { console.error(`\n${bad} wiring check(s) FAILED - do not use this deployment.`); process.exit(1); }
  console.log(`  ${checks.length + cfg.domains.length + 2} checks OK`);

  // ---- write deployment record + ABIs for the gateway ----
  const outDir = path.join(root, 'deployments');
  fs.mkdirSync(path.join(outDir, 'abi'), { recursive: true });
  const record = {
    network: cfg.network, chainId: chainId.toString(), rpcUrl: cfg.rpcUrl,
    deployedAt: new Date().toISOString(),
    accounts: addr,
    contracts: Object.fromEntries(await Promise.all(Object.entries(contracts).map(async ([n, c]) => [n, await c.getAddress()]))),
    governance: cfg.governance,
    gasUsed: { total: totalGas.toString(), perStep: gas }
  };
  for (const n of Object.keys(contracts)) fs.writeFileSync(path.join(outDir, 'abi', n + '.json'), JSON.stringify(artifact(n).abi, null, 2));
  fs.writeFileSync(path.join(outDir, cfg.network + '.json'), JSON.stringify(record, null, 2));
  console.log(`\nWrote deployments/${cfg.network}.json and deployments/abi/*.json  (total setup gas ${totalGas})`);
})().catch(e => { console.error(e); process.exit(1); });
