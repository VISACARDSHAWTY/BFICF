// All deployment settings in one place. Override with environment variables.
//
// LOCAL (hardhat node):   no keys needed - signers are taken from the node's accounts.
// REAL NETWORK (Besu...): set RPC_URL, NETWORK and one private key per role (see `keyEnv`).
//                         The SECAUTH key is the deployer AND the Security Authority.
const env = process.env;

module.exports = {
  network: env.NETWORK || 'local',
  rpcUrl: env.RPC_URL || 'http://127.0.0.1:8545',
  // Free-gas permissioned chains (Besu/QBFT): GAS_PRICE=0. Leave unset to let the node decide.
  gasPrice: env.GAS_PRICE,

  // role -> env var holding the private key, and the local-node account index used when no key is set
  roles: {
    secauth:          { keyEnv: 'SECAUTH_KEY',  localIndex: 0 },
    oem:              { keyEnv: 'OEM_KEY',      localIndex: 1 },
    cloud:            { keyEnv: 'CLOUD_KEY',    localIndex: 2 },
    edge:             { keyEnv: 'EDGE_KEY',     localIndex: 3 },
    user:             { keyEnv: 'USER_KEY',     localIndex: 4 },
    correlator:       { keyEnv: 'CORRELATOR_KEY', localIndex: 5 },   // federated-correlation service
    recoveryVerifier: { keyEnv: 'RECOVERY_VERIFIER_KEY', localIndex: 6 }
  },

  // DomainType: 0 OEM, 1 CLOUD, 2 EDGE, 3 USER.  Public key = domain's signing key (stored as bytes).
  domains: [
    { role: 'oem',   name: 'OEM',   type: 0, validator: true },
    { role: 'cloud', name: 'Cloud', type: 1, validator: true },
    { role: 'edge',  name: 'Edge',  type: 2, validator: true },
    { role: 'user',  name: 'User',  type: 3, validator: true }
  ],

  governance: {
    quarantineBps: 6000, revokeBps: 6000, patchBps: 5000, quorumBps: 5000,
    correlationQuorumBps: 5000,
    // Contract default is 1 day + 1 day. Testbed profile keeps experiments short.
    commitWindowSec: Number(env.COMMIT_WINDOW || 60),
    revealWindowSec: Number(env.REVEAL_WINDOW || 60)
  },

  minimumConfidenceClass: 1,        // 0 LOW, 1 MEDIUM, 2 HIGH, 3 VERY_HIGH
  executionWindowSec: 3600,         // time to execute + verify a plan before it can be escalated
  requiredAttestations: 1,          // peer attestations per execution receipt
  requiredRecoveryApprovals: 1,     // peer approvals for a device-recovery request
  recoveryValidationWindowSec: 3600
};
