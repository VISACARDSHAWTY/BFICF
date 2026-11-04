const env = process.env;

module.exports = {
  network: "besu",
  rpcUrl: env.RPC_URL || "http://127.0.0.1:8549",
  gasPrice: "0",

  roles: {
    secauth: { keyEnv: "SECAUTH_KEY", localIndex: 0 },
    oem: { keyEnv: "OEM_KEY", localIndex: 1 },
    cloud: { keyEnv: "CLOUD_KEY", localIndex: 2 },
    edge: { keyEnv: "EDGE_KEY", localIndex: 3 },
    user: { keyEnv: "USER_KEY", localIndex: 4 },
    correlator: { keyEnv: "SECAUTH_KEY", localIndex: 0 },
    recoveryVerifier: { keyEnv: "SECAUTH_KEY", localIndex: 0 }
  },

  domains: [
    { role: "oem", name: "OEM", type: 0, validator: true },
    { role: "cloud", name: "Cloud", type: 1, validator: true },
    { role: "edge", name: "Edge", type: 2, validator: true },
    { role: "user", name: "User", type: 3, validator: true },
    { role: "secauth", name: "SECAUTH", type: 4, validator: true }
  ],

  governance: {
    quarantineBps: 6000,
    revokeBps: 6000,
    patchBps: 5000,
    quorumBps: 5000,
    correlationQuorumBps: 5000,
    commitWindowSec: Number(env.COMMIT_WINDOW || 60),
    revealWindowSec: Number(env.REVEAL_WINDOW || 60)
  },

  minimumConfidenceClass: 1,
  executionWindowSec: 3600,
  requiredAttestations: 1,
  requiredRecoveryApprovals: 1,
  recoveryValidationWindowSec: 3600
};