
import { network } from "hardhat";

async function main() {
  const { ethers } = await network.getOrCreate("local");

  console.log("🔍 Starting deployment to local Besu network...");

  const [deployer] = await ethers.getSigners();

  console.log("Deploying with account:", deployer.address);
  console.log(
    "Account balance:",
    await ethers.provider.getBalance(deployer.address)
  );

  // Deploy DomainRegistry
  const DomainRegistry = await ethers.deployContract("DomainRegistry", [
    deployer.address,
  ]);
  await DomainRegistry.waitForDeployment();

  const domainRegistryAddress = await DomainRegistry.getAddress();
  console.log("✅ DomainRegistry deployed to:", domainRegistryAddress);

  // Deploy GovernanceParams
  const GovernanceParams = await ethers.deployContract("GovernanceParams", [
    domainRegistryAddress,
  ]);
  await GovernanceParams.waitForDeployment();

  const governanceParamsAddress = await GovernanceParams.getAddress();
  console.log("✅ GovernanceParams deployed to:", governanceParamsAddress);

  // Security Authority = deployer; OEM = second signer
  const [, oemDomain] = await ethers.getSigners();

  // Register OEM domain
  const oemPubKey = ethers.toUtf8Bytes("oem_pubkey_abc123");

  const registerTx = await DomainRegistry.registerDomain(
    oemDomain.address,
    "OEM-Domain",
    0,
    true,
    oemPubKey
  );
  await registerTx.wait();

  console.log("✅ OEM domain registered:", oemDomain.address);

  // Update governance thresholds
  const updateTx = await GovernanceParams.updateThresholds(
    6000,
    6000,
    5000,
    5000
  );
  await updateTx.wait();

  console.log("✅ Governance thresholds updated");

  // Verify domain is active
  const isActive = await DomainRegistry.isActiveDomain(oemDomain.address);
  console.log("✅ Domain is active:", isActive);

  console.log("\n🎉 Deployment complete!");
  console.log("DomainRegistry:", domainRegistryAddress);
  console.log("GovernanceParams:", governanceParamsAddress);
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error);
  process.exitCode = 1;
});
