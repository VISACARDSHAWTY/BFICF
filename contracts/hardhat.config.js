
import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import fs from "node:fs";
import path from "node:path";

const keyPath = (name) =>
  path.resolve("../chain/nodes", name, "key");

const readKey = (name) =>
  "0x" + fs.readFileSync(keyPath(name), "utf8").trim().replace(/^0x/, "");

export default defineConfig({
  plugins: [hardhatEthers],

  solidity: {
    version: "0.8.38",
    settings: {
      evmVersion: "paris",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },

  networks: {
    local: {
      type: "http",
      url: "http://127.0.0.1:8545",
      accounts: [readKey("secauth"), readKey("oem")],
      chainId: 20260,
      gasPrice: "auto",
    },

    hardhat: {
      type: "edr-simulated",
      chainId: 20260,
    },
  },
});
