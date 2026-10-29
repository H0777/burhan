require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    hardhat: {
      chainId: 31337,
      // R04/F08: standard EIP-170 limit enforced everywhere — production
      // contracts must fit the 24,000-byte runtime budget (see
      // scripts/check-contract-size.js). Never re-enable unlimited size.
      allowUnlimitedContractSize: false
    },
    localhost: {
      // H04 staging: LOCALHOST_RPC_URL retargets deploy/E2E at the staging EVM
      // (http://hardhat-node:8545 from the staging deployer container;
      // http://127.0.0.1:18545 for the host integration runner). Unset ->
      // unchanged default below.
      url: process.env.LOCALHOST_RPC_URL || "http://127.0.0.1:8545",
      chainId: 31337,
      allowUnlimitedContractSize: false
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 11155111
    }
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD"
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY || ""
  },
  coverage: {
    reporter: ["text", "lcov", "html"]
  }
};
