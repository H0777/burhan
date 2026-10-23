export default [
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_governance",
        "type": "address"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "uint256",
        "name": "activityId",
        "type": "uint256"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "operator",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "enum InsiderActivityLog.ActivityType",
        "name": "activityType",
        "type": "uint8"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "relatedTxId",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "bool",
        "name": "isAfterHours",
        "type": "bool"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "name": "ActivityLogged",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "internalType": "uint8",
        "name": "startUtc",
        "type": "uint8"
      },
      {
        "indexed": false,
        "internalType": "uint8",
        "name": "endUtc",
        "type": "uint8"
      }
    ],
    "name": "BusinessHoursUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "newGovernance",
        "type": "address"
      }
    ],
    "name": "GovernanceTransferred",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "operator",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "alertType",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "details",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "name": "InsiderAlert",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "operator",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "flagType",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "details",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "totalFlags",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "name": "OperatorFlagged",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "recorder",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "bool",
        "name": "authorized",
        "type": "bool"
      }
    ],
    "name": "RecorderUpdated",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "businessHourEnd",
    "outputs": [
      {
        "internalType": "uint8",
        "name": "",
        "type": "uint8"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "businessHourStart",
    "outputs": [
      {
        "internalType": "uint8",
        "name": "",
        "type": "uint8"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "_activityId",
        "type": "uint256"
      }
    ],
    "name": "getActivity",
    "outputs": [
      {
        "components": [
          {
            "internalType": "uint256",
            "name": "id",
            "type": "uint256"
          },
          {
            "internalType": "address",
            "name": "operator",
            "type": "address"
          },
          {
            "internalType": "enum InsiderActivityLog.ActivityType",
            "name": "activityType",
            "type": "uint8"
          },
          {
            "internalType": "uint256",
            "name": "relatedTxId",
            "type": "uint256"
          },
          {
            "internalType": "address",
            "name": "relatedAddress",
            "type": "address"
          },
          {
            "internalType": "string",
            "name": "details",
            "type": "string"
          },
          {
            "internalType": "uint256",
            "name": "timestamp",
            "type": "uint256"
          },
          {
            "internalType": "bool",
            "name": "isAfterHours",
            "type": "bool"
          }
        ],
        "internalType": "struct InsiderActivityLog.Activity",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getAllActivityIds",
    "outputs": [
      {
        "internalType": "uint256[]",
        "name": "",
        "type": "uint256[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_operator",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "_beneficiary",
        "type": "address"
      }
    ],
    "name": "getBeneficiaryApprovalCount",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_operator",
        "type": "address"
      }
    ],
    "name": "getOperatorActivities",
    "outputs": [
      {
        "internalType": "uint256[]",
        "name": "",
        "type": "uint256[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_operator",
        "type": "address"
      }
    ],
    "name": "getOperatorProfile",
    "outputs": [
      {
        "components": [
          {
            "internalType": "uint256",
            "name": "totalActions",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "overrideCount",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "afterHoursCount",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "lastActivityTimestamp",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "flagCount",
            "type": "uint256"
          }
        ],
        "internalType": "struct InsiderActivityLog.OperatorProfile",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "governance",
    "outputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "name": "isRecorder",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_operator",
        "type": "address"
      },
      {
        "internalType": "enum InsiderActivityLog.ActivityType",
        "name": "_type",
        "type": "uint8"
      },
      {
        "internalType": "uint256",
        "name": "_relatedTxId",
        "type": "uint256"
      },
      {
        "internalType": "address",
        "name": "_relatedAddress",
        "type": "address"
      },
      {
        "internalType": "string",
        "name": "_details",
        "type": "string"
      }
    ],
    "name": "logActivity",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "activityId",
        "type": "uint256"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint8",
        "name": "_start",
        "type": "uint8"
      },
      {
        "internalType": "uint8",
        "name": "_end",
        "type": "uint8"
      }
    ],
    "name": "setBusinessHours",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_newGov",
        "type": "address"
      }
    ],
    "name": "setGovernance",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_recorder",
        "type": "address"
      },
      {
        "internalType": "bool",
        "name": "_authorized",
        "type": "bool"
      }
    ],
    "name": "setRecorder",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalActivities",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
]
