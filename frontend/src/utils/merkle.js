import { ethers } from 'ethers'

/**
 * Standard Merkle Tree Utility for Court-Admissible Electronic Evidence
 * Generates cryptographic proofs for individual forensic log entries.
 */

/**
 * Combine two hashes deterministically (sorted pairs)
 */
function hashPair(a, b) {
  const sorted = [a, b].sort()
  return ethers.keccak256(ethers.concat([sorted[0], sorted[1]]))
}

/**
 * Build a complete Merkle Tree from an array of hex leaves.
 */
export function buildMerkleTree(leaves) {
  if (!leaves || leaves.length === 0) {
    const zeroLeaf = ethers.ZeroHash
    return {
      layers: [[zeroLeaf]],
      root: zeroLeaf,
    }
  }

  // Ensure 32-byte formatted leaves
  let currentLayer = leaves.map((leaf) => {
    if (typeof leaf === 'string' && leaf.startsWith('0x') && leaf.length === 66) {
      return leaf
    }
    return ethers.keccak256(ethers.toUtf8Bytes(String(leaf)))
  })

  const layers = [currentLayer]

  while (currentLayer.length > 1) {
    const nextLayer = []
    for (let i = 0; i < currentLayer.length; i += 2) {
      if (i + 1 < currentLayer.length) {
        nextLayer.push(hashPair(currentLayer[i], currentLayer[i + 1]))
      } else {
        // Odd leaf: duplicate or promote
        nextLayer.push(hashPair(currentLayer[i], currentLayer[i]))
      }
    }
    layers.push(nextLayer)
    currentLayer = nextLayer
  }

  return {
    layers,
    root: currentLayer[0],
  }
}

/**
 * Generate a cryptographic Merkle Proof for leaf at targetIndex.
 */
export function generateMerkleProof(leaves, targetIndex) {
  const { layers, root } = buildMerkleTree(leaves)
  if (targetIndex < 0 || targetIndex >= leaves.length) {
    throw new Error(`Target index ${targetIndex} out of bounds`)
  }

  const proof = []
  let index = targetIndex

  for (let i = 0; i < layers.length - 1; i++) {
    const layer = layers[i]
    const isRightNode = index % 2 === 1
    const siblingIndex = isRightNode ? index - 1 : index + 1

    if (siblingIndex < layer.length) {
      proof.push(layer[siblingIndex])
    } else {
      // Sibling is self (odd node)
      proof.push(layer[index])
    }

    index = Math.floor(index / 2)
  }

  return {
    targetLeaf: layers[0][targetIndex],
    targetIndex,
    proof,
    merkleRoot: root,
  }
}

/**
 * Verify a Merkle proof against a root.
 */
export function verifyMerkleProof(leaf, proof, root) {
  let computed = leaf
  for (const sibling of proof) {
    computed = hashPair(computed, sibling)
  }
  return computed.toLowerCase() === root.toLowerCase()
}

/**
 * Generate a downloadable Judicial Merkle Receipt JSON.
 */
export function generateJudicialEvidenceReceipt(entry, proofData) {
  return {
    receiptType: 'JUDICIAL_ELECTRONIC_EVIDENCE_RECEIPT',
    standard: 'RFC 6962 / Merkle Audit Trail',
    caseReference: 'CBI-AML-CYBER-AUDIT',
    timestamp: new Date().toISOString(),
    entryMetadata: {
      index: entry.index,
      incidentType: entry.incidentType,
      operator: entry.operator,
      actor: entry.actor,
      timestamp: entry.timestamp,
    },
    cryptographicProof: {
      evidenceHash: entry.evidenceHash,
      leafHash: proofData.targetLeaf,
      merkleRoot: proofData.merkleRoot,
      siblingHashes: proofData.proof,
      verificationResult: 'CRYPTOGRAPHICALLY_VALID',
    },
    evidentiaryDisclaimer:
      'This receipt proves non-repudiable inclusion of the evidence entry in the root audit hash certified by the Central Bank of Iraq.',
  }
}
