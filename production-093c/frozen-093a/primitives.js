'use strict';
// 093A V3: unchanged algorithms extracted from frozen 092B blob c27e4f80bf78d5ead7ad07c148afd50a1e2deff1.
// New file; 092B source and receipts are never modified.
const crypto = require('node:crypto');
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function hmac(seed, label) {
  return crypto.createHmac('sha256', seed).update(label, 'utf8').digest();
}

function derive(seed, label) {
  return hmac(seed, label);
}

function oracleCommitment(caseId, oracle, oracleSalt) {
  return sha256(Buffer.concat([
    Buffer.from('oracle-commit-v2\0', 'utf8'),
    Buffer.from(caseId, 'utf8'),
    Buffer.from('\0', 'utf8'),
    Buffer.from(canonical(oracle), 'utf8'),
    Buffer.from('\0', 'utf8'),
    oracleSalt,
  ]));
}


function merkleRoot(leaves) {
  if (!leaves.length) throw new Error('No leaves');
  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(sha256(Buffer.from(left + right, 'hex')));
    }
    level = next;
  }
  return level[0];
}

function merkleProof(leaves, index) {
  let idx = index;
  let level = [...leaves];
  const proof = [];

  while (level.length > 1) {
    const siblingIndex = idx ^ 1;
    const sibling = level[siblingIndex] ?? level[idx];
    proof.push({ position: siblingIndex < idx ? 'left' : 'right', sha256: sibling });

    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(sha256(Buffer.from(left + right, 'hex')));
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return proof;
}

function verifyProof(leaf, proof, expectedRoot) {
  let current = leaf;
  for (const step of proof) {
    current = step.position === 'left'
      ? sha256(Buffer.from(step.sha256 + current, 'hex'))
      : sha256(Buffer.from(current + step.sha256, 'hex'));
  }
  return current === expectedRoot;
}


module.exports = { canonical, sha256, hmac, derive, oracleCommitment, merkleRoot, merkleProof, verifyProof };
