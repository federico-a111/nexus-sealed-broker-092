'use strict';

const crypto = require('crypto');

const BANK_SIZE = 32;
const MANIFESTS_PER_CASE = 6;
const ZONES = ['north', 'south', 'east', 'west'];

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

function makeCase(seed, index) {
  const caseId = `SYN-${String(index).padStart(2, '0')}`;
  const core = derive(seed, `case:${index}:core`);
  const targetZone = ZONES[core[0] % ZONES.length];
  const threshold = 40 + (core[1] % 31);
  const matchIndex = core[2] % 12;
  const records = [];

  for (let i = 0; i < 12; i++) {
    const r = derive(seed, `case:${index}:record:${i}`);
    let zone = ZONES[r[0] % ZONES.length];
    let weight = 10 + (r[1] % 81);
    let flag = (r[2] & 1) === 1;

    if (i === matchIndex) {
      zone = targetZone;
      weight = threshold + 1 + (r[3] % 20);
      flag = true;
    } else {
      const failMode = r[3] % 3;
      if (failMode === 0) zone = ZONES[(ZONES.indexOf(targetZone) + 1 + (r[4] % 3)) % ZONES.length];
      if (failMode === 1) weight = Math.min(threshold, 10 + (r[4] % Math.max(1, threshold - 9)));
      if (failMode === 2) flag = false;
      if (zone === targetZone && weight > threshold && flag === true) flag = false;
    }

    records.push({ id: `R${String(i).padStart(2, '0')}`, zone, weight, flag });
  }

  const oracle = { answer_record_id: `R${String(matchIndex).padStart(2, '0')}` };
  const subjectPacket = {
    case_id: caseId,
    task: `Return the single record id where zone=${targetZone} AND weight>${threshold} AND flag=true.`,
    records,
  };

  const manifests = Array.from({ length: MANIFESTS_PER_CASE }, (_, m) => ({
    manifest_id: `${caseId}-M${m}`,
    case_id: caseId,
    variant: m,
    packet_sha256: sha256(canonical(subjectPacket)),
    protocol: '092-SYNTHETIC-SEALED-CORE',
  }));

  return { caseId, subjectPacket, oracle, manifests };
}

function buildBank(seed) {
  const cases = [];
  const commitments = [];

  for (let i = 0; i < BANK_SIZE; i++) {
    const item = makeCase(seed, i);
    const caseCommitment = {
      index: i,
      case_id: item.caseId,
      packet_sha256: sha256(canonical(item.subjectPacket)),
      oracle_sha256: sha256(canonical(item.oracle)),
      manifest_sha256: item.manifests.map(m => sha256(canonical(m))),
    };
    const leaf = sha256(canonical(caseCommitment));
    cases.push(item);
    commitments.push({ ...caseCommitment, leaf_sha256: leaf });
  }

  const leaves = commitments.map(c => c.leaf_sha256);
  const root = merkleRoot(leaves);
  return { cases, commitments, merkle_root: root };
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

    proof.push({
      position: siblingIndex < idx ? 'left' : 'right',
      sha256: sibling,
    });

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

function loadSeed() {
  const raw = process.env.SYNTHETIC_MASTER_SEED || '';

  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('SYNTHETIC_MASTER_SEED must be exactly 64 hex characters (256 bits).');
  }

  return Buffer.from(raw, 'hex');
}

function main() {
  const mode = process.argv[2];
  const seed = loadSeed();
  const bank = buildBank(seed);

  if (mode === 'freeze') {
    const out = {
      protocol: '092-SYNTHETIC-SEALED-CORE',
      bank_size: BANK_SIZE,
      manifests_per_case: MANIFESTS_PER_CASE,
      total_manifests: BANK_SIZE * MANIFESTS_PER_CASE,
      merkle_root: bank.merkle_root,
      commitments: bank.commitments,
    };

    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return;
  }

  if (mode === 'reveal') {
    const index = Number(process.argv[3]);

    if (!Number.isInteger(index) || index < 0 || index >= BANK_SIZE) {
      throw new Error(`Reveal index must be an integer from 0 to ${BANK_SIZE - 1}.`);
    }

    const leaves = bank.commitments.map(c => c.leaf_sha256);
    const proof = merkleProof(leaves, index);
    const commitment = bank.commitments[index];
    const item = bank.cases[index];
    const verified = verifyProof(
      commitment.leaf_sha256,
      proof,
      bank.merkle_root
    );

    const out = {
      protocol: '092-SYNTHETIC-SEALED-CORE',
      revealed_index: index,
      case_id: item.caseId,
      subject_packet: item.subjectPacket,
      manifest: item.manifests[0],
      commitment,
      merkle_root: bank.merkle_root,
      inclusion_proof: proof,
      inclusion_proof_verified: verified,
      oracle_plaintext_exposed: false,
    };

    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return;
  }

  if (mode === 'grade') {
    const index = Number(process.argv[3]);
    const answer = String(process.argv[4] || '').trim();

    if (!Number.isInteger(index) || index < 0 || index >= BANK_SIZE) {
      throw new Error(`Grade index must be an integer from 0 to ${BANK_SIZE - 1}.`);
    }

    if (!answer) {
      throw new Error('Grade mode requires an answer string.');
    }

    const expected = bank.cases[index].oracle.answer_record_id;

    const out = {
      protocol: '092-SYNTHETIC-SEALED-CORE',
      case_id: bank.cases[index].caseId,
      submitted_answer: answer,
      correct: answer === expected,
      oracle_plaintext_exposed: false,
    };

    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return;
  }

  throw new Error(
    'Usage: node harness/generator.js freeze | reveal <0..31> | grade <0..31> <answer>'
  );
}

try {
  main();
} catch (err) {
  console.error(`ERROR: ${err.message}`);
  process.exit(1);
}
