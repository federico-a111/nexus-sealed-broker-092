'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const P = require('./primitives');
const S = require('./schema');
const hash = value => P.sha256(P.canonical(value));
const write = (file,value) => { fs.mkdirSync(path.dirname(file),{recursive:true}); fs.writeFileSync(file,typeof value==='string'?value:P.canonical(value),'utf8'); };
const clone = value => JSON.parse(JSON.stringify(value));
function identity(file) {
  const bytes=fs.readFileSync(file);
  return {name:path.basename(file),sha256:P.sha256(bytes),blob:crypto.createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`),bytes])).digest('hex')};
}
function sourceIdentities() { return ['primitives.js','schema.js','generator.js','validator.js','dev-subject.js','proof.js'].map(f=>identity(path.join(__dirname,f))); }
function factory(seed,classId,index) {
  const n = P.derive(seed,`093A:DEV:${classId}:${index}:case`);
  const caseId = `DEV093A-${P.derive(seed,`093A:DEV:id:${classId}:${index}`).toString('hex').slice(0,24)}`;
  const evidence = {};
  let task,oracle,classSpec;
  if(classId==='C1') {
    const threshold=20+index*64+n[0]%40;
    const bad=`'use strict';\nmodule.exports = n => n >= ${threshold};\n`;
    evidence['repo/filter.js']=bad;
    evidence['repo/package.json']=P.canonical({name:caseId,private:true,version:'0.0.0-dev'});
    task=`Repair repo/filter.js so it returns true exactly when integer n is strictly greater than ${threshold}. Return the complete replacement module source in replacement_source. Supported output grammar: 'use strict'; module.exports = n => n COMPARATOR INTEGER; where COMPARATOR is > or >= and INTEGER is a decimal integer. Do not modify the project repository.`;
    oracle={hidden_tests:[{input:threshold-1,expected:false},{input:threshold,expected:false},{input:threshold+1,expected:true},{input:-10,expected:false},{input:threshold+10,expected:true}]};
    classSpec={family:'ephemeral_mini_repo',planted_defect_count:1,hidden_test_grading:true,entry_file:'repo/filter.js',workspace:'subject_case_only',output_language:'whitelisted_commonjs_integer_comparison'};
  } else if(classId==='C2') {
    const expected=100+index*256+n[0],observed=expected+1+n[1]%9;
    evidence['runtime/config.json']=P.canonical({expected_worker_count:expected});
    evidence['runtime/state.json']=P.canonical({observed_worker_count:observed});
    task='Read runtime/config.json and runtime/state.json using native filesystem observations. Diagnose the differing worker count. Return anomaly_path="runtime/state.json", observed=observed_worker_count and expected=expected_worker_count. No persistent system mutation or credential inspection.';
    oracle={answer:{anomaly_path:'runtime/state.json',observed,expected}};
    classSpec={family:'bounded_local_runtime_state',requires_literal_observation:true,persistent_system_mutation:false,fixture_paths:['runtime/config.json','runtime/state.json']};
  } else if(classId==='C3') {
    const a=`claim-${n[0].toString(16)}-a`,b=`claim-${n[1].toString(16)}-b`,sourceId=`source-${n[2].toString(16)}`;
    evidence['evidence/corpus.json']=P.canonical({rule:'Prefer the signed primary source to an unsigned mirror for contradictory claims.',sources:[{id:sourceId,kind:'primary',signed:true,claim:a},{id:'mirror',kind:'mirror',signed:false,claim:b}],contradiction:[a,b]});
    task='Resolve the contradiction from evidence/corpus.json only under its stated source-precedence rule. Return accepted_claim, rejected_claim, source_id. Both arms have exactly these evidence bytes. No web, GitHub acquisition, exclusive device evidence or other-arm output.';
    oracle={answer:{accepted_claim:a,rejected_claim:b,source_id:sourceId}};
    classSpec={family:'equalized_claims_contradictions_provenance',equalized_evidence:true,external_acquisition:false,answer_tuple:['accepted_claim','rejected_claim','source_id']};
  } else if(classId==='C4') {
    const values=Array.from(n.slice(0,6)),modulus=17+n[6]%31;
    evidence['input/numbers.json']=P.canonical({values,modulus});
    task='Return value=(sum(values) mod modulus) from input/numbers.json. Use exactly one AI actor. Native tools are permitted; no second AI or delegation. actor_call_count counts AI actors only, never tools or controller events.';
    oracle={answer:{value:values.reduce((a,b)=>a+b,0)%modulus},actor_call_count:1};
    classSpec={family:'deterministic_single_actor_control',no_delegation:true,actor_counter:'AI_ACTOR_INVOCATION',oracle_actor_count_grading:true};
  } else throw Error('CLASS');
  // Hiding nonces prevent enumeration of low-entropy evidence/contract/packet domains.
  // They are independent of the oracle salt, which is never revealed to a subject.
  for(const ref of Object.keys(evidence)) {
    const nonce=P.derive(seed,`093A:DEV:${caseId}:evidence-nonce:${ref}`).toString('hex');
    evidence[ref]=ref.endsWith('.js')?`// fixture nonce: ${nonce}\n`+evidence[ref]:P.canonical({...JSON.parse(evidence[ref]),fixture_nonce:nonce});
  }
  const refs=Object.entries(evidence).map(([ref,bytes])=>({ref,sha256:P.sha256(bytes),encoding:'utf8'}));
  const packet={case_id:caseId,class_id:classId,version:S.VERSION,scope:S.SCOPE,disclosure_nonce:P.derive(seed,`093A:DEV:${caseId}:packet-nonce`).toString('hex'),task,evidence_refs:refs};
  const contract={case_id:caseId,class_id:classId,family:classSpec.family,version:S.VERSION,scope:S.SCOPE,disclosure_nonce:P.derive(seed,`093A:DEV:${caseId}:contract-nonce`).toString('hex'),operation:task,
    allowed_evidence:refs,forbidden_surfaces:S.FORBIDDEN,output_schema:S.OUTPUT_SCHEMAS[classId],
    success_terminal:'COMPLETE',terminal_capture:S.CAPTURE_SCHEMA,
    grader_input:{output:'run-specific output.json',capture:'run-specific final.json',sealed_oracle:'controller_after_comparison_unit_sealed',expected_answer_in_subject_contract:false},class_spec:classSpec};
  return {caseId,classId,packet,contract,evidence,oracle,salt:P.derive(seed,`093A:DEV:${caseId}:oracle-salt`)};
}
function makeBank(root,seed) {
  if(fs.existsSync(root)) throw Error('NEW_DEV_ROOT_REQUIRED');
  if(!Buffer.isBuffer(seed)||seed.length!==32) throw Error('DEV_SEED_256_BITS_REQUIRED');
  const source=sourceIdentities(),cases=[],runs=[];
  for(const classId of S.CLASSES) for(let i=0;i<8;i++) {
    const caseSeed=P.derive(seed,`093A:DEV:${classId}:${i}:seed`);
    const c=factory(caseSeed,classId,i);c.caseSeed=caseSeed;
    c.role=i<4?'PRIMARY':'RESERVE'; c.ordinal=i%4; cases.push(c);
    const base=`cases/${c.caseId}`;
    const evidenceHashes=c.packet.evidence_refs.map(r=>r.sha256);
    for(const arm of ['A','B']) for(let replicate=1;replicate<=3;replicate++) {
      const runId=`${c.caseId}-${arm}-R${replicate}`;
      runs.push({run_id:runId,case_id:c.caseId,class_id:classId,arm,replicate,version:S.VERSION,scope:S.SCOPE,
        role:c.role,required_actor:S.BASELINES[classId],required_runtime:S.RUNTIMES[S.BASELINES[classId]],
        permitted_actors:arm==='A'?[S.BASELINES[classId]]:['CLASSIC','CLAUDE','NEXUS_PC'],
        packet_ref:`${base}/packet.json`,packet_sha256:hash(c.packet),contract_ref:`${base}/contract.json`,contract_sha256:hash(c.contract),
        evidence_sha256:evidenceHashes,output_destination:`runs/${runId}/output.json`,capture_destination:`runs/${runId}/final.json`,started_destination:`runs/${runId}/started.json`,
        writable_scope:`runs/${runId}`,fresh_context:true,other_arm_output_access:false,
        lifecycle:{first_step:'persist_STARTED_before_packet_or_evidence_read',started_packet_consumed:false,final_schema:S.CAPTURE_SCHEMA},
        routing:{allowed:arm==='B',no_delegation_valid:true,justification_before_second_actor:true,provenance_fields:['decision','evidence_need','justification_event','second_actor_event','mechanism','independent_first_pass']},
        c4_actor_call_count_grading:classId==='C4',actor_counter_semantics:'AI_ACTOR_INVOCATION',
        order_key:P.derive(seed,`093A:DEV:run-order:${runId}`).toString('hex')});
    }
  }
  runs.sort((a,b)=>a.order_key.localeCompare(b.order_key)||a.run_id.localeCompare(b.run_id));
  const order=runs.map(m=>m.run_id),orderHash=hash(order);
  runs.forEach((m,index)=>{delete m.order_key;m.order_index=index;m.run_order_sha256=orderHash;});
  const reserveOrder=Object.fromEntries(S.CLASSES.map(cls=>[cls,cases.filter(c=>c.classId===cls&&c.role==='RESERVE').sort((a,b)=>a.caseId.localeCompare(b.caseId)).map(c=>c.caseId)]));
  const reserveHash=hash(reserveOrder),commitments=[];
  for(const [index,c] of cases.entries()) {
    const manifests=runs.filter(m=>m.case_id===c.caseId);
    const cc={index,case_id:c.caseId,class_id:c.classId,role:c.role,ordinal:c.ordinal,version:S.VERSION,scope:S.SCOPE,
      packet_sha256:hash(c.packet),contract_sha256:hash(c.contract),evidence_sha256:c.packet.evidence_refs.map(r=>r.sha256),
      oracle_commitment_sha256:P.oracleCommitment(c.caseId,c.oracle,c.salt),seed_commitment_sha256:P.sha256(c.caseSeed),
      manifest_sha256:manifests.map(hash),run_ids:manifests.map(m=>m.run_id),reserve_order_sha256:reserveHash};
    commitments.push({...cc,leaf_sha256:hash(cc)});
  }
  const freeze={protocol:'093A-PRODUCTION-CONTRACT-DEV-V3',scope:S.SCOPE,version:S.VERSION,source,
    primary_count:16,reserve_count:16,case_count:32,manifest_count:192,k:3,baselines:S.BASELINES,runtimes:S.RUNTIMES,
    run_order:order,run_order_sha256:orderHash,reserve_order:reserveOrder,reserve_order_sha256:reserveHash,reserve_rule:S.RESERVE_RULE,
    reserve_state:Object.fromEntries(cases.filter(c=>c.role==='RESERVE').map(c=>[c.caseId,{used:false,exposed:false}])),
    grading_rules:S.GRADING_RULES,commitments,merkle_root:P.merkleRoot(commitments.map(c=>c.leaf_sha256)),
    real_heldout_generation:0,heldout_subjects_executed:0};
  write(path.join(root,'public','freeze.json'),freeze);
  for(const c of cases) {
    const base=path.join(root,'controller','cases',c.caseId);
    write(path.join(base,'packet.json'),c.packet);write(path.join(base,'contract.json'),c.contract);
    for(const [ref,bytes] of Object.entries(c.evidence)) write(path.join(base,ref),bytes);
  }
  for(const m of runs) {write(path.join(root,'controller','manifests',`${m.run_id}.json`),m);fs.mkdirSync(path.join(root,'controller',m.writable_scope),{recursive:true});}
  write(path.join(root,'controller','sealed-core.json'),{scope:S.SCOPE,seed_hex:seed.toString('hex'),cases:cases.map(c=>({case_id:c.caseId,case_seed_hex:c.caseSeed.toString('hex'),oracle:c.oracle,oracle_salt_hex:c.salt.toString('hex')}))});
  return {freeze,cases,runs};
}
function load(root) { return JSON.parse(fs.readFileSync(path.join(root,'public','freeze.json'),'utf8')); }
function safeRun(freeze,runId) { const c=freeze.commitments.find(c=>c.run_ids.includes(runId));if(!c)throw Error('UNKNOWN_RUN');return c; }
function reveal(root,runId,destination) {
  const freeze=load(root),c=safeRun(freeze,runId);
  if(fs.existsSync(destination))throw Error('NEW_SUBJECT_DESTINATION_REQUIRED');
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'controller','manifests',`${runId}.json`),'utf8'));
  const packet=JSON.parse(fs.readFileSync(path.join(root,'controller',manifest.packet_ref),'utf8'));
  const contract=JSON.parse(fs.readFileSync(path.join(root,'controller',manifest.contract_ref),'utf8'));
  const proof=P.merkleProof(freeze.commitments.map(c=>c.leaf_sha256),c.index);
  const envelope={manifest,commitment:c,merkle_root:freeze.merkle_root,inclusion_proof:proof,
    packet_ref:manifest.packet_ref,contract_ref:manifest.contract_ref,scope:S.SCOPE};
  write(path.join(destination,'transport.json'),envelope);
  write(path.join(destination,manifest.packet_ref),packet);write(path.join(destination,manifest.contract_ref),contract);
  for(const r of packet.evidence_refs) {
    const content=fs.readFileSync(path.join(root,'controller','cases',c.case_id,r.ref));
    write(path.join(destination,'cases',c.case_id,r.ref),content.toString('utf8'));
  }
  fs.mkdirSync(path.join(destination,manifest.writable_scope),{recursive:true});
  return envelope;
}
function sealComparison(root,caseId) {
  const freeze=load(root),c=freeze.commitments.find(c=>c.case_id===caseId);
  if(!c)throw Error('UNKNOWN_CASE');
  const outputs=c.run_ids.map(runId=>{
    const output=path.join(root,'sealed-outputs',`${runId}.json`);
    const capture=path.join(root,'sealed-outputs',`${runId}.capture.json`);
    return {run_id:runId,output_sha256:P.sha256(fs.readFileSync(output)),capture_sha256:P.sha256(fs.readFileSync(capture))};
  });
  const seal={case_id:caseId,outputs,freeze_sha256:hash(freeze),comparison_unit_sealed:true};
  write(path.join(root,'controller','seals',`${caseId}.json`),seal);return seal;
}
function checkSeal(root,caseId) {
  const seal=JSON.parse(fs.readFileSync(path.join(root,'controller','seals',`${caseId}.json`),'utf8'));
  if(seal.case_id!==caseId||seal.freeze_sha256!==hash(load(root))||seal.comparison_unit_sealed!==true)throw Error('SEAL_INVALID');
  const expected=load(root).commitments.find(c=>c.case_id===caseId).run_ids;
  if(P.canonical(seal.outputs.map(o=>o.run_id).sort())!==P.canonical([...expected].sort()))throw Error('COMPARISON_UNIT_INCOMPLETE');
  for(const o of seal.outputs) {
    if(o.output_sha256!==P.sha256(fs.readFileSync(path.join(root,'sealed-outputs',`${o.run_id}.json`)))||o.capture_sha256!==P.sha256(fs.readFileSync(path.join(root,'sealed-outputs',`${o.run_id}.capture.json`))))throw Error('SEALED_OUTPUT_CHANGED');
  }
  return seal;
}
function grade(root,runId) {
  const freeze=load(root),c=safeRun(freeze,runId);checkSeal(root,c.case_id);
  const core=JSON.parse(fs.readFileSync(path.join(root,'controller','sealed-core.json'),'utf8')).cases.find(x=>x.case_id===c.case_id);
  if(P.oracleCommitment(c.case_id,core.oracle,Buffer.from(core.oracle_salt_hex,'hex'))!==c.oracle_commitment_sha256)throw Error('ORACLE_COMMITMENT');
  const output=JSON.parse(fs.readFileSync(path.join(root,'sealed-outputs',`${runId}.json`),'utf8'));
  const capture=JSON.parse(fs.readFileSync(path.join(root,'sealed-outputs',`${runId}.capture.json`),'utf8'));
  if(capture.status==='BLOCKED')return {run_id:runId,verdict:'NO_EVALUABLE',oracle_commitment_verified:true};
  let correct;
  if(c.class_id==='C1') {
    // Whitelisted mini-language: never execute arbitrary subject-supplied code in the controller.
    const match=/^'use strict';\s*module\.exports = n => n (>|>=) (\d+);\s*$/.exec(output.replacement_source);
    correct=Boolean(match)&&core.oracle.hidden_tests.every(t=>(match[1]==='>'?t.input>Number(match[2]):t.input>=Number(match[2]))===t.expected);
  } else correct=P.canonical(output)===P.canonical(core.oracle.answer);
  if(c.class_id==='C4')correct=correct&&capture.actor_call_count===core.oracle.actor_call_count;
  return {run_id:runId,verdict:correct?'PASS':'FAIL',oracle_commitment_verified:true,oracle_plaintext_exposed:false,oracle_salt_exposed:false};
}
function openOracle(root,caseId) {
  checkSeal(root,caseId);
  const gradeRecord=JSON.parse(fs.readFileSync(path.join(root,'controller','grades',`${caseId}.json`),'utf8'));
  const c=load(root).commitments.find(c=>c.case_id===caseId);
  if(gradeRecord.length!==6||!c.run_ids.every(id=>gradeRecord.some(g=>g.run_id===id)))throw Error('GRADE_FIRST');
  const core=JSON.parse(fs.readFileSync(path.join(root,'controller','sealed-core.json'),'utf8')).cases.find(x=>x.case_id===caseId);
  return {case_id:caseId,oracle:core.oracle,oracle_salt_hex:core.oracle_salt_hex,oracle_commitment_verified:P.oracleCommitment(caseId,core.oracle,Buffer.from(core.oracle_salt_hex,'hex'))===c.oracle_commitment_sha256};
}
function selectReserve(freeze,classId,reason) {
  if(!reason||reason.verdict!=='NO_EVALUABLE'||reason.independent!==true||!reason.literal_reason||reason.subject_outcome_used!==false)throw Error('RESERVE_REQUIRES_INDEPENDENT_INVALIDITY');
  const id=freeze.reserve_order[classId].find(id=>!freeze.reserve_state[id].used&&!freeze.reserve_state[id].exposed);
  if(!id)throw Error('NO_FROZEN_RESERVE');return id;
}
module.exports={hash,write,clone,identity,sourceIdentities,factory,makeBank,load,reveal,sealComparison,checkSeal,grade,openOracle,selectReserve};
if(require.main===module) {
  // No production/held-out mode exists in this DEV authorization.
  if(process.argv[2]!=='dev-freeze'||!process.argv[3])throw Error('DEV_ONLY: node generator.js dev-freeze <new-root>');
  const bank=makeBank(path.resolve(process.argv[3]),crypto.randomBytes(32));
  console.log(JSON.stringify({scope:S.SCOPE,case_count:bank.freeze.case_count,manifest_count:bank.freeze.manifest_count,merkle_root:bank.freeze.merkle_root,real_heldout_generation:0}));
}
