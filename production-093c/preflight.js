'use strict';
// 093C only: permanently contaminated rehearsal, no production bank or AI subject invocation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process'),assert=require('node:assert/strict');
const C=require('./context');if(C.production)throw Error('093C_PREFLIGHT_REHEARSAL_ONLY');
const B=require('./broker'),G=require('./generator'),P=require('./primitives'),V=require('./validator'),S=require('./schema');
const root=path.resolve(process.argv[2]),receiptFile=path.resolve(process.argv[3]),checks={};
const report={unit:'093C_PRODUCTION_ACTIVATION_PACKAGE_AND_PREFLIGHT',terminal:'BLOCKED',scope:C.scope,real_heldout_generation:0,heldout_subjects_executed:0,subject_treatment:0,broker_installation_executed:false,github_workflows_executed:false,node_version:process.version,node_executable:process.execPath};
function json(file){return JSON.parse(fs.readFileSync(file,'utf8'));}
async function check(name,fn){await fn();checks[name]='PASS';}
function reject(fn){assert.throws(fn);}
async function rejectAsync(fn){await assert.rejects(fn);}
function captureProcess(m,surface){
  const r=cp.spawnSync(process.execPath,[path.join(__dirname,'dev-subject.js'),surface,'complete'],{cwd:surface,encoding:'utf8',env:{SystemRoot:process.env.SystemRoot||'',PATH:path.dirname(process.execPath),ACTIVATION_093C_MODE:'REHEARSAL'},timeout:10000});
  assert.equal(r.status,0);assert.equal(r.stdout.trim(),'COMPLETE');
  const startedBytes=fs.readFileSync(path.join(surface,m.started_destination));
  return {run_id:m.run_id,case_id:m.case_id,started_bytes_base64:startedBytes.toString('base64'),capture:json(path.join(surface,m.capture_destination)),output:json(path.join(surface,m.output_destination))};
}
function productionGuard(code,expected){const r=cp.spawnSync(process.execPath,['-e',code],{cwd:__dirname,encoding:'utf8',env:{SystemRoot:process.env.SystemRoot||'',PATH:path.dirname(process.execPath),ACTIVATION_093C_MODE:'PRODUCTION'},timeout:10000});assert.equal(r.status,0);assert.equal(r.stdout.trim(),expected);}
async function main(){
  assert(!fs.existsSync(root));fs.mkdirSync(root,{recursive:true});
  await check('frozen_093a_092b_inputs_byte_identical',()=>{const pins=json(path.join(__dirname,'PINNED_INPUTS.json'));for(const file of pins.files){const actual=G.identity(path.join(__dirname,file.path));assert.equal(actual.blob,file.blob);assert.equal(actual.sha256,file.sha256);}report.frozen_inputs=pins;});
  await check('scientific_schema_and_rules_preserved',()=>{const frozen=require('./frozen-093a/schema');for(const key of ['CLASSES','BASELINES','RUNTIMES','FORBIDDEN','FINAL_FIELDS','OUTPUT_SCHEMAS','CAPTURE_SCHEMA','RESERVE_RULE','GRADING_RULES'])assert.deepEqual(S[key],frozen[key]);report.capture_schema=frozen.CAPTURE_SCHEMA.identity;});
  await check('package_bytes_and_workflows_frozen_before_rehearsal',()=>{
    report.package_sha256=B.packageIdentity();const manifest=json(path.join(__dirname,'PACKAGE_FREEZE.json'));report.package_files=manifest.files;
    for(const action of ['freeze','reveal','grade','open-oracle']){
      const text=fs.readFileSync(path.join(C.packageRoot,'.github','workflows','093c-'+action+'.yml'),'utf8');
      assert(text.includes("github.actor == 'federico-a111'"));assert(text.includes("github.repository == 'federico-a111/nexus-sealed-broker-092'"));assert(text.includes('name: sealed-core-synthetic'));assert(text.includes('persist-credentials: false'));assert(text.includes('STAGE1_V2_PRODUCTION_MASTER_HEX: ${{ secrets.STAGE1_V2_PRODUCTION_MASTER_HEX }}'));assert(text.includes('SYNTHETIC_MASTER_SEED: ${{ secrets.SYNTHETIC_MASTER_SEED }}'));assert(text.includes('node production-093c/driver.js '+action));assert(text.includes('path: ${{ runner.temp }}/093c-public/'));assert(!/path:\s*.*private|path:\s*.*controller/.test(text));assert(!text.includes('npm '));assert(!text.includes('workflow_run:'));assert(/actions\/checkout@[a-f0-9]{40}/.test(text));assert(/actions\/upload-artifact@[a-f0-9]{40}/.test(text));
    }
  });
  await check('production_negative_guards_without_factory_generation',()=>{
    productionGuard("const b=require('./broker');try{b.assertAuthority('freeze','5936862387',{});process.exit(1)}catch(e){console.log(e.message)}",'BROKER_AUTHORITY_DOMAIN_REQUIRED');
    productionGuard("const b=require('./broker');const e={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:b.policy.broker_repository,GITHUB_ACTOR:'untrusted-subject',BROKER_PROTECTED_ENVIRONMENT:b.policy.protected_environment,ACTIVATION_093C_MODE:'PRODUCTION'};try{b.assertAuthority('freeze','5936862387',e);process.exit(1)}catch(e){console.log(e.message)}",'BROKER_AUTHORITY_DOMAIN_REQUIRED');
    productionGuard("const b=require('./broker');const e={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:b.policy.broker_repository,GITHUB_ACTOR:b.policy.broker_owner,BROKER_PROTECTED_ENVIRONMENT:b.policy.protected_environment,ACTIVATION_093C_MODE:'PRODUCTION'};try{b.assertAuthority('grade','5936862387',e);process.exit(1)}catch(e){console.log(e.message)}",'SEPARATE_ACTION_AUTH_REQUIRED');
    productionGuard("const b=require('./broker');try{b.readMaster({STAGE1_V2_PRODUCTION_MASTER_HEX:'22'.repeat(32),SYNTHETIC_MASTER_SEED:'22'.repeat(32)});process.exit(1)}catch(e){console.log(e.message)}",'SYNTHETIC_MASTER_REUSE_DENIED');
    productionGuard("const b=require('./broker');try{b.readMaster({});process.exit(1)}catch(e){console.log(e.message)}",'FRESH_256_BIT_MASTER_REQUIRED');
    productionGuard("const b=require('./broker');try{b.readMaster({STAGE1_V2_PRODUCTION_MASTER_HEX:'22'.repeat(32)});process.exit(1)}catch(e){console.log(e.message)}",'SYNTHETIC_REUSE_GUARD_UNAVAILABLE');
    const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:B.policy.broker_repository,GITHUB_ACTOR:B.policy.broker_owner,BROKER_PROTECTED_ENVIRONMENT:B.policy.protected_environment,ACTIVATION_093C_MODE:'PRODUCTION'};
    // Positive validation of authority METADATA only; no production master/seed/factory is created or called.
    productionGuard("const b=require('./broker');const e="+JSON.stringify(env)+";b.assertAuthority('freeze','5936862387',e);console.log('AUTH_METADATA_ONLY')",'AUTH_METADATA_ONLY');
  });
  await check('full_cardinality_contaminated_rehearsal',()=>{
    const subReceipt=path.join(root,'full-cardinality-receipt.json');const r=cp.spawnSync(process.execPath,[path.join(__dirname,'proof.js'),path.join(root,'full-cardinality'),path.join(__dirname,'frozen-092b.js'),subReceipt],{encoding:'utf8',env:{SystemRoot:process.env.SystemRoot||'',PATH:path.dirname(process.execPath),ACTIVATION_093C_MODE:'REHEARSAL'},timeout:120000});
    assert.equal(r.status,0);const proof=json(subReceipt);assert.equal(proof.terminal,'REHEARSAL_PASS');assert.deepEqual(proof.synthetic_cardinality,{primary:16,reserve:16,total:32,manifests:192});assert.equal(proof.real_heldout_generation,0);assert.equal(proof.heldout_subjects_executed,0);assert(Object.values(proof.checks).every(v=>v==='PASS'));report.full_cardinality_proof=proof;
  });
  const master=crypto.randomBytes(32);process.env.REHEARSAL_093C_MASTER_HEX=master.toString('hex');
  const freezeRoot=path.join(root,'broker-private-freeze');
  class ObservedStore extends B.LocalStore {async putImmutable(ref,value){if(ref==='claim.json')assert(!fs.existsSync(freezeRoot));return super.putImmutable(ref,value);}}
  const store=new ObservedStore(path.join(root,'mock-broker-public-receipts'));let receipt;
  await check('claim_before_info_spend_and_broker_freeze',async()=>{receipt=await B.freeze({root:freezeRoot,store,authorization_ref:'REHEARSAL-AUTH-freeze'});assert.equal(receipt.scope,C.scope);assert.equal(receipt.freeze.primary_count,16);assert.equal(receipt.freeze.reserve_count,16);assert.equal(receipt.freeze.manifest_count,192);assert(!JSON.stringify(receipt).includes(master.toString('hex')));assert(!JSON.stringify(receipt).includes('case_seed_hex'));assert(!JSON.stringify(receipt).includes('oracle_salt_hex'));assert(!JSON.stringify(receipt).includes('hidden_tests'));report.rehearsal_freeze_sha256=G.hash(receipt);report.rehearsal_merkle_root=receipt.freeze.merkle_root;});
  await check('first_freeze_retry_denied_before_factory',async()=>{const blockedRoot=path.join(root,'blocked-repeat-freeze');await rejectAsync(()=>B.freeze({root:blockedRoot,store,authorization_ref:'REHEARSAL-AUTH-freeze'}));assert(!fs.existsSync(blockedRoot));});
  await check('wrong_master_blocked_before_case_materialization',()=>{const blockedRoot=path.join(root,'wrong-master');reject(()=>B.materialize(blockedRoot,Buffer.alloc(32),receipt));assert(!fs.existsSync(blockedRoot));});
  const key=B.recipient(master),core=json(path.join(freezeRoot,'controller','sealed-core.json'));
  await check('production_master_never_persisted_and_domains_separated',()=>{assert(!JSON.stringify(core).includes(master.toString('hex')));for(const c of core.cases){assert.notEqual(c.case_seed_hex,c.oracle_salt_hex);assert.notEqual(c.case_seed_hex,master.toString('hex'));assert.notEqual(c.oracle_salt_hex,master.toString('hex'));}assert.notEqual(P.derive(master,C.domain+'factory-master').toString('hex'),P.derive(master,C.domain+'sealed-output-recipient-private').toString('hex'));assert(key.publicKey.length>0);});
  const caseBundles=[];
  await check('one_run_reveal_c3_delivery_and_sealed_outputs',async()=>{
    for(const cls of S.CLASSES){const c=receipt.freeze.commitments.find(c=>c.class_id===cls&&c.role==='PRIMARY'),envelopes=[],surfaces=[];
      for(const runId of c.run_ids){const surface=path.join(root,'subject-surfaces',runId),privateRoot=path.join(root,'broker-reveal',runId);const result=await B.reveal({root:privateRoot,store,authorization_ref:'REHEARSAL-AUTH-reveal',run_id:runId,destination:surface});assert(result.inclusion_proof_verified);const transport=json(path.join(surface,'transport.json')),m=transport.manifest,payload=captureProcess(m,surface);
        assert.equal(payload.capture.dev_simulation,true);V.validateCapture(m,JSON.parse(Buffer.from(payload.started_bytes_base64,'base64')),payload.capture,payload.output,Buffer.from(payload.started_bytes_base64,'base64'));
        const envelope=B.sealOutput(receipt,runId,payload);assert.deepEqual(B.unsealOutput(receipt,envelope,master),payload);assert(!JSON.stringify(envelope).includes(P.canonical(payload.output)));envelopes.push(envelope);surfaces.push(surface);
      }
      if(cls==='C3'){const bytes=fs.readFileSync(path.join(surfaces[0],'cases',c.case_id,'evidence','corpus.json'));for(const surface of surfaces)assert.deepEqual(fs.readFileSync(path.join(surface,'cases',c.case_id,'evidence','corpus.json')),bytes);}
      caseBundles.push({c,envelopes,surfaces});
    }
    report.broker_reveal_runs=24;report.broker_c3_equalized_deliveries=6;
  });
  await check('ciphertext_tamper_and_cross_run_swap_reject',()=>{const item=caseBundles[0],e=G.clone(item.envelopes[0]);e.ciphertext=(e.ciphertext[0]==='A'?'B':'A')+e.ciphertext.slice(1);reject(()=>B.unsealOutput(receipt,e,master));const swapped=G.clone(item.envelopes[0]);swapped.run_id=item.envelopes[1].run_id;reject(()=>B.unsealOutput(receipt,swapped,master));reject(()=>B.unsealOutput(receipt,item.envelopes[0],Buffer.alloc(32)));});
  await check('incomplete_comparison_and_early_open_reject',async()=>{const item=caseBundles[0],blockedRoot=path.join(root,'grade-incomplete');await rejectAsync(()=>B.grade({root:blockedRoot,store,authorization_ref:'REHEARSAL-AUTH-grade',case_id:item.c.case_id,sealed_comparison:item.envelopes.slice(0,5)}));assert(!fs.existsSync(blockedRoot));const openedRoot=path.join(root,'open-early');await rejectAsync(()=>B.openOracle({root:openedRoot,store,authorization_ref:'REHEARSAL-AUTH-open',case_id:item.c.case_id}));assert(!fs.existsSync(openedRoot));});
  await check('repeat_run_and_unauthorized_reserve_reject',async()=>{const item=caseBundles[0],blockedRoot=path.join(root,'repeat-reveal');await rejectAsync(()=>B.reveal({root:blockedRoot,store,authorization_ref:'REHEARSAL-AUTH-reveal',run_id:item.c.run_ids[0],destination:path.join(root,'repeat-subject')}));assert(!fs.existsSync(blockedRoot));const reserve=receipt.freeze.commitments.find(c=>c.role==='RESERVE');const reserveRoot=path.join(root,'reserve-denied');await rejectAsync(()=>B.reveal({root:reserveRoot,store,authorization_ref:'REHEARSAL-AUTH-reveal',run_id:reserve.run_ids[0],destination:path.join(root,'reserve-subject-denied')}));assert(!fs.existsSync(reserveRoot));});
  await check('complete_broker_grade_and_post_grade_open',async()=>{
    const summaries=[];
    for(const item of caseBundles){const result=await B.grade({root:path.join(root,'broker-grade',item.c.case_id),store,authorization_ref:'REHEARSAL-AUTH-grade',case_id:item.c.case_id,sealed_comparison:item.envelopes});assert.equal(result.grades.length,6);assert(result.grades.every(g=>g.verdict==='PASS'));assert.equal(result.oracle_plaintext_exposed,false);const opened=await B.openOracle({root:path.join(root,'broker-open',item.c.case_id),store,authorization_ref:'REHEARSAL-AUTH-open',case_id:item.c.case_id});assert(opened.oracle_commitment_verified);summaries.push({class_id:item.c.class_id,grades:6,post_grade_audit:'PASS'});}
    report.broker_class_pipeline=summaries;
  });
  await check('immutable_grade_open_receipts_and_package_final_identity',async()=>{const item=caseBundles[0];await rejectAsync(()=>B.grade({root:path.join(root,'repeat-grade'),store,authorization_ref:'REHEARSAL-AUTH-grade',case_id:item.c.case_id,sealed_comparison:item.envelopes}));await rejectAsync(()=>B.openOracle({root:path.join(root,'repeat-open'),store,authorization_ref:'REHEARSAL-AUTH-open',case_id:item.c.case_id}));assert.equal(B.packageIdentity(),report.package_sha256);});
  report.subject_capability_boundary='UNCHANGED; no broker install/dispatch/credential/permission changes';
  report.exposure_model='UNCHANGED: one selected run only, core hidden, other-arm outputs sealed; ciphertext implements the existing sealed-output transport';
  report.scientific_contract_changes='NONE';report.terminal='READY_FOR_BROKER_INSTALL';report.first_blocker='NONE';
}
main().catch(e=>{report.first_blocker=/^[A-Z0-9_:]+$/.test(e.message)?e.message:'PREFLIGHT_CHECK_FAILED';process.exitCode=1;}).finally(()=>{report.checks=checks;G.write(receiptFile,report);console.log(JSON.stringify({terminal:report.terminal,checks:Object.keys(checks).length,first_blocker:report.first_blocker,receipt_path:receiptFile,receipt_sha256:P.sha256(fs.readFileSync(receiptFile)),real_heldout_generation:0,heldout_subjects_executed:0}));});
