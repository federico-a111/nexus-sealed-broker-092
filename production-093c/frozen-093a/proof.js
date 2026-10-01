'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),cp=require('node:child_process');
const P=require('./primitives'),S=require('./schema'),G=require('./generator'),V=require('./validator');
const clone=G.clone;
const root=path.resolve(process.argv[2]||'DEV093A-proof');
const referenceFile=path.resolve(process.argv[3]||path.join(__dirname,'../../30-09-2026 (NEXUS)/092B_PUBLIC_SYNTHETIC_HARNESS_GENERATOR_V2.js'));
const receiptFile=path.resolve(process.argv[4]||path.join(root,'receipt-093a.json'));
const report={unit:'093A_PUBLIC_PRODUCTION_BRIDGE_DEV_PROOF',scope:S.SCOPE,terminal:'BLOCKED',node_executable:process.execPath,node_version:process.version,real_heldout_generation:0,heldout_subjects_executed:0,real_ai_subjects_executed:0,external_packages_used:false,frozen_092b_reinterpreted:false,historical_roots_modified:false,ceremony_091_retried:false};
const checks={};
function check(name,fn){fn();checks[name]='PASS';}
function rejects(fn){assert.throws(fn);}
function json(file){return JSON.parse(fs.readFileSync(file,'utf8'));}
function collectFiles(dir,prefix='') {return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?collectFiles(path.join(dir,e.name),prefix+e.name+'/'):[prefix+e.name]);}
function recommit(target,caseId) {
  const f=G.load(target),c=f.commitments.find(c=>c.case_id===caseId);
  c.manifest_sha256=c.run_ids.map(id=>G.hash(json(path.join(target,'controller','manifests',id+'.json'))));
  const item={...c};delete item.leaf_sha256;c.leaf_sha256=G.hash(item);f.merkle_root=P.merkleRoot(f.commitments.map(c=>c.leaf_sha256));
  G.write(path.join(target,'public','freeze.json'),f);
}
function runDev(m,label,mode) {
  const subjectRoot=path.join(root,'dev-subject-surfaces',label),env=G.reveal(root,m.run_id,subjectRoot);
  const allowed=[...['transport.json',m.packet_ref,m.contract_ref],...json(path.join(subjectRoot,m.packet_ref)).evidence_refs.map(r=>`cases/${m.case_id}/${r.ref}`)].sort();
  assert.deepEqual(collectFiles(subjectRoot).sort(),allowed);
  assert(P.verifyProof(env.commitment.leaf_sha256,env.inclusion_proof,env.merkle_root));
  assert(!JSON.stringify(env).includes('oracle_salt_hex'));assert(!JSON.stringify(env).includes('seed_hex'));
  const result=cp.spawnSync(process.execPath,[path.join(__dirname,'dev-subject.js'),subjectRoot,mode],{cwd:subjectRoot,env:{SystemRoot:process.env.SystemRoot||'',PATH:path.dirname(process.execPath)},encoding:'utf8',timeout:10000});
  assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),mode==='complete'?'COMPLETE':'BLOCKED');
  const startedFile=path.join(subjectRoot,m.started_destination),startedBytes=fs.readFileSync(startedFile),started=JSON.parse(startedBytes),final=json(path.join(subjectRoot,m.capture_destination));
  const output=mode==='complete'?json(path.join(subjectRoot,m.output_destination)):null;
  V.validateCapture(m,started,final,output,startedBytes);
  return {subjectRoot,env,started,startedBytes,final,output};
}
try {
  check('node_syntax_all_sources',()=>{for(const name of ['primitives.js','schema.js','generator.js','validator.js','dev-subject.js','proof.js']){const r=cp.spawnSync(process.execPath,['--check',path.join(__dirname,name)],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);}});
  check('sha256_sentinel',()=>assert.equal(P.sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
  check('canonical_serialization',()=>{const a={z:[{b:2,a:1}],a:'ñ'},b={a:'ñ',z:[{a:1,b:2}]};assert.equal(P.canonical(a),P.canonical(b));assert.equal(G.hash(a),G.hash(b));});
  check('frozen_092b_blob_identity',()=>assert.equal(G.identity(referenceFile).blob,'c27e4f80bf78d5ead7ad07c148afd50a1e2deff1'));
  check('092b_algorithms_byte_identical',()=>{const original=fs.readFileSync(referenceFile,'utf8'),newSource=fs.readFileSync(path.join(__dirname,'primitives.js'),'utf8');for(const [a,b] of [['function canonical','function makeCase'],['function merkleRoot','function loadSeed']])assert(newSource.includes(original.slice(original.indexOf(a),original.indexOf(b))));});
  const bank=G.makeBank(root,crypto.randomBytes(32)),f=bank.freeze;
  const freezeFile=path.join(root,'public','freeze.json'),frozenBytes=fs.readFileSync(freezeFile);
  report.source=G.sourceIdentities();report.source_bundle_sha256=G.hash(report.source);report.commitment_index_sha256=P.sha256(frozenBytes);report.merkle_root=f.merkle_root;report.run_order_sha256=f.run_order_sha256;report.reserve_order_sha256=f.reserve_order_sha256;
  check('full_bank_structural_validation',()=>{report.full_bank=V.validateBank(root);});
  check('validator_no_oracle_access',()=>{const original=fs.readFileSync;fs.readFileSync=function(file,...args){assert(!/sealed-core|oracle|seed/i.test(String(file)),'VALIDATOR_SEALED_CORE_READ');return original.call(this,file,...args);};try{V.validateBank(root);}finally{fs.readFileSync=original;}});
  check('salted_commitment_and_seed_separation',()=>{
    assert.equal(new Set(bank.cases.map(c=>c.salt.toString('hex'))).size,32);
    for(const c of bank.cases){assert.equal(c.salt.length,32);assert.equal(c.caseSeed.length,32);const cc=f.commitments.find(x=>x.case_id===c.caseId);assert.equal(P.sha256(c.caseSeed),cc.seed_commitment_sha256);assert.notEqual(P.sha256(P.canonical(c.oracle)),cc.oracle_commitment_sha256);assert.notEqual(P.oracleCommitment(c.caseId+'changed',c.oracle,c.salt),cc.oracle_commitment_sha256);assert.notEqual(P.oracleCommitment(c.caseId,c.oracle,Buffer.alloc(32)),cc.oracle_commitment_sha256);assert(!frozenBytes.includes(c.salt.toString('hex')));assert(!frozenBytes.includes(c.caseSeed.toString('hex')));}
  });
  check('packet_contract_evidence_hiding_nonces',()=>{
    const nonces=[];
    for(const c of bank.cases){nonces.push(c.packet.disclosure_nonce,c.contract.disclosure_nonce);for(const [ref,bytes] of Object.entries(c.evidence)){const nonce=ref.endsWith('.js')?/^\/\/ fixture nonce: ([a-f0-9]{64})/.exec(bytes)[1]:JSON.parse(bytes).fixture_nonce;nonces.push(nonce);assert.notEqual(nonce,c.salt.toString('hex'));assert(!frozenBytes.includes(nonce));}const p=clone(c.packet);p.disclosure_nonce='0'.repeat(64);assert.notEqual(G.hash(p),G.hash(c.packet));const broken=clone(c.contract);broken.disclosure_nonce=null;rejects(()=>V.validateContract(broken,c.packet));}
    assert(nonces.every(n=>/^[a-f0-9]{64}$/.test(n)));assert.equal(new Set(nonces).size,nonces.length);report.hiding_nonce_count=nonces.length;
    const c2=bank.cases.filter(c=>c.classId==='C2');let candidates=0;
    for(const c of c2){const committed=c.packet.evidence_refs.find(r=>r.ref==='runtime/state.json').sha256;for(let observed=101;observed<=2160;observed++){assert.notEqual(G.hash({observed_worker_count:observed}),committed);assert.notEqual(G.hash({observed_worker_count:observed,fixture_nonce:'0'.repeat(64)}),committed);candidates+=2;}}
    report.low_entropy_c2_dictionary_candidates_rejected=candidates;
  });
  check('reserve_selection_and_order',()=>{
    for(const cls of S.CLASSES){const state=clone(f),trace=[];for(let i=0;i<4;i++){const id=G.selectReserve(state,cls,{verdict:'NO_EVALUABLE',independent:true,literal_reason:'DEV_STRUCTURAL_INVALIDITY',subject_outcome_used:false});assert.equal(id,f.reserve_order[cls][i]);state.reserve_state[id].used=true;trace.push({id,used:true,exposed:false});}rejects(()=>G.selectReserve(state,cls,{verdict:'NO_EVALUABLE',independent:true,literal_reason:'DEV',subject_outcome_used:false}));G.write(path.join(root,'dev-reserve-traces',cls+'.json'),trace);rejects(()=>G.selectReserve(f,cls,{verdict:'FAIL',independent:true,literal_reason:'wrong answer',subject_outcome_used:true}));}
  });
  const negatives={};
  function negative(name,mutate){const target=path.join(root,'dev-negative-banks',name);fs.mkdirSync(target,{recursive:true});fs.cpSync(path.join(root,'public'),path.join(target,'public'),{recursive:true});fs.cpSync(path.join(root,'controller','cases'),path.join(target,'controller','cases'),{recursive:true});fs.cpSync(path.join(root,'controller','manifests'),path.join(target,'controller','manifests'),{recursive:true});fs.cpSync(path.join(root,'controller','runs'),path.join(target,'controller','runs'),{recursive:true});mutate(target);rejects(()=>V.validateBank(target));negatives[name]='REJECT';}
  negative('wrong_packet_hash',target=>{const id=f.commitments[0].case_id,p=path.join(target,'controller','cases',id,'packet.json'),packet=json(p);packet.task+=' corrupted';G.write(p,packet);});
  negative('c3_ab_evidence_mismatch',target=>{const c=f.commitments.find(c=>c.class_id==='C3'),id=c.run_ids.find(id=>id.includes('-B-')),file=path.join(target,'controller','manifests',id+'.json'),m=json(file);m.evidence_sha256[0]='0'.repeat(64);G.write(file,m);recommit(target,c.case_id);});
  negative('missing_final_capture_field',target=>{const c=f.commitments[0],id=c.run_ids[0],file=path.join(target,'controller','manifests',id+'.json'),m=json(file);m.lifecycle.final_schema.required=m.lifecycle.final_schema.required.filter(x=>x!=='actor_call_count');G.write(file,m);recommit(target,c.case_id);});
  negative('wrong_manifest_cardinality',target=>fs.unlinkSync(path.join(target,'controller','manifests',f.run_order[0]+'.json')));
  check('all_contract_and_manifest_required_field_deletions',()=>{
    let n=0;for(const c of bank.cases){for(const field of Object.keys(c.contract)){const broken=clone(c.contract);delete broken[field];rejects(()=>V.validateContract(broken,c.packet));n++;}}
    const c=f.commitments[0],m=bank.runs.find(m=>m.case_id===c.case_id);for(const field of Object.keys(m)){const broken=clone(m);delete broken[field];rejects(()=>V.validateManifest(broken,c,f,path.join(root,'controller'),new Set()));n++;}
    report.required_field_deletion_rejections=n;
  });
  check('class_specific_negative_controls',()=>{for(const c of bank.cases){const broken=clone(c.contract);if(c.classId==='C1')broken.class_spec.planted_defect_count=0;if(c.classId==='C2')broken.class_spec.requires_literal_observation=false;if(c.classId==='C3')broken.class_spec.equalized_evidence=false;if(c.classId==='C4')broken.class_spec.actor_counter='TOOL_CALL';rejects(()=>V.validateContract(broken,c.packet));}});
  check('pre_first_subject_revalidation',()=>assert.equal(V.validateBank(root).verdict,'PASS'));
  const runs=[];
  check('full_cardinality_complete_lifecycle',()=>{
    for(const [i,m] of bank.runs.entries()) {
      const r=runDev(m,m.run_id,'complete');runs.push({...r,manifest:m});
      G.write(path.join(root,'sealed-outputs',m.run_id+'.json'),r.output);G.write(path.join(root,'sealed-outputs',m.run_id+'.capture.json'),r.final);
      if(i===0){rejects(()=>G.grade(root,m.run_id));rejects(()=>G.openOracle(root,m.case_id));}
    }
    assert.equal(runs.length,192);report.dev_processes_complete=192;
  });
  check('blocked_before_and_after_packet_all_classes',()=>{
    const examples=[];for(const cls of S.CLASSES){const m=bank.runs.find(m=>m.class_id===cls);for(const mode of ['blocked-pre','blocked-post']){const r=runDev(m,m.run_id+'-'+mode,mode);assert.equal(r.final.subject_packet_consumed,mode==='blocked-post');examples.push({class_id:cls,mode,started_sha256:r.final.started_sha256,capture_sha256:G.hash(r.final),blocker:r.final.blocker,blocker_stage:r.final.blocker_stage});}}
    report.blocked_lifecycle_examples=examples;report.dev_processes_blocked=8;
  });
  check('c3_actual_two_arm_evidence_bytes',()=>{
    let count=0;for(const c of f.commitments.filter(c=>c.class_id==='C3')){const rr=runs.filter(r=>r.manifest.case_id===c.case_id);const packet=json(path.join(rr[0].subjectRoot,rr[0].manifest.packet_ref));for(const ref of packet.evidence_refs){const bytes=fs.readFileSync(path.join(rr[0].subjectRoot,'cases',c.case_id,ref.ref));for(const r of rr)assert.deepEqual(fs.readFileSync(path.join(r.subjectRoot,'cases',c.case_id,ref.ref)),bytes);}count+=rr.length;}report.c3_delivery_runs_verified=count;
  });
  check('c4_actor_count_and_tool_exclusion',()=>{const rr=runs.filter(r=>r.manifest.class_id==='C4');assert.equal(rr.length,48);for(const r of rr){assert.equal(r.final.actor_call_count,1);assert(r.final.tool_call_count>1);assert.equal(r.final.actor_events.filter(e=>e.type==='AI_ACTOR_INVOCATION').length,1);const broken=clone(r.final);broken.actor_call_count=broken.tool_call_count;rejects(()=>V.validateCapture(r.manifest,r.started,broken,r.output,r.startedBytes));}report.c4_simulated_actor_counts_verified=48;});
  check('final_capture_required_field_deletions',()=>{const r=runs[0];for(const field of S.FINAL_FIELDS){const broken=clone(r.final);delete broken[field];rejects(()=>V.validateCapture(r.manifest,r.started,broken,r.output,r.startedBytes));}report.final_field_deletion_rejections=S.FINAL_FIELDS.length;});
  check('lifecycle_provenance_negative_controls',()=>{const r=runs[0];const badStarted=clone(r.started);badStarted.subject_packet_consumed=true;rejects(()=>V.validateCapture(r.manifest,badStarted,r.final,r.output,r.startedBytes));const badFinal=clone(r.final);badFinal.blocker='unexpected';rejects(()=>V.validateCapture(r.manifest,r.started,badFinal,r.output,r.startedBytes));const blocked=runDev(r.manifest,r.manifest.run_id+'-blocker-negative','blocked-pre');const missing=clone(blocked.final);missing.blocker=null;rejects(()=>V.validateCapture(r.manifest,blocked.started,missing,null,blocked.startedBytes));});
  check('arm_b_pre_second_actor_routing',()=>{
    const r=runs.find(r=>r.manifest.arm==='B'&&r.manifest.class_id==='C3'),capture=clone(r.final);
    const terminal=capture.events.pop();const j=capture.events.length;capture.events.push({index:j,type:'EVIDENCE_NEED_JUSTIFICATION'});const second=j+1;capture.events.push({index:second,type:'AI_ACTOR_INVOCATION',simulated:true});terminal.index=second+1;capture.events.push(terminal);
    capture.actor_events.push({type:'AI_ACTOR_INVOCATION',actor_id:'CLAUDE',simulated:true,event_index:second});capture.actor_call_count=2;capture.material_call_count++;
    capture.routing={decision:'DELEGATE',evidence_need:'DEV independent source-precedence audit',justification_event:j,second_actor_event:second,mechanism:'ADVERSARIAL_AUDIT',independent_first_pass:true};
    V.validateCapture(r.manifest,r.started,capture,r.output,r.startedBytes);
    const broken=clone(capture);broken.routing.justification_event=second+1;assert(V.validateCapture(r.manifest,r.started,broken,r.output,r.startedBytes).treatment_violations.includes('PRE_SECOND_ACTOR_JUSTIFICATION_MISSING_OR_LATE'));
    broken.routing.justification_event=j;broken.routing.evidence_need=null;assert(V.validateCapture(r.manifest,r.started,broken,r.output,r.startedBytes).treatment_violations.includes('PRE_SECOND_ACTOR_JUSTIFICATION_MISSING_OR_LATE'));
    G.write(path.join(root,'dev-routing-captures','pre-second-actor.json'),capture);
  });
  check('sealed_grade_and_post_grade_open_oracle',()=>{
    let grades=0,opened=0;for(const c of f.commitments){G.sealComparison(root,c.case_id);rejects(()=>G.openOracle(root,c.case_id));const results=c.run_ids.map(id=>G.grade(root,id));assert(results.every(g=>g.verdict==='PASS'&&g.oracle_commitment_verified));G.write(path.join(root,'controller','grades',c.case_id+'.json'),results);const audit=G.openOracle(root,c.case_id);assert(audit.oracle_commitment_verified);grades+=6;opened++;}report.dev_grades_pass=grades;report.post_grade_oracle_audits=opened;
  });
  check('sealed_output_tamper_rejected',()=>{const r=runs[0],file=path.join(root,'sealed-outputs',r.manifest.run_id+'.json'),bytes=fs.readFileSync(file);try{fs.writeFileSync(file,'{}');rejects(()=>G.grade(root,r.manifest.run_id));}finally{fs.writeFileSync(file,bytes);}});
  check('bad_output_and_c4_count_fail_deterministic_grader',()=>{
    for(const cls of S.CLASSES){const r=runs.find(r=>r.manifest.class_id===cls),c=f.commitments.find(c=>c.case_id===r.manifest.case_id),file=path.join(root,'sealed-outputs',r.manifest.run_id+'.json'),captureFile=path.join(root,'sealed-outputs',r.manifest.run_id+'.capture.json'),sealFile=path.join(root,'controller','seals',c.case_id+'.json');const bytes=fs.readFileSync(file),capBytes=fs.readFileSync(captureFile),sealBytes=fs.readFileSync(sealFile);try{let output=clone(r.output);if(cls==='C1')output.replacement_source=output.replacement_source.replace('n > ','n >= ');if(cls==='C2')output.observed++;if(cls==='C3')output.source_id='wrong';if(cls==='C4')output.value++;G.write(file,output);G.sealComparison(root,c.case_id);assert.equal(G.grade(root,r.manifest.run_id).verdict,'FAIL');if(cls==='C4'){fs.writeFileSync(file,bytes);const wrongCount=clone(r.final);wrongCount.actor_call_count=2;G.write(captureFile,wrongCount);G.sealComparison(root,c.case_id);assert.equal(G.grade(root,r.manifest.run_id).verdict,'FAIL');}}finally{fs.writeFileSync(file,bytes);fs.writeFileSync(captureFile,capBytes);fs.writeFileSync(sealFile,sealBytes);}}
  });
  check('blocked_capture_deterministic_no_evaluable',()=>{const r=runs[0],c=f.commitments.find(c=>c.case_id===r.manifest.case_id),file=path.join(root,'sealed-outputs',r.manifest.run_id+'.json'),capFile=path.join(root,'sealed-outputs',r.manifest.run_id+'.capture.json'),sealFile=path.join(root,'controller','seals',c.case_id+'.json'),outputBytes=fs.readFileSync(file),capBytes=fs.readFileSync(capFile),sealBytes=fs.readFileSync(sealFile);const blocked=runDev(r.manifest,r.manifest.run_id+'-blocked-grade','blocked-post');try{G.write(file,null);G.write(capFile,blocked.final);G.sealComparison(root,c.case_id);assert.equal(G.grade(root,r.manifest.run_id).verdict,'NO_EVALUABLE');}finally{fs.writeFileSync(file,outputBytes);fs.writeFileSync(capFile,capBytes);fs.writeFileSync(sealFile,sealBytes);}});
  check('c4_gradeable_second_actor_is_fail_not_no_evaluable',()=>{
    const r=runs.find(r=>r.manifest.class_id==='C4'&&r.manifest.arm==='B'),capture=clone(r.final),terminal=capture.events.pop(),j=capture.events.length;
    capture.events.push({index:j,type:'EVIDENCE_NEED_JUSTIFICATION'});capture.events.push({index:j+1,type:'AI_ACTOR_INVOCATION',simulated:true});terminal.index=j+2;capture.events.push(terminal);
    capture.actor_events.push({type:'AI_ACTOR_INVOCATION',actor_id:'CLAUDE',simulated:true,event_index:j+1});capture.actor_call_count=2;capture.material_call_count++;
    capture.routing={decision:'DELEGATE',evidence_need:'DEV unnecessary second AI invocation',justification_event:j,second_actor_event:j+1,mechanism:'INTEGRATION',independent_first_pass:null};
    const validated=V.validateCapture(r.manifest,r.started,capture,r.output,r.startedBytes);assert.equal(validated.verdict,'PASS');assert(validated.treatment_violations.includes('C4_NO_DELEGATION_VIOLATION'));
    const c=f.commitments.find(c=>c.case_id===r.manifest.case_id),capFile=path.join(root,'sealed-outputs',r.manifest.run_id+'.capture.json'),sealFile=path.join(root,'controller','seals',c.case_id+'.json'),capBytes=fs.readFileSync(capFile),sealBytes=fs.readFileSync(sealFile);
    try{G.write(capFile,capture);G.sealComparison(root,c.case_id);assert.equal(G.grade(root,r.manifest.run_id).verdict,'FAIL');G.write(path.join(root,'dev-routing-captures','c4-valid-extra-actor.json'),capture);}finally{fs.writeFileSync(capFile,capBytes);fs.writeFileSync(sealFile,sealBytes);}
  });
  check('frozen_index_and_sources_unchanged',()=>{assert.deepEqual(fs.readFileSync(freezeFile),frozenBytes);assert.deepEqual(G.sourceIdentities(),report.source);assert.equal(G.identity(referenceFile).blob,'c27e4f80bf78d5ead7ad07c148afd50a1e2deff1');assert.equal(V.validateBank(root).verdict,'PASS');});
  report.negative_controls=negatives;report.checks=checks;report.synthetic_cardinality={primary:16,reserve:16,total:32,manifests:192};
  report.actual_runtime_launch_proof='NOT_RETESTED: inherited frozen DEV witnesses, no AI launch in 093A';
  report.isolation_claim='NO_NEW_OS_OR_BROKER_ISOLATION_CLAIM: 092B/092X receipts unchanged; local DEV simulation only';
  report.terminal='READY_FOR_HUMAN_AUTH';report.first_blocker='NONE';
} catch(e) {report.first_blocker=e.message;report.checks=checks;process.exitCode=1;}
G.write(receiptFile,report);
console.log(JSON.stringify({terminal:report.terminal,first_blocker:report.first_blocker,checks:Object.keys(checks).length,receipt_path:receiptFile,receipt_sha256:P.sha256(fs.readFileSync(receiptFile)),real_heldout_generation:0,heldout_subjects_executed:0}));
