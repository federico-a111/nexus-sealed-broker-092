'use strict';
// Treatment-blind: no seed, oracle, expected answer, controller grading or generator imports.
const fs=require('node:fs'),path=require('node:path');
const P=require('./primitives'),S=require('./schema');
const hash=v=>P.sha256(P.canonical(v));
const same=(a,b)=>P.canonical(a)===P.canonical(b);
function requireTrue(v,code) {if(!v)throw Error(code);}
function fields(o,names,code) {requireTrue(o&&typeof o==='object',code);for(const f of names)requireTrue(Object.hasOwn(o,f),`${code}:${f}`);}
function string(v,code){requireTrue(typeof v==='string'&&v.trim().length>0,code);}
function ref(root,relative) {
  string(relative,'PATH_REQUIRED');requireTrue(!path.isAbsolute(relative)&&!relative.includes('\\')&&!relative.split('/').includes('..'),'UNSAFE_REF');
  const resolved=path.resolve(root,relative),base=path.resolve(root)+path.sep;
  requireTrue(resolved.startsWith(base),'PATH_ESCAPE');
  let current=path.resolve(root);
  for(const part of relative.split('/')) { current=path.join(current,part); if(fs.existsSync(current))requireTrue(!fs.lstatSync(current).isSymbolicLink(),'SYMLINK_REF'); }
  return resolved;
}
function read(root,relative) {return JSON.parse(fs.readFileSync(ref(root,relative),'utf8'));}
function validateContract(c,p) {
  fields(c,['case_id','class_id','family','version','scope','disclosure_nonce','operation','allowed_evidence','forbidden_surfaces','output_schema','success_terminal','terminal_capture','grader_input','class_spec'],'CONTRACT_REQUIRED');
  requireTrue(c.case_id===p.case_id&&c.class_id===p.class_id&&c.version===S.VERSION&&c.scope===S.SCOPE,'CONTRACT_IDENTITY');
  requireTrue(/^[a-f0-9]{64}$/.test(c.disclosure_nonce)&&/^[a-f0-9]{64}$/.test(p.disclosure_nonce)&&c.disclosure_nonce!==p.disclosure_nonce,'DISCLOSURE_NONCE');
  string(c.operation,'OPERATION');requireTrue(c.operation.length>70&&c.operation===p.task,'CONCRETE_OPERATION');
  requireTrue(same(c.allowed_evidence,p.evidence_refs)&&c.allowed_evidence.length>0,'ALLOWED_INPUTS');
  requireTrue(same(c.forbidden_surfaces,S.FORBIDDEN),'FORBIDDEN_SURFACES');
  requireTrue(same(c.output_schema,S.OUTPUT_SCHEMAS[c.class_id]),'OUTPUT_SCHEMA');
  requireTrue(c.success_terminal==='COMPLETE'&&same(c.terminal_capture,S.CAPTURE_SCHEMA),'CAPTURE_SCHEMA');
  fields(c.grader_input,['output','capture','sealed_oracle','expected_answer_in_subject_contract'],'GRADER_INPUT');
  requireTrue(c.grader_input.output==='run-specific output.json'&&c.grader_input.capture==='run-specific final.json'&&c.grader_input.expected_answer_in_subject_contract===false&&c.grader_input.sealed_oracle==='controller_after_comparison_unit_sealed','GRADER_SEPARATION');
  const s=c.class_spec;
  requireTrue(c.family===s.family,'FAMILY_BINDING');
  if(c.class_id==='C1')requireTrue(s.family==='ephemeral_mini_repo'&&s.planted_defect_count===1&&s.hidden_test_grading===true&&s.entry_file==='repo/filter.js'&&s.workspace==='subject_case_only'&&s.output_language==='whitelisted_commonjs_integer_comparison'&&p.evidence_refs.some(r=>r.ref===s.entry_file),'C1_REPO');
  else if(c.class_id==='C2')requireTrue(s.family==='bounded_local_runtime_state'&&s.requires_literal_observation===true&&s.persistent_system_mutation===false&&same(s.fixture_paths,['runtime/config.json','runtime/state.json']),'C2_RUNTIME');
  else if(c.class_id==='C3')requireTrue(s.family==='equalized_claims_contradictions_provenance'&&s.equalized_evidence===true&&s.external_acquisition===false&&same(s.answer_tuple,['accepted_claim','rejected_claim','source_id']),'C3_EQUALIZED');
  else if(c.class_id==='C4')requireTrue(s.family==='deterministic_single_actor_control'&&s.no_delegation===true&&s.actor_counter==='AI_ACTOR_INVOCATION'&&s.oracle_actor_count_grading===true,'C4_COUNTER');
  else throw Error('CLASS');
}
function validateManifest(m,c,freeze,root,destinations) {
  const required=['run_id','case_id','class_id','arm','replicate','version','scope','role','required_actor','required_runtime','permitted_actors','packet_ref','packet_sha256','contract_ref','contract_sha256','evidence_sha256','output_destination','capture_destination','started_destination','writable_scope','fresh_context','other_arm_output_access','lifecycle','routing','c4_actor_call_count_grading','actor_counter_semantics','order_index','run_order_sha256'];
  fields(m,required,'MANIFEST_REQUIRED');
  requireTrue(m.case_id===c.case_id&&m.class_id===c.class_id&&m.role===c.role&&m.version===S.VERSION&&m.scope===S.SCOPE,'MANIFEST_IDENTITY');
  requireTrue(['A','B'].includes(m.arm)&&[1,2,3].includes(m.replicate)&&m.run_id===`${c.case_id}-${m.arm}-R${m.replicate}`,'ARM_REPLICATE');
  requireTrue(m.required_actor===S.BASELINES[c.class_id]&&same(m.required_runtime,S.RUNTIMES[m.required_actor]),'RUNTIME_ENTRY');
  requireTrue(same(m.permitted_actors,m.arm==='A'?[m.required_actor]:['CLASSIC','CLAUDE','NEXUS_PC']),'ACTOR_ENVELOPE');
  requireTrue(m.fresh_context===true&&m.other_arm_output_access===false,'ISOLATED_REPLICATES');
  requireTrue(m.packet_ref===`cases/${c.case_id}/packet.json`&&m.contract_ref===`cases/${c.case_id}/contract.json`,'PACKET_REF');
  requireTrue(m.packet_sha256===c.packet_sha256&&m.contract_sha256===c.contract_sha256&&same(m.evidence_sha256,c.evidence_sha256),'MANIFEST_HASHES');
  requireTrue(m.order_index===freeze.run_order.indexOf(m.run_id)&&m.run_order_sha256===freeze.run_order_sha256,'RUN_ORDER');
  requireTrue(m.lifecycle.first_step==='persist_STARTED_before_packet_or_evidence_read'&&m.lifecycle.started_packet_consumed===false&&same(m.lifecycle.final_schema,S.CAPTURE_SCHEMA),'LIFECYCLE');
  requireTrue(m.routing.allowed===(m.arm==='B')&&m.routing.no_delegation_valid===true&&m.routing.justification_before_second_actor===true&&same(m.routing.provenance_fields,['decision','evidence_need','justification_event','second_actor_event','mechanism','independent_first_pass']),'ROUTING_SCHEMA');
  requireTrue(m.c4_actor_call_count_grading===(c.class_id==='C4')&&m.actor_counter_semantics==='AI_ACTOR_INVOCATION','ACTOR_COUNT_SCHEMA');
  for(const [key,name] of [['output_destination','output.json'],['capture_destination','final.json'],['started_destination','started.json']]) {
    requireTrue(m[key]===`runs/${m.run_id}/${name}`,'DESTINATION_BINDING');
    requireTrue(!destinations.has(m[key]),'SHARED_DESTINATION');destinations.add(m[key]);
    const dest=ref(root,m[key]);fs.accessSync(path.dirname(dest),fs.constants.W_OK);
  }
  requireTrue(m.writable_scope===`runs/${m.run_id}`,'WRITE_SCOPE');
}
function validateBank(root) {
  const f=read(root,'public/freeze.json');
  fields(f,['protocol','scope','version','source','primary_count','reserve_count','case_count','manifest_count','k','baselines','runtimes','run_order','run_order_sha256','reserve_order','reserve_order_sha256','reserve_rule','reserve_state','grading_rules','commitments','merkle_root','real_heldout_generation','heldout_subjects_executed'],'FREEZE_REQUIRED');
  requireTrue(f.protocol==='093A-PRODUCTION-CONTRACT-DEV-V3'&&f.version===S.VERSION&&f.scope===S.SCOPE,'DEV_SCOPE');
  requireTrue(f.case_count===32&&f.primary_count===16&&f.reserve_count===16&&f.manifest_count===192&&f.k===3&&f.commitments.length===32,'CARDINALITY');
  requireTrue(same(f.baselines,S.BASELINES)&&same(f.runtimes,S.RUNTIMES)&&same(f.grading_rules,S.GRADING_RULES),'FROZEN_RULES');
  requireTrue(f.real_heldout_generation===0&&f.heldout_subjects_executed===0,'HELDOUT_BOUNDARY');
  requireTrue(f.source.length===6&&f.source.every(s=>/^[a-f0-9]{64}$/.test(s.sha256)&&/^[a-f0-9]{40}$/.test(s.blob)),'SOURCE_IDENTITIES');
  requireTrue(f.run_order.length===192&&new Set(f.run_order).size===192&&hash(f.run_order)===f.run_order_sha256,'ORDER_COMMITMENT');
  requireTrue(hash(f.reserve_order)===f.reserve_order_sha256&&f.reserve_rule===S.RESERVE_RULE,'RESERVE_ORDER_COMMITMENT');
  requireTrue(new Set(f.commitments.map(c=>c.case_id)).size===32,'CASE_UNIQUENESS');
  const destinations=new Set(),runIds=[],counts={};
  for(const [index,c] of f.commitments.entries()) {
    fields(c,['index','case_id','class_id','role','ordinal','version','scope','packet_sha256','contract_sha256','evidence_sha256','oracle_commitment_sha256','seed_commitment_sha256','manifest_sha256','run_ids','reserve_order_sha256','leaf_sha256'],'COMMITMENT_REQUIRED');
    requireTrue(c.index===index&&/^DEV093A-[0-9a-f]{24}$/.test(c.case_id)&&S.CLASSES.includes(c.class_id)&&['PRIMARY','RESERVE'].includes(c.role)&&[0,1,2,3].includes(c.ordinal),'CASE_METADATA');
    requireTrue(c.version===S.VERSION&&c.scope===S.SCOPE&&c.reserve_order_sha256===f.reserve_order_sha256,'CASE_VERSION');
    const leaf={...c};delete leaf.leaf_sha256;requireTrue(hash(leaf)===c.leaf_sha256,'LEAF_COMMITMENT');
    for(const k of ['packet_sha256','contract_sha256','oracle_commitment_sha256','seed_commitment_sha256'])requireTrue(/^[a-f0-9]{64}$/.test(c[k]),'COMMITMENT_FORMAT');
    counts[`${c.class_id}_${c.role}`]=(counts[`${c.class_id}_${c.role}`]||0)+1;
    const p=read(path.join(root,'controller'),`cases/${c.case_id}/packet.json`),contract=read(path.join(root,'controller'),`cases/${c.case_id}/contract.json`);
    fields(p,['case_id','class_id','version','scope','disclosure_nonce','task','evidence_refs'],'PACKET_REQUIRED');
    requireTrue(p.case_id===c.case_id&&p.class_id===c.class_id&&p.version===S.VERSION&&p.scope===S.SCOPE,'PACKET_IDENTITY');
    requireTrue(hash(p)===c.packet_sha256&&hash(contract)===c.contract_sha256&&c.packet_sha256!==c.contract_sha256,'PACKET_CONTRACT_COMMITMENTS');
    validateContract(contract,p);
    const evidence=p.evidence_refs.map(r=>{fields(r,['ref','sha256','encoding'],'EVIDENCE_REF');requireTrue(r.encoding==='utf8','EVIDENCE_ENCODING');const bytes=fs.readFileSync(ref(path.join(root,'controller','cases',c.case_id),r.ref));requireTrue(P.sha256(bytes)===r.sha256,'EVIDENCE_HASH');if(r.ref.endsWith('.js'))requireTrue(/^\/\/ fixture nonce: [a-f0-9]{64}\n/.test(bytes.toString('utf8')),'EVIDENCE_NONCE');else requireTrue(/^[a-f0-9]{64}$/.test(JSON.parse(bytes).fixture_nonce),'EVIDENCE_NONCE');return r.sha256;});
    requireTrue(same(evidence,c.evidence_sha256)&&new Set(p.evidence_refs.map(r=>r.ref)).size===p.evidence_refs.length,'EVIDENCE_COMMITMENT');
    requireTrue(c.run_ids.length===6&&new Set(c.run_ids).size===6&&c.manifest_sha256.length===6,'CASE_MANIFEST_CARDINALITY');
    const pairs=new Set();
    for(const [i,id] of c.run_ids.entries()) {
      const m=read(path.join(root,'controller'),`manifests/${id}.json`);
      requireTrue(hash(m)===c.manifest_sha256[i],'MANIFEST_COMMITMENT');
      validateManifest(m,c,f,path.join(root,'controller'),destinations);pairs.add(`${m.arm}${m.replicate}`);runIds.push(id);
    }
    requireTrue(pairs.size===6,'AB_REPLICATES');
    const ms=c.run_ids.map(id=>read(path.join(root,'controller'),`manifests/${id}.json`));
    requireTrue(ms.every(m=>m.packet_sha256===ms[0].packet_sha256&&m.contract_sha256===ms[0].contract_sha256&&same(m.evidence_sha256,ms[0].evidence_sha256)),'AB_PACKET_EVIDENCE_IDENTITY');
  }
  requireTrue(runIds.length===192&&new Set(runIds).size===192&&same([...runIds].sort(),[...f.run_order].sort()),'FULL_MANIFEST_CARDINALITY');
  requireTrue(fs.readdirSync(path.join(root,'controller','manifests')).filter(n=>n.endsWith('.json')).length===192,'ON_DISK_MANIFEST_CARDINALITY');
  for(const cls of S.CLASSES) {
    requireTrue(counts[`${cls}_PRIMARY`]===4&&counts[`${cls}_RESERVE`]===4,'CLASS_CARDINALITY');
    const reserve=f.commitments.filter(c=>c.class_id===cls&&c.role==='RESERVE').map(c=>c.case_id).sort();
    requireTrue(same(f.reserve_order[cls],reserve)&&reserve.every(id=>same(f.reserve_state[id],{used:false,exposed:false})),'RESERVE_READY');
    for(const role of ['PRIMARY','RESERVE'])requireTrue(new Set(f.commitments.filter(c=>c.class_id===cls&&c.role===role).map(c=>c.ordinal)).size===4,'CLASS_ORDINALS');
  }
  requireTrue(P.merkleRoot(f.commitments.map(c=>c.leaf_sha256))===f.merkle_root,'MERKLE_ROOT');
  return {verdict:'PASS',cases:32,manifests:192,per_class:counts,oracle_semantics_read:false,expected_answers_read:false};
}
function validateCapture(m,started,final,output,startedBytes) {
  fields(started,['run_id','case_id','arm','replicate','status','subject_packet_consumed','actor_id','model_id','runtime_identity','event_index'],'STARTED_REQUIRED');
  fields(final,S.FINAL_FIELDS,'FINAL_REQUIRED');
  for(const k of ['run_id','case_id','arm','replicate'])requireTrue(started[k]===m[k]&&final[k]===m[k],'CAPTURE_RUN_IDENTITY');
  requireTrue(started.status==='STARTED'&&started.subject_packet_consumed===false&&started.event_index===0,'STARTED_BEFORE_PACKET');
  requireTrue(final.started_sha256===P.sha256(startedBytes),'STARTED_BINDING');
  requireTrue(final.packet_sha256===m.packet_sha256&&final.contract_sha256===m.contract_sha256,'CAPTURE_ARTIFACT_BINDING');
  for(const k of ['actor_id','model_id','runtime_identity']) {string(final[k],'PROVENANCE');requireTrue(final[k]===started[k],'IDENTITY_CONTINUITY');}
  requireTrue(final.actor_id===m.required_actor,'ACTOR_IDENTITY');
  requireTrue(typeof final.dev_simulation==='boolean','SIMULATION_ATTESTATION');
  if(final.dev_simulation)requireTrue(final.runtime_identity==='NON_AI_DEV_SIMULATOR'&&final.model_id==='NONE','DEV_RUNTIME_ATTESTATION');
  else requireTrue(final.runtime_identity===m.required_runtime.product&&final.model_id!=='NONE','REQUIRED_RUNTIME_GATE');
  requireTrue(typeof final.subject_packet_consumed==='boolean'&&['COMPLETE','BLOCKED'].includes(final.status),'TERMINAL_STATUS');
  for(const k of ['actor_call_count','tool_call_count','material_call_count','wall_ms','token_usage_proxy','substantive_human_relay_count'])requireTrue(Number.isFinite(final[k])&&final[k]>=0,'RESOURCE_PROVENANCE');
  for(const k of ['actor_call_count','tool_call_count','material_call_count','substantive_human_relay_count'])requireTrue(Number.isInteger(final[k]),'CALL_COUNT_INTEGER');
  requireTrue(Array.isArray(final.actor_events)&&Array.isArray(final.human_interventions)&&Array.isArray(final.events),'EVENT_PROVENANCE');
  requireTrue(final.events[0].type==='STARTED_PERSISTED'&&final.events[0].index===0,'LIFECYCLE_EVENT_ORDER');
  const consumed=final.events.find(e=>e.type==='PACKET_CONSUMED');
  requireTrue(final.subject_packet_consumed===Boolean(consumed)&&(!consumed||consumed.index>0),'PACKET_CONSUMPTION_ORDER');
  requireTrue(final.events.every((e,i)=>e.index===i)&&final.events.at(-1).type===final.status,'SEQUENCE');
  const actors=final.actor_events.filter(e=>e.type==='AI_ACTOR_INVOCATION');
  requireTrue(actors.every(e=>e.simulated===final.dev_simulation),'ACTOR_EVENT_SIMULATION_ATTESTATION');
  requireTrue(final.actor_call_count===actors.length&&actors.length>=1,'ACTOR_COUNTER_ONLY_AI');
  requireTrue(actors.every(e=>Number.isInteger(e.event_index)&&final.events[e.event_index]?.type==='AI_ACTOR_INVOCATION'),'ACTOR_EVENT_BINDING');
  // Observed treatment violations must remain gradeable failures, not structural NO_EVALUABLE.
  const violations=[];
  if(m.arm==='A'&&actors.length!==1)violations.push('ARM_A_SINGLE_ACTOR_VIOLATION');
  fields(final.routing,['decision','evidence_need','justification_event','second_actor_event','mechanism','independent_first_pass'],'ROUTING_CAPTURE');
  requireTrue(['NO_DELEGATION','DELEGATE'].includes(final.routing.decision),'ROUTING_DECISION_TYPE');
  requireTrue(final.routing.evidence_need===null||typeof final.routing.evidence_need==='string'&&final.routing.evidence_need.trim().length>0,'EVIDENCE_NEED_TYPE');
  for(const k of ['justification_event','second_actor_event'])requireTrue(final.routing[k]===null||Number.isInteger(final.routing[k])&&final.routing[k]>=0,'ROUTING_EVENT_TYPE');
  requireTrue(final.routing.independent_first_pass===null||typeof final.routing.independent_first_pass==='boolean','INDEPENDENCE_TYPE');
  if(actors.length>1) {
    if(m.arm!=='B')violations.push('DELEGATION_NOT_ALLOWED_IN_ARM_A');
    if(final.routing.decision!=='DELEGATE')violations.push('ROUTING_DECISION_INCONSISTENT');
    const j=final.routing.justification_event,s=final.routing.second_actor_event;
    if(!final.routing.evidence_need||!Number.isInteger(j)||!Number.isInteger(s)||j>=s||final.events[j]?.type!=='EVIDENCE_NEED_JUSTIFICATION'||final.events[s]?.type!=='AI_ACTOR_INVOCATION'||actors[1].event_index!==s)violations.push('PRE_SECOND_ACTOR_JUSTIFICATION_MISSING_OR_LATE');
    const mechanisms=m.class_id==='C3'?['DIVERSITY','DECOMPOSITION','ADVERSARIAL_AUDIT','INTEGRATION']:['ACCESS','OBSERVATION','TOOL_COMPLEMENTARITY','INTEGRATION'];
    if(!mechanisms.includes(final.routing.mechanism))violations.push('MECHANISM_ATTRIBUTION_MISSING');
    if(final.routing.mechanism==='ADVERSARIAL_AUDIT'&&final.routing.independent_first_pass!==true)violations.push('INDEPENDENT_AUDIT_PROVENANCE_MISSING');
  } else requireTrue(final.routing.decision==='NO_DELEGATION','SINGLE_ACTOR_ROUTING');
  if(m.class_id==='C4'&&actors.length!==1)violations.push('C4_NO_DELEGATION_VIOLATION');
  if(final.status==='COMPLETE') {
    requireTrue(final.subject_packet_consumed===true&&final.blocker===null&&final.blocker_stage===null,'COMPLETE_PROVENANCE');
    const schema=S.OUTPUT_SCHEMAS[m.class_id];fields(output,schema.required,'OUTPUT_REQUIRED');
    requireTrue(same(Object.keys(output).sort(),[...schema.required].sort()),'OUTPUT_SHAPE');
    for(const [key,type] of Object.entries(schema.properties))requireTrue(type==='integer'?Number.isInteger(output[key]):typeof output[key]===type,'OUTPUT_TYPE');
    requireTrue(final.output_sha256===hash(output),'OUTPUT_COMMITMENT');
  } else {string(final.blocker,'BLOCKER_LITERAL');string(final.blocker_stage,'BLOCKER_STAGE');requireTrue(output===null&&final.output_sha256===null,'BLOCKED_OUTPUT');}
  return {verdict:'PASS',terminal:final.status,oracle_semantics_read:false,treatment_violations:violations};
}
module.exports={validateBank,validateContract,validateManifest,validateCapture,requireTrue,ref};
if(require.main===module)console.log(JSON.stringify(validateBank(path.resolve(process.argv[2]))));
