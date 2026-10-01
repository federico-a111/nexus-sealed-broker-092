'use strict';
// Deterministic NON-AI DEV simulator. No genuine subject is invoked; this is not uplift evidence.
const fs=require('node:fs'),path=require('node:path');
const P=require('./primitives'),S=require('./schema');
const root=path.resolve(process.argv[2]),mode=process.argv[3]||'complete',t0=Date.now();
if(!['complete','blocked-pre','blocked-post'].includes(mode))throw Error('DEV_MODE');
const read=relative=>JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'));
const write=(relative,value)=>fs.writeFileSync(path.join(root,relative),P.canonical(value),'utf8');
const transport=read('transport.json'),m=transport.manifest;
if(m.scope!==S.SCOPE)throw Error('DEV_ONLY');
const started={run_id:m.run_id,case_id:m.case_id,arm:m.arm,replicate:m.replicate,status:'STARTED',subject_packet_consumed:false,
  actor_id:m.required_actor,model_id:'NONE',runtime_identity:'NON_AI_DEV_SIMULATOR',event_index:0};
// Only transport metadata was read. First persisted executable step precedes packet/evidence reads.
write(m.started_destination,started);
const events=[{index:0,type:'STARTED_PERSISTED'}],actorEvents=[];
function event(type,extra={}){const e={index:events.length,type,...extra};events.push(e);return e.index;}
const ai=event('AI_ACTOR_INVOCATION',{simulated:true});actorEvents.push({type:'AI_ACTOR_INVOCATION',simulated:true,actor_id:m.required_actor,event_index:ai});
let output=null,consumed=false,tools=0;
if(mode!=='blocked-pre') {
  const packet=read(m.packet_ref),contract=read(m.contract_ref);tools+=2;
  if(P.sha256(P.canonical(packet))!==m.packet_sha256||P.sha256(P.canonical(contract))!==m.contract_sha256)throw Error('SUBJECT_HASH');
  consumed=true;event('PACKET_CONSUMED');
  const evidence=ref=>{const bytes=fs.readFileSync(path.join(root,'cases',m.case_id,ref),'utf8');tools++;const r=packet.evidence_refs.find(r=>r.ref===ref);if(!r||P.sha256(bytes)!==r.sha256)throw Error('EVIDENCE_HASH');event('TOOL_CALL',{ref});return bytes;};
  if(mode==='complete') {
    if(m.class_id==='C1') {
      const source=evidence('repo/filter.js');
      const threshold=/strictly greater than (\d+)/.exec(contract.operation);
      if(!threshold||!source.includes('module.exports'))throw Error('SUBJECT_CONTRACT');
      output={replacement_source:`'use strict';\nmodule.exports = n => n > ${threshold[1]};\n`};
    } else if(m.class_id==='C2') {
      const config=JSON.parse(evidence('runtime/config.json')),state=JSON.parse(evidence('runtime/state.json'));
      output={anomaly_path:'runtime/state.json',observed:state.observed_worker_count,expected:config.expected_worker_count};
    } else if(m.class_id==='C3') {
      const corpus=JSON.parse(evidence('evidence/corpus.json')),trusted=corpus.sources.find(s=>s.kind==='primary'&&s.signed),mirror=corpus.sources.find(s=>s.kind==='mirror');
      output={accepted_claim:trusted.claim,rejected_claim:mirror.claim,source_id:trusted.id};
    } else if(m.class_id==='C4') {
      const input=JSON.parse(evidence('input/numbers.json'));output={value:input.values.reduce((a,b)=>a+b,0)%input.modulus};
    }
  }
}
const status=mode==='complete'?'COMPLETE':'BLOCKED';
if(output!==null)write(m.output_destination,output);
event(status);
const final={run_id:m.run_id,case_id:m.case_id,arm:m.arm,replicate:m.replicate,status,subject_packet_consumed:consumed,
  actor_id:m.required_actor,model_id:'NONE',runtime_identity:'NON_AI_DEV_SIMULATOR',dev_simulation:true,
  actor_events:actorEvents,actor_call_count:1,tool_call_count:tools,material_call_count:tools+1,wall_ms:Date.now()-t0,token_usage_proxy:0,
  human_interventions:[],substantive_human_relay_count:0,
  routing:{decision:'NO_DELEGATION',evidence_need:null,justification_event:null,second_actor_event:null,mechanism:null,independent_first_pass:null},
  blocker:status==='BLOCKED'?'DEV_INJECTED_BLOCKER':null,blocker_stage:status==='BLOCKED'?(consumed?'after_packet':'before_packet'):null,
  packet_sha256:m.packet_sha256,contract_sha256:m.contract_sha256,output_sha256:output===null?null:P.sha256(P.canonical(output)),
  started_sha256:P.sha256(fs.readFileSync(path.join(root,m.started_destination))),events};
write(m.capture_destination,final);
process.stdout.write(status+'\n');
