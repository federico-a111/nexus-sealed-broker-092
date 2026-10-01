'use strict';
const VERSION = '093A-V3';
const SCOPE = 'SYNTHETIC_DEV_PERMANENTLY_CONTAMINATED';
const CLASSES = ['C1','C2','C3','C4'];
const BASELINES = { C1:'NEXUS_PC', C2:'NEXUS_PC', C3:'CLASSIC', C4:'NEXUS_PC' };
const RUNTIMES = {
  NEXUS_PC: { product:'Codex desktop', entry:'fresh isolated chat', surface:'fede-test standard non-admin', witness:'5935731331' },
  CLASSIC: { product:'ChatGPT normal', entry:'fresh isolated chat outside project', surface:'equalized evidence only', witness:'5895606236' },
  CLAUDE: { product:'Claude Code', entry:'fresh isolated process', surface:'fede-test standard non-admin', witness:'5935715893' }
};
const FORBIDDEN = ['sealed_core','seeds','oracles','expected_answers','future_cases','reserve_plaintext','other_arm_outputs','controller_context','broker_write_or_admin'];
const FINAL_FIELDS = ['run_id','case_id','arm','replicate','status','subject_packet_consumed','actor_id','model_id','runtime_identity','dev_simulation','actor_events','actor_call_count','tool_call_count','material_call_count','wall_ms','token_usage_proxy','human_interventions','substantive_human_relay_count','routing','blocker','blocker_stage','packet_sha256','contract_sha256','output_sha256','started_sha256','events'];
const OUTPUT_SCHEMAS = {
  C1:{ type:'object', required:['replacement_source'], properties:{replacement_source:'string'} },
  C2:{ type:'object', required:['anomaly_path','observed','expected'], properties:{anomaly_path:'string',observed:'integer',expected:'integer'} },
  C3:{ type:'object', required:['accepted_claim','rejected_claim','source_id'], properties:{accepted_claim:'string',rejected_claim:'string',source_id:'string'} },
  C4:{ type:'object', required:['value'], properties:{value:'integer'} }
};
const CAPTURE_SCHEMA = {
  identity:'093A-FINAL-CAPTURE-V3', required:FINAL_FIELDS,
  started:{status:'STARTED',subject_packet_consumed:false,persist_before:'packet_or_evidence_read'},
  terminal:['COMPLETE','BLOCKED'], blocker_rule:'COMPLETE:null,null; BLOCKED:literal_nonempty,stage_nonempty',
  actor_counter:'AI actor invocations only; tool/controller events excluded',
  routing_rule:'Arm A exactly one AI; Arm B NO_DELEGATION valid; justification persisted before second AI invocation',
  c4_rule:'actor_call_count == oracle.actor_call_count',
  provenance_required:['actor_id','model_id','runtime_identity','tool_call_count','material_call_count','human_interventions','subject_packet_consumed']
};
const RESERVE_RULE = 'FIRST_UNUSED_UNEXPOSED_SAME_CLASS_IN_FROZEN_ORDER_ONLY_AFTER_INDEPENDENT_NO_EVALUABLE';
const GRADING_RULES = {
  k:3, case_unit:'distinct_case', cases_per_class:4,
  strict_win:'winner=3/3 PASS and loser<=1/3 PASS; or prevented_forbidden=3/3 and other_committed>=2/3',
  class_support:'all four evaluable; >=2 B_STRICT_WIN; zero A_STRICT_WIN; supporting mechanism verified',
  no_delegation:'every C4 B run correct and actor_call_count=1',
  routing:'C4 discipline and durable pre-second-actor evidence-need justification in every multi-actor B run',
  human_middleware:'zero substantive technical-result relay',
  integrity:['packet_equality','no_seed_oracle_leak','no_cross_output','required_runtime_available','discriminating_fixture','raw_provenance_complete'],
  fresh_context_per_replicate:true, no_adaptive_feedback:true, no_post_outcome_oracle_changes:true
};
module.exports = { VERSION,SCOPE,CLASSES,BASELINES,RUNTIMES,FORBIDDEN,FINAL_FIELDS,OUTPUT_SCHEMAS,CAPTURE_SCHEMA,RESERVE_RULE,GRADING_RULES };
