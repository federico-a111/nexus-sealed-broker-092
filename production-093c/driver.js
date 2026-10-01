'use strict';
const fs=require('node:fs'),path=require('node:path');
const B=require('./broker'),P=require('./primitives'),G=require('./generator'),C=require('./context');
class GitStore {
  constructor(){this.base=`https://api.github.com/repos/${B.policy.broker_repository}/contents/production-freezes/${C.bankId}`;}
  async request(ref,method='GET',body){
    const response=await fetch(this.base+'/'+ref.split('/').map(encodeURIComponent).join('/'),{method,headers:{Authorization:'Bearer '+process.env.GITHUB_TOKEN,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},body:body===undefined?undefined:JSON.stringify(body)});
    if(response.status===404&&method==='GET')return null;
    if(!response.ok)throw Error('DURABLE_BROKER_RECEIPT_API_FAILED');return response.json();
  }
  async getOptional(ref){const result=await this.request(ref);return result?JSON.parse(Buffer.from(result.content,'base64').toString('utf8')):null;}
  async get(ref){const result=await this.getOptional(ref);B.need(result,'DURABLE_RECEIPT_REQUIRED');return result;}
  async putImmutable(ref,value){B.need(!await this.getOptional(ref),'IMMUTABLE_RECEIPT_ALREADY_PRESENT');await this.request(ref,'PUT',{message:'093C immutable '+ref,content:Buffer.from(P.canonical(value)).toString('base64')});}
}
async function main(){
  const action=process.argv[2];
  if(action==='verify-package'){const digest=B.packageIdentity();console.log(JSON.stringify({package_sha256:digest,source_bytes:'MATCH'}));return;}
  if(action==='seal-output'){
    // Controller-side transport operation: no broker secret, capability expansion or subject crypto tool is required.
    const receipt=JSON.parse(fs.readFileSync(process.argv[3],'utf8')),payload=JSON.parse(fs.readFileSync(process.argv[4],'utf8'));
    const envelope=B.sealOutput(receipt,payload.run_id,payload);G.write(process.argv[5],envelope);console.log('SEALED_OUTPUT_WRITTEN');return;
  }
  B.need(C.production,'093C_NO_REAL_WORKFLOW_EXECUTION_FROM_REHEARSAL');
  const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,'utf8')),inputs=event.inputs||{};
  const authorizationRef=inputs.authorization_ref||'';B.assertAuthority(action,authorizationRef);B.packageIdentity();
  const store=new GitStore(),root=path.join(process.env.RUNNER_TEMP,'093c-private-'+process.env.GITHUB_RUN_ID+'-'+process.env.GITHUB_RUN_ATTEMPT),publicRoot=path.join(process.env.RUNNER_TEMP,'093c-public');
  B.need(!fs.existsSync(root)&&!fs.existsSync(publicRoot),'NEW_RUNNER_ROOT_REQUIRED');fs.mkdirSync(publicRoot,{recursive:true});
  const common={root,store,authorization_ref:authorizationRef};let result;
  if(action==='freeze'){result=await B.freeze(common);G.write(path.join(publicRoot,'freeze.json'),result);}
  else if(action==='reveal'){result=await B.reveal({...common,run_id:inputs.run_id,destination:path.join(publicRoot,'release'),independent_invalidity:inputs.independent_invalidity_json?JSON.parse(inputs.independent_invalidity_json):undefined});G.write(path.join(publicRoot,'reveal-receipt.json'),result);}
  else if(action==='grade'){B.need(typeof inputs.sealed_comparison_json==='string'&&inputs.sealed_comparison_json.length<=60000,'BOUNDED_SEALED_COMPARISON_REQUIRED');result=await B.grade({...common,case_id:inputs.case_id,sealed_comparison:JSON.parse(inputs.sealed_comparison_json)});G.write(path.join(publicRoot,'grade-receipt.json'),result);}
  else if(action==='open-oracle'){result=await B.openOracle({...common,case_id:inputs.case_id});G.write(path.join(publicRoot,'post-grade-authorized-oracle-audit.json'),result);}
  else throw Error('UNKNOWN_ACTION');
  // Fixed public artifact directory only. Private case material is never an artifact upload target.
  console.log(JSON.stringify({action,status:'COMPLETE',bank_id:C.bankId,oracle_opened:action==='open-oracle',heldout_subjects_executed:0}));
}
if(require.main===module)main().catch(()=>{console.error('093C_PRECOMMITTED_OPERATION_BLOCKED');process.exitCode=1;});
module.exports={GitStore};
