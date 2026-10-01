'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const C=require('./context'),P=require('./primitives'),G=require('./generator'),V=require('./validator'),S=require('./schema'),policy=require('./policy.json');
function need(value,code){if(!value)throw Error(code);}
function packageIdentity() {
  const file=path.join(__dirname,'PACKAGE_FREEZE.json'),manifest=JSON.parse(fs.readFileSync(file,'utf8'));
  for(const entry of manifest.files){const actual=G.identity(path.join(C.packageRoot,entry.path));need(actual.sha256===entry.sha256&&actual.blob===entry.blob,'PACKAGE_BYTES_MISMATCH');}
  need(manifest.files.filter(e=>C.sourcePaths.includes(e.path)).length===C.sourcePaths.length,'PACKAGE_INCOMPLETE');
  return P.sha256(fs.readFileSync(file));
}
function assertAuthority(action,authorizationRef,env=process.env) {
  need(policy.actions.includes(action),'UNKNOWN_ACTION');
  if(!C.production){need(/^REHEARSAL-AUTH-/.test(authorizationRef),'REHEARSAL_AUTH_REQUIRED');return;}
  need(env.GITHUB_ACTIONS==='true'&&env.GITHUB_REPOSITORY===policy.broker_repository&&env.GITHUB_ACTOR===policy.broker_owner&&env.BROKER_PROTECTED_ENVIRONMENT===policy.protected_environment,'BROKER_AUTHORITY_DOMAIN_REQUIRED');
  need(env.ACTIVATION_093C_MODE==='PRODUCTION','PRODUCTION_MODE_EXPLICIT');
  if(action==='freeze')need(authorizationRef===policy.freeze_authorization_ref,'FIRST_BANK_AUTH_REQUIRED');
  else need(/^\d{10,}$/.test(authorizationRef)&&authorizationRef!==policy.freeze_authorization_ref&&authorizationRef!==policy.human_gate_audit_ref,'SEPARATE_ACTION_AUTH_REQUIRED');
}
function readMaster(env=process.env) {
  const masterRaw=C.production?env.STAGE1_V2_PRODUCTION_MASTER_HEX:env.REHEARSAL_093C_MASTER_HEX;
  need(typeof masterRaw==='string'&&/^[a-fA-F0-9]{64}$/.test(masterRaw),'FRESH_256_BIT_MASTER_REQUIRED');
  const master=Buffer.from(masterRaw,'hex');
  if(C.production){need(/^[a-fA-F0-9]{64}$/.test(env.SYNTHETIC_MASTER_SEED||''),'SYNTHETIC_REUSE_GUARD_UNAVAILABLE');need(!crypto.timingSafeEqual(master,Buffer.from(env.SYNTHETIC_MASTER_SEED,'hex')),'SYNTHETIC_MASTER_REUSE_DENIED');}
  return master;
}
function masterCommitment(master){return P.sha256(P.derive(master,C.domain+'master-identity-commitment'));}
function seed(master){return P.derive(master,C.domain+'factory-master');}
function recipient(master){const raw=P.derive(master,C.domain+'sealed-output-recipient-private');const der=Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),raw]);const privateKey=crypto.createPrivateKey({key:der,format:'der',type:'pkcs8'});const publicKey=crypto.createPublicKey(privateKey).export({format:'der',type:'spki'});return {privateKey,publicKey:publicKey.toString('base64')};}
function envelopeAAD(publicReceipt,runId){return P.canonical({bank_id:publicReceipt.bank_id,scope:publicReceipt.scope,package_sha256:publicReceipt.package_sha256,merkle_root:publicReceipt.freeze.merkle_root,run_id:runId});}
function sealOutput(publicReceipt,runId,payload) {
  const receiver=crypto.createPublicKey({key:Buffer.from(publicReceipt.output_recipient_public_key,'base64'),format:'der',type:'spki'}),pair=crypto.generateKeyPairSync('x25519'),shared=crypto.diffieHellman({privateKey:pair.privateKey,publicKey:receiver});
  const aad=envelopeAAD(publicReceipt,runId),key=P.derive(shared,'093C:output-envelope:key:'+aad),nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);
  cipher.setAAD(Buffer.from(aad));const ciphertext=Buffer.concat([cipher.update(P.canonical(payload),'utf8'),cipher.final()]);
  return {bank_id:publicReceipt.bank_id,scope:publicReceipt.scope,run_id:runId,aad_sha256:P.sha256(aad),ephemeral_public_key:pair.publicKey.export({format:'der',type:'spki'}).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
}
function unsealOutput(publicReceipt,envelope,master) {
  need(envelope.bank_id===publicReceipt.bank_id&&envelope.scope===publicReceipt.scope,'ENVELOPE_DOMAIN_MISMATCH');
  const keys=recipient(master);need(keys.publicKey===publicReceipt.output_recipient_public_key,'OUTPUT_RECIPIENT_MISMATCH');
  const aad=envelopeAAD(publicReceipt,envelope.run_id);need(envelope.aad_sha256===P.sha256(aad),'ENVELOPE_AAD_MISMATCH');
  const publicKey=crypto.createPublicKey({key:Buffer.from(envelope.ephemeral_public_key,'base64'),format:'der',type:'spki'}),shared=crypto.diffieHellman({privateKey:keys.privateKey,publicKey});
  const key=P.derive(shared,'093C:output-envelope:key:'+aad),decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.nonce,'base64'));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]).toString('utf8'));
}
function readJson(file){return JSON.parse(fs.readFileSync(file,'utf8'));}
function safePublicReceipt(receipt,master,packageSha) {
  need(receipt.scope===C.scope&&receipt.bank_id===C.bankId&&receipt.package_sha256===packageSha&&receipt.master_commitment===masterCommitment(master),'FROZEN_BANK_OR_MASTER_MISMATCH');
  need(receipt.output_recipient_public_key===recipient(master).publicKey,'FROZEN_RECIPIENT_MISMATCH');
}
function materialize(root,master,publicReceipt) {
  const identity=packageIdentity();if(publicReceipt)safePublicReceipt(publicReceipt,master,identity);
  const bank=G.makeBank(root,seed(master));V.validateBank(root);
  if(publicReceipt)need(G.hash(bank.freeze)===G.hash(publicReceipt.freeze),'FROZEN_ROOT_MISMATCH');
  const coreText=fs.readFileSync(path.join(root,'controller','sealed-core.json'),'utf8');need(!coreText.includes(master.toString('hex')),'MASTER_PERSISTENCE_FORBIDDEN');
  return bank;
}
async function freeze(options) {
  assertAuthority('freeze',options.authorization_ref);const packageSha=packageIdentity(),master=readMaster();
  const claim={bank_id:C.bankId,scope:C.scope,package_sha256:packageSha,master_commitment:masterCommitment(master),authorization_ref:options.authorization_ref,status:'CLAIMED_BEFORE_INFORMATION_SPEND',planned_real_heldout_generation:C.production?1:0};
  await options.store.putImmutable('claim.json',claim); // The first-bank claim is durable BEFORE factory derivation/generation.
  const bank=materialize(options.root,master);
  const receipt={bank_id:C.bankId,scope:C.scope,package_sha256:packageSha,master_commitment:claim.master_commitment,authorization_ref:options.authorization_ref,output_recipient_public_key:recipient(master).publicKey,freeze:bank.freeze,heldout_subjects_executed:0};
  await options.store.putImmutable('freeze.json',receipt);return receipt;
}
function selectCase(receipt,runId) {const c=receipt.freeze.commitments.find(c=>c.run_ids.includes(runId));need(c,'RUN_NOT_FROZEN');return c;}
async function reveal(options) {
  assertAuthority('reveal',options.authorization_ref);const receipt=await options.store.get('freeze.json'),master=readMaster();safePublicReceipt(receipt,master,packageIdentity());
  const c=selectCase(receipt,options.run_id);
  if(c.role==='RESERVE') {
    const reason=options.independent_invalidity;
    need(reason&&/^\d{10,}$/.test(reason.reserve_authorization_ref||'')&&reason.reserve_authorization_ref!==policy.freeze_authorization_ref,'SEPARATE_RESERVE_AUTH_REQUIRED');
    const primary=receipt.freeze.commitments.find(x=>x.case_id===reason.primary_case_id&&x.class_id===c.class_id&&x.role==='PRIMARY');need(primary,'INDEPENDENT_PRIMARY_INVALIDITY_REQUIRED');
    const previous=await options.store.getOptional(`reserves/${c.case_id}.json`);
    if(previous)need(previous.primary_case_id===primary.case_id,'RESERVE_ASSIGNMENT_IMMUTABLE');
    else {
      const state=G.clone(receipt.freeze);for(const id of state.reserve_order[c.class_id])if(await options.store.getOptional(`reserves/${id}.json`))state.reserve_state[id]={used:true,exposed:true};
      need(G.selectReserve(state,c.class_id,reason)===c.case_id,'FROZEN_RESERVE_ORDER_REQUIRED');
      await options.store.putImmutable(`reserves/${c.case_id}.json`,{case_id:c.case_id,primary_case_id:primary.case_id,authorization_ref:reason.reserve_authorization_ref,independent_reason_sha256:G.hash(reason)});
    }
  }
  need(!await options.store.getOptional(`releases/${options.run_id}.json`),'RUN_ALREADY_RELEASED');
  const bank=materialize(options.root,master,receipt);need(G.hash(bank.freeze)===G.hash(receipt.freeze),'REVALIDATION');
  const envelope=G.reveal(options.root,options.run_id,options.destination);
  G.write(path.join(options.destination,'output-recipient.json'),{bank_id:receipt.bank_id,scope:receipt.scope,package_sha256:receipt.package_sha256,output_recipient_public_key:receipt.output_recipient_public_key,merkle_root:receipt.freeze.merkle_root});
  await options.store.putImmutable(`releases/${options.run_id}.json`,{run_id:options.run_id,case_id:c.case_id,role:c.role,authorization_ref:options.authorization_ref,packet_sha256:envelope.manifest.packet_sha256,contract_sha256:envelope.manifest.contract_sha256});
  return {bank_id:receipt.bank_id,run_id:options.run_id,case_id:c.case_id,merkle_root:receipt.freeze.merkle_root,inclusion_proof_verified:P.verifyProof(envelope.commitment.leaf_sha256,envelope.inclusion_proof,receipt.freeze.merkle_root),oracle_plaintext_exposed:false,oracle_salt_exposed:false};
}
async function grade(options) {
  assertAuthority('grade',options.authorization_ref);const receipt=await options.store.get('freeze.json'),master=readMaster();safePublicReceipt(receipt,master,packageIdentity());
  const c=receipt.freeze.commitments.find(c=>c.case_id===options.case_id);need(c,'CASE_NOT_FROZEN');
  need(!await options.store.getOptional(`grades/${c.case_id}.json`),'COMPARISON_ALREADY_GRADED');
  const encrypted=options.sealed_comparison;
  need(Array.isArray(encrypted)&&encrypted.length===6&&new Set(encrypted.map(e=>e.run_id)).size===6&&c.run_ids.every(id=>encrypted.some(e=>e.run_id===id)),'ALL_SIX_SEALED_OUTPUTS_REQUIRED');
  // Incoming dispatch bytes are ciphertext only. No other-arm output/capture plaintext is public.
  const decoded=encrypted.map(e=>({envelope:e,payload:unsealOutput(receipt,e,master)}));
  materialize(options.root,master,receipt);
  for(const item of decoded) {
    const id=item.envelope.run_id,m=readJson(path.join(options.root,'controller','manifests',id+'.json')),payload=item.payload;
    need(payload.run_id===id&&payload.case_id===c.case_id,'SEALED_OUTPUT_IDENTITY');
    const startedBytes=Buffer.from(payload.started_bytes_base64,'base64'),started=JSON.parse(startedBytes);
    V.validateCapture(m,started,payload.capture,payload.output,startedBytes);
    if(C.production)need(payload.capture.dev_simulation===false,'CONTAMINATED_SUBJECT_CAPTURE_DENIED');
    G.write(path.join(options.root,'sealed-outputs',id+'.json'),payload.output);G.write(path.join(options.root,'sealed-outputs',id+'.capture.json'),payload.capture);
  }
  G.sealComparison(options.root,c.case_id);
  const grades=c.run_ids.map(id=>G.grade(options.root,id));G.write(path.join(options.root,'controller','grades',c.case_id+'.json'),grades);
  const result={bank_id:receipt.bank_id,scope:receipt.scope,case_id:c.case_id,package_sha256:receipt.package_sha256,merkle_root:receipt.freeze.merkle_root,authorization_ref:options.authorization_ref,comparison_sealed:true,sealed_envelope_sha256:G.hash(encrypted),sealed_output_commitments:c.run_ids.map(id=>({run_id:id,output_sha256:P.sha256(fs.readFileSync(path.join(options.root,'sealed-outputs',id+'.json'))),capture_sha256:P.sha256(fs.readFileSync(path.join(options.root,'sealed-outputs',id+'.capture.json')))})),grades,oracle_plaintext_exposed:false,oracle_salt_exposed:false};
  await options.store.putImmutable(`grades/${c.case_id}.json`,result);return result;
}
async function openOracle(options) {
  assertAuthority('open-oracle',options.authorization_ref);const receipt=await options.store.get('freeze.json'),master=readMaster();safePublicReceipt(receipt,master,packageIdentity());
  const previous=await options.store.get(`grades/${options.case_id}.json`);need(previous.comparison_sealed===true&&previous.package_sha256===receipt.package_sha256&&previous.merkle_root===receipt.freeze.merkle_root,'GRADE_FIRST');
  need(!await options.store.getOptional(`openings/${options.case_id}.json`),'ORACLE_ALREADY_OPENED');
  const c=receipt.freeze.commitments.find(c=>c.case_id===options.case_id);need(c&&previous.grades.length===6&&c.run_ids.every(id=>previous.grades.some(g=>g.run_id===id)),'COMPLETE_GRADE_UNIT_REQUIRED');
  materialize(options.root,master,receipt);
  const core=readJson(path.join(options.root,'controller','sealed-core.json')).cases.find(x=>x.case_id===options.case_id);
  const result={bank_id:receipt.bank_id,scope:receipt.scope,case_id:options.case_id,authorization_ref:options.authorization_ref,grade_receipt_sha256:G.hash(previous),oracle:core.oracle,oracle_salt_hex:core.oracle_salt_hex,oracle_commitment_verified:P.oracleCommitment(c.case_id,core.oracle,Buffer.from(core.oracle_salt_hex,'hex'))===c.oracle_commitment_sha256};
  need(result.oracle_commitment_verified,'POST_GRADE_ORACLE_COMMITMENT');await options.store.putImmutable(`openings/${c.case_id}.json`,result);return result;
}
class LocalStore {
  constructor(root){this.root=root;}
  async getOptional(ref){const file=path.join(this.root,ref);return fs.existsSync(file)?readJson(file):null;}
  async get(ref){const result=await this.getOptional(ref);need(result,'DURABLE_RECEIPT_REQUIRED');return result;}
  async putImmutable(ref,value){const file=path.join(this.root,ref);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,P.canonical(value),{encoding:'utf8',flag:'wx'});}
}
module.exports={need,packageIdentity,assertAuthority,readMaster,masterCommitment,recipient,sealOutput,unsealOutput,materialize,freeze,reveal,grade,openOracle,LocalStore,policy};
