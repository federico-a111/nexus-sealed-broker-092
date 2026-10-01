'use strict';
const path=require('node:path');
const mode=process.env.ACTIVATION_093C_MODE||'REHEARSAL';
if(!['REHEARSAL','PRODUCTION'].includes(mode))throw Error('093C_INVALID_MODE');
const sourcePaths=['production-093c/context.js','production-093c/schema.js','production-093c/primitives.js','production-093c/generator.js','production-093c/validator.js','production-093c/dev-subject.js','production-093c/proof.js','production-093c/broker.js','production-093c/driver.js','production-093c/preflight.js','production-093c/policy.json','production-093c/frozen-092b.js',...['schema.js','primitives.js','generator.js','validator.js','dev-subject.js','proof.js'].map(f=>'production-093c/frozen-093a/'+f),...['freeze','reveal','grade','open-oracle'].map(f=>`.github/workflows/093c-${f}.yml`)];
const production=mode==='PRODUCTION';
module.exports={mode,production,scope:production?'STAGE1_V2_REAL_HELDOUT':'093C_PERMANENTLY_CONTAMINATED_REHEARSAL',version:'093C-ACTIVATION-V1',casePrefix:production?'HO093C-':'RH093C-',protocol:production?'093C-PRODUCTION-V1':'093C-REHEARSAL-V1',domain:production?'093C:PRODUCTION:V1:':'093C:REHEARSAL:V1:',sourcePaths,packageRoot:path.resolve(__dirname,'..'),bankId:production?'STAGE1V2-HO-093C-01':'REHEARSAL093C-01'};
