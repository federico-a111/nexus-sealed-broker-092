'use strict';
// Scientific schemas/rules are imported unchanged from the pinned 093A source.
const frozen=require('./frozen-093a/schema'),C=require('./context');
module.exports={...frozen,VERSION:C.version,SCOPE:C.scope};
