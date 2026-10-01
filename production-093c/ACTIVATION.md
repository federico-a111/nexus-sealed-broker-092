# 093C production activation package V1

Authority: Issue #48 comment 5936862387. Pinned inputs: 093A commit `50fa0bd7604614b9c097627460bcb1245b94a820`; 092B generator blob `c27e4f80bf78d5ead7ad07c148afd50a1e2deff1`; isolation adjudication 5935731331; human gate audit 5936780054. The existing human authorization covers the first real bank freeze. This package grants no subject execution, outcome grading, oracle opening, unblinding or reserve consumption.

## Exact delivery layout

Install this directory's `.github/workflows/` and `production-093c/` at the broker repository root. The destination is only `federico-a111/nexus-sealed-broker-092`. Installation is a later unit; 093C installs or dispatches nothing. Every file, including the four workflows, must match `production-093c/PACKAGE_FREEZE.json` and the public freeze receipt byte-for-byte before installation is accepted. No edit of 093A or 092B is required. Immutable copies are preserved under `production-093c/frozen-093a/` and `production-093c/frozen-092b.js`.

The frozen public package contains four predeclared workflows: `093c-freeze.yml`, `093c-reveal.yml`, `093c-grade.yml`, `093c-open-oracle.yml`. They accept only broker-owner dispatches, use the existing protected `sealed-core-synthetic` environment, pin checkout/upload actions by full commit SHA, disable persisted checkout credentials, serialize broker operations and upload only `$RUNNER_TEMP/093c-public/`. The private bank/controller directory is never an artifact target. No npm install or additional actor, daemon, scheduler, router or mailbox is introduced.

## Scientific contract preservation

`schema.js` imports the pinned 093A schema verbatim. C1–C4, 4 primary + 4 reserve per class, A/B k=3, 192 manifests, baseline/runtime map, output schemas, `093A-FINAL-CAPTURE-V3`, reserve rule, lifecycle/provenance and grading rules remain unchanged. The factory/validator adapters change only source provenance, scope/version, opaque id namespace and derivation domains. They preserve the frozen class generation expressions and oracle/grading formulas. C4 extra-AI captures remain structurally gradeable FAIL outcomes; malformed provenance remains distinguishable.

| Activation residual | Implementation | Preflight evidence |
| --- | --- | --- |
| New production identity | `context.js`: `093C-ACTIVATION-V1`, `HO093C-*`, `STAGE1_V2_REAL_HELDOUT`, bank `STAGE1V2-HO-093C-01` | Production metadata guard only; no production factory invoked |
| Permanently contaminated rehearsal | `RH093C-*`, `093C_PERMANENTLY_CONTAMINATED_REHEARSAL` | Full 32-case/192-manifest proof and broker-path rehearsal only |
| Fresh production secret in broker authority domain | New protected secret `STAGE1_V2_PRODUCTION_MASTER_HEX`, exactly 256 bits; broker repo/actor/environment guards | Missing/malformed secret, wrong/local authority and synthetic-key reuse reject |
| Never reuse 092B synthetic master | Separate secret plus constant-time comparison against existing `SYNTHETIC_MASTER_SEED` inside broker only | Equal-value test rejects without calling factory |
| Master never committed/logged/returned | Environment only, no raw master field in private core, fixed sanitized stdout/errors | Rehearsal checks public receipt/private core and output domains |
| Seed/salt/hiding-nonce domains | Production-vs-rehearsal prefix, separate factory, case-seed, salt, packet/contract/evidence labels | 093A salted/Merkle tests and per-case derivation-domain tests |
| Claim before first irreversible derivation | Immutable `claim.json` committed before calling the factory | Claim observed before root exists; retry denied before factory |
| Freeze public surface | Original commitments/root/order/provenance plus bank/package identity and public sealed-output recipient | No plaintext seed/oracle/salt/master; public-key metadata discloses no private key |
| Reproducible sealed core | Regenerate the SAME bank only inside broker from protected master; verify master/package commitment before materialization and full frozen-root equality afterward | Wrong master rejected before materialization; identical rehearsal root verifies on every action |
| Selective reveal | One selected case packet/contract and one selected manifest plus inclusion proof | 24 broker-path deliveries, C3 equality, repeat run denied |
| Preserve other-arm output exclusion | Controller seals unchanged output/capture/STARTED payload using public X25519 recipient and AES-256-GCM envelope, bound to bank/run/root/package | Round trip; tamper/cross-run/wrong-key rejects; no new subject crypto/runtime requirement |
| Complete comparison before grade | Exactly six distinct frozen run envelopes, decrypt privately, validate captures, seal, grade | Five-output comparison rejected; four full class pipelines pass |
| Post-grade oracle opening | Separate owner authorization reference, immutable complete grade receipt, regenerated committed oracle | Early/repeat open denied; four post-grade commitments verify |
| Reserve gate | Separate reserve authorization and independent NO_EVALUABLE reason, same-class frozen order, immutable assignment ledger | Rehearsal reserve without authority rejects; original reserve-selection dry run preserved |
| Later byte-identical install | Package manifest includes SHA-256 + Git blob for every delivered file, runtime verification precedes secret access | Package/frozen-input identity checks PASS; no install in 093C |

The encrypted output envelope is a transport implementation of the already-frozen exclusion of other-arm outputs and sealed comparison-unit grading. It does not change the plaintext output/capture schema, arm evidence, oracle, native subject capabilities or exposure policy. The controller can encrypt an authorized capture at its existing capture boundary; subjects do not need a new tool, credential or broker authority.

## Broker prerequisites and gates

The broker owner must supply a **fresh CSPRNG-generated 32-byte value entirely within the broker-owner authority domain** as `STAGE1_V2_PRODUCTION_MASTER_HEX` in the existing protected environment. It must never be generated/provisioned in `fede-test`, pasted into this chat, committed, printed or copied from the synthetic master. 093C does not provision/read this real secret. Existing synthetic master is used only for a private reuse comparison in future production jobs. Missing comparison evidence fails closed.

Before the first real freeze, the later install receipt must prove all delivered bytes match this package and that the subject runtime/permission/isolation boundary has not expanded. No duplicate human decision is required merely because installation has completed; authority remains comment 5936862387 while scientific semantics and exposure model remain fixed.

`freeze` accepts only the original authorization reference. It first persists a claim; any existing claim blocks a retry even if freeze failed partway. A bug/recovery after observing a real bank requires a separately preregistered invalidation/restart, never an adaptive code edit. The public immutable freeze is committed under `production-freezes/STAGE1V2-HO-093C-01/` and can be used to reproduce the same root. No raw seed/oracle/salt/master is committed.

`reveal`, `grade`, `open-oracle` each require a **separate durable authorization reference** supplied by the trusted broker owner. The freeze/human-gate-audit references cannot authorize those actions. Owner dispatch is an authorization attestation, not authority delegated to the subject connector. A reserve reveal additionally requires a separate reserve authorization and independent outcome-free invalidity receipt. No adaptive case replacement is enabled by first-freeze authorization.

`grade` input is an array of six **encrypted** envelopes (bounded to 60000 input characters), not plaintext answers/captures. Event metadata, repository receipts and artifacts cannot disclose other-arm plaintext while a comparison remains active. Only after all six captures validate and outputs seal does the broker emit grade receipts. `open-oracle` emits plaintext only after the complete immutable grade and its own separate owner gate. No feedback is exposed earlier.

## Rehearsal-only reproduction

From the package root:

```powershell
$env:ACTIVATION_093C_MODE = 'REHEARSAL'
node production-093c/preflight.js <NEW_CONTAMINATED_ROOT> <NEW_SANITIZED_RECEIPT>
```

This generates only permanently contaminated rehearsal material, runs deterministic non-AI DEV processes, executes local mock broker operations and preregistered negative controls. It never supplies a real production master, installs a broker workflow, dispatches GitHub Actions or invokes a held-out subject. A successful terminal is `093C = READY_FOR_BROKER_INSTALL`; stop there.

Any material scientific contract, actor capability, broker reach or exposure-policy change must stop for new authority/isolation adjudication. No such change is authorized or made by this package.
