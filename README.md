# After the Tool Call

`after-the-tool-call` is a TypeScript reference implementation for recording and verifying multi-step changes initiated by an agent.

A tool call can time out after the remote system has already applied its effect. At that point, success and failure are both unsafe assumptions. This project models that ambiguity explicitly and preserves the information needed to inspect what was proposed, why it was authorized, which effects were confirmed, and what recovery was attempted.

## What it records

Each change record contains:

- the proposed state transition and its individual effects;
- the evidence used to support the change;
- the delegated authority and policy evaluated at authorization time;
- a durable intent before each external call;
- confirmed effects and unresolved outcomes;
- compensation attempts and their observed results;
- an Ed25519 signature over a canonical representation of the record.

The record uses `uncertain` and `recovery-required` states where a binary success or failure result would discard material information.

## Example

The included scenario coordinates a release across two simulated systems:

1. Promote a release in a registry.
2. Set that release as the target of a campaign.

The demo exercises three paths:

| Scenario                                       | Commit result | Recovery result     |
| ---------------------------------------------- | ------------- | ------------------- |
| Both effects confirmed                         | `committed`   | Not required        |
| Authority revoked after the first effect       | `partial`     | `compensated`       |
| The second call throws with an unknown outcome | `uncertain`   | `recovery-required` |

## Run it

Node 24.14.x is required. The implementation uses Node's built-in SQLite module and has no runtime dependencies.

```sh
npm ci
npm test
npm run demo
```

The demo writes SQLite state, signed receipts, and public keys to `.local/`, which is excluded from version control.

To verify a generated receipt with its trusted public key:

```sh
node dist/src/verify-cli.js \
  .local/<run>-success-receipt.json \
  .local/<run>-success-public.pem
```

## API

The `Kernel` exposes five operations:

| Operation                      | Purpose                                                           |
| ------------------------------ | ----------------------------------------------------------------- |
| `propose(change, evidence)`    | Snapshot the proposed transition, evidence, and starting state    |
| `authorize(changeId, context)` | Evaluate evidence, policy, and delegated authority                |
| `commit(changeId)`             | Recheck conditions before each effect and record its outcome      |
| `compensate(changeId)`         | Attempt reverse-order restoration of confirmed reversible effects |
| `receipt(changeId)`            | Produce a signed record of the change and its current status      |

`verify(receipt, trustedPublicKey)` checks the signature, evidence hash, and consistency of the recorded transitions without contacting the original systems.

## Failure semantics

Before an external call, the kernel persists the step index as pending. It clears that marker only after the adapter confirms the expected downstream state.

If the call throws, the effect remains unresolved. The kernel does not retry it blindly and does not describe it as rolled back merely because earlier confirmed effects were restored.

Compensation uses compare-and-set semantics. It refuses to overwrite a value that has changed since the recorded effect. An irreversible effect is reported for manual remediation.

## Adapter contract

The `Environment` interface supplies current time, policy and authority context, evidence versions, state reads, effect application, and restoration.

Adapters are responsible for implementing idempotency and atomic compare-and-set behavior at the target system. A production adapter should also use target-side fencing or narrowly scoped capabilities when authority can change while a request is in flight.

## Trust model

A valid signature proves that the receipt has not changed since it was signed by the trusted key. It does not prove that an external system reported truthfully, that an effect occurred, or that the signer included every relevant event.

Offline verification reconstructs recorded historical transitions. It does not re-run policy against current state and it does not turn an unresolved outcome into a successful one. Callers must inspect `receipt.body.status` alongside the verification result.

## Implementation status

This repository contains an in-process coordinator, a SQLite store, simulated release adapters, a receipt verifier, and adversarial tests for stale evidence, changed policy, revoked authority, partial failure, ambiguous effects, compensation conflicts, restart recovery, and receipt tampering.

The coordinator currently assumes a single process. External systems are represented by adapters and are not transactionally coupled to SQLite.
