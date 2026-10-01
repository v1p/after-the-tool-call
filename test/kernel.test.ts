import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import { fixture } from "../src/scenario.js";
import { Kernel, Store, hash, verify } from "../src/kernel.js";
function ready(t: TestContext) {
  const f = fixture();
  t.after(() => f.store.close());
  f.kernel.propose(f.change, f.evidence);
  f.kernel.authorize(f.change.id, f.env.context());
  return f;
}
test("successful release and idempotent repeat commit", (t) => {
  const f = ready(t);
  const r = f.kernel.commit(f.change.id);
  assert.equal(r.body.status, "committed");
  assert.equal(r.body.effects.length, 2);
  assert.equal(verify(r, f.keys.publicKey).valid, true);
  assert.deepEqual(f.kernel.commit(f.change.id), r);
});
test("stale evidence expires after authorization", (t) => {
  const f = ready(t);
  f.env.time = 1_401;
  const r = f.kernel.commit(f.change.id);
  assert.equal(r.body.status, "failed");
  assert.equal(r.body.effects.length, 0);
  assert.equal(r.body.failure, "stale-or-invalid-evidence");
});
test("replaced evidence rejected even within expiry", (t) => {
  const f = ready(t);
  f.env.version = "ci-43";
  assert.equal(
    f.kernel.commit(f.change.id).body.failure,
    "evidence-version-changed",
  );
});
test("policy content change blocked even without version bump", (t) => {
  const f = ready(t);
  f.env.controls.policy.maxEvidenceAge = 499;
  assert.equal(f.kernel.commit(f.change.id).body.failure, "policy-changed");
});
test("authority revoked mid-execution leaves a partial effect and permits operator compensation", (t) => {
  const f = ready(t);
  f.env.afterApply = () => {
    f.env.controls.authority.revoked = true;
  };
  const r = f.kernel.commit(f.change.id);
  assert.equal(r.body.status, "partial");
  assert.equal(r.body.effects.length, 1);
  assert.equal(r.body.failure, "authority-invalid");
  const recovered = f.kernel.compensate(f.change.id);
  assert.equal(recovered.body.status, "compensated");
  assert.equal(verify(recovered, f.keys.publicKey).valid, true);
});
test("partial downstream failure preserves uncertainty after compensating known effects", (t) => {
  const f = ready(t);
  f.env.failTarget = "campaign";
  const r = f.kernel.commit(f.change.id);
  assert.equal(r.body.status, "uncertain");
  assert.equal(r.body.pending, 1);
  assert.equal(r.body.effects.length, 1);
  assert.throws(() => f.kernel.commit(f.change.id));
  const recovered = f.kernel.compensate(f.change.id);
  assert.equal(recovered.body.status, "recovery-required");
  assert.equal(f.env.state.registry, "ecu-1.0");
});
test("irreversible action denied by default; explicitly permitted action requires remediation", (t) => {
  const f = fixture();
  t.after(() => f.store.close());
  f.change.steps[1]!.recovery = "irreversible";
  f.kernel.propose(f.change, f.evidence);
  assert.equal(f.kernel.authorize(f.change.id, f.env.context()).allowed, false);
  f.change.id = "release-002";
  f.env.controls.policy.allowIrreversible = true;
  f.kernel.propose(f.change, f.evidence);
  f.kernel.authorize(f.change.id, f.env.context());
  f.kernel.commit(f.change.id);
  const r = f.kernel.compensate(f.change.id);
  assert.equal(r.body.status, "recovery-required");
  assert.equal(r.body.recovery[0]!.outcome, "manual");
  assert.equal(f.env.state.campaign, "ecu-1.1");
});
test("historical replay survives current policy, authority, evidence, and state changes", (t) => {
  const f = ready(t);
  const r = JSON.parse(JSON.stringify(f.kernel.commit(f.change.id)));
  f.env.time = 99_999;
  f.env.controls.authority.revoked = true;
  f.env.version = "deleted";
  f.env.controls.policy.version = "policy-9";
  f.env.state.registry = "ecu-2.0";
  assert.equal(verify(r, f.keys.publicKey).valid, true);
  r.body.evidence.passed = false;
  assert.equal(verify(r, f.keys.publicKey).valid, false);
});
test("wrong trust anchor and freshly signed inconsistent history rejected", (t) => {
  const f = ready(t);
  const r = f.kernel.commit(f.change.id);
  assert.equal(
    verify(r, generateKeyPairSync("ed25519").publicKey).valid,
    false,
  );
  r.body.effects[0]!.after = "unapproved";
  r.digest = hash(r.body);
  r.signature = sign(null, Buffer.from(r.digest), f.keys.privateKey).toString(
    "base64",
  );
  assert.equal(verify(r, f.keys.publicKey).valid, false);
});
test("compensation refuses to overwrite subsequent changes and is repeatable", (t) => {
  const f = ready(t);
  f.kernel.commit(f.change.id);
  f.env.state.registry = "ecu-2.0";
  const r = f.kernel.compensate(f.change.id);
  assert.equal(r.body.status, "recovery-required");
  assert.equal(f.env.state.registry, "ecu-2.0");
  assert.deepEqual(f.kernel.compensate(f.change.id), r);
});
test("SQLite reopen preserves history; interrupted intent blocks blind replay", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "change-transaction-"));
  const path = join(dir, "test.sqlite");
  const f = fixture(path);
  f.kernel.propose(f.change, f.evidence);
  f.kernel.authorize(f.change.id, f.env.context());
  const r = f.store.get(f.change.id);
  r.status = "executing";
  r.pending = 0;
  f.store.save(r);
  f.store.close();
  const store = new Store(path);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true });
  });
  const kernel = new Kernel(store, f.env, f.keys.privateKey);
  assert.equal(kernel.receipt(f.change.id).body.pending, 0);
  assert.throws(() => kernel.commit(f.change.id));
});
test("proposal snapshots cannot be mutated by caller and duplicate IDs fail", (t) => {
  const f = ready(t);
  f.evidence.passed = false;
  assert.equal(f.kernel.receipt(f.change.id).body.evidence.passed, true);
  assert.throws(() => f.kernel.propose(f.change, f.evidence));
});
test("untrusted authorization context cannot expand scope", (t) => {
  const f = fixture();
  t.after(() => f.store.close());
  f.kernel.propose(f.change, f.evidence);
  const c = f.env.context();
  c.policy.allowIrreversible = true;
  assert.throws(() => f.kernel.authorize(f.change.id, c));
});
test("call applies then throws: unknown effect is never called restored", (t) => {
  const f = ready(t);
  const apply = f.env.apply.bind(f.env);
  f.env.apply = (step, key) => {
    apply(step, key);
    if (step.target === "campaign") throw new Error("response lost");
  };
  assert.equal(f.kernel.commit(f.change.id).body.status, "uncertain");
  const r = f.kernel.compensate(f.change.id);
  assert.equal(r.body.status, "recovery-required");
  assert.equal(f.env.state.campaign, "ecu-1.1");
});
test("restore applies then throws: recovery remains unresolved", (t) => {
  const f = ready(t);
  f.kernel.commit(f.change.id);
  const restore = f.env.restore.bind(f.env);
  f.env.restore = (step, key) => {
    restore(step, key);
    throw new Error("response lost");
  };
  const r = f.kernel.compensate(f.change.id);
  assert.equal(r.body.status, "recovery-required");
  assert.equal(r.body.recovery[0]!.outcome, "unknown");
  assert.deepEqual(f.kernel.compensate(f.change.id), r);
});
test("revocation before commit and state conflict prevent all effects", (t) => {
  const f = ready(t);
  f.env.controls.authority.revoked = true;
  assert.equal(f.kernel.commit(f.change.id).body.effects.length, 0);
  const g = ready(t);
  g.env.state.registry = "ecu-2.0";
  assert.equal(g.kernel.commit(g.change.id).body.failure, "state-conflict");
});
test("expired evidence is denied at authorization", (t) => {
  const f = fixture();
  t.after(() => f.store.close());
  f.evidence.expiresAt = 999;
  f.kernel.propose(f.change, f.evidence);
  assert.equal(f.kernel.authorize(f.change.id, f.env.context()).allowed, false);
  assert.throws(() => f.kernel.commit(f.change.id));
});
