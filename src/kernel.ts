import {
  createHash,
  sign,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { DatabaseSync } from "node:sqlite";

type JsonRecord = Record<string, unknown>;

/** Serialize the restricted JSON values used in signed receipts. */
export function canonical(value: unknown): string {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    const record = value as JsonRecord;
    const properties = Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`);
    return `{${properties.join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

export function hash(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export type State = { registry: string; campaign: string };
export type Step = {
  target: keyof State;
  from: string;
  to: string;
  recovery: "restore" | "irreversible";
};
export type Change = {
  id: string;
  agent: string;
  delegationId: string;
  release: string;
  steps: Step[];
};
export type Evidence = {
  source: string;
  version: string;
  observedAt: number;
  expiresAt: number;
  release: string;
  passed: boolean;
  digest: string;
};
export type Policy = {
  version: string;
  allowIrreversible: boolean;
  maxEvidenceAge: number;
};
export type Authority = {
  id: string;
  principal: string;
  agent: string;
  scope: string;
  expiresAt: number;
  revoked: boolean;
};
export type Context = { policy: Policy; authority: Authority };
export type Decision = {
  at: number;
  context: Context;
  allowed: boolean;
  reason: string;
};
export type Effect = {
  index: number;
  before: string;
  after: string;
  decision: Decision;
};
export type Recovery = {
  index: number;
  at: number;
  outcome: "restored" | "manual" | "conflict" | "unknown";
  reason: string;
};
export type Status =
  | "proposed"
  | "authorized"
  | "denied"
  | "executing"
  | "committed"
  | "failed"
  | "partial"
  | "uncertain"
  | "compensated"
  | "recovery-required";
export type RecordBody = {
  schema: 1;
  change: Change;
  evidence: Evidence;
  evidenceHash: string;
  initial: State;
  proposedAt: number;
  decision: Decision | null;
  effects: Effect[];
  recovery: Recovery[];
  status: Status;
  resulting: State;
  failure: string | null;
  pending: number | null;
};
export type Receipt = {
  body: RecordBody;
  digest: string;
  signature: string;
};

export interface Environment {
  now(): number;
  context(): Context;
  evidenceVersion(source: string): string;
  read(): State;
  /** Apply must use the idempotency key and atomically compare-and-set or throw. */
  apply(step: Step, idempotencyKey: string): void;
  /** Restore follows the same contract. A thrown call can have unknown effects. */
  restore(step: Step, idempotencyKey: string): void;
}

type AuthorizationReason =
  | "allowed"
  | "stale-or-invalid-evidence"
  | "authority-invalid"
  | "irreversible-denied";

function clone<T>(value: T): T {
  return structuredClone(value);
}

function evaluateAuthorization(
  change: Change,
  evidence: Evidence,
  context: Context,
  at: number,
): AuthorizationReason {
  const evidenceIsInvalid =
    evidence.release !== change.release ||
    !evidence.passed ||
    !evidence.digest ||
    evidence.observedAt > at ||
    evidence.expiresAt <= at ||
    at - evidence.observedAt > context.policy.maxEvidenceAge;

  if (evidenceIsInvalid) return "stale-or-invalid-evidence";

  const authority = context.authority;
  const authorityIsInvalid =
    authority.id !== change.delegationId ||
    authority.agent !== change.agent ||
    authority.scope !== change.release ||
    authority.revoked ||
    authority.expiresAt <= at;

  if (authorityIsInvalid) return "authority-invalid";

  const containsDisallowedIrreversibleStep =
    !context.policy.allowIrreversible &&
    change.steps.some((step) => step.recovery === "irreversible");
  return containsDisallowedIrreversibleStep ? "irreversible-denied" : "allowed";
}

export class Store {
  private readonly database: DatabaseSync;

  constructor(path = ":memory:") {
    this.database = new DatabaseSync(path);
    this.database.exec(
      "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS changes (id TEXT PRIMARY KEY, body TEXT NOT NULL)",
    );
  }

  create(record: RecordBody): void {
    this.database
      .prepare("INSERT INTO changes VALUES (?, ?)")
      .run(record.change.id, canonical(record));
  }

  save(record: RecordBody): void {
    this.database
      .prepare("UPDATE changes SET body=? WHERE id=?")
      .run(canonical(record), record.change.id);
  }

  get(id: string): RecordBody {
    const row = this.database
      .prepare("SELECT body FROM changes WHERE id=?")
      .get(id);
    if (!row) throw new Error("unknown change");
    return JSON.parse(row.body as string) as RecordBody;
  }

  close(): void {
    this.database.close();
  }
}

export class Kernel {
  constructor(
    private readonly store: Store,
    private readonly environment: Environment,
    private readonly signingKey: KeyObject,
  ) {}

  propose(change: Change, evidence: Evidence): string {
    const targets = new Set(change.steps.map((step) => step.target));
    if (
      !change.id ||
      !change.steps.length ||
      targets.size !== change.steps.length
    ) {
      throw new Error("one step per target required");
    }

    const initial = clone(this.environment.read());
    const transitionIsInvalid = change.steps.some(
      (step) =>
        initial[step.target] !== step.from || step.to !== change.release,
    );
    if (transitionIsInvalid) throw new Error("invalid proposed transition");

    this.store.create({
      schema: 1,
      change: clone(change),
      evidence: clone(evidence),
      evidenceHash: hash(evidence),
      initial,
      proposedAt: this.environment.now(),
      decision: null,
      effects: [],
      recovery: [],
      status: "proposed",
      resulting: initial,
      failure: null,
      pending: null,
    });
    return change.id;
  }

  authorize(id: string, context: Context): Decision {
    const record = this.store.get(id);
    if (record.status !== "proposed") {
      throw new Error("authorization requires proposed change");
    }
    if (hash(context) !== hash(this.environment.context())) {
      throw new Error("untrusted policy context");
    }

    const reason = this.guardReason(record, context);
    record.decision = {
      at: this.environment.now(),
      context: clone(context),
      allowed: reason === "allowed",
      reason,
    };
    record.status = record.decision.allowed ? "authorized" : "denied";
    this.store.save(record);
    return clone(record.decision);
  }

  commit(id: string): Receipt {
    const record = this.store.get(id);
    if (record.status === "committed") return this.receipt(id);
    if (record.status !== "authorized") {
      throw new Error(
        "commit requires fresh authorization; reconcile interrupted execution manually",
      );
    }

    record.status = "executing";
    this.store.save(record);

    for (const [index, step] of record.change.steps.entries()) {
      if (!this.executeStep(id, record, index, step)) break;
    }

    if (record.status === "executing") record.status = "committed";
    record.resulting = clone(this.environment.read());
    this.store.save(record);
    return this.receipt(id);
  }

  receipt(id: string): Receipt {
    const body = this.store.get(id);
    const digest = hash(body);
    const signature = sign(null, Buffer.from(digest), this.signingKey).toString(
      "base64",
    );
    return { body, digest, signature };
  }

  compensate(id: string): Receipt {
    const record = this.store.get(id);
    const compensatable: Status[] = [
      "committed",
      "partial",
      "uncertain",
      "compensated",
      "recovery-required",
    ];
    if (!compensatable.includes(record.status)) {
      throw new Error("nothing safely compensatable");
    }

    for (const effect of [...record.effects].reverse()) {
      const alreadyAttempted = record.recovery.some(
        (recovery) => recovery.index === effect.index,
      );
      if (alreadyAttempted) continue;

      const step = record.change.steps[effect.index]!;
      record.recovery.push(this.recoverEffect(id, record, effect.index, step));
      record.resulting = clone(this.environment.read());
      this.store.save(record);
    }

    const hasUnresolvedWork =
      record.pending !== null ||
      record.recovery.some((recovery) => recovery.outcome !== "restored");
    record.status = hasUnresolvedWork ? "recovery-required" : "compensated";
    this.store.save(record);
    return this.receipt(id);
  }

  private guardReason(record: RecordBody, context: Context): string {
    const currentVersion = this.environment.evidenceVersion(
      record.evidence.source,
    );
    if (currentVersion !== record.evidence.version) {
      return "evidence-version-changed";
    }
    return evaluateAuthorization(
      record.change,
      record.evidence,
      context,
      this.environment.now(),
    );
  }

  private executeStep(
    changeId: string,
    record: RecordBody,
    index: number,
    step: Step,
  ): boolean {
    const context = clone(this.environment.context());
    const policyChanged =
      hash(context.policy) !== hash(record.decision!.context.policy);
    const guardReason = policyChanged
      ? "policy-changed"
      : this.guardReason(record, context);

    if (guardReason !== "allowed") {
      record.failure = guardReason;
      record.status = record.effects.length ? "partial" : "failed";
      return false;
    }
    if (this.environment.read()[step.target] !== step.from) {
      record.failure = "state-conflict";
      record.status = record.effects.length ? "partial" : "failed";
      return false;
    }

    const decision: Decision = {
      at: this.environment.now(),
      context,
      allowed: true,
      reason: "allowed",
    };

    // Persist intent before external I/O so an interrupted call remains visible.
    record.pending = index;
    this.store.save(record);
    try {
      this.environment.apply(step, `${changeId}/${index}`);
      if (this.environment.read()[step.target] !== step.to) {
        throw new Error("unconfirmed downstream state");
      }
    } catch (error) {
      record.failure = String(error);
      record.status = "uncertain";
      return false;
    }

    record.effects.push({
      index,
      before: step.from,
      after: step.to,
      decision,
    });
    record.pending = null;
    record.resulting = clone(this.environment.read());
    this.store.save(record);
    return true;
  }

  private recoverEffect(
    changeId: string,
    record: RecordBody,
    index: number,
    step: Step,
  ): Recovery {
    const at = this.environment.now();
    if (step.recovery === "irreversible") {
      return {
        index,
        at,
        outcome: "manual",
        reason: "irreversible effect requires operator remediation",
      };
    }
    if (this.environment.read()[step.target] !== step.to) {
      return {
        index,
        at,
        outcome: "conflict",
        reason: "downstream state has changed",
      };
    }

    // Persist recovery intent before external I/O. Interruption cannot imply success.
    record.recovery.push({
      index,
      at,
      outcome: "unknown",
      reason: "recovery intent; outcome not confirmed",
    });
    record.status = "recovery-required";
    this.store.save(record);

    let outcome: Recovery["outcome"] = "restored";
    let reason = "compare-and-set restoration";
    try {
      this.environment.restore(step, `${changeId}/${index}/restore`);
      if (this.environment.read()[step.target] !== step.from) {
        throw new Error("restore unconfirmed");
      }
    } catch {
      outcome = "unknown";
      reason = "adapter failed; reconcile manually";
    }

    record.recovery.pop();
    return { index, at, outcome, reason };
  }
}

function assertValid(condition: boolean, reason: string): asserts condition {
  if (!condition) throw new Error(reason);
}

function verifyRecordedAuthorization(record: RecordBody): void {
  if (!record.decision?.allowed) return;
  const result = evaluateAuthorization(
    record.change,
    record.evidence,
    record.decision.context,
    record.decision.at,
  );
  assertValid(result === "allowed", "invalid-authorization");
}

function replayEffects(record: RecordBody): State {
  const state = clone(record.initial);
  for (const [position, effect] of record.effects.entries()) {
    const step = record.change.steps[effect.index];
    const effectIsConsistent =
      step !== undefined &&
      effect.index === position &&
      record.decision?.allowed === true &&
      effect.decision.allowed &&
      effect.decision.at >= record.decision.at &&
      hash(effect.decision.context.policy) ===
        hash(record.decision.context.policy) &&
      evaluateAuthorization(
        record.change,
        record.evidence,
        effect.decision.context,
        effect.decision.at,
      ) === "allowed" &&
      state[step.target] === effect.before &&
      effect.before === step.from &&
      effect.after === step.to;

    assertValid(effectIsConsistent, "invalid-effect");
    state[step.target] = effect.after;
  }
  return state;
}

function replayRecoveries(record: RecordBody, state: State): void {
  const recoveredIndexes = new Set<number>();
  for (const recovery of record.recovery) {
    const step = record.change.steps[recovery.index];
    const referencesConfirmedEffect = record.effects.some(
      (effect) => effect.index === recovery.index,
    );
    assertValid(
      step !== undefined &&
        referencesConfirmedEffect &&
        !recoveredIndexes.has(recovery.index),
      "invalid-recovery",
    );
    recoveredIndexes.add(recovery.index);

    if (recovery.outcome === "restored") {
      assertValid(
        step.recovery === "restore" && state[step.target] === step.to,
        "invalid-restoration",
      );
      state[step.target] = step.from;
    }
  }
}

function verifyTerminalState(record: RecordBody, replayedState: State): void {
  if (record.status === "committed") {
    const completeCommit =
      record.effects.length === record.change.steps.length &&
      record.pending === null &&
      record.failure === null &&
      record.recovery.length === 0;
    assertValid(completeCommit, "incomplete-commit");
  }
  if (record.status === "compensated") {
    const completeCompensation =
      record.pending === null &&
      record.recovery.length === record.effects.length &&
      record.recovery.every((recovery) => recovery.outcome === "restored");
    assertValid(completeCompensation, "incomplete-compensation");
  }
  if (record.status === "committed" || record.status === "compensated") {
    assertValid(
      hash(replayedState) === hash(record.resulting),
      "state-replay-mismatch",
    );
  }
}

/** Verify receipt integrity and replay the recorded history using a trusted key. */
export function verify(
  receipt: Receipt,
  trustedKey: KeyObject,
): { valid: boolean; reason: string } {
  try {
    const record = receipt.body;
    const signatureIsValid = verifySignature(
      null,
      Buffer.from(receipt.digest),
      trustedKey,
      Buffer.from(receipt.signature, "base64"),
    );
    assertValid(
      hash(record) === receipt.digest && signatureIsValid,
      "signature-or-digest",
    );
    assertValid(
      record.schema === 1 && hash(record.evidence) === record.evidenceHash,
      "evidence-hash",
    );

    verifyRecordedAuthorization(record);
    const replayedState = replayEffects(record);
    replayRecoveries(record, replayedState);
    verifyTerminalState(record, replayedState);

    return {
      valid: true,
      reason:
        "signature and recorded historical transitions verified; external truth not attested",
    };
  } catch (error) {
    return { valid: false, reason: String(error) };
  }
}
