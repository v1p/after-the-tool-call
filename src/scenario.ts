import { generateKeyPairSync } from "node:crypto";
import {
  Kernel,
  Store,
  hash,
  type Change,
  type Context,
  type Environment,
  type Evidence,
  type State,
  type Step,
} from "./kernel.js";
export class ReleaseSystems implements Environment {
  time = 1_000;
  version = "ci-42";
  state: State = { registry: "ecu-1.0", campaign: "ecu-1.0" };
  controls: Context = {
    policy: {
      version: "release-policy-1",
      allowIrreversible: false,
      maxEvidenceAge: 500,
    },
    authority: {
      id: "delegation-7",
      principal: "release-manager",
      agent: "release-agent",
      scope: "ecu-1.1",
      expiresAt: 2_000,
      revoked: false,
    },
  };
  afterApply: (() => void) | null = null;
  failTarget: string | null = null;
  now() {
    return this.time;
  }
  context() {
    return structuredClone(this.controls);
  }
  evidenceVersion(_source: string) {
    return this.version;
  }
  read() {
    return structuredClone(this.state);
  }
  apply(step: Step, _idempotencyKey: string) {
    if (this.failTarget === step.target)
      throw new Error(
        "downstream unavailable (outcome unknown to coordinator)",
      );
    if (this.state[step.target] !== step.from)
      throw new Error("compare-and-set conflict");
    this.state[step.target] = step.to;
    this.afterApply?.();
  }
  restore(step: Step, _idempotencyKey: string) {
    if (this.state[step.target] !== step.to)
      throw new Error("compare-and-set conflict");
    this.state[step.target] = step.from;
  }
}
export function fixture(path = ":memory:") {
  const keys = generateKeyPairSync("ed25519");
  const env = new ReleaseSystems();
  const store = new Store(path);
  const kernel = new Kernel(store, env, keys.privateKey);
  const change: Change = {
    id: "release-001",
    agent: "release-agent",
    delegationId: "delegation-7",
    release: "ecu-1.1",
    steps: [
      {
        target: "registry",
        from: "ecu-1.0",
        to: "ecu-1.1",
        recovery: "restore",
      },
      {
        target: "campaign",
        from: "ecu-1.0",
        to: "ecu-1.1",
        recovery: "restore",
      },
    ],
  };
  const evidence: Evidence = {
    source: "ci://ecu/hil-suite",
    version: "ci-42",
    observedAt: 900,
    expiresAt: 1_400,
    release: "ecu-1.1",
    passed: true,
    digest: hash({
      suite: "hardware-in-loop",
      result: "pass",
      release: "ecu-1.1",
    }),
  };
  return { keys, env, store, kernel, change, evidence };
}
