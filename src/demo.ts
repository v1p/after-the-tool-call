import { mkdirSync, writeFileSync } from "node:fs";
import { fixture } from "./scenario.js";
import { verify } from "./kernel.js";
mkdirSync(".local", { recursive: true });
const run = Date.now();
for (const mode of ["success", "revoked", "downstream-failure"] as const) {
  const f = fixture(`.local/${run}-${mode}.sqlite`);
  try {
    f.kernel.propose(f.change, f.evidence);
    f.kernel.authorize(f.change.id, f.env.context());
    if (mode === "revoked")
      f.env.afterApply = () => {
        f.env.controls.authority.revoked = true;
      };
    if (mode === "downstream-failure") f.env.failTarget = "campaign";
    const receipt = f.kernel.commit(f.change.id);
    const recovery =
      mode === "success" ? null : f.kernel.compensate(f.change.id);
    const final = recovery ?? receipt;
    writeFileSync(
      `.local/${run}-${mode}-receipt.json`,
      JSON.stringify(final, null, 2),
    );
    writeFileSync(
      `.local/${run}-${mode}-public.pem`,
      f.keys.publicKey.export({ type: "spki", format: "pem" }),
    );
    console.log(
      JSON.stringify(
        {
          mode,
          commit: receipt.body.status,
          recovery: recovery?.body.status ?? null,
          effects: receipt.body.effects.length,
          verification: verify(final, f.keys.publicKey),
          state: f.env.read(),
        },
        null,
        2,
      ),
    );
  } finally {
    f.store.close();
  }
}
