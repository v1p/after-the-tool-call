import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { verify } from "./kernel.js";
const [receiptPath, keyPath] = process.argv.slice(2);
if (!receiptPath || !keyPath) {
  console.error(
    "Usage: node dist/src/verify-cli.js <receipt.json> <trusted-public.pem>",
  );
  process.exitCode = 2;
} else {
  try {
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    const result = verify(receipt, createPublicKey(readFileSync(keyPath)));
    console.log(
      JSON.stringify({ ...result, status: receipt.body?.status }, null, 2),
    );
    if (!result.valid) process.exitCode = 1;
  } catch (error) {
    console.error(String(error));
    process.exitCode = 1;
  }
}
