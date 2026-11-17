// Steal the VFY checks: policy truth table (from circuit probing),
// commitment known-answer, publicInputsHash shape, and full Groth16
// prove + verify for an EXTRACT turn and a HOLD turn.
import * as snarkjs from "snarkjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  initPoseidon,
  stealPolicy,
  strategyCommitment,
  publicInputsHash,
  buildStealCircuitInput,
  uuidFromHex,
  DEFAULT_PARAMS,
  DEFAULT_SALT,
} from "../src/steal.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const WASM = path.join(ROOT, "circuits", "vfy-policy.wasm");
const ZKEY = path.join(ROOT, "circuits", "vfy-policy_final.zkey");

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log("PASS", name); }
  else { fail++; console.log("FAIL", name); }
}

await initPoseidon();

// --- policy truth table (mirrors the circuit exactly) ---
const P = DEFAULT_PARAMS;
check("extract when opp > 0", (() => { const r = stealPolicy(P, 100n, 100n); return r.action === 2 && r.amount === 10n; })());
check("hold when opp = 0", stealPolicy(P, 100n, 0n).action === 0);
check("fortify when self < p1", (() => { const r = stealPolicy([10, 50, 0, 0, 0, 0, 0, 0], 20n, 100n); return r.action === 1 && r.amount === 0n; })());
check("no fortify at self == p1", stealPolicy([10, 50, 0, 0, 0, 0, 0, 0], 50n, 100n).action === 2);
check("hold when opp <= p2", stealPolicy([10, 0, 50, 0, 0, 0, 0, 0], 100n, 50n).action === 0);
check("extract when opp > p2", stealPolicy([10, 0, 50, 0, 0, 0, 0, 0], 100n, 51n).action === 2);
check("passive p3=1 holds", stealPolicy([10, 0, 0, 1, 0, 0, 0, 0], 100n, 100n).action === 0);
check("fortify beats passive", stealPolicy([10, 50, 0, 1, 0, 0, 0, 0], 20n, 100n).action === 1);

// --- commitment known answer (computed 2026-11-15 from the circuit) ---
const commitment = strategyCommitment(P, DEFAULT_SALT);
check(
  "commitment known answer",
  commitment === "12232616117881309487600514696350805892481461911832571699457167963642599963874"
);

// --- publicInputsHash shape (Build guide TypeScript formula) ---
const h = publicInputsHash({
  matchId: "9f4e1b2a-1234-4abc-8def-0123456789ab",
  turn: 3, action: 2, amount: 10n,
  selfBalance: 95n, opponentBalance: 105n,
  selfFortified: 0, opponentFortified: 0,
  publicSignals: ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
});
check("publicInputsHash is 0x + 64 hex", /^0x[0-9a-f]{64}$/.test(h));
check("uuidFromHex shape", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuidFromHex("81621ee1f2ea12e415955fe5ac18db7441c60099f2bcbc6d18e116f7173e114b")));

// --- full prove + verify: EXTRACT turn ---
const matchId = "9f4e1b2a-1234-4abc-8def-0123456789ab";
const input = buildStealCircuitInput({
  params: P, salt: DEFAULT_SALT, commitment, matchId,
  turn: 3, selfBalance: 95n, opponentBalance: 105n, action: 2, amount: 10n,
});
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
check("public signals count 9", publicSignals.length === 9);
check("public[1] is commitment", publicSignals[1] === commitment);
check("public[2] is matchId field", publicSignals[2] === BigInt("0x9f4e1b2a12344abc8def0123456789ab").toString());
const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
check("extract proof verifies", await snarkjs.groth16.verify(vk, publicSignals, proof));

// --- full prove + verify: HOLD turn (opp = 0) ---
const input2 = buildStealCircuitInput({
  params: P, salt: DEFAULT_SALT, commitment, matchId,
  turn: 20, selfBalance: 180n, opponentBalance: 0n, action: 0, amount: 0n,
});
const r2 = await snarkjs.groth16.fullProve(input2, WASM, ZKEY);
check("hold proof verifies", await snarkjs.groth16.verify(vk, r2.publicSignals, r2.proof));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
