// Steal the VFY protocol support.
//
// Circuit semantics reverse-engineered from circuits/vfy-policy.wasm
// (template VfyPolicyProof) on 2026-11-15 by constraint probing — see
// research/STEAL-THE-VFY.md. Inputs (17): commitment, action, amount, salt
// (private), selfBalance, opponentBalance, matchId, strategyParams[8]
// (private), turnNumber, circuitVersion.
//   commitment === Poseidon(strategyParams[0..7], salt)
//   public signals: [Poseidon(matchId, turnNumber, circuitVersion),
//     commitment, matchId, turnNumber, selfBalance, opponentBalance,
//     action, amount, circuitVersion]
// Param validity enforced by the circuit: p0 in [1,10], p3 in {0,1},
// params[4..7] === 0. Policy (circuit asserts action/amount match exactly):
//   1. selfBalance < p1            -> FORTIFY (amount 0)
//   2. p3 === 1                    -> HOLD
//   3. opponentBalance <= p2       -> HOLD
//   4. otherwise                   -> EXTRACT, amount === p0
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");

let poseidonFn = null;
let poseidonF = null;
export async function initPoseidon() {
  if (poseidonFn) return;
  const { buildPoseidon } = await import("circomlibjs");
  const p = await buildPoseidon();
  poseidonFn = p;
  poseidonF = p.F;
}

export function poseidonHash(values) {
  if (!poseidonFn) throw new Error("poseidon not initialised");
  return poseidonF.toString(poseidonFn(values.map((v) => BigInt(v))));
}

// Our committed strategy: always EXTRACT the max (10). EXTRACT is free and
// stealing is capped by the resolver; a bigger amount never does worse
// (vs a fortified opponent it still nets amount-6). Never fortify (burns 2),
// never hold while the opponent has a spendable balance.
export const DEFAULT_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];
export const DEFAULT_SALT = "98765432109876543210";

export function stealPolicy(params, selfBalance, opponentBalance) {
  const [p0, p1, p2, p3] = params.map((x) => BigInt(x));
  const self = BigInt(selfBalance);
  const opp = BigInt(opponentBalance);
  if (self < p1) return { action: 1, amount: 0n }; // FORTIFY
  if (p3 === 1n) return { action: 0, amount: 0n }; // HOLD (passive mode)
  if (opp <= p2) return { action: 0, amount: 0n }; // HOLD (nothing worth taking)
  return { action: 2, amount: p0 }; // EXTRACT
}

export function strategyCommitment(params, salt) {
  return poseidonHash([...params.map((x) => BigInt(x)), BigInt(salt)]);
}

export function matchIdToField(matchId) {
  // UUID string -> 128-bit integer (dashes removed), as the platform packs it.
  const hex = String(matchId).replace(/-/g, "");
  return BigInt("0x" + hex);
}

function be32(v) {
  let h = BigInt(v).toString(16);
  if (h.length > 64) throw new Error("value does not fit 32 bytes");
  return Buffer.from(h.padStart(64, "0"), "hex");
}

// publicInputsHash per the official Build guide TypeScript (read verbatim
// 2026-11-15): keccak256 over ABI-packed 32-byte big-endian fields, in order:
// matchId, turn, action code, amount, my balance, opponent balance,
// myFortified, oppFortified, then EVERY public signal of the proof.
// (An earlier paraphrase of this formula was wrong; the code block on the
// page is authoritative.)
export function publicInputsHash({ matchId, turn, action, amount, selfBalance, opponentBalance, selfFortified, opponentFortified, publicSignals }) {
  const packed = Buffer.concat([
    be32(matchIdToField(matchId)),
    be32(turn),
    be32(action),
    be32(amount),
    be32(selfBalance),
    be32(opponentBalance),
    be32(selfFortified),
    be32(opponentFortified),
    ...publicSignals.map((s) => be32(s)),
  ]);
  return "0x" + keccak256(packed);
}

export function buildStealCircuitInput({ params, salt, commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  return {
    commitment: String(commitment),
    action: String(action),
    amount: String(amount),
    salt: String(salt),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    matchId: matchIdToField(matchId).toString(),
    strategyParams: params.map(String),
    turnNumber: String(turn),
    circuitVersion: "1",
  };
}

// Deterministic UUID (v4-shaped) from a hex digest — the platform requires
// idempotencyKey to be a uuid and rejects re-used keys.
export function uuidFromHex(hex) {
  const h = String(hex).replace(/[^0-9a-f]/gi, "").slice(0, 32).padStart(32, "0").split("");
  h[12] = "4";
  h[16] = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  const s = h.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

// Fortified flag for the hash: 1 while a fortify is active at this turn.
export function fortifiedFlag(untilTurn, turn) {
  return untilTurn != null && Number(untilTurn) >= Number(turn) ? 1 : 0;
}

export const ACTION_NAMES = { 0: "HOLD", 1: "FORTIFY", 2: "EXTRACT" };
