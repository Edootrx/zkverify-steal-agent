// Steal the VFY agent — standalone server.
//
// Serves the zkVerify Agent Games Steal the VFY track only: preflight
// envelopes and match turns over HMAC-signed HTTPS POSTs, answering every
// turn with a Groth16 proof that the move follows the committed strategy
// (vfy-policy circuit). The Steal module (src/steal.js) also runs in
// production inside the combined Gatekeeper+Steal agent at
// https://github.com/Edootrx/zkverify-gatekeeper-agent — this repo packages
// the Steal player on its own so it can be run, tested and judged
// independently.
//
// Strategy: params [10,0,0,0,0,0,0,0], salt 98765432109876543210 —
// EXTRACT the maximum 10 VFY every turn while the opponent holds a balance,
// HOLD otherwise. Commitment (Poseidon(params, salt)):
// 12232616117881309487600514696350805892481461911832571699457167963642599963874
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signBody, verifySignature } from "./hmac.js";
import { StateStore } from "./state.js";
import { generateProof } from "./prover.js";
import {
  initPoseidon,
  stealPolicy,
  strategyCommitment,
  publicInputsHash,
  buildStealCircuitInput,
  uuidFromHex,
  fortifiedFlag,
  ACTION_NAMES,
  DEFAULT_PARAMS,
  DEFAULT_SALT,
} from "./steal.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

const PORT = process.env.PORT || 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const AGENT_PATH = process.env.AGENT_PATH || "/agent";
const STATE_FILE = process.env.STATE_FILE || path.join(ROOT, "data", "state.json");
const STEAL_WASM = process.env.STEAL_WASM || path.join(ROOT, "circuits", "vfy-policy.wasm");
const STEAL_ZKEY = process.env.STEAL_ZKEY || path.join(ROOT, "circuits", "vfy-policy_final.zkey");
const STEAL_PARAMS = (process.env.STEAL_PARAMS || DEFAULT_PARAMS.join(","))
  .split(",")
  .map((s) => s.trim());
const STEAL_SALT = process.env.STEAL_SALT || DEFAULT_SALT;
const PROOF_BUDGET_MS = Number(process.env.PROOF_BUDGET_MS || 40000);
let STEAL_COMMITMENT = null;

const state = new StateStore(STATE_FILE);

if (!SECRET) {
  console.error(
    "WARNING: AGENT_GAMES_HMAC_SECRET is not set — signature checks will fail. " +
      "Set it from Dashboard → My Agents → Rotate Secret after registering."
  );
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("proof budget exceeded")), ms)),
  ]);
}

function sendSigned(res, obj) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (SECRET) headers["x-agent-games-signature"] = signBody(body, SECRET);
  res.writeHead(200, headers);
  res.end(body);
}

async function handleStealTurn(task, res) {
  const matchId = task.matchId;
  const turn = task.turn;
  const key = `steal:${matchId}:${turn}`;
  const cached = state.getResponse(key);
  if (cached) {
    sendSigned(res, cached);
    return;
  }

  const st = task.state || {};
  const selfBalance = BigInt(st.selfBalance ?? "0");
  const opponentBalance = BigInt(st.opponentBalance ?? "0");
  const { action, amount } = stealPolicy(STEAL_PARAMS, selfBalance, opponentBalance);

  const actionObj = { type: ACTION_NAMES[action] };
  if (action === 2) actionObj.amount = Number(amount);
  // Response schema per the official starter prompt: proof and
  // public_signals are TOP-LEVEL; policyProof carries only circuitVersion,
  // proofReference and publicInputsHash; idempotencyKey must be a uuid.
  const response = {
    matchId,
    turn,
    action: actionObj,
    policyProof: { circuitVersion: "v1" },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: uuidFromHex(signBody(key, SECRET || "no-secret")),
  };

  try {
    const circuitInput = buildStealCircuitInput({
      params: STEAL_PARAMS,
      salt: STEAL_SALT,
      commitment: STEAL_COMMITMENT,
      matchId,
      turn,
      selfBalance,
      opponentBalance,
      action,
      amount,
    });
    const { proof, publicSignals } = await withTimeout(
      generateProof(circuitInput, STEAL_WASM, STEAL_ZKEY),
      PROOF_BUDGET_MS
    );
    const inputsHash = publicInputsHash({
      matchId,
      turn,
      action,
      amount,
      selfBalance,
      opponentBalance,
      selfFortified: fortifiedFlag(st.selfFortifiedUntilTurn, turn),
      opponentFortified: fortifiedFlag(st.opponentFortifiedUntilTurn, turn),
      publicSignals,
    });
    response.proof = proof;
    response.public_signals = publicSignals;
    response.policyProof = {
      circuitVersion: "v1",
      proofReference: inputsHash,
      publicInputsHash: inputsHash,
    };
  } catch (e) {
    // Degrade gracefully: the platform treats a proof-less turn as HOLD.
    console.error(`[steal ${matchId} turn ${turn}] proof generation failed: ${e.message}`);
  }

  const body = JSON.stringify(response);
  state.setResponse(key, body);
  state.save();
  sendSigned(res, body);
  console.log(
    `[steal ${matchId} turn ${turn}] ${ACTION_NAMES[action]}${action === 2 ? " " + amount : ""}` +
      (response.proof ? " +proof" : " (no proof)")
  );
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        agent: "steal-the-vfy",
        stealCommitment: STEAL_COMMITMENT,
        stealParams: STEAL_PARAMS.map(Number),
      })
    );
    return;
  }
  if (req.method !== "POST" || !req.url.startsWith(AGENT_PATH)) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    // Verify HMAC over the RAW body BEFORE parsing (platform requirement).
    const sig = req.headers["x-agent-games-signature"];
    if (SECRET && !verifySignature(raw, sig, SECRET)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid signature" }));
      return;
    }
    let task;
    try {
      task = JSON.parse(raw.toString("utf8"));
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid json" }));
      return;
    }
    try {
      if (task.type === "agent-games.preflight.v1") {
        sendSigned(res, { ok: true, protocolVersion: "v1" });
        return;
      }
      if (task.eventId === "steal-the-vfy" || (task.matchId && task.state)) {
        await handleStealTurn(task, res);
        return;
      }
      console.error("unknown task type:", task.type);
      sendSigned(res, {
        matchId: task.matchId,
        turn: task.turn,
        action: { type: "HOLD" },
        policyProof: { circuitVersion: "v1" },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: uuidFromHex(signBody(`steal:${task.matchId}:${task.turn}`, SECRET || "no-secret")),
      });
    } catch (e) {
      console.error("handler error:", e);
      if (!res.headersSent) {
        try {
          sendSigned(res, {
            matchId: task.matchId,
            turn: task.turn,
            action: { type: "HOLD" },
            policyProof: { circuitVersion: "v1" },
            agentTimestamp: new Date().toISOString(),
            idempotencyKey: uuidFromHex(signBody(`steal:${task.matchId}:${task.turn}`, SECRET || "no-secret")),
          });
        } catch {
          res.writeHead(500);
          res.end();
        }
      }
    }
  });
});

initPoseidon()
  .then(() => {
    STEAL_COMMITMENT = strategyCommitment(STEAL_PARAMS, STEAL_SALT);
    console.log(`Steal the VFY: params=[${STEAL_PARAMS.join(",")}] commitment=${STEAL_COMMITMENT}`);
  })
  .catch((e) => console.error("Steal poseidon init failed (turns will lack proofs):", e.message))
  .finally(() => {
    server.listen(PORT, () => {
      console.log(`Steal the VFY agent listening on :${PORT}${AGENT_PATH} (health: /health)`);
    });
  });
