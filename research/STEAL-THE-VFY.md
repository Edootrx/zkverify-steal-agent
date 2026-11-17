# Steal the VFY — protocol notes (from official Build guide §06 + event page, read 15 Nov 2026 11:30 WITA)

## Entry status (verified twice, 15 Nov 11:29–11:35 WITA)
- Dashboard refuses entry: "Steal the VFY entry is locked while a tournament is in progress."
- Current tournament already paired (9 agents, R2, 11 matches). Entries lock once paired.
- Event page hero data is INCONSISTENT between loads (two different prize/schedule variants seen; one even showed a bogus leaderboard). Do not trust a single load. One variant mentioned: pairing locks Mon 16 Nov 18:30 WITA, Swiss 17–21 Nov, final Mon 23 Nov 20:00 WITA — UNVERIFIED, may indicate a second tournament window.

## Game mechanics
- Swiss 5 rounds → Top 16/32 knockout. Match = 20 turns, both agents start at 100 VFY (simulated), higher final balance wins. Match lasts 15–25 min. No rematches; pairing by similar match points.
- Actions per turn (simultaneous, deterministic resolution):
  - HOLD: no transfer.
  - FORTIFY: costs 2 VFY, blocks up to 6 VFY of incoming extraction that turn.
  - EXTRACT N: free, steals up to N (max 10) from opponent's spendable balance; fortified opponent reduces effective steal by 6.
- Scoring: win +18, draw +9, loss +3, verified-turn reliability bonus +0..+2, timeout −1/turn, invalid policy proof −2/turn.

## Turn protocol
- POST /agent signed envelope: {protocolVersion:"v1", eventId:"steal-the-vfy", mode:"competition", matchId, turn, issuedAt, deadlineAt, state:{selfBalance, opponentBalance, selfFortifiedUntilTurn, opponentFortifiedUntilTurn}, strategyCommitment:{hash}, resolverVersion:"v1", nonce}. Turn deadline 5 min (platform waits ~30s per push); missed turn = HOLD.
- Response 200 JSON (CONFIRMED by the official starter prompt + practice verification 15 Nov): {matchId, turn, action:{type:"EXTRACT", amount:5} (amount omitted for HOLD/FORTIFY), policyProof:{circuitVersion:"v1", proofReference, publicInputsHash}, proof, public_signals, agentTimestamp, idempotencyKey}. proof and public_signals are TOP-LEVEL fields, NOT inside policyProof. idempotencyKey MUST be a UUID. Missing/mistyped required field = treated as HOLD without proof.
- Circuit: vfy-policy.wasm / vfy-policy_final.zkey, vk_hash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047 (zkVerify mainnet).
- publicInputsHash — CORRECTED 15 Nov from the Build guide's actual TypeScript code block (an earlier paraphrase was WRONG and cost several failed practices): keccak256 of 32-byte big-endian fields in order: matchId (dashes removed), turn, action code (HOLD 0, FORTIFY 1, EXTRACT 2), amount (0 for HOLD/FORTIFY), selfBalance, opponentBalance, selfFortified flag (0/1), opponentFortified flag (0/1), then ALL 9 proof public signals in order. Platform recomputes and rejects mismatches.
- Strategy commitment: hash of the policy circuit, registered via Dashboard → My Agents → Edit agent (Steal the VFY section) BEFORE Swiss Round 1 opens; frozen at pairing; same agent + circuit for all 5 rounds; without an active commitment the agent cannot be paired.
- Practice envelope (observed verbatim in server logs 15 Nov 12:50 WITA): mode:"practice", state includes priorTurnHash ("0x0" on turn 1), NO strategyCommitment field, deadlineAt = issuedAt + 15s in practice.
- Practice categories: Steal — Fortify / Extract / Hold. ALL THREE VERIFIED 15 Nov 12:56–12:58 WITA (see below).

## Circuit semantics — SOLVED 15 Nov 2026 (constraint probing, probe/test-policy*.mjs)
- Inputs (17): commitment, action, amount, salt (private), selfBalance, opponentBalance, matchId, strategyParams[8] (private), turnNumber, circuitVersion.
- commitment === Poseidon(strategyParams[0..7], salt) (assert ~L72).
- Public signals (9): [Poseidon(matchId, turnNumber, circuitVersion), commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion].
- Validity: p0 ∈ [1,10], p3 ∈ {0,1}, params[4..7] === 0.
- Policy the circuit enforces (action assert ~L140, amount assert ~L149), in precedence order:
  1. selfBalance < p1 → FORTIFY (amount 0)
  2. p3 === 1 → HOLD (passive mode)
  3. opponentBalance <= p2 → HOLD
  4. else → EXTRACT with amount === p0 exactly (even if opponent balance < amount; resolver caps)
- matchId field = UUID hex without dashes as a 128-bit integer.

## Our strategy (implemented in src/steal.js, live in the server)
- Params [10,0,0,0,0,0,0,0], salt 98765432109876543210 → always EXTRACT 10 while opponent > 0, else HOLD. Rationale: EXTRACT is free, a larger amount never does worse (fortified opponent still loses amount−6), FORTIFY burns 2/turn, so max-extract guarantees at least a draw vs any policy in this circuit family and beats anyone who ever holds/fortifies.
- **Commitment: 12232616117881309487600514696350805892481461911832571699457167963642599963874** (also exposed at /health as stealCommitment). Register THIS hash in Edit agent → Steal the VFY if/when entry opens. Do NOT rotate the HMAC secret or change STEAL_PARAMS/STEAL_SALT during a tournament — the commitment would break.
- Local verification: test/steal-check.mjs 16/16 PASS incl. full Groth16 prove+verify for EXTRACT and HOLD turns; server E2E PASS (turn answered in ~1.2s warm, retries idempotent).
- **PLATFORM PRACTICE: ALL 3 CATEGORIES VERIFIED 15 Nov 2026** — Extract (12:56 WITA): CORRECT DECISION, proof VERIFIED, balance 110 (EXTRACT vs HOLD referee); Fortify (12:57): CORRECT, VERIFIED, balance 102 (EXTRACT vs EXTRACT); Hold (12:58): CORRECT, VERIFIED, balance 104 (EXTRACT vs FORTIFY: 10−6=4 ✓). Latencies 0.9–7.0s (practice deadline 15s; competition waits ~30s/push).
- Calibration saga (for future debugging): the first Steal handler nested proof/public_signals inside policyProof, used a hex idempotencyKey, and used a wrong paraphrased hash formula → generic "did not match the VFY protocol schema" failures. The diagnostic text lives only in the browser clipboard, which the browser tooling cannot paste anywhere — the decisive sources were the Railway server logs (exact request/response) and the starter prompt + TypeScript code block on the Build page read in the live browser. DEBUG_STEAL=1 env enables request/response logging in src/server.js (variable removed from Railway after calibration).

## Still open if entry reopens
1. Register the commitment above in the dashboard (Edit agent, Steal section) before pairing locks.
2. Nothing else — handler is platform-verified via practice. If a future tournament's Fortify/Hold states carry non-null fortifiedUntilTurn values, watch the first live turns: the hash's fortified flags are implemented as (untilTurn != null && untilTurn >= turn) ? 1 : 0, calibrated only against null states so far.
