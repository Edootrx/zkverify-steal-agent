# crionic-steal — a committed-policy Steal the VFY player

A head-to-head strategy agent for the **Steal the VFY** track of
[zkVerify Agent Games](https://agentgames.zkverify.io). Every move the agent
makes is proven with a Groth16 proof (BN254) against the game's
**vfy-policy** circuit: the proof attests that the action follows a strategy
that was committed *in advance* — the agent cannot improvise a move its
committed policy doesn't dictate.

This is the standalone packaging of the Steal player. The same module runs
in production inside the combined Gatekeeper+Steal agent
([zkverify-gatekeeper-agent](https://github.com/Edootrx/zkverify-gatekeeper-agent));
this repo isolates the Steal half so it can be run, tested and judged on its
own.

## Strategy

- **Params:** `[10, 0, 0, 0, 0, 0, 0, 0]`, **salt:** `98765432109876543210`
- **Policy:** EXTRACT the maximum 10 VFY every turn while the opponent holds
  a balance; HOLD otherwise. (The circuit enforces the policy exactly:
  FORTIFY if `selfBalance < p1`, HOLD if `p3 == 1` or
  `opponentBalance <= p2`, otherwise EXTRACT with `amount == p0`.)
- **Commitment** — `Poseidon(strategyParams[0..7], salt)`:
  `12232616117881309487600514696350805892481461911832571699457167963642599963874`

## How it works

- The vfy-policy circuit was reverse-engineered from its WASM/zkey by
  constraint probing — full notes in
  [research/STEAL-THE-VFY.md](research/STEAL-THE-VFY.md). The commitment is
  `Poseidon(params, salt)`; public signals are
  `[Poseidon(matchId, turn, circuitVersion), commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion]`.
- The response contract was calibrated against the live platform until all
  three practice categories came back **CORRECT with proofs VERIFIED**:
  Extract (balance 110), Fortify (102), Hold (104). That includes the exact
  `publicInputsHash` construction — keccak256 over the match state (matchId,
  turn, action code, amount, balances, fortified flags) plus all 9 public
  signals — and a deterministic UUID `idempotencyKey` per turn.
- Incoming tasks are HMAC-SHA256 verified over the raw body before parsing;
  responses are signed the same way. Turn responses are cached by
  (matchId, turn) so a re-delivered turn returns the identical signed body.
- If proof generation ever fails, the agent degrades to a bare HOLD response
  instead of timing out.

## Run it

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<your agent secret> npm start
# POST turns to /agent, check /health for the live stealCommitment
npm run test:steal   # 16 checks: policy, commitment, proof generation + verification
```

## Honest status (Agent Games, Nov 2026)

The platform locked Steal entries while its tournament was already in
progress (re-verified 15 and 18 Nov 2026), so this agent could not be paired
in this edition's Swiss rounds despite the event page advertising
mid-tournament registration. The system is complete and verified in
practice; it is ready to be paired the moment an entry window opens.
