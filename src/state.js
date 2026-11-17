import fs from "node:fs";
import path from "node:path";

// Persistent seen-set of proof_tx values (PROOF_REUSED detection) + idempotency
// cache of final responses per task_id. Stored as one JSON file, written
// atomically (tmp + rename) after every task so a restart never loses state.
export class StateStore {
  constructor(file) {
    this.file = file;
    this.seen = new Set();
    this.responses = new Map();
    try {
      const raw = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const t of raw.seen || []) this.seen.add(t);
      for (const [k, v] of Object.entries(raw.responses || {})) this.responses.set(k, v);
    } catch {
      // fresh start
    }
  }

  hasSeen(proofTx) {
    return proofTx != null && this.seen.has(String(proofTx).toLowerCase());
  }

  markSeen(proofTx) {
    if (proofTx != null) this.seen.add(String(proofTx).toLowerCase());
  }

  getResponse(taskId) {
    return this.responses.get(taskId);
  }

  setResponse(taskId, responseBody) {
    this.responses.set(taskId, responseBody);
  }

  save() {
    const data = {
      seen: [...this.seen],
      responses: Object.fromEntries(this.responses),
    };
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(data));
    fs.renameSync(tmp, this.file);
  }
}
