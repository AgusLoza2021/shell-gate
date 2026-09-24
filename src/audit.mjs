// S4: the audit log.
//
// A gate whose only record is "it worked" hides the half that matters later.
// A denial that leaves no trace cannot be told apart from a request that never
// arrived, and those two need completely different responses: one is a policy
// decision, the other is a plumbing failure. So refusals are recorded with the
// same weight as executions.
//
// The record is built as a VALUE, not as a view over live objects. An audit
// line that can change after the fact because someone mutated the command it
// was built from is not an audit line.

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { fingerprintCommand } from './policy.mjs';

const defaultFs = { appendFileSync, mkdirSync };

// Outcomes in which a process actually ran. Everything else has nothing to
// measure, and reporting `0` for something that never started would read as a
// successful empty run.
const EXECUTED_OUTCOMES = new Set(['ok', 'failed', 'timedOut']);

const LOG_MODE = 0o600;

/**
 * Build one audit record.
 *
 * @param {{commandName: string, command: object|null, result: {verdict: string, reason?: string, exitCode?: number|null, durationMs?: number|null, stdoutBytes?: number|null, stderrBytes?: number|null, truncated?: object|null}, now: number}} input
 * @returns {object} A plain, JSON-serializable record.
 */
export function formatAuditRecord({ commandName, command, result, now }) {
  const outcome = result?.verdict ?? 'spawn-failed';
  const executed = EXECUTED_OUTCOMES.has(outcome);
  const hasCommand = command !== null && command !== undefined;

  const measured = (value) => (executed ? (value ?? null) : null);

  return {
    at: new Date(now).toISOString(),
    command: commandName ?? null,
    outcome,
    reason: result?.reason ?? null,
    // A denied request has no command, so there is nothing to identify. The
    // field stays present and null rather than disappearing, so every line in
    // the log has the same shape and can be read by a consumer that assumes it.
    fingerprint: hasCommand ? fingerprintCommand(command) : null,
    argv: hasCommand ? [...(command.argv ?? [])] : null,
    cwd: hasCommand ? (command.cwd ?? null) : null,
    exitCode: measured(result?.exitCode),
    durationMs: measured(result?.durationMs),
    stdoutBytes: measured(result?.stdoutBytes),
    stderrBytes: measured(result?.stderrBytes),
    truncated: measured(result?.truncated),
  };
}

/**
 * Append one record as one JSON line.
 *
 * The log is owner-only (0600): it names every command the owner allowed and
 * every one that was refused, which is a map of the machine's capabilities.
 *
 * The directory is created rather than assumed. The first real run of this
 * tool failed every command with 'could not write the audit record' because
 * `audit/` did not exist yet -- and not one unit test saw it, because every
 * one of them injected a fake filesystem. A gate that refuses to work until
 * its own log directory happens to exist is a gate nobody keeps.
 *
 * Fail closed: a failed write reports failure and never throws, because the
 * caller must be able to decide what to do about a gate whose record is
 * unreliable -- and it must not decide that by crashing.
 *
 * @param {{path: string, record: object, fsImpl?: {mkdirSync: Function, appendFileSync: Function}}} input
 * @returns {{verdict: 'ok'} | {verdict: 'failed', reason: string}}
 */
export function appendAuditRecord({ path, record, fsImpl = defaultFs } = {}) {
  if (typeof path !== 'string' || path.length === 0) {
    return { verdict: 'failed', reason: 'audit path must be a non-empty string' };
  }
  if (record === null || typeof record !== 'object') {
    return { verdict: 'failed', reason: 'audit record must be an object' };
  }

  try {
    fsImpl.mkdirSync(dirname(path), { recursive: true });
    fsImpl.appendFileSync(path, `${JSON.stringify(record)}\n`, {
      encoding: 'utf8',
      mode: LOG_MODE,
    });
  } catch (error) {
    return { verdict: 'failed', reason: `audit append failed: ${error.message}` };
  }

  return { verdict: 'ok' };
}
