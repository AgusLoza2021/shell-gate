/**
 * Approvals: decisions that outlive the invocation that made them.
 *
 * Capa 1 could only ask "are you at the keyboard right now?", which is a
 * question the person asking did not need to answer. An approval here is a
 * decision that can be made in one invocation and honoured in a later one,
 * which is what makes a gate useful when the person deciding is not the
 * process asking.
 *
 * Three failure modes appear the moment a decision outlives its invocation,
 * and every rule in this module exists to refuse one of them:
 *
 *   replay  - an old approval used again          -> consuming removes it
 *   drift   - the policy edited after approval,
 *             so `git push` silently authorises
 *             `git push --force`                  -> bound to the fingerprint
 *   staleness - an approval from last week still
 *             being live                          -> carries its own expiry
 *
 * Drift is the one worth naming. Replay is the obvious attack and the easiest
 * to test; a policy edit does not look like a security event, which is exactly
 * why an approval bound to a *name* and not to a *command* would quietly grant
 * a permission nobody gave.
 *
 * The design assumes the disk is trustworthy. It does not sign approvals and
 * does not defend a machine where the attacker can already write the policy
 * file. Reading this module should not suggest otherwise.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { fingerprintCommand, validateArgv } from './policy.mjs';

/** The only approvals file format this version understands. */
export const SUPPORTED_VERSION = 1;

/** Ten minutes: long enough for a round trip, short enough to be useless tomorrow. */
export const DEFAULT_TTL_SECONDS = 600;

/** An approvals file names which commands are one decision away from running. */
const FILE_MODE = 0o600;

const defaultFs = { mkdirSync, readFileSync, renameSync, writeFileSync };

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Milliseconds since the epoch for an ISO-8601 string, or null when the value
 * cannot be read as a time. Returning null rather than NaN keeps every caller
 * from having to remember that NaN comparisons are always false -- a subtlety
 * that would silently turn "unreadable date" into "not expired".
 *
 * @param {unknown} value
 * @returns {number|null}
 */
function parseInstant(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? milliseconds : null;
}

/**
 * An approval is usable strictly before it expires. At the expiry instant it is
 * already gone: a closed boundary is the only kind a reader can reason about
 * without checking which comparison was used.
 *
 * @param {object} approval
 * @param {number} now
 * @returns {boolean}
 */
function isUsableAt(approval, now) {
  const expiresAt = parseInstant(approval.expiresAt);
  return expiresAt !== null && now < expiresAt;
}

/**
 * Build a one-use approval for one exact command.
 *
 * The result is a plain value with no reference to the command it came from,
 * so a later policy reload cannot change what was approved.
 *
 * @param {{commandName: string, command: {argv: string[], cwd?: string|null}, now: number, ttlSeconds?: number}} input
 * @returns {{verdict: 'ok', approval: object} | {verdict: 'invalid', errors: string[]}}
 */
export function createApproval({
  commandName,
  command,
  now,
  ttlSeconds = DEFAULT_TTL_SECONDS,
} = {}) {
  const errors = [];

  if (typeof commandName !== 'string' || commandName.length === 0) {
    errors.push('command name must be a non-empty string');
  }
  if (!isPlainObject(command)) {
    errors.push('command must be an object');
  } else {
    const argvResult = validateArgv(command.argv);
    if (argvResult.verdict !== 'ok') errors.push(`command argv ${argvResult.reason}`);
  }
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
    errors.push(`ttlSeconds must be a positive whole number of seconds, got ${JSON.stringify(ttlSeconds)}`);
  }
  if (!Number.isFinite(now)) {
    errors.push('now must be a number');
  }

  if (errors.length > 0) return { verdict: 'invalid', errors };

  return {
    verdict: 'ok',
    approval: {
      command: commandName,
      fingerprint: fingerprintCommand(command),
      grantedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlSeconds * 1000).toISOString(),
    },
  };
}

/**
 * Read one approval entry, pushing errors prefixed with its index. Returns null
 * on any problem, so a malformed entry can never be returned as usable.
 *
 * @param {unknown} entry
 * @param {string[]} errors
 * @param {number} index
 * @returns {object|null}
 */
function parseApprovalEntry(entry, errors, index) {
  const at = `approvals.${index}`;
  const before = errors.length;

  if (!isPlainObject(entry)) {
    errors.push(`${at} must be an object`);
    return null;
  }
  if (typeof entry.command !== 'string' || entry.command.length === 0) {
    errors.push(`${at}.command must be a non-empty string`);
  }
  if (typeof entry.fingerprint !== 'string' || entry.fingerprint.length === 0) {
    errors.push(`${at}.fingerprint must be a non-empty string`);
  }

  const grantedAt = parseInstant(entry.grantedAt);
  if (grantedAt === null) errors.push(`${at}.grantedAt must be an ISO-8601 instant`);

  const expiresAt = parseInstant(entry.expiresAt);
  if (expiresAt === null) errors.push(`${at}.expiresAt must be an ISO-8601 instant`);

  // Expiring before or when it was granted is not a very short approval, it is
  // a record that cannot mean anything. Accepting it would mean accepting a
  // window whose direction we guessed.
  if (grantedAt !== null && expiresAt !== null && expiresAt <= grantedAt) {
    errors.push(`${at}.expiresAt must be after ${at}.grantedAt`);
  }

  if (errors.length !== before) return null;

  // A copy, so nothing that happens later can rewrite what was read.
  return {
    command: entry.command,
    fingerprint: entry.fingerprint,
    grantedAt: entry.grantedAt,
    expiresAt: entry.expiresAt,
  };
}

/**
 * Parse an approvals document. Fails closed: an unreadable document yields no
 * approvals at all, never a partial list and never a permissive default.
 *
 * @param {string} text
 * @returns {{verdict: 'ok', approvals: object[]} | {verdict: 'invalid', errors: string[]}}
 */
export function parseApprovals(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { verdict: 'invalid', errors: ['approvals document must be a non-empty string'] };
  }

  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    return {
      verdict: 'invalid',
      errors: [`approvals document is not valid JSON: ${error.message}`],
    };
  }

  if (!isPlainObject(document)) {
    return { verdict: 'invalid', errors: ['approvals document must be a JSON object'] };
  }
  // A future format could redefine a field whose meaning decides what runs, so
  // reading it with today's rules is not a smaller risk than refusing to read
  // it at all.
  if (document.version !== SUPPORTED_VERSION) {
    return {
      verdict: 'invalid',
      errors: [`unsupported approvals version: ${JSON.stringify(document.version)}`],
    };
  }
  if (!Array.isArray(document.approvals)) {
    return { verdict: 'invalid', errors: ['approvals must be an array'] };
  }

  const errors = [];
  const approvals = [];
  document.approvals.forEach((entry, index) => {
    const parsed = parseApprovalEntry(entry, errors, index);
    if (parsed !== null) approvals.push(parsed);
  });

  if (errors.length > 0) return { verdict: 'invalid', errors };
  return { verdict: 'ok', approvals };
}

/**
 * Read the approvals file.
 *
 * Absence and damage are deliberately different outcomes. A missing file means
 * nothing has been approved yet, which is the normal state of a new clone and
 * not an error. A file that exists but cannot be read settles nothing, so it is
 * reported as invalid and the caller fails closed.
 *
 * @param {{path: string, fsImpl?: {readFileSync: Function}}} input
 * @returns {{verdict: 'ok', approvals: object[]} | {verdict: 'invalid', errors: string[]}}
 */
export function readApprovals({ path, fsImpl = defaultFs } = {}) {
  if (typeof path !== 'string' || path.length === 0) {
    return { verdict: 'invalid', errors: ['approvals path must be a non-empty string'] };
  }

  let text;
  try {
    text = fsImpl.readFileSync(path, 'utf8');
  } catch (error) {
    if (error && error.code === 'ENOENT') return { verdict: 'ok', approvals: [] };
    return {
      verdict: 'invalid',
      errors: [`could not read the approvals file: ${error.message}`],
    };
  }

  return parseApprovals(text);
}

/**
 * Find an approval that authorises this exact command right now.
 *
 * Every refusal carries the reason it happened, because "you have no approval"
 * and "your approval is for a different command" send the owner to different
 * places: the first to the approve command, the second to whatever edited the
 * policy.
 *
 * Pure: it decides, it does not delete. Consuming is a separate effect.
 *
 * @param {object[]} approvals
 * @param {{commandName: string, command: object, now: number}} input
 * @returns {{verdict: 'ok', approval: object} | {verdict: 'denied', reason: string}}
 */
export function findUsableApproval(approvals, { commandName, command, now } = {}) {
  if (!Array.isArray(approvals)) {
    return { verdict: 'denied', reason: 'the approvals file holds no list of approvals' };
  }

  const named = approvals.filter(
    (approval) => isPlainObject(approval) && approval.command === commandName,
  );
  if (named.length === 0) {
    return {
      verdict: 'denied',
      reason: `no approval for "${commandName}"`,
    };
  }

  const expected = fingerprintCommand(command);
  const matching = named.filter((approval) => approval.fingerprint === expected);
  if (matching.length === 0) {
    return {
      verdict: 'denied',
      reason:
        `the approval for "${commandName}" was granted for a different command: ` +
        'the policy changed after it was approved',
    };
  }

  const usable = matching.find((approval) => isUsableAt(approval, now));
  if (usable !== undefined) return { verdict: 'ok', approval: usable };

  const latest = matching.reduce((a, b) =>
    parseInstant(b.expiresAt) > parseInstant(a.expiresAt) ? b : a,
  );
  return {
    verdict: 'denied',
    reason: `the approval for "${commandName}" expired at ${latest.expiresAt}`,
  };
}

/**
 * Replace the approvals file atomically.
 *
 * Written to a temporary file and renamed into place. A half-written approvals
 * file is not cosmetic: it fails closed forever, so the gate would refuse every
 * command until a human noticed, and the cause would look like a corrupted
 * configuration rather than an interrupted write.
 *
 * @param {{path: string, approvals: object[], fsImpl: object}} input
 * @returns {{verdict: 'ok'} | {verdict: 'failed', reason: string}}
 */
function writeApprovals({ path, approvals, fsImpl }) {
  const temporaryPath = `${path}.tmp`;
  try {
    fsImpl.mkdirSync(dirname(path), { recursive: true });
    fsImpl.writeFileSync(
      temporaryPath,
      `${JSON.stringify({ version: SUPPORTED_VERSION, approvals }, null, 2)}\n`,
      { encoding: 'utf8', mode: FILE_MODE },
    );
    fsImpl.renameSync(temporaryPath, path);
    return { verdict: 'ok' };
  } catch (error) {
    return { verdict: 'failed', reason: `could not write the approvals file: ${error.message}` };
  }
}

/**
 * Grant an approval and record it.
 *
 * Expired approvals are dropped while granting, not by a timer. The file is a
 * list of pending decisions, so an expired one kept around is a decision
 * waiting to be misread as still-pending, and nothing prunes it otherwise.
 *
 * @param {{path: string, commandName: string, command: object, now: number, ttlSeconds?: number, fsImpl?: object}} input
 * @returns {{verdict: 'ok', approval: object} | {verdict: 'failed', reason: string}}
 */
export function grantApproval({
  path,
  commandName,
  command,
  now,
  ttlSeconds = DEFAULT_TTL_SECONDS,
  fsImpl = defaultFs,
} = {}) {
  const created = createApproval({ commandName, command, now, ttlSeconds });
  if (created.verdict !== 'ok') {
    return { verdict: 'failed', reason: created.errors.join('; ') };
  }

  const existing = readApprovals({ path, fsImpl });
  if (existing.verdict !== 'ok') {
    return { verdict: 'failed', reason: existing.errors.join('; ') };
  }

  const kept = existing.approvals.filter((approval) => isUsableAt(approval, now));
  const written = writeApprovals({
    path,
    approvals: [...kept, created.approval],
    fsImpl,
  });
  if (written.verdict !== 'ok') return { verdict: 'failed', reason: written.reason };

  return { verdict: 'ok', approval: created.approval };
}

/**
 * Consume the approval that authorises this exact command, if there is one.
 *
 * This is the only place an approval stops existing, and it happens in the same
 * step that reports success: an approval reported as used must actually be
 * gone, because the alternative is a decision that keeps working after it has
 * been spent.
 *
 * Note what is not claimed: the read and the write are separate system calls,
 * so two processes racing on one approval can both find it unused. The rename
 * makes the file consistent, not the decision, and a lock file is out of scope
 * here. That limitation belongs in the README rather than in a comment nobody
 * reads.
 *
 * @param {{path: string, commandName: string, command: object, now: number, fsImpl?: object}} input
 * @returns {{verdict: 'ok', approval: object} | {verdict: 'denied', reason: string} | {verdict: 'failed', reason: string}}
 */
export function consumeApproval({
  path,
  commandName,
  command,
  now,
  fsImpl = defaultFs,
} = {}) {
  const existing = readApprovals({ path, fsImpl });
  if (existing.verdict !== 'ok') {
    return { verdict: 'failed', reason: existing.errors.join('; ') };
  }

  const found = findUsableApproval(existing.approvals, { commandName, command, now });
  if (found.verdict !== 'ok') {
    return { verdict: 'denied', reason: found.reason };
  }

  // Identity, not equality: the approval came out of this array, so the exact
  // entry that was judged usable is the exact entry that gets removed.
  const remaining = existing.approvals.filter((approval) => approval !== found.approval);
  const written = writeApprovals({ path, approvals: remaining, fsImpl });
  if (written.verdict !== 'ok') return { verdict: 'failed', reason: written.reason };

  return { verdict: 'ok', approval: found.approval };
}
