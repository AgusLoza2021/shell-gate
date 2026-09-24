// S2: the policy engine.
//
// The whole repository rests on one sentence: a caller never sends a command,
// it sends a NAME. This module is where that name becomes -- or fails to
// become -- an executable argv. It is pure on purpose: text in, verdict out.
// No filesystem, no process, no clock. That is what makes the boundary itself
// testable instead of only its consequences.
//
// Two rules are worth stating outright, because both are easy to get wrong:
//
//   1. Deny is the default AND the fallback. An undeclared name does not
//      exist. There is no prefix match, no case folding, no "did you mean".
//      A suggestion is a decision the gate must never make for the caller:
//      the caller is on a low-trust channel, and the whole point is that the
//      PC, not the channel, decides what exists.
//
//   2. Safety defaults favour the cautious side. When a policy omits
//      `approval`, it becomes 'always', not 'never'. A forgotten field must
//      cost the author a prompt, never a silent execution.

import { createHash } from 'node:crypto';
import { isAbsolute } from 'node:path';

const SUPPORTED_VERSION = 1;
const NAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;
const APPROVAL_VALUES = new Set(['never', 'always']);
const DEFAULT_TIMEOUT_SECONDS = 60;
const DEFAULT_MAX_OUTPUT_BYTES = 65536;
const DEFAULT_APPROVAL = 'always';

// Closed key set. An unknown key is an error rather than a silent default,
// because the realistic failure is a typo: `timeout: 300` instead of
// `timeout_seconds: 300` would otherwise leave the author believing a 5-minute
// command is bounded when it is running on the 60-second default.
const COMMAND_KEYS = new Set([
  'description',
  'argv',
  'cwd',
  'timeout_seconds',
  'max_output_bytes',
  'approval',
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

/**
 * Parse and validate a policy document.
 *
 * Invalid input never yields a partial policy: either every command is usable
 * or the caller gets errors and no policy at all. A half-loaded policy is more
 * dangerous than a rejected one, because it looks like it worked.
 *
 * @param {string} text Raw policy document (JSON).
 * @returns {{verdict: 'ok', policy: object} | {verdict: 'invalid', errors: string[]}}
 */
export function parsePolicy(text) {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { verdict: 'invalid', errors: ['policy text must be a non-empty string'] };
  }

  let raw;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    return { verdict: 'invalid', errors: [`policy is not valid JSON: ${error.message}`] };
  }

  if (!isPlainObject(raw)) {
    return { verdict: 'invalid', errors: ['policy must be a JSON object'] };
  }

  const errors = [];

  // An unknown version must fail closed. Reading a future format with today's
  // rules could silently reinterpret a field whose meaning changed, and a
  // policy is a security boundary: a silent reinterpretation is a hole.
  if (raw.version !== SUPPORTED_VERSION) {
    errors.push(
      `policy version must be exactly ${SUPPORTED_VERSION}, got ${JSON.stringify(raw.version)}`,
    );
  }

  if (!isPlainObject(raw.commands)) {
    errors.push('policy must declare a "commands" object');
    return { verdict: 'invalid', errors };
  }

  const names = Object.keys(raw.commands);
  if (names.length === 0) {
    errors.push('policy must declare at least one command');
  }

  const commands = {};
  for (const name of names) {
    const parsed = parseCommand(name, raw.commands[name], errors);
    if (parsed !== null) commands[name] = parsed;
  }

  if (errors.length > 0) return { verdict: 'invalid', errors };
  return { verdict: 'ok', policy: { version: SUPPORTED_VERSION, commands } };
}

/**
 * Validate one declared command and apply its defaults.
 * Returns null when the command is unusable; every problem is pushed to
 * `errors` with the command name in it, so one run reports every mistake
 * instead of one mistake per run.
 */
function parseCommand(name, value, errors) {
  const where = `commands.${name}`;
  let usable = true;

  if (!NAME_PATTERN.test(name)) {
    errors.push(`${where}: name must match ${NAME_PATTERN} (lowercase, no whitespace)`);
    return null;
  }

  if (!isPlainObject(value)) {
    errors.push(`${where}: must be an object`);
    return null;
  }

  for (const key of Object.keys(value)) {
    if (!COMMAND_KEYS.has(key)) {
      errors.push(`${where}: unknown key "${key}"`);
      usable = false;
    }
  }

  let argv = null;
  const argvCheck = validateArgv(value.argv);
  if (argvCheck.verdict === 'ok') {
    argv = [...value.argv];
  } else {
    errors.push(`${where}: argv ${argvCheck.reason}`);
    usable = false;
  }

  let description = '';
  if (value.description !== undefined) {
    if (typeof value.description === 'string') {
      description = value.description;
    } else {
      errors.push(`${where}: description must be a string`);
      usable = false;
    }
  }

  let cwd = null;
  if (value.cwd !== undefined) {
    if (typeof value.cwd !== 'string' || value.cwd.length === 0) {
      errors.push(`${where}: cwd must be a non-empty string`);
      usable = false;
    } else if (!isAbsolute(value.cwd)) {
      errors.push(`${where}: cwd must be an absolute path`);
      usable = false;
    } else {
      cwd = value.cwd;
    }
  }

  let timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
  if (value.timeout_seconds !== undefined) {
    if (isPositiveSafeInteger(value.timeout_seconds)) {
      timeoutSeconds = value.timeout_seconds;
    } else {
      errors.push(`${where}: timeout_seconds must be a positive integer`);
      usable = false;
    }
  }

  let maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES;
  if (value.max_output_bytes !== undefined) {
    if (isPositiveSafeInteger(value.max_output_bytes)) {
      maxOutputBytes = value.max_output_bytes;
    } else {
      errors.push(`${where}: max_output_bytes must be a positive integer`);
      usable = false;
    }
  }

  let approval = DEFAULT_APPROVAL;
  if (value.approval !== undefined) {
    if (typeof value.approval === 'string' && APPROVAL_VALUES.has(value.approval)) {
      approval = value.approval;
    } else {
      errors.push(`${where}: approval must be one of "never", "always"`);
      usable = false;
    }
  }

  if (!usable) return null;
  return {
    name,
    description,
    argv,
    cwd,
    timeout_seconds: timeoutSeconds,
    max_output_bytes: maxOutputBytes,
    approval,
  };
}

/**
 * Turn a caller-supplied name into a declared command.
 *
 * The name is an exact key or nothing. Case folding, trimming and prefix
 * matching are all deliberate omissions: each one would let a caller reach a
 * command the policy never granted them.
 *
 * @param {object} policy Result of a successful parsePolicy.
 * @param {string} name Command name as sent by the caller.
 * @returns {{verdict: 'ok', command: object} | {verdict: 'denied', reason: string}}
 */
export function resolveCommand(policy, name) {
  if (typeof name !== 'string' || name.length === 0) {
    return { verdict: 'denied', reason: 'command name must be a non-empty string' };
  }
  if (!isPlainObject(policy) || !isPlainObject(policy.commands)) {
    return { verdict: 'denied', reason: 'policy is missing or malformed' };
  }

  // Object.hasOwn, never a bare lookup. A plain object inherits from
  // Object.prototype, so `commands[name] !== undefined` would resolve
  // `toString`, `constructor` and friends to FUNCTIONS and hand a caller
  // something executable that no policy ever declared. Only an own property
  // is a declared command.
  if (!Object.hasOwn(policy.commands, name)) {
    return { verdict: 'denied', reason: `unknown command: ${name}` };
  }

  return { verdict: 'ok', command: policy.commands[name] };
}

/**
 * Validate the shape of an argument vector.
 *
 * What is deliberately NOT checked: shell metacharacters. `;`, `&&`, `|`,
 * backticks, `$()`, `>`, `<` and quotes are accepted here, because they are
 * DATA. They only become syntax if something hands the string to a shell, and
 * this project never does that: execution uses argv with `shell: false`.
 *
 * Screening characters here would be security theatre with a real cost: it
 * would reject legitimate arguments such as a commit message containing `&&`
 * or a Windows path containing spaces. A gate that over-blocks gets switched
 * off, and a gate that is switched off protects nothing. The guarantee lives
 * in the execution call site, and the test that proves it lives in the runner
 * suite.
 *
 * @param {unknown} argv
 * @returns {{verdict: 'ok'} | {verdict: 'invalid', reason: string}}
 */
export function validateArgv(argv) {
  if (!Array.isArray(argv)) {
    return { verdict: 'invalid', reason: 'must be an array of strings, never a command string' };
  }
  if (argv.length === 0) {
    return { verdict: 'invalid', reason: 'must contain at least one element' };
  }
  for (let index = 0; index < argv.length; index += 1) {
    const element = argv[index];
    if (typeof element !== 'string') {
      return { verdict: 'invalid', reason: `element ${index} must be a string` };
    }
    if (element.length === 0) {
      return { verdict: 'invalid', reason: `element ${index} must not be empty` };
    }
    if (element.includes('\0')) {
      return { verdict: 'invalid', reason: `element ${index} must not contain a NUL byte` };
    }
  }
  return { verdict: 'ok' };
}

/**
 * Deterministic identity of an executable command: which program, with which
 * arguments, in which directory. Two identical declarations must produce the
 * same value on any run and any machine, so a later layer can bind a human
 * approval to one exact action instead of to prose that can be reinterpreted.
 *
 * Object keys are sorted before hashing (argv order is NOT sorted: argument
 * order is semantic, and `git --short status` is not `git status --short`).
 *
 * @param {{argv: string[], cwd?: string|null}} command
 * @returns {string} 16 lowercase hex characters.
 */
export function fingerprintCommand(command) {
  const canonical = JSON.stringify(
    { argv: command?.argv ?? [], cwd: command?.cwd ?? null },
    (_key, value) => {
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        return Object.fromEntries(
          Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        );
      }
      return value;
    },
  );
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}
