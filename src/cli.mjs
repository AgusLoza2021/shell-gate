// S5: the command line.
//
// The CLI is thin, but it owns one thing nothing else owns: the exit code.
// That number is the only channel a scheduled task, a script or a future chat
// adapter can act on without parsing prose, so every scenario gets a distinct
// documented value instead of collapsing into "it failed".
//
// The refusals are the interesting half. A denial exits 3 and starts nothing;
// a pending approval exits 4 and starts nothing. Both are written to the audit
// log first, so "the gate said no" leaves evidence, which is exactly the case
// an owner most needs to reconstruct later.
//
// A3 added a second way to say yes -- a decision recorded earlier by `approve`
// -- and deliberately no new exit code for it. "Nobody ever approved this" and
// "the approval expired" and "the policy changed since" are all the same
// answer to the only question an exit code can carry: a human has to decide.
// Splitting one of those three out would have been arbitrary, and the precise
// fact travels instead in the reason on stderr, in the audit record and in the
// --json line, which is where a caller that cares about the difference looks.
//
// Failing closed on an unreadable approvals store is the one behaviour worth
// stating twice: a store we could not verify grants nothing, so the command
// does not run. An approval that cannot be checked is not an approval.

import { readFileSync } from 'node:fs';

import { parsePolicy, resolveCommand } from './policy.mjs';
import { formatAuditRecord, appendAuditRecord } from './audit.mjs';
import { runCommand } from './runner.mjs';
import { DEFAULT_TTL_SECONDS, consumeApproval, grantApproval } from './approval.mjs';

/**
 * Exit codes. Stable public contract -- a caller switches on these numbers,
 * so they must not be renumbered once published.
 */
export const EXIT = {
  OK: 0,
  USAGE: 1,
  POLICY: 2,
  DENIED: 3,
  APPROVAL_REQUIRED: 4,
  COMMAND_FAILED: 5,
  UNAVAILABLE: 6,
};

const DEFAULT_POLICY_PATH = 'shell-gate.json';
const DEFAULT_AUDIT_PATH = 'audit/shell-gate.jsonl';
const DEFAULT_APPROVALS_PATH = 'approvals.json';

// Machine verdicts are camelCase; a human reading stderr should not have to
// decode that, and 'timedOut' reads as a typo rather than a sentence.
const OUTCOME_TEXT = {
  ok: 'ok',
  failed: 'failed',
  timedOut: 'timed out',
  'spawn-failed': 'could not start',
};

const USAGE = `usage: shell-gate <command> [options]

commands:
  list                  show every declared command
  check <name>          show what <name> would run, without running it
  approve <name>        record a one-use approval for <name>
  run <name>            run <name>

options:
  --yes, -y             approve a command whose approval is "always"
  --ttl=<seconds>       how long an approval stays valid (default: ${DEFAULT_TTL_SECONDS})
  --json                print one machine-readable JSON line
  --policy=<path>       policy file (default: ${DEFAULT_POLICY_PATH})
  --audit=<path>        audit log (default: ${DEFAULT_AUDIT_PATH})
  --approvals=<path>    approvals file (default: ${DEFAULT_APPROVALS_PATH})
  --help, -h            show this text

exit codes:
  0  ran and exited 0
  1  usage error
  2  the policy is missing, unreadable or invalid
  3  the name is not declared in the policy
  4  approval is required and no usable approval was found
  5  the command ran and exited non-zero
  6  the command timed out, could not start, or its record could not be written
`;

/**
 * Run the CLI.
 *
 * Collaborators are injected so the behaviour can be tested without a real
 * process, a real disk or a real clock -- and so the tests can assert the
 * strongest property this program has: that a refusal spawns nothing.
 *
 * @param {{argv?: string[], deps?: object}} input
 * @returns {Promise<number>} One of EXIT.
 */
export async function main({ argv = [], deps = {} } = {}) {
  const {
    readFile = (path) => readFileSync(path, 'utf8'),
    runCommand: runCommandImpl = runCommand,
    appendAuditRecord: appendAuditRecordImpl = appendAuditRecord,
    consumeApproval: consumeApprovalImpl = consumeApproval,
    grantApproval: grantApprovalImpl = grantApproval,
    now = Date.now,
    write = (text) => process.stdout.write(text),
    writeError = (text) => process.stderr.write(text),
  } = deps;

  const flags = {
    yes: false,
    json: false,
    help: false,
    ttlSeconds: null,
    policyPath: DEFAULT_POLICY_PATH,
    auditPath: DEFAULT_AUDIT_PATH,
    approvalsPath: DEFAULT_APPROVALS_PATH,
  };
  const positional = [];

  for (const token of argv) {
    if (token === '--yes' || token === '-y') flags.yes = true;
    else if (token === '--json') flags.json = true;
    else if (token === '--help' || token === '-h') flags.help = true;
    else if (token.startsWith('--policy=')) flags.policyPath = token.slice('--policy='.length);
    else if (token.startsWith('--audit=')) flags.auditPath = token.slice('--audit='.length);
    else if (token.startsWith('--approvals=')) {
      flags.approvalsPath = token.slice('--approvals='.length);
    } else if (token.startsWith('--ttl=')) {
      const raw = token.slice('--ttl='.length);
      // Strictly digits. '1.5' and '30s' must not be silently rounded or
      // truncated into a lifetime nobody chose -- an approval's expiry is a
      // security boundary, so a malformed one is refused, not repaired.
      if (!/^\d+$/.test(raw) || Number(raw) <= 0) {
        writeError(
          `shell-gate: --ttl needs a positive whole number of seconds, got ${JSON.stringify(raw)}\n\n${USAGE}`,
        );
        return EXIT.USAGE;
      }
      flags.ttlSeconds = Number(raw);
    } else if (token.startsWith('-')) {
      writeError(`shell-gate: unknown flag: ${token}\n\n${USAGE}`);
      return EXIT.USAGE;
    } else positional.push(token);
  }

  const [subcommand, name] = positional;

  if (flags.help) {
    write(USAGE);
    return EXIT.OK;
  }
  if (subcommand === undefined) {
    writeError(USAGE);
    return EXIT.USAGE;
  }
  // Reject an unknown subcommand before touching the policy: "the file is
  // missing" is a misleading answer to "you typed the command wrong".
  if (!['list', 'check', 'approve', 'run'].includes(subcommand)) {
    writeError(`shell-gate: unknown command: ${subcommand}\n\n${USAGE}`);
    return EXIT.USAGE;
  }
  if (subcommand !== 'list' && (name === undefined || name.length === 0)) {
    writeError(`shell-gate: ${subcommand} needs a command name\n\n${USAGE}`);
    return EXIT.USAGE;
  }

  let policyText;
  try {
    policyText = readFile(flags.policyPath);
  } catch (error) {
    writeError(`shell-gate: cannot read policy ${flags.policyPath}: ${error.message}\n`);
    return EXIT.POLICY;
  }

  const parsedPolicy = parsePolicy(policyText);
  if (parsedPolicy.verdict !== 'ok') {
    writeError(`shell-gate: policy ${flags.policyPath} is invalid:\n`);
    for (const error of parsedPolicy.errors) writeError(`  - ${error}\n`);
    return EXIT.POLICY;
  }
  const policy = parsedPolicy.policy;

  const audit = (input) => {
    const written = appendAuditRecordImpl({
      path: flags.auditPath,
      record: formatAuditRecord(input),
    });
    if (written.verdict !== 'ok') {
      // An execution we cannot account for is a serious condition for a gate,
      // so it is reported loudly rather than swallowed.
      writeError(`shell-gate: could not write the audit record: ${written.reason}\n`);
      return false;
    }
    return true;
  };

  if (subcommand === 'list') {
    if (flags.json) {
      write(`${JSON.stringify({ policy: flags.policyPath, commands: policy.commands })}\n`);
      return EXIT.OK;
    }
    write(`shell-gate: ${Object.keys(policy.commands).length} command(s) declared in ${flags.policyPath}\n`);
    for (const command of Object.values(policy.commands)) {
      const summary = command.description || command.argv.join(' ');
      write(`  ${command.name.padEnd(20)} ${command.approval.padEnd(6)} ${summary}\n`);
    }
    return EXIT.OK;
  }

  if (subcommand === 'check') {
    const resolved = resolveCommand(policy, name);
    if (resolved.verdict !== 'ok') {
      writeError(`shell-gate: unknown command: ${name}\n`);
      if (flags.json) write(`${JSON.stringify({ command: name, outcome: 'denied' })}\n`);
      return EXIT.DENIED;
    }
    const target = resolved.command;

    if (flags.json) {
      write(`${JSON.stringify(target)}\n`);
      return EXIT.OK;
    }
    write(`${target.name}: allowed\n`);
    write(`  description  ${target.description || '(none)'}\n`);
    write(`  argv         ${target.argv.join(' ')}\n`);
    write(`  cwd          ${target.cwd ?? '(inherited)'}\n`);
    write(`  timeout      ${target.timeout_seconds}s\n`);
    write(`  max output   ${target.max_output_bytes} bytes\n`);
    write(`  approval     ${target.approval}\n`);
    return EXIT.OK;
  }

  // A denial is three effects that must never drift apart: a record, a message
  // and a number. Written once so they cannot.
  const deny = (commandName, reason) => {
    audit({ commandName, command: null, result: { verdict: 'denied', reason }, now: now() });
    writeError(`shell-gate: unknown command: ${commandName}\n`);
    if (flags.json) {
      write(`${JSON.stringify({ command: commandName, outcome: 'denied', reason })}\n`);
    }
    return EXIT.DENIED;
  };

  if (subcommand === 'approve') {
    const resolved = resolveCommand(policy, name);
    if (resolved.verdict !== 'ok') return deny(name, resolved.reason);
    const target = resolved.command;

    const granted = grantApprovalImpl({
      path: flags.approvalsPath,
      commandName: name,
      command: target,
      now: now(),
      ttlSeconds: flags.ttlSeconds ?? DEFAULT_TTL_SECONDS,
    });
    if (granted.verdict !== 'ok') {
      writeError(`shell-gate: could not record the approval: ${granted.reason}\n`);
      return EXIT.UNAVAILABLE;
    }

    // A decision is a security event, so it gets a record like one. Without it
    // the log could show a run authorised by 'stored' and no evidence of anyone
    // ever having stored anything. 'granted' is not an executed outcome, so the
    // audit module already records it with no measurements but with the
    // command's fingerprint -- which is the shape this event wants.
    audit({
      commandName: name,
      command: target,
      result: { verdict: 'granted' },
      approval: 'stored',
      now: now(),
    });

    if (target.approval === 'never') {
      writeError(
        `shell-gate: note: "${name}" never requires approval, so this decision will not be used unless the policy changes\n`,
      );
    }

    if (flags.json) {
      write(
        `${JSON.stringify({
          command: name,
          outcome: 'granted',
          fingerprint: granted.approval.fingerprint,
          grantedAt: granted.approval.grantedAt,
          expiresAt: granted.approval.expiresAt,
        })}\n`,
      );
    } else {
      write(`approved: ${name} (one use)\n`);
      write(`  fingerprint  ${granted.approval.fingerprint}\n`);
      write(`  granted at   ${granted.approval.grantedAt}\n`);
      write(`  expires      ${granted.approval.expiresAt}\n`);
    }
    return EXIT.OK;
  }

  // subcommand === 'run'
  const resolved = resolveCommand(policy, name);
  if (resolved.verdict !== 'ok') return deny(name, resolved.reason);
  const target = resolved.command;

  // The approval gate sits before the runner, not inside it: the runner's job
  // is to run a command that was already authorised. A refusal here must not
  // reach it at all, and the tests assert exactly that.
  let approvalKind = 'not-required';
  if (target.approval === 'always') {
    if (flags.yes) {
      // A decision made in the moment wins over a stored one because it is the
      // only one that costs nothing a later invocation could have spent.
      approvalKind = 'interactive';
    } else {
      const consumed = consumeApprovalImpl({
        path: flags.approvalsPath,
        commandName: name,
        command: target,
        now: now(),
      });
      // Fail closed. A store that cannot be read settles nothing, so the command
      // does not run on the strength of an approval that was never verified.
      // The refusal is audited like every other one: 'needs-approval' plus a
      // reason that names the real cause, because a gate that goes quiet exactly
      // when its own bookkeeping breaks leaves nothing to investigate.
      if (consumed.verdict === 'failed') {
        audit({
          commandName: name,
          command: target,
          result: { verdict: 'needs-approval', reason: consumed.reason },
          now: now(),
        });
        writeError(`shell-gate: ${consumed.reason}\n`);
        return EXIT.UNAVAILABLE;
      }
      if (consumed.verdict !== 'ok') {
        audit({
          commandName: name,
          command: target,
          result: { verdict: 'needs-approval', reason: consumed.reason },
          now: now(),
        });
        writeError(`shell-gate: "${name}" requires approval: ${consumed.reason}\n`);
        writeError(
          `shell-gate: re-run with --yes to approve it now, or record one in advance: shell-gate approve ${name}\n`,
        );
        if (flags.json) {
          write(
            `${JSON.stringify({ command: name, outcome: 'needs-approval', reason: consumed.reason })}\n`,
          );
        }
        return EXIT.APPROVAL_REQUIRED;
      }
      approvalKind = 'stored';
    }
  }

  const result = await runCommandImpl({ command: target });
  const recorded = audit({
    commandName: name,
    command: target,
    result,
    approval: approvalKind,
    now: now(),
  });

  if (flags.json) {
    write(
      `${JSON.stringify({
        command: name,
        outcome: result.verdict,
        exitCode: result.exitCode,
        signal: result.signal ?? null,
        durationMs: result.durationMs,
        stdout: result.stdout,
        stderr: result.stderr,
        truncated: result.truncated,
      })}\n`,
    );
  } else {
    if (result.stdout) write(result.stdout);
    if (result.stderr) writeError(result.stderr);
    if (result.reason) writeError(`shell-gate: ${result.reason}\n`);
    writeError(
      `shell-gate: ${name} ${OUTCOME_TEXT[result.verdict] ?? result.verdict} (exit ${result.exitCode ?? '-'}, ${result.durationMs}ms)\n`,
    );
  }

  if (!recorded) return EXIT.UNAVAILABLE;
  if (result.verdict === 'ok') return EXIT.OK;
  if (result.verdict === 'failed') return EXIT.COMMAND_FAILED;
  return EXIT.UNAVAILABLE;
}
