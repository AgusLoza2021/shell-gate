// S5: the command line. The CLI is thin on purpose, but it owns one thing that
// nothing else owns: the exit code. That code is the only channel a script,
// a scheduled task or a future chat adapter can act on without parsing prose,
// so every scenario gets a distinct, documented number.
//
// The CLI is exercised through `main` with injected collaborators: no real
// process, no real disk, no real clock. That keeps the tests fast and lets us
// assert the thing that actually matters -- that a refusal spawns NOTHING.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { main } from '../src/cli.mjs';

const POLICY = JSON.stringify({
  version: 1,
  commands: {
    test: { description: 'Run the test suite', argv: ['node', '--test'] },
    'git.status': { argv: ['git', 'status', '--short'], approval: 'never' },
  },
});

function harness({ policy = POLICY, runResult, auditVerdict = 'ok', consume, grant } = {}) {
  const stdout = [];
  const stderr = [];
  const spawns = [];
  const audits = [];
  const consumes = [];
  const grants = [];

  const deps = {
    readFile: (path) => {
      if (path === 'shell-gate.json') {
        if (policy === null) {
          const error = new Error('ENOENT: no such file or directory');
          error.code = 'ENOENT';
          throw error;
        }
        return policy;
      }
      throw new Error(`unexpected read: ${path}`);
    },
    runCommand: async (input) => {
      spawns.push(input);
      return (
        runResult ?? {
          verdict: 'ok',
          exitCode: 0,
          stdout: 'all good',
          stderr: '',
          durationMs: 12,
          stdoutBytes: 8,
          stderrBytes: 0,
          truncated: { stdout: false, stderr: false },
        }
      );
    },
    appendAuditRecord: (input) => {
      audits.push(input);
      return auditVerdict === 'ok'
        ? { verdict: 'ok' }
        : { verdict: 'failed', reason: 'EPERM: operation not permitted' };
    },
    // The approvals store is injected whole: the CLI's contract with it is what
    // these tests are about, and `tests/approval.test.mjs` owns its internals.
    consumeApproval: (input) => {
      consumes.push(input);
      return (
        (consume && consume(input)) ?? {
          verdict: 'denied',
          reason: `no approval for "${input.commandName}"`,
        }
      );
    },
    grantApproval: (input) => {
      grants.push(input);
      return (
        (grant && grant(input)) ?? {
          verdict: 'ok',
          approval: {
            command: input.commandName,
            fingerprint: '0123456789abcdef',
            grantedAt: new Date(input.now).toISOString(),
            expiresAt: new Date(input.now + input.ttlSeconds * 1000).toISOString(),
          },
        }
      );
    },
    now: () => 1758715200000,
    write: (text) => stdout.push(text),
    writeError: (text) => stderr.push(text),
  };

  return {
    deps,
    spawns,
    audits,
    consumes,
    grants,
    stdout: () => stdout.join(''),
    stderr: () => stderr.join(''),
  };
}

describe('cli: usage', () => {
  test('no arguments prints usage and exits 1', async () => {
    const h = harness();
    const code = await main({ argv: [], deps: h.deps });
    assert.equal(code, 1);
    assert.match(h.stderr(), /usage/i);
  });

  test('--help prints usage and exits 0', async () => {
    const h = harness();
    const code = await main({ argv: ['--help'], deps: h.deps });
    assert.equal(code, 0);
    assert.match(h.stdout() + h.stderr(), /usage/i);
  });

  test('an unknown subcommand exits 1 without reading the policy', async () => {
    const h = harness({ policy: null });
    const code = await main({ argv: ['deploy'], deps: h.deps });
    assert.equal(code, 1);
    assert.equal(h.spawns.length, 0);
  });

  test('an unknown flag exits 1', async () => {
    const h = harness();
    const code = await main({ argv: ['list', '--force'], deps: h.deps });
    assert.equal(code, 1);
    assert.match(h.stderr(), /unknown flag/i);
  });
});

describe('cli: list and check never execute anything', () => {
  test('list names every declared command', async () => {
    const h = harness();
    const code = await main({ argv: ['list'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.spawns.length, 0);
    assert.match(h.stdout(), /test/);
    assert.match(h.stdout(), /git\.status/);
  });

  test('check reports the resolved command without running it', async () => {
    const h = harness();
    const code = await main({ argv: ['check', 'git.status'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.spawns.length, 0);
    assert.match(h.stdout(), /git status --short/);
    assert.match(h.stdout(), /never/);
  });

  test('check on an undeclared name exits 3 and runs nothing', async () => {
    const h = harness();
    const code = await main({ argv: ['check', 'rm'], deps: h.deps });
    assert.equal(code, 3);
    assert.equal(h.spawns.length, 0);
    assert.match(h.stderr(), /unknown command/);
  });

  test('a missing policy exits 2 and explains itself', async () => {
    const h = harness({ policy: null });
    const code = await main({ argv: ['list'], deps: h.deps });
    assert.equal(code, 2);
    assert.match(h.stderr(), /shell-gate\.json/);
  });

  test('an invalid policy exits 2 and reports every error', async () => {
    const h = harness({ policy: JSON.stringify({ version: 9, commands: { bad: { argv: [] } } }) });
    const code = await main({ argv: ['list'], deps: h.deps });
    assert.equal(code, 2);
    assert.match(h.stderr(), /version/);
    assert.match(h.stderr(), /argv/);
  });

  test('check without a name exits 1', async () => {
    const h = harness();
    const code = await main({ argv: ['check'], deps: h.deps });
    assert.equal(code, 1);
    assert.equal(h.spawns.length, 0);
  });
});

describe('cli: run refuses before it executes', () => {
  test('an undeclared name exits 3, spawns nothing, and is audited', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'rm'], deps: h.deps });
    assert.equal(code, 3);
    assert.equal(h.spawns.length, 0, 'a denial must never reach the runner');
    assert.equal(h.audits.length, 1, 'a denial must leave a record');
    assert.equal(h.audits[0].record.outcome, 'denied');
  });

  test('a command needing approval without --yes exits 4 and spawns nothing', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(code, 4);
    assert.equal(h.spawns.length, 0, 'a refusal must never reach the runner');
    assert.equal(h.audits.length, 1);
    assert.equal(h.audits[0].record.outcome, 'needs-approval');
    assert.match(h.stderr(), /--yes/);
  });

  test('the same command with --yes runs', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'test', '--yes'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.spawns.length, 1);
    assert.deepEqual(h.spawns[0].command.argv, ['node', '--test']);
  });

  test('a command declared approval never runs without --yes', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.spawns.length, 1);
  });

  test('a refusal leaves no execution measurements in the record', async () => {
    const h = harness();
    await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(h.audits[0].record.exitCode, null);
    assert.equal(h.audits[0].record.durationMs, null);
    assert.equal(h.audits[0].record.at, new Date(1758715200000).toISOString());
  });
});

describe('cli: run reports the outcome in the exit code', () => {
  test('success exits 0 and passes the output through', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 0);
    assert.match(h.stdout(), /all good/);
  });

  test('a non-zero exit exits 5', async () => {
    const h = harness({
      runResult: { verdict: 'failed', exitCode: 1, stdout: '', stderr: 'nope', durationMs: 5, stdoutBytes: 0, stderrBytes: 4, truncated: { stdout: false, stderr: false } },
    });
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 5);
    assert.match(h.stderr(), /nope/);
  });

  test('a timeout exits 6', async () => {
    const h = harness({
      runResult: { verdict: 'timedOut', exitCode: null, stdout: '', stderr: '', durationMs: 60000, stdoutBytes: 0, stderrBytes: 0, truncated: { stdout: false, stderr: false } },
    });
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 6);
    assert.match(h.stderr(), /timed out/i);
  });

  test('a command that could not start exits 6', async () => {
    const h = harness({
      runResult: { verdict: 'spawn-failed', exitCode: null, stdout: '', stderr: '', durationMs: 1, stdoutBytes: 0, stderrBytes: 0, truncated: { stdout: false, stderr: false }, reason: 'ENOENT' },
    });
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 6);
    assert.match(h.stderr(), /ENOENT/);
  });

  test('an unrecordable execution exits 6 and says its record is missing', async () => {
    const h = harness({ auditVerdict: 'failed' });
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 6);
    assert.match(h.stderr(), /audit/i);
  });

  test('every execution is audited with the command that ran', async () => {
    const h = harness();
    await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(h.audits.length, 1);
    assert.equal(h.audits[0].record.outcome, 'ok');
    assert.deepEqual(h.audits[0].record.argv, ['git', 'status', '--short']);
    assert.match(h.audits[0].path, /audit/);
  });
});

describe('cli: --json is a machine contract', () => {
  test('run --json prints exactly one parseable JSON line', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'git.status', '--json'], deps: h.deps });
    assert.equal(code, 0);

    const lines = h.stdout().trim().split('\n');
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.command, 'git.status');
    assert.equal(parsed.exitCode, 0);
    assert.equal(parsed.stdout, 'all good');
  });

  test('list --json is parseable and names the commands', async () => {
    const h = harness();
    await main({ argv: ['list', '--json'], deps: h.deps });
    const parsed = JSON.parse(h.stdout().trim());
    assert.deepEqual(Object.keys(parsed.commands).sort(), ['git.status', 'test']);
  });

  test('a refusal with --json is still one JSON line and still exits 3', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'rm', '--json'], deps: h.deps });
    assert.equal(code, 3);
    const parsed = JSON.parse(h.stdout().trim());
    assert.equal(parsed.outcome, 'denied');
    assert.equal(h.spawns.length, 0);
  });
});

describe('cli: approve records a one-use decision', () => {
  test('approve prints the decision, its fingerprint and its expiry, and exits 0', async () => {
    const h = harness();
    const code = await main({ argv: ['approve', 'test'], deps: h.deps });
    assert.equal(code, 0);
    assert.match(h.stdout(), /test/);
    assert.match(h.stdout(), /0123456789abcdef/);
    assert.match(h.stdout(), /expires/);
  });

  test('the decision binds to the command exactly as the policy declares it', async () => {
    const h = harness();
    await main({ argv: ['approve', 'test'], deps: h.deps });
    assert.equal(h.grants.length, 1);
    assert.equal(h.grants[0].commandName, 'test');
    assert.deepEqual(h.grants[0].command.argv, ['node', '--test']);
    assert.equal(h.grants[0].path, 'approvals.json');
  });

  test('approve is audited: a decision is a security event, not just a write', async () => {
    // Without this, the log could show a run authorised by 'stored' with no
    // corresponding record of anyone having stored anything.
    const h = harness();
    await main({ argv: ['approve', 'test'], deps: h.deps });
    assert.equal(h.audits.length, 1);
    assert.equal(h.audits[0].record.outcome, 'granted');
    assert.equal(h.audits[0].record.approval, 'stored');
    // A grant is not an execution, so nothing was measured.
    assert.equal(h.audits[0].record.exitCode, null);
    assert.match(h.audits[0].record.fingerprint, /^[0-9a-f]{16}$/);
  });

  test('an undeclared name exits 3 and grants nothing', async () => {
    const h = harness();
    const code = await main({ argv: ['approve', 'rm'], deps: h.deps });
    assert.equal(code, 3);
    assert.equal(h.grants.length, 0);
    assert.equal(h.audits[0].record.outcome, 'denied');
  });

  test('approve without a name is a usage error', async () => {
    const h = harness();
    const code = await main({ argv: ['approve'], deps: h.deps });
    assert.equal(code, 1);
    assert.equal(h.grants.length, 0);
  });

  test('--ttl is passed to the decision', async () => {
    const h = harness();
    await main({ argv: ['approve', 'test', '--ttl=30'], deps: h.deps });
    assert.equal(h.grants[0].ttlSeconds, 30);
  });

  test('the default ttl applies when none is given', async () => {
    const h = harness();
    await main({ argv: ['approve', 'test'], deps: h.deps });
    assert.equal(h.grants[0].ttlSeconds, 600);
  });

  test('a nonsensical ttl is a usage error, never a silent default', async () => {
    for (const ttl of ['0', '-5', 'abc', '1.5', '']) {
      const h = harness();
      const code = await main({ argv: ['approve', 'test', `--ttl=${ttl}`], deps: h.deps });
      assert.equal(code, 1, `ttl=${ttl}`);
      assert.equal(h.grants.length, 0, `ttl=${ttl}`);
      assert.match(h.stderr(), /ttl/, `ttl=${ttl}`);
    }
  });

  test('approving a command that never needs approval says so instead of pretending', async () => {
    const h = harness();
    const code = await main({ argv: ['approve', 'git.status'], deps: h.deps });
    assert.equal(code, 0);
    assert.match(h.stderr(), /never requires approval/);
  });

  test('a grant that could not be recorded exits 6 and says so', async () => {
    const h = harness({
      grant: () => ({ verdict: 'failed', reason: 'EPERM: operation not permitted' }),
    });
    const code = await main({ argv: ['approve', 'test'], deps: h.deps });
    assert.equal(code, 6);
    assert.match(h.stderr(), /EPERM/);
  });

  test('approve --json is one parseable line', async () => {
    const h = harness();
    const code = await main({ argv: ['approve', 'test', '--json'], deps: h.deps });
    assert.equal(code, 0);
    const parsed = JSON.parse(h.stdout().trim());
    assert.equal(parsed.command, 'test');
    assert.equal(parsed.outcome, 'granted');
    assert.equal(parsed.fingerprint, '0123456789abcdef');
    assert.ok(parsed.expiresAt);
  });

  test('--approvals selects the store', async () => {
    const h = harness();
    await main({ argv: ['approve', 'test', '--approvals=other.json'], deps: h.deps });
    assert.equal(h.grants[0].path, 'other.json');
  });
});

describe('cli: run consumes a stored approval', () => {
  const usable = () => ({ verdict: 'ok', approval: { command: 'test', fingerprint: 'f'.repeat(16) } });

  test('a stored approval runs the command and is recorded as such', async () => {
    const h = harness({ consume: usable });
    const code = await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.spawns.length, 1);
    assert.equal(h.audits[0].record.outcome, 'ok');
    assert.equal(h.audits[0].record.approval, 'stored');
  });

  test('--yes does not spend a stored decision', async () => {
    // A decision made in the moment costs nothing that a later invocation could
    // have used, so it wins and the stored one survives.
    const h = harness({ consume: usable });
    const code = await main({ argv: ['run', 'test', '--yes'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.consumes.length, 0);
    assert.equal(h.audits[0].record.approval, 'interactive');
  });

  test('a command that needs no approval is recorded as not-required and consults no store', async () => {
    const h = harness({ consume: usable });
    const code = await main({ argv: ['run', 'git.status'], deps: h.deps });
    assert.equal(code, 0);
    assert.equal(h.consumes.length, 0);
    assert.equal(h.audits[0].record.approval, 'not-required');
  });

  test('no usable approval exits 4 and spawns nothing', async () => {
    const h = harness();
    const code = await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(code, 4);
    assert.equal(h.spawns.length, 0);
    assert.equal(h.audits[0].record.approval, null);
  });

  test('the reason is reported, not just the exit code', async () => {
    const h = harness({
      consume: () => ({
        verdict: 'denied',
        reason: 'the approval for "test" expired at 2026-09-24T18:10:00.000Z',
      }),
    });
    const code = await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(code, 4);
    assert.match(h.stderr(), /expired/);
    // The record keeps the specific reason: 'expired' and 'never granted' need
    // different responses from whoever reads the log a week later.
    assert.match(h.audits[0].record.reason, /expired/);
  });

  test('the JSON refusal carries the reason too', async () => {
    const h = harness({
      consume: () => ({ verdict: 'denied', reason: 'the policy changed after it was approved' }),
    });
    const code = await main({ argv: ['run', 'test', '--json'], deps: h.deps });
    assert.equal(code, 4);
    const parsed = JSON.parse(h.stdout().trim());
    assert.equal(parsed.outcome, 'needs-approval');
    assert.match(parsed.reason, /policy changed/);
  });

  test('an unusable approvals store exits 6 and spawns nothing', async () => {
    // Fail closed: a store that cannot be read settles nothing, so the command
    // does not run on the strength of an approval that was never verified.
    const h = harness({
      consume: () => ({
        verdict: 'failed',
        reason: 'could not read the approvals file: EACCES: permission denied',
      }),
    });
    const code = await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(code, 6);
    assert.equal(h.spawns.length, 0);
    assert.match(h.stderr(), /EACCES/);
  });

  test('a refusal we could not verify is still audited, like every other refusal', async () => {
    // 'every refusal leaves evidence' has to mean every refusal. A gate that
    // goes quiet precisely when its own bookkeeping is broken is the one that
    // leaves nothing to investigate.
    const h = harness({
      consume: () => ({ verdict: 'failed', reason: 'could not read the approvals file: EACCES' }),
    });
    await main({ argv: ['run', 'test'], deps: h.deps });
    assert.equal(h.audits.length, 1);
    assert.equal(h.audits[0].record.outcome, 'needs-approval');
    assert.match(h.audits[0].record.reason, /EACCES/);
    assert.equal(h.audits[0].record.approval, null);
  });

  test('the decision is bound to the command the policy declares right now', async () => {
    const h = harness({ consume: usable });
    await main({ argv: ['run', 'test'], deps: h.deps });
    assert.deepEqual(h.consumes[0].command.argv, ['node', '--test']);
    assert.equal(h.consumes[0].commandName, 'test');
    assert.equal(h.consumes[0].path, 'approvals.json');
    assert.equal(typeof h.consumes[0].now, 'number');
  });

  test('--approvals selects the store for a run too', async () => {
    const h = harness({ consume: usable });
    await main({ argv: ['run', 'test', '--approvals=other.json'], deps: h.deps });
    assert.equal(h.consumes[0].path, 'other.json');
  });
});

describe('cli: --policy selects the policy file', () => {
  test('an explicit policy path is read instead of the default', async () => {
    const reads = [];
    const h = harness();
    const code = await main({
      argv: ['list', '--policy=other.json'],
      deps: { ...h.deps, readFile: (path) => { reads.push(path); return POLICY; } },
    });
    assert.equal(code, 0);
    assert.deepEqual(reads, ['other.json']);
  });
});
