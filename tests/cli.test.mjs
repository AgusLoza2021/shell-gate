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

function harness({ policy = POLICY, runResult, auditVerdict = 'ok' } = {}) {
  const stdout = [];
  const stderr = [];
  const spawns = [];
  const audits = [];

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
    now: () => 1758715200000,
    write: (text) => stdout.push(text),
    writeError: (text) => stderr.push(text),
  };

  return {
    deps,
    spawns,
    audits,
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
