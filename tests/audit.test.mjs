// S4: the audit log. A gate whose only record is "it worked" hides the half
// that matters later. A denial that leaves no trace cannot be told apart from
// a request that never arrived, and those two need very different responses.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
// The real filesystem is imported on purpose. Every other test here injects a
// fake, and a fake once hid a defect that broke every real run: the log
// directory did not exist, so the append failed and the gate refused to run.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { formatAuditRecord, appendAuditRecord } from '../src/audit.mjs';

const NOW = Date.UTC(2026, 8, 24, 12, 0, 0);
const COMMAND = {
  argv: ['node', '--test', 'tests/*.test.mjs'],
  cwd: 'C:/work/project',
  approval: 'never',
  timeout_seconds: 60,
  max_output_bytes: 1024,
};

// `approval` is hoisted out of the result: it is the caller's decision, not the
// runner's output, and the two arrive at formatAuditRecord as siblings.
function executedRecord({ approval, ...resultOverrides } = {}) {
  return formatAuditRecord({
    commandName: 'test',
    command: COMMAND,
    result: {
      verdict: 'ok',
      exitCode: 0,
      durationMs: 1234,
      stdoutBytes: 42,
      stderrBytes: 0,
      truncated: { stdout: false, stderr: false },
      ...resultOverrides,
    },
    approval,
    now: NOW,
  });
}

describe('audit: formatAuditRecord describes an execution', () => {
  test('an executed command records its outcome and measurements', () => {
    const record = executedRecord();
    assert.equal(record.at, '2026-09-24T12:00:00.000Z');
    assert.equal(record.command, 'test');
    assert.equal(record.outcome, 'ok');
    assert.equal(record.exitCode, 0);
    assert.equal(record.durationMs, 1234);
    assert.equal(record.stdoutBytes, 42);
    assert.equal(record.stderrBytes, 0);
    assert.deepEqual(record.truncated, { stdout: false, stderr: false });
    assert.equal(record.cwd, 'C:/work/project');
    assert.match(record.fingerprint, /^[0-9a-f]{16}$/);
  });

  test('the fingerprint matches the command that actually ran', () => {
    const record = executedRecord();
    const again = formatAuditRecord({
      commandName: 'test',
      command: { ...COMMAND },
      result: { verdict: 'ok', exitCode: 0 },
      now: NOW,
    });
    assert.equal(record.fingerprint, again.fingerprint);
  });

  test('a failing command is distinguished from a successful one', () => {
    const record = executedRecord({ verdict: 'failed', exitCode: 1, stderrBytes: 88 });
    assert.equal(record.outcome, 'failed');
    assert.equal(record.exitCode, 1);
    assert.equal(record.stderrBytes, 88);
  });

  test('a timeout is its own outcome, not a failure', () => {
    const record = executedRecord({ verdict: 'timedOut', exitCode: null });
    assert.equal(record.outcome, 'timedOut');
    assert.equal(record.exitCode, null);
  });

  test('truncation is recorded per stream', () => {
    const record = executedRecord({ truncated: { stdout: true, stderr: false } });
    assert.deepEqual(record.truncated, { stdout: true, stderr: false });
  });
});

describe('audit: formatAuditRecord describes a refusal', () => {
  test('a denial is recorded with no execution measurements', () => {
    const record = formatAuditRecord({
      commandName: 'rm',
      command: null,
      result: { verdict: 'denied', reason: 'unknown command: rm' },
      now: NOW,
    });
    assert.equal(record.outcome, 'denied');
    assert.equal(record.reason, 'unknown command: rm');
    assert.equal(record.exitCode, null);
    assert.equal(record.durationMs, null);
    assert.equal(record.stdoutBytes, null);
    assert.equal(record.stderrBytes, null);
    assert.equal(record.truncated, null);
  });

  test('a denied request has no command, so it has no fingerprint and no argv', () => {
    const record = formatAuditRecord({
      commandName: 'rm',
      command: null,
      result: { verdict: 'denied', reason: 'unknown command' },
      now: NOW,
    });
    assert.equal(record.fingerprint, null);
    assert.equal(record.argv, null);
    assert.equal(record.cwd, null);
  });

  test('a refusal awaiting approval is recorded as needs-approval', () => {
    const record = formatAuditRecord({
      commandName: 'restart-broker',
      command: COMMAND,
      result: { verdict: 'needs-approval', reason: 'approval is always' },
      now: NOW,
    });
    assert.equal(record.outcome, 'needs-approval');
    assert.equal(record.exitCode, null);
    assert.match(record.fingerprint, /^[0-9a-f]{16}$/);
  });
});

describe('audit: formatAuditRecord is a value, not a view', () => {
  test('the record survives mutation of the command it was built from', () => {
    const command = { argv: ['node', '--test'], cwd: 'C:/work' };
    const record = formatAuditRecord({
      commandName: 'test',
      command,
      result: { verdict: 'ok', exitCode: 0 },
      now: NOW,
    });
    command.argv.push('--watch');
    command.cwd = 'C:/somewhere-else';
    assert.deepEqual(record.argv, ['node', '--test']);
    assert.equal(record.cwd, 'C:/work');
  });

  test('the record is JSON-serializable and carries no undefined values', () => {
    for (const record of [
      executedRecord(),
      formatAuditRecord({ commandName: 'rm', command: null, result: { verdict: 'denied', reason: 'no' }, now: NOW }),
    ]) {
      const roundTrip = JSON.parse(JSON.stringify(record));
      assert.deepEqual(Object.keys(roundTrip).sort(), Object.keys(record).sort());
      assert.equal(Object.values(roundTrip).includes(undefined), false);
    }
  });

  test('one record fits on one line, so the log stays line-delimited', () => {
    const line = JSON.stringify(executedRecord());
    assert.equal(line.includes('\n'), false);
  });
});

describe('audit: the record says how the run was authorised', () => {
  test('a command that needs no approval is recorded as not-required', () => {
    const record = executedRecord({ approval: 'not-required' });
    assert.equal(record.approval, 'not-required');
  });

  test('a decision made in the moment is recorded as interactive', () => {
    const record = executedRecord({ approval: 'interactive' });
    assert.equal(record.approval, 'interactive');
  });

  test('a decision made earlier is recorded as stored', () => {
    const record = executedRecord({ approval: 'stored' });
    assert.equal(record.approval, 'stored');
  });

  test('an authorisation that was not recorded is null, never a guess', () => {
    assert.equal(executedRecord().approval, null);
  });

  test('a value the log does not define becomes null, not a new kind of authorisation', () => {
    for (const approval of ['yes', 'approved', '', 0, {}, ['stored']]) {
      assert.equal(executedRecord({ approval }).approval, null, JSON.stringify(approval));
    }
  });

  test('a refusal has no authorisation to record', () => {
    const record = formatAuditRecord({
      commandName: 'rm',
      command: null,
      result: { verdict: 'denied', reason: 'unknown command' },
      now: NOW,
    });
    assert.equal(record.approval, null);
  });

  test('the authorisation is provenance, not a measurement: a spent approval still shows', () => {
    // A stored approval that was consumed and then failed to start is the case
    // that matters operationally: a decision was spent and nothing ran. Forcing
    // this field to null for every non-executed outcome -- as the byte counts
    // are -- would erase exactly the fact worth knowing.
    const record = formatAuditRecord({
      commandName: 'publish',
      command: COMMAND,
      result: { verdict: 'spawn-failed', reason: 'ENOENT' },
      approval: 'stored',
      now: NOW,
    });
    assert.equal(record.outcome, 'spawn-failed');
    assert.equal(record.approval, 'stored');
    assert.equal(record.exitCode, null);
  });

  test('every record carries the field, so the log has one shape', () => {
    for (const approval of [undefined, 'stored', 'nonsense']) {
      const record = executedRecord(approval === undefined ? {} : { approval });
      assert.ok('approval' in record);
      assert.ok(record.approval === null || typeof record.approval === 'string');
    }
  });
});

describe('audit: appendAuditRecord appends one line', () => {
  function spyFs(onAppend) {
    const calls = [];
    const mkdirs = [];
    const order = [];
    return {
      calls,
      mkdirs,
      order,
      appendFileSync: (path, data, options) => {
        order.push('append');
        calls.push({ path, data, options });
        if (onAppend) onAppend(path, data, options);
      },
      mkdirSync: (path, options) => {
        order.push('mkdir');
        mkdirs.push({ path, options });
      },
    };
  }

  test('appends exactly one line ending in a newline', () => {
    const fsImpl = spyFs();
    const result = appendAuditRecord({ path: 'audit/gate.jsonl', record: { a: 1 }, fsImpl });
    assert.equal(result.verdict, 'ok');
    assert.equal(fsImpl.calls.length, 1);
    assert.equal(fsImpl.calls[0].path, 'audit/gate.jsonl');
    assert.equal(fsImpl.calls[0].data, '{"a":1}\n');
  });

  test('the log is owner-only: it names every command that was allowed', () => {
    const fsImpl = spyFs();
    appendAuditRecord({ path: 'audit/gate.jsonl', record: { a: 1 }, fsImpl });
    assert.equal(fsImpl.calls[0].options.mode, 0o600);
    assert.equal(fsImpl.calls[0].options.encoding, 'utf8');
  });

  test('two records produce two lines, never a rewritten file', () => {
    const fsImpl = spyFs();
    appendAuditRecord({ path: 'audit/gate.jsonl', record: { n: 1 }, fsImpl });
    appendAuditRecord({ path: 'audit/gate.jsonl', record: { n: 2 }, fsImpl });
    assert.deepEqual(fsImpl.calls.map((call) => call.data), ['{"n":1}\n', '{"n":2}\n']);
  });

  test('the log directory is created before the record is appended', () => {
    const fsImpl = spyFs();
    // Both sides use join(), so the assertion describes the directory that was
    // created rather than the separator this platform happens to use.
    appendAuditRecord({
      path: join('audit', 'nested', 'gate.jsonl'),
      record: { a: 1 },
      fsImpl,
    });
    assert.deepEqual(fsImpl.mkdirs, [{ path: join('audit', 'nested'), options: { recursive: true } }]);
    // Order matters: appending before creating the directory is the defect.
    assert.deepEqual(fsImpl.order, ['mkdir', 'append']);
  });

  test('a write failure fails closed instead of throwing', () => {
    const fsImpl = {
      mkdirSync: () => {},
      appendFileSync: () => {
        throw new Error('EPERM: operation not permitted');
      },
    };
    const result = appendAuditRecord({ path: 'audit/gate.jsonl', record: { a: 1 }, fsImpl });
    assert.equal(result.verdict, 'failed');
    assert.match(result.reason, /EPERM/);
  });

  test('a failure to create the directory also fails closed', () => {
    const fsImpl = {
      mkdirSync: () => {
        throw new Error('EACCES: permission denied');
      },
      appendFileSync: () => {},
    };
    const result = appendAuditRecord({ path: 'audit/gate.jsonl', record: { a: 1 }, fsImpl });
    assert.equal(result.verdict, 'failed');
    assert.match(result.reason, /EACCES/);
  });

  test('a missing path or record is a failure, not a crash', () => {
    for (const input of [{ record: {} }, { path: 'audit/gate.jsonl' }, {}]) {
      const result = appendAuditRecord({ ...input, fsImpl: spyFs() });
      assert.equal(result.verdict, 'failed', JSON.stringify(input));
      assert.ok(result.reason.length > 0);
    }
  });
});

// These run against the real filesystem with no injected collaborators, because
// that is the configuration the tool actually ships in -- and the one where the
// missing-directory defect lived undetected.
describe('audit: against a real filesystem', () => {
  function withTempDir(run) {
    const root = mkdtempSync(join(tmpdir(), 'shell-gate-audit-'));
    try {
      return run(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  test('a nested log path is created rather than assumed to exist', () => {
    withTempDir((root) => {
      const path = join(root, 'audit', 'nested', 'gate.jsonl');
      const result = appendAuditRecord({ path, record: { a: 1 } });
      assert.equal(result.verdict, 'ok', result.reason);
      assert.equal(readFileSync(path, 'utf8'), '{"a":1}\n');
    });
  });

  test('a second append adds a line instead of replacing the file', () => {
    withTempDir((root) => {
      const path = join(root, 'audit', 'gate.jsonl');
      appendAuditRecord({ path, record: { n: 1 } });
      appendAuditRecord({ path, record: { n: 2 } });
      assert.equal(readFileSync(path, 'utf8'), '{"n":1}\n{"n":2}\n');
    });
  });

  test('a record written for real is the record that was built', () => {
    withTempDir((root) => {
      const path = join(root, 'audit', 'gate.jsonl');
      const record = formatAuditRecord({
        commandName: 'status',
        command: { argv: ['git', 'status'], cwd: null },
        result: {
          verdict: 'ok',
          exitCode: 0,
          durationMs: 5,
          stdoutBytes: 3,
          stderrBytes: 0,
          truncated: { stdout: false, stderr: false },
        },
        now: NOW,
      });
      appendAuditRecord({ path, record });
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), record);
    });
  });
});
