import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
// The real filesystem is imported on purpose: the atomic rename is a platform
// behaviour (Windows overwrites differently from POSIX), and a spy cannot tell
// us whether the replacement actually happened.
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { fingerprintCommand } from '../src/policy.mjs';
import {
  DEFAULT_TTL_SECONDS,
  createApproval,
  parseApprovals,
  readApprovals,
  findUsableApproval,
  grantApproval,
  consumeApproval,
} from '../src/approval.mjs';

const NOW = Date.parse('2026-09-24T18:00:00.000Z');
const MINUTE = 60 * 1000;

/** The command as it would be declared in a policy. */
function publish() {
  return { argv: ['git', 'push'], cwd: null };
}

/** A well-formed approval, one hour in the future. */
function approved(overrides = {}) {
  return {
    command: 'publish',
    fingerprint: fingerprintCommand(publish()),
    grantedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60 * MINUTE).toISOString(),
    ...overrides,
  };
}

function document(approvals) {
  return JSON.stringify({ version: 1, approvals });
}

function spyFs({ file = null, onWrite } = {}) {
  const reads = [];
  const writes = [];
  const renames = [];
  const mkdirs = [];
  return {
    reads,
    writes,
    renames,
    mkdirs,
    readFileSync: (path, options) => {
      reads.push({ path, options });
      if (file === null) {
        const error = new Error(`ENOENT: no such file or directory, open '${path}'`);
        error.code = 'ENOENT';
        throw error;
      }
      return file;
    },
    writeFileSync: (path, data, options) => {
      writes.push({ path, data, options });
      if (onWrite) onWrite(path, data, options);
    },
    renameSync: (from, to) => {
      renames.push({ from, to });
    },
    mkdirSync: (path, options) => {
      mkdirs.push({ path, options });
    },
  };
}

describe('approval: createApproval binds a decision to one command', () => {
  test('the approval carries the fingerprint of the command it was granted for', () => {
    const result = createApproval({ commandName: 'publish', command: publish(), now: NOW });
    assert.equal(result.verdict, 'ok');
    assert.equal(result.approval.fingerprint, fingerprintCommand(publish()));
    assert.equal(result.approval.command, 'publish');
  });

  test('the approval expires one ttl after it was granted', () => {
    const result = createApproval({
      commandName: 'publish',
      command: publish(),
      now: NOW,
      ttlSeconds: 120,
    });
    assert.equal(result.approval.grantedAt, new Date(NOW).toISOString());
    assert.equal(result.approval.expiresAt, new Date(NOW + 2 * MINUTE).toISOString());
  });

  test('the default ttl is ten minutes', () => {
    assert.equal(DEFAULT_TTL_SECONDS, 600);
    const result = createApproval({ commandName: 'publish', command: publish(), now: NOW });
    assert.equal(Date.parse(result.approval.expiresAt) - NOW, 600 * 1000);
  });

  test('the caller supplies the time, so an approval is reproducible', () => {
    const a = createApproval({ commandName: 'publish', command: publish(), now: NOW });
    const b = createApproval({ commandName: 'publish', command: publish(), now: NOW });
    assert.deepEqual(a.approval, b.approval);
  });

  test('a command without a usable argv is refused', () => {
    for (const command of [null, {}, { argv: 'git push' }, { argv: [] }, { argv: [1, 2] }]) {
      const result = createApproval({ commandName: 'publish', command, now: NOW });
      assert.equal(result.verdict, 'invalid', JSON.stringify(command));
      assert.ok(result.errors.length > 0);
    }
  });

  test('a nameless command is refused', () => {
    for (const commandName of ['', null, undefined, 42]) {
      const result = createApproval({ commandName, command: publish(), now: NOW });
      assert.equal(result.verdict, 'invalid', String(commandName));
    }
  });

  test('a nonsensical ttl is refused rather than silently corrected', () => {
    for (const ttlSeconds of [0, -1, 1.5, '600', NaN]) {
      const result = createApproval({
        commandName: 'publish',
        command: publish(),
        now: NOW,
        ttlSeconds,
      });
      assert.equal(result.verdict, 'invalid', String(ttlSeconds));
    }
  });
});

describe('approval: parseApprovals fails closed', () => {
  test('a well-formed file parses into approvals', () => {
    const result = parseApprovals(document([approved()]));
    assert.equal(result.verdict, 'ok');
    assert.equal(result.approvals.length, 1);
    assert.equal(result.approvals[0].command, 'publish');
  });

  test('an empty file is rejected, not treated as no approvals', () => {
    const result = parseApprovals('');
    assert.equal(result.verdict, 'invalid');
  });

  test('text that is not JSON is rejected', () => {
    assert.equal(parseApprovals('not json').verdict, 'invalid');
  });

  test('an unknown version is rejected', () => {
    for (const version of [2, '1', null, undefined]) {
      const result = parseApprovals(JSON.stringify({ version, approvals: [] }));
      assert.equal(result.verdict, 'invalid', JSON.stringify(version));
    }
  });

  test('approvals must be an array', () => {
    for (const approvals of [{}, 'none', null, undefined]) {
      const result = parseApprovals(JSON.stringify({ version: 1, approvals }));
      assert.equal(result.verdict, 'invalid', JSON.stringify(approvals));
    }
  });

  test('a malformed entry is rejected and named by its index', () => {
    const cases = [
      { command: '' },
      { command: 'publish' },
      { command: 'publish', fingerprint: '' },
      { command: 'publish', fingerprint: 'abc', grantedAt: 'not a date', expiresAt: 'x' },
      {
        command: 'publish',
        fingerprint: 'abc',
        grantedAt: new Date(NOW).toISOString(),
        expiresAt: 'not a date',
      },
      {
        command: 'publish',
        fingerprint: 'abc',
        grantedAt: new Date(NOW + MINUTE).toISOString(),
        // Expiring before it was granted is not an approval with a short life,
        // it is a malformed record.
        expiresAt: new Date(NOW).toISOString(),
      },
    ];
    for (const entry of cases) {
      const result = parseApprovals(document([approved(), entry]));
      assert.equal(result.verdict, 'invalid', JSON.stringify(entry));
      assert.ok(
        result.errors.some((error) => error.startsWith('approvals.1')),
        `expected an error naming index 1, got ${JSON.stringify(result.errors)}`,
      );
    }
  });

  test('a rejected file yields no usable approvals at all', () => {
    const result = parseApprovals(document([approved(), { command: 'publish' }]));
    assert.equal(result.approvals, undefined);
  });

  test('the parsed approvals are copies, not views over the input document', () => {
    const entry = approved();
    const result = parseApprovals(document([entry]));
    result.approvals[0].command = 'tampered';
    assert.equal(entry.command, 'publish');
  });
});

describe('approval: findUsableApproval is where drift is caught', () => {
  test('the reason states the fact and leaves the remedy to the caller', () => {
    // The CLI renders the next step ("shell-gate approve greet"). A module that
    // emits instructions too produces the same sentence twice, at the one
    // moment the reader is already unsure what to do.
    const result = findUsableApproval([], {
      commandName: 'publish',
      command: publish(),
      now: NOW,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /no approval for "publish"/);
    assert.doesNotMatch(result.reason, /shell-gate/);
  });

  test('an approval for this exact command is usable', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: publish(),
      now: NOW,
    });
    assert.equal(result.verdict, 'ok');
    assert.equal(result.approval.command, 'publish');
  });

  test('an approval for a different fingerprint is denied: the policy changed', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      // Same name, same executable, one extra argument. This is the case the
      // whole feature exists for: approving `git push` must not authorise
      // `git push --force` after someone edits the policy.
      command: { argv: ['git', 'push', '--force'], cwd: null },
      now: NOW,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /different command/);
  });

  test('a different working directory is a different command', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: { argv: ['git', 'push'], cwd: 'C:\\elsewhere' },
      now: NOW,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /different command/);
  });

  test('an approval for another command name is denied, even with the same argv', () => {
    const result = findUsableApproval([approved({ command: 'deploy' })], {
      commandName: 'publish',
      command: publish(),
      now: NOW,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /no approval/);
  });

  test('an expired approval is denied', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: publish(),
      now: NOW + 61 * MINUTE,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /expired/);
  });

  test('an approval expiring exactly now is denied: the boundary is closed', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: publish(),
      now: NOW + 60 * MINUTE,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /expired/);
  });

  test('an approval one millisecond before expiry is still usable', () => {
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: publish(),
      now: NOW + 60 * MINUTE - 1,
    });
    assert.equal(result.verdict, 'ok');
  });

  test('the drift reason is preferred over the expiry reason when both apply', () => {
    // The actionable fact is that the policy changed, not that time passed.
    const result = findUsableApproval([approved()], {
      commandName: 'publish',
      command: { argv: ['git', 'push', '--force'], cwd: null },
      now: NOW + 61 * MINUTE,
    });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /different command/);
  });

  test('an empty list is denied with a reason that says so', () => {
    const result = findUsableApproval([], { commandName: 'publish', command: publish(), now: NOW });
    assert.equal(result.verdict, 'denied');
    assert.match(result.reason, /no approval for "publish"/);
  });

  test('an approval missing its fingerprint is denied, never treated as a wildcard', () => {
    const result = findUsableApproval([approved({ fingerprint: null })], {
      commandName: 'publish',
      command: publish(),
      now: NOW,
    });
    assert.equal(result.verdict, 'denied');
  });

  test('searching does not mutate the approvals it was given', () => {
    const approvals = [approved()];
    const snapshot = JSON.stringify(approvals);
    findUsableApproval(approvals, { commandName: 'publish', command: publish(), now: NOW });
    assert.equal(JSON.stringify(approvals), snapshot);
  });

  test('a non-array is denied rather than thrown', () => {
    for (const approvals of [null, undefined, {}, 'no']) {
      const result = findUsableApproval(approvals, {
        commandName: 'publish',
        command: publish(),
        now: NOW,
      });
      assert.equal(result.verdict, 'denied', JSON.stringify(approvals));
    }
  });
});

describe('approval: readApprovals treats absence differently from damage', () => {
  test('a missing file means no approvals, which is not an error', () => {
    const result = readApprovals({ path: 'approvals.json', fsImpl: spyFs() });
    assert.equal(result.verdict, 'ok');
    assert.deepEqual(result.approvals, []);
  });

  test('a malformed file is invalid, so the caller fails closed', () => {
    const result = readApprovals({ path: 'approvals.json', fsImpl: spyFs({ file: '{oops' }) });
    assert.equal(result.verdict, 'invalid');
    assert.ok(result.errors.length > 0);
  });

  test('an unreadable file for any other reason is invalid, never thrown', () => {
    const fsImpl = spyFs();
    fsImpl.readFileSync = () => {
      const error = new Error('EACCES: permission denied');
      error.code = 'EACCES';
      throw error;
    };
    const result = readApprovals({ path: 'approvals.json', fsImpl });
    assert.equal(result.verdict, 'invalid');
    assert.match(result.errors[0], /EACCES/);
  });
});

describe('approval: granting and consuming a stored decision', () => {
  test('granting appends one approval and writes it owner-only', () => {
    const fsImpl = spyFs({ file: document([]) });
    const result = grantApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'ok');
    assert.equal(fsImpl.writes.length, 1);
    assert.equal(fsImpl.writes[0].options.mode, 0o600);
    assert.equal(JSON.parse(fsImpl.writes[0].data).approvals.length, 1);
  });

  test('granting creates the directory when it does not exist', () => {
    // Capa 1 shipped a defect where the log directory was assumed to exist.
    // The same assumption here would break the gate on a fresh clone.
    const fsImpl = spyFs({ file: document([]) });
    grantApproval({
      path: join('config', 'nested', 'approvals.json'),
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.deepEqual(fsImpl.mkdirs, [
      { path: join('config', 'nested'), options: { recursive: true } },
    ]);
  });

  test('granting keeps an unexpired approval it found', () => {
    const fsImpl = spyFs({ file: document([approved({ command: 'deploy' })]) });
    grantApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    const written = JSON.parse(fsImpl.writes[0].data);
    assert.deepEqual(
      written.approvals.map((a) => a.command).sort(),
      ['deploy', 'publish'],
    );
  });

  test('granting prunes approvals that already expired', () => {
    const stale = approved({
      command: 'deploy',
      grantedAt: new Date(NOW - 120 * MINUTE).toISOString(),
      expiresAt: new Date(NOW - 60 * MINUTE).toISOString(),
    });
    const fsImpl = spyFs({ file: document([stale]) });
    grantApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    const written = JSON.parse(fsImpl.writes[0].data);
    assert.deepEqual(
      written.approvals.map((a) => a.command),
      ['publish'],
    );
  });

  test('the file is replaced through a temporary file, never written in place', () => {
    const fsImpl = spyFs({ file: document([]) });
    grantApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(fsImpl.writes[0].path, 'approvals.json.tmp');
    assert.deepEqual(fsImpl.renames, [
      { from: 'approvals.json.tmp', to: 'approvals.json' },
    ]);
  });

  test('consuming returns the approval and removes exactly that one', () => {
    const fsImpl = spyFs({
      file: document([approved({ command: 'deploy' }), approved()]),
    });
    const result = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'ok');
    assert.equal(result.approval.command, 'publish');
    const written = JSON.parse(fsImpl.writes[0].data);
    assert.deepEqual(
      written.approvals.map((a) => a.command),
      ['deploy'],
    );
  });

  test('a consumed approval is gone, so a second attempt is denied', () => {
    const fsImpl = spyFs({ file: document([approved()]) });
    const first = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(first.verdict, 'ok');
    // Feed the written document back, as a real second process would read it.
    const second = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl: spyFs({ file: fsImpl.writes[0].data }),
    });
    assert.equal(second.verdict, 'denied');
    assert.match(second.reason, /no approval/);
  });

  test('consuming with nothing pending is denied without writing anything', () => {
    const fsImpl = spyFs({ file: document([]) });
    const result = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'denied');
    assert.equal(fsImpl.writes.length, 0);
  });

  test('a malformed approvals file denies instead of throwing', () => {
    const fsImpl = spyFs({ file: '{"version":1,"approvals":"lots"}' });
    const result = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'failed');
    assert.ok(result.reason.length > 0);
  });

  test('a failed write fails closed and does not report success', () => {
    const fsImpl = spyFs({
      file: document([approved()]),
      onWrite: () => {
        throw new Error('EPERM: operation not permitted');
      },
    });
    const result = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'failed');
    assert.match(result.reason, /EPERM/);
  });

  test('a failing rename fails closed: the approval must not be reported as used', () => {
    const fsImpl = spyFs({ file: document([approved()]) });
    fsImpl.renameSync = () => {
      throw new Error('EXDEV: cross-device link not permitted');
    };
    const result = consumeApproval({
      path: 'approvals.json',
      commandName: 'publish',
      command: publish(),
      now: NOW,
      fsImpl,
    });
    assert.equal(result.verdict, 'failed');
    assert.match(result.reason, /EXDEV/);
  });
});

// No injected collaborators: the point is that a real approval survives a real
// write, a real rename and a real re-read on this platform.
describe('approval: against a real filesystem', () => {
  function withTempDir(run) {
    const root = mkdtempSync(join(tmpdir(), 'shell-gate-approval-'));
    try {
      return run(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  test('a granted approval is consumed exactly once', () => {
    withTempDir((root) => {
      const path = join(root, 'approvals', 'approvals.json');
      const granted = grantApproval({
        path,
        commandName: 'publish',
        command: publish(),
        now: NOW,
      });
      assert.equal(granted.verdict, 'ok', granted.reason);

      const first = consumeApproval({ path, commandName: 'publish', command: publish(), now: NOW });
      assert.equal(first.verdict, 'ok', first.reason);

      const second = consumeApproval({ path, commandName: 'publish', command: publish(), now: NOW });
      assert.equal(second.verdict, 'denied');
      assert.match(second.reason, /no approval/);
    });
  });

  test('replacing the file by rename works on this platform', () => {
    withTempDir((root) => {
      const path = join(root, 'approvals.json');
      writeFileSync(path, document([approved({ command: 'old' })]));
      const result = grantApproval({
        path,
        commandName: 'publish',
        command: publish(),
        now: NOW,
      });
      assert.equal(result.verdict, 'ok', result.reason);
      const written = JSON.parse(readFileSync(path, 'utf8'));
      assert.deepEqual(
        written.approvals.map((a) => a.command).sort(),
        ['old', 'publish'],
      );
    });
  });

  test('a policy edited after the approval is refused, on a real file', () => {
    withTempDir((root) => {
      const path = join(root, 'approvals.json');
      grantApproval({ path, commandName: 'publish', command: publish(), now: NOW });
      const result = consumeApproval({
        path,
        commandName: 'publish',
        command: { argv: ['git', 'push', '--force'], cwd: null },
        now: NOW,
      });
      assert.equal(result.verdict, 'denied');
      assert.match(result.reason, /different command/);
    });
  });

  test('the approvals file is owner-only where the platform honours it', () => {
    if (process.platform === 'win32') {
      // Windows ACLs are a separate mechanism; the mode option is a POSIX
      // guarantee and claiming otherwise would be a lie.
      return;
    }
    withTempDir((root) => {
      const path = join(root, 'approvals.json');
      grantApproval({ path, commandName: 'publish', command: publish(), now: NOW });
      assert.equal(statSync(path).mode & 0o777, 0o600);
    });
  });
});
